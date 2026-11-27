package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/wmetcalf/blastbox/agent/internal/runner"
	"github.com/wmetcalf/blastbox/agent/internal/sandbox"
	"github.com/wmetcalf/blastbox/agent/internal/wire"
)

var recJobIDRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// wipeDir removes a job dir whatever modes the engine left behind.
func wipeDir(dir string) {
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if d != nil && d.IsDir() {
			os.Chmod(p, 0o700)
		}
		return nil
	})
	os.RemoveAll(dir)
}

// snapshotRecovery records the job ids present on disk at startup, BEFORE any slot loop runs.
// Only these ids (plus any the runner reports as "refused") are ever recovered: a job dir that
// appears later belongs to a live job of this process and must never be touched.
func (a *Agent) snapshotRecovery() {
	ents, err := os.ReadDir(filepath.Join(a.Cfg.StateDir, "jobs"))
	if err != nil {
		return
	}
	a.mu.Lock()
	for _, e := range ents {
		a.recSet[e.Name()] = true
	}
	a.mu.Unlock()
}

func (a *Agent) addRecovery(id string) {
	a.mu.Lock()
	a.recSet[id] = true
	a.mu.Unlock()
}

// recoverJobs settles the job dirs in the recovery set and returns how many remain:
//
//	uploaded marker (202)      -> replay the same PUT, or poll the disposition when no tar is kept;
//	                              NEVER fail or release (the server refuses both once it holds the result)
//	reported marker            -> wipe: the control plane answered the upload (a Fail now could
//	                              beat the finalizer's running->done and discard the result)
//	started + result.tar/json  -> replay the idempotent result PUT (done/accepted: wipe;
//	                              refused by the extractor: Fail)
//	started marker             -> Fail("agent restarted mid-run"); never Release (a sandbox saw the input)
//	claim.json only            -> Release
//	neither / unreadable       -> wipe
//
// A dir is wiped on success, ErrClaimLost and ErrRefused; any other error keeps it (and its id
// in the set) for the next pass. Ids that are in flight in this process are skipped.
func (a *Agent) recoverJobs(ctx context.Context) int {
	jobs := filepath.Join(a.Cfg.StateDir, "jobs")
	a.mu.Lock()
	ids := make([]string, 0, len(a.recSet))
	for id := range a.recSet {
		ids = append(ids, id)
	}
	a.mu.Unlock()
	left := 0
	for _, id := range ids {
		if !a.recoverID(ctx, jobs, id) {
			left++
		}
	}
	return left
}

// recoverID settles one id under its lock, so a live run of the same job (claimed again while
// a recovery request was in flight) waits for the wipe instead of being wiped.
func (a *Agent) recoverID(ctx context.Context, jobs, id string) (done bool) {
	unlock := a.lockID(id)
	defer unlock()
	a.mu.Lock()
	_, live := a.inflight[id]
	a.mu.Unlock()
	if live || ctx.Err() != nil {
		return false
	}
	dir := filepath.Join(jobs, id)
	if _, err := os.Lstat(dir); err != nil || a.recoverOne(ctx, dir, id) {
		a.mu.Lock()
		delete(a.recSet, id)
		delete(a.unswept, id)
		a.mu.Unlock()
		return true
	}
	return false
}

// resultRecord returns the kept upload of a job dir: its tar and the headers it was sent with.
func resultRecord(dir string) (string, wire.ResultMeta, bool) {
	tar := filepath.Join(dir, runner.ResultTarName)
	if fi, err := os.Lstat(tar); err != nil || !fi.Mode().IsRegular() {
		return "", wire.ResultMeta{}, false
	}
	raw, err := os.ReadFile(filepath.Join(dir, runner.ResultMetaName))
	var rec runner.ResultRecord
	if err != nil || json.Unmarshal(raw, &rec) != nil {
		return "", wire.ResultMeta{}, false
	}
	m := wire.ResultMeta{WorkerRuntime: rec.WorkerRuntime}
	if rec.StartedAtMs > 0 {
		m.StartedAt = time.UnixMilli(rec.StartedAtMs)
	}
	if rec.FinishedAtMs > 0 {
		m.FinishedAt = time.UnixMilli(rec.FinishedAtMs)
	}
	return tar, m, true
}

func (a *Agent) recoverOne(ctx context.Context, dir, name string) (settled bool) {
	if _, err := os.Lstat(filepath.Join(dir, runner.ReportedName)); err == nil {
		a.Log.Info("recovery: the control plane already answered this job's upload; wiping", "job", name)
		wipeDir(dir)
		return true
	}
	_, uploadedErr := os.Lstat(filepath.Join(dir, runner.UploadedName))
	uploaded := uploadedErr == nil
	_, startErr := os.Lstat(filepath.Join(dir, "started"))
	started := startErr == nil
	if started {
		// A run the previous agent left behind may still be alive: stop it before the job is
		// settled or its dir wiped under it, whatever the state of its claim record.
		if raw, err := os.ReadFile(filepath.Join(dir, runner.RunRecordName)); err == nil {
			var rec sandbox.RunRecord
			if json.Unmarshal(raw, &rec) == nil {
				if err := a.KillRunFn(rec); err != nil {
					a.Log.Warn("recovery: the previous run could not be shown stopped; will retry", "job", name, "err", err.Error())
					// Its engine must not claim meanwhile, also after a restart (the gate lives in
					// memory): name it from the claim record, or gate every engine if unreadable.
					var ce struct {
						Engine string `json:"engine"`
					}
					if raw, err := os.ReadFile(filepath.Join(dir, "claim.json")); err == nil {
						json.Unmarshal(raw, &ce)
					}
					a.mu.Lock()
					a.unswept[name] = ce.Engine
					a.mu.Unlock()
					return false
				}

			}
		}
	}
	a.mu.Lock()
	delete(a.unswept, name) // stopped, or nothing recorded that could be stopped
	a.mu.Unlock()
	raw, err := os.ReadFile(filepath.Join(dir, "claim.json"))
	var cj struct {
		JobID   string `json:"job_id"`
		ClaimID string `json:"claim_id"`
		Receipt string `json:"receipt"`
		Claimed int64  `json:"claimed_at_ms"`
	}
	if err != nil || json.Unmarshal(raw, &cj) != nil || cj.JobID != name || !recJobIDRE.MatchString(cj.JobID) ||
		cj.ClaimID == "" || cj.Receipt == "" {
		a.Log.Warn("recovery: job dir without a usable claim record; wiping", "job", name, "started", started)
		wipeDir(dir)
		return true
	}
	cl := &wire.Claim{JobID: cj.JobID, ClaimID: cj.ClaimID, Receipt: cj.Receipt}
	switch {
	case cj.Claimed > 0:
		cl.ClaimedAt = time.UnixMilli(cj.Claimed)
	default:
		// A claim.json from before the claim time was recorded: its mtime is never before the
		// claim, which is all the finished_at clamp needs.
		if fi, err := os.Lstat(filepath.Join(dir, "claim.json")); err == nil {
			cl.ClaimedAt = fi.ModTime()
		}
	}
	rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if uploaded {
		return a.recoverUploaded(rctx, dir, name, cl)
	}
	var cerr error
	action := "release"
	if started {
		action = "fail"
		reason := "agent restarted mid-run"
		if tar, meta, ok := resultRecord(dir); ok {
			action = "replay upload"
			out, err := a.client().PutResult(rctx, cl, tar, meta)
			switch {
			case err != nil && runner.Permanent(err):
				action, reason = "fail", "result upload refused: "+err.Error()
			case err != nil:
				cerr = err
			case out.Status == "failed":
				action, reason = "fail", "control plane rejected the result: "+out.Reason
			default:
				a.Log.Info("recovery: result upload replayed", "job", name, "status", out.Status)
			}
		}
		if action == "fail" {
			cerr = a.client().Fail(rctx, cl, reason, a.Now())
		}
	} else {
		cerr = a.client().Release(rctx, cl)
	}
	switch {
	case cerr == nil:
		a.Log.Info("recovery: job settled", "job", name, "action", action)
	case errors.Is(cerr, wire.ErrClaimLost), errors.Is(cerr, wire.ErrRefused):
		a.Log.Info("recovery: claim no longer ours; wiping", "job", name, "action", action, "err", cerr.Error())
	case runner.Permanent(cerr):
		// The control plane will never accept this report (no such job, or refused outright).
		a.Log.Warn("recovery: report permanently refused; wiping", "job", name, "action", action, "err", cerr.Error())
	default:
		a.Log.Warn("recovery: will retry", "job", name, "action", action, "err", cerr.Error())
		return false
	}
	wipeDir(dir)
	return true
}

// recoverUploaded settles a job whose result upload the control plane accepted (202). It holds
// the result and refuses release and fail (403), so the only follow-ups are the same idempotent
// PUT, when its tar is kept, or a disposition poll. Even a 422 on the replay is never answered
// with a fail: the first-time 422 that justifies one stores nothing and was seen before the marker.
func (a *Agent) recoverUploaded(ctx context.Context, dir, name string, cl *wire.Claim) bool {
	var err error
	if tar, meta, ok := resultRecord(dir); ok {
		var out wire.Outcome
		out, err = a.client().PutResult(ctx, cl, tar, meta)
		if err == nil {
			a.Log.Info("recovery: accepted upload replayed", "job", name, "status", out.Status)
			wipeDir(dir)
			return true
		}
	} else {
		var st string
		st, err = a.client().Disposition(ctx, cl.JobID)
		if err == nil {
			if st == "running" {
				a.Log.Info("recovery: finalizer still working on an accepted upload; will poll again", "job", name)
				return false
			}
			a.Log.Info("recovery: accepted upload settled", "job", name, "disposition", st)
			wipeDir(dir)
			return true
		}
	}
	switch {
	case errors.Is(err, wire.ErrClaimLost), errors.Is(err, wire.ErrRefused), runner.Permanent(err):
		a.Log.Warn("recovery: accepted upload no longer answerable; wiping", "job", name, "err", err.Error())
		wipeDir(dir)
		return true
	}
	a.Log.Warn("recovery: will retry", "job", name, "action", "poll accepted upload", "err", err.Error())
	return false
}
