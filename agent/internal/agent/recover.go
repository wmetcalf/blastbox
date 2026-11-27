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
//	started marker       -> Fail("agent restarted mid-run"); never Release (a sandbox saw the input)
//	claim.json only      -> Release
//	neither / unreadable -> wipe
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
		a.mu.Lock()
		_, live := a.inflight[id]
		a.mu.Unlock()
		if live {
			left++
			continue
		}
		if ctx.Err() != nil {
			left++
			continue
		}
		dir := filepath.Join(jobs, id)
		if _, err := os.Lstat(dir); err != nil || a.recoverOne(ctx, dir, id) {
			a.mu.Lock()
			delete(a.recSet, id)
			a.mu.Unlock()
			continue
		}
		left++
	}
	return left
}

func (a *Agent) recoverOne(ctx context.Context, dir, name string) (settled bool) {
	_, startErr := os.Lstat(filepath.Join(dir, "started"))
	started := startErr == nil
	raw, err := os.ReadFile(filepath.Join(dir, "claim.json"))
	var cj struct {
		JobID   string `json:"job_id"`
		ClaimID string `json:"claim_id"`
		Receipt string `json:"receipt"`
	}
	if err != nil || json.Unmarshal(raw, &cj) != nil || cj.JobID != name || !recJobIDRE.MatchString(cj.JobID) ||
		cj.ClaimID == "" || cj.Receipt == "" {
		a.Log.Warn("recovery: job dir without a usable claim record; wiping", "job", name, "started", started)
		wipeDir(dir)
		return true
	}
	cl := &wire.Claim{JobID: cj.JobID, ClaimID: cj.ClaimID, Receipt: cj.Receipt}
	rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var cerr error
	action := "release"
	if started {
		action = "fail"
		cerr = a.client().Fail(rctx, cl, "agent restarted mid-run", a.Now())
	} else {
		cerr = a.client().Release(rctx, cl)
	}
	switch {
	case cerr == nil:
		a.Log.Info("recovery: job settled", "job", name, "action", action)
	case errors.Is(cerr, wire.ErrClaimLost), errors.Is(cerr, wire.ErrRefused):
		a.Log.Info("recovery: claim no longer ours; wiping", "job", name, "action", action, "err", cerr.Error())
	default:
		a.Log.Warn("recovery: will retry", "job", name, "action", action, "err", cerr.Error())
		return false
	}
	wipeDir(dir)
	return true
}
