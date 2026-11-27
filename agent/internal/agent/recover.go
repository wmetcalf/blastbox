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

// recoverJobs settles every job dir left under <state>/jobs by a previous run and returns how
// many remain (to be retried):
//
//	started marker      -> Fail("agent restarted mid-run"); never Release (a sandbox saw the input)
//	claim.json only     -> Release
//	neither / unreadable -> wipe
//
// A dir is wiped on success, ErrClaimLost and ErrRefused; any other error keeps it.
func (a *Agent) recoverJobs(ctx context.Context) int {
	jobs := filepath.Join(a.Cfg.StateDir, "jobs")
	ents, err := os.ReadDir(jobs)
	if err != nil {
		return 0
	}
	left := 0
	for _, e := range ents {
		dir := filepath.Join(jobs, e.Name())
		if !e.IsDir() {
			os.Remove(dir)
			continue
		}
		if ctx.Err() != nil {
			left++
			continue
		}
		if !a.recoverOne(ctx, dir, e.Name()) {
			left++
		}
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
