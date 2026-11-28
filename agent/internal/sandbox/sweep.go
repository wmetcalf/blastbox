package sandbox

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"syscall"
	"time"
)

// RunIdentity names one seatbelt run's processes by their SANDBOX rather than their ancestry.
// A child that forks, setsid()s and lets the leader exit is no longer in the run's process
// group, so a group kill and a group RSS sum both miss it; it still carries the run's profile,
// and only that profile grants write to the run's scratch dir and lookup of the run's canary
// while denying the network (a port of macos_common.writer_matcher). On Linux the jail's PID
// namespace already takes every descendant down with nsjail, so nothing is matched there.
type RunIdentity struct {
	Scratch      string    // the run's scratch dir, EvalSymlinks-resolved
	Canary       string    // the Mach service name only this run's profile may look up
	StartedAfter time.Time // processes started before this are never the run's
}

// NewCanary returns a fresh per-run canary (cf. macos_common.run_canary). Nothing registers
// it, so the grant gives the child nothing.
func NewCanary() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "io.blastbox.run." + hex.EncodeToString(b), nil
}

// RunRecord is what a job dir keeps about its sandboxed run (runner's sandbox.json), so that
// crash recovery can stop a run the agent no longer supervises before settling its job.
type RunRecord struct {
	PID          int    `json:"pid"`      // the process group leader (Setpgid)
	Identity     int64  `json:"identity"` // ProcIdentity(pid) at start
	Scratch      string `json:"scratch,omitempty"`
	Canary       string `json:"canary,omitempty"`
	StartedAfter int64  `json:"started_after_us,omitempty"`
	// NotAfter (unix seconds) is when the run cannot be alive any more (its time limit plus a
	// grace): until then a record that identifies no process is not a stopped run.
	NotAfter int64 `json:"not_after,omitempty"`
}

// KillRun SIGKILLs a recorded run's process group while its leader is still that process, then
// sweeps a seatbelt run's escapees. A leader that is gone is never a reason to signal the group
// number, which may name another group by now: on Linux the jail died with its leader (nsjail's
// PID namespace), and on macOS every other process of the run carries its sandbox and is swept.
// A record that identifies no process (the agent died between starting the run and recording
// its pid) and has no sweep identity counts as stopped only once its time limit has passed.
// An error means the run could not be shown stopped.
func KillRun(rec RunRecord) error {
	switch {
	case rec.PID > 1 && rec.Identity != 0:
		if id, alive := ProcIdentity(rec.PID); alive && id == rec.Identity {
			if err := syscall.Kill(-rec.PID, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
				return errorf("cannot kill the run's process group %d: %v", rec.PID, err)
			}
			// SIGKILL is asynchronous: return only once the leader is gone.
			for dl := time.Now().Add(killWait); !leaderGone(rec); {
				if time.Now().After(dl) {
					return errorf("process %d still alive %s after SIGKILL", rec.PID, killWait)
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	case rec.Canary == "" && rec.NotAfter > 0 && time.Now().Unix() < rec.NotAfter:
		return errorf("the run is not identifiable; waiting out its time limit (until %s)",
			time.Unix(rec.NotAfter, 0).UTC().Format(time.RFC3339))
	}
	if rec.Canary != "" {
		_, err := SweepRun(RunIdentity{Scratch: rec.Scratch, Canary: rec.Canary,
			StartedAfter: time.UnixMicro(rec.StartedAfter)})
		return err
	}
	return nil
}

// killWait bounds how long one KillRun waits for a SIGKILLed leader: recovery runs at startup,
// before heartbeats, so a leader stuck in the kernel is retried by the next pass instead.
const killWait = 5 * time.Second

// leaderGone: the recorded leader no longer runs, or its pid now names another process.
func leaderGone(rec RunRecord) bool {
	if procGone(rec.PID) {
		return true
	}
	id, ok := ProcIdentity(rec.PID)
	return !ok || id != rec.Identity
}

func errorf(format string, a ...any) error { return fmt.Errorf("sandbox sweep: "+format, a...) }
