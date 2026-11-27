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
}

// KillRun SIGKILLs a recorded run's process group, if its leader is still that process (or is
// gone: the kernel does not reuse a pid while its process group lives), then sweeps a seatbelt
// run's escapees. An error means the run could not be shown stopped.
func KillRun(rec RunRecord) error {
	if rec.PID > 1 {
		id, alive := ProcIdentity(rec.PID)
		if !alive || id == rec.Identity {
			syscall.Kill(-rec.PID, syscall.SIGKILL)
		}
	}
	if rec.Canary != "" {
		_, err := SweepRun(RunIdentity{Scratch: rec.Scratch, Canary: rec.Canary,
			StartedAfter: time.UnixMicro(rec.StartedAfter)})
		return err
	}
	return nil
}

func errorf(format string, a ...any) error { return fmt.Errorf("sandbox sweep: "+format, a...) }
