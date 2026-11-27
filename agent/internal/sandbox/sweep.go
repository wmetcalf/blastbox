package sandbox

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
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

func errorf(format string, a ...any) error { return fmt.Errorf("sandbox sweep: "+format, a...) }
