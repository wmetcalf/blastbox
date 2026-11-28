package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/wmetcalf/blastbox/agent/internal/config"
)

// lockStateDir takes an exclusive, non-blocking flock on <state_dir>/agent.lock for the life of
// the process. A second agent on the same state dir would snapshot the first one's live job dirs
// as crash leftovers, then fail their claims and wipe them under the running engines.
func lockStateDir(stateDir string) (*os.File, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(stateDir, "agent.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("state dir %s is in use by another agent: %w", stateDir, err)
	}
	return f, nil
}

// lockCert takes an exclusive flock on <state_dir>/cert.lock, waiting for it until ctx is done:
// renewal steps of a running agent and of `blastbox-agent renew` write and rename the same key
// and cert files. It lives in the state dir, which is always the agent's to write (the key dir
// need not be), and a holder stuck on the network never blocks a shutdown past its context.
func lockCert(ctx context.Context, cfg *config.Config) (func(), error) {
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(cfg.StateDir, "cert.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { f.Close() }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, fmt.Errorf("certificate lock: %w", err)
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, fmt.Errorf("certificate lock: %w", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}
