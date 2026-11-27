package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
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
