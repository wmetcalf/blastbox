package runner

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// Wipe removes a job dir whatever the engine did to it, and proves it is gone. An engine owns
// the files it writes and may have locked them: modes (restored here) and, on macOS, the user
// flags uchg/uappnd, which seatbelt leaves settable in scratch (cleared here; a deny ACL cannot
// be set there). Symlinks are never followed. A dir that is still present is an error, so the
// caller can keep it for another attempt rather than leave job data behind.
func Wipe(dir string) error {
	if os.RemoveAll(dir) == nil {
		if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
			return nil
		}
	}
	// Something was locked: unlock what is left (in batches, never following a symlink) and
	// try again.
	unlock := func(p string, isDir bool) {
		clearUserFlags(p) // before chmod: a uchg file or dir refuses chmod too
		if isDir {
			os.Chmod(p, 0o700)
		}
	}
	if fi, err := os.Lstat(dir); err == nil && fi.Mode()&fs.ModeSymlink == 0 {
		unlock(dir, fi.IsDir())
		if fi.IsDir() {
			walkBatched(dir, true, func(p string, d fs.DirEntry) error {
				if d.Type()&fs.ModeSymlink == 0 {
					unlock(p, d.IsDir())
				}
				return nil
			})
		}
	}
	rmErr := os.RemoveAll(dir)
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		if rmErr == nil {
			rmErr = errors.New("still present")
		}
		return fmt.Errorf("wipe %s: %w", dir, rmErr)
	}
	return nil
}
