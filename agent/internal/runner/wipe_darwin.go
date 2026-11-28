//go:build darwin

package runner

import "syscall"

// clearUserFlags clears the file flags of p (not a symlink: the caller skips those, and the
// engine that could swap one in has been stopped before any wipe). Best effort: Wipe proves
// the result.
func clearUserFlags(p string) { syscall.Chflags(p, 0) }
