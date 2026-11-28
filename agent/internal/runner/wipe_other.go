//go:build !darwin

package runner

// clearUserFlags: only macOS lets a sandboxed engine set user file flags the wipe must undo.
func clearUserFlags(string) {}
