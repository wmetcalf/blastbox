//go:build unix

package config

import (
	"errors"
	"io/fs"
	"syscall"
)

// fileOwner returns the owning uid of a file.
func fileOwner(st fs.FileInfo) (int, error) {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("cannot determine file owner")
	}
	return int(sys.Uid), nil
}
