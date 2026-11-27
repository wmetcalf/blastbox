//go:build !unix

package config

import (
	"errors"
	"io/fs"
)

// fileOwner refuses on platforms where ownership cannot be checked (fail closed).
func fileOwner(fs.FileInfo) (int, error) {
	return 0, errors.New("key ownership cannot be verified on this OS")
}
