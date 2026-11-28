package runner

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// dirBatch is how many entries walkBatched reads from a directory at a time.
var dirBatch = 256

// readDirBatch reads up to n entries of an open directory (a seam for tests).
var readDirBatch = func(f *os.File, n int) ([]fs.DirEntry, error) { return f.ReadDir(n) }

// walkBatched visits every entry under root (not root itself) without following symlinks,
// reading each directory dirBatch entries at a time, so memory never depends on how many
// entries one directory holds: fn can enforce a count and stop the walk before the rest of a
// huge directory is read (filepath.WalkDir reads and sorts a whole directory first). fn is
// called for a directory before it is opened. Order is unspecified. A directory that cannot be
// opened or read is an error, unless skipErrs, which skips it.
func walkBatched(root string, skipErrs bool, fn func(p string, d fs.DirEntry) error) error {
	stack := []string{root}
	for len(stack) > 0 {
		dir := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		f, err := os.Open(dir)
		if err != nil {
			if skipErrs {
				continue
			}
			return err
		}
		for {
			ents, err := readDirBatch(f, dirBatch)
			for _, e := range ents {
				p := filepath.Join(dir, e.Name())
				if ferr := fn(p, e); ferr != nil {
					f.Close()
					return ferr
				}
				if e.IsDir() {
					stack = append(stack, p)
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				f.Close()
				if skipErrs {
					break
				}
				return err
			}
		}
		f.Close()
	}
	return nil
}
