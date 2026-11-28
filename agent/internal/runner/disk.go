package runner

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// maxDiskEntries caps the entries a run may hold in its writable dirs (the Python seatbelt
// lifecycle's MAX_SCRATCH_ENTRIES); the measurement stops counting just past it, so a
// directory bomb cannot make the measurement itself expensive.
var maxDiskEntries = 200_000

// dirUsage measures (bytes in allocated blocks, entries, complete) under roots without
// following symlinks. Directories are opened O_NOFOLLOW|O_DIRECTORY and read in batches, so a
// run that swaps a directory for a symlink cannot steer the walk into another tree. Hard links
// are charged once. It stops just past maxEntries. complete is false when part of a tree could
// not be read (a run can chmod 000 a directory to hide it): the caller must treat that as over
// budget, never as empty. A root or entry that vanished mid-walk is simply gone.
func dirUsage(roots []string, maxEntries int) (used int64, entries int, complete bool) {
	complete = true
	charged := map[[2]uint64]bool{}
	charge := func(fi fs.FileInfo) {
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			used += fi.Size()
			return
		}
		if !fi.IsDir() && st.Nlink > 1 {
			k := [2]uint64{uint64(st.Dev), uint64(st.Ino)}
			if charged[k] {
				return
			}
			charged[k] = true
		}
		used += int64(st.Blocks) * 512
	}
	var stack []string
	for _, r := range roots {
		fi, err := os.Lstat(r)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				complete = false
			}
			continue
		}
		if !fi.IsDir() {
			entries++
			charge(fi)
			continue
		}
		stack = append(stack, r)
	}
	for len(stack) > 0 {
		dir := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			if err != syscall.ENOENT && err != syscall.ENOTDIR && err != syscall.ELOOP {
				complete = false
			}
			continue // gone, or swapped for a link or file since it was listed: never followed
		}
		f := os.NewFile(uintptr(fd), dir)
		for {
			ents, err := readDirBatch(f, dirBatch)
			for _, e := range ents {
				if entries++; entries > maxEntries {
					f.Close()
					return used, entries, complete
				}
				p := filepath.Join(dir, e.Name())
				fi, lerr := os.Lstat(p)
				if lerr != nil {
					if !errors.Is(lerr, fs.ErrNotExist) {
						complete = false
					}
					continue
				}
				charge(fi)
				if fi.IsDir() {
					stack = append(stack, p)
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					complete = false
				}
				break
			}
		}
		f.Close()
	}
	return used, entries, complete
}

// underRoots reports whether path lies in (or is) one of roots.
func underRoots(path string, roots []string) bool {
	for _, r := range roots {
		if path == r || strings.HasPrefix(path, r+"/") {
			return true
		}
	}
	return false
}
