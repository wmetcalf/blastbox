package runner

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"
)

// Write writes a deterministic USTAR archive of the regular files under root to dst (created
// exclusively, mode 0600). Paths are sorted bytewise; every header has mode 0644, uid/gid 0,
// empty uname/gname and mtime 0; directories are not emitted. Anything that is not a regular
// file (symlinks, devices, FIFOs, sockets) and any hardlinked file (nlink > 1) is refused, as is
// any path that is not UTF-8 or that USTAR cannot hold without a PAX extension. Names are raw
// UTF-8 bytes, split into prefix/name as Python's tarfile does (conformance result_tars/writer).
// The same bytes come out on every host.
func Write(root, dst string) (err error) {
	var names []string
	werr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case fi.IsDir():
			return nil
		case !fi.Mode().IsRegular():
			return fmt.Errorf("%s: not a regular file (%s)", rel, fi.Mode().Type())
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && uint64(st.Nlink) > 1 {
			return fmt.Errorf("%s: hardlinked file (nlink %d)", rel, st.Nlink)
		}
		names = append(names, filepath.ToSlash(rel))
		return nil
	})
	if werr != nil {
		return werr
	}
	sort.Strings(names) // bytewise

	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(dst)
		}
	}()
	tw := bufio.NewWriterSize(f, 64<<10)
	for _, name := range names {
		if err := addFile(tw, root, name); err != nil {
			return err
		}
	}
	if _, err := tw.Write(make([]byte, 2*blockSize)); err != nil { // end-of-archive marker
		return err
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	return f.Sync()
}

const (
	blockSize  = 512
	nameSize   = 100
	prefixSize = 155
	maxSize    = 1<<33 - 1 // 11 octal digits
)

// splitName splits name into a USTAR prefix and name exactly as Python's tarfile does: the
// SHORTEST "/"-boundary prefix whose remainder fits. ok is false when no split fits.
func splitName(name string) (prefix, base string, ok bool) {
	if len(name) <= nameSize {
		return "", name, true
	}
	parts := strings.Split(name, "/")
	for i := 1; i < len(parts); i++ {
		p, b := strings.Join(parts[:i], "/"), strings.Join(parts[i:], "/")
		if len(p) <= prefixSize && len(b) <= nameSize {
			return p, b, true
		}
	}
	return "", "", false
}

// ustarHeader is the 512-byte header Go's archive/tar wrote for an ASCII name (and Python's
// tarfile writes for any UTF-8 name): mode 0644, uid/gid 0, mtime 0, empty uname/gname,
// devmajor/devminor "0000000\0".
func ustarHeader(name string, size int64) ([]byte, error) {
	if !utf8.ValidString(name) || strings.ContainsRune(name, 0) {
		return nil, errors.New("name is not UTF-8")
	}
	if size < 0 || size > maxSize {
		return nil, fmt.Errorf("size %d does not fit a USTAR header", size)
	}
	prefix, base, ok := splitName(name)
	if !ok {
		return nil, errors.New("path too long for a USTAR header")
	}
	h := make([]byte, blockSize)
	copy(h[0:100], base)
	copy(h[100:108], "0000644\x00")
	copy(h[108:116], "0000000\x00")
	copy(h[116:124], "0000000\x00")
	copy(h[124:136], fmt.Sprintf("%011o\x00", size))
	copy(h[136:148], "00000000000\x00")
	copy(h[148:156], "        ")
	h[156] = '0'
	copy(h[257:265], "ustar\x0000")
	copy(h[329:337], "0000000\x00")
	copy(h[337:345], "0000000\x00")
	copy(h[345:500], prefix)
	sum := 0
	for _, c := range h {
		sum += int(c)
	}
	copy(h[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return h, nil
}

func addFile(tw io.Writer, root, name string) error {
	p := filepath.Join(root, filepath.FromSlash(name))
	in, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	// Re-check on the open descriptor: the file must still be what the walk saw.
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: changed while archiving", name)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && uint64(st.Nlink) > 1 {
		return fmt.Errorf("%s: hardlinked file", name)
	}
	hdr, err := ustarHeader(name, fi.Size())
	if err != nil {
		return fmt.Errorf("%+q: %w", name, err)
	}
	if _, err := tw.Write(hdr); err != nil {
		return err
	}
	n, err := io.Copy(tw, io.LimitReader(in, fi.Size()))
	if err != nil {
		return err
	}
	if n != fi.Size() {
		return errors.New(name + ": short read")
	}
	if pad := -n & (blockSize - 1); pad > 0 {
		if _, err := tw.Write(make([]byte, pad)); err != nil {
			return err
		}
	}
	return nil
}
