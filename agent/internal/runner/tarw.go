package runner

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"
)

// Write writes a deterministic USTAR archive of the regular files under root to dst (created
// exclusively, mode 0600). Paths are sorted bytewise; every header has mode 0644, uid/gid 0,
// empty uname/gname and mtime 0; directories are not emitted. Anything that is not a regular
// file (symlinks, devices, FIFOs, sockets) and any hardlinked file (nlink > 1) is refused, as is
// any path USTAR cannot hold without a PAX extension. The same bytes come out on every host.
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
	tw := tar.NewWriter(f)
	for _, name := range names {
		if err := addFile(tw, root, name); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return f.Sync()
}

func addFile(tw *tar.Writer, root, name string) error {
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
	hdr := &tar.Header{
		Typeflag: tar.TypeReg, Name: name, Size: fi.Size(), Mode: 0o644,
		ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("%s: %w (USTAR cannot hold this path)", name, err)
	}
	n, err := io.Copy(tw, io.LimitReader(in, fi.Size()))
	if err != nil {
		return err
	}
	if n != fi.Size() {
		return errors.New(name + ": short read")
	}
	return nil
}
