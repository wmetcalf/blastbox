package runner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWipeRestoresModesAndRemoves(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "job")
	sub := filepath.Join(dir, "scratch", "locked")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(sub, "f"), []byte("x"), 0o600)
	os.Chmod(sub, 0)
	if err := Wipe(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("dir survived: %v", err)
	}
}

// A dir Wipe could not remove is reported, not silently left behind.
func TestWipeReportsADirItCouldNotRemove(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root removes anything")
	}
	parent := t.TempDir()
	dir := filepath.Join(parent, "job")
	os.Mkdir(dir, 0o700)
	os.Chmod(parent, 0o500)
	t.Cleanup(func() { os.Chmod(parent, 0o700) })
	if err := Wipe(dir); err == nil {
		t.Fatal("Wipe reported success for a dir still on disk")
	}
}
