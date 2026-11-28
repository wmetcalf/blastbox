package runner

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// goldenTree is the fixed tree of the golden vector; testdata/tarcheck.py rebuilds the same tar with Python tarfile.
var goldenTree = []struct{ path, body string }{
	{"metadata.json", `{"a":1}`},
	{"art/z.bin", "zz"},
	{"art/a.txt", "hello\n"},
	{"B.txt", ""},
	{"deep/er/path/f", strings.Repeat("x", 1000)},
	{"a-" + strings.Repeat("n", 90) + "/" + strings.Repeat("m", 90), "split into ustar prefix"},
}

const goldenTarSHA256 = "a63fd9607b479f5202dc02e3f701dc59f68902505b16416449dd8a51db3c4b3f"

func buildTree(t *testing.T, root string) {
	t.Helper()
	for _, f := range goldenTree {
		p := filepath.Join(root, f.path)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(f.body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	os.Mkdir(filepath.Join(root, "empty-dir"), 0o755)
}

func writeTar(t *testing.T, root string) []byte {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "r.tar")
	if err := Write(root, dst); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(dst)
	return b
}

func TestTarGolden(t *testing.T) {
	root := t.TempDir()
	buildTree(t, root)
	b := writeTar(t, root)
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != goldenTarSHA256 {
		t.Fatalf("tar sha256 = %s, want %s", got, goldenTarSHA256)
	}
}

func TestTarDeterministicAndNormalised(t *testing.T) {
	root := t.TempDir()
	buildTree(t, root)
	// Different mtimes/modes on disk must not leak into the archive.
	os.Chmod(filepath.Join(root, "art/a.txt"), 0o600)
	os.Chtimes(filepath.Join(root, "B.txt"), mustTime(), mustTime())
	a := writeTar(t, root)
	b := writeTar(t, root)
	if !bytes.Equal(a, b) {
		t.Fatal("two runs differ")
	}
	tr := tar.NewReader(bytes.NewReader(a))
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
		if h.Typeflag != tar.TypeReg || h.Mode != 0o644 || h.Uid != 0 || h.Gid != 0 ||
			h.Uname != "" || h.Gname != "" || h.ModTime.Unix() != 0 || h.Format != tar.FormatUSTAR {
			t.Errorf("%s: header %+v", h.Name, h)
		}
	}
	want := []string{"B.txt", "a-" + strings.Repeat("n", 90) + "/" + strings.Repeat("m", 90), "art/a.txt", "art/z.bin", "deep/er/path/f", "metadata.json"}
	if strings.Join(names, "|") != strings.Join(want, "|") {
		t.Fatalf("order %q", names)
	}
}

func TestTarRefusesNonRegular(t *testing.T) {
	for _, c := range []struct {
		name string
		mk   func(root string) error
	}{
		{"symlink", func(r string) error { return os.Symlink("/etc/passwd", filepath.Join(r, "l")) }},
		{"hardlink", func(r string) error { return os.Link(filepath.Join(r, "f"), filepath.Join(r, "h")) }},
		{"fifo", func(r string) error { return mkfifo(filepath.Join(r, "p")) }},
		{"not utf-8", func(r string) error { return os.WriteFile(filepath.Join(r, "caf\xe9"), []byte("x"), 0o600) }},
		{"too long", func(r string) error {
			return os.WriteFile(filepath.Join(r, strings.Repeat("n", 101)), []byte("x"), 0o600)
		}},
	} {
		root := t.TempDir()
		os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o600)
		if err := c.mk(root); err != nil {
			if errors.Is(err, syscall.EILSEQ) {
				continue // APFS refuses non-UTF-8 names, so no engine there can produce one
			}
			t.Fatalf("%s setup: %v", c.name, err)
		}
		dst := filepath.Join(t.TempDir(), "r.tar")
		if err := Write(root, dst); err == nil {
			t.Errorf("%s: want refusal", c.name)
		}
		if _, err := os.Stat(dst); err == nil {
			t.Errorf("%s: partial tar left behind", c.name)
		}
	}
}

// The writer is byte-for-byte Python's tarfile USTAR (the conformance generator), including
// raw UTF-8 names and tarfile's shortest-prefix split of long paths.
func TestTarMatchesPythonTarfile(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	tree := map[string]string{
		"metadata.json": "7b7d",
		strings.Repeat("x", 50) + "/" + strings.Repeat("y", 50) + "/" + strings.Repeat("z", 40): "01",
		"art/" + strings.Repeat("é", 60) + "/f.txt":                                             "02",
		strings.Repeat("n", 100):       "",
		"a/" + strings.Repeat("b", 99): "0303",
	}
	root := t.TempDir()
	for rel, hx := range tree {
		body, _ := hex.DecodeString(hx)
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	js, _ := json.Marshal(tree)
	cmd := exec.Command(py, filepath.Join("testdata", "tartree.py"))
	cmd.Stdin = bytes.NewReader(js)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(writeTar(t, root))
	if got, want := hex.EncodeToString(sum[:]), strings.TrimSpace(string(out)); got != want {
		t.Fatalf("Go tar %s, Python tarfile %s", got, want)
	}
}
