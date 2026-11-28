package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wmetcalf/blastbox/agent/internal/conformance"
)

// TestWriterVectors: for each result_tars/writer vector, Write must produce exactly the tar the
// Python reference built (tar_sha256, tar_bytes). In tree, metadata.json is UTF-8 text and
// every other value is hex.
func TestWriterVectors(t *testing.T) {
	ents, err := os.ReadDir(conformance.Path("result_tars", "writer"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range ents {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		n++
		name := strings.TrimSuffix(e.Name(), ".json")
		t.Run(name, func(t *testing.T) {
			var v struct {
				Tree      map[string]string `json:"tree"`
				TarSHA256 string            `json:"tar_sha256"`
				TarBytes  int               `json:"tar_bytes"`
			}
			if err := conformance.ReadJSON(filepath.Join("result_tars", "writer", e.Name()), &v); err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			for rel, val := range v.Tree {
				body := []byte(val)
				if rel != "metadata.json" {
					if body, err = hex.DecodeString(val); err != nil {
						t.Fatalf("%s: %v", rel, err)
					}
				}
				p := filepath.Join(root, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			b := writeTar(t, root)
			sum := sha256.Sum256(b)
			if got := hex.EncodeToString(sum[:]); got != v.TarSHA256 || len(b) != v.TarBytes {
				t.Fatalf("tar sha256 %s (%d bytes), want %s (%d bytes)", got, len(b), v.TarSHA256, v.TarBytes)
			}
		})
	}
	if n == 0 {
		t.Fatal("no result_tars/writer vectors")
	}
}
