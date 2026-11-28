package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An envelope declaring more artifacts than max_artifacts is refused before anything is
// hashed; a file declared many times is hashed once.
func TestFillArtifactsBoundsDeclarations(t *testing.T) {
	f := setup(t, "true")
	j := &job{c: f.claim, out: t.TempDir()}
	os.WriteFile(filepath.Join(j.out, "a"), []byte("x"), 0o600)
	decl := func(n int) {
		var b strings.Builder
		b.WriteString(`{"artifacts":[`)
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(`{"path":"a"}`)
		}
		b.WriteString(`]}`)
		os.WriteFile(filepath.Join(j.out, metadataName), []byte(b.String()), 0o600)
	}
	files := map[string]int64{"a": 1, metadataName: 0}
	decl(int(f.claim.Run.Limits.MaxArtifacts) + 1)
	if err := j.fillArtifacts(files); err == nil || !strings.Contains(err.Error(), "max_artifacts") {
		t.Fatalf("err = %v, want the max_artifacts refusal", err)
	}
	decl(int(f.claim.Run.Limits.MaxArtifacts))
	opened := 0
	prev := fileSHA
	fileSHA = func(p string) (string, error) { opened++; return prev(p) }
	t.Cleanup(func() { fileSHA = prev })
	if err := j.fillArtifacts(files); err != nil {
		t.Fatal(err)
	}
	if opened != 1 {
		t.Fatalf("hashed the same file %d times", opened)
	}
}
