package runner

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// One directory of many entries is read in batches and the walk stops at the count limit, not
// after reading the whole directory.
func TestCheckOutputStopsReadingAtTheCountLimit(t *testing.T) {
	f := setup(t, "true")
	j := &job{c: f.claim, out: t.TempDir()}
	os.WriteFile(filepath.Join(j.out, metadataName), []byte("{}"), 0o600)
	big := filepath.Join(j.out, "big")
	os.Mkdir(big, 0o700)
	for i := 0; i < 2000; i++ {
		os.WriteFile(filepath.Join(big, fmt.Sprintf("f%05d", i)), nil, 0o600)
	}
	one := int64(1)
	j.c.Run.Limits.MaxArtifacts = one
	prevBatch, prevRead := dirBatch, readDirBatch
	t.Cleanup(func() { dirBatch, readDirBatch = prevBatch, prevRead })
	dirBatch = 8
	read := 0
	readDirBatch = func(fh *os.File, n int) ([]fs.DirEntry, error) {
		ents, err := prevRead(fh, n)
		read += len(ents)
		return ents, err
	}
	if _, err := j.checkOutput(); err == nil || !strings.Contains(err.Error(), "tar members") {
		t.Fatalf("err = %v, want the member-count refusal", err)
	}
	if limit := int(one) + int(tarMemberSlack) + 2*dirBatch + 2; read > limit {
		t.Fatalf("read %d entries before refusing; the limit allows %d", read, limit)
	}
}
