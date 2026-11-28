package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDirUsageCountsBlocksEntriesAndHardLinksOnce(t *testing.T) {
	root := t.TempDir()
	os.Mkdir(filepath.Join(root, "d"), 0o700)
	big := filepath.Join(root, "d", "big")
	os.WriteFile(big, make([]byte, 1<<20), 0o600)
	os.Link(big, filepath.Join(root, "d", "again"))
	os.Symlink("/etc", filepath.Join(root, "link")) // counted as itself, never followed
	used, entries, complete := dirUsage([]string{root}, 100)
	if !complete || entries != 4 {
		t.Fatalf("entries=%d complete=%v", entries, complete)
	}
	if used < 1<<20 || used > 1<<20+1<<16 {
		t.Fatalf("used=%d, want about 1 MiB (the hard link charged once)", used)
	}
	if _, n, _ := dirUsage([]string{root}, 2); n != 3 {
		t.Fatalf("the walk did not stop just past the entry cap: %d", n)
	}
}

// A directory the run hid (chmod 000) is unmeasured, which fails closed.
func TestDirUsageUnreadableIsIncomplete(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads anything")
	}
	root := t.TempDir()
	h := filepath.Join(root, "hidden")
	os.Mkdir(h, 0o700)
	os.WriteFile(filepath.Join(h, "f"), make([]byte, 4096), 0o600)
	os.Chmod(h, 0)
	t.Cleanup(func() { os.Chmod(h, 0o700) })
	if _, _, complete := dirUsage([]string{root}, 100); complete {
		t.Fatal("an unreadable directory was measured as complete")
	}
}

// diskFixture is a run whose budget is 1 MiB above a tiny output floor.
func diskFixture(t *testing.T, script string) *fixture {
	f := setup(t, script)
	mib := 1
	f.eng.MaxDiskMiB = &mib
	f.claim.Run.Limits.MaxTotalArtifacts = 1 << 20
	f.claim.Run.Limits.MaxMetadata = 1 << 16
	return f
}

// The floor of the budget in diskFixture: 1 MiB + 64 KiB + 64 MiB.
const diskFloorMiB = 66

func TestDiskWatchdogKillsARunFillingScratch(t *testing.T) {
	f := diskFixture(t, fmt.Sprintf(`i=0; while [ $i -lt %d ]; do head -c 1048576 /dev/zero > "$3/f$i"; i=$((i+1)); done; sleep 20`, diskFloorMiB+8))
	f.r.DiskPoll = 20 * time.Millisecond
	t0 := time.Now()
	res := f.run()
	f.wantFail(t, res, "disk budget exceeded")
	if time.Since(t0) > 15*time.Second {
		t.Fatalf("killed only after %s", time.Since(t0))
	}
}

// A burst written after the last sample, just before a clean exit, is caught after the run.
func TestDiskBudgetCheckedAfterTheRun(t *testing.T) {
	f := diskFixture(t, fmt.Sprintf(`out="$1"; i=0; while [ $i -lt %d ]; do head -c 1048576 /dev/zero > "$3/f$i"; i=$((i+1)); done
printf '{}' > "$out/metadata.json"`, diskFloorMiB+8))
	f.r.DiskPoll = time.Hour
	res := f.run()
	f.wantFail(t, res, "after the run")
}

// Files the run unlinked but still holds open count against the budget.
func TestDiskWatchdogCountsHeldUnlinkedFiles(t *testing.T) {
	f := diskFixture(t, fmt.Sprintf(`exec 3>"$3/held"; rm "$3/held"; head -c %d /dev/zero >&3; sleep 20`, (diskFloorMiB+8)<<20))
	f.r.DiskPoll = 20 * time.Millisecond
	res := f.run()
	f.wantFail(t, res, "disk budget exceeded")
}

func TestDiskWatchdogFailsClosedWhenItCannotMeasure(t *testing.T) {
	f := diskFixture(t, `sleep 20`)
	f.r.DiskPoll = 10 * time.Millisecond
	f.r.held = func([]int, []string) (int64, error) { return 0, fmt.Errorf("lsof broke") }
	res := f.run()
	f.wantFail(t, res, "disk watchdog unavailable")
}

func TestDiskEntryCap(t *testing.T) {
	prev := maxDiskEntries
	maxDiskEntries = 50
	t.Cleanup(func() { maxDiskEntries = prev })
	f := diskFixture(t, `i=0; while [ $i -lt 80 ]; do : > "$3/e$i"; i=$((i+1)); done; sleep 20`)
	f.r.DiskPoll = 20 * time.Millisecond
	res := f.run()
	f.wantFail(t, res, "entries")
	if !strings.Contains(res.Reason, "disk budget") {
		t.Fatal(res.Reason)
	}
}
