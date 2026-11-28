//go:build darwin

package runner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wmetcalf/blastbox/agent/internal/sandbox"
)

// seatbeltFixture runs the real sandbox (sandbox-exec via the __launch launcher), which needs a
// blastbox-agent binary: BLASTBOX_AGENT_BIN.
func seatbeltFixture(t *testing.T, script string) *fixture {
	t.Helper()
	bin := os.Getenv("BLASTBOX_AGENT_BIN")
	if bin == "" {
		t.Skip("BLASTBOX_AGENT_BIN not set")
	}
	f := setup(t, script)
	f.r.build = nil
	f.r.Host = sandbox.Host{AgentBin: bin}
	// The engine script lives in its own tree: a read-only grant may not overlap the state dir.
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	sp := filepath.Join(dir, "engine.sh")
	if err := os.Rename(f.eng.Argv[1], sp); err != nil {
		t.Fatal(err)
	}
	f.eng.Argv[1] = sp
	f.eng.ROPaths = []string{dir}
	st, _ := filepath.EvalSymlinks(f.state)
	f.state = st
	return f
}

func alive(tag string) bool {
	out, _ := exec.Command("/bin/ps", "-axo", "command=").Output()
	return strings.Contains(string(out), tag)
}

// A child that setsid()s out of the run's process group is still the run's: it must be dead
// when Run returns, whatever the run's outcome.
func TestSeatbeltEscapeeIsSwept(t *testing.T) {
	for _, tc := range []struct{ name, tail string }{
		{"exit0", `printf '{}' > "$1/metadata.json"`},
		{"deadline", `sleep 60`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tag := fmt.Sprintf("347.%d", time.Now().UnixNano()%1000000)
			f := seatbeltFixture(t, fmt.Sprintf(
				`/usr/bin/perl -e 'use POSIX; if (fork() == 0) { POSIX::setsid(); exec("/bin/sleep", "%s"); }'
sleep 1
%s`, tag, tc.tail))
			f.claim.Run.DeadlineS = 4
			t.Cleanup(func() { exec.Command("/usr/bin/pkill", "-f", tag).Run() })
			res := f.run()
			t.Logf("result %+v", res)
			if res.Outcome == "released" {
				t.Fatalf("the engine never ran: %+v", res)
			}
			if alive(tag) {
				t.Fatalf("the setsid()'d child (sleep %s) outlived the run", tag)
			}
			if res.Outcome == "failed" && strings.HasPrefix(res.Reason, "sandbox") {
				t.Fatalf("the sweep itself failed: %+v", res)
			}
		})
	}
}

// The memory watchdog counts a setsid()'d child of the run.
func TestSeatbeltWatchdogCountsEscapee(t *testing.T) {
	f := seatbeltFixture(t,
		`/usr/bin/perl -e 'use POSIX; if (fork() == 0) { POSIX::setsid(); my $b = "x" x (300 << 20); sleep 30; }'
sleep 30`)
	mib := 64
	f.eng.MaxRSSMiB = &mib
	f.claim.Run.DeadlineS = 20
	t0 := time.Now()
	res := f.run()
	if res.Outcome != "failed" || !strings.Contains(res.Reason, "memory cap exceeded") {
		t.Fatalf("result %+v after %s, want memory cap exceeded", res, time.Since(t0))
	}
}

// An engine may set uchg (seatbelt leaves file flags settable in scratch); the job dir must
// still be wiped once the run is over.
func TestSeatbeltImmutableScratchIsWiped(t *testing.T) {
	f := seatbeltFixture(t, `printf x > "$HOME/locked" && /usr/bin/chflags uchg "$HOME/locked" && mkdir "$HOME/d" && /usr/bin/chflags uchg "$HOME/d"
printf '{}' > "$1/metadata.json"`)
	res := f.run()
	t.Logf("result %+v", res)
	if res.Outcome == "released" {
		t.Fatalf("the engine never ran: %+v", res)
	}
	jobs := filepath.Join(f.state, "jobs")
	t.Cleanup(func() { exec.Command("/usr/bin/chflags", "-R", "nouchg", jobs).Run() })
	ents, _ := os.ReadDir(jobs)
	for _, e := range ents {
		t.Errorf("job dir %s left behind", e.Name())
	}
}

// A seatbelt run gets RLIMIT_NPROC = the uid's process count + nprocAllowance (darwin counts
// the whole uid), so a fork bomb is stopped by the kernel, not the next watchdog sample.
func TestSeatbeltRunHasAProcessLimit(t *testing.T) {
	var counted int64
	prev := uidProcs
	uidProcs = func() (int64, error) { n, err := prev(); counted = n; return n, err }
	t.Cleanup(func() { uidProcs = prev })
	f := seatbeltFixture(t, `echo "nproc=$(ulimit -u)" >&2; exit 3`)
	var logs []string
	f.r.Logf = func(format string, a ...any) { logs = append(logs, fmt.Sprintf(format, a...)) }
	res := f.run()
	all := strings.Join(logs, "\n")
	if res.Outcome != "failed" || !strings.Contains(all, "nproc=") {
		t.Fatalf("result %+v, logs %s", res, all)
	}
	want := fmt.Sprintf("nproc=%d", counted+nprocAllowance)
	if !strings.Contains(all, want) {
		t.Fatalf("engine saw %s, want %s (or lower, if the kernel clamped it)", all, want)
	}
}
