package sandbox

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	sweepQuietRounds = 3                // consecutive conclusive empty rounds before the run is gone
	sweepRounds      = 400              // rounds that may kill, meet the unknown, or find nothing
	sweepSettle      = 30 * time.Second // how long a killed or unreadable process is waited out
)

// Match reports whether pid is one of this run's processes (see RunIdentity).
func (id RunIdentity) Match(pid int) bool {
	st, ok := procStart(pid)
	return ok && id.matchStarted(pid, st)
}

func (id RunIdentity) matchStarted(pid int, startUsec int64) bool {
	if id.Scratch == "" || id.Canary == "" || startUsec < id.StartedAfter.UnixMicro() || !isSandboxed(pid) {
		return false
	}
	if fi, err := os.Lstat(id.Scratch); err != nil || !fi.IsDir() {
		return false
	}
	return mayWrite(pid, id.Scratch) && mayLookup(pid, id.Canary) && !mayUseNetwork(pid)
}

// procState is "gone", "zombie", "exiting" or "alive" (also when ps fails: never "gone" on doubt).
func procState(pid int) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
	s := strings.TrimSpace(string(out))
	if err != nil && s == "" {
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			return "gone" // ps -p exits 1 when the pid does not exist
		}
		return "alive"
	}
	switch {
	case s == "":
		return "gone"
	case strings.HasPrefix(s, "Z"):
		return "zombie"
	case strings.Contains(s[1:], "E"):
		return "exiting"
	}
	return "alive"
}

// restoreScratch puts a real directory back at the scratch path if the run removed it or swapped
// it for something else: the identity is a path-based write grant, so a fresh directory at the
// same path identifies the run's processes again.
func restoreScratch(p string) error {
	fi, err := os.Lstat(p)
	if err == nil && fi.IsDir() {
		return nil
	}
	if err == nil {
		if rerr := os.Remove(p); rerr != nil {
			return errorf("cannot restore %s: %v", p, rerr)
		}
	}
	if err := os.Mkdir(p, 0o700); err != nil && !os.IsExist(err) {
		return errorf("cannot restore %s: %v", p, err)
	}
	if fi, err := os.Lstat(p); err != nil || !fi.IsDir() {
		return errorf("cannot restore %s", p)
	}
	return nil
}

// SweepRun SIGKILLs every process of this uid that carries the run's sandbox, until none is
// left (a port of macos_common.sweep_sandboxed with writer_matcher). It returns how many it
// killed, or an error when the run's processes cannot be shown gone: such a run must not be
// reported as finished, nor its output collected.
func SweepRun(id RunIdentity) (int, error) {
	if id.Scratch == "" || id.Canary == "" {
		return 0, errorf("run identity incomplete")
	}
	me, uid := os.Getpid(), os.Getuid()
	type ident struct {
		pid   int
		start int64
	}
	killed := map[ident]time.Time{}
	unreadable := map[int]time.Time{}
	quiet, budget := 0, sweepRounds
	for {
		if err := restoreScratch(id.Scratch); err != nil {
			return len(killed), err
		}
		pids, err := procListUIDPids(uid)
		if err != nil {
			return len(killed), errorf("cannot enumerate processes: %v", err)
		}
		now := time.Now()
		live, inconclusive, waiting, fresh, newKill := 0, false, false, false, false
		for _, p := range pids {
			if p == me {
				continue
			}
			st, ok := procStart(p)
			if !ok {
				switch procState(p) {
				case "zombie", "exiting":
					continue // can't run any more: holds no grant
				case "gone":
					inconclusive = true // exited between listing and identifying
					continue
				}
				if _, ok2 := procStart(p); !ok2 && isSandboxed(p) {
					t, seen := unreadable[p]
					if !seen {
						unreadable[p], fresh = now, true
					} else if now.Sub(t) > sweepSettle {
						return len(killed), errorf("cannot identify sandboxed process %d", p)
					}
					waiting = true
					continue
				}
				inconclusive = true
				continue
			}
			if !id.matchStarted(p, st) {
				if s2, ok2 := procStart(p); !ok2 || s2 != st {
					inconclusive = true // exited (or was replaced) while being matched
				}
				continue
			}
			k := ident{p, st}
			if t, was := killed[k]; was {
				if procState(p) != "alive" {
					continue // killed, awaiting its reaper
				}
				if now.Sub(t) > sweepSettle {
					return len(killed), errorf("process %d is still alive %s after SIGKILL", p, sweepSettle)
				}
				live++
				waiting = true
				continue
			}
			// Revalidate right before signalling: a pid reused since the match is not killed.
			if s2, ok2 := procStart(p); ok2 && s2 == st {
				syscall.Kill(p, syscall.SIGKILL)
				killed[k], newKill = now, true
			} else {
				inconclusive = true
			}
			live++
		}
		if live == 0 {
			if inconclusive || waiting {
				quiet = 0
			} else if quiet++; quiet >= sweepQuietRounds {
				return len(killed), nil
			}
		} else {
			quiet = 0
		}
		if newKill || fresh || inconclusive || (!waiting && live == 0) {
			if budget--; budget <= 0 {
				return len(killed), errorf("could not show the run's processes gone")
			}
		}
		d := 5 * time.Millisecond
		if waiting || (live > 0 && !newKill) {
			d = 50 * time.Millisecond
		}
		time.Sleep(d)
	}
}
