package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// psTimeout bounds one memory sample: the supervisor's select cannot service the deadline while
// a sample runs, so a slow or wedged ps must turn into a failed sample, not a stalled kill.
const psTimeout = 5 * time.Second

// groupRSSKiB sums the resident set (KiB) of the job, via ps: darwin does not enforce RLIMIT_AS
// and there is no cgo to call libproc. The job is its process group plus any process of this
// uid that also matches (the run's sandbox identity): a child that setsid()s leaves the group
// but not the sandbox. A ps that fails, times out or prints a row it cannot parse is an error
// (the watchdog fails closed on repeated errors), never a smaller sum.
func groupRSSKiB(pgid int, also func(pid int) bool) (int64, error) {
	procs, err := groupProcs(pgid, also)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, rss := range procs {
		total += rss
	}
	return total, nil
}

// groupProcs returns the job's processes (see groupRSSKiB) with their resident set in KiB.
func groupProcs(pgid int, also func(pid int) bool) (map[int]int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), psTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/ps", "-axo", "pid=,pgid=,uid=,rss=").Output()
	if err != nil {
		return nil, err
	}
	me := os.Getuid()
	procs := map[int]int64{}
	for _, ln := range strings.Split(string(out), "\n") {
		f := strings.Fields(ln)
		if len(f) == 0 {
			continue
		}
		if len(f) != 4 {
			return nil, fmt.Errorf("ps row %q", ln)
		}
		var v [4]int64
		for i := range f {
			n, err := strconv.ParseInt(f[i], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("ps row %q: %v", ln, err)
			}
			v[i] = n
		}
		pid, g, uid, rss := int(v[0]), int(v[1]), int(v[2]), v[3]
		if g == pgid || (also != nil && uid == me && also(pid)) {
			procs[pid] = rss
		}
	}
	return procs, nil
}

// lsofTimeout bounds one held-file sample, as psTimeout does a memory sample.
const lsofTimeout = 5 * time.Second

// heldUnlinkedBytes is what the run's processes hold in files under roots that they have
// unlinked (open or mapped, link count 0), via lsof: no cgo to call libproc. Each file is
// charged once, at its size. A failing or unparseable lsof is an error (the watchdog fails
// closed on repeated errors), never a smaller sum.
func heldUnlinkedBytes(pids []int, roots []string) (int64, error) {
	if len(pids) == 0 {
		return 0, nil
	}
	ps := make([]string, len(pids))
	for i, p := range pids {
		ps[i] = strconv.Itoa(p)
	}
	ctx, cancel := context.WithTimeout(context.Background(), lsofTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/sbin/lsof", "-n", "-P", "-w", "+L1", "-a", "-p", strings.Join(ps, ","), "-F", "Dins")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	// lsof exits 1 when nothing matched (no unlinked file held, or every pid gone).
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 1 || stderr.Len() > 0 {
			return 0, fmt.Errorf("lsof: %v: %s", err, strings.TrimSpace(stderr.String()))
		}
	}
	held := map[string]int64{}
	var dev, ino string
	var size int64
	for _, ln := range strings.Split(string(out), "\n") {
		if ln == "" {
			continue
		}
		switch ln[0] {
		case 'p', 'f':
			dev, ino, size = "", "", 0 // a new process or file set
		case 'D':
			dev = ln[1:]
		case 'i':
			ino = ln[1:]
		case 's':
			n, err := strconv.ParseInt(ln[1:], 10, 64)
			if err != nil {
				return 0, fmt.Errorf("lsof row %q", ln)
			}
			size = n
		case 'n':
			if underRoots(ln[1:], roots) {
				k := dev + ":" + ino
				if dev == "" || ino == "" {
					k = ln // no identity: charge it by name
				}
				if size > held[k] {
					held[k] = size
				}
			}
		}
	}
	var total int64
	for _, n := range held {
		total += n
	}
	return total, nil
}
