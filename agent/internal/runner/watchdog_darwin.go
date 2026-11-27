package runner

import (
	"context"
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
	ctx, cancel := context.WithTimeout(context.Background(), psTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/ps", "-axo", "pid=,pgid=,uid=,rss=").Output()
	if err != nil {
		return 0, err
	}
	me := os.Getuid()
	var total int64
	for _, ln := range strings.Split(string(out), "\n") {
		f := strings.Fields(ln)
		if len(f) == 0 {
			continue
		}
		if len(f) != 4 {
			return 0, fmt.Errorf("ps row %q", ln)
		}
		var v [4]int64
		for i := range f {
			n, err := strconv.ParseInt(f[i], 10, 64)
			if err != nil {
				return 0, fmt.Errorf("ps row %q: %v", ln, err)
			}
			v[i] = n
		}
		pid, g, uid, rss := int(v[0]), int(v[1]), int(v[2]), v[3]
		if g == pgid || (also != nil && uid == me && also(pid)) {
			total += rss
		}
	}
	return total, nil
}
