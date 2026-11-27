package runner

import (
	"os/exec"
	"strconv"
	"strings"
)

// groupRSSKiB sums the resident set (KiB) of every process in the process group, via ps: darwin
// does not enforce RLIMIT_AS and there is no cgo to call libproc. Seatbelt does not change the
// process group, so the group is the whole job.
func groupRSSKiB(pgid int) (int64, error) {
	out, err := exec.Command("/bin/ps", "-axo", "pgid=,rss=").Output()
	if err != nil {
		return 0, err
	}
	var total int64
	for _, ln := range strings.Split(string(out), "\n") {
		f := strings.Fields(ln)
		if len(f) != 2 {
			continue
		}
		if g, err := strconv.Atoi(f[0]); err != nil || g != pgid {
			continue
		}
		n, _ := strconv.ParseInt(f[1], 10, 64)
		total += n
	}
	return total, nil
}
