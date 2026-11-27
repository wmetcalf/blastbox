package sandbox

import (
	"os"
	"strconv"
	"strings"
)

// ProcIdentity returns pid's start time (clock ticks since boot, /proc/<pid>/stat field 22):
// with the pid, it names one process; a pid alone may since have been reused.
func ProcIdentity(pid int) (int64, bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, false
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(s[i+1:]) // f[0] is field 3 (state); starttime is field 22
	if len(f) < 20 {
		return 0, false
	}
	n, err := strconv.ParseInt(f[19], 10, 64)
	return n, err == nil
}

// procGone reports whether pid no longer runs: absent, or a zombie awaiting its reaper.
func procGone(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return true
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	return i < 0 || i+2 >= len(s) || s[i+2] == 'Z' || s[i+2] == 'X'
}
