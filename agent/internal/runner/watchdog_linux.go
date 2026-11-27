package runner

import (
	"os"
	"strconv"
	"strings"
)

var pageKiB = int64(os.Getpagesize()) / 1024

// groupRSSKiB sums the resident set of the job: the process group leader's group plus every
// descendant of the leader (an nsjail child calls setsid, so it leaves the group but stays in
// the leader's process tree). It reads /proc directly: no cgo, no helper binary. also is the
// darwin sandbox identity and is not needed here: nsjail's PID namespace keeps every descendant
// in the tree.
func groupRSSKiB(pgid int, also func(pid int) bool) (int64, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	type proc struct {
		ppid, pgrp int
		rss        int64
	}
	procs := map[int]proc{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		// comm may contain spaces and parens: fields start after the LAST ')'.
		s := string(b)
		i := strings.LastIndexByte(s, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(s[i+1:]) // f[0]=state f[1]=ppid f[2]=pgrp
		if len(f) < 3 {
			continue
		}
		ppid, _ := strconv.Atoi(f[1])
		pgrp, _ := strconv.Atoi(f[2])
		var rss int64
		if m, err := os.ReadFile("/proc/" + e.Name() + "/statm"); err == nil {
			if sf := strings.Fields(string(m)); len(sf) >= 2 {
				n, _ := strconv.ParseInt(sf[1], 10, 64)
				rss = n * pageKiB
			}
		}
		procs[pid] = proc{ppid, pgrp, rss}
	}
	in := map[int]bool{pgid: true}
	for changed := true; changed; {
		changed = false
		for pid, p := range procs {
			if !in[pid] && (p.pgrp == pgid || in[p.ppid]) {
				in[pid] = true
				changed = true
			}
		}
	}
	var total int64
	for pid := range in {
		total += procs[pid].rss
	}
	return total, nil
}
