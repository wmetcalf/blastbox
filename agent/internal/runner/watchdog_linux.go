package runner

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"syscall"
)

var pageKiB = int64(os.Getpagesize()) / 1024

// groupRSSKiB sums the resident set of the job: the process group leader's group plus every
// descendant of the leader (an nsjail child calls setsid, so it leaves the group but stays in
// the leader's process tree). It reads /proc directly: no cgo, no helper binary. also is the
// darwin sandbox identity and is not needed here: nsjail's PID namespace keeps every descendant
// in the tree.
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
func groupProcs(pgid int, _ func(pid int) bool) (map[int]int64, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
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
	out := make(map[int]int64, len(in))
	for pid := range in {
		if p, ok := procs[pid]; ok {
			out[pid] = p.rss
		}
	}
	return out, nil
}

// heldUnlinkedBytes is what the run's processes hold in files under roots that they have
// unlinked: open descriptors and file mappings still pin those blocks, which no directory
// walk can see. A member that exits mid-scan is skipped; any other read failure is an error
// (the watchdog fails closed on repeated errors). Each file is charged once.
func heldUnlinkedBytes(pids []int, roots []string) (int64, error) {
	const deleted = " (deleted)"
	held := map[[2]uint64]int64{} // (dev, inode) -> the most any view of it showed
	charge := func(dev, ino uint64, n int64) {
		if k := [2]uint64{dev, ino}; n > held[k] {
			held[k] = n
		}
	}
	for _, pid := range pids {
		base := "/proc/" + strconv.Itoa(pid)
		fds, err := os.ReadDir(base + "/fd")
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
				continue
			}
			return 0, err
		}
		for _, e := range fds {
			fp := base + "/fd/" + e.Name()
			link, err := os.Readlink(fp)
			if err != nil || !strings.HasSuffix(link, deleted) || !underRoots(strings.TrimSuffix(link, deleted), roots) {
				continue
			}
			var st syscall.Stat_t
			if syscall.Stat(fp, &st) != nil {
				continue // closed since it was listed
			}
			charge(uint64(st.Dev), st.Ino, int64(st.Blocks)*512)
		}
		maps, err := os.ReadFile(base + "/maps")
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
				continue
			}
			return 0, err
		}
		// A mapping keeps its file after the descriptor is closed: charge its extent
		// (offset + length).
		for _, ln := range strings.Split(string(maps), "\n") {
			if !strings.HasSuffix(ln, deleted) {
				continue
			}
			f := strings.Fields(ln)
			if len(f) < 6 {
				continue
			}
			if !underRoots(strings.TrimSuffix(strings.Join(f[5:], " "), deleted), roots) {
				continue
			}
			lo, hi, ok1 := strings.Cut(f[0], "-")
			maj, min, ok2 := strings.Cut(f[3], ":")
			a, err1 := strconv.ParseUint(lo, 16, 64)
			b, err2 := strconv.ParseUint(hi, 16, 64)
			off, err3 := strconv.ParseUint(f[2], 16, 64)
			ino, err4 := strconv.ParseUint(f[4], 10, 64)
			ma, err5 := strconv.ParseUint(maj, 16, 64)
			mi, err6 := strconv.ParseUint(min, 16, 64)
			if !ok1 || !ok2 || errors.Join(err1, err2, err3, err4, err5, err6) != nil || b < a {
				return 0, fmt.Errorf("maps row %q", ln)
			}
			charge(mkdev(ma, mi), ino, int64(off+(b-a)))
		}
	}
	var total int64
	for _, n := range held {
		total += n
	}
	return total, nil
}

// mkdev is glibc's makedev: the st_dev encoding of a major:minor pair.
func mkdev(major, minor uint64) uint64 {
	return (minor & 0xff) | ((major & 0xfff) << 8) | ((minor &^ 0xff) << 12) | ((major &^ 0xfff) << 32)
}

// uidProcCount counts this uid's processes (used for a seatbelt run, i.e. darwin; nsjail sets
// its own --rlimit_nproc).
func uidProcCount() (int64, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	me := uint32(os.Getuid())
	var n int64
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		var st syscall.Stat_t
		if syscall.Stat("/proc/"+e.Name(), &st) == nil && st.Uid == me {
			n++
		}
	}
	if n == 0 {
		return 0, errors.New("no process of this uid in /proc")
	}
	return n, nil
}
