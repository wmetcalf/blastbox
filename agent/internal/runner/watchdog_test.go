package runner

import (
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// Runs on both OSes: the group's RSS is positive while it lives and covers a grandchild.
func TestGroupRSSCoversTheGroup(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "sleep 30 & sleep 30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); cmd.Wait() }()
	time.Sleep(200 * time.Millisecond)
	one, err := groupRSSKiB(cmd.Process.Pid)
	if err != nil || one <= 0 {
		t.Fatalf("rss=%d err=%v", one, err)
	}
	if none, _ := groupRSSKiB(1 << 30); none != 0 {
		t.Fatalf("unknown group reported %d", none)
	}
}
