package runner

import (
	"os/exec"
	"syscall"
	"testing"

	"github.com/wmetcalf/blastbox/agent/internal/sandbox"
)

// The group is signalled only while its leader is the process that was started: a reaped
// leader (its number free for reuse) or another process under that pid is never signalled.
func TestKillGroupOnlyWhileTheLeaderIsTheRun(t *testing.T) {
	start := func() *exec.Cmd {
		c := exec.Command("/bin/sleep", "30")
		c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Process.Kill(); c.Wait() })
		return c
	}
	c := start()
	id, ok := sandbox.ProcIdentity(c.Process.Pid)
	if !ok {
		t.Skip("no process identity on this host")
	}
	if killGroupOf(c.Process.Pid, id+1) {
		t.Fatal("signalled a group whose leader is not the run's process")
	}
	if !killGroupOf(c.Process.Pid, id) {
		t.Fatal("did not signal the run's own group")
	}
	c.Wait() // reaped: the number may be reused from here on
	if killGroupOf(c.Process.Pid, id) {
		t.Fatal("signalled the group of a reaped leader")
	}
}
