package sandbox

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/wmetcalf/blastbox/agent/internal/config"
)

func TestRunProbeUsageAndVerdicts(t *testing.T) {
	var b bytes.Buffer
	if code := RunProbe(nil, &b); code != 2 {
		t.Errorf("no args: exit %d", code)
	}
	// Denied everything: unreadable path, refused port, uncreatable path.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close() // nothing listens now: connect is refused
	b.Reset()
	code := RunProbe([]string{"--read", "/nonexistent/x", "--connect", addr, "--write", "/nonexistent/y"}, &b)
	if code != 0 || !strings.Contains(b.String(), `"ok":true`) {
		t.Errorf("all denied: exit %d %s", code, b.String())
	}
}

// Proves the probe can fail: unsandboxed, every access succeeds, so it must report not-OK.
func TestProbeFailsWithoutSandbox(t *testing.T) {
	dir := t.TempDir()
	canary := filepath.Join(dir, "canary")
	os.WriteFile(canary, []byte("c"), 0o644)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	out, err := exec.Command(testAgentBin, "__probe", "--read", canary, "--connect", ln.Addr().String(),
		"--write", filepath.Join(dir, "w")).CombinedOutput()
	ee, ok := err.(*exec.ExitError)
	if !ok || ee.ExitCode() != 1 {
		t.Fatalf("unsandboxed probe must exit 1, got err=%v out=%s", err, out)
	}
	for _, k := range []string{`"read":"ALLOWED"`, `"connect":"ALLOWED"`, `"write":"ALLOWED"`, `"ok":false`} {
		if !strings.Contains(string(out), k) {
			t.Errorf("verdict missing %s: %s", k, out)
		}
	}
}

func TestProbeRefusesEngineWithoutSandbox(t *testing.T) {
	h := Host{AgentBin: testAgentBin}
	r := h.Probe(context.Background(), config.Engine{Name: "e", Sandbox: "none"})
	if r.OK {
		t.Fatal("sandbox none must not pass a confinement proof")
	}
}

func TestLaunchAppliesRlimit(t *testing.T) {
	out, err := exec.Command(testAgentBin, "__launch", "--rlimit-nofile", "77", "--", "/bin/sh", "-c", "ulimit -n").CombinedOutput()
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if strings.TrimSpace(string(out)) != "77" {
		t.Errorf("ulimit -n = %q, want 77", out)
	}
	if err := RunLaunch([]string{"--bogus", "1", "--", "/bin/true"}); err == nil {
		t.Error("unknown flag must be refused")
	}
	if err := RunLaunch([]string{"--rlimit-cpu", "1"}); err == nil {
		t.Error("missing command must be refused")
	}
}

// shared body: a real sandbox proves the probe passes and a self-test gates correctly.
func sandboxProofs(t *testing.T, h Host, sandbox string) {
	h.AgentBin = testAgentBin
	eng := config.Engine{Name: "probe-" + sandbox, Sandbox: sandbox}
	r := h.Probe(context.Background(), eng)
	if !r.OK {
		t.Fatalf("probe under %s must pass: %s", sandbox, r.Reason)
	}
	if r.At.IsZero() {
		t.Error("At not set")
	}
	good := config.Engine{Name: "st", Sandbox: sandbox, SelftestArgv: []string{"/usr/bin/true"}}
	if r := h.SelfTest(context.Background(), good); !r.OK {
		t.Errorf("selftest /usr/bin/true: %s", r.Reason)
	}
	bad := config.Engine{Name: "st", Sandbox: sandbox, SelftestArgv: []string{"/usr/bin/false"}}
	if r := h.SelfTest(context.Background(), bad); r.OK {
		t.Error("selftest /usr/bin/false must not pass")
	}
	none := config.Engine{Name: "st", Sandbox: sandbox}
	if r := h.SelfTest(context.Background(), none); r.OK {
		t.Error("missing selftest_argv must not pass")
	}
}

// KillRun stops the recorded run, and never a process whose pid matches but whose identity
// does not (the pid was reused).
func TestKillRunGuardsPidReuse(t *testing.T) {
	start := func() *exec.Cmd {
		c := exec.Command("/bin/sh", "-c", "sleep 60 & sleep 60")
		c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { syscall.Kill(-c.Process.Pid, syscall.SIGKILL); c.Wait() })
		return c
	}
	other := start()
	id, ok := ProcIdentity(other.Process.Pid)
	if !ok {
		t.Fatal("no identity")
	}
	if err := KillRun(RunRecord{PID: other.Process.Pid, Identity: id + 1}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if syscall.Kill(other.Process.Pid, 0) != nil {
		t.Fatal("killed a process whose identity does not match the record")
	}
	mine := start()
	id, _ = ProcIdentity(mine.Process.Pid)
	if err := KillRun(RunRecord{PID: mine.Process.Pid, Identity: id}); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { mine.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the recorded run survived KillRun")
	}
}
