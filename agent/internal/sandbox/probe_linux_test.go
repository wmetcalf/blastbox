//go:build linux

package sandbox

import (
	"context"
	"os"
	"os/exec"
	"testing"

	"github.com/wmetcalf/blastbox/agent/internal/config"
)

func nsjailHost(t *testing.T) Host {
	p := os.Getenv("BLASTBOX_NSJAIL")
	if p == "" {
		p = "/usr/local/bin/nsjail"
	}
	if _, err := os.Stat(p); err != nil {
		t.Skipf("nsjail not installed at %s", p)
	}
	h := Host{NsjailPath: p}
	if _, err := os.Stat("/etc/blastbox/seccomp.policy"); err == nil {
		h.SeccompPolicy = "/etc/blastbox/seccomp.policy"
	}
	// Does a bare jail start here (user namespaces may be blocked)?
	out, err := exec.Command(p, "--mode", "o", "--quiet", "--really_quiet", "--user", "65534", "--group", "65534",
		"--bindmount_ro", "/usr:/usr", "--symlink", "usr/bin:/bin", "--symlink", "usr/lib:/lib", "--symlink", "usr/lib64:/lib64",
		"--", "/usr/bin/true").CombinedOutput()
	if err != nil {
		t.Skipf("nsjail cannot start here (userns blocked?): %v: %s", err, out)
	}
	return h
}

func TestProbeDeniesUnderNsjail(t *testing.T) { sandboxProofs(t, nsjailHost(t), "nsjail") }

func TestNsjailCommandRunsUnderLauncher(t *testing.T) {
	h := nsjailHost(t)
	eng := config.Engine{Name: "x", Sandbox: "nsjail", SelftestArgv: []string{"/bin/sh", "-c", "test \"$HOME\" = \"$TMPDIR\" && test \"$LANG\" = C && test -z \"$SECRET_TOKEN\""}}
	t.Setenv("SECRET_TOKEN", "leak")
	h.AgentBin = testAgentBin
	if r := h.SelfTest(context.Background(), eng); !r.OK {
		t.Fatalf("env check inside the jail: %s", r.Reason)
	}
}
