//go:build linux

package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/wmetcalf/blastbox/agent/internal/config"
	"github.com/wmetcalf/blastbox/agent/internal/conformance"
)

func nsjailHost(t *testing.T) Host {
	p := os.Getenv("BLASTBOX_NSJAIL")
	if p == "" {
		p = "/usr/local/bin/nsjail"
	}
	if _, err := os.Stat(p); err != nil {
		t.Skipf("nsjail not installed at %s", p)
	}
	h := Host{NsjailPath: p, AllowMissingAppArmor: true}
	for _, pol := range []string{"/etc/blastbox/seccomp.policy", filepath.Join(conformance.Dir(), "..", "..", "deploy", "seccomp", "blastbox.seccomp.policy")} {
		if _, err := os.Stat(pol); err == nil {
			h.SeccompPolicy = pol
			break
		}
	}
	if h.SeccompPolicy == "" {
		t.Skip("no KAFEL seccomp policy on this host (nsjail host would be insecure)")
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

// runNsjail runs argv through Command under a real nsjail with the given limits.
func runNsjail(t *testing.T, h Host, exe string, argv []string, lim Limits) ([]byte, error) {
	t.Helper()
	scratch := t.TempDir()
	cmd, err := Command(context.Background(), Nsjail, Request{
		ExecPaths: []string{exe}, Scratch: scratch, Nonce: "n0nce", AgentBin: testAgentBin,
		NsjailPath: h.NsjailPath, SeccompPolicy: h.SeccompPolicy, AllowMissingAppArmor: true,
	}, argv, lim)
	if err != nil {
		t.Fatal(err)
	}
	return cmd.CombinedOutput()
}

// The launcher used to pin RLIMIT_FSIZE (soft = hard) before exec'ing nsjail, which then failed
// to set its own, larger --rlimit_fsize (an unprivileged user cannot raise a hard limit): every
// real job died with exit 255 while the probe (which sets no file-size cap) stayed green.
func TestNsjailCommandRunsWithAFileSizeLimit(t *testing.T) {
	h := nsjailHost(t)
	out, err := runNsjail(t, h, "/usr/bin/true", []string{"/usr/bin/true"}, Limits{TimeoutS: 10, FSizeBytes: 50 << 20})
	if err != nil {
		t.Fatalf("a run with a file-size cap did not start: %v: %s", err, out)
	}
}

// The jail mounts the RESOLVED engine binary; a symlinked argv[0] outside /usr does not exist
// in the jail, so the run must exec the resolved path.
func TestNsjailCommandRunsASymlinkedEngine(t *testing.T) {
	h := nsjailHost(t)
	dir := t.TempDir()
	link := filepath.Join(dir, "engine")
	if err := os.Symlink("/usr/bin/true", link); err != nil {
		t.Fatal(err)
	}
	out, err := runNsjail(t, h, "/usr/bin/true", []string{link}, Limits{TimeoutS: 10})
	if err != nil {
		t.Fatalf("a symlinked engine did not run in the jail: %v: %s", err, out)
	}
}
