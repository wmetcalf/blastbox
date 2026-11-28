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

// argv[0] is exec'd as given: a multi-call binary or a venv launcher behind a symlink depends
// on the name it was invoked by. A symlinked argv[0] the jail cannot see gets the resolved
// file mounted AT that path rather than argv[0] rewritten to the target.
func TestNsjailCommandKeepsTheInvokedName(t *testing.T) {
	h := nsjailHost(t)
	real, link := t.TempDir(), t.TempDir()
	script := filepath.Join(real, "engine.sh")
	name := filepath.Join(link, "applet")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntest \"$0\" = '"+name+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(script, name); err != nil {
		t.Fatal(err)
	}
	resolved, _ := filepath.EvalSymlinks(script)
	out, err := runNsjail(t, h, resolved, []string{name}, Limits{TimeoutS: 10})
	if err != nil {
		t.Fatalf("the engine did not see the name it was invoked by: %v: %s", err, out)
	}
}

// An engine binary inside one of the engine's ro_paths was mounted twice, the file and then its
// directory over it; nsjail could not remount the shadowed file read-only and every job died
// before the handshake ("Launching child process failed"), while the probe stayed green.
func TestNsjailCommandRunsAnEngineInsideItsROPath(t *testing.T) {
	h := nsjailHost(t)
	dir := t.TempDir()
	script := filepath.Join(dir, "engine.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	scratch := t.TempDir()
	cmd, err := Command(context.Background(), Nsjail, Request{
		ExecPaths: []string{script}, ROPaths: []string{dir}, Scratch: scratch, Nonce: "n0nce",
		AgentBin: testAgentBin, NsjailPath: h.NsjailPath, SeccompPolicy: h.SeccompPolicy, AllowMissingAppArmor: true,
	}, []string{script}, Limits{TimeoutS: 10})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("an engine inside its ro_path did not run in the jail: %v: %s", err, out)
	}
	if b, _ := os.ReadFile(filepath.Join(scratch, HandshakeName)); string(b) != "n0nce" {
		t.Fatalf("handshake = %q", b)
	}
}
