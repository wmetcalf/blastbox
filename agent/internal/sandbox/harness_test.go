package sandbox

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/wmetcalf/blastbox/agent/internal/config"
)

// fakeBuild is a sandbox stand-in: it runs the handshake shim (or, with skipShim, argv alone)
// UNSANDBOXED, so the probe's own bookkeeping branches can be exercised on any host.
func fakeBuild(skipShim bool) func(context.Context, Kind, Request, []string, Limits) (*exec.Cmd, error) {
	return func(ctx context.Context, _ Kind, req Request, argv []string, _ Limits) (*exec.Cmd, error) {
		var full []string
		if skipShim {
			full = argv
		} else {
			full = shimArgv(req.Nonce, req.Scratch+"/"+HandshakeName, argv)
		}
		cmd := exec.CommandContext(ctx, full[0], full[1:]...)
		cmd.Dir = req.Scratch
		return cmd, nil
	}
}

func fakeHost(skipShim bool) Host {
	return Host{AgentBin: testAgentBin, build: fakeBuild(skipShim)}
}

func verdictEngine(argv ...string) config.Engine {
	return config.Engine{Name: "e", Sandbox: "seatbelt", ProbeArgv: argv}
}

func TestCustomProbeMustPrintAllDeniedVerdict(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		argv   []string
		wantOK bool
		reason string
	}{
		{"true proves nothing", []string{"/usr/bin/true"}, false, "no verdict"},
		{"garbage output", []string{"/bin/sh", "-c", "echo hello"}, false, "not JSON"},
		{"one allowed", []string{"/bin/sh", "-c", `echo '{"read":"denied","connect":"ALLOWED","write":"denied"}'`}, false, "connect"},
		{"missing key", []string{"/bin/sh", "-c", `echo '{"read":"denied","connect":"denied"}'`}, false, "write"},
		{"all denied", []string{"/bin/sh", "-c", `echo '{"read":"denied","connect":"denied","write":"denied"}'`}, true, ""},
	}
	for _, c := range cases {
		r := fakeHost(false).Probe(ctx, verdictEngine(c.argv...))
		if r.OK != c.wantOK || (c.reason != "" && !strings.Contains(r.Reason, c.reason)) {
			t.Errorf("%s: OK=%v reason=%q", c.name, r.OK, r.Reason)
		}
	}
}

func TestProbeNeedsHandshake(t *testing.T) {
	r := fakeHost(true).Probe(context.Background(), verdictEngine("/bin/sh", "-c",
		`echo '{"read":"denied","connect":"denied","write":"denied"}'`))
	if r.OK || !strings.Contains(r.Reason, "handshake") {
		t.Fatalf("a run with no handshake must fail: %+v", r)
	}
}

func TestProbeFailsWhenListenerGotAConnection(t *testing.T) {
	// Unsandboxed built-in probe connects to the listener (and reads/writes freely).
	r := fakeHost(false).Probe(context.Background(), verdictEngine(testAgentBin, "__probe",
		"--read", "{canary}", "--connect", "{connect}", "--write", "{outside}"))
	if r.OK || !strings.Contains(r.Reason, "listener") {
		t.Fatalf("expected a listener-connection failure: %+v", r)
	}
}

func TestNsjailHostWithoutLayersIsInsecure(t *testing.T) {
	h := Host{NsjailPath: "/usr/local/bin/nsjail", AgentBin: testAgentBin}
	got := strings.Join(h.InsecurityReasons(), ",")
	if got != "seccomp_policy_missing,apparmor_missing" {
		t.Errorf("reasons = %q", got)
	}
	eng := config.Engine{Name: "e", Sandbox: "nsjail", SelftestArgv: []string{"/usr/bin/true"}}
	if r := h.Probe(context.Background(), eng); r.OK || !strings.Contains(r.Reason, "insecure nsjail host") {
		t.Errorf("probe must refuse an insecure host: %+v", r)
	}
	if r := h.SelfTest(context.Background(), eng); r.OK || !strings.Contains(r.Reason, "apparmor_missing") {
		t.Errorf("selftest must refuse an insecure host: %+v", r)
	}
	h.SeccompPolicy = "/etc/passwd"
	h.AllowMissingAppArmor = true
	if r := h.InsecurityReasons(); len(r) != 0 {
		t.Errorf("explicit opt-out should clear apparmor: %v", r)
	}
}

func TestCommandNeverAllowsEgress(t *testing.T) {
	pins := HostPins{AppArmorProfile: "p", Exists: map[string]bool{"/usr": true}, Symlinks: map[string]bool{}}
	cmd, err := Command(context.Background(), Nsjail, Request{
		ExecPaths: []string{"/usr/bin/true"}, Scratch: "/tmp/s", Nonce: "n", AgentBin: "/x/agent",
		NsjailPath: "/usr/local/bin/nsjail", Pins: &pins,
	}, []string{"/usr/bin/true"}, Limits{TimeoutS: 5})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range cmd.Args {
		if a == "--disable_clone_newnet" {
			t.Fatal("Command produced an egress-capable argv")
		}
	}
	if !contains(cmd.Args, "--iface_no_lo") {
		t.Error("expected the sealed net namespace flag")
	}
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Setpgid != true {
		t.Error("Setpgid not set")
	}
}
