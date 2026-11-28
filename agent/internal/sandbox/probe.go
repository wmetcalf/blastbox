package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wmetcalf/blastbox/agent/internal/config"
)

// ProbeResult is the verdict of a confinement proof; it gates claiming.
type ProbeResult struct {
	OK     bool
	Reason string
	At     time.Time
}

// Host carries the host-level inputs the proofs need.
type Host struct {
	AgentBin             string // blastbox-agent binary; "" = os.Executable()
	NsjailPath           string // linux
	SeccompPolicy        string // required for nsjail; "" or missing = insecure
	AppArmorProfile      string // nsjail: operator-declared profile; proven by an aa-exec probe
	AllowMissingAppArmor bool   // operator accepts a host with no usable AppArmor profile
	ScratchBase          string // "" = os.TempDir()
	Timeout              time.Duration

	build func(context.Context, Kind, Request, []string, Limits) (*exec.Cmd, error) // test seam; nil = Command
}

// DefaultHost is used by the package-level Probe and SelfTest.
var DefaultHost = Host{NsjailPath: "/usr/local/bin/nsjail"}

// HostFromConfig builds the Host for a loaded config (nsjail layers come from [nsjail]).
func HostFromConfig(c *config.Config) Host {
	h := Host{}
	if c.Nsjail != nil {
		h.NsjailPath, h.SeccompPolicy = c.Nsjail.Path, c.Nsjail.SeccompPolicy
		h.AppArmorProfile, h.AllowMissingAppArmor = c.Nsjail.AppArmorProfile, c.Nsjail.AllowMissingAppArmor
	}
	return h
}

func Probe(ctx context.Context, eng config.Engine) ProbeResult { return DefaultHost.Probe(ctx, eng) }
func SelfTest(ctx context.Context, eng config.Engine) ProbeResult {
	return DefaultHost.SelfTest(ctx, eng)
}

// apparmorAttaches reports whether the declared profile can be attached on this host. securityfs
// is root-only, so (like blastbox's apparmor.py for a non-root worker) the profile is the
// operator's declaration and is PROVEN by running `aa-exec -p <profile> -- /usr/bin/true`: an
// unloaded profile makes aa-exec fail, whatever the reason.
func (h Host) apparmorAttaches() (bool, string) {
	if h.AppArmorProfile == "" {
		return false, "no apparmor_profile configured"
	}
	aa := DetectHostPins().AAExec
	if aa == "" {
		return false, "aa-exec not found"
	}
	true_ := "/usr/bin/true"
	if _, err := os.Stat(true_); err != nil {
		true_ = "/bin/true"
	}
	if out, err := exec.Command(aa, "-p", h.AppArmorProfile, "--", true_).CombinedOutput(); err != nil {
		return false, fmt.Sprintf("aa-exec -p %s failed: %v: %s", h.AppArmorProfile, err, strings.TrimSpace(string(out)))
	}
	return true, ""
}

// InsecurityReasons lists why the nsjail backend would run with a missing layer, mirroring
// nsjail.py: "seccomp_policy_missing" and "apparmor_missing" (the latter waived only by an
// explicit allow_missing_apparmor). Probe and SelfTest refuse while any reason is present.
func (h Host) InsecurityReasons() []string {
	var reasons []string
	if st, err := os.Stat(h.SeccompPolicy); h.SeccompPolicy == "" || err != nil || !st.Mode().IsRegular() {
		reasons = append(reasons, "seccomp_policy_missing")
	}
	if ok, _ := h.apparmorAttaches(); !ok && !h.AllowMissingAppArmor {
		reasons = append(reasons, "apparmor_missing")
	}
	return reasons
}

func (h Host) layers(kind Kind) string {
	if kind != Nsjail {
		return "seatbelt"
	}
	l := "nsjail+seccomp"
	if ok, _ := h.apparmorAttaches(); ok {
		return l + "+apparmor(" + h.AppArmorProfile + ")"
	}
	return l + " (apparmor ABSENT, allowed by operator)"
}

// RunProbe is `blastbox-agent __probe --read F --connect HOST:PORT --write P`. It attempts all
// three and exits 0 only if ALL are denied, printing a one-line JSON verdict.
func RunProbe(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("__probe", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	read := fs.String("read", "", "file that must not be readable")
	connect := fs.String("connect", "", "host:port that must not be reachable")
	write := fs.String("write", "", "path that must not be creatable")
	if err := fs.Parse(args); err != nil || *read == "" || *connect == "" || *write == "" {
		fmt.Fprintln(w, `{"ok":false,"error":"usage: __probe --read F --connect H:P --write P"}`)
		return 2
	}
	verdict := map[string]string{"read": "denied", "connect": "denied", "write": "denied"}
	if f, err := os.Open(*read); err == nil {
		b := make([]byte, 1)
		if _, rerr := f.Read(b); rerr == nil || rerr == io.EOF {
			verdict["read"] = "ALLOWED"
		}
		f.Close()
	}
	if c, err := net.DialTimeout("tcp", *connect, 2*time.Second); err == nil {
		verdict["connect"] = "ALLOWED"
		c.Close()
	}
	if f, err := os.OpenFile(*write, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err == nil {
		verdict["write"] = "ALLOWED"
		f.Close()
		os.Remove(*write)
	}
	ok := true
	for _, v := range verdict {
		if v != "denied" {
			ok = false
		}
	}
	out, _ := json.Marshal(map[string]any{"ok": ok, "read": verdict["read"], "connect": verdict["connect"], "write": verdict["write"]})
	fmt.Fprintln(w, string(out))
	if ok {
		return 0
	}
	return 1
}

// AttachAppArmor reports whether the declared AppArmor profile is proven to attach on this host.
func (h Host) AttachAppArmor() bool { ok, _ := h.apparmorAttaches(); return ok }

func (h Host) agentBin() (string, error) {
	if h.AgentBin != "" {
		return h.AgentBin, nil
	}
	return os.Executable()
}

func kindFor(eng config.Engine) (Kind, error) {
	switch eng.Sandbox {
	case "seatbelt":
		return Seatbelt, nil
	case "nsjail":
		return Nsjail, nil
	}
	return "", fmt.Errorf("engine %q has sandbox %q: nothing to prove", eng.Name, eng.Sandbox)
}

func resolve(p string) (string, error) {
	if !filepath.IsAbs(p) {
		lp, err := exec.LookPath(p)
		if err != nil {
			return "", err
		}
		p = lp
	}
	return filepath.EvalSymlinks(p)
}

func (h Host) request(eng config.Engine, scratch, argv0 string) (Request, error) {
	agent, err := h.agentBin()
	if err != nil {
		return Request{}, err
	}
	exe, err := resolve(argv0)
	if err != nil {
		return Request{}, err
	}
	var ro []string
	for _, p := range eng.ROPaths {
		r, err := filepath.EvalSymlinks(p)
		if err != nil {
			return Request{}, err
		}
		ro = append(ro, r)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return Request{}, err
	}
	return Request{
		ExecPaths: []string{exe}, ROPaths: ro, Accelerators: eng.Accelerators,
		Scratch: scratch, Canary: "bb.canary." + hex.EncodeToString(nonce[:8]),
		Nonce: hex.EncodeToString(nonce), AgentBin: agent,
		NsjailPath: h.NsjailPath, SeccompPolicy: h.SeccompPolicy,
		AppArmorProfile: h.AppArmorProfile, AllowMissingAppArmor: h.AllowMissingAppArmor,
	}, nil
}

func handshakeOK(scratch, nonce string) bool {
	m := filepath.Join(scratch, HandshakeName)
	fi, err := os.Lstat(m)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	b, err := os.ReadFile(m)
	os.Remove(m)
	return err == nil && string(b) == nonce
}

type runResult struct {
	code      int
	stdout    []byte
	stderr    []byte
	handshake bool
	layers    string
}

// runUnder runs argv under eng's sandbox in a fresh scratch.
func (h Host) runUnder(ctx context.Context, eng config.Engine, scratch string, argv []string) (runResult, error) {
	kind, err := kindFor(eng)
	if err != nil {
		return runResult{}, err
	}
	req, err := h.request(eng, scratch, argv[0])
	if err != nil {
		return runResult{}, err
	}
	if kind == Nsjail {
		req.AttachAppArmor, _ = h.apparmorAttaches()
	}
	to := h.Timeout
	if to == 0 {
		to = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	build := h.build
	if build == nil {
		build = Command
	}
	cmd, err := build(ctx, kind, req, argv, Limits{TimeoutS: int64(to / time.Second)})
	if err != nil {
		return runResult{}, err
	}
	stdout, stderr := &tailBuf{max: probeOutputCap}, &tailBuf{max: probeOutputCap}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	runErr := cmd.Run()
	code := 0
	if runErr != nil {
		var ee *exec.ExitError
		if !errors.As(runErr, &ee) {
			return runResult{}, runErr
		}
		code = ee.ExitCode()
	}
	return runResult{code, stdout.bytes(), stderr.bytes(), handshakeOK(scratch, req.Nonce), h.layers(kind)}, nil
}

// probeOutputCap bounds what is kept of a probe's or self-test's stdout and stderr: the tail,
// since the verdict is the last line.
const probeOutputCap = 64 << 10

type tailBuf struct {
	mu  sync.Mutex
	max int
	b   []byte
}

func (w *tailBuf) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(p) >= w.max {
		w.b = append(w.b[:0], p[len(p)-w.max:]...)
		return len(p), nil
	}
	if over := len(w.b) + len(p) - w.max; over > 0 {
		w.b = append(w.b[:0], w.b[over:]...)
	}
	w.b = append(w.b, p...)
	return len(p), nil
}

func (w *tailBuf) bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.b...)
}

// parseVerdict enforces the probe output contract: the last non-empty stdout line is a JSON
// object whose "read", "connect" and "write" are all "denied".
func parseVerdict(stdout []byte) error {
	lines := strings.Split(strings.TrimSpace(string(stdout)), "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	if last == "" {
		return errors.New("probe printed no verdict")
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(last), &v); err != nil {
		return fmt.Errorf("probe verdict is not JSON: %v", err)
	}
	for _, k := range []string{"read", "connect", "write"} {
		if s, ok := v[k].(string); !ok || s != "denied" {
			return fmt.Errorf("probe verdict %q = %v, want \"denied\"", k, v[k])
		}
	}
	return nil
}

func fail(format string, a ...any) ProbeResult {
	return ProbeResult{OK: false, Reason: fmt.Sprintf(format, a...), At: time.Now()}
}

func (h Host) tempDir(prefix string) (string, error) {
	base := h.ScratchBase
	if base == "" {
		base = os.TempDir()
	}
	d, err := os.MkdirTemp(base, prefix)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(d)
}

// Probe proves the engine's sandbox confines: a canary outside the grants is unreadable, a
// loopback listener is unreachable, and a path outside the grants cannot be created. OK needs the
// handshake nonce, probe exit 0, no connection at the listener, and the outside path absent.
func (h Host) Probe(ctx context.Context, eng config.Engine) ProbeResult {
	scratch, err := h.tempDir("bb-probe-scratch-")
	if err != nil {
		return fail("scratch: %v", err)
	}
	defer os.RemoveAll(scratch)
	outsideDir, err := h.tempDir("bb-probe-outside-")
	if err != nil {
		return fail("outside dir: %v", err)
	}
	defer os.RemoveAll(outsideDir)
	canary := filepath.Join(outsideDir, "canary")
	if err := os.WriteFile(canary, []byte("canary"), 0o644); err != nil {
		return fail("canary: %v", err)
	}
	outside := filepath.Join(outsideDir, "must-not-exist")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fail("listener: %v", err)
	}
	defer ln.Close()
	var conns atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			c.Close()
		}
	}()

	kind, kerr := kindFor(eng)
	if kerr != nil {
		return fail("%v", kerr)
	}
	var argv []string
	if len(eng.ProbeArgv) > 0 {
		repl := strings.NewReplacer("{canary}", canary, "{connect}", ln.Addr().String(), "{outside}", outside)
		for _, a := range eng.ProbeArgv {
			argv = append(argv, repl.Replace(a))
		}
	} else {
		agent, err := h.agentBin()
		if err != nil {
			return fail("agent binary: %v", err)
		}
		argv = []string{agent, "__probe", "--read", canary, "--connect", ln.Addr().String(), "--write", outside}
	}
	if kind == Nsjail {
		if reasons := h.InsecurityReasons(); len(reasons) > 0 {
			return fail("insecure nsjail host: %s", strings.Join(reasons, ", "))
		}
	}
	for _, ro := range eng.ROPaths {
		if r, err := filepath.EvalSymlinks(ro); err == nil && (isRelativeTo(canary, r) || isRelativeTo(outside, r)) {
			return fail("probe paths lie under the engine's ro_paths %s", r)
		}
	}
	rr, err := h.runUnder(ctx, eng, scratch, argv)
	if err != nil {
		return fail("probe did not run: %v", err)
	}
	time.Sleep(50 * time.Millisecond) // let a stray accept land
	switch {
	case !rr.handshake:
		return fail("no handshake nonce: the run was not confined (exit %d)", rr.code)
	case conns.Load() != 0:
		return fail("loopback listener received %d connection(s)", conns.Load())
	case rr.code != 0:
		return fail("probe exit %d (something was not denied): %s", rr.code, strings.TrimSpace(string(rr.stdout)+string(rr.stderr)))
	}
	if err := parseVerdict(rr.stdout); err != nil {
		return fail("%v", err)
	}
	if _, err := os.Lstat(outside); err == nil {
		return fail("outside path was created")
	}
	if b, _ := os.ReadFile(canary); string(b) != "canary" {
		return fail("canary was modified")
	}
	return ProbeResult{OK: true, Reason: "denied: read, connect, write; layers: " + rr.layers, At: time.Now()}
}

// SelfTest runs the engine's known-positive selftest_argv under the same sandbox: it must exit
// 0 and the handshake must be present.
func (h Host) SelfTest(ctx context.Context, eng config.Engine) ProbeResult {
	if len(eng.SelftestArgv) == 0 {
		return fail("engine %q has no selftest_argv", eng.Name)
	}
	scratch, err := h.tempDir("bb-selftest-")
	if err != nil {
		return fail("scratch: %v", err)
	}
	defer os.RemoveAll(scratch)
	if kind, err := kindFor(eng); err != nil {
		return fail("%v", err)
	} else if kind == Nsjail {
		if reasons := h.InsecurityReasons(); len(reasons) > 0 {
			return fail("insecure nsjail host: %s", strings.Join(reasons, ", "))
		}
	}
	rr, err := h.runUnder(ctx, eng, scratch, eng.SelftestArgv)
	if err != nil {
		return fail("selftest did not run: %v", err)
	}
	switch {
	case !rr.handshake:
		return fail("no handshake nonce: the run was not confined (exit %d)", rr.code)
	case rr.code != 0:
		return fail("selftest exit %d: %s", rr.code, strings.TrimSpace(string(rr.stdout)+string(rr.stderr)))
	}
	return ProbeResult{OK: true, Reason: "selftest passed; layers: " + rr.layers, At: time.Now()}
}
