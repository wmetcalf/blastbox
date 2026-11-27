package sandbox

import (
	"bytes"
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
	AgentBin      string // blastbox-agent binary; "" = os.Executable()
	NsjailPath    string // linux
	SeccompPolicy string // "" = none
	ScratchBase   string // "" = os.TempDir()
	Timeout       time.Duration
}

// DefaultHost is used by the package-level Probe and SelfTest.
var DefaultHost = Host{NsjailPath: "/usr/local/bin/nsjail"}

func Probe(ctx context.Context, eng config.Engine) ProbeResult { return DefaultHost.Probe(ctx, eng) }
func SelfTest(ctx context.Context, eng config.Engine) ProbeResult {
	return DefaultHost.SelfTest(ctx, eng)
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

// runUnder runs argv under eng's sandbox in a fresh scratch; returns (exit, stdout, handshake).
func (h Host) runUnder(ctx context.Context, eng config.Engine, scratch string, argv []string) (int, []byte, bool, error) {
	kind, err := kindFor(eng)
	if err != nil {
		return 0, nil, false, err
	}
	req, err := h.request(eng, scratch, argv[0])
	if err != nil {
		return 0, nil, false, err
	}
	to := h.Timeout
	if to == 0 {
		to = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	cmd, err := Command(ctx, kind, req, argv, Limits{TimeoutS: int64(to / time.Second)})
	if err != nil {
		return 0, nil, false, err
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	code := 0
	if runErr != nil {
		var ee *exec.ExitError
		if !errors.As(runErr, &ee) {
			return 0, nil, false, runErr
		}
		code = ee.ExitCode()
	}
	hs := handshakeOK(scratch, req.Nonce)
	return code, append(stdout.Bytes(), stderr.Bytes()...), hs, nil
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
	code, out, hs, err := h.runUnder(ctx, eng, scratch, argv)
	if err != nil {
		return fail("probe did not run: %v", err)
	}
	time.Sleep(50 * time.Millisecond) // let a stray accept land
	switch {
	case !hs:
		return fail("no handshake nonce: the run was not confined (exit %d)", code)
	case code != 0:
		return fail("probe exit %d (something was not denied): %s", code, strings.TrimSpace(string(out)))
	case conns.Load() != 0:
		return fail("loopback listener received %d connection(s)", conns.Load())
	}
	if _, err := os.Lstat(outside); err == nil {
		return fail("outside path was created")
	}
	if b, _ := os.ReadFile(canary); string(b) != "canary" {
		return fail("canary was modified")
	}
	return ProbeResult{OK: true, Reason: "denied: read, connect, write", At: time.Now()}
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
	code, out, hs, err := h.runUnder(ctx, eng, scratch, eng.SelftestArgv)
	if err != nil {
		return fail("selftest did not run: %v", err)
	}
	switch {
	case !hs:
		return fail("no handshake nonce: the run was not confined (exit %d)", code)
	case code != 0:
		return fail("selftest exit %d: %s", code, strings.TrimSpace(string(out)))
	}
	return ProbeResult{OK: true, Reason: "selftest passed", At: time.Now()}
}
