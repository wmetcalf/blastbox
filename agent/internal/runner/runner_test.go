package runner

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/wmetcalf/blastbox/agent/internal/config"
	"github.com/wmetcalf/blastbox/agent/internal/conformance"
	"github.com/wmetcalf/blastbox/agent/internal/sandbox"
	"github.com/wmetcalf/blastbox/agent/internal/wire"
)

const testJob = "job-1"

// ---- fake ingress ----

type ingress struct {
	t   *testing.T
	srv *httptest.Server
	mu  sync.Mutex

	input       []byte
	inputHeader string // "" = the true sha256
	putStatus   int    // 0 = 200
	putBody     string
	dispStatus  string // disposition answer; "" = done

	inputGets int
	puts      int
	putTar    []byte
	updates   []map[string]any // POST /v1/nodes/jobs/<id> bodies
	disps     int
}

func newIngress(t *testing.T) (*ingress, *wire.Client) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	ca, _ := x509.ParseCertificate(der)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	skey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	stpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "ingress"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	sder, _ := x509.CreateCertificate(rand.Reader, stpl, ca, &skey.PublicKey, key)

	in := &ingress{t: t, input: []byte("the sample")}
	in.srv = httptest.NewUnstartedServer(http.HandlerFunc(in.serve))
	in.srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{sder}, PrivateKey: skey}}}
	in.srv.StartTLS()
	t.Cleanup(in.srv.Close)

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(caFile, caPEM, 0o600)
	cl, err := wire.New(&config.Config{
		Ingress: in.srv.URL, CAFile: caFile,
		CertFile: conformance.Path("node_certs", "v2_without_wg.crt"),
		KeyFile:  conformance.Path("node_certs", "v2_without_wg.key"),
	}, "blastbox-agent/0.0.0 (test)")
	if err != nil {
		t.Fatal(err)
	}
	return in, cl
}

func (in *ingress) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	in.mu.Lock()
	defer in.mu.Unlock()
	js := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}
	jp := "/v1/nodes/jobs/" + testJob
	switch {
	case r.URL.Path == "/v1/nodes/challenge":
		js(200, map[string]any{"challenge": "c", "expires_in": 60, "scope": "claim-next"})
	case r.URL.Path == "/v1/nodes/session":
		js(200, map[string]any{"token": "tok", "expires_in": 600, "node_id": "node-v2"})
	case r.Method == "GET" && r.URL.Path == jp+"/input":
		in.inputGets++
		sum := sha256.Sum256(in.input)
		h := hex.EncodeToString(sum[:])
		if in.inputHeader != "" {
			h = in.inputHeader
		}
		w.Header().Set("x-blastbox-input-sha256", h)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(in.input)
	case r.Method == "PUT" && r.URL.Path == jp+"/result":
		in.puts++
		in.putTar = body
		switch in.putStatus {
		case 409:
			w.WriteHeader(409)
		case 202:
			js(202, map[string]any{"status": "accepted"})
		case 422:
			js(422, map[string]any{"status": "failed", "reason": "bad envelope"})
		default:
			js(200, map[string]any{"status": "done"})
		}
	case r.Method == "POST" && r.URL.Path == jp:
		var m map[string]any
		json.Unmarshal(body, &m)
		in.updates = append(in.updates, m)
		js(200, map[string]any{"ok": true})
	case r.Method == "GET" && r.URL.Path == jp+"/disposition":
		in.disps++
		st := in.dispStatus
		if st == "" {
			st = "done"
		}
		js(200, map[string]any{"job": map[string]any{"status": st}})
	default:
		http.NotFound(w, r)
	}
}

func (in *ingress) update(i int) map[string]any {
	in.mu.Lock()
	defer in.mu.Unlock()
	if i >= len(in.updates) {
		in.t.Fatalf("no update #%d (have %d)", i, len(in.updates))
	}
	return in.updates[i]["fields"].(map[string]any)
}

func (in *ingress) tarFiles() map[string]string {
	in.mu.Lock()
	defer in.mu.Unlock()
	out := map[string]string{}
	tr := tar.NewReader(bytes.NewReader(in.putTar))
	for {
		h, err := tr.Next()
		if err != nil {
			return out
		}
		b, _ := io.ReadAll(tr)
		out[h.Name] = string(b)
	}
}

// ---- fixtures ----

func fakeBuild(ctx context.Context, _ sandbox.Kind, req sandbox.Request, argv []string, _ sandbox.Limits) (*exec.Cmd, error) {
	full := append([]string{"/bin/sh", "-c", sandbox.HandshakeShim, "bb-handshake", req.Nonce,
		filepath.Join(req.Scratch, sandbox.HandshakeName)}, argv...)
	cmd := exec.CommandContext(ctx, full[0], full[1:]...)
	env, err := sandbox.ChildEnv(req.Scratch, req.Env)
	if err != nil {
		return nil, err
	}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Dir = req.Scratch
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 3 * time.Second
	return cmd, nil
}

type fixture struct {
	in    *ingress
	cl    *wire.Client
	r     *Runner
	state string
	eng   config.Engine
	claim *wire.Claim
}

func setup(t *testing.T, script string) *fixture {
	t.Helper()
	in, cl := newIngress(t)
	dir := t.TempDir()
	sp := filepath.Join(dir, "engine.sh")
	os.WriteFile(sp, []byte("#!/bin/sh\n"+script), 0o755)
	state := filepath.Join(dir, "state")
	os.Mkdir(state, 0o700)
	sum := sha256.Sum256(in.input)
	f := &fixture{in: in, cl: cl, state: state,
		eng: config.Engine{Name: "eng", Argv: []string{"/bin/sh", sp, "{out}", "{input}", "{scratch}"}, Output: "dir", Sandbox: "seatbelt"},
		claim: &wire.Claim{JobID: testJob, ClaimID: "claim-1", Receipt: "rcpt", NodeID: "node-v2",
			Run: wire.RunBlock{DeadlineS: 20, Network: "none", Params: map[string]any{},
				Limits: wire.Limits{MaxInput: 1 << 20, MaxMetadata: 1 << 16, MaxArtifact: 1 << 20, MaxTotalArtifacts: 1 << 22, MaxArtifacts: 10},
				Input:  wire.InputInfo{SHA256: hex.EncodeToString(sum[:]), Filename: "../weird name.docx"}}},
		r: &Runner{build: fakeBuild, Logf: t.Logf, MemPoll: 50 * time.Millisecond, DispPoll: 5 * time.Millisecond,
			DispWait: time.Second, RetryBase: time.Millisecond}}
	return f
}

func (f *fixture) run() Result {
	return f.r.Run(context.Background(), f.cl, f.eng, f.claim, f.state)
}

func (f *fixture) wiped(t *testing.T) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(f.state, "jobs", testJob)); err == nil {
		t.Error("job dir was not wiped")
	}
}

func (f *fixture) wantFail(t *testing.T, res Result, sub string) {
	t.Helper()
	if res.Outcome != "failed" || !strings.Contains(res.Reason, sub) {
		t.Fatalf("result %+v, want failed containing %q", res, sub)
	}
	if len(f.in.updates) != 1 {
		t.Fatalf("updates %v", f.in.updates)
	}
	fields := f.in.update(0)
	if fields["status"] != "failed" || !strings.Contains(fmt.Sprint(fields["error"]), sub) {
		t.Fatalf("server saw %v", fields)
	}
	if f.in.puts != 0 {
		t.Error("a failed job uploaded a result")
	}
	f.wiped(t)
}

const happyEngine = `
out="$1"
mkdir -p "$out/art"
printf hello > "$out/art/a.txt"
if [ -f "$out/../started" ]; then echo seen > "$out/art/started.txt"; fi
test "$(cat "$2")" = "the sample" && echo input-ok > "$out/art/input.txt"
printf '{"schema":"x","artifacts":[{"kind":"text","path":"art/a.txt","id":"a","sha256":"","bytes":0},{"id":"gone","path":"art/none","kind":"t"}],"z":1}' > "$out/metadata.json"
`

func TestHappyPath(t *testing.T) {
	f := setup(t, happyEngine)
	res := f.run()
	if res.Outcome != "done" {
		t.Fatalf("%+v", res)
	}
	if f.in.puts != 1 || len(f.in.updates) != 0 {
		t.Fatalf("puts=%d updates=%v", f.in.puts, f.in.updates)
	}
	files := f.in.tarFiles()
	if files["art/a.txt"] != "hello" || files["art/started.txt"] != "seen\n" || files["art/input.txt"] != "input-ok\n" {
		t.Fatalf("tar members %v", files)
	}
	sum := sha256.Sum256([]byte("hello"))
	want := `{"artifacts":[{"bytes":5,"id":"a","kind":"text","path":"art/a.txt","sha256":"` +
		hex.EncodeToString(sum[:]) + `"},{"id":"gone","kind":"t","path":"art/none"}],"schema":"x","z":1}`
	if files["metadata.json"] != want {
		t.Fatalf("metadata\n got %s\nwant %s", files["metadata.json"], want)
	}
	f.wiped(t)
}

func TestAcceptedPollsDisposition(t *testing.T) {
	f := setup(t, happyEngine)
	f.in.putStatus = 202
	res := f.run()
	if res.Outcome != "done" || f.in.disps == 0 {
		t.Fatalf("%+v disps=%d", res, f.in.disps)
	}
	f = setup(t, happyEngine)
	f.in.putStatus, f.in.dispStatus = 202, "failed"
	if res := f.run(); res.Outcome != "failed" {
		t.Fatalf("%+v", res)
	}
}

func TestRejectedResultIsFailed(t *testing.T) {
	f := setup(t, happyEngine)
	f.in.putStatus = 422
	if res := f.run(); res.Outcome != "failed" || !strings.Contains(res.Reason, "bad envelope") || len(f.in.updates) != 0 {
		t.Fatalf("%+v", res)
	}
	f.wiped(t)
}

func TestEnvelopeModeKeepsBytesVerbatim(t *testing.T) {
	// No declared artifacts: the engine's bytes (odd spacing and key order) go through untouched.
	f := setup(t, `printf '{ "schema" : "wtqrk",  "b":1, "a":2 }\n'`)
	f.eng.Output = "stdout-envelope"
	if res := f.run(); res.Outcome != "done" {
		t.Fatalf("%+v", res)
	}
	if got := f.in.tarFiles()["metadata.json"]; got != "{ \"schema\" : \"wtqrk\",  \"b\":1, \"a\":2 }\n" {
		t.Fatalf("envelope rewritten: %q", got)
	}
}

func TestEnvelopeOverCapFails(t *testing.T) {
	f := setup(t, `head -c 100000 /dev/zero | tr '\0' x`)
	f.eng.Output = "stdout-envelope"
	f.claim.Run.Limits.MaxMetadata = 1000
	f.wantFail(t, f.run(), "envelope over max_metadata")
}

func TestNetworkNotNoneReleases(t *testing.T) {
	f := setup(t, happyEngine)
	f.claim.Run.Network = "monitored-proxy"
	res := f.run()
	if res.Outcome != "released" || f.in.inputGets != 0 {
		t.Fatalf("%+v gets=%d", res, f.in.inputGets)
	}
	fl := f.in.update(0)
	if fl["status"] != "queued" || fl["claim_id"] != nil {
		t.Fatalf("release shape %v", fl)
	}
}

func TestInputHashMismatchReleases(t *testing.T) {
	f := setup(t, happyEngine)
	f.in.inputHeader = strings.Repeat("0", 64)
	res := f.run()
	if res.Outcome != "released" || f.in.update(0)["status"] != "queued" {
		t.Fatalf("%+v", res)
	}
	f.wiped(t)
	if f.in.puts != 0 {
		t.Error("uploaded")
	}
}

func TestUnsandboxedEngineReleases(t *testing.T) {
	f := setup(t, happyEngine)
	f.eng.Sandbox = "none"
	if res := f.run(); res.Outcome != "released" || f.in.inputGets != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestSandboxBuildErrorReleasesBeforeStarted(t *testing.T) {
	f := setup(t, happyEngine)
	f.r.build = func(context.Context, sandbox.Kind, sandbox.Request, []string, sandbox.Limits) (*exec.Cmd, error) {
		return nil, fmt.Errorf("insecure host")
	}
	if res := f.run(); res.Outcome != "released" {
		t.Fatalf("%+v", res)
	}
}

func TestDeadlineKillsWholeGroup(t *testing.T) {
	pidf := filepath.Join(t.TempDir(), "pid")
	f := setup(t, fmt.Sprintf(`sleep 60 & echo $! > %s; wait`, pidf))
	f.claim.Run.DeadlineS = 1
	t0 := time.Now()
	res := f.run()
	if time.Since(t0) > 15*time.Second {
		t.Fatal("deadline not enforced")
	}
	f.wantFail(t, res, "deadline exceeded after 1s")
	b, _ := os.ReadFile(pidf)
	var pid int
	fmt.Sscan(string(b), &pid)
	for i := 0; i < 50 && syscall.Kill(pid, 0) == nil; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if pid == 0 || syscall.Kill(pid, 0) == nil {
		t.Errorf("grandchild %d survived the deadline", pid)
	}
}

func TestMemoryWatchdogKills(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("no python3")
	}
	f := setup(t, `exec python3 -c "b = b'x' * (300 << 20); import time; time.sleep(30)"`)
	mib := 64
	f.eng.MaxRSSMiB = &mib
	t0 := time.Now()
	res := f.run()
	if time.Since(t0) > 20*time.Second {
		t.Fatal("watchdog too slow")
	}
	f.wantFail(t, res, "memory cap exceeded")
}

func TestOversizeOutputFails(t *testing.T) {
	f := setup(t, `mkdir -p "$1/art"; head -c 5000 /dev/zero > "$1/art/big"; echo '{}' > "$1/metadata.json"`)
	f.claim.Run.Limits.MaxArtifact = 100
	f.wantFail(t, f.run(), "over max_artifact")
}

func TestTooManyArtifactsAndTotalFail(t *testing.T) {
	f := setup(t, `for i in 1 2 3 4; do echo x > "$1/f$i"; done; echo '{}' > "$1/metadata.json"`)
	f.claim.Run.Limits.MaxArtifacts = 3
	f.wantFail(t, f.run(), "max_artifacts")
	f = setup(t, `head -c 300 /dev/zero > "$1/a"; head -c 300 /dev/zero > "$1/b"; echo '{}' > "$1/metadata.json"`)
	f.claim.Run.Limits.MaxTotalArtifacts = 500
	f.wantFail(t, f.run(), "max_total_artifacts")
}

func TestMissingMetadataFails(t *testing.T) {
	f := setup(t, `echo x > "$1/a"`)
	f.wantFail(t, f.run(), "no metadata.json")
}

func TestSymlinkInOutputFails(t *testing.T) {
	f := setup(t, `ln -s /etc/passwd "$1/leak"; echo '{}' > "$1/metadata.json"`)
	f.wantFail(t, f.run(), "non-regular file in output: leak")
}

func TestHardlinkInOutputFails(t *testing.T) {
	f := setup(t, `echo x > "$1/a"; ln "$1/a" "$1/b"; echo '{}' > "$1/metadata.json"`)
	f.wantFail(t, f.run(), "hardlinked")
}

func TestFifoInOutputFails(t *testing.T) {
	f := setup(t, `mkfifo "$1/p"; echo '{}' > "$1/metadata.json"`)
	f.wantFail(t, f.run(), "non-regular")
}

func TestLostClaimOnPutNoRetryAndWiped(t *testing.T) {
	f := setup(t, happyEngine)
	f.in.putStatus = 409
	res := f.run()
	if res.Outcome != "lost" || f.in.puts != 1 || len(f.in.updates) != 0 {
		t.Fatalf("%+v puts=%d updates=%v", res, f.in.puts, f.in.updates)
	}
	f.wiped(t)
}

func TestBadParamKeyFailsBeforeLaunch(t *testing.T) {
	ran := filepath.Join(t.TempDir(), "ran")
	f := setup(t, "touch "+ran+"; "+happyEngine)
	f.claim.Run.Params = map[string]any{"lower-case": "x"}
	f.wantFail(t, f.run(), "invalid run params")
	if _, err := os.Stat(ran); err == nil {
		t.Error("engine ran")
	}
	if f.in.inputGets != 0 {
		t.Error("input fetched for a doomed job")
	}
	f = setup(t, happyEngine)
	f.claim.Run.Params = map[string]any{"OK": strings.Repeat("v", 8193)}
	f.wantFail(t, f.run(), "over 8 KiB")
}

func TestParamsBecomeEnvButNeverBlastbox(t *testing.T) {
	f := setup(t, `printf '%s|%s|%s|%s' "$FOO" "$N" "$BLASTBOX_SECRET" "$PATH" > "$1/env.txt"; echo '{}' > "$1/metadata.json"`)
	f.claim.Run.Params = map[string]any{"FOO": "bar", "N": float64(5), "BLASTBOX_SECRET": "no"}
	if res := f.run(); res.Outcome != "done" {
		t.Fatalf("%+v", res)
	}
	if got := f.in.tarFiles()["env.txt"]; got != "bar|5||/usr/bin:/bin" {
		t.Fatalf("env %q", got)
	}
	f = setup(t, `printf '%s' "$FOO" > "$1/env.txt"; echo '{}' > "$1/metadata.json"`)
	no := false
	f.eng.EnvParams = &no
	f.claim.Run.Params = map[string]any{"FOO": "bar"}
	f.run()
	if got := f.in.tarFiles()["env.txt"]; got != "" {
		t.Fatalf("env_params=false still forwarded: %q", got)
	}
}

func TestNonZeroExitFails(t *testing.T) {
	f := setup(t, `echo '{}' > "$1/metadata.json"; exit 3`)
	f.wantFail(t, f.run(), "engine exited with status 3")
}

func TestMissingHandshakeFails(t *testing.T) {
	f := setup(t, `rm -f "$3/.bb-handshake"; echo '{}' > "$1/metadata.json"`)
	f.wantFail(t, f.run(), "handshake")
}

func TestFailIsRetriedOnServerError(t *testing.T) {
	f := setup(t, `exit 1`)
	var n int
	var mu sync.Mutex
	srv := f.in.srv
	h := srv.Config.Handler
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/v1/nodes/jobs/"+testJob {
			mu.Lock()
			n++
			c := n
			mu.Unlock()
			if c == 1 {
				w.WriteHeader(503)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
	if res := f.run(); res.Outcome != "failed" || !strings.Contains(res.Reason, "status 1") || strings.Contains(res.Reason, "not delivered") {
		t.Fatalf("%+v", res)
	}
	if n != 2 {
		t.Fatalf("fail posted %d times", n)
	}
}

func TestTemplate(t *testing.T) {
	v := map[string]string{"input": "/i", "out": "/o", "scratch": "/s"}
	got, err := template([]string{"x", "--in={input}", "{out}/{scratch}"}, v)
	if err != nil || strings.Join(got, " ") != "x --in=/i /o//s" {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"{nope}", "{input", "a}b", "{}"} {
		if _, err := template([]string{bad}, v); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSanitiseName(t *testing.T) {
	for in, want := range map[string]string{"../a b.docx": "a_b.docx", "": "input", "...": "input", ".hidden": "hidden", `C:\x\y.exe`: "y.exe"} {
		if got := sanitiseName(in); got != want {
			t.Errorf("%q -> %q want %q", in, got, want)
		}
	}
}

func TestWipeHandlesUnreadableTree(t *testing.T) {
	d := filepath.Join(t.TempDir(), "j")
	os.MkdirAll(filepath.Join(d, "a/b"), 0o700)
	os.WriteFile(filepath.Join(d, "a/b/f"), []byte("x"), 0o600)
	os.Chmod(filepath.Join(d, "a/b"), 0)
	os.Chmod(filepath.Join(d, "a"), 0o500)
	wipe(d)
	if _, err := os.Lstat(d); err == nil {
		t.Fatal("not wiped")
	}
}
