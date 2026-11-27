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

	input        []byte
	inputHeader  string // "" = the true sha256
	putStatus    int    // 0 = 200
	putBody      string
	dispStatus   string // disposition answer; "" = done
	updStatus    int    // status for POST /v1/nodes/jobs/<id>; 0 = 200
	state        string // the fixture's state dir (for markers seen mid-run)
	reportedSeen bool   // the "reported" marker existed when disposition was polled

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
		case 503:
			w.WriteHeader(503)
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
		if in.updStatus != 0 {
			w.WriteHeader(in.updStatus)
			return
		}
		js(200, map[string]any{"ok": true})
	case r.Method == "GET" && r.URL.Path == jp+"/disposition":
		in.disps++
		if _, err := os.Lstat(filepath.Join(in.state, "jobs", testJob, "reported")); err == nil {
			in.reportedSeen = true
		}
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
	in.state = state
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
	// A first-time extraction refusal stores no outcome on the control plane, so the job would
	// stay RUNNING: the agent fails it (spec 6.4: "the job is FAILED"). When the 422 replays
	// a stored failure the Fail is merely refused.
	res := f.run()
	if res.Outcome != "failed" || !strings.Contains(res.Reason, "bad envelope") {
		t.Fatalf("%+v", res)
	}
	if len(f.in.updates) != 1 || f.in.update(0)["status"] != "failed" ||
		!strings.Contains(fmt.Sprint(f.in.update(0)["error"]), "bad envelope") {
		t.Fatalf("server saw %v", f.in.updates)
	}
	f.wiped(t)
}

// A terminal report the control plane never answered keeps the job dir for crash recovery,
// which retries it, instead of wiping the only record of the claim.
func TestUndeliveredFailIsKeptForRecovery(t *testing.T) {
	f := setup(t, `echo '{}' > "$1/metadata.json"; exit 3`)
	f.in.updStatus = 503
	res := f.run()
	if res.Outcome != "failed" || !res.Keep {
		t.Fatalf("%+v, want failed and kept", res)
	}
	d := filepath.Join(f.state, "jobs", testJob)
	for _, n := range []string{"started", "claim.json"} {
		if _, err := os.Lstat(filepath.Join(d, n)); err != nil {
			t.Fatalf("%s gone: %v", n, err)
		}
	}
}

// A report the control plane answered with a permanent refusal (a 4xx, a 404) will never be
// accepted: keeping the dir would only make recovery repeat it forever.
func TestRejectedReportIsNotKept(t *testing.T) {
	for _, code := range []int{400, 404} {
		f := setup(t, `echo '{}' > "$1/metadata.json"; exit 3`)
		f.in.updStatus = code
		if res := f.run(); res.Keep {
			t.Fatalf("HTTP %d: %+v kept", code, res)
		}
		f.wiped(t)
	}
}

func TestUndeliveredUploadIsKeptForRecovery(t *testing.T) {
	f := setup(t, happyEngine)
	f.in.putStatus = 503
	res := f.run()
	if !res.Keep || len(f.in.updates) != 0 {
		t.Fatalf("%+v updates=%v: an unanswered upload is retried by recovery, not failed", res, f.in.updates)
	}
	d := filepath.Join(f.state, "jobs", testJob)
	for _, n := range []string{"started", "claim.json", "result.tar", "result.json"} {
		if _, err := os.Lstat(filepath.Join(d, n)); err != nil {
			t.Fatalf("%s gone: %v", n, err)
		}
	}
}

func TestAcceptedResultIsMarkedReported(t *testing.T) {
	f := setup(t, happyEngine)
	f.in.putStatus = 202
	f.in.dispStatus = "running"
	f.r.DispWait = 50 * time.Millisecond
	if res := f.run(); res.Outcome != "done" || res.Keep {
		t.Fatalf("%+v", res)
	}
	if !f.in.reportedSeen {
		t.Fatal("no durable reported marker while the disposition was pending: a crash now would fail a good result")
	}
	f.wiped(t)
}

// An envelope Go's decoder cannot round-trip exactly (a lone surrogate escape, invalid UTF-8)
// is left byte-for-byte as the engine wrote it rather than silently rewritten with U+FFFD.
func TestLossyEnvelopeIsLeftVerbatim(t *testing.T) {
	for name, meta := range map[string]string{
		"lone surrogate": `{"s":"\ud800","artifacts":[{"path":"a.txt","sha256":"","bytes":0}]}`,
		"invalid utf8":   "{\"s\":\"\xff\",\"artifacts\":[{\"path\":\"a.txt\",\"sha256\":\"\",\"bytes\":0}]}",
	} {
		t.Run(name, func(t *testing.T) {
			src := filepath.Join(t.TempDir(), "meta.json")
			os.WriteFile(src, []byte(meta), 0o600)
			f := setup(t, `printf x > "$1/a.txt"; cat `+src+` > "$1/metadata.json"`)
			if res := f.run(); res.Outcome != "done" {
				t.Fatalf("%+v", res)
			}
			if got := f.in.tarFiles()["metadata.json"]; got != meta {
				t.Fatalf("envelope rewritten: %q", got)
			}
		})
	}
}

// The running sandbox is recorded (for recovery after an agent crash) while it runs.
func TestRunRecordWrittenWhileRunning(t *testing.T) {
	f := setup(t, `sleep 0.5; cat "$1/../sandbox.json" > "$1/rec.json"; echo '{}' > "$1/metadata.json"`)
	if res := f.run(); res.Outcome != "done" {
		t.Fatalf("%+v", res)
	}
	var rec sandbox.RunRecord
	if err := json.Unmarshal([]byte(f.in.tarFiles()["rec.json"]), &rec); err != nil || rec.PID <= 1 || rec.Identity == 0 {
		t.Fatalf("run record %+v (%v)", rec, err)
	}
}

// A sandbox fault is reported to the host (the agent stops claiming) BEFORE the job's report,
// which may take minutes against a struggling control plane.
func TestSandboxFaultReportedBeforeTheJobReport(t *testing.T) {
	f := setup(t, `rm -f "$3/.bb-handshake"; echo '{}' > "$1/metadata.json"`)
	var beforeReport bool
	f.r.SandboxFault = func(engine, reason string) {
		f.in.mu.Lock()
		beforeReport = len(f.in.updates) == 0
		f.in.mu.Unlock()
	}
	res := f.run()
	if !res.SandboxFailure || !beforeReport {
		t.Fatalf("%+v: fault hook before report = %v", res, beforeReport)
	}
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
	var startedAtBuild = true
	f.r.build = func(context.Context, sandbox.Kind, sandbox.Request, []string, sandbox.Limits) (*exec.Cmd, error) {
		_, err := os.Lstat(filepath.Join(f.state, "jobs", testJob, "started"))
		startedAtBuild = err == nil
		return nil, fmt.Errorf("insecure host")
	}
	defer func() {
		if startedAtBuild {
			t.Error("started marker existed when the sandbox build failed")
		}
	}()
	if res := f.run(); res.Outcome != "released" || !res.SandboxFailure {
		t.Fatalf("%+v, want released as a sandbox failure", res)
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
	f.wantFail(t, f.run(), `non-regular file in output: "leak"`)
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

// Params the dispatcher would drop are dropped here too, not fatal: a lowercase or oversized
// key, and the loader/interpreter/shell keys a submitter must never set.
func TestUnusableParamsAreDropped(t *testing.T) {
	const show = `env | grep -E '^(FOO|PYTHON|IFS|LD_|DYLD_|lower|NUL)' | sort | tr '\n' ' ' > "$1/env.txt"; printf %s "$BIG" > "$1/big.txt"; echo '{}' > "$1/metadata.json"`
	f := setup(t, show)
	f.claim.Run.Params = map[string]any{"FOO": "bar", "lower-case": "x", "password": "infected",
		"BIG": strings.Repeat("é", 5000), "NUL": "a\x00b", "PYTHONPATH": "/x", "PYTHONSTARTUP": "/x", "IFS": "x",
		"LD_PRELOAD": "/x", "DYLD_INSERT_LIBRARIES": "/x"}
	if res := f.run(); res.Outcome != "done" {
		t.Fatalf("%+v", res)
	}
	files := f.in.tarFiles()
	if got := files["env.txt"]; got != "FOO=bar " {
		t.Fatalf("env %q", got)
	}
	// Like the dispatcher (_MAX_ENV_VALUE_LEN), an over-long value is cut to 4096 characters.
	if got := files["big.txt"]; got != strings.Repeat("é", 4096) {
		t.Fatalf("BIG has %d runes, want 4096", len([]rune(got)))
	}
}

func TestEngineParamAllowlistAndReservedKeys(t *testing.T) {
	const show = `env | grep -E '^(FOO|BAR|MODE)=' | sort | tr '\n' ' ' > "$1/env.txt"; echo '{}' > "$1/metadata.json"`
	params := map[string]any{"FOO": "1", "BAR": "2", "MODE": "3"}
	for _, tc := range []struct {
		name     string
		allow    *[]string
		reserved []string
		want     string
	}{
		{"none", nil, nil, "BAR=2 FOO=1 MODE=3 "},
		{"allowlist", &[]string{"FOO", "MODE"}, nil, "FOO=1 MODE=3 "},
		{"empty allowlist blocks all", &[]string{}, nil, ""},
		{"reserved", nil, []string{"MODE"}, "BAR=2 FOO=1 "},
		{"reserved beats allowlist", &[]string{"FOO", "MODE"}, []string{"MODE"}, "FOO=1 "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t, show)
			f.eng.ParamKeys, f.eng.ReservedParamKeys = tc.allow, tc.reserved
			f.claim.Run.Params = params
			if res := f.run(); res.Outcome != "done" {
				t.Fatalf("%+v", res)
			}
			if got := f.in.tarFiles()["env.txt"]; got != tc.want {
				t.Fatalf("env %q, want %q", got, tc.want)
			}
		})
	}
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
	res := f.run()
	f.wantFail(t, res, "handshake")
	if !res.SandboxFailure {
		t.Fatalf("%+v: a missing handshake is a sandbox failure", res)
	}
}

func TestNonSandboxFailureIsNotFlagged(t *testing.T) {
	f := setup(t, `exit 3`)
	if res := f.run(); res.Outcome != "failed" || res.SandboxFailure {
		t.Fatalf("%+v: an engine's own exit status is not a sandbox failure", res)
	}
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

func TestCtxCancelMidRunFailsNotReleases(t *testing.T) {
	f := setup(t, `sleep 60`)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(300 * time.Millisecond); cancel() }()
	res := f.r.Run(ctx, f.cl, f.eng, f.claim, f.state)
	f.wantFail(t, res, "run interrupted")
	if f.in.update(0)["status"] == "queued" {
		t.Fatal("a started job was released")
	}
}

func TestLostClaimOnFail(t *testing.T) {
	f := setup(t, `exit 1`)
	srv := f.in.srv
	h := srv.Config.Handler
	var posts int
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/v1/nodes/jobs/"+testJob {
			posts++
			w.WriteHeader(409)
			return
		}
		h.ServeHTTP(w, r)
	})
	res := f.run()
	if res.Outcome != "lost" || posts != 1 {
		t.Fatalf("%+v posts=%d", res, posts)
	}
	f.wiped(t)
}

func TestWatchdogFailsClosedWhenBlind(t *testing.T) {
	f := setup(t, `sleep 60`)
	var calls int
	f.r.rss = func(int) (int64, error) { calls++; return 0, fmt.Errorf("ps broke") }
	t0 := time.Now()
	res := f.run()
	if time.Since(t0) > 10*time.Second {
		t.Fatal("blind watchdog did not stop the run")
	}
	f.wantFail(t, res, "memory watchdog unavailable")
	if calls != 3 {
		t.Fatalf("killed after %d errors, want 3", calls)
	}
	// A transient error then success does not kill.
	f = setup(t, `sleep 0.5`)
	n := 0
	f.r.rss = func(int) (int64, error) {
		n++
		if n%3 != 0 {
			return 0, fmt.Errorf("blip")
		}
		return 1, nil
	}
	f.claim.Run.DeadlineS = 20
	if res := f.run(); strings.Contains(res.Reason, "watchdog") {
		t.Fatalf("transient errors killed the job: %+v", res)
	}
}

func TestRefusesStartedJobDir(t *testing.T) {
	f := setup(t, happyEngine)
	d := filepath.Join(f.state, "jobs", testJob)
	os.MkdirAll(d, 0o700)
	os.WriteFile(filepath.Join(d, "started"), []byte("1\n"), 0o600)
	os.WriteFile(filepath.Join(d, "evidence"), []byte("keep"), 0o600)
	res := f.run()
	if res.Outcome != "refused" || f.in.inputGets != 0 || f.in.puts != 0 {
		t.Fatalf("%+v", res)
	}
	// The job reached a sandbox on this node before (under an earlier claim): the NEW claim is
	// failed, never released and never run; the old dir is left to recovery.
	if len(f.in.updates) != 1 || f.in.update(0)["status"] != "failed" {
		t.Fatalf("new claim not failed: %v", f.in.updates)
	}
	if b, _ := os.ReadFile(filepath.Join(d, "evidence")); string(b) != "keep" {
		t.Fatal("started job dir was touched")
	}
}

func TestClaimJSONRecordsStarted(t *testing.T) {
	f := setup(t, `cat "$3/../claim.json" > "$1/c.json"; echo '{}' > "$1/metadata.json"`)
	if res := f.run(); res.Outcome != "done" {
		t.Fatalf("%+v", res)
	}
	if got := f.in.tarFiles()["c.json"]; !strings.Contains(got, `"started":true`) {
		t.Fatalf("claim.json %q", got)
	}
}

func TestServerReasonIsASCIIAndCapped(t *testing.T) {
	f := setup(t, `echo '{}' > "$1/metadata.json"; echo x > "$1/caf\303\251"; ln -s /x "$1/l\303\251"`)
	res := f.run()
	if res.Outcome != "failed" {
		t.Fatalf("%+v", res)
	}
	for _, r := range fmt.Sprint(f.in.update(0)["error"]) {
		if r < 0x20 || r > 0x7e {
			t.Fatalf("non-ASCII in %q", f.in.update(0)["error"])
		}
	}
	if got := serverReason(strings.Repeat("a", 500) + "\n\u00e9"); len(got) != 200 {
		t.Fatalf("len %d", len(got))
	}
}
