package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wmetcalf/blastbox/agent/internal/config"
	"github.com/wmetcalf/blastbox/agent/internal/runner"
	"github.com/wmetcalf/blastbox/agent/internal/sandbox"
	"github.com/wmetcalf/blastbox/agent/internal/wire"
)

type pki struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
	ser  int64
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-90 * 24 * time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &pki{cert: c, key: k, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ser: 10}
}

func (p *pki) serverCert(t *testing.T) tls.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "ingress"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.cert, &k.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// issueNode signs a node certificate that satisfies config.CheckNodeCert.
func (p *pki) issueNode(t *testing.T, id string, pub *ecdsa.PublicKey, nb, na time.Time) []byte {
	t.Helper()
	eku, _ := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 99999, 1, 2}})
	info := []byte(`{"v":2,"node_id":"` + id + `","engines":[],"tiers":[],"credentials":false}`)
	p.ser++
	tpl := &x509.Certificate{SerialNumber: big.NewInt(p.ser), Subject: pkix.Name{CommonName: id},
		NotBefore: nb, NotAfter: na,
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: eku},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}, Value: info}}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.cert, pub, p.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func writeKey(t *testing.T, path string, k *ecdsa.PrivateKey) {
	t.Helper()
	if err := writeKeyExcl(path, k); err != nil {
		t.Fatal(err)
	}
}

// ingress is a scriptable control plane.
type ingress struct {
	t   *testing.T
	srv *httptest.Server
	ca  *pki

	mu          sync.Mutex
	claims      int
	hbs         []wire.Heartbeat
	sessions    []string
	updates     map[string]map[string]any // job id -> posted body
	csrs        [][]byte
	renewBodies []map[string]any
	issued      []byte
	dateOffset  time.Duration
	hbResp      map[string]any
	onClaim     func(n int) (code int, body string)
	jobStatus   map[string]int // job id -> status code override for updates
}

func newIngress(t *testing.T, ca *pki) *ingress {
	in := &ingress{t: t, ca: ca, updates: map[string]map[string]any{}, jobStatus: map[string]int{},
		hbResp: map[string]any{"heartbeat_s": 30}}
	in.srv = httptest.NewUnstartedServer(http.HandlerFunc(in.serve))
	in.srv.TLS = &tls.Config{Certificates: []tls.Certificate{ca.serverCert(t)}}
	in.srv.StartTLS()
	t.Cleanup(in.srv.Close)
	return in
}

func (in *ingress) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	in.mu.Lock()
	off := in.dateOffset
	in.mu.Unlock()
	w.Header().Set("Date", time.Now().Add(off).UTC().Format(http.TimeFormat))
	js := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}
	switch p := r.URL.Path; {
	case p == "/v1/nodes/challenge":
		js(200, map[string]any{"challenge": "c1", "expires_in": 60, "scope": "claim-next"})
	case p == "/v1/nodes/session":
		var m map[string]string
		json.Unmarshal(body, &m)
		in.mu.Lock()
		in.sessions = append(in.sessions, m["cert_pem"])
		n := len(in.sessions)
		in.mu.Unlock()
		js(200, map[string]any{"token": "tok-" + string(rune('a'+n%26)), "expires_in": 600})
	case p == "/v1/nodes/heartbeat":
		var hb wire.Heartbeat
		json.Unmarshal(body, &hb)
		in.mu.Lock()
		in.hbs = append(in.hbs, hb)
		resp := map[string]any{}
		for k, v := range in.hbResp {
			resp[k] = v
		}
		in.mu.Unlock()
		resp["server_time"] = float64(time.Now().Add(off).UnixNano()) / 1e9
		js(200, resp)
	case p == "/v1/nodes/claim":
		in.mu.Lock()
		in.claims++
		n, h := in.claims, in.onClaim
		in.mu.Unlock()
		if h == nil {
			w.WriteHeader(204)
			return
		}
		code, b := h(n)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		io.WriteString(w, b)
	case p == "/v1/nodes/renew":
		var m struct {
			CSR       string  `json:"csr_pem"`
			Cert      string  `json:"cert_pem"`
			IssuedAt  float64 `json:"issued_at"`
			Signature string  `json:"signature"`
		}
		if json.Unmarshal(body, &m) != nil {
			w.WriteHeader(400)
			return
		}
		blk, _ := pem.Decode([]byte(m.CSR))
		if blk == nil {
			w.WriteHeader(400)
			return
		}
		csr, err := x509.ParseCertificateRequest(blk.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			w.WriteHeader(400)
			return
		}
		cblk, _ := pem.Decode([]byte(m.Cert))
		if cblk == nil {
			w.WriteHeader(400)
			return
		}
		ccert, err := x509.ParseCertificate(cblk.Bytes)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		cpub, _ := ccert.PublicKey.(*ecdsa.PublicKey)
		if cpub == nil || ccert.Subject.CommonName != csr.Subject.CommonName ||
			m.IssuedAt != float64(int64(m.IssuedAt)) ||
			!wire.Verify(cpub, wire.RenewPayload(ccert.Subject.CommonName, m.CSR, int64(m.IssuedAt)), m.Signature) {
			w.WriteHeader(403)
			return
		}
		in.mu.Lock()
		in.renewBodies = append(in.renewBodies, map[string]any{"cert_pem": m.Cert, "csr_pem": m.CSR, "issued_at": m.IssuedAt})
		in.csrs = append(in.csrs, []byte(m.CSR))
		in.issued = in.ca.issueNode(in.t, csr.Subject.CommonName, csr.PublicKey.(*ecdsa.PublicKey),
			time.Now().Add(-time.Minute), time.Now().Add(7*24*time.Hour))
		in.mu.Unlock()
		w.WriteHeader(202)
	case p == "/v1/nodes/cert":
		in.mu.Lock()
		c := in.issued
		in.mu.Unlock()
		if c == nil {
			w.WriteHeader(404)
			return
		}
		js(200, map[string]any{"cert_pem": string(c)})
	case strings.HasPrefix(p, "/v1/nodes/jobs/") && r.Method == "POST":
		id := strings.TrimPrefix(p, "/v1/nodes/jobs/")
		var m map[string]any
		json.Unmarshal(body, &m)
		in.mu.Lock()
		in.updates[id] = m
		code := in.jobStatus[id]
		in.mu.Unlock()
		if code != 0 && code != 200 {
			w.WriteHeader(code)
			return
		}
		js(200, map[string]any{"ok": true})
	default:
		http.NotFound(w, r)
	}
}

func (in *ingress) claimCount() int { in.mu.Lock(); defer in.mu.Unlock(); return in.claims }
func (in *ingress) hbCount() int    { in.mu.Lock(); defer in.mu.Unlock(); return len(in.hbs) }
func (in *ingress) update(id string) map[string]any {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.updates[id]
}

func claimBody(jobID string) string {
	return `{"job":{"job_id":"` + jobID + `","claim_id":"cid-` + jobID + `"},"node_id":"node-a","receipt":"rcpt-` + jobID + `",
"run":{"deadline_s":60,"limits":{},"network":"none","params":{},"input":{"sha256":"","bytes":null,"filename":"s.bin"}}}`
}

type env struct {
	t    *testing.T
	ca   *pki
	in   *ingress
	dir  string
	cfg  *config.Config
	key  *ecdsa.PrivateKey
	cert []byte
}

// newEnv builds PKI, a fake ingress and a config whose node cert is valid for the given window.
func newEnv(t *testing.T, nb, na time.Time) *env {
	t.Helper()
	ca := newPKI(t)
	in := newIngress(t, ca)
	dir := t.TempDir()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := ca.issueNode(t, "node-a", &k.PublicKey, nb, na)
	os.WriteFile(filepath.Join(dir, "ca.pem"), ca.pem, 0o644)
	os.WriteFile(filepath.Join(dir, "node.crt"), cert, 0o644)
	writeKey(t, filepath.Join(dir, "node.key"), k)
	state := filepath.Join(dir, "state")
	os.MkdirAll(state, 0o700)
	cfg := &config.Config{Ingress: in.srv.URL, CAFile: filepath.Join(dir, "ca.pem"),
		CertFile: filepath.Join(dir, "node.crt"), KeyFile: filepath.Join(dir, "node.key"), StateDir: state, Claim: true,
		Engines: []config.Engine{{Name: "eng", Argv: []string{"/bin/true"}, Output: "stdout-envelope", Sandbox: "none", MinSandbox: "none"}}}
	return &env{t: t, ca: ca, in: in, dir: dir, cfg: cfg, key: k, cert: cert}
}

func fresh(t *testing.T) *env {
	return newEnv(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
}

type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *safeBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type fakeRunner struct {
	fn func(ctx context.Context, c *wire.Claim) runner.Result
}

func (f fakeRunner) Run(ctx context.Context, _ *wire.Client, _ config.Engine, c *wire.Claim, _ string) runner.Result {
	return f.fn(ctx, c)
}

// harness wires fast time and quiet logs onto an agent.
type harness struct {
	a      *Agent
	logs   *safeBuf
	mu     sync.Mutex
	sleeps []time.Duration
}

func newHarness(e *env) *harness {
	h := &harness{logs: &safeBuf{}}
	a := New(e.cfg)
	a.Version = "1.0.0"
	a.Log = slog.New(slog.NewJSONHandler(h.logs, nil))
	a.ProbeFn = func(context.Context, config.Engine) sandbox.ProbeResult { return sandbox.ProbeResult{OK: true} }
	a.SelfTestFn = a.ProbeFn
	a.Rand = func() float64 { return 0.5 }
	a.DrainGrace = 2 * time.Second
	a.Runner = fakeRunner{fn: func(context.Context, *wire.Claim) runner.Result { return runner.Result{Outcome: "done"} }}
	a.Sleep = func(ctx context.Context, d time.Duration) bool {
		h.mu.Lock()
		h.sleeps = append(h.sleeps, d)
		h.mu.Unlock()
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Millisecond):
			return true
		}
	}
	h.a = a
	return h
}

func (h *harness) slept(d time.Duration) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range h.sleeps {
		if s == d {
			return true
		}
	}
	return false
}

// start runs the agent; stop cancels it and returns Run's error.
func (h *harness) start(t *testing.T) (stop func() error) {
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- h.a.Run(ctx) }()
	var once sync.Once
	var err error
	stop = func() error {
		once.Do(func() {
			cancel()
			select {
			case err = <-errc:
			case <-time.After(10 * time.Second):
				t.Error("agent did not stop")
			}
		})
		return err
	}
	t.Cleanup(func() { stop() })
	return stop
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	dl := time.Now().Add(10 * time.Second)
	for time.Now().Before(dl) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func jobDir(e *env, id string, started bool, withClaim bool) string {
	d := filepath.Join(e.cfg.StateDir, "jobs", id)
	os.MkdirAll(d, 0o700)
	if withClaim {
		os.WriteFile(filepath.Join(d, "claim.json"), []byte(`{"job_id":"`+id+`","claim_id":"cid-`+id+`","receipt":"rcpt-`+id+`","engine":"eng","started":`+map[bool]string{true: "true", false: "false"}[started]+`}`), 0o600)
	}
	if started {
		os.WriteFile(filepath.Join(d, "started"), nil, 0o600)
	}
	return d
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
