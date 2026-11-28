package wire

import (
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
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/wmetcalf/blastbox/agent/internal/config"
	"github.com/wmetcalf/blastbox/agent/internal/conformance"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{c, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca *testCA) serverCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "ingress"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// fake is a scriptable ingress.
type fake struct {
	t                *testing.T
	srv              *httptest.Server
	mu               sync.Mutex
	urls             []string
	bodies           map[string][]byte
	sessions         int
	challenge, scope string
	pub              *ecdsa.PublicKey
	sigOK            []bool
	payloads         [][]byte
	token            string
	expires          float64
	handler          func(w http.ResponseWriter, r *http.Request) bool
	host             string
}

func newClient(t *testing.T, f *fake, ca *testCA) *Client {
	t.Helper()
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	os.WriteFile(caFile, ca.pem, 0o600)
	ingress := f.srv.URL
	if f.host != "" {
		ingress = strings.Replace(ingress, "127.0.0.1", f.host, 1)
	}
	cfg := &config.Config{
		Ingress: ingress, CAFile: caFile,
		CertFile: conformance.Path("node_certs", "v2_without_wg.crt"),
		KeyFile:  conformance.Path("node_certs", "v2_without_wg.key"),
	}
	c, err := New(cfg, "blastbox-agent/0.0.0 (test/test)")
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(readFile(t, cfg.CertFile))
	cert, _ := x509.ParseCertificate(blk.Bytes)
	f.pub = cert.PublicKey.(*ecdsa.PublicKey)
	return c
}

func readFile(t *testing.T, p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newFake(t *testing.T, ca *testCA) *fake {
	f := &fake{t: t, bodies: map[string][]byte{}, challenge: "1.7e+09:abc", scope: "claim-next",
		token: "tok-1", expires: 600}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{ca.serverCert(t)}}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) record(r *http.Request) []byte {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.urls = append(f.urls, r.URL.String())
	f.bodies[r.Method+" "+r.URL.Path] = b
	f.mu.Unlock()
	return b
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	body := f.record(r)
	if f.handler != nil && f.handler(w, r) {
		return
	}
	js := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}
	switch r.URL.Path {
	case "/v1/nodes/challenge":
		js(200, map[string]any{"challenge": f.challenge, "expires_in": 60, "scope": f.scope})
	case "/v1/nodes/session":
		var req struct{ CertPEM, Challenge, Signature string }
		var m map[string]string
		json.Unmarshal(body, &m)
		req.Challenge, req.Signature = m["challenge"], m["signature"]
		payload := SigningPayload(req.Challenge, f.scope, "node-v2")
		f.mu.Lock()
		f.payloads = append(f.payloads, payload)
		f.sigOK = append(f.sigOK, req.Challenge == f.challenge && Verify(f.pub, payload, req.Signature))
		f.sessions++
		n := f.sessions
		f.mu.Unlock()
		js(200, map[string]any{"token": f.token + "-" + strconv.Itoa(n), "expires_in": f.expires, "node_id": "node-v2"})
	default:
		http.NotFound(w, r)
	}
}

func setup(t *testing.T) (*fake, *Client) {
	ca := newCA(t, "test ingress CA")
	f := newFake(t, ca)
	return f, newClient(t, f, ca)
}

func TestHandshakeSignsOpaqueChallengeByteForByte(t *testing.T) {
	f, c := setup(t)
	if err := c.Session(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.sigOK) != 1 || !f.sigOK[0] {
		t.Fatalf("signature did not verify: %v", f.sigOK)
	}
	want := "blastbox/node-claim/v1\x001.7e+09:abc\x00claim-next\x00node-v2"
	if string(f.payloads[0]) != want {
		t.Fatalf("payload %q", f.payloads[0])
	}
}

func TestHandshakeConformanceVectors(t *testing.T) {
	var sf conformance.SigningFile
	if err := conformance.ReadJSON("signing_payload.json", &sf); err != nil {
		t.Fatal(err)
	}
	for _, cs := range sf.Cases {
		if cs.Scope != claimScope {
			// The client pins the scope (TestHandshakeRefusesOtherScopes); other scopes' byte
			// layout is covered by TestSigningPayloadVectors.
			continue
		}
		f, c := setup(t)
		f.challenge, f.scope = cs.Challenge, cs.Scope
		c.nodeID = cs.NodeID
		if err := c.Session(context.Background()); err != nil {
			t.Fatalf("%s: %v", cs.NodeID, err)
		}
		var m map[string]string
		json.Unmarshal(f.bodies["POST /v1/nodes/session"], &m)
		want, _ := hex.DecodeString(cs.PayloadHex)
		if !Verify(f.pub, want, m["signature"]) {
			t.Errorf("case %q/%q: signature not over the vector payload", cs.NodeID, cs.Scope)
		}
	}
}

func TestNoSecretsInURLsAndUserAgent(t *testing.T) {
	f, c := setup(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/nodes/claim" {
			if r.Header.Get("User-Agent") != "blastbox-agent/0.0.0 (test/test)" {
				t.Errorf("UA %q", r.Header.Get("User-Agent"))
			}
			w.WriteHeader(204)
			return true
		}
		return false
	}
	if cl, err := c.Claim(context.Background(), "eng", nil); err != nil || cl != nil {
		t.Fatalf("204 want nil,nil got %v %v", cl, err)
	}
	for _, u := range f.urls {
		if strings.Contains(u, "?") || strings.Contains(u, "tok-") {
			t.Errorf("secret-ish URL %q", u)
		}
	}
	var m map[string]any
	json.Unmarshal(f.bodies["POST /v1/nodes/claim"], &m)
	if _, ok := m["claimant_tier"]; ok {
		t.Error("claimant_tier sent")
	}
	if m["engine"] != "eng" {
		t.Error("engine missing")
	}
}

func TestWrongCARefused(t *testing.T) {
	ca := newCA(t, "real")
	other := newCA(t, "other")
	f := newFake(t, other) // server cert from a CA the client does not trust
	c := newClient(t, f, ca)
	err := c.Session(context.Background())
	if !errors.Is(err, ErrTLS) {
		t.Fatalf("want TLS failure, got %v", err)
	}
	if len(f.urls) != 0 {
		t.Fatal("request reached the server")
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	f, c := setup(t)
	var hits int
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer target.Close()
	f.handler = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/nodes/claim" {
			http.Redirect(w, r, target.URL+"/x", 307)
			return true
		}
		return false
	}
	_, err := c.Claim(context.Background(), "e", nil)
	if !errors.Is(err, ErrRedirect) {
		t.Fatalf("got %v", err)
	}
	if hits != 0 {
		t.Fatal("redirect followed")
	}
}

func Test401OneRehandshake(t *testing.T) {
	f, c := setup(t)
	var claims int
	f.handler = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/nodes/claim" {
			claims++
			if r.Header.Get(hdrSession) == "tok-1-1" {
				w.WriteHeader(401)
			} else {
				w.WriteHeader(204)
			}
			return true
		}
		return false
	}
	if _, err := c.Claim(context.Background(), "e", nil); err != nil {
		t.Fatal(err)
	}
	if f.sessions != 2 || claims != 2 || c.handshakes != 2 {
		t.Fatalf("sessions=%d claims=%d", f.sessions, claims)
	}
}

func Test401TwiceIsUnauthorizedNoLoop(t *testing.T) {
	f, c := setup(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/nodes/claim" {
			w.WriteHeader(401)
			return true
		}
		return false
	}
	_, err := c.Claim(context.Background(), "e", nil)
	if !errors.Is(err, ErrUnauthorized) || f.sessions != 2 {
		t.Fatalf("err=%v sessions=%d", err, f.sessions)
	}
}

func TestSessionRenewsBeforeExpiry(t *testing.T) {
	f, c := setup(t)
	f.expires = 100
	clock := time.Now()
	c.now = func() time.Time { return clock }
	ctx := context.Background()
	c.Session(ctx)
	c.Session(ctx)
	if f.sessions != 1 {
		t.Fatalf("sessions=%d", f.sessions)
	}
	clock = clock.Add(100*time.Second - renewMargin + time.Second)
	c.Session(ctx)
	if f.sessions != 2 {
		t.Fatalf("no renewal: sessions=%d", f.sessions)
	}
}

func TestForbiddenMapping(t *testing.T) {
	f, c := setup(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasPrefix(r.URL.Path, "/v1/nodes/claim") || strings.HasSuffix(r.URL.Path, "/input") ||
			strings.HasSuffix(r.URL.Path, "/heartbeat") {
			w.WriteHeader(403)
			return true
		}
		if r.URL.Path == "/v1/nodes/jobs/j1" {
			w.WriteHeader(409)
			return true
		}
		return false
	}
	ctx := context.Background()
	if _, err := c.Claim(ctx, "", nil); !errors.Is(err, ErrRefused) {
		t.Errorf("claim 403: %v", err)
	}
	cl := &Claim{JobID: "j1", ClaimID: "c", Receipt: "r", Run: RunBlock{Limits: Limits{MaxInput: 10}}}
	if _, err := c.FetchInput(ctx, cl, filepath.Join(t.TempDir(), "in")); !errors.Is(err, ErrClaimLost) {
		t.Errorf("input 403: %v", err)
	}
	if _, err := c.Heartbeat(ctx, Heartbeat{}); !errors.Is(err, ErrRefused) {
		t.Errorf("heartbeat 403: %v", err)
	}
	if err := c.Release(ctx, cl); !errors.Is(err, ErrClaimLost) {
		t.Errorf("release 409: %v", err)
	}
}

func TestClaimParsesRunBlock(t *testing.T) {
	f, c := setup(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/nodes/claim" {
			w.Write([]byte(`{"job":{"job_id":"j-9","claim_id":"cid","params":{"A":"1"}},"node_id":"node-v2","receipt":"rcpt",
"run":{"deadline_s":300,"limits":{"max_input":100,"max_metadata":1,"max_artifact":2,"max_total_artifacts":3,"max_artifacts":4},
"network":"none","params":{"A":"1"},"input":{"sha256":"ab","bytes":null,"filename":"s.bin"}}}`))
			return true
		}
		return false
	}
	cl, err := c.Claim(context.Background(), "e", []string{"x"})
	if err != nil {
		t.Fatal(err)
	}
	if cl.JobID != "j-9" || cl.ClaimID != "cid" || cl.Receipt != "rcpt" || cl.Run.Limits.MaxInput != 100 ||
		cl.Run.Network != "none" || cl.Run.Input.Bytes != nil || cl.Run.Params["A"] != "1" {
		t.Fatalf("%+v", cl)
	}
	var m map[string]any
	json.Unmarshal(f.bodies["POST /v1/nodes/claim"], &m)
	if ex := m["exclude"].([]any); len(ex) != 1 {
		t.Fatalf("exclude %v", m)
	}
}

func inputServer(f *fake, content []byte, hdrSum string, declared int) {
	f.handler = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/input") {
			if r.Header.Get(hdrClaim) != "c" || r.Header.Get(hdrReceipt) != "r" || r.Header.Get(hdrSession) == "" {
				w.WriteHeader(403)
				return true
			}
			w.Header().Set("x-blastbox-input-sha256", hdrSum)
			w.Header().Set("Content-Length", strconv.Itoa(declared))
			w.Write(content)
			return true
		}
		return false
	}
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func TestFetchInput(t *testing.T) {
	data := []byte("hello sample")
	i64 := int64(len(data))
	cases := []struct {
		name    string
		content []byte
		hdr     string
		decl    int
		cl      Claim
		ok      bool
	}{
		{"ok", data, sum(data), len(data), Claim{Run: RunBlock{Limits: Limits{MaxInput: 100}, Input: InputInfo{SHA256: sum(data), Bytes: &i64}}}, true},
		{"oversize by declared length", data, sum(data), len(data), Claim{Run: RunBlock{Limits: Limits{MaxInput: 5}}}, false},
		{"header hash mismatch", data, strings.Repeat("0", 64), len(data), Claim{Run: RunBlock{Limits: Limits{MaxInput: 100}}}, false},
		{"claim hash mismatch", data, sum(data), len(data), Claim{Run: RunBlock{Limits: Limits{MaxInput: 100}, Input: InputInfo{SHA256: strings.Repeat("1", 64)}}}, false},
		{"short body", data[:4], sum(data), len(data), Claim{Run: RunBlock{Limits: Limits{MaxInput: 100}}}, false},
		{"length differs from claim", data, sum(data), len(data), Claim{Run: RunBlock{Limits: Limits{MaxInput: 100}, Input: InputInfo{Bytes: ptr(int64(3))}}}, false},
		{"no limit", data, sum(data), len(data), Claim{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, c := setup(t)
			inputServer(f, tc.content, tc.hdr, tc.decl)
			cl := tc.cl
			cl.JobID, cl.ClaimID, cl.Receipt = "j1", "c", "r"
			dst := filepath.Join(t.TempDir(), "in")
			got, err := c.FetchInput(context.Background(), &cl, dst)
			if tc.ok {
				if err != nil || got != sum(data) {
					t.Fatalf("%v %s", err, got)
				}
				if b, _ := os.ReadFile(dst); string(b) != string(data) {
					t.Fatal("content")
				}
				return
			}
			if err == nil {
				t.Fatal("want error")
			}
			if _, serr := os.Stat(dst); serr == nil {
				t.Fatal("partial input left on disk")
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

func TestFetchInputAbortsOnUnboundedBody(t *testing.T) {
	f, c := setup(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/input") {
			w.Header().Set("x-blastbox-input-sha256", strings.Repeat("0", 64))
			w.(http.Flusher).Flush() // chunked, no Content-Length
			w.Write(make([]byte, 4096))
			return true
		}
		return false
	}
	cl := &Claim{JobID: "j1", ClaimID: "c", Receipt: "r", Run: RunBlock{Limits: Limits{MaxInput: 1000}}}
	dst := filepath.Join(t.TempDir(), "in")
	_, err := c.FetchInput(context.Background(), cl, dst)
	if err == nil || !strings.Contains(err.Error(), "max_input") {
		t.Fatalf("got %v", err)
	}
	if _, serr := os.Stat(dst); serr == nil {
		t.Fatal("left on disk")
	}
}

func TestPutResult(t *testing.T) {
	tar := filepath.Join(t.TempDir(), "r.tar")
	payload := []byte("TARBYTES")
	os.WriteFile(tar, payload, 0o600)
	for _, tc := range []struct {
		code   int
		body   string
		status string
		reason string
		err    error
	}{
		{202, `{"status":"accepted"}`, "accepted", "", nil},
		{200, `{"status":"done"}`, "done", "", nil},
		{422, `{"status":"failed","reason":"bad tar"}`, "failed", "bad tar", nil},
		{409, `{}`, "", "", ErrClaimLost},
		{403, `{}`, "", "", ErrClaimLost},
		{500, `{}`, "", "", ErrServer},
	} {
		f, c := setup(t)
		// Node clock 10 minutes ahead of the server.
		c.now = func() time.Time { return time.Now().Add(10 * time.Minute) }
		var hdr http.Header
		var got []byte
		var clen int64
		f.handler = func(w http.ResponseWriter, r *http.Request) bool {
			if r.Method == "PUT" {
				hdr, clen = r.Header.Clone(), r.ContentLength
				got = f.bodies["PUT /v1/nodes/jobs/j1/result"]
				w.WriteHeader(tc.code)
				w.Write([]byte(tc.body))
				return true
			}
			return false
		}
		cl := &Claim{JobID: "j1", ClaimID: "c1", Receipt: "r1"}
		start := c.now().Add(-time.Minute)
		o, err := c.PutResult(context.Background(), cl, tar, ResultMeta{
			WorkerRuntime: "nsjail", StartedAt: start, FinishedAt: c.now().Add(time.Hour)})
		if !errors.Is(err, tc.err) || (tc.err == nil && (o.Status != tc.status || o.Reason != tc.reason)) {
			t.Errorf("%d: %+v %v", tc.code, o, err)
			continue
		}
		if string(got) != string(payload) || clen != int64(len(payload)) ||
			hdr.Get("Content-Type") != "application/x-tar" ||
			hdr.Get(hdrClaim) != "c1" || hdr.Get(hdrReceipt) != "r1" || hdr.Get(hdrSession) == "" ||
			hdr.Get("x-blastbox-worker-runtime") != "nsjail" {
			t.Errorf("%d: bad request %v clen=%d body=%q", tc.code, hdr, clen, got)
		}
		// The server's Date told us the node is ~10 min ahead; times are shifted back and the
		// future finish is clamped to the server's present.
		fin, _ := strconv.ParseInt(hdr.Get("x-blastbox-finished-at-ms"), 10, 64)
		if d := time.UnixMilli(fin).Sub(time.Now()); d > 2*time.Second {
			t.Errorf("finished-at not clamped to server time: +%v", d)
		}
		st, _ := strconv.ParseInt(hdr.Get("x-blastbox-started-at-ms"), 10, 64)
		// started = (node now - 1 min) shifted onto the server clock = real now - 1 min
		if d := time.Since(time.UnixMilli(st)); d < 58*time.Second || d > 63*time.Second {
			t.Errorf("started-at-ms not translated to server time: %v ago", d)
		}
	}
}

func TestFailAndReleaseBodies(t *testing.T) {
	f, c := setup(t)
	c.now = func() time.Time { return time.Now().Add(10 * time.Minute) } // skewed node clock
	f.handler = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/nodes/jobs/j1" {
			w.Write([]byte(`{"job":{}}`))
			return true
		}
		return false
	}
	cl := &Claim{JobID: "j1", ClaimID: "c1", Receipt: "r1"}
	ctx := context.Background()
	if err := c.Fail(ctx, cl, strings.Repeat("é", 9000), c.now()); err != nil {
		t.Fatal(err)
	}
	var m struct {
		ClaimID, Receipt string
		Fields           map[string]any
		ExpectStatus     string `json:"expect_status"`
	}
	raw := f.bodies["POST /v1/nodes/jobs/j1"]
	json.Unmarshal(raw, &m)
	if m.Fields["status"] != "failed" || m.ExpectStatus != "running" {
		t.Fatalf("%s", raw)
	}
	if _, has := m.Fields["expires_at"]; has {
		t.Fatal("expires_at sent")
	}
	if e := m.Fields["error"].(string); len(e) > 8192 || !strings.HasPrefix(e, "é") {
		t.Fatalf("error len %d", len(e))
	}
	// First request learned the skew from Date (the Fail itself may be the first POST after the
	// handshake, so the session responses already set it).
	nowf := float64(time.Now().UnixNano()) / 1e9
	if fin := m.Fields["finished_at"].(float64); fin > nowf+2 || fin < nowf-5 {
		t.Fatalf("finished_at %v not within [now-5, now+2] of %v", fin, nowf)
	}
	if err := c.Release(ctx, cl); err != nil {
		t.Fatal(err)
	}
	m.Fields = nil
	json.Unmarshal(f.bodies["POST /v1/nodes/jobs/j1"], &m)
	if m.Fields["status"] != "queued" || m.Fields["claim_id"] != nil || len(m.Fields) != 2 || m.ExpectStatus != "running" {
		t.Fatalf("%s", f.bodies["POST /v1/nodes/jobs/j1"])
	}
	if _, present := func() (any, bool) {
		var raw map[string]map[string]json.RawMessage
		json.Unmarshal(f.bodies["POST /v1/nodes/jobs/j1"], &raw)
		v, ok := raw["fields"]["claim_id"]
		return v, ok
	}(); !present {
		t.Fatal("claim_id: null must be present")
	}
}

func TestHeartbeatRenewCertDisposition(t *testing.T) {
	f, c := setup(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/v1/nodes/heartbeat":
			w.Write([]byte(`{"server_time":` + strconv.FormatFloat(float64(time.Now().Add(-5*time.Minute).UnixNano())/1e9, 'f', 3, 64) +
				`,"min_agent_version":"0.0.0","heartbeat_s":30}`))
		case "/v1/nodes/renew":
			w.WriteHeader(202)
			w.Write([]byte(`{"queued":true}`))
		case "/v1/nodes/cert":
			w.Write([]byte(`{"cert_pem":"PEM","not_after":"x"}`))
		case "/v1/nodes/jobs/jj/disposition":
			w.Write([]byte(`{"job":{"status":"done","claim_id":null,"expires_at":null}}`))
		case "/v1/nodes/jobs/gone/disposition":
			w.Write([]byte(`{"job":null}`))
		default:
			return false
		}
		return true
	}
	ctx := context.Background()
	hr, err := c.Heartbeat(ctx, Heartbeat{AgentVersion: "1"})
	if err != nil || hr.HeartbeatS != 30 {
		t.Fatalf("%+v %v", hr, err)
	}
	if d := time.Since(c.ServerNow()); d < 4*time.Minute || d > 6*time.Minute {
		t.Errorf("skew not learned: server behind by %v", d)
	}
	var m map[string]any
	json.Unmarshal(f.bodies["POST /v1/nodes/heartbeat"], &m)
	if m["engines"] == nil || m["in_flight"] == nil {
		t.Error("lists must serialise as [] not null")
	}
	if err := c.Renew(ctx, []byte("CSR")); err != nil {
		t.Error(err)
	}
	if b, err := c.FetchCert(ctx); err != nil || string(b) != "PEM" {
		t.Error(b, err)
	}
	if s, err := c.Disposition(ctx, "jj"); err != nil || s != "done" {
		t.Error(s, err)
	}
	if s, err := c.Disposition(ctx, "gone"); err != nil || s != DispositionAbsent {
		t.Error(s, err)
	}
	if _, err := c.Disposition(ctx, "../x"); err == nil {
		t.Error("path traversal accepted")
	}
}

func TestOriginEnforcedAndConfigRejects(t *testing.T) {
	_, c := setup(t)
	req, _ := http.NewRequest("GET", "https://example.invalid/x", nil)
	if _, err := c.hc.Transport.RoundTrip(req); err == nil || !strings.Contains(err.Error(), "origin") {
		t.Fatalf("got %v", err)
	}
	for _, bad := range []string{"http://127.0.0.1:1", "https://u:p@127.0.0.1:1", "https://127.0.0.1:1/?q=1", "nope"} {
		cfg := &config.Config{Ingress: bad}
		if _, err := New(cfg, "ua"); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestKeyMismatchAndLoadKey(t *testing.T) {
	ca := newCA(t, "ca")
	f := newFake(t, ca)
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	os.WriteFile(caFile, ca.pem, 0o600)
	cfg := &config.Config{Ingress: f.srv.URL, CAFile: caFile,
		CertFile: conformance.Path("node_certs", "v2_without_wg.crt"),
		KeyFile:  conformance.Path("node_certs", "v1_with_wg.key")}
	if _, err := New(cfg, "ua"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("got %v", err)
	}
	// symlink refused
	link := filepath.Join(dir, "k")
	os.Symlink(conformance.Path("node_certs", "v2_without_wg.key"), link)
	if _, err := LoadKey(link); err == nil {
		t.Fatal("symlinked key accepted")
	}
	// SEC1 accepted
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(k)
	p := filepath.Join(dir, "sec1")
	os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
	if _, err := LoadKey(p); err != nil {
		t.Fatal(err)
	}
	// P-384 refused
	k3, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ = x509.MarshalPKCS8PrivateKey(k3)
	p = filepath.Join(dir, "p384")
	os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	if _, err := LoadKey(p); err == nil {
		t.Fatal("P-384 accepted")
	}
}

func TestHandshakeRefusesOtherScopes(t *testing.T) {
	f, c := setup(t)
	f.scope = "job-7f3a"
	if err := c.Session(context.Background()); !errors.Is(err, ErrRefused) {
		t.Fatalf("got %v", err)
	}
	if f.sessions != 0 || len(f.bodies["POST /v1/nodes/session"]) != 0 {
		t.Fatal("signed a challenge with a foreign scope")
	}
}

func TestTLSErrorClass(t *testing.T) {
	ca, other := newCA(t, "real"), newCA(t, "other")
	f := newFake(t, other)
	if err := newClient(t, f, ca).Session(context.Background()); !errors.Is(err, ErrTLS) || errors.Is(err, ErrServer) {
		t.Fatalf("wrong CA: %v", err)
	}
	// Cert has only the 127.0.0.1 IP SAN; dial "localhost".
	f2 := newFake(t, ca)
	f2.host = "localhost"
	if err := newClient(t, f2, ca).Session(context.Background()); !errors.Is(err, ErrTLS) {
		t.Fatalf("SAN mismatch: %v", err)
	}
	if len(f2.urls) != 0 {
		t.Fatal("request reached server")
	}
}

func TestClaimNodeIDMismatchRefused(t *testing.T) {
	f, c := setup(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/nodes/claim" {
			w.Write([]byte(`{"job":{"job_id":"j","claim_id":"c"},"node_id":"someone-else","receipt":"r","run":{}}`))
			return true
		}
		return false
	}
	if _, err := c.Claim(context.Background(), "", nil); !errors.Is(err, ErrRefused) {
		t.Fatalf("got %v", err)
	}
}

func TestRetryableAndDetailTruncation(t *testing.T) {
	f, c := setup(t)
	code := 408
	f.handler = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/nodes/renew" {
			w.WriteHeader(code)
			w.Write([]byte(`{"detail":"` + strings.Repeat("x", 1000) + `"}`))
			return true
		}
		return false
	}
	for _, code = range []int{408, 429} {
		if err := c.Renew(context.Background(), []byte("c")); !errors.Is(err, ErrServer) {
			t.Fatalf("%d: %v", code, err)
		}
	}
	code = 400
	err := c.Renew(context.Background(), []byte("c"))
	if !errors.Is(err, ErrRejected) || len(err.Error()) > 400 {
		t.Fatalf("%v", err)
	}
}

func Test401MidPutResultReopensBody(t *testing.T) {
	f, c := setup(t)
	tar := filepath.Join(t.TempDir(), "r.tar")
	os.WriteFile(tar, []byte("TARBYTES"), 0o600)
	var puts int
	var last []byte
	f.handler = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == "PUT" {
			puts++
			if r.Header.Get(hdrSession) == "tok-1-1" {
				w.WriteHeader(401)
				return true
			}
			last = f.bodies["PUT /v1/nodes/jobs/j1/result"]
			w.WriteHeader(202)
			w.Write([]byte(`{"status":"accepted"}`))
			return true
		}
		return false
	}
	o, err := c.PutResult(context.Background(), &Claim{JobID: "j1", ClaimID: "c", Receipt: "r"}, tar, ResultMeta{})
	if err != nil || o.Status != "accepted" || puts != 2 || string(last) != "TARBYTES" || c.handshakes != 2 {
		t.Fatalf("%+v %v puts=%d body=%q hs=%d", o, err, puts, last, c.handshakes)
	}
}

func TestHeartbeatSkewNotOverwrittenByDate(t *testing.T) {
	f, c := setup(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/nodes/heartbeat" {
			w.Write([]byte(`{"server_time":` + strconv.FormatFloat(float64(time.Now().Add(-5*time.Minute).UnixNano())/1e9, 'f', 3, 64) + `,"heartbeat_s":30}`))
			return true
		}
		if r.URL.Path == "/v1/nodes/claim" {
			w.WriteHeader(204)
			return true
		}
		return false
	}
	ctx := context.Background()
	if _, err := c.Heartbeat(ctx, Heartbeat{}); err != nil || !c.hbSkew.Load() {
		t.Fatal(err, c.hbSkew.Load())
	}
	before := c.skew.Load()
	c.Claim(ctx, "", nil)
	if c.skew.Load() != before {
		t.Fatal("Date overwrote the heartbeat skew")
	}
}

func keys(m map[string]json.RawMessage) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// The control plane's finalizer-only mode accepts exactly these key sets.
func TestFailAndReleaseExactKeySets(t *testing.T) {
	f, c := setup(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/nodes/jobs/j1" {
			w.Write([]byte(`{"job":{}}`))
			return true
		}
		return false
	}
	cl := &Claim{JobID: "j1", ClaimID: "c1", Receipt: "r1"}
	ctx := context.Background()
	decode := func() (map[string]json.RawMessage, map[string]json.RawMessage) {
		var top map[string]json.RawMessage
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(f.bodies["POST /v1/nodes/jobs/j1"], &top); err != nil {
			t.Fatal(err)
		}
		json.Unmarshal(top["fields"], &fields)
		return top, fields
	}
	want := func(got []string, w ...string) {
		t.Helper()
		if strings.Join(got, ",") != strings.Join(w, ",") {
			t.Fatalf("keys %v, want %v", got, w)
		}
	}
	if err := c.Release(ctx, cl); err != nil {
		t.Fatal(err)
	}
	top, fields := decode()
	want(keys(top), "claim_id", "expect_status", "fields", "receipt")
	want(keys(fields), "claim_id", "status")
	if string(top["expect_status"]) != `"running"` || string(fields["status"]) != `"queued"` || string(fields["claim_id"]) != "null" {
		t.Fatalf("%s", f.bodies["POST /v1/nodes/jobs/j1"])
	}
	if err := c.Fail(ctx, cl, "boom", c.now()); err != nil {
		t.Fatal(err)
	}
	top, fields = decode()
	want(keys(top), "claim_id", "expect_status", "fields", "receipt")
	want(keys(fields), "error", "finished_at", "status")
	if string(top["expect_status"]) != `"running"` {
		t.Fatalf("%s", top["expect_status"])
	}
	if err := c.Fail(ctx, cl, "", c.now()); err != nil {
		t.Fatal(err)
	}
	_, fields = decode()
	want(keys(fields), "finished_at", "status") // error is optional: omitted when empty
}

// finished_at is never before the run's started_at as the server knows it: the claim time.
func TestFailFinishedAtClampedToClaimTime(t *testing.T) {
	f, c := setup(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/nodes/jobs/j1" {
			w.Write([]byte(`{"job":{}}`))
			return true
		}
		return false
	}
	ctx := context.Background()
	if err := c.Session(ctx); err != nil {
		t.Fatal(err)
	}
	claimed := c.now().Add(-2 * time.Second)
	cl := &Claim{JobID: "j1", ClaimID: "c1", Receipt: "r1", ClaimedAt: claimed}
	// A finish time (e.g. a node clock step back) earlier than the claim.
	if err := c.Fail(ctx, cl, "x", claimed.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	var m struct{ Fields map[string]any }
	json.Unmarshal(f.bodies["POST /v1/nodes/jobs/j1"], &m)
	fin := m.Fields["finished_at"].(float64)
	startedSrv := float64(c.toServer(claimed).UnixNano()) / 1e9
	if fin < startedSrv-1e-6 {
		t.Fatalf("finished_at %v before the claim time %v", fin, startedSrv)
	}
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOnContactReportsDialErrorsAndAnyHTTPResponse(t *testing.T) {
	ca := newCA(t, "test ingress CA")
	f := newFake(t, ca)
	c := newClient(t, f, ca)
	var got []error
	c.OnContact = func(err error) { got = append(got, err) }
	dial := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.EADDRNOTAVAIL)}
	c.hc.Transport = rtFunc(func(*http.Request) (*http.Response, error) { return nil, dial })
	if err := c.Session(context.Background()); err == nil {
		t.Fatal("want an error")
	}
	if len(got) != 1 || !errors.Is(got[0], syscall.EADDRNOTAVAIL) {
		t.Fatalf("want the dial error with its errno: %v", got)
	}
	if strings.Contains(fmt.Sprint(got[0]), "/v1/nodes") {
		t.Fatalf("hook error carries the URL: %v", got[0])
	}
	for _, code := range []int{200, 302, 404, 503} {
		got = nil
		code := code
		c.hc.Transport = rtFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: code, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{}"))}, nil
		})
		c.Session(context.Background())
		if len(got) == 0 || got[0] != nil {
			t.Fatalf("status %d must count as reachable: %v", code, got)
		}
	}
}

func TestOnSessionReportsHandshakeResult(t *testing.T) {
	ca := newCA(t, "test ingress CA")
	f := newFake(t, ca)
	c := newClient(t, f, ca)
	var got []error
	c.OnSession = func(err error) { got = append(got, err) }
	if err := c.Session(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.Session(context.Background()); err != nil { // cached token: no new handshake
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != nil {
		t.Fatalf("want one nil report for one handshake, got %v", got)
	}
	c2 := newClient(t, f, ca)
	var got2 []error
	c2.OnSession = func(err error) { got2 = append(got2, err) }
	c2.hc.Transport = rtFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("down") })
	c2.Session(context.Background())
	if len(got2) != 1 || got2[0] == nil {
		t.Fatalf("want one failure report, got %v", got2)
	}
}

// The ingress refusing the node's client certificate (expired, revoked, wrong CA) is a TLS
// alert FROM the server; it needs an operator just like a client-side verification failure,
// so it is ErrTLS (the long operator back-off), never a transient server error.
func TestClientCertRejectedByIngressIsTLS(t *testing.T) {
	ca, other := newCA(t, "real"), newCA(t, "other")
	f := newFake(t, ca)
	f.srv.Close()
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	pool := x509.NewCertPool()
	pool.AddCert(other.cert)
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{ca.serverCert(t)},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	f.srv.StartTLS()
	err := newClient(t, f, ca).Session(context.Background())
	if !errors.Is(err, ErrTLS) || errors.Is(err, ErrServer) {
		t.Fatalf("client cert refused by the ingress: %v", err)
	}
}
