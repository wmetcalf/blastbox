package wire

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/wmetcalf/blastbox/agent/internal/config"
)

// Typed outcomes. Callers branch on these with errors.Is.
var (
	ErrRefused      = errors.New("wire: refused by the control plane (403)")
	ErrClaimLost    = errors.New("wire: claim lost")
	ErrUnauthorized = errors.New("wire: session rejected after re-handshake (401)")
	ErrServer       = errors.New("wire: server or network error (retryable)")
	ErrRedirect     = errors.New("wire: redirect refused")
	ErrRejected     = errors.New("wire: request rejected (4xx)")
	ErrNotFound     = errors.New("wire: not found")
)

// DispositionAbsent is what Disposition returns when the control plane has no such job.
const DispositionAbsent = "absent"

const (
	hdrSession = "x-blastbox-node-session"
	hdrClaim   = "x-blastbox-claim-id"
	hdrReceipt = "x-blastbox-receipt"

	renewMargin   = 30 * time.Second
	jsonTimeout   = 30 * time.Second
	streamTimeout = 30 * time.Minute
	maxJSONBody   = 4 << 20
	maxErrorChars = 8192
)

var jobIDRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// Limits mirrors the claim's run.limits.
type Limits struct {
	MaxInput          int64 `json:"max_input"`
	MaxMetadata       int64 `json:"max_metadata"`
	MaxArtifact       int64 `json:"max_artifact"`
	MaxTotalArtifacts int64 `json:"max_total_artifacts"`
	MaxArtifacts      int64 `json:"max_artifacts"`
}

// InputInfo mirrors run.input. Bytes is nil when the server does not know the size.
type InputInfo struct {
	SHA256   string `json:"sha256"`
	Bytes    *int64 `json:"bytes"`
	Filename string `json:"filename"`
}

// RunBlock is the server-authored execution contract of a claim.
type RunBlock struct {
	DeadlineS int            `json:"deadline_s"`
	Limits    Limits         `json:"limits"`
	Network   string         `json:"network"`
	Params    map[string]any `json:"params"`
	Input     InputInfo      `json:"input"`
}

// Claim is one handed-over job. Job is the raw record; the agent reads Run, not Job.params.
type Claim struct {
	Job     json.RawMessage
	JobID   string
	ClaimID string
	Receipt string
	NodeID  string
	Run     RunBlock
}

// ResultMeta describes an uploaded result. Times are local; the client translates them to
// the server's clock.
type ResultMeta struct {
	WorkerRuntime string
	StartedAt     time.Time
	FinishedAt    time.Time
}

// Outcome is the control plane's answer to a result upload.
type Outcome struct {
	Status string // "accepted" | "done" | "failed"
	Reason string
}

// Heartbeat is the body of POST /v1/nodes/heartbeat.
type Heartbeat struct {
	AgentVersion string            `json:"agent_version"`
	BinarySHA256 string            `json:"binary_sha256"`
	GOOS         string            `json:"goos"`
	GOARCH       string            `json:"goarch"`
	StartedAt    string            `json:"started_at"`
	Engines      []HeartbeatEngine `json:"engines"`
	InFlight     []HeartbeatJob    `json:"in_flight"`
	CertNotAfter string            `json:"cert_not_after"`
}

// HeartbeatEngine reports one engine's state.
type HeartbeatEngine struct {
	Name       string `json:"name"`
	Sandbox    string `json:"sandbox"`
	Floor      string `json:"floor"`
	Slots      int    `json:"slots"`
	Busy       int    `json:"busy"`
	SelftestOK bool   `json:"selftest_ok"`
	SelftestAt string `json:"selftest_at"`
}

// HeartbeatJob reports one in-flight job.
type HeartbeatJob struct {
	JobID      string `json:"job_id"`
	ClaimID    string `json:"claim_id"`
	StartedAt  string `json:"started_at"`
	DeadlineAt string `json:"deadline_at"`
}

// HeartbeatResp is the control plane's heartbeat answer.
type HeartbeatResp struct {
	ServerTime      float64 `json:"server_time"`
	MinAgentVersion string  `json:"min_agent_version"`
	HeartbeatS      int     `json:"heartbeat_s"`
}

// Client speaks the node protocol over one pinned-CA HTTPS origin.
type Client struct {
	base   *url.URL
	origin string
	hc     *http.Client
	ua     string
	nodeID string
	cert   string // PEM, sent in the session request
	key    *ecdsa.PrivateKey

	now  func() time.Time
	skew atomic.Int64 // server clock minus local clock, ns

	mu         sync.Mutex
	token      string
	tokenUntil time.Time
	handshakes int
}

type originOnly struct {
	origin string
	next   http.RoundTripper
}

func (o originOnly) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme+"://"+r.URL.Host != o.origin {
		return nil, fmt.Errorf("wire: %s is not the ingress origin", r.URL.Redacted())
	}
	return o.next.RoundTrip(r)
}

// New builds a client. TLS roots are only cfg.CAFile; no proxy; no redirects.
func New(cfg *config.Config, ua string) (*Client, error) {
	base, err := url.Parse(cfg.Ingress)
	if err != nil || base.Scheme != "https" || base.Hostname() == "" || base.User != nil ||
		base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("wire: ingress must be a plain https URL")
	}
	caPEM, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("wire: ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("wire: ca_file holds no certificate")
	}
	certPEM, err := os.ReadFile(cfg.CertFile)
	if err != nil {
		return nil, fmt.Errorf("wire: cert_file: %w", err)
	}
	blk, _ := pem.Decode(certPEM)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, errors.New("wire: cert_file has no CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("wire: cert_file: %w", err)
	}
	key, err := LoadKey(cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("wire: node key does not match the node certificate")
	}
	origin := "https://" + base.Host
	tr := &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12, ServerName: base.Hostname()},
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		MaxIdleConnsPerHost:   2,
		ForceAttemptHTTP2:     true,
	}
	c := &Client{
		base: base, origin: origin, ua: ua, nodeID: cert.Subject.CommonName,
		cert: string(certPEM), key: key, now: time.Now,
		hc: &http.Client{
			Transport: originOnly{origin: origin, next: tr},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return ErrRedirect
			},
		},
	}
	return c, nil
}

// NodeID is the certificate's subject CN.
func (c *Client) NodeID() string { return c.nodeID }

// ServerNow estimates the control plane's current time.
func (c *Client) ServerNow() time.Time { return c.now().Add(time.Duration(c.skew.Load())) }

func (c *Client) toServer(t time.Time) time.Time {
	s := t.Add(time.Duration(c.skew.Load()))
	if n := c.ServerNow(); s.After(n) {
		return n
	}
	return s
}

func (c *Client) noteDate(h http.Header) {
	if d := h.Get("Date"); d != "" {
		if t, err := http.ParseTime(d); err == nil {
			c.skew.Store(int64(t.Sub(c.now())))
		}
	}
}

// ---- transport ----

type reqSpec struct {
	method  string
	path    string
	headers map[string]string
	body    func() (io.ReadCloser, int64, error) // fresh body per attempt
	ctype   string
	timeout time.Duration
}

type resp struct {
	*http.Response
	cancel func()
}

func (r *resp) Close() {
	r.Body.Close()
	r.cancel()
}

func (c *Client) send(ctx context.Context, s reqSpec, token string) (*resp, error) {
	to := s.timeout
	if to == 0 {
		to = jsonTimeout
	}
	rctx, cancel := context.WithTimeout(ctx, to)
	u := *c.base
	u.Path = strings.TrimRight(c.base.Path, "/") + s.path
	var body io.Reader
	var rc io.ReadCloser
	var n int64
	if s.body != nil {
		var err error
		if rc, n, err = s.body(); err != nil {
			cancel()
			return nil, err
		}
		body = rc
	}
	req, err := http.NewRequestWithContext(rctx, s.method, u.String(), body)
	if err != nil {
		cancel()
		if rc != nil {
			rc.Close()
		}
		return nil, err
	}
	if rc != nil {
		req.ContentLength = n
		req.GetBody = nil
	}
	req.Header.Set("User-Agent", c.ua)
	req.Header.Set("Accept", "application/json")
	if s.ctype != "" {
		req.Header.Set("Content-Type", s.ctype)
	}
	if token != "" {
		req.Header.Set(hdrSession, token)
	}
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}
	r, err := c.hc.Do(req)
	if err != nil {
		cancel()
		if errors.Is(err, ErrRedirect) {
			return nil, ErrRedirect
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w: %v", ErrServer, scrub(err))
	}
	c.noteDate(r.Header)
	if r.StatusCode >= 300 && r.StatusCode < 400 {
		r.Body.Close()
		cancel()
		return nil, ErrRedirect
	}
	return &resp{Response: r, cancel: cancel}, nil
}

// scrub drops the URL from a url.Error so logs carry no request details.
func scrub(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// authed sends with the session, re-handshaking exactly once on 401.
func (c *Client) authed(ctx context.Context, s reqSpec) (*resp, error) {
	tok, err := c.ensure(ctx)
	if err != nil {
		return nil, err
	}
	r, err := c.send(ctx, s, tok)
	if err != nil {
		return nil, err
	}
	if r.StatusCode != http.StatusUnauthorized {
		return r, nil
	}
	r.Close()
	if tok, err = c.handshake(ctx, tok); err != nil {
		return nil, err
	}
	r, err = c.send(ctx, s, tok)
	if err != nil {
		return nil, err
	}
	if r.StatusCode == http.StatusUnauthorized {
		r.Close()
		return nil, ErrUnauthorized
	}
	return r, nil
}

func readJSON(r *resp, v any) error {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBody+1))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrServer, scrub(err))
	}
	if len(raw) > maxJSONBody {
		return fmt.Errorf("%w: response too large", ErrServer)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%w: malformed response", ErrServer)
	}
	return nil
}

// detail extracts FastAPI's {"detail": ...} for error messages.
func detail(r *resp) string {
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	var d struct {
		Detail any `json:"detail"`
	}
	if json.Unmarshal(raw, &d) == nil {
		if s, ok := d.Detail.(string); ok {
			return s
		}
	}
	return ""
}

// statusErr maps a non-success status. claimed means the caller held the claim, so 403 = lost.
func statusErr(r *resp, claimed bool) error {
	code := r.StatusCode
	switch {
	case code == http.StatusForbidden && claimed, code == http.StatusConflict:
		return fmt.Errorf("%w: HTTP %d", ErrClaimLost, code)
	case code == http.StatusForbidden:
		return ErrRefused
	case code == http.StatusNotFound:
		return ErrNotFound
	case code >= 500:
		return fmt.Errorf("%w: HTTP %d", ErrServer, code)
	default:
		return fmt.Errorf("%w: HTTP %d: %s", ErrRejected, code, detail(r))
	}
}

// ---- session ----

func (c *Client) valid() bool { return c.token != "" && c.now().Before(c.tokenUntil) }

// Session ensures a live session, handshaking if none exists or it is within 30 s of expiry.
func (c *Client) Session(ctx context.Context) error {
	_, err := c.ensure(ctx)
	return err
}

func (c *Client) ensure(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.valid() {
		t := c.token
		c.mu.Unlock()
		return t, nil
	}
	c.mu.Unlock()
	return c.handshake(ctx, "")
}

// handshake opens a session unless another caller already replaced stale.
func (c *Client) handshake(ctx context.Context, stale string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.valid() && c.token != stale {
		return c.token, nil
	}
	c.token = ""
	r, err := c.send(ctx, reqSpec{method: "GET", path: "/v1/nodes/challenge"}, "")
	if err != nil {
		return "", err
	}
	var ch struct {
		Challenge string `json:"challenge"`
		Scope     string `json:"scope"`
	}
	if r.StatusCode != 200 {
		defer r.Close()
		return "", statusErr(r, false)
	}
	err = readJSON(r, &ch)
	r.Close()
	if err != nil {
		return "", err
	}
	if ch.Challenge == "" {
		return "", fmt.Errorf("%w: incomplete challenge", ErrServer)
	}
	sig, err := Sign(c.key, SigningPayload(ch.Challenge, ch.Scope, c.nodeID))
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(map[string]string{
		"cert_pem": c.cert, "challenge": ch.Challenge, "signature": sig})
	r, err = c.send(ctx, reqSpec{method: "POST", path: "/v1/nodes/session", ctype: "application/json",
		body: bytesBody(body)}, "")
	if err != nil {
		return "", err
	}
	defer r.Close()
	if r.StatusCode != 200 {
		return "", statusErr(r, false)
	}
	var s struct {
		Token     string  `json:"token"`
		ExpiresIn float64 `json:"expires_in"`
	}
	if err := readJSON(r, &s); err != nil {
		return "", err
	}
	if s.Token == "" {
		return "", fmt.Errorf("%w: no token", ErrServer)
	}
	life := time.Duration(s.ExpiresIn * float64(time.Second))
	if life > 2*renewMargin {
		life -= renewMargin
	} else {
		life /= 2
	}
	c.token = s.Token
	c.tokenUntil = c.now().Add(life)
	c.handshakes++
	return c.token, nil
}

func bytesBody(b []byte) func() (io.ReadCloser, int64, error) {
	return func() (io.ReadCloser, int64, error) {
		return io.NopCloser(bytes.NewReader(b)), int64(len(b)), nil
	}
}

func jsonBody(v any) (func() (io.ReadCloser, int64, error), error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return bytesBody(b), nil
}

func jobPath(id, suffix string) (string, error) {
	if !jobIDRE.MatchString(id) {
		return "", errors.New("wire: invalid job id")
	}
	return "/v1/nodes/jobs/" + id + suffix, nil
}

func claimHeaders(cl *Claim) map[string]string {
	return map[string]string{hdrClaim: cl.ClaimID, hdrReceipt: cl.Receipt}
}

// ---- claim ----

// Claim asks for work. (nil, nil) means nothing to do (204). claimant_tier is never sent.
func (c *Client) Claim(ctx context.Context, engine string, exclude []string) (*Claim, error) {
	req := map[string]any{"exclude": exclude}
	if exclude == nil {
		req["exclude"] = []string{}
	}
	if engine != "" {
		req["engine"] = engine
	}
	body, err := jsonBody(req)
	if err != nil {
		return nil, err
	}
	r, err := c.authed(ctx, reqSpec{method: "POST", path: "/v1/nodes/claim", ctype: "application/json", body: body})
	if err != nil {
		return nil, err
	}
	defer r.Close()
	switch r.StatusCode {
	case 204:
		return nil, nil
	case 200:
	default:
		return nil, statusErr(r, false)
	}
	var out struct {
		Job     json.RawMessage `json:"job"`
		NodeID  string          `json:"node_id"`
		Receipt string          `json:"receipt"`
		Run     RunBlock        `json:"run"`
	}
	if err := readJSON(r, &out); err != nil {
		return nil, err
	}
	var j struct {
		JobID   string `json:"job_id"`
		ClaimID string `json:"claim_id"`
	}
	if err := json.Unmarshal(out.Job, &j); err != nil || !jobIDRE.MatchString(j.JobID) ||
		j.ClaimID == "" || out.Receipt == "" {
		return nil, fmt.Errorf("%w: incomplete claim", ErrServer)
	}
	return &Claim{Job: out.Job, JobID: j.JobID, ClaimID: j.ClaimID, Receipt: out.Receipt,
		NodeID: out.NodeID, Run: out.Run}, nil
}

// ---- input ----

// FetchInput streams the job's input to dst (created exclusively, mode 0600; removed on any
// failure) and returns its sha256. It aborts beyond Run.Limits.MaxInput, on a short body, and
// on any hash disagreement between the header, the content and Run.Input.SHA256.
func (c *Client) FetchInput(ctx context.Context, cl *Claim, dst string) (sum string, err error) {
	p, err := jobPath(cl.JobID, "/input")
	if err != nil {
		return "", err
	}
	r, err := c.authed(ctx, reqSpec{method: "GET", path: p, headers: claimHeaders(cl), timeout: streamTimeout})
	if err != nil {
		return "", err
	}
	defer r.Close()
	if r.StatusCode != 200 {
		return "", statusErr(r, true)
	}
	max := cl.Run.Limits.MaxInput
	if max <= 0 {
		return "", errors.New("wire: claim carries no max_input limit")
	}
	if r.ContentLength > max {
		return "", fmt.Errorf("wire: input larger than max_input (%d)", max)
	}
	if b := cl.Run.Input.Bytes; b != nil && r.ContentLength >= 0 && r.ContentLength != *b {
		return "", errors.New("wire: input length differs from the claim")
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	defer func() {
		f.Close()
		if err != nil {
			os.Remove(dst)
		}
	}()
	hw := newSHA()
	n, cerr := io.Copy(io.MultiWriter(f, hw), io.LimitReader(r.Body, max+1))
	if cerr != nil {
		return "", fmt.Errorf("%w: input stream: %v", ErrServer, scrub(cerr))
	}
	if n > max {
		return "", fmt.Errorf("wire: input larger than max_input (%d)", max)
	}
	if r.ContentLength >= 0 && n != r.ContentLength {
		return "", errors.New("wire: input body shorter than Content-Length")
	}
	if b := cl.Run.Input.Bytes; b != nil && n != *b {
		return "", errors.New("wire: input length differs from the claim")
	}
	got := hw.sum()
	if h := strings.ToLower(r.Header.Get("x-blastbox-input-sha256")); h != got {
		return "", errors.New("wire: input hash differs from the header")
	}
	if want := strings.ToLower(cl.Run.Input.SHA256); want != "" && want != got {
		return "", errors.New("wire: input hash differs from the claim")
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	return got, nil
}

// ---- result ----

// PutResult uploads the result tar, streamed from tarPath. 409/403 mean the claim is lost.
func (c *Client) PutResult(ctx context.Context, cl *Claim, tarPath string, meta ResultMeta) (Outcome, error) {
	p, err := jobPath(cl.JobID, "/result")
	if err != nil {
		return Outcome{}, err
	}
	if err := c.Session(ctx); err != nil { // learn the server clock before translating times
		return Outcome{}, err
	}
	h := claimHeaders(cl)
	if meta.WorkerRuntime != "" {
		h["x-blastbox-worker-runtime"] = meta.WorkerRuntime
	}
	if !meta.StartedAt.IsZero() {
		h["x-blastbox-started-at-ms"] = strconv.FormatInt(c.toServer(meta.StartedAt).UnixMilli(), 10)
	}
	if !meta.FinishedAt.IsZero() {
		h["x-blastbox-finished-at-ms"] = strconv.FormatInt(c.toServer(meta.FinishedAt).UnixMilli(), 10)
	}
	open := func() (io.ReadCloser, int64, error) {
		f, err := os.Open(tarPath)
		if err != nil {
			return nil, 0, err
		}
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() {
			f.Close()
			return nil, 0, errors.New("wire: result tar is not a regular file")
		}
		return f, st.Size(), nil
	}
	r, err := c.authed(ctx, reqSpec{method: "PUT", path: p, headers: h, body: open,
		ctype: "application/x-tar", timeout: streamTimeout})
	if err != nil {
		return Outcome{}, err
	}
	defer r.Close()
	var out struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	switch r.StatusCode {
	case 200, 202, 422:
		if err := readJSON(r, &out); err != nil {
			return Outcome{}, err
		}
		want := map[int]string{200: "done", 202: "accepted", 422: "failed"}[r.StatusCode]
		if out.Status != want {
			return Outcome{}, fmt.Errorf("%w: unexpected status %q", ErrServer, out.Status)
		}
		return Outcome{Status: out.Status, Reason: out.Reason}, nil
	default:
		return Outcome{}, statusErr(r, true)
	}
}

// ---- fail / release ----

func (c *Client) update(ctx context.Context, cl *Claim, fields map[string]any) error {
	p, err := jobPath(cl.JobID, "")
	if err != nil {
		return err
	}
	body, err := jsonBody(map[string]any{
		"claim_id": cl.ClaimID, "receipt": cl.Receipt, "fields": fields, "expect_status": "running"})
	if err != nil {
		return err
	}
	r, err := c.authed(ctx, reqSpec{method: "POST", path: p, ctype: "application/json", body: body})
	if err != nil {
		return err
	}
	defer r.Close()
	if r.StatusCode != 200 {
		return statusErr(r, true)
	}
	return nil
}

// Fail marks the held job failed. expires_at is never sent. finishedAt is a local time,
// translated to the server clock and clamped to the server's present.
func (c *Client) Fail(ctx context.Context, cl *Claim, reason string, finishedAt time.Time) error {
	if err := c.Session(ctx); err != nil { // learn the server clock before translating times
		return err
	}
	if finishedAt.IsZero() {
		finishedAt = c.now()
	}
	fin := float64(c.toServer(finishedAt).UnixNano()) / 1e9
	return c.update(ctx, cl, map[string]any{
		"status": "failed", "error": truncate(reason, maxErrorChars), "finished_at": fin})
}

// Release puts an unstarted job back on the queue.
func (c *Client) Release(ctx context.Context, cl *Claim) error {
	return c.update(ctx, cl, map[string]any{"status": "queued", "claim_id": nil})
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	s = s[:max]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// ---- heartbeat / renew / cert / disposition ----

// Heartbeat reports liveness and learns the control plane's clock.
func (c *Client) Heartbeat(ctx context.Context, hb Heartbeat) (HeartbeatResp, error) {
	if hb.Engines == nil {
		hb.Engines = []HeartbeatEngine{}
	}
	if hb.InFlight == nil {
		hb.InFlight = []HeartbeatJob{}
	}
	body, err := jsonBody(hb)
	if err != nil {
		return HeartbeatResp{}, err
	}
	sent := c.now()
	r, err := c.authed(ctx, reqSpec{method: "POST", path: "/v1/nodes/heartbeat", ctype: "application/json", body: body})
	if err != nil {
		return HeartbeatResp{}, err
	}
	defer r.Close()
	if r.StatusCode != 200 {
		return HeartbeatResp{}, statusErr(r, false)
	}
	var out HeartbeatResp
	if err := readJSON(r, &out); err != nil {
		return HeartbeatResp{}, err
	}
	if out.ServerTime > 0 {
		mid := sent.Add(c.now().Sub(sent) / 2)
		c.skew.Store(int64(time.Duration(out.ServerTime*1e9) - time.Duration(mid.UnixNano())))
	}
	return out, nil
}

// Renew queues a CSR for certificate renewal.
func (c *Client) Renew(ctx context.Context, csrPEM []byte) error {
	body, err := jsonBody(map[string]string{"csr_pem": string(csrPEM)})
	if err != nil {
		return err
	}
	r, err := c.authed(ctx, reqSpec{method: "POST", path: "/v1/nodes/renew", ctype: "application/json", body: body})
	if err != nil {
		return err
	}
	defer r.Close()
	if r.StatusCode != 202 {
		return statusErr(r, false)
	}
	return nil
}

// FetchCert returns the node's current certificate PEM (ErrNotFound if none is issued yet).
func (c *Client) FetchCert(ctx context.Context) ([]byte, error) {
	r, err := c.authed(ctx, reqSpec{method: "GET", path: "/v1/nodes/cert"})
	if err != nil {
		return nil, err
	}
	defer r.Close()
	if r.StatusCode != 200 {
		return nil, statusErr(r, false)
	}
	var out struct {
		CertPEM string `json:"cert_pem"`
	}
	if err := readJSON(r, &out); err != nil {
		return nil, err
	}
	if out.CertPEM == "" {
		return nil, fmt.Errorf("%w: empty certificate", ErrServer)
	}
	return []byte(out.CertPEM), nil
}

// Disposition returns a job's status ("running", "done", ...) or DispositionAbsent.
func (c *Client) Disposition(ctx context.Context, jobID string) (string, error) {
	p, err := jobPath(jobID, "/disposition")
	if err != nil {
		return "", err
	}
	r, err := c.authed(ctx, reqSpec{method: "GET", path: p})
	if err != nil {
		return "", err
	}
	defer r.Close()
	if r.StatusCode != 200 {
		return "", statusErr(r, false)
	}
	var out struct {
		Job *struct {
			Status string `json:"status"`
		} `json:"job"`
	}
	if err := readJSON(r, &out); err != nil {
		return "", err
	}
	if out.Job == nil {
		return DispositionAbsent, nil
	}
	return out.Job.Status, nil
}
