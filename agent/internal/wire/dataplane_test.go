package wire

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wmetcalf/blastbox/agent/internal/conformance"
)

// vectorFiles lists conformance/v1/<dir>/*.json (non-recursive), sorted.
func vectorFiles(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(conformance.Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		t.Fatalf("no vectors under %s", dir)
	}
	return out
}

type claimVector struct {
	Status   int             `json:"status"`
	Body     json.RawMessage `json:"body"`
	Decision string          `json:"decision"`
}

// asNode rewrites the vector's node_id (the reference rig's "alpha") to the test client's.
func asNode(t *testing.T, body json.RawMessage, node string) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["node_id"]; ok {
		m["node_id"] = node
	}
	b, _ := json.Marshal(m)
	return b
}

func writeVector(w http.ResponseWriter, status int, body []byte) {
	if body != nil && string(body) != "null" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)
	if body != nil && string(body) != "null" {
		w.Write(body)
	}
}

// TestClaimResponseVectors replays each real POST /v1/nodes/claim answer and checks the
// agent's decision: run, idle, rehandshake (exactly one new handshake), refused (no
// re-handshake), or release_unstarted (any run.network other than "none"; see Runner.Run).
func TestClaimResponseVectors(t *testing.T) {
	for _, name := range vectorFiles(t, "claim_responses") {
		t.Run(strings.TrimSuffix(name, ".json"), func(t *testing.T) {
			var v claimVector
			if err := conformance.ReadJSON(filepath.Join("claim_responses", name), &v); err != nil {
				t.Fatal(err)
			}
			f, c := setup(t)
			var mu sync.Mutex
			claims := 0
			f.handler = func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/v1/nodes/claim" {
					return false
				}
				mu.Lock()
				claims++
				n := claims
				mu.Unlock()
				if n > 1 { // after a re-handshake: nothing to do
					w.WriteHeader(204)
					return true
				}
				body := []byte(v.Body)
				if v.Status == 200 {
					body = asNode(t, v.Body, "node-v2")
				}
				writeVector(w, v.Status, body)
				return true
			}
			cl, err := c.Claim(context.Background(), "clamav", nil)
			got := ""
			switch {
			case errors.Is(err, ErrRefused):
				got = "refused"
			case err != nil:
				t.Fatalf("claim: %v", err)
			case cl == nil && f.sessions == 2 && claims == 2:
				got = "rehandshake"
			case cl == nil && f.sessions == 1 && claims == 1:
				got = "idle"
			case cl != nil && cl.Run.Network != "none":
				got = "release_unstarted"
			case cl != nil:
				got = "run"
			default:
				t.Fatalf("unclassified: sessions=%d claims=%d", f.sessions, claims)
			}
			if got != v.Decision {
				t.Fatalf("decision %q, vector says %q (sessions=%d claims=%d err=%v)",
					got, v.Decision, f.sessions, claims, err)
			}
			if got == "refused" && (f.sessions != 1 || claims != 1) {
				t.Fatalf("refused claim re-handshook or retried: sessions=%d claims=%d", f.sessions, claims)
			}
			if cl == nil {
				return
			}
			// The run block must decode losslessly: the agent executes Run, never Job.params.
			var want struct {
				Run map[string]any `json:"run"`
				Job struct {
					JobID string `json:"job_id"`
				} `json:"job"`
			}
			json.Unmarshal(v.Body, &want)
			rb, _ := json.Marshal(cl.Run)
			var gotRun map[string]any
			json.Unmarshal(rb, &gotRun)
			if !reflect.DeepEqual(gotRun, want.Run) {
				t.Fatalf("run block\n got %v\nwant %v", gotRun, want.Run)
			}
			if cl.JobID != want.Job.JobID || cl.ClaimID == "" || cl.Receipt == "" || cl.NodeID != "node-v2" {
				t.Fatalf("claim %+v", cl)
			}
		})
	}
}

type inputVector struct {
	Status   int               `json:"status"`
	Headers  map[string]string `json:"headers"`
	BodyHex  string            `json:"body_hex"`
	MaxInput int64             `json:"max_input"`
	Verdict  string            `json:"verdict"`
	Expected struct {
		Bytes  *int64 `json:"bytes"`
		SHA256 string `json:"sha256"`
	} `json:"expected"`
}

// classifyInput maps a FetchInput result onto the input_stream verdict vocabulary.
func classifyInput(err error) string {
	switch {
	case err == nil:
		return "accept"
	case errors.Is(err, ErrRedirect):
		return "abort_redirect"
	case strings.Contains(err.Error(), "hash"):
		return "abort_hash"
	case strings.Contains(err.Error(), "larger than max_input"), strings.Contains(err.Error(), "longer than"):
		return "abort_long"
	case strings.Contains(err.Error(), "shorter"), errors.Is(err, ErrServer):
		return "abort_short"
	}
	return "unclassified: " + err.Error()
}

// TestInputStreamVectors replays each GET .../input response and checks accept / abort.
func TestInputStreamVectors(t *testing.T) {
	for _, name := range vectorFiles(t, "input_stream") {
		t.Run(strings.TrimSuffix(name, ".json"), func(t *testing.T) {
			var v inputVector
			if err := conformance.ReadJSON(filepath.Join("input_stream", name), &v); err != nil {
				t.Fatal(err)
			}
			body, err := hex.DecodeString(v.BodyHex)
			if err != nil {
				t.Fatal(err)
			}
			f, c := setup(t)
			f.handler = func(w http.ResponseWriter, r *http.Request) bool {
				if !strings.HasSuffix(r.URL.Path, "/input") {
					return false
				}
				for k, val := range v.Headers {
					w.Header().Set(k, val)
				}
				w.WriteHeader(v.Status)
				w.Write(body) // a short body under a longer content-length is cut off by the server
				return true
			}
			cl := Claim{JobID: "job-1", ClaimID: "c", Receipt: "r", Run: RunBlock{
				Limits: Limits{MaxInput: v.MaxInput},
				Input:  InputInfo{SHA256: v.Expected.SHA256, Bytes: v.Expected.Bytes}}}
			dst := filepath.Join(t.TempDir(), "in")
			sum, err := c.FetchInput(context.Background(), &cl, dst)
			if got := classifyInput(err); got != v.Verdict {
				t.Fatalf("verdict %q, vector says %q (err=%v)", got, v.Verdict, err)
			}
			if v.Verdict != "accept" {
				if _, serr := os.Lstat(dst); serr == nil {
					t.Fatal("aborted input left on disk")
				}
				return
			}
			if sum != v.Expected.SHA256 {
				t.Fatalf("sum %s, want %s", sum, v.Expected.SHA256)
			}
			if b, _ := os.ReadFile(dst); !bytes.Equal(b, body) {
				t.Fatal("content differs")
			}
		})
	}
}

type transcriptStep struct {
	Req struct {
		Method         string   `json:"method"`
		Path           string   `json:"path"`
		HeadersPresent []string `json:"headers_present"`
	} `json:"req"`
	Resp struct {
		Status int `json:"status"`
	} `json:"resp"`
}

// TestTranscriptVectors: driving the client through each scenario sends exactly the requests
// of the server's transcript, in order, with the same x-blastbox-* headers, and the client
// reacts to each recorded status as the scenario requires.
func TestTranscriptVectors(t *testing.T) {
	var run claimVector
	if err := conformance.ReadJSON("claim_responses/run_basic.json", &run); err != nil {
		t.Fatal(err)
	}
	sample := []byte("sample-bytes")
	drivers := map[string]func(t *testing.T, c *Client){
		"happy": func(t *testing.T, c *Client) {
			cl := mustClaim(t, c)
			fetch(t, c, cl)
			putAccepted(t, c, cl)
		},
		"refused": func(t *testing.T, c *Client) {
			if _, err := c.Claim(context.Background(), "clamav", nil); !errors.Is(err, ErrRefused) {
				t.Fatalf("claim: %v, want ErrRefused", err)
			}
		},
		"lost_claim_409": func(t *testing.T, c *Client) {
			cl := mustClaim(t, c)
			if err := c.Release(context.Background(), cl); !errors.Is(err, ErrClaimLost) {
				t.Fatalf("status write: %v, want ErrClaimLost", err)
			}
		},
		"session_expiry_mid_upload": func(t *testing.T, c *Client) {
			cl := mustClaim(t, c)
			fetch(t, c, cl)
			putAccepted(t, c, cl)
		},
	}
	for _, name := range vectorFiles(t, "transcripts") {
		name := strings.TrimSuffix(name, ".json")
		t.Run(name, func(t *testing.T) {
			drive, ok := drivers[name]
			if !ok {
				t.Fatalf("no driver for transcript %s", name)
			}
			var steps []transcriptStep
			if err := conformance.ReadJSON(filepath.Join("transcripts", name+".json"), &steps); err != nil {
				t.Fatal(err)
			}
			f, c := setup(t)
			var mu sync.Mutex
			i := 0
			f.handler = func(w http.ResponseWriter, r *http.Request) bool {
				mu.Lock()
				defer mu.Unlock()
				if i >= len(steps) {
					t.Errorf("request %d %s %s beyond the transcript", i, r.Method, r.URL.Path)
					w.WriteHeader(500)
					return true
				}
				s := steps[i]
				i++
				path := strings.ReplaceAll(s.Req.Path, "{job_id}", "job-1")
				var hdrs []string
				for k := range r.Header {
					if lk := strings.ToLower(k); strings.HasPrefix(lk, "x-blastbox-") {
						hdrs = append(hdrs, lk)
					}
				}
				sort.Strings(hdrs)
				want := append([]string{}, s.Req.HeadersPresent...)
				sort.Strings(want)
				if r.Method != s.Req.Method || r.URL.Path != path || strings.Join(hdrs, ",") != strings.Join(want, ",") {
					t.Errorf("step %d: got %s %s %v, transcript %s %s %v",
						i-1, r.Method, r.URL.Path, hdrs, s.Req.Method, path, want)
				}
				st := s.Resp.Status
				if st != 200 && st != 202 {
					writeVector(w, st, []byte(`{"detail":"from the transcript"}`))
					return true
				}
				switch {
				case r.URL.Path == "/v1/nodes/challenge", r.URL.Path == "/v1/nodes/session":
					return false // the fake's own challenge / session answers (status 200)
				case r.URL.Path == "/v1/nodes/claim":
					writeVector(w, st, asNode(t, run.Body, "node-v2"))
				case strings.HasSuffix(r.URL.Path, "/input"):
					w.Header().Set("x-blastbox-input-sha256", sum(sample))
					w.Header().Set("Content-Length", strconv.Itoa(len(sample)))
					w.WriteHeader(st)
					w.Write(sample)
				case strings.HasSuffix(r.URL.Path, "/result"):
					writeVector(w, st, []byte(`{"status":"accepted"}`))
				default:
					writeVector(w, st, []byte(`{}`))
				}
				return true
			}
			drive(t, c)
			mu.Lock()
			defer mu.Unlock()
			if i != len(steps) {
				t.Fatalf("client sent %d requests, transcript has %d", i, len(steps))
			}
		})
	}
}

func mustClaim(t *testing.T, c *Client) *Claim {
	t.Helper()
	cl, err := c.Claim(context.Background(), "clamav", nil)
	if err != nil || cl == nil {
		t.Fatalf("claim: %v %v", cl, err)
	}
	return cl
}

func fetch(t *testing.T, c *Client, cl *Claim) {
	t.Helper()
	if _, err := c.FetchInput(context.Background(), cl, filepath.Join(t.TempDir(), "in")); err != nil {
		t.Fatalf("input: %v", err)
	}
}

func putAccepted(t *testing.T, c *Client, cl *Claim) {
	t.Helper()
	tar := filepath.Join(t.TempDir(), "r.tar")
	os.WriteFile(tar, make([]byte, 1024), 0o600)
	now := time.Now()
	out, err := c.PutResult(context.Background(), cl, tar,
		ResultMeta{WorkerRuntime: "seatbelt", StartedAt: now.Add(-time.Second), FinishedAt: now})
	if err != nil || out.Status != "accepted" {
		t.Fatalf("result: %+v %v", out, err)
	}
}
