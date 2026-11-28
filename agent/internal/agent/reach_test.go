package agent

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/wmetcalf/blastbox/agent/internal/wire"
)

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := strings.TrimSpace(l.b.String())
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func (l *lockedBuf) count(level string) int {
	n := 0
	for _, ln := range l.lines() {
		if strings.Contains(ln, `"level":"`+level+`"`) {
			n++
		}
	}
	return n
}

type clk struct{ t time.Time }

func (c *clk) now() time.Time      { return c.t }
func (c *clk) add(d time.Duration) { c.t = c.t.Add(d) }
func dialErr(e error) error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", e)}
}
func newMon(after time.Duration) (*reachMon, *clk, *lockedBuf) {
	c := &clk{t: time.Unix(1_800_000_000, 0)}
	b := &lockedBuf{}
	log := slog.New(slog.NewJSONHandler(b, nil))
	return newReachMon(c.now, log, after, "ingress.example:8443"), c, b
}

func TestReachMonOneErrorOnTransitionThenRateLimitedRepeatThenInfoOnRecovery(t *testing.T) {
	m, c, b := newMon(90 * time.Second)
	m.Contact(nil)
	for i := 0; i < 8; i++ { // 80 s of failures: still inside the threshold
		c.add(10 * time.Second)
		m.Contact(dialErr(syscall.ECONNREFUSED))
	}
	if b.count("ERROR") != 0 {
		t.Fatalf("logged before threshold: %v", b.lines())
	}
	c.add(15 * time.Second) // 95 s
	m.Contact(dialErr(syscall.ECONNREFUSED))
	if b.count("ERROR") != 1 {
		t.Fatalf("want exactly 1 ERROR on transition, got %v", b.lines())
	}
	line := b.lines()[0]
	if !strings.Contains(line, "ingress unreachable for 95s: ") || !strings.Contains(line, "refused") ||
		!strings.Contains(line, "ingress.example:8443") {
		t.Fatalf("bad message: %s", line)
	}
	for i := 0; i < 50; i++ { // 9 min of continued failure: no repeat
		c.add(10 * time.Second)
		m.Contact(dialErr(syscall.ECONNREFUSED))
	}
	if b.count("ERROR") != 1 {
		t.Fatalf("repeated inside 10 min: %v", b.lines())
	}
	c.add(2 * time.Minute) // past 10 min since the first ERROR
	m.Contact(dialErr(syscall.ECONNREFUSED))
	if b.count("ERROR") != 2 {
		t.Fatalf("want a repeat after 10 min, got %v", b.lines())
	}
	if b.count("INFO") != 0 {
		t.Fatalf("INFO before recovery")
	}
	m.Contact(nil)
	if b.count("INFO") != 1 || b.count("ERROR") != 2 {
		t.Fatalf("want one INFO on recovery: %v", b.lines())
	}
	m.Contact(nil)
	if b.count("INFO") != 1 {
		t.Fatalf("INFO repeated")
	}
	// a new outage logs a fresh ERROR on its own transition
	c.add(time.Second)
	m.Contact(dialErr(syscall.ECONNREFUSED))
	c.add(100 * time.Second)
	m.Contact(dialErr(syscall.ECONNREFUSED))
	if b.count("ERROR") != 3 {
		t.Fatalf("second outage: %v", b.lines())
	}
}

func TestReachMonStartsTheClockAtConstruction(t *testing.T) {
	m, c, b := newMon(90 * time.Second)
	c.add(91 * time.Second)
	m.Contact(dialErr(syscall.ENETUNREACH))
	if b.count("ERROR") != 1 {
		t.Fatalf("a never-reachable ingress must still alarm: %v", b.lines())
	}
}

func TestClassifyDialError(t *testing.T) {
	host := "10.1.2.3:8443"
	cases := []struct {
		name string
		err  error
		want []string
	}{
		{"eaddrnotavail", dialErr(syscall.EADDRNOTAVAIL), []string{
			"local source address not available", "stale static host route", "route -n get 10.1.2.3", "needs sudo"}},
		{"refused", dialErr(syscall.ECONNREFUSED), []string{"refused"}},
		{"netunreach", dialErr(syscall.ENETUNREACH), []string{"no route"}},
		{"hostunreach", dialErr(syscall.EHOSTUNREACH), []string{"no route"}},
		{"timeout", &net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}, []string{"timed out"}},
		{"ctxdeadline", fmt.Errorf("x: %w", context.DeadlineExceeded), []string{"timed out"}},
		{"tls", fmt.Errorf("%w: boom", wire.ErrTLS), []string{"TLS"}},
		{"tls-x509", x509.UnknownAuthorityError{}, []string{"TLS"}},
		// The ingress refused the NODE's certificate: point at renew/enrol, not at ca_file.
		{"client-cert-refused", fmt.Errorf("%w: %w: remote error", wire.ErrTLS, wire.ErrClientCertRefused),
			[]string{"refused this node's certificate", "blastbox-agent renew", "enrol"}},
		{"dns", &net.OpError{Op: "dial", Err: &net.DNSError{Err: "no such host", Name: "ingress.example"}}, []string{"DNS"}},
		{"other", errors.New("weird"), []string{"unclassified"}},
	}
	for _, tc := range cases {
		got := classifyReach(tc.err, host)
		for _, w := range tc.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: %q lacks %q", tc.name, got, w)
			}
		}
		if !strings.Contains(got, host) {
			t.Errorf("%s: %q lacks the host:port", tc.name, got)
		}
	}
}

func TestIngressHostPort(t *testing.T) {
	for in, want := range map[string]string{
		"https://a.example":      "a.example:443",
		"https://a.example:8443": "a.example:8443",
		"https://10.0.0.1:9/":    "10.0.0.1:9",
	} {
		if got := ingressHostPort(in); got != want {
			t.Errorf("%s: got %s want %s", in, got, want)
		}
	}
}
