package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/wmetcalf/blastbox/agent/internal/wire"
)

const reachRepeat = 10 * time.Minute

// reachMon watches ingress round trips and says so loudly when none succeeds for too long. It
// only logs: it never touches routes and never runs anything privileged. Any HTTP answer counts
// as reachable; only transport failures count against the ingress. The clock starts at
// construction, so an ingress that was never reachable still alarms.
type reachMon struct {
	now      func() time.Time
	log      func() *slog.Logger
	after    time.Duration
	hostPort string

	mu      sync.Mutex
	lastOK  time.Time
	down    bool
	lastLog time.Time
}

func newReachMon(now func() time.Time, log *slog.Logger, after time.Duration, hostPort string) *reachMon {
	return &reachMon{now: now, log: func() *slog.Logger { return log }, after: after, hostPort: hostPort, lastOK: now()}
}

// Contact records one ingress attempt: nil = the ingress answered, else the transport error.
func (m *reachMon) Contact(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if err == nil {
		if m.down {
			m.log().Info(fmt.Sprintf("ingress reachable again after %ds (%s)", secs(now.Sub(m.lastOK)), m.hostPort))
		}
		m.down, m.lastOK = false, now
		return
	}
	gap := now.Sub(m.lastOK)
	if gap <= m.after {
		return
	}
	if m.down && now.Sub(m.lastLog) < reachRepeat {
		return
	}
	m.down, m.lastLog = true, now
	m.log().Error(fmt.Sprintf("ingress unreachable for %ds: %s", secs(gap), classifyReach(err, m.hostPort)))
}

func secs(d time.Duration) int { return int(d / time.Second) }

// classifyReach turns a dial/transport error into an operator-facing cause. It never prints the
// raw error (which could carry request details), only a fixed description and host:port.
func classifyReach(err error, hostPort string) string {
	host := hostPort
	if h, _, e := net.SplitHostPort(hostPort); e == nil {
		host = h
	}
	var ua x509.UnknownAuthorityError
	var he x509.HostnameError
	var ci x509.CertificateInvalidError
	var dns *net.DNSError
	var ne net.Error
	switch {
	case errors.Is(err, wire.ErrClientCertRefused):
		return fmt.Sprintf("the ingress %s refused this node's certificate (expired, revoked or not issued by its CA): run `blastbox-agent renew` while it is valid, else `blastbox-agent enrol`", hostPort)
	case errors.Is(err, wire.ErrTLS) || errors.As(err, &ua) || errors.As(err, &he) || errors.As(err, &ci):
		return fmt.Sprintf("TLS verification failed for %s (check ca_file and the ingress certificate)", hostPort)
	case errors.Is(err, syscall.EADDRNOTAVAIL):
		return fmt.Sprintf("local source address not available — likely a stale static host route to the ingress pinned to an old address; check `route -n get %s` and delete the stale route (needs sudo) [ingress %s]", host, hostPort)
	case errors.Is(err, syscall.ECONNREFUSED):
		return fmt.Sprintf("connection refused by %s (nothing listening, or a firewall reset)", hostPort)
	case errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH):
		return fmt.Sprintf("no route to %s (network or host unreachable)", hostPort)
	case errors.As(err, &dns):
		return fmt.Sprintf("DNS lookup for %s failed (ingress %s)", host, hostPort)
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) ||
		(errors.As(err, &ne) && ne.Timeout()):
		return fmt.Sprintf("connection to %s timed out", hostPort)
	}
	return fmt.Sprintf("unclassified network error reaching %s (%T)", hostPort, err)
}

// ingressHostPort is the ingress URL's host:port (443 when the port is absent).
func ingressHostPort(ingress string) string {
	u, err := url.Parse(ingress)
	if err != nil || u.Hostname() == "" {
		return strings.TrimPrefix(ingress, "https://")
	}
	p := u.Port()
	if p == "" {
		p = "443"
	}
	return net.JoinHostPort(u.Hostname(), p)
}
