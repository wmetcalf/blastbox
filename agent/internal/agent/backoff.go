package agent

import (
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/wmetcalf/blastbox/agent/internal/wire"
)

// Back-off table (spec §5).
const (
	idleDelay    = 2 * time.Second  // 204: nothing to claim
	refusedDelay = 60 * time.Second // 403
	tlsDelay     = 5 * time.Minute  // ErrTLS / ErrRedirect: an operator must act
	serverMin    = 1 * time.Second
	serverMax    = 30 * time.Second
	jitter       = 0.20
)

// serverBackoff is the exponential delay for the attempt'th consecutive server/network error
// (attempt 0 = first): 1 s doubling to 30 s, spread by +-20 % using rnd in [0,1).
func serverBackoff(attempt int, rnd float64) time.Duration {
	d := serverMax
	if attempt < 6 { // 1<<5 = 32 s already exceeds the cap
		if v := serverMin << uint(attempt); v < serverMax {
			d = v
		}
	}
	f := 1 + (rnd*2-1)*jitter
	return time.Duration(float64(d) * f)
}

// classify maps a wire error to its fixed delay and log level. ok=false means the error is
// the ErrServer class and the caller should use the exponential schedule; ErrUnauthorized is
// the caller's to handle (re-session first) and also reports ok=false.
func classify(err error) (d time.Duration, lvl slog.Level, ok bool) {
	switch {
	case errors.Is(err, wire.ErrRefused):
		return refusedDelay, slog.LevelWarn, true
	case errors.Is(err, wire.ErrTLS), errors.Is(err, wire.ErrRedirect):
		return tlsDelay, slog.LevelError, true
	}
	return 0, slog.LevelWarn, false
}

// semver compares dotted numeric versions; "dev", empty or unparseable parts count as 0, and a
// prerelease (1.2.3-rc1) is below its release.
func semverLess(a, b string) bool { return semverCmp(a, b) < 0 }

func semverCmp(a, b string) int {
	pa, pb := semverParts(a), semverParts(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	// Equal numbers: a prerelease is below its release, and prereleases are ordered by their
	// dot-separated identifiers (semver 2.0 §11); build metadata after "+" does not count.
	ra, rb := prerelease(a), prerelease(b)
	switch {
	case ra == rb:
		return 0
	case ra == "":
		return 1
	case rb == "":
		return -1
	}
	return prereleaseCmp(ra, rb)
}

// prereleaseCmp orders two non-empty prerelease strings (semver 2.0 §11.4): identifiers are
// compared left to right, numeric ones numerically and below alphanumeric ones, others in
// ASCII order; a shorter list that is a prefix of the longer one is lower.
func prereleaseCmp(a, b string) int {
	ia, ib := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(ia) && i < len(ib); i++ {
		x, y := ia[i], ib[i]
		if x == y {
			continue
		}
		nx, ex := strconv.ParseUint(x, 10, 64)
		ny, ey := strconv.ParseUint(y, 10, 64)
		switch {
		case ex == nil && ey == nil:
			if nx < ny {
				return -1
			}
			return 1
		case ex == nil:
			return -1
		case ey == nil:
			return 1
		case x < y:
			return -1
		default:
			return 1
		}
	}
	switch {
	case len(ia) < len(ib):
		return -1
	case len(ia) > len(ib):
		return 1
	}
	return 0
}

func prerelease(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		return v[i+1:]
	}
	return ""
}

func semverParts(v string) [3]int {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	for i, s := range strings.SplitN(v, ".", 3) {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			n = 0
		}
		out[i] = n
	}
	return out
}
