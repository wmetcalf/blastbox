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
	// Equal numbers: a prerelease is below its release (semver 2.0 §11); build metadata after
	// "+" does not count. Two prereleases of one version compare equal here (fail-open only
	// between prereleases, never past the release itself).
	if pa, pb := prerelease(a), prerelease(b); pa != pb && (pa == "" || pb == "") {
		if pa != "" {
			return -1
		}
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
