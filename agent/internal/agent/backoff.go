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

// semver compares dotted numeric versions; "dev", empty or unparseable parts count as 0.
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
	return 0
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
