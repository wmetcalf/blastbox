package runner

import "sync"

// RLIMIT_NPROC counts the whole uid on darwin, so a seatbelt run's limit is set from the uid's
// current process count (the Python seatbelt launcher's NPROC_ALLOWANCE and shared ceiling).
const (
	nprocAllowance = 64  // processes one run may add to what the uid runs when it starts
	nprocBudget    = 512 // processes all of this agent's concurrent runs may add together
)

// uidProcs counts this uid's processes (a seam for tests).
var uidProcs = uidProcCount

var nproc struct {
	sync.Mutex
	inFlight int
	ceiling  int64
}

// nprocLimit returns the RLIMIT_NPROC for a run starting now, and the release to call once
// the run is over. Each run gets the uid's current count plus nprocAllowance, never above a
// ceiling fixed while any run is in flight (the count when the first of them started plus
// nprocBudget): a per-run "count + allowance" alone would let each run count its concurrent
// runs' processes into its baseline, so N slots could reach N allowances between them. The
// ceiling is re-measured only when nothing is in flight. A count that cannot be taken is an
// error: the run must not start without the limit.
func nprocLimit() (uint64, func(), error) {
	n, err := uidProcs()
	if err != nil {
		return 0, nil, err
	}
	nproc.Lock()
	defer nproc.Unlock()
	if nproc.inFlight == 0 || nproc.ceiling < 1 {
		nproc.ceiling = n + nprocBudget
	}
	nproc.inFlight++
	release := sync.OnceFunc(func() {
		nproc.Lock()
		nproc.inFlight--
		nproc.Unlock()
	})
	return uint64(min(n+nprocAllowance, nproc.ceiling)), release, nil
}
