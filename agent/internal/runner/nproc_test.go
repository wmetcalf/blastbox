package runner

import (
	"errors"
	"testing"
)

var errTest = errors.New("ps broke")

// The ceiling is fixed while any run is in flight: a run that starts while others are running
// cannot count their processes into a higher limit.
func TestNprocCeilingIsSharedWhileRunsAreInFlight(t *testing.T) {
	prev := uidProcs
	t.Cleanup(func() { uidProcs = prev })
	count := int64(100)
	uidProcs = func() (int64, error) { return count, nil }
	l1, done1, err := nprocLimit()
	if err != nil || l1 != 100+nprocAllowance {
		t.Fatalf("first run: %d %v", l1, err)
	}
	count = 100 + nprocBudget // the first run's processes, and more
	l2, done2, _ := nprocLimit()
	if l2 != 100+nprocBudget {
		t.Fatalf("second run limit %d, want the shared ceiling %d", l2, 100+nprocBudget)
	}
	done1()
	done1() // idempotent
	done2()
	count = 300
	l3, done3, _ := nprocLimit()
	defer done3()
	if l3 != 300+nprocAllowance {
		t.Fatalf("with nothing in flight the ceiling is re-measured: %d", l3)
	}
}

func TestNprocCountFailureRefusesTheRun(t *testing.T) {
	prev := uidProcs
	t.Cleanup(func() { uidProcs = prev })
	uidProcs = func() (int64, error) { return 0, errTest }
	if _, _, err := nprocLimit(); err == nil {
		t.Fatal("a run was allowed without a process limit")
	}
	f := setup(t, `printf '{}' > "$1/metadata.json"`)
	res := f.run()
	if res.Outcome != "released" || !res.SandboxFailure {
		t.Fatalf("result %+v, want a released sandbox failure", res)
	}
}
