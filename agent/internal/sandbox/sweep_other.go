//go:build !darwin

package sandbox

// Match is false off darwin: there are no seatbelt runs to find.
func (id RunIdentity) Match(pid int) bool { return false }

// SweepRun is a no-op off darwin (nsjail's PID namespace dies with nsjail).
func SweepRun(id RunIdentity) (int, error) { return 0, nil }
