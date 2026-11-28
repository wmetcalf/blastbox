//go:build darwin

package sandbox

// rlimitNProc is RLIMIT_NPROC (not exported by package syscall).
const rlimitNProc = 7
