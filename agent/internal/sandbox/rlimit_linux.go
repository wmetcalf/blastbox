//go:build linux

package sandbox

// rlimitNProc is RLIMIT_NPROC (not exported by package syscall).
const rlimitNProc = 6
