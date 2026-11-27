package sandbox

import (
	"encoding/binary"
	"runtime"
	"syscall"
	"unsafe"
)

// cgo-free calls into libSystem, the way golang.org/x/sys/unix makes them: the function is
// imported dynamically and reached through an assembly trampoline that syscall.syscall6 calls on
// the system stack. syscall6 also stores a4 on the stack, which is where the arm64 ABI wants the
// first variadic argument, so sandbox_check's filter argument arrives where libSystem reads it.

//go:linkname syscall_syscall6 syscall.syscall6
func syscall_syscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

var (
	libc_sandbox_check_trampoline_addr uintptr
	libc_proc_listpids_trampoline_addr uintptr
	libc_proc_pidinfo_trampoline_addr  uintptr
)

//go:cgo_import_dynamic libc_sandbox_check sandbox_check "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_proc_listpids proc_listpids "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_proc_pidinfo proc_pidinfo "/usr/lib/libSystem.B.dylib"

const (
	sbFilterPath       = 1
	sbFilterGlobalName = 2
	sbCheckNoReport    = 0x40000000
	procUIDOnly        = 4
	procPidTBSDInfo    = 3
	procBSDInfoSize    = 136 // struct proc_bsdinfo
	bsdStartSecOff     = 120 // pbi_start_tvsec
	bsdStartUsecOff    = 128 // pbi_start_tvusec
)

// heapBytes returns zeroed memory that is guaranteed to live on the heap. Every buffer handed
// to libSystem must: its address travels as a uintptr, which a goroutine stack copy (a
// morestack at the call into syscall6) would not update, leaving libSystem a stale pointer. Not
// inlined, so the returned slice always escapes.
//
//go:noinline
func heapBytes(n int) []byte { return make([]byte, n) }

func cstr(s string) []byte {
	b := heapBytes(len(s) + 1)
	copy(b, s)
	return b
}

// sandboxCheck returns sandbox_check's result: 0 allowed, 1 denied, -1 error. op "" passes NULL
// (with typ 0: "is pid sandboxed at all").
func sandboxCheck(pid int, op string, typ int, arg string) int {
	var o, a []byte
	var op0, arg0 uintptr
	if op != "" {
		o = cstr(op)
		op0 = uintptr(unsafe.Pointer(&o[0]))
	}
	if arg != "" {
		a = cstr(arg)
		arg0 = uintptr(unsafe.Pointer(&a[0]))
	}
	r, _, _ := syscall_syscall6(libc_sandbox_check_trampoline_addr, uintptr(pid), op0, uintptr(typ), arg0, 0, 0)
	runtime.KeepAlive(o)
	runtime.KeepAlive(a)
	return int(int32(r))
}

func isSandboxed(pid int) bool { return sandboxCheck(pid, "", 0, "") == 1 }

func mayWrite(pid int, path string) bool {
	return sandboxCheck(pid, "file-write-data", sbFilterPath|sbCheckNoReport, path) == 0
}

func mayLookup(pid int, name string) bool {
	return sandboxCheck(pid, "mach-lookup", sbFilterGlobalName|sbCheckNoReport, name) == 0
}

func mayUseNetwork(pid int) bool {
	return sandboxCheck(pid, "network-outbound", sbCheckNoReport, "") == 0
}

// procListUIDPids returns every pid owned by uid. A full buffer may be truncated (the list can
// grow between the sizing call and the listing), so it is retried larger and fails closed.
func procListUIDPids(uid int) ([]int, error) {
	extra := 256
	for try := 0; try < 5; try++ {
		n, _, _ := syscall_syscall6(libc_proc_listpids_trampoline_addr, procUIDOnly, uintptr(uid), 0, 0, 0, 0)
		if int32(n) <= 0 {
			return nil, errorf("proc_listpids sizing returned %d", int32(n))
		}
		buf := make([]int32, int(int32(n))/4+extra)
		size := len(buf) * 4
		got, _, _ := syscall_syscall6(libc_proc_listpids_trampoline_addr, procUIDOnly, uintptr(uid),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(size), 0, 0)
		runtime.KeepAlive(buf)
		g := int(int32(got))
		if g <= 0 {
			return nil, errorf("proc_listpids returned %d", g)
		}
		if g < size {
			out := make([]int, 0, g/4)
			for _, p := range buf[:g/4] {
				if p > 0 {
					out = append(out, int(p))
				}
			}
			return out, nil
		}
		extra *= 4
	}
	return nil, errorf("the process list kept filling its buffer")
}

// procStart returns pid's start time in microseconds since the epoch (its identity: a pid alone
// may by now name another process), or false.
func procStart(pid int) (int64, bool) {
	buf := heapBytes(procBSDInfoSize)
	r, _, _ := syscall_syscall6(libc_proc_pidinfo_trampoline_addr, uintptr(pid), procPidTBSDInfo, 0,
		uintptr(unsafe.Pointer(&buf[0])), procBSDInfoSize, 0)
	runtime.KeepAlive(buf)
	if int32(r) != procBSDInfoSize {
		return 0, false
	}
	sec := binary.LittleEndian.Uint64(buf[bsdStartSecOff:])
	usec := binary.LittleEndian.Uint64(buf[bsdStartUsecOff:])
	return int64(sec)*1e6 + int64(usec), true
}
