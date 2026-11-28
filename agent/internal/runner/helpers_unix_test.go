package runner

import (
	"syscall"
	"time"
)

func mkfifo(p string) error { return syscall.Mkfifo(p, 0o600) }
func mustTime() time.Time   { return time.Unix(1700000000, 0) }
