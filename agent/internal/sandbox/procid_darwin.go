package sandbox

// ProcIdentity returns pid's start time (microseconds since the epoch): with the pid, it names
// one process; a pid alone may since have been reused.
func ProcIdentity(pid int) (int64, bool) { return procStart(pid) }
