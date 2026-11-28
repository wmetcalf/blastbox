package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Kind is a sandbox backend.
type Kind string

const (
	Seatbelt Kind = "seatbelt"
	Nsjail   Kind = "nsjail"
)

// Limits are per-run caps. Zero means "unset" for rlimits (and the blastbox default for
// TimeoutS). NProc is per-UID on both OSes: leave it 0 unless the agent runs as a dedicated user.
type Limits struct {
	CPUSeconds uint64
	FSizeBytes uint64
	NoFile     uint64
	NProc      uint64
	TimeoutS   int64
}

var reservedEnv = map[string]bool{"HOME": true, "CFFIXED_USER_HOME": true, "TMPDIR": true, "PATH": true, "LANG": true}

func orderedKeys(m map[string]string, order []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, k := range order {
		if _, ok := m[k]; ok && !seen[k] {
			out = append(out, k)
			seen[k] = true
		}
	}
	var rest []string
	for k := range m {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	return append(out, rest...)
}

// ChildEnv is the explicit minimal child environment: HOME and TMPDIR = scratch, a fixed PATH,
// LANG=C, plus caller params. os.Environ() is never inherited; reserved keys and loader-control
// prefixes (DYLD_/LD_) in params are dropped, and malformed entries are an error.
func ChildEnv(scratch string, params map[string]string) (map[string]string, error) {
	env := map[string]string{
		"HOME": scratch, "TMPDIR": scratch, "PATH": "/usr/bin:/bin", "LANG": "C",
	}
	for k, v := range params {
		if k == "" || strings.ContainsAny(k, "=\x00") || strings.Contains(v, "\x00") {
			return nil, fmt.Errorf("invalid env entry %q", k)
		}
		if reservedEnv[k] || strings.HasPrefix(k, "DYLD_") || strings.HasPrefix(k, "LD_") {
			continue
		}
		env[k] = v
	}
	return env, nil
}

func envSlice(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, k := range orderedKeys(m, nil) {
		out = append(out, k+"="+m[k])
	}
	return out
}

func shimArgv(nonce, marker string, target []string) []string {
	return append([]string{"/bin/sh", "-c", HandshakeShim, "bb-handshake", nonce, marker}, target...)
}

// Command builds the exec.Cmd that runs argv under the sandbox, through the rlimit launcher:
//
//	blastbox-agent __launch --rlimit-* N -- <sandbox-exec ... | nsjail ...> /bin/sh -c SHIM sh NONCE MARKER argv...
//
// The scratch dir is always granted read-write. The environment is never inherited.
func Command(ctx context.Context, sb Kind, req Request, argv []string, lim Limits) (*exec.Cmd, error) {
	if len(argv) == 0 {
		return nil, errors.New("argv must be non-empty")
	}
	if req.Scratch == "" {
		return nil, errors.New("scratch is required")
	}
	agent := req.AgentBin
	if agent == "" {
		var err error
		if agent, err = os.Executable(); err != nil {
			return nil, err
		}
	}
	env, err := ChildEnv(req.Scratch, req.Env)
	if err != nil {
		return nil, err
	}
	marker := filepath.Join(req.Scratch, HandshakeName)
	rw := append([]string(nil), req.RWPaths...)
	if !contains(rw, req.Scratch) {
		rw = append(rw, req.Scratch)
	}

	launch := []string{agent, "__launch"}
	add := func(flag string, v uint64) {
		if v > 0 {
			launch = append(launch, flag, strconv.FormatUint(v, 10))
		}
	}
	add("--rlimit-cpu", lim.CPUSeconds)
	if sb != Nsjail {
		// nsjail sets its own --rlimit_fsize (soft = hard) in the child; a hard limit pinned
		// here first could not be raised by an unprivileged nsjail and every run would fail.
		add("--rlimit-fsize", lim.FSizeBytes)
	}
	add("--rlimit-nofile", lim.NoFile)
	add("--rlimit-nproc", lim.NProc)
	launch = append(launch, "--")

	var inner []string
	var cmdEnv []string
	switch sb {
	case Seatbelt:
		sreq := req
		sreq.RWPaths = rw
		profile, params, err := BuildSeatbeltProfile(sreq)
		if err != nil {
			return nil, err
		}
		inner = []string{"/usr/bin/sandbox-exec", "-p", profile}
		for _, k := range orderedKeys(params, nil) {
			inner = append(inner, "-D", k+"="+params[k])
		}
		inner = append(inner, "--")
		inner = append(inner, shimArgv(req.Nonce, marker, argv)...)
		cmdEnv = envSlice(env)
	case Nsjail:
		pins := DetectHostPins()
		if req.Pins != nil {
			pins = *req.Pins
		}
		nreq := NsjailRequest{
			Argv: shimArgv(req.Nonce, marker, argv),
			Env:  env,
			// Never egress: Command cannot produce --disable_clone_newnet.
			Limits:         NsjailLimits{TimeoutS: lim.TimeoutS},
			AttachAppArmor: req.AttachAppArmor,
		}
		if req.AppArmorProfile != "" {
			pins.AppArmorProfile = req.AppArmorProfile
		}
		nreq.EnvOrder = []string{"HOME", "TMPDIR", "LANG"}
		// Engine and probe binaries outside /usr must be visible in the jail; mounting the
		// files themselves (not their directories) keeps the grant minimal.
		// A path inside another granted read-only path is not mounted again: the ancestor's
		// bind already exposes it, and a file mounted before its directory is shadowed by the
		// directory mount, which nsjail then fails to remount read-only.
		ro := append(append([]string(nil), req.ExecPaths...), req.ROPaths...)
		seen := map[string]bool{}
		for _, p := range ro {
			if seen[p] || isRelativeTo(p, "/usr") || isRelativeTo(p, "/etc") || insideOther(p, ro) {
				continue
			}
			seen[p] = true
			nreq.ROMounts = append(nreq.ROMounts, Mount{p, p})
		}
		if m, ok := jailAlias(argv[0], req.ExecPaths, req.ROPaths, rw); ok {
			nreq.ROMounts = append(nreq.ROMounts, m)
		}
		for _, p := range rw {
			nreq.RWMounts = append(nreq.RWMounts, Mount{p, p})
		}
		if req.NsjailPath == "" {
			return nil, errors.New("nsjail path is required")
		}
		// Command itself refuses an insecure nsjail host, whatever the caller checked.
		if req.SeccompPolicy == "" {
			return nil, errors.New("nsjail: seccomp policy is required (seccomp_policy_missing)")
		}
		if !req.AttachAppArmor && !req.AllowMissingAppArmor {
			return nil, errors.New("nsjail: AppArmor profile is not attached and allow_missing_apparmor is not set (apparmor_missing)")
		}
		inner, err = BuildNsjailArgv(nreq, req.NsjailPath, req.SeccompPolicy, pins)
		if err != nil {
			return nil, err
		}
		capNsjailFSize(inner, lim.FSizeBytes)
		cmdEnv = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	default:
		return nil, fmt.Errorf("unknown sandbox %q", sb)
	}

	full := append(launch, inner...)
	cmd := exec.CommandContext(ctx, full[0], full[1:]...)
	cmd.Env = cmdEnv
	cmd.Dir = req.Scratch
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 3 * time.Second
	return cmd, nil
}

// capNsjailFSize lowers nsjail's --rlimit_fsize (MiB, the tmpfs size by default) to the
// requested per-file cap, rounded up to a whole MiB. It never raises it.
func capNsjailFSize(argv []string, fsize uint64) {
	if fsize == 0 {
		return
	}
	want := (fsize + (1<<20 - 1)) >> 20
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] != "--rlimit_fsize" {
			continue
		}
		if cur, err := strconv.ParseUint(argv[i+1], 10, 64); err == nil && want < cur {
			argv[i+1] = strconv.FormatUint(want, 10)
		}
		return
	}
}

// jailAlias makes argv[0] exist inside the jail under the name it is invoked by. The jail
// sees /usr, /etc, the ro/rw paths and the resolved ExecPaths at their own paths; an absolute
// argv[0] elsewhere that is a symlink to an ExecPath gets that file mounted at its own path
// (argv[0] is never rewritten: a multi-call binary or a venv launcher depends on the name).
func jailAlias(argv0 string, execPaths, roPaths, rwPaths []string) (Mount, bool) {
	if !filepath.IsAbs(argv0) || isRelativeTo(argv0, "/usr") || isRelativeTo(argv0, "/etc") ||
		contains(execPaths, argv0) {
		return Mount{}, false
	}
	for _, p := range append(append([]string(nil), roPaths...), rwPaths...) {
		if isRelativeTo(argv0, p) {
			return Mount{}, false
		}
	}
	resolved, err := filepath.EvalSymlinks(argv0)
	if err != nil || resolved == argv0 || !contains(execPaths, resolved) {
		return Mount{}, false
	}
	return Mount{resolved, argv0}, true
}

// insideOther reports whether p lies strictly inside another path of ps.
func insideOther(p string, ps []string) bool {
	for _, q := range ps {
		if q != p && isRelativeTo(p, q) {
			return true
		}
	}
	return false
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// RunLaunch is the `blastbox-agent __launch` entry point (cgo-free rlimit launcher): apply the
// requested rlimits to this process, then exec the target, which inherits them. args excludes
// the program name and the "__launch" word.
func RunLaunch(args []string) error {
	type rl struct {
		flag string
		res  int
	}
	table := []rl{{"--rlimit-cpu", syscall.RLIMIT_CPU}, {"--rlimit-fsize", syscall.RLIMIT_FSIZE},
		{"--rlimit-nofile", syscall.RLIMIT_NOFILE}, {"--rlimit-nproc", rlimitNProc}}
	want := map[string]uint64{}
	i := 0
	for ; i < len(args); i++ {
		if args[i] == "--" {
			i++
			break
		}
		known := false
		for _, t := range table {
			if args[i] == t.flag {
				if i+1 >= len(args) {
					return fmt.Errorf("%s needs a value", t.flag)
				}
				n, err := strconv.ParseUint(args[i+1], 10, 64)
				if err != nil {
					return fmt.Errorf("%s: %w", t.flag, err)
				}
				want[t.flag] = n
				i++
				known = true
				break
			}
		}
		if !known {
			return fmt.Errorf("unknown launch flag %q", args[i])
		}
	}
	target := args[min(i, len(args)):]
	if len(target) == 0 {
		return errors.New("no command after --")
	}
	for _, t := range table {
		if n, ok := want[t.flag]; ok {
			lim := syscall.Rlimit{Cur: n, Max: n}
			if err := syscall.Setrlimit(t.res, &lim); err != nil {
				return fmt.Errorf("setrlimit %s=%d: %w", t.flag, n, err)
			}
		}
	}
	path, err := exec.LookPath(target[0])
	if err != nil {
		return err
	}
	return syscall.Exec(path, target, os.Environ())
}
