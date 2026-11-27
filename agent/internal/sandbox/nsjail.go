package sandbox

import (
	"os"
	"strconv"
	"strings"
)

// Mount is a bind mount source:target.
type Mount struct{ Source, Target string }

// NsjailLimits mirrors blastbox Limits; zero values mean the blastbox defaults.
type NsjailLimits struct {
	MemoryBytes int64 // default 8 GiB
	TimeoutS    int64 // default 120
	TmpfsBytes  int64 // default 1 GiB
	NetEgress   bool
}

// NsjailRequest is the nsjail-specific request (mounts keep source/target).
type NsjailRequest struct {
	Argv           []string
	ROMounts       []Mount
	RWMounts       []Mount
	Env            map[string]string
	EnvOrder       []string // optional emission order for Env keys beyond the minimal base
	Limits         NsjailLimits
	AttachAppArmor bool
}

// HostPins are the host probes the Python builder reads at launch time (the conformance vectors
// record them as host_pins); the agent computes them the same way via DetectHostPins.
type HostPins struct {
	AAExec          string // "" = no aa-exec helper
	AppArmorProfile string
	Exists          map[string]bool // paths that exist (follows symlinks)
	Symlinks        map[string]bool // paths that are symlinks
}

var (
	usrDirs      = []string{"/usr", "/etc"}
	usrSymlinks  = [][2]string{{"/bin", "usr/bin"}, {"/sbin", "usr/sbin"}, {"/lib", "usr/lib"}, {"/lib64", "usr/lib64"}}
	devNodes     = []string{"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"}
	minimalEnv   = [][2]string{{"PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}, {"HOME", "/tmp"}}
	defaultMem   = int64(8 << 30)
	defaultTmpfs = int64(1 << 30)
)

// DetectHostPins probes this host as nsjail.py does at launch.
func DetectHostPins() HostPins {
	p := HostPins{AppArmorProfile: "blastbox-child", Exists: map[string]bool{}, Symlinks: map[string]bool{}}
	var paths []string
	paths = append(paths, usrDirs...)
	for _, l := range usrSymlinks {
		paths = append(paths, l[0])
	}
	paths = append(paths, devNodes...)
	for _, d := range paths {
		if _, err := os.Stat(d); err == nil {
			p.Exists[d] = true
		}
		if fi, err := os.Lstat(d); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			p.Symlinks[d] = true
		}
	}
	if fi, err := os.Stat("/usr/bin/aa-exec"); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
		p.AAExec = "/usr/bin/aa-exec"
	}
	return p
}

// AppArmorEnforcing reports whether the child profile is loaded in enforce mode right now.
// Unreadable securityfs means "not confirmed" (fail to the less-hardened-but-working argv).
func AppArmorEnforcing(profile string) bool {
	raw, err := os.ReadFile("/sys/kernel/security/apparmor/profiles")
	if err != nil {
		return false
	}
	return strings.Contains(string(raw), profile+" (enforce)")
}

// BuildNsjailArgv is a port of NsjailSandbox._build_argv. pins carries the host probes.
// seccompPolicy "" omits the flag (no policy found).
func BuildNsjailArgv(req NsjailRequest, nsjailPath, seccompPolicy string, pins HostPins) ([]string, error) {
	mem, tmpfs, timeout := req.Limits.MemoryBytes, req.Limits.TmpfsBytes, req.Limits.TimeoutS
	if mem == 0 {
		mem = defaultMem
	}
	if tmpfs == 0 {
		tmpfs = defaultTmpfs
	}
	if timeout == 0 {
		timeout = 120
	}
	argv := []string{
		nsjailPath,
		"--mode", "o",
		"--quiet",
		"--really_quiet",
		"--time_limit", strconv.FormatInt(timeout, 10),
		"--rlimit_as", strconv.FormatInt(mem/(1024*1024), 10),
		"--rlimit_fsize", strconv.FormatInt(tmpfs/(1024*1024), 10),
		"--rlimit_nofile", "4096",
		"--rlimit_nproc", "256",
		"--rlimit_core", "0",
		"--user", "65534",
		"--group", "65534",
		"--hostname", "blastbox",
	}
	if req.Limits.NetEgress {
		argv = append(argv, "--disable_clone_newnet")
	} else {
		argv = append(argv, "--iface_no_lo")
	}
	for _, d := range usrDirs {
		if pins.Exists[d] {
			argv = append(argv, "--bindmount_ro", d+":"+d)
		}
	}
	for _, l := range usrSymlinks {
		if pins.Symlinks[l[0]] {
			argv = append(argv, "--symlink", l[1]+":"+l[0])
		} else if pins.Exists[l[0]] {
			argv = append(argv, "--bindmount_ro", l[0]+":"+l[0])
		}
	}
	argv = append(argv, "--tmpfsmount", "/tmp")
	for _, d := range devNodes {
		if pins.Exists[d] {
			argv = append(argv, "--bindmount_ro", d+":"+d)
		}
	}
	for _, m := range req.ROMounts {
		argv = append(argv, "--bindmount_ro", m.Source+":"+m.Target)
	}
	for _, m := range req.RWMounts {
		argv = append(argv, "--bindmount", m.Source+":"+m.Target)
	}
	// Minimal base then the request overlay: an overridden base key keeps its position (dict
	// merge); new keys follow in EnvOrder, then any remaining sorted, for determinism.
	emitted := map[string]bool{}
	for _, kv := range minimalEnv {
		v := kv[1]
		if o, ok := req.Env[kv[0]]; ok {
			v = o
		}
		argv = append(argv, "--env", kv[0]+"="+v)
		emitted[kv[0]] = true
	}
	for _, k := range orderedKeys(req.Env, req.EnvOrder) {
		if !emitted[k] {
			argv = append(argv, "--env", k+"="+req.Env[k])
		}
	}
	if seccompPolicy != "" {
		argv = append(argv, "--seccomp_policy", seccompPolicy)
	}
	aa := pins.AAExec
	if aa != "" && !req.AttachAppArmor {
		aa = ""
	}
	if aa != "" {
		argv = append(argv, "--proc_rw")
	}
	inner := append([]string(nil), req.Argv...)
	if aa != "" {
		inner = append([]string{aa, "-p", pins.AppArmorProfile, "--"}, inner...)
	}
	argv = append(argv, "--")
	argv = append(argv, inner...)
	return argv, nil
}
