// Package sandbox builds and applies the node agent's confinement: an exact port of blastbox's
// seatbelt profile builder and nsjail argv builder (golden-tested against conformance/v1), the
// rlimit launcher, and the proof run before the agent claims any work.
package sandbox

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// Handshake shim: runs INSIDE the sandbox, so the nonce it writes proves the run was confined.
// Copied verbatim from seatbelt.py HANDSHAKE_SHIM.
const (
	HandshakeShim = `printf %s "$1" > "$2" || exit 125; shift 2; exec "$@"`
	HandshakeName = ".bb-handshake"
)

var systemExecDirs = []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/libexec"}

var devRead = []string{"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"}

var aneUserClients = []string{"H11ANEInDirectPathClient", "H11ANEInUserClient",
	"H1xANELoadBalancerDirectPathClient", "H1xANEInDirectPathClient"}
var gpuUserClients = []string{"IOSurfaceRootUserClient", "AGXDeviceUserClient"}

func quoted(ss []string) string {
	q := make([]string, len(ss))
	for i, s := range ss {
		q[i] = `"` + s + `"`
	}
	return strings.Join(q, " ")
}

func accelRules(name string) []string {
	switch name {
	case "gpu":
		return []string{
			"(allow iokit-open-user-client (iokit-user-client-class " + quoted(gpuUserClients) + "))",
			`(allow mach-lookup (global-name "com.apple.cvmsServ"))`,
		}
	case "ane":
		return []string{
			"(allow iokit-open-user-client (iokit-user-client-class " + quoted(aneUserClients) + "))",
			`(allow mach-lookup (global-name "com.apple.appleneuralengine"))`,
		}
	}
	return nil
}

// Request is what a sandboxed run is granted. All paths must be filepath.EvalSymlinks-resolved
// by the caller (Seatbelt matches resolved paths). The last group is used by Command only.
type Request struct {
	ExecPaths    []string
	ROPaths      []string
	RWPaths      []string
	Accelerators []string
	Scratch      string // "" = none
	Canary       string // "" = none

	// Command-only inputs.
	Nonce         string            // handshake nonce written by the in-sandbox shim
	Env           map[string]string // extra child env (run params); reserved keys are dropped
	AgentBin      string            // blastbox-agent binary (hosts __launch); default os.Executable
	NsjailPath    string
	SeccompPolicy string
	Pins          *HostPins // nil = DetectHostPins()
	// AppArmorProfile and AttachAppArmor: nsjail only. Attach only when the host proved the
	// profile attaches (Host does); otherwise the layer is absent and reported as such.
	AppArmorProfile string
	AttachAppArmor  bool
	// AllowMissingAppArmor is the operator's explicit opt-out: without it, Command refuses an
	// nsjail run whose AppArmor profile is not attached.
	AllowMissingAppArmor bool
}

// BuildSeatbeltProfile is an exact port of seatbelt.build_profile.
func BuildSeatbeltProfile(req Request) (string, map[string]string, error) {
	var unknown []string
	accels := map[string]bool{}
	for _, a := range req.Accelerators {
		if a != "gpu" && a != "ane" {
			unknown = append(unknown, a)
		}
		accels[a] = true
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return "", nil, fmt.Errorf("unknown accelerator(s) %v; known: [ane gpu]", unknown)
	}
	if err := CheckRODisjoint(req.ROPaths, req.RWPaths); err != nil {
		return "", nil, err
	}
	params := map[string]string{}
	refs := func(prefix string, paths []string, kind string) string {
		out := make([]string, len(paths))
		for i, p := range paths {
			key := fmt.Sprintf("%s_%d", prefix, i)
			params[key] = p
			out[i] = fmt.Sprintf(`(%s (param "%s"))`, kind, key)
		}
		return strings.Join(out, " ")
	}
	dev := make([]string, len(devRead))
	for i, d := range devRead {
		dev[i] = fmt.Sprintf(`(literal "%s")`, d)
	}
	dirSet := map[string]bool{}
	for _, p := range req.ExecPaths {
		dirSet[filepath.Dir(p)] = true
	}
	exeDirs := make([]string, 0, len(dirSet))
	for d := range dirSet {
		exeDirs = append(exeDirs, d)
	}
	sort.Strings(exeDirs)

	lines := []string{
		"(version 1)",
		"(deny default)",
		`(import "system.sb")`,
		"(allow process-fork)",
		"(allow signal (target same-sandbox))",
		"(allow file-read-metadata)",
		"(allow sysctl-read)",
		"(allow file-read* " + strings.Join(dev, " ") + ")",
		`(allow file-write-data (literal "/dev/null"))`,
		"(allow file-read* process-exec " + refs("SYS", systemExecDirs, "subpath") + ")",
		"(allow file-read* process-exec " + refs("EXE", req.ExecPaths, "literal") + ")",
		"(allow file-read* " + refs("EXEDIR", exeDirs, "literal") + ")",
	}
	if len(req.ROPaths) > 0 {
		lines = append(lines, "(allow file-read* process-exec "+refs("RO", req.ROPaths, "subpath")+")")
	}
	if len(req.RWPaths) > 0 {
		lines = append(lines, "(allow file-read* file-write* "+refs("RW", req.RWPaths, "subpath")+")")
		var mounts []string
		for _, p := range req.RWPaths {
			if p != req.Scratch {
				mounts = append(mounts, p)
			}
		}
		if len(mounts) > 0 {
			lines = append(lines, "(deny file-write-flags "+refs("RWF", mounts, "subpath")+")")
		}
		lines = append(lines, "(deny file-write-acl "+refs("RWA", req.RWPaths, "subpath")+")")
		lines = append(lines, "(deny file-write-unlink "+refs("RWR", pinnedPaths(req.RWPaths), "literal")+")")
		lines = append(lines, "(deny file-link)")
	}
	names := make([]string, 0, len(accels))
	for a := range accels {
		names = append(names, a)
	}
	sort.Strings(names)
	for _, a := range names {
		lines = append(lines, accelRules(a)...)
	}
	if accels["ane"] && req.Scratch != "" {
		params["SCRATCH_EXT"] = req.Scratch
		lines = append(lines, `(allow file-issue-extension (require-all `+
			`(extension-class "com.apple.app-sandbox.read") (subpath (param "SCRATCH_EXT"))))`)
	}
	if req.Canary != "" {
		params["CANARY"] = req.Canary
		lines = append(lines, `(allow mach-lookup (global-name (param "CANARY")))`)
	}
	lines = append(lines, "(deny network*)")
	return strings.Join(lines, "\n") + "\n", params, nil
}

// isRelativeTo mirrors pathlib.PurePath.is_relative_to on already-normalized paths.
func isRelativeTo(p, base string) bool {
	if p == base {
		return true
	}
	if base == "/" {
		return strings.HasPrefix(p, "/")
	}
	return strings.HasPrefix(p, base+"/")
}

// CheckRODisjoint refuses a read-only mount that equals, lies inside, or contains a writable
// mount (port of _check_ro_rw_disjoint).
func CheckRODisjoint(ro, rw []string) error {
	for _, r := range ro {
		rc := filepath.Clean(r)
		for _, w := range rw {
			wc := filepath.Clean(w)
			if rc == wc || isRelativeTo(rc, wc) || isRelativeTo(wc, rc) {
				return errors.New("seatbelt: read-only mount " + rc + " overlaps writable mount " + wc +
					"; the writable grant would cover it (and App Sandbox refuses the same layout) -- mount disjoint trees")
			}
		}
	}
	return nil
}

// pinnedPaths: every rw root, plus each directory between a root and another rw root that
// contains it (port of _pinned_paths).
func pinnedPaths(rw []string) []string {
	roots := make([]string, len(rw))
	pinned := map[string]bool{}
	for i, p := range rw {
		roots[i] = filepath.Clean(p)
		pinned[roots[i]] = true
	}
	for _, r := range roots {
		for _, outer := range roots {
			if outer != r && isRelativeTo(r, outer) {
				d := filepath.Dir(r)
				for d != outer {
					pinned[d] = true
					d = filepath.Dir(d)
				}
			}
		}
	}
	out := make([]string, 0, len(pinned))
	for p := range pinned {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
