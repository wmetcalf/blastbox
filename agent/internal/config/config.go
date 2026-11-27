// Package config loads and validates the agent's TOML configuration. Validation is
// fail-closed: an agent that cannot prove its own posture refuses to start.
package config

import (
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config is the agent configuration.
type Config struct {
	Ingress  string   `toml:"ingress"`
	CAFile   string   `toml:"ca_file"`
	CertFile string   `toml:"cert_file"`
	KeyFile  string   `toml:"key_file"`
	StateDir string   `toml:"state_dir"`
	Claim    bool     `toml:"claim"` // false = shadow: handshake, heartbeat, probes only
	Engines  []Engine `toml:"engine"`
	Nsjail   *Nsjail  `toml:"nsjail"`
}

// Engine is one engine this node can run.
type Engine struct {
	Name         string   `toml:"name"`
	Argv         []string `toml:"argv"`
	Output       string   `toml:"output"` // "stdout-envelope" | "dir"
	Sandbox      string   `toml:"sandbox"`
	MinSandbox   string   `toml:"min_sandbox"`
	ROPaths      []string `toml:"ro_paths"`
	Accelerators []string `toml:"accelerators"`
	Slots        *int     `toml:"slots"`
	// ProbeArgv optionally replaces the built-in confinement probe. CONTRACT: it must try to read
	// {canary}, connect to {connect} and create {outside}, and print ONE JSON line to stdout,
	// {"read":"denied","connect":"denied","write":"denied"}; the agent requires all three to be
	// "denied". Missing or unparseable output is not OK (exit status alone proves nothing).
	ProbeArgv    []string `toml:"probe_argv"`
	SelftestArgv []string `toml:"selftest_argv"` // known-positive self-test, must exit 0
	MaxRSSMiB    *int     `toml:"max_rss_mib"`
	EnvParams    *bool    `toml:"env_params"` // forward run.params as env vars (default true)
	// ParamKeys is the engine's param ALLOWLIST (the dispatcher's per-engine PARAM_KEYS): unset
	// = any key that clears the reserved floor; set (even empty) = only these keys.
	ParamKeys *[]string `toml:"param_keys"`
	// ReservedParamKeys are keys this engine never takes from a job (posture selectors, binary
	// paths), on top of the engine-agnostic floor; they win over ParamKeys.
	ReservedParamKeys []string `toml:"reserved_param_keys"`
}

// Nsjail pins the nsjail binary and the confinement layers around it. Like blastbox's nsjail
// backend, a host without the seccomp policy or an AppArmor profile is INSECURE and the agent
// refuses to claim work on it unless the operator explicitly opts out of AppArmor.
type Nsjail struct {
	Path            string `toml:"path"`
	SHA256          string `toml:"sha256"`
	SeccompPolicy   string `toml:"seccomp_policy"`   // required: absolute path of an existing KAFEL policy
	AppArmorProfile string `toml:"apparmor_profile"` // required unless allow_missing_apparmor; the agent proves it attaches
	// AllowMissingAppArmor accepts a host with no AppArmor profile. The probe result then
	// records that layer as absent.
	AllowMissingAppArmor bool `toml:"allow_missing_apparmor"`
}

// SlotCount returns the effective slot count (default 1).
func (e *Engine) SlotCount() int {
	if e.Slots == nil {
		return 1
	}
	return *e.Slots
}

// FloorName is the engine's effective min_sandbox (default seatbelt), as reported in the heartbeat.
func (e *Engine) FloorName() string {
	if e.MinSandbox == "" {
		return "seatbelt"
	}
	return e.MinSandbox
}

// RSSLimitMiB returns the effective RSS cap (default 2048).
func (e *Engine) RSSLimitMiB() int {
	if e.MaxRSSMiB == nil {
		return 2048
	}
	return *e.MaxRSSMiB
}

// ForwardParams reports whether run.params are forwarded as env vars (default true).
func (e *Engine) ForwardParams() bool { return e.EnvParams == nil || *e.EnvParams }

// ParamKeyRE is the shape of a run param forwarded as an env var.
var ParamKeyRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

var (
	engineNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	sha256RE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// sandboxRank orders sandbox strength: none < seatbelt = nsjail.
func sandboxRank(s string) (int, bool) {
	switch s {
	case "none":
		return 0, true
	case "seatbelt", "nsjail":
		return 1, true
	}
	return 0, false
}

// Load reads, strictly decodes and validates the config at path.
func Load(path string) (*Config, error) { return load(path, runtime.GOOS) }

func load(path, goos string) (*Config, error) {
	var c Config
	md, err := toml.DecodeFile(path, &c)
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	if un := md.Undecoded(); len(un) > 0 {
		keys := make([]string, len(un))
		for i, k := range un {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("config %s: unknown keys: %s", path, strings.Join(keys, ", "))
	}
	if err := c.validate(goos); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) validate(goos string) error {
	u, err := url.Parse(c.Ingress)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("ingress must be an https:// URL, got %q", c.Ingress)
	}
	if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || strings.Contains(c.Ingress, "#") {
		return fmt.Errorf("ingress must be a bare https://host[:port] (no userinfo, path, query or fragment), got %q", c.Ingress)
	}
	for name, f := range map[string]string{"ca_file": c.CAFile, "cert_file": c.CertFile} {
		st, err := os.Stat(f)
		if err != nil || !st.Mode().IsRegular() {
			return fmt.Errorf("%s %q is missing or not a regular file", name, f)
		}
	}
	if err := checkKeyFile(c.KeyFile, fileOwner, os.Getuid()); err != nil {
		return err
	}
	if c.StateDir == "" || !filepath.IsAbs(c.StateDir) {
		return fmt.Errorf("state_dir must be an absolute path, got %q", c.StateDir)
	}
	if len(c.Engines) == 0 {
		return fmt.Errorf("at least one [[engine]] is required")
	}
	seen := map[string]bool{}
	needNsjail := false
	for i := range c.Engines {
		e := &c.Engines[i]
		if err := e.validate(goos); err != nil {
			return fmt.Errorf("engine[%d] %q: %w", i, e.Name, err)
		}
		if seen[e.Name] {
			return fmt.Errorf("duplicate engine name %q", e.Name)
		}
		seen[e.Name] = true
		if e.Sandbox == "nsjail" {
			needNsjail = true
		}
	}
	if needNsjail {
		if c.Nsjail == nil || !filepath.IsAbs(c.Nsjail.Path) || !sha256RE.MatchString(c.Nsjail.SHA256) {
			return fmt.Errorf("[nsjail] needs an absolute path and a pinned lowercase hex sha256")
		}
		if st, err := os.Stat(c.Nsjail.SeccompPolicy); !filepath.IsAbs(c.Nsjail.SeccompPolicy) || err != nil || !st.Mode().IsRegular() {
			return fmt.Errorf("[nsjail] seccomp_policy %q must be an absolute path of an existing file", c.Nsjail.SeccompPolicy)
		}
		if c.Nsjail.AppArmorProfile == "" && !c.Nsjail.AllowMissingAppArmor {
			return fmt.Errorf("[nsjail] needs apparmor_profile, or allow_missing_apparmor = true to run without it")
		}
	}
	return nil
}

func (e *Engine) validate(goos string) error {
	if !engineNameRE.MatchString(e.Name) {
		return fmt.Errorf("invalid name")
	}
	if err := absArgv("argv", e.Argv, true); err != nil {
		return err
	}
	if err := absArgv("probe_argv", e.ProbeArgv, false); err != nil {
		return err
	}
	if err := absArgv("selftest_argv", e.SelftestArgv, false); err != nil {
		return err
	}
	switch e.Output {
	case "stdout-envelope":
	case "dir":
		if !strings.Contains(strings.Join(e.Argv, "\x00"), "{out}") {
			return fmt.Errorf(`output "dir" needs an {out} placeholder in argv`)
		}
	default:
		return fmt.Errorf(`output must be "stdout-envelope" or "dir", got %q`, e.Output)
	}
	rank, ok := sandboxRank(e.Sandbox)
	if !ok {
		return fmt.Errorf("sandbox must be seatbelt, nsjail or none, got %q", e.Sandbox)
	}
	min := e.MinSandbox
	if min == "" {
		min = "seatbelt" // fail-closed default
	}
	minRank, ok := sandboxRank(min)
	if !ok {
		return fmt.Errorf("min_sandbox must be seatbelt, nsjail or none, got %q", min)
	}
	if rank < minRank {
		return fmt.Errorf("sandbox %q is below min_sandbox %q", e.Sandbox, min)
	}
	if e.Sandbox == "seatbelt" && goos != "darwin" {
		return fmt.Errorf("sandbox seatbelt is only available on darwin (running %s)", goos)
	}
	if e.Sandbox == "nsjail" && goos != "linux" {
		return fmt.Errorf("sandbox nsjail is only available on linux (running %s)", goos)
	}
	for _, p := range e.ROPaths {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("ro_paths entry %q must be absolute", p)
		}
	}
	for _, a := range e.Accelerators {
		if a != "ane" && a != "gpu" {
			return fmt.Errorf("unknown accelerator %q", a)
		}
	}
	if s := e.SlotCount(); s < 1 || s > 16 {
		return fmt.Errorf("slots must be 1..16, got %d", s)
	}
	if r := e.RSSLimitMiB(); r < 64 {
		return fmt.Errorf("max_rss_mib must be >= 64, got %d", r)
	}
	var keys []string
	if e.ParamKeys != nil {
		keys = append(keys, *e.ParamKeys...)
	}
	for _, k := range append(keys, e.ReservedParamKeys...) {
		if !ParamKeyRE.MatchString(k) {
			return fmt.Errorf("param key %q must match %s", k, ParamKeyRE)
		}
	}
	return nil
}

func absArgv(name string, argv []string, required bool) error {
	if len(argv) == 0 {
		if required {
			return fmt.Errorf("%s is required", name)
		}
		return nil
	}
	if !filepath.IsAbs(argv[0]) {
		return fmt.Errorf("%s[0] must be an absolute path, got %q", name, argv[0])
	}
	return nil
}

// checkKeyFile refuses a key that is a symlink, not a regular file, owned by someone other
// than wantUID (as reported by owner), or accessible to group/other.
func checkKeyFile(path string, owner func(fs.FileInfo) (int, error), wantUID int) error {
	st, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("key_file %q: %w", path, err)
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("key_file %q is a symlink", path)
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("key_file %q is not a regular file", path)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("key_file %q has mode %04o; it must have no group/other access", path, st.Mode().Perm())
	}
	uid, err := owner(st)
	if err != nil {
		return fmt.Errorf("key_file %q: %w", path, err)
	}
	if uid != wantUID {
		return fmt.Errorf("key_file %q is owned by uid %d, not %d", path, uid, wantUID)
	}
	return nil
}
