package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type fixture struct{ dir, ca, crt, key string }

func newFixture(t *testing.T) fixture {
	t.Helper()
	d := t.TempDir()
	f := fixture{dir: d, ca: filepath.Join(d, "ca.crt"), crt: filepath.Join(d, "node.crt"), key: filepath.Join(d, "node.key")}
	for _, p := range []string{f.ca, f.crt} {
		os.WriteFile(p, []byte("x"), 0o644)
	}
	os.WriteFile(f.key, []byte("x"), 0o600)
	return f
}

func (f fixture) toml(engine, tail string) string {
	return fmt.Sprintf(`ingress = "https://172.18.101.15:8005"
ca_file = %q
cert_file = %q
key_file = %q
state_dir = %q
claim = false
%s
%s
`, f.ca, f.crt, f.key, filepath.Join(f.dir, "state"), engine, tail)
}

func eng(extra string) string {
	return `[[engine]]
name = "williamtells"
argv = ["/opt/wt/bin/scan", "blastbox", "{input}"]
output = "stdout-envelope"
` + extra
}

// nativeSandbox is the sandbox valid on the running OS (load takes goos explicitly in tests).
func write(t *testing.T, f fixture, body string) string {
	p := filepath.Join(f.dir, "agent.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadOK(t *testing.T) {
	f := newFixture(t)
	p := write(t, f, f.toml(eng(`sandbox = "seatbelt"
min_sandbox = "seatbelt"
ro_paths = ["/opt/wt"]
accelerators = ["ane", "gpu"]
slots = 2
selftest_argv = ["/opt/wt/bin/scan", "self-test"]
`), ""))
	c, err := load(p, "darwin")
	if err != nil {
		t.Fatal(err)
	}
	e := c.Engines[0]
	if e.SlotCount() != 2 || e.RSSLimitMiB() != 2048 || !e.ForwardParams() || c.Claim {
		t.Fatalf("defaults wrong: %+v", e)
	}
	// nsjail on linux with a pinned binary
	p = write(t, f, f.toml(eng(`sandbox = "nsjail"`+"\n"), "[nsjail]\npath = \"/usr/local/bin/nsjail\"\nsha256 = \""+strings.Repeat("a", 64)+"\"\n"))
	if _, err := load(p, "linux"); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRefusals(t *testing.T) {
	good := `sandbox = "nsjail"` + "\n"
	nsj := "[nsjail]\npath = \"/usr/local/bin/nsjail\"\nsha256 = \"" + strings.Repeat("b", 64) + "\"\n"
	cases := []struct {
		name  string
		goos  string
		build func(f fixture) string
		want  string
	}{
		{"unknown top key", "linux", func(f fixture) string { return f.toml(eng(good), nsj) + "bogus = 1\n" }, "unknown keys"},
		{"unknown engine key", "linux", func(f fixture) string { return f.toml(eng(good+"bogus = 1\n"), nsj) }, "unknown keys"},
		{"http ingress", "linux", func(f fixture) string {
			return strings.Replace(f.toml(eng(good), nsj), "https://", "http://", 1)
		}, "https"},
		{"missing ca", "linux", func(f fixture) string { os.Remove(f.ca); return f.toml(eng(good), nsj) }, "ca_file"},
		{"missing cert", "linux", func(f fixture) string { os.Remove(f.crt); return f.toml(eng(good), nsj) }, "cert_file"},
		{"missing key", "linux", func(f fixture) string { os.Remove(f.key); return f.toml(eng(good), nsj) }, "key_file"},
		{"key 0640", "linux", func(f fixture) string { os.Chmod(f.key, 0o640); return f.toml(eng(good), nsj) }, "0600"},
		{"key symlink", "linux", func(f fixture) string {
			real := f.key + ".real"
			os.Rename(f.key, real)
			os.Symlink(real, f.key)
			return f.toml(eng(good), nsj)
		}, "symlink"},
		{"relative state_dir", "linux", func(f fixture) string {
			return strings.Replace(f.toml(eng(good), nsj), f.dir+"/state", "state", 1)
		}, "state_dir"},
		{"no engines", "linux", func(f fixture) string { return f.toml("", "") }, "engine"},
		{"sandbox below min", "linux", func(f fixture) string {
			return f.toml(eng(`sandbox = "none"`+"\n"+`min_sandbox = "seatbelt"`+"\n"), "")
		}, "below min_sandbox"},
		{"none with default min", "linux", func(f fixture) string { return f.toml(eng(`sandbox = "none"`+"\n"), "") }, "below min_sandbox"},
		{"seatbelt on linux", "linux", func(f fixture) string { return f.toml(eng(`sandbox = "seatbelt"`+"\n"), "") }, "darwin"},
		{"nsjail on darwin", "darwin", func(f fixture) string { return f.toml(eng(good), nsj) }, "linux"},
		{"nsjail unpinned", "linux", func(f fixture) string { return f.toml(eng(good), "") }, "nsjail"},
		{"nsjail bad sha", "linux", func(f fixture) string {
			return f.toml(eng(good), "[nsjail]\npath = \"/x/nsjail\"\nsha256 = \"abc\"\n")
		}, "sha256"},
		{"slots 0", "linux", func(f fixture) string { return f.toml(eng(good+"slots = 0\n"), nsj) }, "slots"},
		{"slots 17", "linux", func(f fixture) string { return f.toml(eng(good+"slots = 17\n"), nsj) }, "slots"},
		{"argv relative", "linux", func(f fixture) string {
			return strings.Replace(f.toml(eng(good), nsj), `"/opt/wt/bin/scan", "blastbox"`, `"scan", "blastbox"`, 1)
		}, "absolute"},
		{"selftest relative", "linux", func(f fixture) string {
			return f.toml(eng(good+`selftest_argv = ["scan", "self-test"]`+"\n"), nsj)
		}, "selftest_argv"},
		{"bad output", "linux", func(f fixture) string {
			return strings.Replace(f.toml(eng(good), nsj), "stdout-envelope", "tcp", 1)
		}, "output"},
		{"dir output without {out}", "linux", func(f fixture) string {
			return strings.Replace(f.toml(eng(good), nsj), "stdout-envelope", "dir", 1)
		}, "{out}"},
		{"dup engine", "linux", func(f fixture) string { return f.toml(eng(good)+eng(good), nsj) }, "duplicate"},
		{"bad accelerator", "linux", func(f fixture) string { return f.toml(eng(good+`accelerators = ["tpu"]`+"\n"), nsj) }, "accelerator"},
		{"relative ro_path", "linux", func(f fixture) string { return f.toml(eng(good+`ro_paths = ["opt"]`+"\n"), nsj) }, "ro_paths"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			body := tc.build(f)
			_, err := load(write(t, f, body), tc.goos)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q lacks %q", err, tc.want)
			}
		})
	}
}

func TestLoadUsesRuntimeGOOS(t *testing.T) {
	f := newFixture(t)
	wrong := "seatbelt"
	if runtime.GOOS == "darwin" {
		wrong = "nsjail"
	}
	if _, err := Load(write(t, f, f.toml(eng(`sandbox = "`+wrong+`"`+"\n"), ""))); err == nil {
		t.Fatal("wrong-OS sandbox accepted")
	}
}
