package config

import (
	"errors"
	"fmt"
	"io/fs"
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
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(f.key, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
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
	p = write(t, f, f.toml(eng(`sandbox = "nsjail"`+"\n"), "[nsjail]\npath = \"/usr/local/bin/nsjail\"\nsha256 = \""+strings.Repeat("a", 64)+"\"\nseccomp_policy = \"/etc/passwd\"\nallow_missing_apparmor = true\n"))
	if _, err := load(p, "linux"); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRefusals(t *testing.T) {
	good := `sandbox = "nsjail"` + "\n"
	nsj := "[nsjail]\npath = \"/usr/local/bin/nsjail\"\nsha256 = \"" + strings.Repeat("b", 64) + "\"\nseccomp_policy = \"/etc/passwd\"\nallow_missing_apparmor = true\n"
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
		{"ingress path", "linux", func(f fixture) string {
			return strings.Replace(f.toml(eng(good), nsj), "8005\"", "8005/api\"", 1)
		}, "bare https"},
		{"ingress userinfo", "linux", func(f fixture) string {
			return strings.Replace(f.toml(eng(good), nsj), "https://", "https://u:p@", 1)
		}, "bare https"},
		{"ingress query", "linux", func(f fixture) string {
			return strings.Replace(f.toml(eng(good), nsj), "8005\"", "8005?x=1\"", 1)
		}, "bare https"},
		{"ingress fragment", "linux", func(f fixture) string {
			return strings.Replace(f.toml(eng(good), nsj), "8005\"", "8005#f\"", 1)
		}, "bare https"},
		{"missing ca", "linux", func(f fixture) string { _ = os.Remove(f.ca); return f.toml(eng(good), nsj) }, "ca_file"},
		{"missing cert", "linux", func(f fixture) string { _ = os.Remove(f.crt); return f.toml(eng(good), nsj) }, "cert_file"},
		{"missing key", "linux", func(f fixture) string { _ = os.Remove(f.key); return f.toml(eng(good), nsj) }, "key_file"},
		{"key 0640", "linux", func(f fixture) string {
			if err := os.Chmod(f.key, 0o640); err != nil {
				t.Fatal(err)
			}
			return f.toml(eng(good), nsj)
		}, "no group/other"},
		{"key symlink", "linux", func(f fixture) string {
			real := f.key + ".real"
			if err := os.Rename(f.key, real); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, f.key); err != nil {
				t.Fatal(err)
			}
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
			return f.toml(eng(good), "[nsjail]\npath = \"/x/nsjail\"\nsha256 = \"abc\"\n"+"seccomp_policy = \"/etc/passwd\"\nallow_missing_apparmor = true\n")
		}, "sha256"},
		{"nsjail no seccomp", "linux", func(f fixture) string {
			return f.toml(eng(good), strings.Replace(nsj, "seccomp_policy = \"/etc/passwd\"", "seccomp_policy = \"/nonexistent/policy\"", 1))
		}, "seccomp_policy"},
		{"nsjail no apparmor", "linux", func(f fixture) string {
			return f.toml(eng(good), strings.Replace(nsj, "allow_missing_apparmor = true", "", 1))
		}, "apparmor_profile"},
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

func TestKeyFileChecks(t *testing.T) {
	f := newFixture(t)
	me := os.Getuid()
	for _, mode := range []os.FileMode{0o400, 0o600, 0o700} {
		if err := os.Chmod(f.key, mode); err != nil {
			t.Fatal(err)
		}
		if err := checkKeyFile(f.key, fileOwner, me); err != nil {
			t.Errorf("mode %04o refused: %v", mode, err)
		}
	}
	if err := os.Chmod(f.key, 0o604); err != nil {
		t.Fatal(err)
	}
	if err := checkKeyFile(f.key, fileOwner, me); err == nil || !strings.Contains(err.Error(), "no group/other") {
		t.Errorf("other-readable key: %v", err)
	}
	if err := os.Chmod(f.key, 0o600); err != nil {
		t.Fatal(err)
	}
	// Wrong owner: expect a different uid than the file's.
	if err := checkKeyFile(f.key, fileOwner, me+1); err == nil || !strings.Contains(err.Error(), "owned by uid") {
		t.Errorf("wrong owner accepted: %v", err)
	}
	fake := func(fs.FileInfo) (int, error) { return me + 7, nil }
	if err := checkKeyFile(f.key, fake, me); err == nil || !strings.Contains(err.Error(), "owned by uid") {
		t.Errorf("injected foreign owner accepted: %v", err)
	}
	fail := func(fs.FileInfo) (int, error) { return 0, errors.New("no owner info") }
	if err := checkKeyFile(f.key, fail, me); err == nil {
		t.Error("owner lookup failure accepted")
	}
}
