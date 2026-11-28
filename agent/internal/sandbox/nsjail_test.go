package sandbox

import (
	"reflect"
	"testing"

	"github.com/wmetcalf/blastbox/agent/internal/conformance"
)

func TestNsjailGolden(t *testing.T) {
	files, err := conformance.SandboxFiles("nsjail")
	if err != nil || len(files) == 0 {
		t.Fatalf("no nsjail vectors: %v", err)
	}
	for _, f := range files {
		t.Run(f, func(t *testing.T) {
			var c conformance.NsjailCase
			if err := conformance.ReadJSON(f, &c); err != nil {
				t.Fatal(err)
			}
			r := c.Request
			req := NsjailRequest{Argv: r.Argv, Env: r.Env, AttachAppArmor: r.AttachAppArmor}
			for _, m := range r.ROMounts {
				req.ROMounts = append(req.ROMounts, Mount{m.Source, m.Target})
			}
			for _, m := range r.RWMounts {
				req.RWMounts = append(req.RWMounts, Mount{m.Source, m.Target})
			}
			if r.Limits.MemoryBytes != nil {
				req.Limits.MemoryBytes = *r.Limits.MemoryBytes
			}
			if r.Limits.TimeoutS != nil {
				req.Limits.TimeoutS = *r.Limits.TimeoutS
			}
			if r.Limits.TmpfsBytes != nil {
				req.Limits.TmpfsBytes = *r.Limits.TmpfsBytes
			}
			req.Limits.NetEgress = r.Limits.NetEgress
			hp := c.HostPins
			pins := HostPins{AppArmorProfile: hp.AppArmorProfile, Exists: map[string]bool{}, Symlinks: map[string]bool{}}
			if r.AAExec {
				pins.AAExec = hp.AAExec
			}
			for _, p := range hp.PathsThatExist {
				pins.Exists[p] = true
			}
			for _, p := range hp.PathsThatAreSymlink {
				pins.Symlinks[p] = true
			}
			got, err := BuildNsjailArgv(req, hp.Nsjail, hp.SeccompPolicy, pins)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, c.Argv) {
				t.Errorf("argv mismatch\n got: %q\nwant: %q", got, c.Argv)
			}
		})
	}
}

func TestChildEnvNeverInheritsAndDropsReserved(t *testing.T) {
	t.Setenv("SECRET_TOKEN", "leak")
	env, err := ChildEnv("/scratch", map[string]string{"A": "1", "HOME": "/evil", "DYLD_INSERT_LIBRARIES": "x", "LD_PRELOAD": "y"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"HOME": "/scratch", "TMPDIR": "/scratch", "PATH": "/usr/bin:/bin", "LANG": "C", "A": "1"}
	if !reflect.DeepEqual(env, want) {
		t.Errorf("got %v want %v", env, want)
	}
	if _, err := ChildEnv("/s", map[string]string{"A=B": "1"}); err == nil {
		t.Error("'=' in key must be an error")
	}
}
