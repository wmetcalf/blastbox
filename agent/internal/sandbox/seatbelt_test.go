package sandbox

import (
	"strings"
	"testing"

	"github.com/wmetcalf/blastbox/agent/internal/conformance"
)

func TestSeatbeltGolden(t *testing.T) {
	files, err := conformance.SandboxFiles("seatbelt")
	if err != nil || len(files) == 0 {
		t.Fatalf("no seatbelt vectors: %v", err)
	}
	for _, f := range files {
		t.Run(f, func(t *testing.T) {
			var c conformance.SeatbeltCase
			if err := conformance.ReadJSON(f, &c); err != nil {
				t.Fatal(err)
			}
			r := c.Request
			req := Request{ExecPaths: r.ExecPaths, ROPaths: r.ROPaths, RWPaths: r.RWPaths, Accelerators: r.Accelerators}
			if r.Scratch != nil {
				req.Scratch = *r.Scratch
			}
			if r.Canary != nil {
				req.Canary = *r.Canary
			}
			profile, params, err := BuildSeatbeltProfile(req)
			if err != nil {
				t.Fatal(err)
			}
			if profile != c.Profile {
				t.Errorf("profile mismatch\n got: %q\nwant: %q", profile, c.Profile)
			}
			if len(params) != len(c.Params) {
				t.Errorf("params: got %v want %v", params, c.Params)
			}
			for k, v := range c.Params {
				if params[k] != v {
					t.Errorf("param %s: got %q want %q", k, params[k], v)
				}
			}
		})
	}
}

func TestSeatbeltRefusals(t *testing.T) {
	cases := map[string]Request{
		"ro equals rw":     {ExecPaths: []string{"/x/e"}, ROPaths: []string{"/a/b"}, RWPaths: []string{"/a/b"}},
		"ro inside rw":     {ExecPaths: []string{"/x/e"}, ROPaths: []string{"/a/b/c"}, RWPaths: []string{"/a/b"}},
		"ro contains rw":   {ExecPaths: []string{"/x/e"}, ROPaths: []string{"/a"}, RWPaths: []string{"/a/b"}},
		"unknown accel":    {ExecPaths: []string{"/x/e"}, Accelerators: []string{"tpu"}},
		"ro contains root": {ExecPaths: []string{"/x/e"}, ROPaths: []string{"/"}, RWPaths: []string{"/a"}},
	}
	for name, req := range cases {
		if _, _, err := BuildSeatbeltProfile(req); err == nil {
			t.Errorf("%s: expected refusal", name)
		}
	}
	// siblings sharing a name prefix are disjoint
	if _, _, err := BuildSeatbeltProfile(Request{ExecPaths: []string{"/x/e"}, ROPaths: []string{"/a/bc"}, RWPaths: []string{"/a/b"}}); err != nil {
		t.Errorf("prefix siblings must be allowed: %v", err)
	}
}

func TestSeatbeltNoPathInProfile(t *testing.T) {
	p, _, err := BuildSeatbeltProfile(Request{ExecPaths: []string{"/opt/secret-engine/bin"}, ROPaths: []string{"/srv/inputs"}, RWPaths: []string{"/var/w"}, Scratch: "/var/w"})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"secret-engine", "/srv/inputs", "/var/w"} {
		if strings.Contains(p, s) {
			t.Errorf("path %q leaked into profile text", s)
		}
	}
}
