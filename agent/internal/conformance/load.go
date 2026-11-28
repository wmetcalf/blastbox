// Package conformance loads the committed conformance/v1 vectors for tests.
package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Dir returns the absolute path of conformance/v1 (walks up from this source file to go.mod,
// then ../conformance/v1).
func Dir() string {
	if d := os.Getenv("BLASTBOX_CONFORMANCE_DIR"); d != "" { // cross-compiled test binaries
		return d
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("conformance: cannot locate source")
	}
	d := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return filepath.Join(filepath.Dir(d), "conformance", "v1")
		}
		p := filepath.Dir(d)
		if p == d {
			panic("conformance: go.mod not found")
		}
		d = p
	}
}

// Path joins elements under Dir().
func Path(elem ...string) string { return filepath.Join(append([]string{Dir()}, elem...)...) }

// ReadJSON decodes a vector file into v.
func ReadJSON(rel string, v any) error {
	raw, err := os.ReadFile(Path(rel))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%s: %w", rel, err)
	}
	return nil
}

type SigningCase struct {
	Challenge  string `json:"challenge"`
	NodeID     string `json:"node_id"`
	PayloadHex string `json:"payload_hex"`
	Scope      string `json:"scope"`
}

type SigningFile struct {
	Cases []SigningCase `json:"cases"`
}

type CanonCase struct {
	Input        json.RawMessage `json:"input"`
	CanonicalHex string          `json:"canonical_hex"`
	InputRepr    string          `json:"input_repr"`
	Error        string          `json:"error"`
}

type CanonFile struct {
	Cases []CanonCase `json:"cases"`
}

type SignedEntry struct {
	PayloadHex   string `json:"payload_hex"`
	PublicKeyPEM string `json:"public_key_pem"`
	SignatureB64 string `json:"signature_b64"`
	// Valid is absent (nil) for a normal entry, meaning true; false marks a deliberately
	// tampered signature that must fail verification.
	Valid *bool `json:"valid,omitempty"`
}

type CrossFile struct {
	PythonSigned []SignedEntry `json:"python_signed"`
	GoSigned     []SignedEntry `json:"go_signed"`
}

type Admit struct {
	Challenge    string  `json:"challenge"`
	Scope        string  `json:"scope"`
	SignatureB64 string  `json:"signature_b64"`
	Verdict      string  `json:"verdict"`
	VerifyAt     float64 `json:"verify_at"`
}

type CertCase struct {
	Admit   *Admit `json:"admit"`
	Cert    string `json:"cert"`
	Key     string `json:"key"`
	Name    string `json:"name"`
	NodeID  string `json:"node_id"`
	Verdict string `json:"verdict"`
	Why     string `json:"why"`
}

type CertCases struct {
	CA       string     `json:"ca"`
	Cases    []CertCase `json:"cases"`
	Now      string     `json:"now"`
	NowEpoch float64    `json:"now_epoch"`
}

// SandboxFiles lists the vector files under sandbox/<kind> (kind is "seatbelt" or "nsjail"),
// as paths relative to Dir(), sorted.
func SandboxFiles(kind string) ([]string, error) {
	ents, err := os.ReadDir(Path("sandbox", kind))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			out = append(out, filepath.Join("sandbox", kind, e.Name()))
		}
	}
	return out, nil
}

// SeatbeltCase is one sandbox/seatbelt vector.
type SeatbeltCase struct {
	Request struct {
		Accelerators []string `json:"accelerators"`
		Canary       *string  `json:"canary"`
		ExecPaths    []string `json:"exec_paths"`
		ROPaths      []string `json:"ro_paths"`
		RWPaths      []string `json:"rw_paths"`
		Scratch      *string  `json:"scratch"`
	} `json:"request"`
	Params  map[string]string `json:"params"`
	Profile string            `json:"profile"`
}

// NsjailMount is a source/target bind mount in an nsjail vector.
type NsjailMount struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

// NsjailCase is one sandbox/nsjail vector.
type NsjailCase struct {
	Request struct {
		AAExec         bool              `json:"aa_exec"`
		Argv           []string          `json:"argv"`
		AttachAppArmor bool              `json:"attach_apparmor"`
		Env            map[string]string `json:"env"`
		Limits         struct {
			MemoryBytes *int64 `json:"memory_bytes"`
			TimeoutS    *int64 `json:"timeout_s"`
			TmpfsBytes  *int64 `json:"tmpfs_bytes"`
			NetEgress   bool   `json:"net_egress"`
		} `json:"limits"`
		ROMounts []NsjailMount `json:"ro_mounts"`
		RWMounts []NsjailMount `json:"rw_mounts"`
	} `json:"request"`
	HostPins struct {
		AAExec              string   `json:"aa_exec"`
		AppArmorProfile     string   `json:"apparmor_profile"`
		Nsjail              string   `json:"nsjail"`
		SeccompPolicy       string   `json:"seccomp_policy"`
		PathsThatExist      []string `json:"paths_that_exist"`
		PathsThatAreSymlink []string `json:"paths_that_are_symlinks"`
	} `json:"host_pins"`
	Argv []string `json:"argv"`
}
