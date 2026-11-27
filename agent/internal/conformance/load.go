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
