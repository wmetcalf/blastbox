package canon_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/wmetcalf/blastbox/agent/internal/canon"
	"github.com/wmetcalf/blastbox/agent/internal/conformance"
)

// floatInputs maps the vector's Python repr to equivalent JSON text.
var floatInputs = map[string]string{
	"{'a': 1.5}":                `{"a":1.5}`,
	"{'a': [1, {'b': 2.0}]}":    `{"a":[1,{"b":2.0}]}`,
	"[0.0]":                     `[0.0]`,
	"{'x': {'y': {'z': -0.5}}}": `{"x":{"y":{"z":-0.5}}}`,
	"1e+100":                    `1e+100`,
	"[1e+22]":                   `[1e+22]`,
	"{'a': 1e-07}":              `{"a":1e-07}`,
}

func TestCanonicalJSONVectors(t *testing.T) {
	var f conformance.CanonFile
	if err := conformance.ReadJSON("canonical_json.json", &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("no cases")
	}
	for i, c := range f.Cases {
		if c.Error != "" {
			text, ok := floatInputs[c.InputRepr]
			if !ok {
				t.Fatalf("case %d: unmapped float repr %q", i, c.InputRepr)
			}
			if _, err := canon.MarshalJSONText([]byte(text)); !errors.Is(err, canon.ErrFloat) {
				t.Errorf("case %d (%s): want ErrFloat, got %v", i, c.InputRepr, err)
			}
			continue
		}
		got, err := canon.MarshalJSONText(c.Input)
		if err != nil {
			t.Errorf("case %d: %v", i, err)
			continue
		}
		want, _ := hex.DecodeString(c.CanonicalHex)
		if !bytes.Equal(got, want) {
			t.Errorf("case %d:\n got %s\nwant %s", i, got, want)
		}
	}
}

func TestFloatTypesRejected(t *testing.T) {
	for _, v := range []any{1.5, float32(2), map[string]any{"a": []any{3.0}}, json.Number("1E5")} {
		if _, err := canon.Marshal(v); !errors.Is(err, canon.ErrFloat) {
			t.Errorf("%v: want ErrFloat, got %v", v, err)
		}
	}
}

func TestNoHTMLEscape(t *testing.T) {
	got, err := canon.Marshal("<&>")
	if err != nil || string(got) != "\"<&>\"" {
		t.Fatalf("%q %v", got, err)
	}
}
