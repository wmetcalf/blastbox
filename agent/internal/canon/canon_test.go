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

func TestEdgeCases(t *testing.T) {
	got, err := canon.MarshalJSONText([]byte(`[-0, 0, -5]`))
	if err != nil || string(got) != "[0,0,-5]" {
		t.Fatalf("%q %v", got, err)
	}
	if got, err := canon.Marshal(json.Number("-0")); err != nil || string(got) != "0" {
		t.Fatalf("%q %v", got, err)
	}
	for _, bad := range []json.Number{"", "+1", "01", "0x1", "1_0", "-", "abc"} {
		if _, err := canon.Marshal(bad); err == nil || errors.Is(err, canon.ErrFloat) {
			t.Errorf("%q: want non-float number error, got %v", bad, err)
		}
	}
	for _, bad := range []string{`{} {}`, `1 2`, `[] x`, "{}\x00"} {
		if _, err := canon.MarshalJSONText([]byte(bad)); err == nil {
			t.Errorf("trailing data accepted: %q", bad)
		}
	}
	if _, err := canon.MarshalJSONText([]byte(" {} \n")); err != nil {
		t.Errorf("trailing whitespace refused: %v", err)
	}
	for _, bad := range []any{"a\xffb", map[string]any{"k\xff": 1}} {
		if _, err := canon.Marshal(bad); !errors.Is(err, canon.ErrUTF8) {
			t.Errorf("%q: want ErrUTF8, got %v", bad, err)
		}
	}
	if _, err := canon.MarshalJSONText([]byte("\"a\xffb\"")); !errors.Is(err, canon.ErrUTF8) {
		t.Errorf("raw invalid UTF-8 text: %v", err)
	}
}

// encoding/json turns a lone UTF-16 surrogate escape into U+FFFD, where Python keeps it and
// re-emits it: such a document cannot be canonicalised byte-exactly, so it is refused.
func TestLoneSurrogatesRefused(t *testing.T) {
	for _, bad := range []string{`"\ud800"`, `"\uDC00x"`, `["\ud83d"]`, `{"a":"\ud83dA"}`, `"\ude00\ud83d"`} {
		if _, err := canon.MarshalJSONText([]byte(bad)); !errors.Is(err, canon.ErrSurrogate) {
			t.Errorf("%s: want ErrSurrogate, got %v", bad, err)
		}
		if canon.Lossless([]byte(bad)) {
			t.Errorf("%s: reported lossless", bad)
		}
	}
	for _, ok := range []string{`"😀"`, `"\\ud800"`, `"\\😀"`, `"plain"`, `{"ké":1}`} {
		if !canon.Lossless([]byte(ok)) {
			t.Errorf("%s: reported lossy", ok)
		}
		if _, err := canon.MarshalJSONText([]byte(ok)); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	if canon.Lossless([]byte("\"a\xffb\"")) {
		t.Error("invalid UTF-8 reported lossless")
	}
}
