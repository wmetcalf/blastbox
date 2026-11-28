// Package canon reproduces Python's
// json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True).
package canon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"unicode/utf16"
	"unicode/utf8"
)

var intRE = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// ErrUTF8 is returned for a string that is not valid UTF-8.
var ErrUTF8 = errors.New("canon: invalid UTF-8")

// ErrSurrogate is returned for a JSON document holding an unpaired UTF-16 surrogate escape,
// which encoding/json replaces with U+FFFD where Python keeps it.
var ErrSurrogate = errors.New("canon: unpaired UTF-16 surrogate escape")

// ErrFloat is returned for any non-integer number.
var ErrFloat = errors.New("canon: floats are not allowed")

// Marshal encodes v canonically. Supported: nil, bool, string, ints, json.Number,
// []any, map[string]any. Floats (float32/64 or a json.Number containing . e E) are rejected.
func Marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := enc(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// MarshalJSONText canonicalises a JSON document (numbers kept exact via UseNumber).
func MarshalJSONText(text []byte) ([]byte, error) {
	if !utf8.Valid(text) {
		return nil, ErrUTF8
	}
	if loneSurrogate(text) {
		return nil, ErrSurrogate
	}
	d := json.NewDecoder(bytes.NewReader(text))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("canon: trailing data after JSON value")
	}
	return Marshal(v)
}

// Lossless reports whether encoding/json decodes text without altering any string: the text is
// valid UTF-8 and holds no unpaired surrogate escape (both become U+FFFD silently).
func Lossless(text []byte) bool { return utf8.Valid(text) && !loneSurrogate(text) }

func hex4(b []byte) (rune, bool) {
	if len(b) < 4 {
		return 0, false
	}
	var r rune
	for _, c := range b[:4] {
		switch {
		case c >= '0' && c <= '9':
			r = r<<4 | rune(c-'0')
		case c >= 'a' && c <= 'f':
			r = r<<4 | rune(c-'a'+10)
		case c >= 'A' && c <= 'F':
			r = r<<4 | rune(c-'A'+10)
		default:
			return 0, false
		}
	}
	return r, true
}

// loneSurrogate scans the string literals of a JSON text for a \uD800-\uDFFF escape that is not
// a high surrogate immediately followed by a low one.
func loneSurrogate(text []byte) bool {
	in := false
	for i := 0; i < len(text); i++ {
		c := text[i]
		if !in {
			if c == '"' {
				in = true
			}
			continue
		}
		switch c {
		case '"':
			in = false
		case '\\':
			if i+1 >= len(text) {
				return false
			}
			if text[i+1] != 'u' {
				i++
				continue
			}
			r, ok := hex4(text[i+2:])
			if !ok {
				return false // malformed: the decoder refuses it anyway
			}
			i += 5
			switch {
			case r >= 0xDC00 && r <= 0xDFFF:
				return true
			case r >= 0xD800 && r <= 0xDBFF:
				if i+6 >= len(text) || text[i+1] != '\\' || text[i+2] != 'u' {
					return true
				}
				lo, ok := hex4(text[i+3:])
				if !ok || lo < 0xDC00 || lo > 0xDFFF {
					return true
				}
				i += 6
			}
		}
	}
	return false
}

func enc(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		return encString(b, x)
	case json.Number:
		if !intRE.MatchString(string(x)) {
			// A number with . e E is a float; anything else is not a JSON integer literal.
			for _, c := range string(x) {
				if c == '.' || c == 'e' || c == 'E' {
					return ErrFloat
				}
			}
			return fmt.Errorf("canon: invalid number %q", string(x))
		}
		if string(x) == "-0" {
			b.WriteString("0")
		} else {
			b.WriteString(string(x))
		}
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		fmt.Fprintf(b, "%d", x)
	case float32, float64:
		return ErrFloat
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := enc(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		// UTF-8 byte order == code point order == Python's str sort.
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := encString(b, k); err != nil {
				return err
			}
			b.WriteByte(':')
			if err := enc(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("canon: unsupported type %T", v)
	}
	return nil
}

func encString(b *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return ErrUTF8
	}
	const hex = "0123456789abcdef"
	u := func(r rune) {
		b.WriteString(`\u`)
		b.WriteByte(hex[r>>12&0xf])
		b.WriteByte(hex[r>>8&0xf])
		b.WriteByte(hex[r>>4&0xf])
		b.WriteByte(hex[r&0xf])
	}
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r < 0x20:
			u(r)
		case r < 0x7f:
			b.WriteRune(r)
		case r >= 0x10000:
			r1, r2 := utf16.EncodeRune(r)
			u(r1)
			u(r2)
		default:
			u(r)
		}
	}
	b.WriteByte('"')
	return nil
}
