package wire_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/wmetcalf/blastbox/agent/internal/conformance"
	"github.com/wmetcalf/blastbox/agent/internal/wire"
)

var updateGoSigned = flag.Bool("update-go-signed", false,
	"rewrite go_signed in conformance/v1/ecdsa_cross.json and renew_proof.json (then regenerate SHA256SUMS)")

func TestSigningPayloadVectors(t *testing.T) {
	var f conformance.SigningFile
	if err := conformance.ReadJSON("signing_payload.json", &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("no cases")
	}
	for i, c := range f.Cases {
		want, err := hex.DecodeString(c.PayloadHex)
		if err != nil {
			t.Fatal(err)
		}
		if got := wire.SigningPayload(c.Challenge, c.Scope, c.NodeID); !bytes.Equal(got, want) {
			t.Errorf("case %d: got %x want %x", i, got, want)
		}
	}
}

func parsePub(t *testing.T, p string) *ecdsa.PublicKey {
	t.Helper()
	blk, _ := pem.Decode([]byte(p))
	if blk == nil {
		t.Fatal("bad PEM")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return k.(*ecdsa.PublicKey)
}

func TestECDSACross(t *testing.T) {
	var f conformance.CrossFile
	if err := conformance.ReadJSON("ecdsa_cross.json", &f); err != nil {
		t.Fatal(err)
	}
	if len(f.PythonSigned) == 0 {
		t.Fatal("python_signed empty")
	}
	for i, e := range f.PythonSigned {
		payload, _ := hex.DecodeString(e.PayloadHex)
		want := e.Valid == nil || *e.Valid
		if got := wire.Verify(parsePub(t, e.PublicKeyPEM), payload, e.SignatureB64); got != want {
			t.Errorf("python_signed[%d]: verify=%v, vector says valid=%v", i, got, want)
		}
		if wire.Verify(parsePub(t, e.PublicKeyPEM), append(payload, 'x'), e.SignatureB64) {
			t.Errorf("python_signed[%d] verifies a tampered payload", i)
		}
	}
	for i, e := range f.GoSigned {
		payload, _ := hex.DecodeString(e.PayloadHex)
		if !wire.Verify(parsePub(t, e.PublicKeyPEM), payload, e.SignatureB64) {
			t.Errorf("go_signed[%d] does not verify", i)
		}
	}
}

func TestSignRoundTrip(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p := wire.SigningPayload("1.0:ab", "claim-next", "n")
	s, err := wire.Sign(k, p)
	if err != nil || !wire.Verify(&k.PublicKey, p, s) {
		t.Fatalf("round trip: %v", err)
	}
}

func TestUpdateGoSigned(t *testing.T) {
	if !*updateGoSigned {
		t.Skip("pass -update-go-signed to regenerate go_signed")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	var cross []conformance.SignedEntry
	for _, in := range [][3]string{
		{"1700000060.0:e88956c6b85d793a9c3e20025fbe965ef1ffb7c0e11b531d9044af68dcd8039e", "claim-next", "mac-mini-1"},
		{"1700000060.0:e88956c6b85d793a9c3e20025fbe965ef1ffb7c0e11b531d9044af68dcd8039e", "job-7f3a", "worker.a_b-2"},
		{"1700000060.0:9721bb7b2318ec162bd256ddf121bba04b25e9fdbf6c707bebb625333520016c", "j\u00f6b-\U0001F600", "n"},
	} {
		p := wire.SigningPayload(in[0], in[1], in[2])
		sig, err := wire.Sign(key, p)
		if err != nil {
			t.Fatal(err)
		}
		cross = append(cross, conformance.SignedEntry{
			PayloadHex: hex.EncodeToString(p), PublicKeyPEM: pemStr, SignatureB64: sig})
	}
	setGoSigned(t, "ecdsa_cross.json", cross)

	// renew_proof.json: the proof of possession exactly as Client.Renew signs it.
	type renewEntry struct {
		NodeID       string `json:"node_id"`
		CSRPEM       string `json:"csr_pem"`
		IssuedAt     int64  `json:"issued_at"`
		PayloadHex   string `json:"payload_hex"`
		PublicKeyPEM string `json:"public_key_pem"`
		SignatureB64 string `json:"signature_b64"`
	}
	var renew []renewEntry
	for _, in := range []struct {
		node, csr string
		at        int64
	}{
		{"node-v2", "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n", 1700000000},
		{"mac-mini-1", "-----BEGIN CERTIFICATE REQUEST-----\r\nAAAA\r\n-----END CERTIFICATE REQUEST-----\r\n", 0},
		{"worker.a_b-2", "x\u00e9\U0001F600", 4102444800},
	} {
		p := wire.RenewPayload(in.node, in.csr, in.at)
		sig, err := wire.Sign(key, p)
		if err != nil {
			t.Fatal(err)
		}
		renew = append(renew, renewEntry{NodeID: in.node, CSRPEM: in.csr, IssuedAt: in.at,
			PayloadHex: hex.EncodeToString(p), PublicKeyPEM: pemStr, SignatureB64: sig})
	}
	setGoSigned(t, "renew_proof.json", renew)
	t.Log("wrote go_signed; refresh SHA256SUMS with: .venv/bin/python scripts/gen_conformance.py")
}

// setGoSigned replaces rel's go_signed list and rewrites the file exactly as the generator's
// _dumps does (indent 2, sorted keys, ASCII-only), so every other entry keeps its bytes.
func setGoSigned(t *testing.T, rel string, goSigned any) {
	t.Helper()
	raw, err := os.ReadFile(conformance.Path(rel))
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic map[string]any
	if err := dec.Decode(&generic); err != nil {
		t.Fatal(err)
	}
	// Through a generic value so the entries' keys come out sorted, as sort_keys does.
	gs, err := json.Marshal(goSigned)
	if err != nil {
		t.Fatal(err)
	}
	var entries []any
	if err := json.Unmarshal(gs, &entries); err != nil {
		t.Fatal(err)
	}
	generic["go_signed"] = entries
	out := pyDumps(t, generic)
	if err := os.WriteFile(conformance.Path(rel), out, 0o644); err != nil {
		t.Fatal(err)
	}
	// Everything but go_signed must round-trip to the same bytes.
	delete(generic, "go_signed")
	var orig map[string]any
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	_ = dec.Decode(&orig)
	delete(orig, "go_signed")
	orig["go_signed"], generic["go_signed"] = []any{}, []any{}
	if !bytes.Equal(pyDumps(t, orig), pyDumps(t, generic)) {
		t.Fatalf("%s: rewriting changed entries other than go_signed", rel)
	}
}

// pyDumps is json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + "\n".
func pyDumps(t *testing.T, doc any) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	for _, r := range buf.String() {
		switch {
		case r < 0x80:
			out.WriteRune(r)
		case r > 0xffff:
			r -= 0x10000
			fmt.Fprintf(&out, "\\u%04x\\u%04x", 0xd800+(r>>10), 0xdc00+(r&0x3ff))
		default:
			fmt.Fprintf(&out, "\\u%04x", r)
		}
	}
	return []byte(out.String())
}

func TestSignRefusesNonP256(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := wire.Sign(k, []byte("x")); err == nil {
		t.Fatal("P-384 key accepted")
	}
	if _, err := wire.Sign(nil, []byte("x")); err == nil {
		t.Fatal("nil key accepted")
	}
}

func TestRenewPayloadBytes(t *testing.T) {
	csr := "-----BEGIN CERTIFICATE REQUEST-----\nabc\n-----END CERTIFICATE REQUEST-----\n"
	sum := sha256.Sum256([]byte(csr))
	want := "blastbox/node-renew/v1\x00node-a\x00" + hex.EncodeToString(sum[:]) + "\x001700000123"
	if got := string(wire.RenewPayload("node-a", csr, 1700000123)); got != want {
		t.Fatalf("payload %q, want %q", got, want)
	}
	// hex is lowercase and 64 chars.
	if h := hex.EncodeToString(sum[:]); len(h) != 64 || h != strings.ToLower(h) {
		t.Fatal(h)
	}
}

// renew_proof.json: every payload case and signed entry must be RenewPayload of its own inputs,
// python_signed verdicts follow "valid" (absent = true), and go_signed entries all verify.
func TestRenewProofVectors(t *testing.T) {
	type entry struct {
		NodeID     string `json:"node_id"`
		CSRPEM     string `json:"csr_pem"`
		IssuedAt   int64  `json:"issued_at"`
		PayloadHex string `json:"payload_hex"`
		conformance.SignedEntry
	}
	var f struct {
		Domain       string  `json:"domain"`
		PayloadCases []entry `json:"payload_cases"`
		PythonSigned []entry `json:"python_signed"`
		GoSigned     []entry `json:"go_signed"`
	}
	if err := conformance.ReadJSON("renew_proof.json", &f); err != nil {
		t.Fatal(err)
	}
	if f.Domain != "blastbox/node-renew/v1" {
		t.Fatalf("domain %q", f.Domain)
	}
	if len(f.PayloadCases) == 0 || len(f.PythonSigned) == 0 {
		t.Fatalf("payload_cases=%d python_signed=%d: both must be non-empty",
			len(f.PayloadCases), len(f.PythonSigned))
	}
	check := func(list string, es []entry, signed bool) (valid, invalid int) {
		for i, e := range es {
			p := wire.RenewPayload(e.NodeID, e.CSRPEM, e.IssuedAt)
			if got := hex.EncodeToString(p); got != e.PayloadHex {
				t.Errorf("%s[%d]: payload %s, want %s", list, i, got, e.PayloadHex)
			}
			if !signed {
				continue
			}
			want := e.Valid == nil || *e.Valid
			if got := wire.Verify(parsePub(t, e.PublicKeyPEM), p, e.SignatureB64); got != want {
				t.Errorf("%s[%d]: verify=%v, want %v", list, i, got, want)
			}
			if want {
				valid++
				if wire.Verify(parsePub(t, e.PublicKeyPEM), append(p, 'x'), e.SignatureB64) {
					t.Errorf("%s[%d] verifies a tampered payload", list, i)
				}
			} else {
				invalid++
			}
		}
		return
	}
	check("payload_cases", f.PayloadCases, false)
	if v, n := check("python_signed", f.PythonSigned, true); v == 0 || n == 0 {
		t.Errorf("python_signed: %d valid, %d negative; want both", v, n)
	}
	if _, n := check("go_signed", f.GoSigned, true); n != 0 {
		t.Errorf("go_signed has %d negative entries", n)
	}
	if len(f.GoSigned) == 0 {
		t.Error("go_signed empty: run go test ./internal/wire -run TestUpdateGoSigned -update-go-signed")
	}
}
