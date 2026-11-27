package wire_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"os"
	"testing"

	"github.com/wmetcalf/blastbox/agent/internal/conformance"
	"github.com/wmetcalf/blastbox/agent/internal/wire"
)

var updateGoSigned = flag.Bool("update-go-signed", false,
	"append go_signed entries to conformance/v1/ecdsa_cross.json and refresh SHA256SUMS")

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
		if !wire.Verify(parsePub(t, e.PublicKeyPEM), payload, e.SignatureB64) {
			t.Errorf("python_signed[%d] does not verify", i)
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
	var f conformance.CrossFile
	if err := conformance.ReadJSON("ecdsa_cross.json", &f); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	f.GoSigned = nil
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
		f.GoSigned = append(f.GoSigned, conformance.SignedEntry{
			PayloadHex: hex.EncodeToString(p), PublicKeyPEM: pemStr, SignatureB64: sig})
	}
	// Same formatting as the generator's _dumps (indent=2, sorted keys, ASCII-only content).
	raw, err := os.ReadFile(conformance.Path("ecdsa_cross.json"))
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	generic["go_signed"] = f.GoSigned
	enc, err := json.MarshalIndent(generic, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(conformance.Path("ecdsa_cross.json"), append(enc, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Log("wrote go_signed; refresh SHA256SUMS with: python3 scripts/gen_conformance.py")
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
