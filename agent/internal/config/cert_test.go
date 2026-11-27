package config_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wmetcalf/blastbox/agent/internal/config"
	"github.com/wmetcalf/blastbox/agent/internal/conformance"
	"github.com/wmetcalf/blastbox/agent/internal/wire"
)

func TestCheckNodeCertVectors(t *testing.T) {
	var cc conformance.CertCases
	if err := conformance.ReadJSON("node_certs/cases.json", &cc); err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339, cc.Now)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(conformance.Path("node_certs", cc.CA))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range cc.Cases {
		certPEM, err := os.ReadFile(conformance.Path("node_certs", c.Cert))
		if err != nil {
			t.Fatal(err)
		}
		// The certificate verdict: identity verifies (rsa_key verifies as an identity but
		// admit_identity refuses a non-EC key). v1_wrong_key_signature has a fine cert; only
		// its claim signature is bad.
		pyAccept := c.Verdict == "ok" && c.Name != "rsa_key"
		id, notAfter, err := config.CheckNodeCert(certPEM, ca, now)
		seen[c.Name] = true
		if pyAccept {
			if err != nil {
				t.Errorf("%s: want accept, got %v", c.Name, err)
				continue
			}
			if id != c.NodeID || !notAfter.After(now) {
				t.Errorf("%s: id=%q notAfter=%v", c.Name, id, notAfter)
			}
		} else if err == nil {
			t.Errorf("%s (%s): Python refuses, Go accepted", c.Name, c.Why)
		}
		// The signed admit claim must verify against the cert's key iff Python said ok.
		if c.Admit != nil && pyAccept {
			blk, _ := pem.Decode(certPEM)
			x, _ := x509.ParseCertificate(blk.Bytes)
			pub := x.PublicKey.(*ecdsa.PublicKey)
			p := wire.SigningPayload(c.Admit.Challenge, c.Admit.Scope, c.NodeID)
			if got := wire.Verify(pub, p, c.Admit.SignatureB64); got != (c.Admit.Verdict == "ok") {
				t.Errorf("%s: admit signature verify=%v, vector verdict %q", c.Name, got, c.Admit.Verdict)
			}
		}
	}
	for _, n := range []string{"wrong_eku", "client_auth_eku", "node_plus_client_auth_eku", "cn_mismatch", "expired", "missing_node_info",
		"garbled_node_info", "unsupported_version", "foreign_ca", "rsa_key", "v1_with_wg", "v2_without_wg", "v2_bad_wg", "v1_without_wg"} {
		if !seen[n] {
			t.Errorf("vector %s not exercised", n)
		}
	}
}

func TestCheckNodeCertExpiryUsesNow(t *testing.T) {
	var cc conformance.CertCases
	if err := conformance.ReadJSON("node_certs/cases.json", &cc); err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339, cc.Now)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(conformance.Path("node_certs", cc.CA))
	if err != nil {
		t.Fatal(err)
	}
	crt, err := os.ReadFile(conformance.Path("node_certs", "v1_with_wg.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := config.CheckNodeCert(crt, ca, now); err != nil {
		t.Fatalf("not accepted at the frozen now: %v", err)
	}
	if _, _, err := config.CheckNodeCert(crt, ca, time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("cert accepted far past its notAfter")
	}
	if _, _, err := config.CheckNodeCert([]byte("junk"), ca, now); err == nil {
		t.Fatal("junk accepted")
	}
}

var (
	oidServerAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidClientAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidAnyEKU     = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidNodeEKU    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 2}
)

type certOpts struct {
	ekus       []asn1.ObjectIdentifier
	ekuCrit    bool
	rsaKey     bool
	cns        []string
	infoNodeID string
}

func okOpts() certOpts {
	return certOpts{ekus: []asn1.ObjectIdentifier{oidNodeEKU}, ekuCrit: true, cns: []string{"node-x"}, infoNodeID: "node-x"}
}

// issue builds a CA and a leaf per o; returns leaf PEM, CA PEM and a "now" inside validity.
func issue(t *testing.T, o certOpts) (certPEM, caPEM []byte, now time.Time) {
	t.Helper()
	now = time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour * 24 * 365),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	var pub any
	if o.rsaKey {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		pub = &k.PublicKey
	} else {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub = &k.PublicKey
	}
	var names []pkix.AttributeTypeAndValue
	for _, cn := range o.cns {
		names = append(names, pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: cn})
	}
	ekuDER, err := asn1.Marshal(o.ekus)
	if err != nil {
		t.Fatal(err)
	}
	info := []byte(`{"v":2,"node_id":"` + o.infoNodeID + `","engines":[],"tiers":[],"credentials":false}`)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{ExtraNames: names},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour * 24 * 30),
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: o.ekuCrit, Value: ekuDER},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}, Value: info},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, pub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), now
}

// TestGoOnlyStrictness covers rules where Go is deliberately stricter than (or equal to) Python.
func TestGoOnlyStrictness(t *testing.T) {
	good := okOpts()
	c, ca, now := issue(t, good)
	if id, _, err := config.CheckNodeCert(c, ca, now); err != nil || id != "node-x" {
		t.Fatalf("baseline refused: %v", err)
	}
	mut := func(f func(*certOpts)) certOpts { o := okOpts(); f(&o); return o }
	cases := []struct {
		name string
		o    certOpts
	}{
		{"node EKU + clientAuth", mut(func(o *certOpts) { o.ekus = append(o.ekus, oidClientAuth) })},
		{"node EKU + serverAuth", mut(func(o *certOpts) { o.ekus = append(o.ekus, oidServerAuth) })},
		{"node EKU + anyEKU", mut(func(o *certOpts) { o.ekus = append(o.ekus, oidAnyEKU) })},
		{"non-critical EKU", mut(func(o *certOpts) { o.ekuCrit = false })},
		{"RSA key", mut(func(o *certOpts) { o.rsaKey = true })},
		{"two CNs, first matches", mut(func(o *certOpts) { o.cns = []string{"node-x", "other"} })},
		{"two CNs, second matches", mut(func(o *certOpts) { o.cns = []string{"other", "node-x"} })},
		{"no CN", mut(func(o *certOpts) { o.cns = nil })},
		{"node id uppercase", mut(func(o *certOpts) { o.cns = []string{"Node-X"}; o.infoNodeID = "Node-X" })},
		{"node id leading dash", mut(func(o *certOpts) { o.cns = []string{"-x"}; o.infoNodeID = "-x" })},
		{"node id too long", mut(func(o *certOpts) {
			l := strings.Repeat("a", 64)
			o.cns = []string{l}
			o.infoNodeID = l
		})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, ca, now := issue(t, tc.o)
			if _, _, err := config.CheckNodeCert(c, ca, now); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
