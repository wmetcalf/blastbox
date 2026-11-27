package config_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"os"
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
	for _, n := range []string{"wrong_eku", "client_auth_eku", "cn_mismatch", "expired", "missing_node_info",
		"garbled_node_info", "unsupported_version", "foreign_ca", "rsa_key", "v1_with_wg", "v2_without_wg"} {
		if !seen[n] {
			t.Errorf("vector %s not exercised", n)
		}
	}
}

func TestCheckNodeCertExpiryUsesNow(t *testing.T) {
	var cc conformance.CertCases
	_ = conformance.ReadJSON("node_certs/cases.json", &cc)
	ca, _ := os.ReadFile(conformance.Path("node_certs", cc.CA))
	crt, _ := os.ReadFile(conformance.Path("node_certs", "v1_with_wg.crt"))
	if _, _, err := config.CheckNodeCert(crt, ca, time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("cert accepted far past its notAfter")
	}
	if _, _, err := config.CheckNodeCert([]byte("junk"), ca, time.Now()); err == nil {
		t.Fatal("junk accepted")
	}
}
