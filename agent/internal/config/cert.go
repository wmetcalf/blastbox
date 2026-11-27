package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"time"
)

var (
	oidNodeInfo = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}
	oidNodeAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 2}
	oidEKU      = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidCN       = asn1.ObjectIdentifier{2, 5, 4, 3}
	nodeIDRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
)

// CheckNodeCert is the agent's pre-flight check of its own certificate, mirroring the
// dispatcher's admission (pki.node_identity + admit_identity). It is intentionally at least
// as strict: any cert Python refuses is refused here, and so is a cert carrying clientAuth
// or serverAuth alongside the node EKU.
func CheckNodeCert(certPEM, caPEM []byte, now time.Time) (nodeID string, notAfter time.Time, err error) {
	blk, _ := pem.Decode(certPEM)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return "", time.Time{}, errors.New("node cert: no CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("node cert: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return "", time.Time{}, errors.New("CA file holds no certificate")
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return "", time.Time{}, fmt.Errorf("node cert does not verify against the CA: %w", err)
	}
	if now.After(cert.NotAfter) || now.Before(cert.NotBefore) {
		return "", time.Time{}, errors.New("node cert is outside its validity window")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return "", time.Time{}, errors.New("node cert key must be ECDSA P-256")
	}
	hasNode := false
	for _, o := range cert.UnknownExtKeyUsage {
		if o.Equal(oidNodeAuth) {
			hasNode = true
		}
	}
	if !hasNode {
		return "", time.Time{}, errors.New("node cert lacks the node EKU")
	}
	for _, u := range cert.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth || u == x509.ExtKeyUsageServerAuth || u == x509.ExtKeyUsageAny {
			return "", time.Time{}, errors.New("node cert must not carry clientAuth/serverAuth/anyEKU")
		}
	}
	var infoRaw []byte
	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(oidEKU) && !ext.Critical:
			return "", time.Time{}, errors.New("node cert EKU must be critical")
		case ext.Id.Equal(oidNodeInfo):
			infoRaw = ext.Value
		}
	}
	if infoRaw == nil {
		return "", time.Time{}, errors.New("node cert has no node-info extension")
	}
	var info struct {
		V      int    `json:"v"`
		NodeID string `json:"node_id"`
	}
	if err := json.Unmarshal(infoRaw, &info); err != nil {
		return "", time.Time{}, fmt.Errorf("node-info is not valid JSON: %w", err)
	}
	if info.V != 1 && info.V != 2 {
		return "", time.Time{}, fmt.Errorf("unsupported node-info version %d", info.V)
	}
	if !nodeIDRE.MatchString(info.NodeID) {
		return "", time.Time{}, fmt.Errorf("node-info node_id %q is not a valid node id", info.NodeID)
	}
	var cns []string
	for _, atv := range cert.Subject.Names {
		if atv.Type.Equal(oidCN) {
			s, _ := atv.Value.(string)
			cns = append(cns, s)
		}
	}
	if len(cns) != 1 || cns[0] != info.NodeID {
		return "", time.Time{}, errors.New("subject must carry exactly one CN, equal to node-info node_id")
	}
	return info.NodeID, cert.NotAfter, nil
}
