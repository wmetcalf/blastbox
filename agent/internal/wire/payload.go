// Package wire holds the node protocol's byte-level primitives.
package wire

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
)

// sigDomain is the domain-separation prefix (node_auth._SIG_DOMAIN).
const sigDomain = "blastbox/node-claim/v1"

// SigningPayload returns exactly what a node signs: domain, challenge, scope and
// node id joined by NUL bytes.
func SigningPayload(challenge, scope, nodeID string) []byte {
	out := make([]byte, 0, len(sigDomain)+len(challenge)+len(scope)+len(nodeID)+3)
	out = append(out, sigDomain...)
	out = append(out, 0)
	out = append(out, challenge...)
	out = append(out, 0)
	out = append(out, scope...)
	out = append(out, 0)
	out = append(out, nodeID...)
	return out
}

// Sign returns the ECDSA P-256/SHA-256 DER signature of payload, standard base64.
func Sign(key *ecdsa.PrivateKey, payload []byte) (string, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return "", errors.New("wire: signing key must be ECDSA P-256")
	}
	h := sha256.Sum256(payload)
	der, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// Verify checks a base64 DER signature made by Sign (or Python's sign_claim).
func Verify(pub *ecdsa.PublicKey, payload []byte, sigB64 string) bool {
	der, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	h := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(pub, h[:], der)
}

// renewDomain is the domain-separation prefix of the renewal proof of possession.
const renewDomain = "blastbox/node-renew/v1"

// RenewPayload returns what the CURRENT node key signs to renew: domain, node id, lowercase
// hex SHA-256 of the exact csr_pem bytes sent, and decimal issued_at, joined by NUL bytes.
func RenewPayload(nodeID, csrPEM string, issuedAt int64) []byte {
	sum := sha256.Sum256([]byte(csrPEM))
	out := []byte(renewDomain)
	out = append(out, 0)
	out = append(out, nodeID...)
	out = append(out, 0)
	out = append(out, hex.EncodeToString(sum[:])...)
	out = append(out, 0)
	out = strconv.AppendInt(out, issuedAt, 10)
	return out
}
