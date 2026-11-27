// Package wire holds the node protocol's byte-level primitives.
package wire

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
