package wire

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

const maxKeyFile = 16 << 10

// LoadKey reads a node private key. The file is opened with O_NOFOLLOW (a symlinked key is
// refused). PKCS#8 ("PRIVATE KEY") is what blastbox's pki writes; SEC1 ("EC PRIVATE KEY") is
// accepted too. Only ECDSA P-256 is accepted.
func LoadKey(path string) (*ecdsa.PrivateKey, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("node key: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return nil, fmt.Errorf("node key: %w", err)
	}
	if len(raw) > maxKeyFile {
		return nil, errors.New("node key: file too large")
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, errors.New("node key: no PEM block")
	}
	var key *ecdsa.PrivateKey
	switch blk.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, errors.New("node key: unparseable PKCS#8")
		}
		ek, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("node key: must be ECDSA P-256")
		}
		key = ek
	case "EC PRIVATE KEY":
		ek, err := x509.ParseECPrivateKey(blk.Bytes)
		if err != nil {
			return nil, errors.New("node key: unparseable SEC1 key")
		}
		key = ek
	default:
		return nil, fmt.Errorf("node key: unsupported PEM type %q", blk.Type)
	}
	if key.Curve != elliptic.P256() {
		return nil, errors.New("node key: must be ECDSA P-256")
	}
	return key, nil
}
