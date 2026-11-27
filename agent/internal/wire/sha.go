package wire

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
)

type shaw struct{ hash.Hash }

func newSHA() shaw         { return shaw{sha256.New()} }
func (s shaw) sum() string { return hex.EncodeToString(s.Sum(nil)) }
