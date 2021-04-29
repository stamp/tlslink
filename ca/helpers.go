package ca

import (
	"crypto/sha1"
	"math/big"
)

func bigIntHash(n *big.Int) []byte {
	h := sha1.New()
	h.Write(n.Bytes())
	return h.Sum(nil)
}
