//go:build ignore

// The second allowed base name for hkdf.Extract, present for the same reason crypto.go
// is: with only one allowed file in the fixture, dropping the other from the gate's
// allowed list would change nothing the control can see.
//
// Under testdata and build constrained out, like every file in this directory.
package forbidden

import (
	"crypto/hkdf"
	"crypto/sha256"
)

func hpkeExtract(salt []byte, ikm []byte) []byte {
	prk, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		return nil
	}
	return prk
}
