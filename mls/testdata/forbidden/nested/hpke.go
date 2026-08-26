//go:build ignore

// The second allowed base name, one directory deeper, present for the reason its sibling
// is: with only one twin in the fixture, dropping the other from the allowed list would
// change nothing the control can see.
//
// Under testdata and build constrained out, like every file in this tree.
package nested

import (
	"crypto/hkdf"
	"crypto/sha256"
)

func nestedHpkeExtract(salt []byte, ikm []byte) []byte {
	prk, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		return nil
	}
	return prk
}
