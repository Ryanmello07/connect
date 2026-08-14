//go:build ignore

// The allowed half of the hkdf confinement control. crypto.go is one of the two base
// names the gate permits, so this file has to make the call and has to go unreported.
// Without it, "the control reported only violations.go" would mean "nothing else calls
// it" rather than "everything else that calls it is allowed to", and widening the
// allowed list to every file would still pass.
//
// Under testdata and build constrained out, like every file in this directory.
package forbidden

import (
	"crypto/hkdf"
	"crypto/sha256"
)

// Takes (salt, ikm) and swaps at the boundary, which is the whole reason the call is
// confined to two reviewable files.
func cryptoExtract(salt []byte, ikm []byte) []byte {
	prk, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		return nil
	}
	return prk
}
