//go:build ignore

// A file whose BASE name is on the hkdf confinement's allowed list and whose PATH is not.
//
// The exemption this controls used to be read off the base name, so a file called
// crypto.go was excused wherever it sat -- in a subpackage, in a subdirectory, anywhere
// under the scanned roots -- and a confined call could be moved into one of those and go
// unreported. The control requires this file to be reported, which is what holds the
// allowed list to being a list of paths rather than a list of names.
//
// Derived rather than written out: the control builds one expected path per entry of the
// allowed list, so an allowed path added without a twin here fails rather than arriving
// uncontrolled.
//
// Under testdata and build constrained out, like every file in this tree.
package nested

import (
	"crypto/hkdf"
	"crypto/sha256"
)

func nestedCryptoExtract(salt []byte, ikm []byte) []byte {
	prk, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		return nil
	}
	return prk
}
