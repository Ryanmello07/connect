// The RFC 9180 base mode corpus this package is held to, and the loader that is the one
// way into it.
//
// The values were transcribed by hand into this package before this file existed, because
// tasks 5 to 8 had to verify themselves before there was a corpus to verify against. Two
// corpora that are meant to agree, with nothing asserting that they do, is how they drift,
// so the transcriptions are gone and this file is what remains. The commit that added it
// carried a bridge test asserting the two agreed on all 94 published values they shared;
// that agreement is why the vendored file is trusted here, since a file fetched from a url
// proves nothing about itself beyond its own digest.
//
// The corpus is the whole published one rather than the six sequence numbers RFC 9180
// appendix A prints. That is the difference between the transcription and the file: the
// appendix is a readable excerpt and test-vectors.json is the corpus, so the seal known
// answer now walks 257 sequence numbers per suite where it used to walk six.
//
// Provenance is the part that has to be argued rather than asserted, and interop/PINS.md
// argues it. Both digests there were reproduced from the upstream commit before these
// bytes were written: the upstream file hashes to 61fc662f…, the filtered re-serialization
// hashes to the constant below, the two vendored entries deep-equal the two upstream
// entries the predicate selects, and re-running the transform reproduces these bytes. The
// filter exists because the upstream file is 5.9 MB and 128 entries, 126 of them for
// algorithms this implementation does not have.
//
// Only two entries are vendored and that is a claim about the registry rather than about
// the RFC. RFC 9180 gives HKDF-SHA256 the kdf code point 0x0001 and AES-128-GCM the aead
// code point 0x0001 in two separate registries, so on suite 0x0001 those two positions
// hold the same byte and a transposition between them moves nothing anyone can observe. On
// suite 0x0003 the aead is 0x0003 and the same transposition moves every derived byte. A
// corpus carrying one suite is therefore a corpus that cannot see the mistake hpke.go's
// file comment is about, whichever suite it carries — which is why loadHpkeVectors refuses
// to return anything but one entry per registered suite.
package mls

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// One published encryption, as the upstream file carries it: the message a sender's
// context produces at one sequence number, with the nonce printed beside it.
//
// sequence is not a field of the file. Upstream indexes the encryptions array by sequence
// number and prints no counter, so the loader supplies it from the position and the nonce
// comparison is what holds that reading honest — an off by one between index and sequence
// moves the low byte of every nonce and fails at the first row.
type hpkeVectorEncryption struct {
	Aad   string `json:"aad"`
	Ct    string `json:"ct"`
	Nonce string `json:"nonce"`
	Pt    string `json:"pt"`

	sequence uint64
}

// One published exported value. The length travels with the value rather than being read
// off it, so a corpus that lost a byte fails as a disagreement about a published length
// instead of quietly asserting a shorter export.
type hpkeVectorExport struct {
	ExporterContext string `json:"exporter_context"`
	Length          int    `json:"L"`
	ExportedValue   string `json:"exported_value"`
}

// One base mode entry, with every field a labelled extract or expand, a key pair
// derivation, an encapsulation, a decapsulation, a seal or an export consumes or produces.
//
// name and suite are derived by the loader and are not in the file. The file identifies an
// entry by the kem, kdf and aead code points it was generated for, which is the only
// identification that can be checked against the registry rather than trusted; suite is
// the registry's answer to that triple and name is for the failure messages.
type hpkeVector struct {
	Mode               int                    `json:"mode"`
	KemId              HpkeKemId              `json:"kem_id"`
	KdfId              HpkeKdfId              `json:"kdf_id"`
	AeadId             HpkeAeadId             `json:"aead_id"`
	Info               string                 `json:"info"`
	IkmE               string                 `json:"ikmE"`
	IkmR               string                 `json:"ikmR"`
	SkEm               string                 `json:"skEm"`
	SkRm               string                 `json:"skRm"`
	PkEm               string                 `json:"pkEm"`
	PkRm               string                 `json:"pkRm"`
	Enc                string                 `json:"enc"`
	SharedSecret       string                 `json:"shared_secret"`
	KeyScheduleContext string                 `json:"key_schedule_context"`
	Secret             string                 `json:"secret"`
	Key                string                 `json:"key"`
	BaseNonce          string                 `json:"base_nonce"`
	ExporterSecret     string                 `json:"exporter_secret"`
	Encryptions        []hpkeVectorEncryption `json:"encryptions"`
	Exports            []hpkeVectorExport     `json:"exports"`

	name  string
	suite CipherSuite
}

const hpkeVectorPath = "testdata/vectors/rfc/hpke-rfc9180-x25519.json"

// The digest recorded in interop/PINS.md, where the provenance that makes it worth
// anything is written down. A vector file that changed under us must break the build
// rather than quietly weaken every known answer that reads it.
const hpkeVectorSha256 = "3cc5f951dea0b7dbe80419215e64c810498ee4dd76c376763bbe6860c346b11a"

// The published sequence numbers the corpus has to reach. 255 and 256 are the load bearing
// pair: a counter written little endian, or written at the front of the nonce, agrees with
// a big endian one on every sequence number below 256 and disagrees at exactly the byte
// crossing. A corpus that stopped short of it would leave every nonce known answer passing
// against an implementation that matches nobody.
const hpkeVectorHighestSequence = 256

// The corpus, with every shape assertion the loops that consume it depend on already made.
//
// The assertions live here rather than in the tests because this is the only place that
// can make them once for all of them. A table that lost a row is not an empty table, and
// only the empty case was ever refused — so until the count was checked, dropping either
// entry left every known answer in the package green. The same is true of the encryptions
// and the exports: a loop over an empty slice reports success, so a corpus stripped to its
// key schedule would satisfy the seal and export known answers by never running them.
func loadHpkeVectors(t *testing.T) []hpkeVector {
	t.Helper()
	raw, err := os.ReadFile(hpkeVectorPath)
	if err != nil {
		t.Fatalf("read %s: %v", hpkeVectorPath, err)
	}
	digest := sha256.Sum256(raw)
	if got := hex.EncodeToString(digest[:]); got != hpkeVectorSha256 {
		t.Fatalf("%s sha256 = %s, want %s (see interop/PINS.md)", hpkeVectorPath, got, hpkeVectorSha256)
	}
	var vectors []hpkeVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse %s: %v", hpkeVectorPath, err)
	}
	suites := Suites()
	if len(vectors) != len(suites) {
		t.Fatalf("%s holds %d vectors for %d registered suites, so a suite goes unpinned",
			hpkeVectorPath, len(vectors), len(suites))
	}
	for i := range vectors {
		params := suiteForHpkeVector(t, vectors[i])
		vectors[i].suite = params.Suite
		vectors[i].name = "rfc 9180 test-vectors.json, mode 0, " + params.Name
		for j := range vectors[i].Encryptions {
			vectors[i].Encryptions[j].sequence = uint64(j)
		}
	}
	slices.SortFunc(vectors, func(a hpkeVector, b hpkeVector) int {
		return int(a.suite) - int(b.suite)
	})
	for i, suite := range suites {
		if vectors[i].suite != suite {
			t.Fatalf("vector %d is for suite %#04x, want %#04x", i, uint16(vectors[i].suite), uint16(suite))
		}
		if got := len(vectors[i].Encryptions); got <= hpkeVectorHighestSequence {
			t.Fatalf("%s carries %d encryptions, so the sequence counter never reaches %d and never crosses a byte",
				vectors[i].name, got, hpkeVectorHighestSequence)
		}
		if len(vectors[i].Exports) == 0 {
			t.Fatalf("%s carries no exported values, so every export known answer would loop over nothing", vectors[i].name)
		}
	}
	return vectors
}

// The registered suite a vector was generated for, refusing anything else. A vector for a
// mode, kem, kdf or aead this package does not implement asserts nothing about it, and
// silently skipping such an entry is how a corpus ends up with two rows and one of them
// tested.
func suiteForHpkeVector(t *testing.T, vector hpkeVector) *SuiteParams {
	t.Helper()
	if vector.Mode != 0 {
		t.Fatalf("vector mode is %d, want 0 (base)", vector.Mode)
	}
	for _, suite := range Suites() {
		params, err := LookupSuite(suite)
		if err != nil {
			t.Fatalf("LookupSuite: %v", err)
		}
		if params.KemId == vector.KemId && params.KdfId == vector.KdfId && params.AeadId == vector.AeadId {
			return params
		}
	}
	t.Fatalf("no registered suite for kem %#04x kdf %#04x aead %#04x", vector.KemId, vector.KdfId, vector.AeadId)
	return nil
}

// TestHpkeVectorFileCarriesTheBytesUpstreamPublished is the provenance check the digest
// pin cannot make on its own. A digest says the file has not moved since the digest was
// taken; it says nothing about what the file was when that happened. This repository has
// already vendored a corpus whose sixteen files were all rewritten by git's autocrlf on
// the way in and whose manifest was then computed over the rewritten bytes, so it verified
// sixteen of sixteen against bytes upstream never published, and only a reviewer who
// fetched upstream and compared noticed.
//
// A carriage return is what that rewrite leaves behind. Upstream publishes this file with
// none anywhere in it, so one appearing here means the bytes were smudged between upstream
// and the index — and the count is reported rather than merely the presence, because a
// single stray one and a wholesale rewrite are different accidents.
// testdata/vectors/rfc/.gitattributes carries the -text that prevents it; this is the
// assertion that notices when it stops working.
func TestHpkeVectorFileCarriesTheBytesUpstreamPublished(t *testing.T) {
	raw, err := os.ReadFile(hpkeVectorPath)
	if err != nil {
		t.Fatalf("read %s: %v", hpkeVectorPath, err)
	}
	if len(raw) == 0 {
		t.Fatalf("%s is empty, so the count below is about nothing", hpkeVectorPath)
	}
	if n := bytes.Count(raw, []byte{'\r'}); n != 0 {
		t.Fatalf("%s carries %d carriage returns; upstream publishes it with none, so these bytes are not the bytes that were fetched",
			hpkeVectorPath, n)
	}
}

// TestHpkeVectorDigestIsRecordedInThePinFile ties the constant to the one pin file. The
// constant's own comment says the digest is recorded in interop/PINS.md, and until this
// existed nothing held it to that: re-vendoring at a newer upstream commit and updating
// only the constant would leave the pin file describing a file that is no longer there,
// with every test still green. The provenance claim is what is being protected, and a
// provenance claim nobody compares is the failure this directory was rebuilt for.
func TestHpkeVectorDigestIsRecordedInThePinFile(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("interop", "PINS.md"))
	if err != nil {
		t.Fatalf("read interop/PINS.md: %v", err)
	}
	text := string(body)
	for _, want := range []string{hpkeVectorSha256, hpkeVectorPath} {
		if !strings.Contains(text, want) {
			t.Errorf("interop/PINS.md does not record %s", want)
		}
	}
}

// TestHpkeVectorCorpusIsTheWholePublishedCorpus states the shape every known answer in
// this package relies on, as a test of its own rather than only as a precondition inside
// the loader. The loader's assertions run whenever a test loads the corpus, but they read
// as plumbing; a reader asking what the corpus is supposed to contain should not have to
// infer it from a helper's fatal calls.
//
// The counts are exact rather than lower bounds. A corpus that grew an entry is a corpus
// somebody re-vendored under a different filter, and the right response is a failure that
// says so rather than a loop that quietly covers more or less than the pin file claims.
func TestHpkeVectorCorpusIsTheWholePublishedCorpus(t *testing.T) {
	vectors := loadHpkeVectors(t)
	if len(vectors) != 2 {
		t.Fatalf("the corpus holds %d entries, want 2", len(vectors))
	}
	for _, vector := range vectors {
		if got := len(vector.Encryptions); got != hpkeVectorHighestSequence+1 {
			t.Errorf("%s carries %d encryptions, want %d", vector.name, got, hpkeVectorHighestSequence+1)
		}
		if got := len(vector.Exports); got != 3 {
			t.Errorf("%s carries %d exported values, want 3", vector.name, got)
		}
		if vector.KemId != HpkeKemX25519HkdfSha256 || vector.KdfId != HpkeKdfHkdfSha256 {
			t.Errorf("%s is for kem %#04x kdf %#04x, want %#04x and %#04x",
				vector.name, vector.KemId, vector.KdfId, HpkeKemX25519HkdfSha256, HpkeKdfHkdfSha256)
		}
	}
	// the two entries have to differ in their aead, since that is the only position where
	// the 0x0001 kdf and aead collision is visible at all
	if vectors[0].AeadId == vectors[1].AeadId {
		t.Fatalf("both entries are for aead %#04x, so the kdf and aead positions can be transposed unobserved", vectors[0].AeadId)
	}
}

// TestHpkeVectorEncapsulatedKeyIsTheEphemeralPublicKey states what RFC 9180 section 4.1
// means by enc for a DHKEM: SerializePublicKey(pkE) and nothing else. The corpus publishes
// pkEm and enc as separate fields and the key derivation known answer compares the derived
// ephemeral public key against one of them, so without this the other is never read and a
// corpus whose two fields disagreed would go unnoticed.
//
// It is also the only thing in this package that says the encapsulated key is a public key
// rather than an opaque kem output. Both are 32 bytes here, so no length can say it.
func TestHpkeVectorEncapsulatedKeyIsTheEphemeralPublicKey(t *testing.T) {
	for _, vector := range loadHpkeVectors(t) {
		pkEm := decodeVectorField(t, vector.name, "pkEm", vector.PkEm)
		enc := decodeVectorField(t, vector.name, "enc", vector.Enc)
		if !bytes.Equal(pkEm, enc) {
			t.Errorf("%s: pkEm = %x but enc = %x, and RFC 9180 section 4.1 makes them the same bytes",
				vector.name, pkEm, enc)
		}
	}
}
