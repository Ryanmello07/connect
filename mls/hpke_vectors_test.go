// the RFC 9180 base-mode vectors, both suites we instantiate.
//
// these drive production code: encapsulation runs through hpkeEncapDeterministic
// with the vector's own ephemeral key, so a passing run means the shipped Encap is
// right rather than that a test reimplemented it.
package mls

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type hpkeVectorEncryption struct {
	Aad   string `json:"aad"`
	Ct    string `json:"ct"`
	Nonce string `json:"nonce"`
	Pt    string `json:"pt"`
}

type hpkeVectorExport struct {
	ExporterContext string `json:"exporter_context"`
	Length          int    `json:"L"`
	ExportedValue   string `json:"exported_value"`
}

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
}

const hpkeVectorPath = "testdata/vectors/rfc/hpke-rfc9180-x25519.json"

// the digest recorded in interop/PINS.md. a vector file that changed under us must
// break the build, not quietly weaken the gate.
const hpkeVectorSha256 = "3cc5f951dea0b7dbe80419215e64c810498ee4dd76c376763bbe6860c346b11a"

// TestHpkeVectorFileCarriesTheBytesUpstreamPublished is the provenance check the digest
// pin above cannot make on its own. A digest says the file has not moved since the digest
// was taken; it says nothing about what the file was when that happened. This repository
// has already vendored a corpus whose sixteen files were all rewritten by git's autocrlf
// on the way in and whose manifest was then computed over the rewritten bytes, so it
// verified sixteen of sixteen against bytes upstream never published, and only a reviewer
// who fetched upstream and compared noticed.
//
// A carriage return is what that rewrite leaves behind. Upstream publishes this file with
// no CR byte anywhere in it, so one appearing here means the bytes were smudged between
// upstream and the index — and the count is asserted rather than the presence, so the
// message names how badly. testdata/vectors/rfc/.gitattributes carries the -text that
// prevents it; this is the assertion that notices when it stops working.
func TestHpkeVectorFileCarriesTheBytesUpstreamPublished(t *testing.T) {
	raw, err := os.ReadFile(hpkeVectorPath)
	if err != nil {
		t.Fatalf("read %s: %v", hpkeVectorPath, err)
	}
	if len(raw) == 0 {
		t.Fatalf("%s is empty, so the count below is about nothing", hpkeVectorPath)
	}
	if n := bytes.Count(raw, []byte{'\r'}); n != 0 {
		t.Fatalf("%s carries %d carriage returns; upstream publishes it with none, so these bytes are not the bytes that were fetched", hpkeVectorPath, n)
	}
}

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
	if len(vectors) != 2 {
		t.Fatalf("%s has %d vectors, want 2", hpkeVectorPath, len(vectors))
	}
	return vectors
}

// TestHpkeVectorDigestIsRecordedInThePinFile ties the constant above to the one pin file.
// The constant's own comment says the digest is recorded in interop/PINS.md, and until this
// existed nothing held it to that: re-vendoring at a newer upstream commit and updating only
// the constant would have left the pin file describing a file that is no longer there, with
// every test still green. The provenance claim is the thing being protected here, and a
// provenance claim nobody compares is the failure mode this whole directory was rebuilt for.
func TestHpkeVectorDigestIsRecordedInThePinFile(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("interop", "PINS.md"))
	if err != nil {
		t.Fatalf("read interop/PINS.md: %v", err)
	}
	if !strings.Contains(string(body), hpkeVectorSha256) {
		t.Errorf("interop/PINS.md does not record the vendored digest %s", hpkeVectorSha256)
	}
	if !strings.Contains(string(body), hpkeVectorPath) {
		t.Errorf("interop/PINS.md does not name %s", hpkeVectorPath)
	}
}

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

func TestHpkeVectorDeriveKeyPair(t *testing.T) {
	for _, vector := range loadHpkeVectors(t) {
		params := suiteForHpkeVector(t, vector)
		privE, pubE, err := HpkeDeriveKeyPair(params, decodeVectorField(t, "vector", "ikmE", vector.IkmE))
		if err != nil {
			t.Fatalf("derive e: %v", err)
		}
		if !bytes.Equal(privE, decodeVectorField(t, "vector", "skEm", vector.SkEm)) {
			t.Errorf("aead %#04x: skEm = %x, want %s", vector.AeadId, privE, vector.SkEm)
		}
		if !bytes.Equal(pubE, decodeVectorField(t, "vector", "pkEm", vector.PkEm)) {
			t.Errorf("aead %#04x: pkEm = %x, want %s", vector.AeadId, pubE, vector.PkEm)
		}
		privR, pubR, err := HpkeDeriveKeyPair(params, decodeVectorField(t, "vector", "ikmR", vector.IkmR))
		if err != nil {
			t.Fatalf("derive r: %v", err)
		}
		if !bytes.Equal(privR, decodeVectorField(t, "vector", "skRm", vector.SkRm)) {
			t.Errorf("aead %#04x: skRm = %x, want %s", vector.AeadId, privR, vector.SkRm)
		}
		if !bytes.Equal(pubR, decodeVectorField(t, "vector", "pkRm", vector.PkRm)) {
			t.Errorf("aead %#04x: pkRm = %x, want %s", vector.AeadId, pubR, vector.PkRm)
		}
	}
}

func TestHpkeVectorEncapAndDecap(t *testing.T) {
	for _, vector := range loadHpkeVectors(t) {
		params := suiteForHpkeVector(t, vector)
		sharedSecret, kemOutput, err := hpkeEncapDeterministic(params,
			HpkePublicKey(decodeVectorField(t, "vector", "pkRm", vector.PkRm)),
			HpkePrivateKey(decodeVectorField(t, "vector", "skEm", vector.SkEm)))
		if err != nil {
			t.Fatalf("encap: %v", err)
		}
		if !bytes.Equal(kemOutput, decodeVectorField(t, "vector", "enc", vector.Enc)) {
			t.Errorf("aead %#04x: enc = %x, want %s", vector.AeadId, kemOutput, vector.Enc)
		}
		if !bytes.Equal(sharedSecret, decodeVectorField(t, "vector", "shared_secret", vector.SharedSecret)) {
			t.Errorf("aead %#04x: shared_secret = %x, want %s", vector.AeadId, sharedSecret, vector.SharedSecret)
		}
		back, err := hpkeDecap(params, HpkePrivateKey(decodeVectorField(t, "vector", "skRm", vector.SkRm)),
			decodeVectorField(t, "vector", "enc", vector.Enc))
		if err != nil {
			t.Fatalf("decap: %v", err)
		}
		if !bytes.Equal(back, decodeVectorField(t, "vector", "shared_secret", vector.SharedSecret)) {
			t.Errorf("aead %#04x: decap shared_secret = %x, want %s", vector.AeadId, back, vector.SharedSecret)
		}
	}
}

func TestHpkeVectorKeySchedule(t *testing.T) {
	for _, vector := range loadHpkeVectors(t) {
		params := suiteForHpkeVector(t, vector)
		ctx, err := hpkeKeySchedule(params, decodeVectorField(t, "vector", "shared_secret", vector.SharedSecret),
			decodeVectorField(t, "vector", "info", vector.Info))
		if err != nil {
			t.Fatalf("key schedule: %v", err)
		}
		if !bytes.Equal(ctx.baseNonce, decodeVectorField(t, "vector", "base_nonce", vector.BaseNonce)) {
			t.Errorf("aead %#04x: base_nonce = %x, want %s", vector.AeadId, ctx.baseNonce, vector.BaseNonce)
		}
		if !bytes.Equal(ctx.exporterSecret, decodeVectorField(t, "vector", "exporter_secret", vector.ExporterSecret)) {
			t.Errorf("aead %#04x: exporter_secret = %x, want %s", vector.AeadId, ctx.exporterSecret, vector.ExporterSecret)
		}
	}
}

func TestHpkeVectorEncryptions(t *testing.T) {
	// the vector's encryptions are indexed by sequence number, which is exactly the
	// context's own counter, so this walks the nonce derivation as well as the aead.
	for _, vector := range loadHpkeVectors(t) {
		params := suiteForHpkeVector(t, vector)
		sender, err := hpkeKeySchedule(params, decodeVectorField(t, "vector", "shared_secret", vector.SharedSecret),
			decodeVectorField(t, "vector", "info", vector.Info))
		if err != nil {
			t.Fatalf("key schedule: %v", err)
		}
		for i, encryption := range vector.Encryptions {
			nonce := sender.nonce()
			if !bytes.Equal(nonce, decodeVectorField(t, "vector", "nonce", encryption.Nonce)) {
				t.Fatalf("aead %#04x seq %d: nonce = %x, want %s", vector.AeadId, i, nonce, encryption.Nonce)
			}
			ciphertext, err := sender.Seal(decodeVectorField(t, "vector", "aad", encryption.Aad),
				decodeVectorField(t, "vector", "pt", encryption.Pt))
			if err != nil {
				t.Fatalf("seal %d: %v", i, err)
			}
			if !bytes.Equal(ciphertext, decodeVectorField(t, "vector", "ct", encryption.Ct)) {
				t.Fatalf("aead %#04x seq %d: ct = %x, want %s", vector.AeadId, i, ciphertext, encryption.Ct)
			}
		}
	}
}

func TestHpkeVectorExports(t *testing.T) {
	for _, vector := range loadHpkeVectors(t) {
		params := suiteForHpkeVector(t, vector)
		ctx, err := hpkeKeySchedule(params, decodeVectorField(t, "vector", "shared_secret", vector.SharedSecret),
			decodeVectorField(t, "vector", "info", vector.Info))
		if err != nil {
			t.Fatalf("key schedule: %v", err)
		}
		for i, export := range vector.Exports {
			got, err := ctx.Export(decodePossiblyEmptyVectorField(t, "vector", "exporter_context", export.ExporterContext), export.Length)
			if err != nil {
				t.Fatalf("export %d: %v", i, err)
			}
			if !bytes.Equal(got, decodeVectorField(t, "vector", "exported_value", export.ExportedValue)) {
				t.Errorf("aead %#04x export %d = %x, want %s", vector.AeadId, i, got, export.ExportedValue)
			}
		}
	}
}

// TestVendoredVectorsMatchTheInlineTranscriptions is the bridge between the two corpora
// and it exists only for the length of this task's own commit. Tasks 5 and 6 built
// rfc9180BaseVectors by three independent routes that agree — hand transcription from
// the RFC 9180 appendix A text, the pinned toolchain's own vendored cfrg corpus at
// GOROOT/src/crypto/hpke/testdata/rfc9180.json, and a direct read of the RFC — and the
// vendored file arrives by a fourth. Replacing the table without comparing the two would
// discard that agreement and leave the new corpus resting on nothing but its own digest,
// which is what a file fetched from a url proves about itself and nothing more.
//
// It compares decoded bytes rather than the hex text, since a value that differs only in
// case is the same published value and a spelling disagreement is not the claim here.
//
// Every count is asserted before the comparison. A bridge that walked an empty table, or
// a table whose rows failed to match a suite, would report agreement between the vendored
// corpus and nothing at all — which is the exact shape of the vacuous pass this project
// has paid for twice.
func TestVendoredVectorsMatchTheInlineTranscriptions(t *testing.T) {
	vendored := map[CipherSuite]hpkeVector{}
	for _, vector := range loadHpkeVectors(t) {
		vendored[suiteForHpkeVector(t, vector).Suite] = vector
	}
	if len(vendored) != 2 {
		t.Fatalf("the vendored corpus resolved to %d suites, want 2", len(vendored))
	}
	if len(rfc9180BaseVectors) != 2 {
		t.Fatalf("the inline table holds %d rows, want 2", len(rfc9180BaseVectors))
	}
	compared := 0
	for _, inline := range rfc9180BaseVectors {
		vector, ok := vendored[inline.suite]
		if !ok {
			t.Fatalf("%s: the vendored corpus has no entry for suite %#04x", inline.name, uint16(inline.suite))
		}
		fields := []struct {
			field    string
			inline   string
			vendored string
		}{
			{field: "info", inline: inline.info, vendored: vector.Info},
			{field: "ikmE", inline: inline.ikmE, vendored: vector.IkmE},
			{field: "skEm", inline: inline.skEm, vendored: vector.SkEm},
			{field: "ikmR", inline: inline.ikmR, vendored: vector.IkmR},
			{field: "skRm", inline: inline.skRm, vendored: vector.SkRm},
			{field: "pkRm", inline: inline.pkRm, vendored: vector.PkRm},
			{field: "enc", inline: inline.enc, vendored: vector.Enc},
			{field: "pkEm", inline: inline.enc, vendored: vector.PkEm},
			{field: "shared_secret", inline: inline.sharedSecret, vendored: vector.SharedSecret},
			{field: "key_schedule_context", inline: inline.keyScheduleContext, vendored: vector.KeyScheduleContext},
			{field: "secret", inline: inline.secret, vendored: vector.Secret},
			{field: "key", inline: inline.key, vendored: vector.Key},
			{field: "base_nonce", inline: inline.baseNonce, vendored: vector.BaseNonce},
			{field: "exporter_secret", inline: inline.exporterSecret, vendored: vector.ExporterSecret},
		}
		for _, field := range fields {
			want := decodeVectorField(t, inline.name, field.field, field.inline)
			got := decodeVectorField(t, inline.name, field.field, field.vendored)
			if !bytes.Equal(got, want) {
				t.Errorf("%s: vendored %s = %x, the inline transcription says %x", inline.name, field.field, got, want)
			}
			compared++
		}
		if len(inline.encryptions) != 6 {
			t.Fatalf("%s: the inline table holds %d encryptions, want the six the appendix prints", inline.name, len(inline.encryptions))
		}
		for _, encryption := range inline.encryptions {
			if encryption.sequence >= uint64(len(vector.Encryptions)) {
				t.Fatalf("%s: the vendored corpus stops before sequence %d", inline.name, encryption.sequence)
			}
			published := vector.Encryptions[encryption.sequence]
			rows := []struct {
				field    string
				inline   string
				vendored string
			}{
				{field: "pt", inline: encryption.pt, vendored: published.Pt},
				{field: "aad", inline: encryption.aad, vendored: published.Aad},
				{field: "nonce", inline: encryption.nonce, vendored: published.Nonce},
				{field: "ct", inline: encryption.ct, vendored: published.Ct},
			}
			for _, row := range rows {
				want := decodeVectorField(t, inline.name, row.field, row.inline)
				got := decodeVectorField(t, inline.name, row.field, row.vendored)
				if !bytes.Equal(got, want) {
					t.Errorf("%s: vendored %s at sequence %d = %x, the inline transcription says %x",
						inline.name, row.field, encryption.sequence, got, want)
				}
				compared++
			}
		}
		if len(inline.exports) != len(vector.Exports) {
			t.Fatalf("%s: the inline table holds %d exports and the vendored corpus %d",
				inline.name, len(inline.exports), len(vector.Exports))
		}
		for i, export := range inline.exports {
			published := vector.Exports[i]
			if export.length != published.Length {
				t.Errorf("%s: vendored export %d is %d bytes, the inline transcription says %d",
					inline.name, i, published.Length, export.length)
			}
			want := decodePossiblyEmptyVectorField(t, inline.name, "exporter_context", export.exporterContext)
			got := decodePossiblyEmptyVectorField(t, inline.name, "exporter_context", published.ExporterContext)
			if !bytes.Equal(got, want) {
				t.Errorf("%s: vendored exporter_context %d = %x, the inline transcription says %x", inline.name, i, got, want)
			}
			wantValue := decodeVectorField(t, inline.name, "exported_value", export.value)
			gotValue := decodeVectorField(t, inline.name, "exported_value", published.ExportedValue)
			if !bytes.Equal(gotValue, wantValue) {
				t.Errorf("%s: vendored exported_value %d = %x, the inline transcription says %x", inline.name, i, gotValue, wantValue)
			}
			compared += 3
		}
	}
	if compared != 94 {
		t.Fatalf("the bridge compared %d published values, want 94", compared)
	}
	t.Logf("the vendored corpus agrees with the inline transcriptions on all %d published values", compared)
}
