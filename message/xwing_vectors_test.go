// The draft-connolly-cfrg-xwing-kem known answer vectors. MASTER section 7.2 makes passing these
// a precondition of any use of X-Wing, and the reason is that nothing else can hold the
// construction to anything. A KEM that round trips with itself proves only that it agrees with
// itself: the label moved to the front of the combiner, the two shared secrets swapped, ct_X and
// pk_X swapped, the seed expansion taken out of the wrong window -- every one of those still
// produces thirty two bytes and still round trips, because both ends are the same file.
//
// So the vectors are run in BOTH directions and the count that is asserted is the count of
// DISTINCT PUBLISHED ANSWERS the implementation is held against, not the count of calls made.
// This project has already shipped a generate direction that shared its serializer with the
// consume direction and therefore proved nothing; the three directions below share no serializer
// with each other.
//
// keygen, seed -> pk. A full known answer test. It holds the SHAKE-256 expansion, the ML-KEM key
// generation and this package's own pk_M then pk_X encoder against published octets.
//
// decapsulation, (seed, ct) -> ss. A full known answer test, on a ciphertext this package did not
// produce. It transitively pins the ciphertext split, ML-KEM decapsulation, the x25519 dh, and the
// combiner including the label's position. It does NOT read this package's public key encoder,
// which is why it and the keygen direction are independent rather than two readings of one path.
//
// encapsulation, eseed -> ct_X. A full known answer test for the x25519 half.
//
// encapsulation, eseed -> ct_M. NOT REACHABLE. crypto/mlkem's Encapsulate takes no randomness and
// returns no error, so ML-KEM's derandomized encapsulation is not exposed by the standard library.
// It is covered by round trip in xwing_test.go and by the standard library's own FIPS 203 ACVP
// tests. Re-implementing ML-KEM to close that gap would mean shipping new crypto, which the global
// constraints forbid outright.
//
// The gap above is the one place this file cannot hold the draft, and it is stated rather than
// left for a reader to discover by counting.
package message

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/connect/mls"
)

// One vector as the draft's reference implementation publishes it. Every field is hex.
type xwingVector struct {
	Seed  string `json:"seed"`
	Sk    string `json:"sk"`
	Pk    string `json:"pk"`
	Eseed string `json:"eseed"`
	Ct    string `json:"ct"`
	Ss    string `json:"ss"`
}

const (
	xwingVectorPath = "testdata/vectors/rfc/xwing-draft10.json"
	// the attributes file that keeps git's text conversion off the corpus. core.autocrlf is
	// true at system scope on the windows boxes that build this repository, and a smudged
	// vector file verifies against bytes the draft never published.
	xwingVectorAttributesPath = "testdata/vectors/rfc/.gitattributes"
	// the one pin file of the slice, which is mls's rather than this package's
	xwingVectorPinFilePath = "../mls/interop/PINS.md"
)

// The provenance, recorded here and in ../mls/interop/PINS.md, and held to that file field by
// field below. The corpus is vendored whole and unmodified, so the vendored digest and the
// upstream digest are the same value and are named separately anyway: they answer two different
// questions, and a re-vendoring that filtered the file would separate them.
const (
	xwingVectorUpstreamRepository = "dconnolly/draft-connolly-cfrg-xwing-kem"
	xwingVectorUpstreamCommit     = "9b6ce9e614811dba8d46841052f3883cbc4c1a65"
	xwingVectorUpstreamPath       = "spec/test-vectors.json"
	xwingVectorSha256             = "409efe197550b22985b4a0419418a0c5f2c2b193426c55bd998399ec8d3e614d"
	xwingVectorCount              = 3
)

// The raw file, its digest checked before anything parses it.
func loadXwingVectorFile(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(xwingVectorPath)
	if err != nil {
		t.Fatalf("read %s: %v", xwingVectorPath, err)
	}
	digest := sha256.Sum256(raw)
	if got := hex.EncodeToString(digest[:]); got != xwingVectorSha256 {
		t.Fatalf("%s sha256 = %s, want %s (see %s)", xwingVectorPath, got, xwingVectorSha256, xwingVectorPinFilePath)
	}
	return raw
}

func loadXwingVectors(t *testing.T) []xwingVector {
	t.Helper()
	var vectors []xwingVector
	if err := json.Unmarshal(loadXwingVectorFile(t), &vectors); err != nil {
		t.Fatalf("parse %s: %v", xwingVectorPath, err)
	}
	if len(vectors) != xwingVectorCount {
		t.Fatalf("%s has %d vectors, want %d", xwingVectorPath, len(vectors), xwingVectorCount)
	}
	return vectors
}

// The same file read as raw objects, so the FIELDS it publishes are read off the file rather
// than off the struct above. A corpus that grew a seventh field would be silently dropped by the
// struct and the coverage rule below would never notice; read this way it fails.
func loadXwingVectorObjects(t *testing.T) []map[string]string {
	t.Helper()
	var objects []map[string]string
	if err := json.Unmarshal(loadXwingVectorFile(t), &objects); err != nil {
		t.Fatalf("parse %s as objects: %v", xwingVectorPath, err)
	}
	return objects
}

// package message cannot see p8's MustHex: it is declared in mls/vectors_test.go, and a _test.go
// file's symbols are not exported across a package boundary. this is the only hex decoder in the
// slice that is not p8's, and only for that reason.
func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

func TestXwingVectorKeyGen(t *testing.T) {
	for i, vector := range loadXwingVectors(t) {
		seed := mustHexBytes(t, vector.Seed)
		if !bytes.Equal(seed, mustHexBytes(t, vector.Sk)) {
			t.Fatalf("vector %d: sk is not the seed, which the draft says it is", i)
		}
		priv, err := XwingKeyGenFromSeed(seed)
		if err != nil {
			t.Fatalf("vector %d keygen: %v", i, err)
		}
		if got, want := priv.Public().Bytes(), mustHexBytes(t, vector.Pk); !bytes.Equal(got, want) {
			t.Errorf("vector %d: pk = %x..., want %x...", i, got[:16], want[:16])
		}
	}
}

func TestXwingVectorDecapsulate(t *testing.T) {
	for i, vector := range loadXwingVectors(t) {
		priv, err := XwingKeyGenFromSeed(mustHexBytes(t, vector.Seed))
		if err != nil {
			t.Fatalf("vector %d keygen: %v", i, err)
		}
		ss, err := XwingDecapsulate(priv, mustHexBytes(t, vector.Ct))
		if err != nil {
			t.Fatalf("vector %d decapsulate: %v", i, err)
		}
		if got, want := ss, mustHexBytes(t, vector.Ss); !bytes.Equal(got, want) {
			t.Errorf("vector %d: ss = %x, want %x", i, got, want)
		}
	}
}

func TestXwingVectorEncapsulateX25519Half(t *testing.T) {
	// eseed[32:64] is ek_X, and ct[1088:1120] must be its public key. this is the half of
	// encapsulation the standard library lets us pin exactly.
	for i, vector := range loadXwingVectors(t) {
		eseed := mustHexBytes(t, vector.Eseed)
		if len(eseed) != 2*XwingX25519KeySize {
			t.Fatalf("vector %d: eseed is %d bytes, want %d", i, len(eseed), 2*XwingX25519KeySize)
		}
		got, err := x25519PublicKeyOfScalar(eseed[XwingX25519KeySize:])
		if err != nil {
			t.Fatalf("vector %d ephemeral: %v", i, err)
		}
		ct := mustHexBytes(t, vector.Ct)
		if want := ct[XwingMlkemCiphertextSize:]; !bytes.Equal(got, want) {
			t.Errorf("vector %d: ct_X = %x, want %x", i, got, want)
		}
	}
}

// ── what the vector gate is actually worth, measured rather than claimed ─────────────

// One comparison the gate makes against a value the draft published.
//
// It carries what this package PRODUCED and the corpus field the answer belongs to, and it does
// NOT carry the published bytes. That is deliberate and it is the difference between a gate and
// a gate that can be made vacuous by one line: a collector that also decided what the answer
// should be could set the two equal to each other, and every count below would still read nine.
// The published side is computed from the file by xwingPublishedValue, which has no access to
// anything this package produced, so the only way to satisfy a comparison is to match the file.
type xwingPublishedAnswer struct {
	vector int
	// the field of the vector the answer belongs to
	field string
	// what the answer is about: this implementation's output, or the corpus itself
	holdsTheImplementation bool
	got                    []byte
}

// The bytes one field of one vector publishes as an answer, read out of the corpus and nowhere
// else. ct is the one field that is an input AND an answer: the whole 1120 octets go in, and the
// last 32 of them are ct_X, which is the half of encapsulation the standard library lets this
// package be held to.
func xwingPublishedValue(t *testing.T, vector xwingVector, field string) []byte {
	t.Helper()
	switch field {
	case "sk":
		return mustHexBytes(t, vector.Sk)
	case "pk":
		return mustHexBytes(t, vector.Pk)
	case "ss":
		return mustHexBytes(t, vector.Ss)
	case "ct":
		return mustHexBytes(t, vector.Ct)[XwingMlkemCiphertextSize:]
	}
	t.Fatalf("the gate recorded an answer about the field %q and this function publishes no value for it", field)
	return nil
}

// Every published answer the gate holds this package against, together with which of the
// corpus's own fields were read as inputs.
//
// This exists so that the coverage claim in the file comment is a measurement. A vector gate is
// worth the number of DISTINCT published answers it compares against, and every failure mode
// this project has found in one -- a direction that reused the other's serializer, a loop that
// compared a value to itself, a field of the corpus nobody read -- shows up as a number here
// rather than as a green test.
func xwingHoldAgainstTheDraft(t *testing.T) ([]xwingPublishedAnswer, map[string]bool) {
	t.Helper()
	answers := []xwingPublishedAnswer{}
	consumed := map[string]bool{}
	for i, vector := range loadXwingVectors(t) {
		seed := mustHexBytes(t, vector.Seed)
		consumed["seed"] = true

		// the corpus's own claim about itself, which is not a statement about this package
		answers = append(answers, xwingPublishedAnswer{
			vector: i, field: "sk", holdsTheImplementation: false, got: seed,
		})

		priv, err := XwingKeyGenFromSeed(seed)
		if err != nil {
			t.Fatalf("vector %d keygen: %v", i, err)
		}
		answers = append(answers, xwingPublishedAnswer{
			vector: i, field: "pk", holdsTheImplementation: true, got: priv.Public().Bytes(),
		})

		ct := mustHexBytes(t, vector.Ct)
		consumed["ct"] = true
		shared, err := XwingDecapsulate(priv, ct)
		if err != nil {
			t.Fatalf("vector %d decapsulate: %v", i, err)
		}
		answers = append(answers, xwingPublishedAnswer{
			vector: i, field: "ss", holdsTheImplementation: true, got: shared,
		})

		eseed := mustHexBytes(t, vector.Eseed)
		consumed["eseed"] = true
		ephemeral, err := x25519PublicKeyOfScalar(eseed[XwingX25519KeySize:])
		if err != nil {
			t.Fatalf("vector %d ephemeral: %v", i, err)
		}
		answers = append(answers, xwingPublishedAnswer{
			vector: i, field: "ct", holdsTheImplementation: true, got: ephemeral,
		})
	}
	return answers, consumed
}

// TestXwingIsHeldAgainstNineDistinctPublishedAnswers is the count that says the three directions
// above are three directions and not one written three ways.
//
// Nine is three vectors times the three answers the standard library lets this package be held
// to. Every published side is recomputed HERE, out of the corpus, rather than taken from the
// collector, so a comparison cannot be satisfied by anything this package produced. The
// assertion is then on the number of DISTINCT published byte strings: a gate that compared the
// same answer nine times reports fewer than nine and fails. The count of CALLS is not asserted
// anywhere, because a call count is satisfied by nine copies of one comparison.
func TestXwingIsHeldAgainstNineDistinctPublishedAnswers(t *testing.T) {
	vectors := loadXwingVectors(t)
	answers, _ := xwingHoldAgainstTheDraft(t)
	distinct := map[string]bool{}
	held := 0
	for _, answer := range answers {
		if answer.vector < 0 || answer.vector >= len(vectors) {
			t.Fatalf("the gate recorded an answer about vector %d and the corpus has %d", answer.vector, len(vectors))
		}
		want := xwingPublishedValue(t, vectors[answer.vector], answer.field)
		if len(want) == 0 {
			t.Fatalf("vector %d publishes nothing for %s, so that comparison is against an empty string", answer.vector, answer.field)
		}
		if !bytes.Equal(answer.got, want) {
			t.Errorf("vector %d, %s: got %x, want %x", answer.vector, answer.field, answer.got, want)
		}
		if !answer.holdsTheImplementation {
			continue
		}
		held++
		distinct[string(want)] = true
	}
	if held != 3*xwingVectorCount {
		t.Errorf("the gate holds this package against %d published answers, want %d", held, 3*xwingVectorCount)
	}
	if len(distinct) != 3*xwingVectorCount {
		t.Errorf("those %d comparisons are against %d DISTINCT published values; two of them are the same answer, so one of the two proves nothing",
			held, len(distinct))
	}
	t.Logf("%d published answers compared, %d of them holding this package, %d distinct", len(answers), held, len(distinct))
}

// TestEveryFieldTheCorpusPublishesIsReadBySomething derives the coverage class off the file
// rather than off a list.
//
// A vendored corpus carries fields, and a gate is only as wide as the fields it touches. Naming
// them here would be an enumeration that a re-vendoring silently outgrows; reading the file's own
// keys means a seventh field arrives as a failure that says which one nobody reads.
func TestEveryFieldTheCorpusPublishesIsReadBySomething(t *testing.T) {
	answers, consumed := xwingHoldAgainstTheDraft(t)
	compared := map[string]bool{}
	for _, answer := range answers {
		compared[answer.field] = true
	}
	published := map[string]bool{}
	for i, object := range loadXwingVectorObjects(t) {
		if len(object) == 0 {
			t.Fatalf("vector %d has no fields at all, so this rule would hold over nothing", i)
		}
		for field := range object {
			published[field] = true
		}
	}
	for _, field := range slices.Sorted(maps.Keys(published)) {
		if !consumed[field] && !compared[field] {
			t.Errorf("the draft publishes %q and this package's vector gate neither consumes it as an input nor compares against it, so that field is vendored and unread", field)
		}
	}
	// and the other direction, so a field this gate believes it reads cannot outlive the corpus
	for _, field := range slices.Sorted(maps.Keys(compared)) {
		if !published[field] {
			t.Errorf("the gate compares against a field %q the corpus does not publish", field)
		}
	}
	for _, field := range slices.Sorted(maps.Keys(consumed)) {
		if !published[field] {
			t.Errorf("the gate consumes a field %q the corpus does not publish", field)
		}
	}
	t.Logf("%d published fields, %d consumed as inputs, %d compared as answers", len(published), len(consumed), len(compared))
}

// TestXwingCombinerOrderMatchesTheDraft is the specific defect this guards: spec A section 5.4's
// table puts XWingLabel FIRST and the draft puts it LAST.
//
// Both halves report with Errorf rather than Fatalf, deliberately. Written with a Fatalf on the
// first half -- which is how the plan supplied it -- the second half is unreachable in every case
// that would make it fire: an empty label makes the two forms identical, but it also makes the
// first half fail, so the assertion that was supposed to catch it never runs. Two independent
// observations are worth having; one observation and one line of dead code are not.
func TestXwingCombinerOrderMatchesTheDraft(t *testing.T) {
	vector := loadXwingVectors(t)[0]
	priv, err := XwingKeyGenFromSeed(mustHexBytes(t, vector.Seed))
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	ct := mustHexBytes(t, vector.Ct)
	published := mustHexBytes(t, vector.Ss)
	ss, err := XwingDecapsulate(priv, ct)
	if err != nil {
		t.Fatalf("decapsulate: %v", err)
	}
	if !bytes.Equal(ss, published) {
		t.Errorf("the combiner does not match the draft: ss = %x, want %x", ss, published)
	}

	// recompute with the label first, the form spec A section 5.4's table describes, and assert
	// it does NOT reproduce the vector. without this the wrong ordering could be reintroduced
	// and only an X-Wing peer would ever notice -- and we have none.
	mlkemShared, err := priv.mlkemPrivate.Decapsulate(ct[0:XwingMlkemCiphertextSize])
	if err != nil {
		t.Fatalf("mlkem decapsulate: %v", err)
	}
	ephemeralPublic, err := mls.X25519PublicKey(ct[XwingMlkemCiphertextSize:])
	if err != nil {
		t.Fatalf("parse ct_X: %v", err)
	}
	x25519Shared, err := mls.X25519DH(priv.x25519Private, ephemeralPublic)
	if err != nil {
		t.Fatalf("x25519: %v", err)
	}
	labelFirst := sha3.New256()
	labelFirst.Write(xwingLabel)
	labelFirst.Write(mlkemShared)
	labelFirst.Write(x25519Shared)
	labelFirst.Write(ct[XwingMlkemCiphertextSize:])
	labelFirst.Write(priv.x25519PublicKey)
	if bytes.Equal(published, labelFirst.Sum(nil)) {
		t.Errorf("a label first combiner reproduced the draft's answer, which is only possible if the label is empty or the two forms have collided")
	}
}

// ── the corpus's provenance ──────────────────────────────────────────────────────────

// TestXwingVectorFileWasNotSmudgedOnTheWayIn. core.autocrlf is true at system scope on the
// windows boxes that build this repository, and the sixteen mlswg corpora were once vendored
// already smudged with a manifest computed over the smudged bytes, so they verified against
// bytes upstream never published. The digest check above catches that too, but this names it:
// a carriage return in a corpus fetched from a repository that publishes LF is git having
// rewritten the evidence.
// The predicate, split out so the control below runs the same code the rule does rather than a
// second copy of it.
func xwingCarriageReturnAt(raw []byte) int {
	return bytes.IndexByte(raw, '\r')
}

func TestXwingVectorFileWasNotSmudgedOnTheWayIn(t *testing.T) {
	raw := loadXwingVectorFile(t)
	if i := xwingCarriageReturnAt(raw); i >= 0 {
		t.Fatalf("%s carries a carriage return at offset %d; git rewrote the corpus on checkout and it is no longer the bytes upstream published", xwingVectorPath, i)
	}
	// The control, and it is not decoration here. This corpus is a SINGLE LINE of json with no
	// newline in it at all, so there is nothing in it for git to convert and the rule above
	// cannot fail on the file as vendored. What is load bearing against a smudge today is the
	// digest in loadXwingVectorFile and the attributes file the test below reads; this rule is
	// what would catch a re-vendoring that shipped a pretty printed corpus, and without a control
	// it would be a matcher nothing has ever seen say yes.
	if n := bytes.Count(raw, []byte{'\n'}); n != 0 {
		t.Errorf("%s holds %d newlines; it was a single line when this control was written, so re-read the paragraph above and decide which of the two checks is now the weaker one", xwingVectorPath, n)
	}
	smudged := append(append([]byte{}, raw[:16]...), append([]byte{'\r', '\n'}, raw[16:]...)...)
	if i := xwingCarriageReturnAt(smudged); i != 16 {
		t.Fatalf("the smudge predicate answered %d on a corpus carrying a carriage return at offset 16, so it would report the real file clean whatever git had done to it", i)
	}
}

// TestXwingVectorDirectoryDisablesGitsTextConversion reads the attributes file itself, so the
// rule going missing fails on the commit that removes it rather than on the next person's fresh
// clone.
func TestXwingVectorDirectoryDisablesGitsTextConversion(t *testing.T) {
	raw, err := os.ReadFile(xwingVectorAttributesPath)
	if err != nil {
		t.Fatalf("read %s, which is what keeps git from rewriting the corpus: %v", xwingVectorAttributesPath, err)
	}
	if !strings.Contains(string(raw), "* -text") {
		t.Fatalf("%s does not carry `* -text`, so the corpus is subject to core.autocrlf: %q", xwingVectorAttributesPath, string(raw))
	}
}

// The two column table under one heading of the pin file, as a field to value map.
//
// Scoped to that heading's own section rather than to the file, because the commit appears in
// the fence, in the table and in the fetch url, and a strings.Contains over the whole file is
// answered by whichever copy was not corrupted. That is measured, not supposed: mls's own
// provenance test records 33 of 35 corruptions of the sibling section leaving every test green.
//
// It is a second copy of a parser mls already has, for the same reason mustHexBytes above is a
// second copy of p8's hex decoder: the original is declared in mls/hpke_vectors_test.go, and a
// _test.go file's symbols are not visible across a package boundary. It is not a preference and
// there is no way to share it short of moving the helper into non test source.
func xwingPinFileRows(t *testing.T, text string, heading string) map[string]string {
	t.Helper()
	start := strings.Index(text, heading)
	if start < 0 {
		t.Fatalf("%s has no %q section, so its provenance table cannot be located", xwingVectorPinFilePath, heading)
	}
	section := text[start+len(heading):]
	if next := strings.Index(section, "\n## "); next >= 0 {
		section = section[:next]
	}
	rows := map[string]string{}
	for _, raw := range strings.Split(section, "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) != 2 {
			continue
		}
		field := strings.TrimSpace(cells[0])
		if field == "Field" || strings.Trim(field, "-") == "" {
			continue
		}
		rows[field] = strings.Trim(strings.TrimSpace(cells[1]), "`")
	}
	if len(rows) == 0 {
		t.Fatalf("%s's %q section has no table rows, so this rule would hold over nothing", xwingVectorPinFilePath, heading)
	}
	return rows
}

// TestXwingVectorProvenanceIsRecordedInThePinFile ties this file's constants to the one pin file
// of the slice, in both directions and field by field.
//
// The provenance is the deliverable. X-Wing is an Internet-Draft with no IANA code point, so this
// corpus moves when the draft moves, and a digest with no recorded origin is a number nobody can
// re-derive. The row table is compared in both directions so that a row nobody pins fails as
// loudly as a row that disagrees.
func TestXwingVectorProvenanceIsRecordedInThePinFile(t *testing.T) {
	body, err := os.ReadFile(filepath.FromSlash(xwingVectorPinFilePath))
	if err != nil {
		t.Fatalf("read %s: %v", xwingVectorPinFilePath, err)
	}
	text := string(body)

	// the machine readable pin, in the shape the file's own prose requires of every line of its
	// fenced block
	if !strings.Contains(text, "xwing="+xwingVectorUpstreamCommit) {
		t.Errorf("%s has no machine-readable xwing=%s line, so the upstream commit is recorded only in prose",
			xwingVectorPinFilePath, xwingVectorUpstreamCommit)
	}

	rows := xwingPinFileRows(t, text, "## message/"+xwingVectorPath)
	want := map[string]string{
		"Upstream repository": xwingVectorUpstreamRepository,
		"Upstream commit":     xwingVectorUpstreamCommit,
		"Upstream path":       xwingVectorUpstreamPath,
		"Upstream sha256":     xwingVectorSha256,
		"Vendored sha256":     xwingVectorSha256,
		"Vectors":             "3",
	}
	for _, field := range slices.Sorted(maps.Keys(want)) {
		got, ok := rows[field]
		if !ok {
			t.Errorf("%s provenance table has no %q row", xwingVectorPinFilePath, field)
			continue
		}
		if got != want[field] {
			t.Errorf("%s records %s = %s, this corpus was vendored from %s", xwingVectorPinFilePath, field, got, want[field])
		}
	}
	for _, field := range slices.Sorted(maps.Keys(rows)) {
		if _, ok := want[field]; !ok {
			t.Errorf("%s provenance table carries an unpinned %q row", xwingVectorPinFilePath, field)
		}
	}

	// the claims that occur once, including the url that has to agree with the three fields it
	// is built out of
	for _, claim := range []struct {
		what string
		want string
	}{
		{
			what: "the fetch url",
			want: "https://raw.githubusercontent.com/" + xwingVectorUpstreamRepository +
				"/" + xwingVectorUpstreamCommit + "/" + xwingVectorUpstreamPath,
		},
		{what: "the attributes file", want: "message/" + xwingVectorAttributesPath},
		{what: "the file holding the second copy of the digest", want: "message/xwing_vectors_test.go"},
		{what: "the constant holding it", want: "xwingVectorSha256"},
		{what: "the smudge detector", want: "TestXwingVectorFileWasNotSmudgedOnTheWayIn"},
		{what: "the attributes check", want: "TestXwingVectorDirectoryDisablesGitsTextConversion"},
		{what: "this test", want: "TestXwingVectorProvenanceIsRecordedInThePinFile"},
	} {
		if !strings.Contains(text, claim.want) {
			t.Errorf("%s does not record %s: %q", xwingVectorPinFilePath, claim.what, claim.want)
		}
	}

	// the row in the summary table at the top, which records the vendored digest a second time
	row := ""
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "|") && strings.Contains(line, "`../../message/"+xwingVectorPath+"`") {
			row = line
			break
		}
	}
	if row == "" {
		t.Fatalf("%s summary table has no row for %s", xwingVectorPinFilePath, xwingVectorPath)
	}
	if !strings.Contains(row, xwingVectorSha256) {
		t.Errorf("%s summary row for %s does not carry sha256 %s", xwingVectorPinFilePath, xwingVectorPath, xwingVectorSha256)
	}
	if !strings.Contains(row, "`xwing=` line above") {
		t.Errorf("%s summary row for %s does not point at the machine-readable xwing= line", xwingVectorPinFilePath, xwingVectorPath)
	}
}
