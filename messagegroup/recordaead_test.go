package messagegroup

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/connect/message"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

// One parsed production file of this package, with the file set that positioned it, so a gate
// below can print a line number rather than a name.
type messagegroupSource struct {
	path   string
	parsed *ast.File
}

// Every non test go file of this package, parsed with its comments.
//
// The SCOPE question, answered separately from every class question below per R3a: it is this
// directory and only this directory. Each gate that uses this reader states what its class is;
// the scope is the same for all of them because the properties they hold are about what this
// package ships, and connect/message -- the other half of the record layer -- can neither
// import this package nor declare the constant, the primitive or the derivations these gates
// read. A gate here that also had to read ../message would be a gate over a class with members
// on both sides, and task 11's call site gate is the one of those; it is written there, where
// the class first has a member, and not here, where it would report clean having read nothing.
//
// A directory with no production file is fatal rather than empty. An empty reading clears every
// rule written over it, which is this tree's most expensive failure mode.
func messagegroupProductionSources(t *testing.T) (*token.FileSet, []messagegroupSource) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read this package's directory: %v", err)
	}
	fileSet := token.NewFileSet()
	sources := []messagegroupSource{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.ToSlash(filepath.Join(".", name))
		parsed, err := parser.ParseFile(fileSet, path, nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		sources = append(sources, messagegroupSource{path: path, parsed: parsed})
	}
	if len(sources) == 0 {
		t.Fatal("no non test go file was read out of this package, so every gate written over this reading cleared its subject having read nothing")
	}
	return fileSet, sources
}

// The value MASTER section 8 pins, transcribed here so the assertion below compares the package
// against the specification and not against itself.
const recordAeadAlgIdFromMaster uint16 = 0x0021

// The two identifiers that are already in this tree and are NOT the record aead's, restated so
// the collision is refused by name rather than by a reader noticing.
const (
	hkdfSha256AlgIdFromMaster uint16 = 0x0031
	xwingAlgIdFromMaster      uint16 = 0x0014
)

// Property 1, the value half.
func TestRecordAeadAlgIdIsTheCodePointMasterRegisters(t *testing.T) {
	if RecordAeadAlgId != recordAeadAlgIdFromMaster {
		t.Errorf("RecordAeadAlgId = %#04x, and MASTER section 8 pins %#04x for XChaCha20-Poly1305",
			RecordAeadAlgId, recordAeadAlgIdFromMaster)
	}
	// the two near misses MASTER names as the ones a reader reaches for. 0x0031 is the kdf that
	// PRODUCED the key and 0x0014 is the wrap kem; either one in this constant builds a preimage
	// that round trips against itself and fails every other implementation.
	if RecordAeadAlgId == hkdfSha256AlgIdFromMaster {
		t.Errorf("RecordAeadAlgId = %#04x, which is HKDF-SHA-256: the function that produced the key, not the one that consumes it",
			RecordAeadAlgId)
	}
	if RecordAeadAlgId == xwingAlgIdFromMaster || RecordAeadAlgId == XwingAlgId {
		t.Errorf("RecordAeadAlgId = %#04x, which is the X-Wing wrap identifier and names no aead",
			RecordAeadAlgId)
	}
}

// Property 1, the "one constant" half.
//
// The CLASS is derived and not listed: every package level constant of this package's
// production source whose value is the literal MASTER registers, whatever it is called and
// whatever file it is in. Exactly one may exist and it must be RecordAeadAlgId. A second
// spelling of the same code point is the shape this tree keeps rediscovering -- two names for
// one wire value, one of which is edited.
func TestExactlyOneConstantOfThisPackageCarriesTheRecordAeadCodePoint(t *testing.T) {
	fileSet, sources := messagegroupProductionSources(t)
	carrying := []string{}
	for _, source := range sources {
		for _, declaration := range source.parsed.Decls {
			general, isGeneral := declaration.(*ast.GenDecl)
			if !isGeneral || general.Tok != token.CONST {
				continue
			}
			for _, spec := range general.Specs {
				value, isValue := spec.(*ast.ValueSpec)
				if !isValue {
					continue
				}
				for i, name := range value.Names {
					if len(value.Values) <= i {
						continue
					}
					literal, isLiteral := value.Values[i].(*ast.BasicLit)
					if !isLiteral || literal.Kind != token.INT {
						continue
					}
					if !recordAeadLiteralIsTheCodePoint(literal.Value) {
						continue
					}
					carrying = append(carrying, name.Name+" at "+fileSet.Position(name.Pos()).String())
				}
			}
		}
	}
	if len(carrying) != 1 {
		t.Fatalf("%d package level constants of this package carry the record aead code point %#04x: %v; MASTER registers one identifier and a second name for it is one edit away from two implementations disagreeing",
			len(carrying), recordAeadAlgIdFromMaster, carrying)
	}
	if !strings.HasPrefix(carrying[0], "RecordAeadAlgId ") {
		t.Errorf("the one constant carrying %#04x is %s, and the interface this package publishes names it RecordAeadAlgId",
			recordAeadAlgIdFromMaster, carrying[0])
	}
}

// Whether a go integer literal, in any spelling the language allows, is the code point.
//
// Read as a number rather than matched as the text 0x0021, because 33, 0o41 and 0b100001 are
// the same constant and a gate that matched the hex spelling would report clean over any of
// them.
func recordAeadLiteralIsTheCodePoint(text string) bool {
	cleaned := strings.ToLower(strings.ReplaceAll(text, "_", ""))
	base := 10
	switch {
	case strings.HasPrefix(cleaned, "0x"):
		base, cleaned = 16, cleaned[2:]
	case strings.HasPrefix(cleaned, "0b"):
		base, cleaned = 2, cleaned[2:]
	case strings.HasPrefix(cleaned, "0o"):
		base, cleaned = 8, cleaned[2:]
	case 1 < len(cleaned) && cleaned[0] == '0':
		base, cleaned = 8, cleaned[1:]
	}
	if len(cleaned) == 0 {
		return false
	}
	value := uint64(0)
	for _, digit := range cleaned {
		place := strings.IndexRune("0123456789abcdef", digit)
		if place < 0 || base <= place {
			return false
		}
		value = value*uint64(base) + uint64(place)
	}
	return value == uint64(recordAeadAlgIdFromMaster)
}

// A key, a nonce, an aad and a plaintext that are each distinctive and none of which is a
// repeat of another, so a swap at any call site below shows up as a different ciphertext.
func recordAeadFixture() (key []byte, nonce []byte, aad []byte, plaintext []byte) {
	key = make([]byte, chacha20poly1305.KeySize)
	for i := range key {
		key[i] = byte(0x40 + i)
	}
	nonce = make([]byte, chacha20poly1305.NonceSizeX)
	for i := range nonce {
		nonce[i] = byte(0x90 + i)
	}
	aad = []byte("URmessage/v1/aad-head-stand-in")
	plaintext = []byte("the durable text message CP3b is the bar for")
	return key, nonce, aad, plaintext
}

// Property 2, the width half: the nonce this wrapper takes is the extended one.
func TestTheRecordAeadNonceIsTwentyFourOctets(t *testing.T) {
	if recordAeadNonceBytes != 24 {
		t.Errorf("recordAeadNonceBytes = %d; section 5.3 hands out a 32 octet key and a 24 octet nonce as one 56 octet expansion, and 24 is XChaCha20-Poly1305's and no other v1 suite's",
			recordAeadNonceBytes)
	}
	if recordAeadNonceBytes != chacha20poly1305.NonceSizeX {
		t.Errorf("recordAeadNonceBytes = %d and chacha20poly1305.NonceSizeX = %d; the wrapper's width must be the extended construction's own",
			recordAeadNonceBytes, chacha20poly1305.NonceSizeX)
	}
	if recordAeadNonceBytes == chacha20poly1305.NonceSize {
		t.Errorf("recordAeadNonceBytes = %d, which is the TWELVE octet variant's nonce; a build on that variant discards twelve octets of every record nonce and round trips against itself",
			recordAeadNonceBytes)
	}
	if recordAeadKeyBytes != chacha20poly1305.KeySize {
		t.Errorf("recordAeadKeyBytes = %d and chacha20poly1305.KeySize = %d", recordAeadKeyBytes, chacha20poly1305.KeySize)
	}
	if recordAeadKeyBytes != 32 {
		t.Errorf("recordAeadKeyBytes = %d, want the 32 octet key both variants take", recordAeadKeyBytes)
	}
}

// Property 2, the construction half, and the one assertion in this file that is not against
// this package's own arithmetic.
//
// XChaCha20-Poly1305 is defined as HChaCha20 over the key and the first sixteen octets of the
// nonce, then ChaCha20-Poly1305 under that subkey with the nonce four zero octets followed by
// the last eight. Rebuilding it that way out of two other packages is the only thing here that
// can tell NewX from New: every property below is satisfied by both, because both are the same
// package's aead over the same key.
func TestTheRecordAeadIsTheExtendedNonceConstructionAndNotItsTwelveOctetTwin(t *testing.T) {
	key, nonce, aad, plaintext := recordAeadFixture()
	sealed, err := sealRecordAead(key, nonce, aad, plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	subKey, err := chacha20.HChaCha20(key, nonce[:16])
	if err != nil {
		t.Fatalf("hchacha20 over the first sixteen nonce octets: %v", err)
	}
	inner, err := chacha20poly1305.New(subKey)
	if err != nil {
		t.Fatalf("chacha20poly1305 under the derived subkey: %v", err)
	}
	innerNonce := make([]byte, chacha20poly1305.NonceSize)
	copy(innerNonce[4:], nonce[16:])
	want := inner.Seal(nil, innerNonce, plaintext, aad)
	if string(sealed) != string(want) {
		t.Errorf("the wrapper sealed\n%x\nand the extended construction rebuilt from HChaCha20 and the twelve octet aead gives\n%x",
			sealed, want)
	}
}

// Property 2, the refusal half: two distinct sentinels, and both are decided before anything is
// encrypted.
func TestTheRecordAeadRefusesEveryWidthButItsOwn(t *testing.T) {
	key, nonce, aad, plaintext := recordAeadFixture()
	for _, width := range []int{0, 1, 12, 16, 24, 31, 33, 64} {
		if width == recordAeadKeyBytes {
			continue
		}
		short := make([]byte, width)
		if _, err := sealRecordAead(short, nonce, aad, plaintext); !errors.Is(err, ErrRecordAeadKeyLength) {
			t.Errorf("sealing under a %d octet key gave %v, want ErrRecordAeadKeyLength", width, err)
		}
		if _, err := openRecordAead(short, nonce, aad, plaintext); !errors.Is(err, ErrRecordAeadKeyLength) {
			t.Errorf("opening under a %d octet key gave %v, want ErrRecordAeadKeyLength", width, err)
		}
	}
	for _, width := range []int{0, 1, 8, 12, 16, 23, 25, 32} {
		if width == recordAeadNonceBytes {
			continue
		}
		short := make([]byte, width)
		if _, err := sealRecordAead(key, short, aad, plaintext); !errors.Is(err, ErrRecordAeadNonceLength) {
			t.Errorf("sealing under a %d octet nonce gave %v, want ErrRecordAeadNonceLength", width, err)
		}
		if _, err := openRecordAead(key, short, aad, plaintext); !errors.Is(err, ErrRecordAeadNonceLength) {
			t.Errorf("opening under a %d octet nonce gave %v, want ErrRecordAeadNonceLength", width, err)
		}
	}
	// the twelve octet nonce is the one that must never be a silently truncated success, and it
	// is the one a build on chacha20poly1305.New would accept.
	twelve := make([]byte, chacha20poly1305.NonceSize)
	sealed, err := sealRecordAead(key, twelve, aad, plaintext)
	if sealed != nil || !errors.Is(err, ErrRecordAeadNonceLength) {
		t.Errorf("a twelve octet nonce sealed %d octets with %v; it owes ErrRecordAeadNonceLength and no ciphertext", len(sealed), err)
	}
	// the two refusals are distinct values and neither is the open failure.
	for _, pair := range [][2]error{
		{ErrRecordAeadKeyLength, ErrRecordAeadNonceLength},
		{ErrRecordAeadKeyLength, ErrRecordAeadOpen},
		{ErrRecordAeadNonceLength, ErrRecordAeadOpen},
	} {
		if errors.Is(pair[0], pair[1]) || errors.Is(pair[1], pair[0]) {
			t.Errorf("%v and %v are not distinct sentinels, so a caller cannot tell the two refusals apart", pair[0], pair[1])
		}
	}
	// and the widths are refused BEFORE any arithmetic: a bad key with a bad nonce reports the
	// key, and neither reaches the primitive at all.
	if _, err := sealRecordAead(make([]byte, 3), make([]byte, 3), aad, plaintext); !errors.Is(err, ErrRecordAeadKeyLength) {
		t.Errorf("a bad key and a bad nonce gave %v; the key is checked first and nothing is encrypted either way", err)
	}
}

// Property 3: the ciphertext is the plaintext plus the tag, and the tag is the same sixteen the
// size bucket ladder in connect/message accounts for.
func TestTheRecordAeadCiphertextIsThePlaintextPlusOneTag(t *testing.T) {
	key, nonce, aad, _ := recordAeadFixture()
	for _, length := range []int{0, 1, 15, 16, 17, 256, 1024, 4096} {
		plaintext := make([]byte, length)
		for i := range plaintext {
			plaintext[i] = byte(i)
		}
		sealed, err := sealRecordAead(key, nonce, aad, plaintext)
		if err != nil {
			t.Fatalf("seal %d octets: %v", length, err)
		}
		if len(sealed) != length+recordAeadTagBytes {
			t.Errorf("sealing %d octets gave %d, want %d", length, len(sealed), length+recordAeadTagBytes)
		}
	}
	// the ladder's tag width, derived from the two exported functions rather than written down,
	// because connect/message's own aeadTagBytes is unexported and this package may not see it.
	// Every rung must account for exactly this file's overhead.
	rungs := 0
	for bucket := message.SizeBucket(0); int(bucket) < 8; bucket++ {
		body := message.SizeBucketBytes(bucket)
		if body < 0 {
			continue
		}
		rungs++
		if overhead := message.SizeBucketCtBodyBytes(bucket) - body; overhead != recordAeadTagBytes {
			t.Errorf("size bucket %d accounts for %d octets of aead overhead and this aead adds %d; the ladder is what the server checks the stored ciphertext length against",
				bucket, overhead, recordAeadTagBytes)
		}
	}
	if rungs == 0 {
		t.Fatal("no size bucket answered a body length, so the ladder cross check read nothing")
	}
}

// Property 4: nothing that was not sealed under exactly these four values opens.
func TestOpenRefusesEverySingleBitMutationAndAnswersNoPlaintext(t *testing.T) {
	key, nonce, aad, plaintext := recordAeadFixture()
	sealed, err := sealRecordAead(key, nonce, aad, plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	opened, err := openRecordAead(key, nonce, aad, sealed)
	if err != nil {
		t.Fatalf("open the record this test seals: %v", err)
	}
	if string(opened) != string(plaintext) {
		t.Fatalf("opened %q, want %q", opened, plaintext)
	}
	flips := 0
	for _, subject := range []struct {
		name  string
		bytes []byte
	}{
		{name: "key", bytes: key},
		{name: "nonce", bytes: nonce},
		{name: "aad", bytes: aad},
		{name: "ciphertext", bytes: sealed},
	} {
		for i := range subject.bytes {
			for bit := 0; bit < 8; bit++ {
				mutated := slices.Clone(subject.bytes)
				mutated[i] ^= 1 << bit
				arguments := [4][]byte{key, nonce, aad, sealed}
				switch subject.name {
				case "key":
					arguments[0] = mutated
				case "nonce":
					arguments[1] = mutated
				case "aad":
					arguments[2] = mutated
				case "ciphertext":
					arguments[3] = mutated
				}
				flips++
				out, err := openRecordAead(arguments[0], arguments[1], arguments[2], arguments[3])
				if !errors.Is(err, ErrRecordAeadOpen) {
					t.Fatalf("flipping bit %d of octet %d of the %s opened with %v, want ErrRecordAeadOpen", bit, i, subject.name, err)
				}
				if out != nil {
					t.Fatalf("flipping bit %d of octet %d of the %s answered %d octets beside the refusal; an unauthenticated ciphertext yields no plaintext, not a prefix of one",
						bit, i, subject.name, len(out))
				}
			}
		}
	}
	if flips != 8*(len(key)+len(nonce)+len(aad)+len(sealed)) {
		t.Errorf("%d single bit mutations were tried and the four inputs hold %d bits", flips, 8*(len(key)+len(nonce)+len(aad)+len(sealed)))
	}
	// a truncated ciphertext, which is not a single bit flip and is the shape a tag stripper
	// produces.
	for _, cut := range []int{0, 1, recordAeadTagBytes, len(sealed) - 1} {
		if _, err := openRecordAead(key, nonce, aad, sealed[:cut]); !errors.Is(err, ErrRecordAeadOpen) {
			t.Errorf("opening the first %d octets of the ciphertext gave %v, want ErrRecordAeadOpen", cut, err)
		}
	}
}

// A header with every field set to something distinctive, so the two preimages built from it
// differ in more than their label.
func recordAeadHeaderFixture() message.RecordHeader {
	header := message.RecordHeader{
		Epoch:          9,
		StreamIndex:    41,
		IsCommit:       false,
		RetentionClass: message.RetentionDurable,
		EphBucket:      0,
		SizeBucket:     message.SizeBucket256,
		ExpireAt:       1757000000000,
	}
	for i := range header.GroupId {
		header.GroupId[i] = byte(0x10 + i)
	}
	for i := range header.SenderHandle {
		header.SenderHandle[i] = byte(0xA0 + i)
	}
	for i := range header.BodyHash {
		header.BodyHash[i] = byte(0x70 + i)
	}
	return header
}

// Property 5: the aad is not optional, and the two record aads are not interchangeable.
//
// Built through connect/message's own AADHead and AADBody rather than through two byte strings
// invented here, so what is asserted is MASTER invariant I7 over the preimages the record layer
// actually uses -- and so the record aead's own alg_id is what parameterises both of them.
func TestACiphertextSealedUnderOneRecordAadDoesNotOpenUnderTheOther(t *testing.T) {
	key, nonce, _, plaintext := recordAeadFixture()
	header := recordAeadHeaderFixture()
	aadHead, err := message.AADHead(RecordAeadAlgId, &header, nil)
	if err != nil {
		t.Fatalf("build aad_head: %v", err)
	}
	aadBody, err := message.AADBody(RecordAeadAlgId, header.BodyBinding())
	if err != nil {
		t.Fatalf("build aad_body: %v", err)
	}
	if string(aadHead) == string(aadBody) {
		t.Fatal("aad_head and aad_body are the same octets for one header, so this property is unfalsifiable here")
	}
	sealed, err := sealRecordAead(key, nonce, aadHead, plaintext)
	if err != nil {
		t.Fatalf("seal under aad_head: %v", err)
	}
	if out, err := openRecordAead(key, nonce, aadBody, sealed); !errors.Is(err, ErrRecordAeadOpen) || out != nil {
		t.Errorf("a ciphertext sealed under aad_head opened under aad_body with %v and %d octets; the two aads bind two different keys' ciphertexts and neither is optional",
			err, len(out))
	}
	if out, err := openRecordAead(key, nonce, nil, sealed); !errors.Is(err, ErrRecordAeadOpen) || out != nil {
		t.Errorf("a ciphertext sealed under aad_head opened under NO aad with %v and %d octets", err, len(out))
	}
	if out, err := openRecordAead(key, nonce, aadHead, sealed); err != nil || string(out) != string(plaintext) {
		t.Errorf("the ciphertext did not open under its own aad_head: %v", err)
	}
	// and the identifier is inside both preimages, which is why it is this package's constant
	// that the record layer passes: an aad built under a different alg_id is a different aad.
	otherHead, err := message.AADHead(hkdfSha256AlgIdFromMaster, &header, nil)
	if err != nil {
		t.Fatalf("build aad_head under the wrong alg_id: %v", err)
	}
	if string(otherHead) == string(aadHead) {
		t.Fatal("aad_head does not depend on alg_id, so the constant this task pins is not authenticated by anything")
	}
	if out, err := openRecordAead(key, nonce, otherHead, sealed); !errors.Is(err, ErrRecordAeadOpen) || out != nil {
		t.Errorf("a ciphertext sealed under aad_head with alg_id %#04x opened under alg_id %#04x", RecordAeadAlgId, hkdfSha256AlgIdFromMaster)
	}
}
