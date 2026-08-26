// Compile time pins on every cross plan symbol the key schedule and the secret tree
// consume, at the signatures the canonical interface registry gives them. A signature
// change in another plan breaks the build here rather than three tasks later, and a pin
// that pins the wrong shape catches the drift by failing, which is the whole point of
// the file.
//
// Only two of the producing plans have landed in this package: syntax and the crypto
// provider. Tree math, the registry enums and extensions, framing's ContentType and the
// validation plan's ValSem and vector helpers are all still elsewhere, so they cannot be
// pinned yet — an undefined name is a build failure, not a red test, and a build failure
// takes the whole package down including everything already green.
//
// What stands in for them is TestEveryCrossPlanSymbolThatHasLandedIsPinnedHere. It reads
// this package's own source and fails the moment one of those symbols appears, which is
// exactly the moment its pin has to be written. Landing a producing plan without adding
// its pins is therefore loud rather than silent, and the window in which this plan
// consumes an unpinned signature is one commit wide.
package mls

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// Pinned free functions from the crypto plan and the syntax plan, the two that have
// landed. Each is an assignment to a function type written out in full, so a parameter
// added, a result dropped or a named type swapped for its underlying one all fail here.
var (
	_ func(CipherSuite) (CryptoProvider, error) = NewCryptoProvider

	// registry section 2 — the syntax entry points, not append style free functions.
	// There is no syntax.WriteVarVec and no Bytes() without the error.
	_ func() *syntax.Writer                  = syntax.NewWriter
	_ func([]byte) *syntax.Reader            = syntax.NewReader
	_ func(syntax.Marshaler) ([]byte, error) = syntax.Marshal
	_ func([]byte, syntax.Unmarshaler) error = syntax.Unmarshal
)

// Pinned values, which drift differently from functions: a constant retyped or a
// sentinel replaced by a value of another type still compiles at most call sites and
// changes what errors.Is answers.
var (
	_ int   = syntax.MaxVectorLength
	_ error = syntax.ErrTrailingBytes
	_ error = syntax.ErrLengthExceedsMax

	_ CipherSuite = CipherSuiteX25519AesGcm128Sha256Ed25519
	_ CipherSuite = CipherSuiteX25519ChaCha20Sha256Ed25519

	// registry section 3.2 — both hpke key types are byte slices. The assignment is
	// the pin: a struct or an array behind either name stops compiling here.
	_ []byte = HpkePublicKey(nil)
	_ []byte = HpkePrivateKey(nil)
)

// pinnedCodec exists only to carry the C1 method set. Declaring the two methods and then
// asserting the interface is what pins their signatures: syntax.Codec satisfied by a
// type this file wrote means MarshalMLS still takes *syntax.Writer and returns error,
// and UnmarshalMLS still takes *syntax.Reader and returns error. Asserting the interface
// against an existing type would only pin that type.
type pinnedCodec struct{}

// MarshalMLS pins the C1 encode half. It encodes nothing; the signature is the assertion.
func (self *pinnedCodec) MarshalMLS(w *syntax.Writer) error { return nil }

// UnmarshalMLS pins the C1 decode half. It decodes nothing; the signature is the assertion.
func (self *pinnedCodec) UnmarshalMLS(r *syntax.Reader) error { return nil }

var (
	_ syntax.Marshaler   = (*pinnedCodec)(nil)
	_ syntax.Unmarshaler = (*pinnedCodec)(nil)
	_ syntax.Codec       = (*pinnedCodec)(nil)
)

// TestConsumedCryptoProviderShape pins the CryptoProvider method set this plan calls,
// and the three lengths every derivation in it is sized by. Extract is pinned at
// (salt, ikm) — guardrail 1 — and that order is not observable from a signature of two
// byte slices, so what a signature can hold is held here and the order itself is the
// crypto plan's own vector tests.
func TestConsumedCryptoProviderShape(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	var (
		_ func() CipherSuite                                  = crypto.Suite
		_ func([]byte, []byte) []byte                         = crypto.Extract
		_ func([]byte, []byte, int) []byte                    = crypto.Expand
		_ func([]byte, string, []byte, int) []byte            = crypto.ExpandWithLabel
		_ func([]byte, string) []byte                         = crypto.DeriveSecret
		_ func([]byte, string, uint32, int) []byte            = crypto.DeriveTreeSecret
		_ func([]byte) []byte                                 = crypto.Hash
		_ func([]byte, []byte) []byte                         = crypto.Mac
		_ func([]byte, []byte, []byte) bool                   = crypto.MacVerify
		_ func() int                                          = crypto.HashSize
		_ func() int                                          = crypto.KeySize
		_ func() int                                          = crypto.NonceSize
		_ func(int) []byte                                    = crypto.Random
		_ func([]byte) (HpkePrivateKey, HpkePublicKey, error) = crypto.DeriveKeyPair
	)
	if crypto.Suite() != CipherSuiteX25519ChaCha20Sha256Ed25519 {
		t.Fatalf("Suite() = %#04x, want the suite it was constructed for", uint16(crypto.Suite()))
	}
	if crypto.HashSize() != 32 {
		t.Fatalf("HashSize = %d, want 32", crypto.HashSize())
	}
	if crypto.KeySize() != 32 {
		t.Fatalf("KeySize = %d, want 32", crypto.KeySize())
	}
	if crypto.NonceSize() != 12 {
		t.Fatalf("NonceSize = %d, want 12", crypto.NonceSize())
	}
	if n := len(crypto.Extract(nil, nil)); n != crypto.HashSize() {
		t.Fatalf("Extract produced %d bytes, want HashSize %d", n, crypto.HashSize())
	}
	if n := len(crypto.DeriveSecret(make([]byte, 32), "pin")); n != crypto.HashSize() {
		t.Fatalf("DeriveSecret produced %d bytes, want HashSize %d", n, crypto.HashSize())
	}
}

// TestConsumedHpkePublicKeyIsASlice pins that HpkePublicKey is a byte slice and carries
// no Bytes method. The Bytes() pin the first draft of this plan carried does not exist
// and never did, so the vector's external_pub is compared against the slice directly.
//
// The absence half is asserted rather than described: a Bytes method appearing later
// would give a caller two spellings of the same bytes, which is how one of them ends up
// hex encoded and the other not.
func TestConsumedHpkePublicKeyIsASlice(t *testing.T) {
	pub := HpkePublicKey([]byte{0x01, 0x02})
	var raw []byte = pub
	if len(raw) != 2 || raw[0] != 0x01 || raw[1] != 0x02 {
		t.Fatalf("HpkePublicKey did not convert to its bytes: %v", raw)
	}
	if _, ok := any(pub).(interface{ Bytes() []byte }); ok {
		t.Fatal("HpkePublicKey grew a Bytes method; registry section 3.2 says it is a slice and nothing else")
	}
	if _, ok := any(HpkePrivateKey(nil)).(interface{ Bytes() []byte }); ok {
		t.Fatal("HpkePrivateKey grew a Bytes method; registry section 3.2 says it is a slice and nothing else")
	}
}

// TestConsumedSyntaxWriterShape pins the syntax reader and writer surface. Every leaf
// write returns nothing (C2): the error is sticky and is collected once, at Bytes().
func TestConsumedSyntaxWriterShape(t *testing.T) {
	w := syntax.NewWriter()
	var (
		_ func(uint8)            = w.WriteUint8
		_ func(uint16)           = w.WriteUint16
		_ func(uint32)           = w.WriteUint32
		_ func(uint64)           = w.WriteUint64
		_ func([]byte)           = w.WriteOpaque
		_ func([]byte)           = w.WriteRaw
		_ func() ([]byte, error) = w.Bytes
		_ func() error           = w.Err
	)
	w.WriteUint16(0x0001)
	w.WriteOpaque([]byte{0x02, 0x03})
	b, err := w.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if len(b) != 5 {
		t.Fatalf("encoded %d bytes, want 5: two for the uint16, one varint length, two opaque", len(b))
	}
	r := syntax.NewReader(b)
	var (
		_ func() (uint8, error)     = r.ReadUint8
		_ func() (uint16, error)    = r.ReadUint16
		_ func() (uint32, error)    = r.ReadUint32
		_ func() (uint64, error)    = r.ReadUint64
		_ func() ([]byte, error)    = r.ReadOpaque
		_ func(int) ([]byte, error) = r.ReadRaw
		_ func() error              = r.Done
	)
	if _, err := r.ReadUint16(); err != nil {
		t.Fatalf("ReadUint16: %v", err)
	}
	if _, err := r.ReadOpaque(); err != nil {
		t.Fatalf("ReadOpaque: %v", err)
	}
	if err := r.Done(); err != nil {
		t.Fatalf("Done: %v", err)
	}
	if syntax.MaxVectorLength != 1<<20 {
		t.Fatalf("syntax.MaxVectorLength = %d, registry section 2 says 1<<20", syntax.MaxVectorLength)
	}
}

// keyScheduleVectorFamilies is the four mlswg families this plan gates, transcribed from
// its file structure table. Nothing in the tree derives this set today — the runners that
// would name it are later tasks — so the count assertion in the test below is what stops
// the list shrinking, since a deleted entry would otherwise leave a shorter list that
// still passes every per file check.
var keyScheduleVectorFamilies = []string{
	"key-schedule.json",
	"psk_secret.json",
	"transcript-hashes.json",
	"secret-tree.json",
}

// TestVectorFilesPresent asserts the four vector families this plan gates were vendored
// by the validation plan's single vendoring task, are not empty, and are covered by the
// digest manifest beside them. This plan reads them and never writes them.
//
// The manifest half matters more than the presence half: a file that is present but
// unlisted is a file nothing pins, and a file whose digest disagrees with the manifest is
// a file that changed after it was pinned. TestVectorFilesArePinned in vectors_pin_test.go
// checks all sixteen families; this checks the four this plan cannot run without, so a
// change to that file's list cannot quietly drop one of them.
//
// KNOWN DEFECT, stated rather than asserted because asserting it would leave this branch
// red for a condition this plan may not fix: the sixteen vendored files are CRLF, while
// the mlswg blobs at the commit interop/PINS.md pins are LF. key-schedule.json is
// 0e29a307... here and 05aa9a68... upstream. VECTORS.sha256 was computed over the local
// bytes, so it verifies sixteen for sixteen against bytes upstream never published. Every
// hex value inside is intact and encoding/json treats CR as whitespace, so no KAT in this
// plan is wrong because of it — what is lost is the provenance claim, and re-vendoring
// belongs to the task that vendored them.
func TestVectorFilesPresent(t *testing.T) {
	if len(keyScheduleVectorFamilies) != 4 {
		t.Fatalf("this plan gates %d vector families, want the 4 of its file structure table",
			len(keyScheduleVectorFamilies))
	}
	manifest := readVectorManifest(t)
	for _, name := range keyScheduleVectorFamilies {
		path := filepath.Join("testdata", "vectors", name)
		body, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("vector %s: %v — the validation plan's task 6 vendors these; it has not landed", name, err)
			continue
		}
		if len(body) == 0 {
			t.Errorf("vector %s is empty", name)
			continue
		}
		want, listed := manifest[name]
		if !listed {
			t.Errorf("vector %s is not listed in VECTORS.sha256, so nothing pins the bytes this plan reads", name)
			continue
		}
		sum := sha256.Sum256(body)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("vector %s digest %s, VECTORS.sha256 says %s", name, got, want)
		}
	}
}

// readVectorManifest parses VECTORS.sha256 into name to digest. It fails rather than
// returning an empty map, because an unreadable manifest would make every coverage check
// above report "not listed" for the wrong reason.
func readVectorManifest(t *testing.T) map[string]string {
	t.Helper()
	handle, err := os.Open(filepath.Join("testdata", "vectors", "VECTORS.sha256"))
	if err != nil {
		t.Fatalf("open VECTORS.sha256: %v", err)
	}
	defer handle.Close()
	manifest := map[string]string{}
	scanner := bufio.NewScanner(handle)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 {
			manifest[fields[1]] = strings.TrimPrefix(fields[0], "*")
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read VECTORS.sha256: %v", err)
	}
	if len(manifest) == 0 {
		t.Fatal("VECTORS.sha256 parsed to no entries, so every coverage check above would fail for the wrong reason")
	}
	return manifest
}

// crossPlanSymbolsNotYetLanded is every symbol from this plan's "what this plan consumes"
// section whose producing plan is not in this package yet, mapped to the plan that owns
// it. The names are transcribed from the interface registry because that document is
// normative and there is nothing in this tree to derive them from — the code that will
// call them is written by later tasks. What IS derived is whether each has landed, which
// is read from the package's own syntax tree below rather than kept as a boolean here.
//
// GroupContext and PreSharedKeyId are this plan's own, from tasks 3 and 13. They are in
// the same list for the same reason: the moment either exists, this file owes it the
// var _ syntax.Codec pin the plan's task 1 block carries.
var crossPlanSymbolsNotYetLanded = map[string]string{
	"LeafIndex":              "p3 tree math",
	"NodeIndex":              "p3 tree math",
	"LeafCount":              "p3 tree math",
	"NodeWidth":              "p3 tree math",
	"Root":                   "p3 tree math",
	"Left":                   "p3 tree math",
	"Right":                  "p3 tree math",
	"LeafIndex.NodeIndex":    "p3 tree math",
	"NodeIndex.Level":        "p3 tree math",
	"ProtocolVersion":        "p5 registry enums and extensions",
	"ProtocolVersionMls10":   "p5 registry enums and extensions",
	"ExtensionType":          "p5 registry enums and extensions",
	"Extension":              "p5 registry enums and extensions",
	"WriteExtensions":        "p5 registry enums and extensions",
	"ReadExtensions":         "p5 registry enums and extensions",
	"ContentType":            "p6 framing",
	"ContentTypeApplication": "p6 framing",
	"ContentTypeProposal":    "p6 framing",
	"ContentTypeCommit":      "p6 framing",
	"ValSemCode":             "p8 validation and interop",
	"ValSem":                 "p8 validation and interop",
	"ValSem401":              "p8 validation and interop",
	"ValSem402":              "p8 validation and interop",
	"ValSem403":              "p8 validation and interop",
	"ErrPskNonceLength":      "p8 validation and interop",
	"ErrPskType":             "p8 validation and interop",
	"ErrDuplicatePsk":        "p8 validation and interop",
	"VectorFamily":           "p8 validation and interop",
	"RegisterVectorFamily":   "p8 validation and interop",
	"LoadVectorFile":         "p8 validation and interop",
	"MustHex":                "p8 validation and interop",
	"HexOf":                  "p8 validation and interop",
	"GroupContext":           "this plan, task 3",
	"PreSharedKeyId":         "this plan, task 13",
}

// TestEveryCrossPlanSymbolThatHasLandedIsPinnedHere fails when a producing plan merges
// and its pins were not written. That failure is the point: the pin block above is this
// plan's drift detector, and a detector that is silently incomplete detects nothing.
//
// A scan that read nothing would report every symbol as still pending and pass, so the
// positive control below is what separates "not landed" from "not looked". It names
// symbols this package certainly declares, one of each kind the collector handles, and a
// name that certainly does not exist.
func TestEveryCrossPlanSymbolThatHasLandedIsPinnedHere(t *testing.T) {
	declared := packageLevelDeclarations(t, ".")
	t.Logf("%d package level declarations read from this package's source", len(declared))

	for _, control := range []string{
		"CryptoProvider",                         // a type
		"NewCryptoProvider",                      // a func
		"HpkePublicKey",                          // a type from another file
		"CipherSuiteX25519ChaCha20Sha256Ed25519", // a const
		"ErrSecretLength",                        // a var, from this task
		"zeroizeSecret",                          // an unexported func, from this task
		"suiteCryptoProvider.Suite",              // a method, the shape the two tree math methods have
	} {
		if _, ok := declared[control]; !ok {
			t.Fatalf("the scan did not find %s, which this package certainly declares, so it is reporting every symbol below as pending having read nothing useful", control)
		}
	}
	if _, ok := declared["ThisSymbolDoesNotExistAnywhereInPackageMls"]; ok {
		t.Fatal("the scan reports a symbol that cannot exist, so it is matching text rather than declarations")
	}

	for _, name := range slices.Sorted(maps.Keys(crossPlanSymbolsNotYetLanded)) {
		if file, ok := declared[name]; ok {
			t.Errorf("%s has landed in %s (%s) but this file still lists it as not yet pinned; write its compile time pin in the block at the top of this file at the signature the interface registry gives it, then delete this entry",
				name, file, crossPlanSymbolsNotYetLanded[name])
		}
	}
	t.Logf("%d cross plan symbols still pending a pin", len(crossPlanSymbolsNotYetLanded))
}

// packageLevelDeclarations reads every non test go file of a directory and returns the
// package level names it declares, mapped to the file that declares them. Methods appear
// as Receiver.Name, because that is the shape the two tree math methods the registry pins
// have. Test files are excluded: this file is a test file and names every pending symbol
// in a map literal, so including them would report all of them as landed.
func packageLevelDeclarations(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	declared := map[string]string{}
	files := 0
	fileSet := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fileSet, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files++
		for _, declaration := range parsed.Decls {
			switch typed := declaration.(type) {
			case *ast.FuncDecl:
				if typed.Recv == nil || len(typed.Recv.List) == 0 {
					declared[typed.Name.Name] = name
					continue
				}
				declared[receiverTypeName(typed.Recv.List[0].Type)+"."+typed.Name.Name] = name
			case *ast.GenDecl:
				for _, spec := range typed.Specs {
					switch typedSpec := spec.(type) {
					case *ast.TypeSpec:
						declared[typedSpec.Name.Name] = name
					case *ast.ValueSpec:
						for _, ident := range typedSpec.Names {
							if ident.Name != "_" {
								declared[ident.Name] = name
							}
						}
					}
				}
			}
		}
	}
	if files == 0 {
		t.Fatalf("no non test go file found in %s, so this scan proves nothing", dir)
	}
	return declared
}

// receiverTypeName reduces a method receiver to the bare type name, so *T, T and a
// generic T[P] all report T.
func receiverTypeName(expr ast.Expr) string {
	switch typed := expr.(type) {
	case *ast.StarExpr:
		return receiverTypeName(typed.X)
	case *ast.IndexExpr:
		return receiverTypeName(typed.X)
	case *ast.IndexListExpr:
		return receiverTypeName(typed.X)
	case *ast.Ident:
		return typed.Name
	}
	return ""
}
