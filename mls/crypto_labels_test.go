// The RFC 9420 section 5.1 and 5.2 labelled constructions, held to published bytes.
//
// Every mistake this file exists to catch produces a well formed output of exactly the
// right length. Dropping the "MLS 1.0 " prefix, altering it, omitting the uint16 length,
// writing the context without its length prefix, transposing label and context, or
// encoding the generation little endian all round trip perfectly, and all of them
// silently leave the protocol: two implementations that disagree on any of them derive
// different secrets from the same transcript and can never talk. Nothing self referential
// distinguishes them, so the load bearing tests here are the ones that compare against
// bytes this project did not compute.
//
// Five vendored corpora carry that weight, and each of them is the only source for
// something. The digests of all three are pinned by TestVectorFilesArePinned in
// vectors_pin_test.go, so vendored here means the bytes that manifest names.
//
//   - crypto-basics.json is the direct one: one published answer each for
//     ExpandWithLabel, DeriveSecret, DeriveTreeSecret and RefHash, per suite. It is the
//     only corpus that names the constructions of this file, and its RefHash entry is
//     the only published pin on the RefHashInput encoding.
//   - secret-tree.json is the only published pin on the generation's byte order. Every
//     derive_tree_secret vector in crypto-basics uses generation 0xa0a0a0a0, which is its
//     own reversal, so that corpus cannot tell a big endian uint32 from a little endian
//     one or from one repeated byte. The single leaf secret-tree entries publish keys at
//     generation 15, which is 0x0000000f and is not its own reversal.
//   - key-schedule.json is the only published context longer than 63 bytes. Its group
//     context is 112 bytes, so a hand rolled one byte length prefix in place of
//     WriteOpaque agrees with every other vector here and disagrees there.
//   - welcome.json is the only published pin on the key package reference label. The
//     new_member field of an EncryptedGroupSecrets is MakeKeyPackageRef over the
//     KeyPackage the Welcome is addressed to, so the corpus carries a reference somebody
//     else computed. Its key packages are hundreds of bytes, which also makes it the
//     only published RefHash value past the one byte length prefix.
//   - passive-client-handling-commit.json is the same for the proposal reference label:
//     its commits reference proposals it also publishes, so MakeProposalRef over the
//     AuthenticatedContent that framed one must land in the commit bytes.
//
// Those last two are what make the two reference labels non circular. Comparing a
// constant against a string literal in the same tree, which is all
// TestRefLabelsAreTheRfcStrings can do, cannot tell a correct label from one this
// project misspelled the same way twice — and a misspelled label still produces 32
// bytes, still separates the two reference kinds, still round trips, and interoperates
// with no peer alive.
//
// The counts are asserted rather than assumed. A loader that filtered every entry away
// reports exactly what a clean run reports, so each vector test counts the comparisons it
// actually made and fails if the number moved.
//
// Two properties are not published anywhere and rest on the hand derived rows of
// TestKdfLabelEncoding instead, which is worth knowing when reading what the corpora do
// and do not carry. The length field's high byte is one: every length in all three
// corpora is 32, so nothing published can tell a uint16 from a uint8 above 255, and
// lengths above 255 are reachable — Expand serves up to 8160 bytes and MLS-Exporter takes
// a length the caller chooses. The empty label field is the other: no published vector
// derives under an empty label, so the 0x00 that says "present and empty" rather than
// "omitted" is pinned only by the row that writes it out. Both are held by the rows read
// off RFC 9420 section 5.1 rather than by a byte this project did not compute, and there
// is no vector in this corpus that could do better.
package mls

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// One crypto-basics entry, reduced to the three constructions this file owns. The other
// fields of the published object belong to task 14 and are not read here.
type labelKatBasics struct {
	CipherSuite      uint16                   `json:"cipher_suite"`
	ExpandWithLabel  labelKatExpandWithLabel  `json:"expand_with_label"`
	DeriveSecret     labelKatDeriveSecret     `json:"derive_secret"`
	DeriveTreeSecret labelKatDeriveTreeSecret `json:"derive_tree_secret"`
	RefHash          labelKatRefHash          `json:"ref_hash"`
}

// An ExpandWithLabel known answer: every argument, and the bytes it must produce.
type labelKatExpandWithLabel struct {
	Secret  string `json:"secret"`
	Label   string `json:"label"`
	Context string `json:"context"`
	Length  int    `json:"length"`
	Out     string `json:"out"`
}

// A DeriveSecret known answer. There is no length field, because the output is Nh.
type labelKatDeriveSecret struct {
	Secret string `json:"secret"`
	Label  string `json:"label"`
	Out    string `json:"out"`
}

// A DeriveTreeSecret known answer, generation included.
type labelKatDeriveTreeSecret struct {
	Secret     string `json:"secret"`
	Label      string `json:"label"`
	Generation uint32 `json:"generation"`
	Length     int    `json:"length"`
	Out        string `json:"out"`
}

// A RefHash known answer. The published label is the bare string "RefHash" with no
// "MLS 1.0 " prefix, which is what says RefHash must not add one: its callers carry
// theirs. The value is 32 bytes, inside the one byte length prefix, so this entry pins
// which bytes are hashed but not how a longer field is framed. welcome.json is what does
// that.
type labelKatRefHash struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Out   string `json:"out"`
}

// One secret-tree entry. Only the single leaf entries are used, where the whole secret
// tree is one node and the root secret is the encryption secret unchanged, so a published
// generation is reachable without any tree math.
type labelKatSecretTree struct {
	CipherSuite      uint16                  `json:"cipher_suite"`
	EncryptionSecret string                  `json:"encryption_secret"`
	SenderData       labelKatSenderData      `json:"sender_data"`
	Leaves           [][]labelKatRatchetStep `json:"leaves"`
}

// The sender data key and nonce, derived from a sample of the ciphertext they protect.
// The sample is the first Nh bytes, which for both registered suites is 32 of the 77
// published ones, so a run that fed the whole ciphertext fails here.
type labelKatSenderData struct {
	SenderDataSecret string `json:"sender_data_secret"`
	Ciphertext       string `json:"ciphertext"`
	Key              string `json:"key"`
	Nonce            string `json:"nonce"`
}

// The published keys and nonces at one generation of one leaf's two ratchets.
type labelKatRatchetStep struct {
	Generation       uint32 `json:"generation"`
	HandshakeKey     string `json:"handshake_key"`
	HandshakeNonce   string `json:"handshake_nonce"`
	ApplicationKey   string `json:"application_key"`
	ApplicationNonce string `json:"application_nonce"`
}

// One key-schedule entry: the initial init secret and the epochs chained from it.
type labelKatSchedule struct {
	CipherSuite       uint16          `json:"cipher_suite"`
	InitialInitSecret string          `json:"initial_init_secret"`
	Epochs            []labelKatEpoch `json:"epochs"`
}

// One epoch of the key schedule. Only the fields reachable with this task's own
// primitives are read: the joiner and epoch secrets are ExpandWithLabel over the 112 byte
// group context, and the rest are DeriveSecret over the epoch secret.
type labelKatEpoch struct {
	GroupContext       string           `json:"group_context"`
	CommitSecret       string           `json:"commit_secret"`
	PskSecret          string           `json:"psk_secret"`
	JoinerSecret       string           `json:"joiner_secret"`
	WelcomeSecret      string           `json:"welcome_secret"`
	InitSecret         string           `json:"init_secret"`
	SenderDataSecret   string           `json:"sender_data_secret"`
	EncryptionSecret   string           `json:"encryption_secret"`
	ExporterSecret     string           `json:"exporter_secret"`
	ExternalSecret     string           `json:"external_secret"`
	ConfirmationKey    string           `json:"confirmation_key"`
	MembershipKey      string           `json:"membership_key"`
	ResumptionPsk      string           `json:"resumption_psk"`
	EpochAuthenticator string           `json:"epoch_authenticator"`
	Exporter           labelKatExporter `json:"exporter"`
}

// The published MLS-Exporter answer. The label is an ascii string that happens to be
// spelled in hex digits, and reading it as hex builds a different preimage that matches
// nothing, so the vector is also what says which reading is right.
type labelKatExporter struct {
	Label   string `json:"label"`
	Context string `json:"context"`
	Length  int    `json:"length"`
	Secret  string `json:"secret"`
}

// One welcome entry, reduced to the joiner's key package and the Welcome addressed to
// it. Both are published as serialized MLSMessages.
type labelKatWelcome struct {
	CipherSuite uint16 `json:"cipher_suite"`
	KeyPackage  string `json:"key_package"`
	Welcome     string `json:"welcome"`
}

// One passive client transcript, reduced to the epochs whose commits reference proposals.
type labelKatPassiveClient struct {
	CipherSuite uint16                 `json:"cipher_suite"`
	Epochs      []labelKatPassiveEpoch `json:"epochs"`
}

// One epoch of it: the proposals the client is handed, and the commit that names them.
type labelKatPassiveEpoch struct {
	Proposals []string `json:"proposals"`
	Commit    string   `json:"commit"`
}

// The four byte MLSMessage header the corpora put ahead of a KeyPackage and ahead of a
// PublicMessage: protocol version mls10, then the wire format (RFC 9420 section 6).
// Neither reference is taken over all of these bytes, and both headers are asserted
// rather than assumed, so a re-vendored corpus that changed shape fails where it changed
// instead of hashing a header into a reference.
var (
	mlsMessageKeyPackageHeader    = []byte{0x00, 0x01, 0x00, 0x05}
	mlsMessagePublicMessageHeader = []byte{0x00, 0x01, 0x00, 0x01}
)

// The protocol version field an MLSMessage opens with. It is the only part of that header
// which is not also part of the AuthenticatedContent a proposal reference is taken over.
const mlsMessageVersionLength = 2

// A vendored corpus, decoded. A missing or unparsable file is fatal rather than skipped:
// a corpus that is not there is the same silence as a corpus that agrees with everything.
func loadLabelKat(t *testing.T, name string, into any) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "vectors", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if err := json.Unmarshal(body, into); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
}

// A published answer, compared. The label says which construction and which suite moved,
// so a failure names the field rather than printing two hex strings.
func assertLabelKat(t *testing.T, what string, got []byte, wantHex string) {
	t.Helper()
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatalf("%s: the published answer is not hex: %v", what, err)
	}
	if len(want) == 0 {
		t.Fatalf("%s: the published answer is empty", what)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s = %x, want %x", what, got, want)
	}
}

// The number of comparisons each corpus must contribute, so a filter that quietly stopped
// matching fails instead of passing. crypto-basics publishes seven entries and two name a
// registered suite; secret-tree publishes twenty one and two are both registered and
// single leaf; key-schedule publishes seven and two are registered, five epochs each.
const (
	labelKatBasicsComparisons     = 6
	labelKatSecretTreeComparisons = 20
	labelKatScheduleComparisons   = 120
)

// The published references each reference corpus must contribute, counted for the same
// reason. crypto-basics publishes one RefHash answer per suite and two suites are
// registered; welcome.json publishes one Welcome per suite; the passive client corpus
// publishes thirteen transcripts per suite, one epoch of each references a single
// proposal, so twelve land per registered suite.
const (
	labelKatRefHashComparisons = 2
	labelKatKeyPackageRefs     = 2
	labelKatProposalRefs       = 24
)

// The generation the secret-tree corpus publishes beyond zero. It is a constant here
// rather than read from the file because it is the reason that corpus is used at all:
// 0x0000000f differs from its own byte reversal, so it separates a big endian generation
// from a little endian one. If upstream ever republishes at a palindromic generation this
// stops matching, and the coverage that was lost is visible instead of silent.
const labelKatAsymmetricGeneration = 15

func TestKdfLabelEncoding(t *testing.T) {
	// KDFLabel is { uint16 length; opaque label<V>; opaque context<V> } and the label
	// carries the "MLS 1.0 " prefix. MLS derives every secret from this preimage, so a
	// byte wrong here moves every key in the protocol. These rows are read off RFC 9420
	// section 5.1 rather than published, so the vector tests below are the authority and
	// this is what says which field moved when they fail.
	for _, testCase := range []struct {
		name    string
		label   string
		context []byte
		length  int
		want    []byte
	}{
		{
			name:    "two byte context",
			label:   "test",
			context: []byte{0xde, 0xad},
			length:  32,
			want: concatBytes([]byte{0x00, 0x20}, []byte{byte(len(MlsLabelPrefix + "test"))},
				[]byte(MlsLabelPrefix+"test"), []byte{0x02, 0xde, 0xad}),
		},
		{
			// an empty context still writes its length byte. this is the one shape a
			// DeriveSecret test cannot see, because with no context bytes the readings
			// "field omitted" and "field present and empty" differ only by this 0x00.
			name:    "empty context and empty label",
			label:   "",
			context: nil,
			length:  0,
			want: concatBytes([]byte{0x00, 0x00}, []byte{byte(len(MlsLabelPrefix))},
				[]byte(MlsLabelPrefix), []byte{0x00}),
		},
		{
			// the length is a big endian uint16. a uint8, a uint32 or a byte swap each
			// produce a preimage of an entirely plausible shape.
			name:    "length is a big endian uint16",
			label:   "x",
			context: nil,
			length:  0xbeef,
			want: concatBytes([]byte{0xbe, 0xef}, []byte{byte(len(MlsLabelPrefix + "x"))},
				[]byte(MlsLabelPrefix+"x"), []byte{0x00}),
		},
		{
			// a context of 64 bytes crosses into the two byte prefix, so a hand rolled
			// single byte length encodes 0x40 here and truncates the vector.
			name:    "context at the two byte prefix boundary",
			label:   "y",
			context: bytes.Repeat([]byte{0x5a}, 64),
			length:  16,
			want: concatBytes([]byte{0x00, 0x10}, []byte{byte(len(MlsLabelPrefix + "y"))},
				[]byte(MlsLabelPrefix+"y"), []byte{0x40, 0x40}, bytes.Repeat([]byte{0x5a}, 64)),
		},
	} {
		if got := mlsKdfLabel(testCase.label, testCase.context, testCase.length); !bytes.Equal(got, testCase.want) {
			t.Errorf("%s: mlsKdfLabel = %x, want %x", testCase.name, got, testCase.want)
		}
	}
}

// The expected encodings above, assembled, so a row reads as the fields of KDFLabel in
// order rather than as a chain of appends.
func concatBytes(parts ...[]byte) []byte {
	out := []byte{}
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

func TestOpaqueVectorBoundariesMatchSyntax(t *testing.T) {
	// the boundary conformance this plan owes the Syntax plan. if syntax's prefix widths
	// drift, every signature and every derived secret in this package moves, and it must
	// fail here rather than at an interop run.
	for _, testCase := range []struct {
		n      int
		prefix []byte
	}{
		{n: 0, prefix: []byte{0x00}},
		{n: 63, prefix: []byte{0x3f}},
		{n: 64, prefix: []byte{0x40, 0x40}},
		{n: 16383, prefix: []byte{0x7f, 0xff}},
		{n: 16384, prefix: []byte{0x80, 0x00, 0x40, 0x00}},
	} {
		writer := syntax.NewWriter()
		writer.WriteOpaque(make([]byte, testCase.n))
		encoded, err := writer.Bytes()
		if err != nil {
			t.Fatalf("length %d: %v", testCase.n, err)
		}
		if !bytes.HasPrefix(encoded, testCase.prefix) {
			t.Errorf("length %d encoded with prefix %x, want %x", testCase.n, encoded[:len(testCase.prefix)], testCase.prefix)
		}
		if len(encoded) != len(testCase.prefix)+testCase.n {
			t.Errorf("length %d encoded to %d bytes, want %d", testCase.n, len(encoded), len(testCase.prefix)+testCase.n)
		}
		// and it must read back as the same vector, so the two halves of the prefix
		// cannot drift apart in the same commit.
		back, err := syntax.NewReader(encoded).ReadOpaque()
		if err != nil {
			t.Fatalf("length %d read back: %v", testCase.n, err)
		}
		if len(back) != testCase.n {
			t.Errorf("length %d read back as %d bytes", testCase.n, len(back))
		}
	}
}

func TestLabelWriterUsesTheDefaultVectorLimit(t *testing.T) {
	// mlsLabelBytes panics rather than returning a short preimage, and this pins the
	// boundary at which it would: syntax.MaxVectorLength. every value that reaches a
	// labelled construction came through a decode or an encode already bounded by it, so
	// the panic is unreachable in production — but if that ever stops being true, it must
	// stop being true loudly.
	writer := syntax.NewWriter()
	writer.WriteOpaque(make([]byte, syntax.MaxVectorLength))
	if _, err := writer.Bytes(); err != nil {
		t.Fatalf("a vector of exactly MaxVectorLength was refused: %v", err)
	}
	overlong := syntax.NewWriter()
	overlong.WriteOpaque(make([]byte, syntax.MaxVectorLength+1))
	if _, err := overlong.Bytes(); err == nil {
		t.Fatalf("a vector of MaxVectorLength+1 was accepted")
	}
	// and the refusal reaches the caller as a panic rather than as a short preimage,
	// since a label describing more bytes than it carries is what a signature bypass is
	// built out of.
	if recovered := recoveredPanic(func() { mlsLabelBytes(overlong) }); recovered == nil {
		t.Fatalf("mlsLabelBytes returned a preimage its writer had already refused")
	}
	// the assertions above build their own writer, so none of them can see which limit
	// the label path chose for its own. these run through the constructions themselves,
	// at every field a caller's bytes flow into: a raised limit there accepts a field a
	// compliant reader refuses, and a lowered one refuses a preimage the protocol
	// requires, and neither moves a byte of any published answer. it is also where a
	// hand rolled length prefix stops, since a uint8 written ahead of a raw field agrees
	// with WriteOpaque below 64 bytes and consults no limit at all.
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	for _, testCase := range []struct {
		name string
		room int
		call func(n int)
	}{
		{
			name: "the kdf label's context field",
			room: syntax.MaxVectorLength,
			call: func(n int) { mlsKdfLabel("label", make([]byte, n), 32) },
		},
		{
			// the kdf label carries the "MLS 1.0 " prefix as well, so its own boundary
			// sits that many bytes below the limit
			name: "the kdf label's label field",
			room: syntax.MaxVectorLength - len(MlsLabelPrefix),
			call: func(n int) { mlsKdfLabel(strings.Repeat("x", n), nil, 32) },
		},
		{
			// RefHash adds nothing to the label it is handed, so both of its fields
			// reach the whole limit
			name: "the ref hash label field",
			room: syntax.MaxVectorLength,
			call: func(n int) { RefHash(crypto, strings.Repeat("x", n), nil) },
		},
		{
			name: "the ref hash value field",
			room: syntax.MaxVectorLength,
			call: func(n int) { RefHash(crypto, "label", make([]byte, n)) },
		},
	} {
		if recovered := recoveredPanic(func() { testCase.call(testCase.room) }); recovered != nil {
			t.Errorf("a labelled construction refused %s at the limit: %v", testCase.name, recovered)
		}
		if recovered := recoveredPanic(func() { testCase.call(testCase.room + 1) }); recovered == nil {
			t.Errorf("a labelled construction accepted %s one byte past the limit", testCase.name)
		}
	}
}

// Every way this package enters the codec, and the limit each entry carries.
//
// The behavioural half above reaches only the fields a caller's bytes flow into.
// DeriveTreeSecret's writer takes a uint32 and nothing else, and WriteUint32 never
// consults maxVectorLength, so no input can tell that writer's limit from any other —
// which is the shape of a mutation that survives an entire package's tests. What pins it
// instead is the constructor, read out of the source: MLS caps every field at
// MaxVectorLength, only the ratchet tree paths pass MaxRatchetTreeLength, and nothing
// here is a ratchet tree.
//
// The list is every syntax call in the package's non test source rather than the ones
// this file makes, and it is pinned whole rather than filtered by name. A later task that
// adds a construction adds a line here, which is the point: a raised limit is a decision
// somebody has to write down, and syntax offers a Limit variant of every entry point.
func TestEverySyntaxEncoderInThisPackageUsesTheDefaultLimit(t *testing.T) {
	entered := []string{}
	for _, path := range packageSourcePaths(t) {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		for _, call := range mustParseSource(t, path).callsToPackage("syntax") {
			entered = append(entered, path+": "+call)
		}
	}
	want := []string{
		"crypto_labels.go: syntax.NewWriter()",
		"crypto_labels.go: syntax.NewWriter()",
		"crypto_labels.go: syntax.NewWriter()",
	}
	if !slices.Equal(entered, want) {
		t.Errorf("this package enters the codec at %v, want %v", entered, want)
	}
	// and the matcher reports a raised limit as the different call it is, rather than
	// reading every constructor as the default one
	control := mustParseText(t, "the raised limit control", raisedWriterLimitControl)
	if calls := control.callsToPackage("syntax"); !slices.Equal(calls, []string{"syntax.NewWriterLimit(syntax.MaxRatchetTreeLength)"}) {
		t.Errorf("the matcher read %v out of a control building one raised writer", calls)
	}
}

// A labelled construction whose writer would accept a field sixteen times longer than any
// MLS structure permits. Every matcher above runs on this as well, so one that stopped
// matching fails here rather than issuing the real file a clean bill.
const raisedWriterLimitControl = `package mls

func mlsKdfLabel(label string, context []byte, length int) []byte {
	writer := syntax.NewWriterLimit(syntax.MaxRatchetTreeLength)
	writer.WriteUint16(uint16(length))
	return mlsLabelBytes(writer)
}
`

// Every preimage is storage of its own. These two are the only preimage builders in this
// file a caller cannot reach through the provider, so nothing else in the package can see
// them
// answer out of one reused array — and a reused array here is not merely a stale digest:
// mlsKdfLabel is on the path of every derivation, so two goroutines deriving at once
// would each expand over the other's preimage. There is no race detector on this machine
// to report that, so what says it cannot happen is that the storage is never shared.
func TestLabelPreimagesAreFreshBuffers(t *testing.T) {
	for _, testCase := range []struct {
		name string
		call func() []byte
	}{
		{name: "mlsLabelBytes", call: func() []byte {
			writer := syntax.NewWriter()
			writer.WriteOpaque([]byte("preimage"))
			return mlsLabelBytes(writer)
		}},
		{name: "mlsKdfLabel", call: func() []byte { return mlsKdfLabel("label", []byte("context"), 32) }},
	} {
		first, second := testCase.call(), testCase.call()
		if len(first) == 0 || len(second) == 0 {
			t.Errorf("%s returned nothing, so this shares nothing either", testCase.name)
			continue
		}
		if &first[0] == &second[0] {
			t.Errorf("two calls to %s returned the same storage", testCase.name)
			continue
		}
		held := bytes.Clone(first)
		// a third call with a longer argument, since a cache that reallocates for a
		// bigger answer leaves the first result intact and only a same sized one moves it
		mlsKdfLabel("a much longer label than the first", bytes.Repeat([]byte{0x7e}, 96), 48)
		testCase.call()
		if !bytes.Equal(first, held) {
			t.Errorf("a preimage from %s changed from %x to %x when it was called again",
				testCase.name, held, first)
		}
	}
}

func TestDeriveSecretIsExpandWithEmptyContext(t *testing.T) {
	// this pair is self referential on purpose and cannot see a dropped context field: an
	// implementation that never wrote the context at all satisfies both sides of the
	// equality. what separates the two readings is the empty context row of
	// TestKdfLabelEncoding and the published derive_secret answers in
	// TestLabelledKdfMatchesTheCryptoBasicsVectors, where the missing 0x00 moves the
	// preimage and therefore every output byte.
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	secret := bytes.Repeat([]byte{0x10}, 32)
	if got, want := crypto.DeriveSecret(secret, "epoch"), crypto.ExpandWithLabel(secret, "epoch", nil, 32); !bytes.Equal(got, want) {
		t.Fatalf("DeriveSecret = %x, want %x", got, want)
	}
	if n := len(crypto.DeriveSecret(secret, "epoch")); n != crypto.HashSize() {
		t.Fatalf("DeriveSecret returned %d bytes, want %d", n, crypto.HashSize())
	}
	// a nil context and an empty one are one call, since callers reach this from both
	// directions and a length prefixed empty vector has one encoding.
	if !bytes.Equal(crypto.ExpandWithLabel(secret, "epoch", nil, 32), crypto.ExpandWithLabel(secret, "epoch", []byte{}, 32)) {
		t.Fatalf("a nil context and an empty context derived different secrets")
	}
}

func TestDeriveTreeSecretPutsGenerationInContext(t *testing.T) {
	// the generation is the whole context, written as four big endian bytes. the literal
	// on the right is what lets this see a byte swap: 0xa0b0c0d0 differs from its own
	// reversal, unlike the 0xa0a0a0a0 every published crypto-basics vector carries. the
	// published half of the same claim is
	// TestDeriveTreeSecretGenerationIsBigEndianInTheSecretTreeVectors.
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	secret := bytes.Repeat([]byte{0x11}, 32)
	generation := uint32(0xa0b0c0d0)
	got := crypto.DeriveTreeSecret(secret, "handshake", generation, 32)
	want := crypto.ExpandWithLabel(secret, "handshake", []byte{0xa0, 0xb0, 0xc0, 0xd0}, 32)
	if !bytes.Equal(got, want) {
		t.Fatalf("DeriveTreeSecret = %x, want %x — the generation is not a big-endian uint32 context", got, want)
	}
	if bytes.Equal(got, crypto.DeriveTreeSecret(secret, "handshake", generation+1, 32)) {
		t.Fatalf("consecutive generations derive the same secret")
	}
	// generation zero is not the same as no generation. an implementation that dropped
	// the context agrees with an empty one here and disagrees with every published byte.
	if bytes.Equal(crypto.DeriveTreeSecret(secret, "handshake", 0, 32), crypto.ExpandWithLabel(secret, "handshake", nil, 32)) {
		t.Fatalf("generation 0 derived the same secret as an absent context")
	}
	// the generation is four bytes wide whatever its value, so a uint8 or a uint16
	// encoding agrees with the low bytes of every vector and collides here.
	if bytes.Equal(crypto.DeriveTreeSecret(secret, "handshake", 0x00000001, 32), crypto.DeriveTreeSecret(secret, "handshake", 0x01000001, 32)) {
		t.Fatalf("generations differing above the low byte derive the same secret")
	}
}

// A suite whose Nh agrees with nothing else about it. Both registered suites fix Nh, Nk
// on 0x0003, Nsecret, Nenc, Npk, Nsk, NsigPub and NsigPriv at 32, so within the registry
// the hash size and seven other parameters and the literal 32 are one number, and a
// DeriveSecret written against any of them derives exactly what one written against Nh
// derives. RFC 9420 registers five further suites at Nh 48 and 64, and on one of those the
// same code returns a secret shorter than the suite claims while reporting success.
//
// Nothing in the registry can see that, so this provider is assembled rather than looked
// up. Every other length is distinct from Nh and from the secret's own length, which is
// what makes each substitution a different number rather than the same one.
var labelKatSyntheticParams = SuiteParams{
	Suite:       CipherSuite(0xfffe),
	Name:        "synthetic_nh48",
	KemId:       HpkeKemX25519HkdfSha256,
	KdfId:       HpkeKdfHkdfSha256,
	AeadId:      HpkeAeadChaCha20Poly1305,
	SignatureId: SignatureSchemeEd25519,
	Nh:          48,
	Nk:          32,
	Nn:          12,
	Nt:          16,
	Nsecret:     17,
	Nenc:        18,
	Npk:         19,
	Nsk:         20,
	NsigPub:     21,
	NsigPriv:    22,
}

func TestDeriveSecretLengthIsTheSuitesHashSize(t *testing.T) {
	crypto := &suiteCryptoProvider{params: &labelKatSyntheticParams, random: rand.Reader}
	// longer than Nh so Expand's short pseudorandom key guard is not what is being
	// measured here, and a different length from Nh so len(secret) is not Nh either.
	secret := bytes.Repeat([]byte{0x13}, 64)
	got := crypto.DeriveSecret(secret, "epoch")
	if len(got) != labelKatSyntheticParams.Nh {
		t.Fatalf("DeriveSecret returned %d bytes for a suite whose Nh is %d", len(got), labelKatSyntheticParams.Nh)
	}
	// and the length in the preimage moved with it, so this is the suite's hash size in
	// both places rather than only in the size of the answer.
	if want := crypto.ExpandWithLabel(secret, "epoch", nil, labelKatSyntheticParams.Nh); !bytes.Equal(got, want) {
		t.Fatalf("DeriveSecret = %x, want %x", got, want)
	}
	for _, other := range []struct {
		name  string
		value int
	}{
		{name: "Nk", value: labelKatSyntheticParams.Nk},
		{name: "Nn", value: labelKatSyntheticParams.Nn},
		{name: "Nt", value: labelKatSyntheticParams.Nt},
		{name: "Nsecret", value: labelKatSyntheticParams.Nsecret},
		{name: "Nenc", value: labelKatSyntheticParams.Nenc},
		{name: "Npk", value: labelKatSyntheticParams.Npk},
		{name: "Nsk", value: labelKatSyntheticParams.Nsk},
		{name: "NsigPub", value: labelKatSyntheticParams.NsigPub},
		{name: "NsigPriv", value: labelKatSyntheticParams.NsigPriv},
		{name: "the registry's own hash size", value: 32},
		{name: "the secret's length", value: len(secret)},
	} {
		if other.value == labelKatSyntheticParams.Nh {
			t.Errorf("%s is %d, the same as Nh, so substituting it here would change nothing", other.name, other.value)
		}
	}
}

func TestExpandWithLabelSeparatesLabels(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	secret := bytes.Repeat([]byte{0x12}, 32)
	// the pair that would collide under naive concatenation: "ab" ‖ "c" vs "a" ‖ "bc".
	if bytes.Equal(crypto.ExpandWithLabel(secret, "ab", []byte("c"), 32),
		crypto.ExpandWithLabel(secret, "a", []byte("bc"), 32)) {
		t.Fatalf("label and context are not length separated")
	}
	// and the two arguments are not interchangeable. this arm cannot fail while the
	// prefix rides on the label: "MLS 1.0 ab" against "MLS 1.0 cd" separates the two
	// calls whichever order the fields are written in, so a transposed pair of writes
	// passes here. it is kept as the statement of the property and not as coverage of it
	// — what sees a transposition is TestKdfLabelEncoding, which pins the field order to
	// bytes, and the three published corpora below.
	if bytes.Equal(crypto.ExpandWithLabel(secret, "ab", []byte("cd"), 32),
		crypto.ExpandWithLabel(secret, "cd", []byte("ab"), 32)) {
		t.Fatalf("label and context are interchangeable")
	}
}

func TestLabelledKdfMatchesTheCryptoBasicsVectors(t *testing.T) {
	// the published answers for exactly the three functions of this file. these are the
	// only assertions in the package that can tell the "MLS 1.0 " prefix from any other
	// eight bytes, or from none at all.
	vectors := []labelKatBasics{}
	loadLabelKat(t, "crypto-basics.json", &vectors)
	compared := 0
	for _, vector := range vectors {
		suite := CipherSuite(vector.CipherSuite)
		if !IsRegisteredSuite(suite) {
			continue
		}
		crypto := mustProvider(t, suite)
		at := fmt.Sprintf(" suite %#04x", uint16(suite))
		expand := vector.ExpandWithLabel
		assertLabelKat(t, "expand_with_label"+at,
			crypto.ExpandWithLabel(mustDecodeHex(t, "secret", expand.Secret), expand.Label,
				mustDecodeHex(t, "context", expand.Context), expand.Length),
			expand.Out)
		derive := vector.DeriveSecret
		assertLabelKat(t, "derive_secret"+at,
			crypto.DeriveSecret(mustDecodeHex(t, "secret", derive.Secret), derive.Label),
			derive.Out)
		tree := vector.DeriveTreeSecret
		assertLabelKat(t, "derive_tree_secret"+at,
			crypto.DeriveTreeSecret(mustDecodeHex(t, "secret", tree.Secret), tree.Label, tree.Generation, tree.Length),
			tree.Out)
		compared += 3
	}
	if compared != labelKatBasicsComparisons {
		t.Fatalf("compared %d crypto-basics answers, want %d", compared, labelKatBasicsComparisons)
	}
}

func TestDeriveTreeSecretGenerationIsBigEndianInTheSecretTreeVectors(t *testing.T) {
	// the published pin on the generation's byte order, which crypto-basics cannot
	// supply. a single leaf secret tree is one node, so the root secret is the encryption
	// secret unchanged and the two ratchets hang directly off it (RFC 9420 section 9):
	//
	//	ratchet_[0]   = ExpandWithLabel(encryption_secret, "handshake"|"application", "", Nh)
	//	key_[j]       = DeriveTreeSecret(ratchet_[j], "key",    j, Nk)
	//	nonce_[j]     = DeriveTreeSecret(ratchet_[j], "nonce",  j, Nn)
	//	ratchet_[j+1] = DeriveTreeSecret(ratchet_[j], "secret", j, Nh)
	//
	// walking to generation 15 puts fifteen distinct generations into fifteen distinct
	// preimages, so an encoding wrong at any one of them moves the published key at the
	// end. the ratchet roots are also the only published ExpandWithLabel answers with an
	// empty context, which is what holds the empty context's own length byte.
	vectors := []labelKatSecretTree{}
	loadLabelKat(t, "secret-tree.json", &vectors)
	compared := 0
	sawAsymmetric := false
	for _, vector := range vectors {
		suite := CipherSuite(vector.CipherSuite)
		if !IsRegisteredSuite(suite) || len(vector.Leaves) != 1 {
			continue
		}
		crypto := mustProvider(t, suite)
		params, err := LookupSuite(suite)
		if err != nil {
			t.Fatalf("LookupSuite(%#04x): %v", uint16(suite), err)
		}
		at := fmt.Sprintf(" suite %#04x", uint16(suite))
		sample := mustDecodeHex(t, "ciphertext", vector.SenderData.Ciphertext)[:crypto.HashSize()]
		senderSecret := mustDecodeHex(t, "sender_data_secret", vector.SenderData.SenderDataSecret)
		assertLabelKat(t, "sender_data key"+at,
			crypto.ExpandWithLabel(senderSecret, "key", sample, params.Nk), vector.SenderData.Key)
		assertLabelKat(t, "sender_data nonce"+at,
			crypto.ExpandWithLabel(senderSecret, "nonce", sample, params.Nn), vector.SenderData.Nonce)
		compared += 2

		published := map[uint32]labelKatRatchetStep{}
		highest := uint32(0)
		for _, step := range vector.Leaves[0] {
			published[step.Generation] = step
			if step.Generation > highest {
				highest = step.Generation
			}
			if step.Generation == labelKatAsymmetricGeneration {
				sawAsymmetric = true
			}
		}
		for _, ratchet := range []struct {
			label string
			key   func(step labelKatRatchetStep) string
			nonce func(step labelKatRatchetStep) string
		}{
			{
				label: "handshake",
				key:   func(step labelKatRatchetStep) string { return step.HandshakeKey },
				nonce: func(step labelKatRatchetStep) string { return step.HandshakeNonce },
			},
			{
				label: "application",
				key:   func(step labelKatRatchetStep) string { return step.ApplicationKey },
				nonce: func(step labelKatRatchetStep) string { return step.ApplicationNonce },
			},
		} {
			root := mustDecodeHex(t, "encryption_secret", vector.EncryptionSecret)
			secret := crypto.ExpandWithLabel(root, ratchet.label, nil, crypto.HashSize())
			for generation := uint32(0); generation <= highest; generation++ {
				if step, ok := published[generation]; ok {
					where := fmt.Sprintf("%s generation %d%s", ratchet.label, generation, at)
					assertLabelKat(t, where+" key",
						crypto.DeriveTreeSecret(secret, "key", generation, params.Nk), ratchet.key(step))
					assertLabelKat(t, where+" nonce",
						crypto.DeriveTreeSecret(secret, "nonce", generation, params.Nn), ratchet.nonce(step))
					compared += 2
				}
				secret = crypto.DeriveTreeSecret(secret, "secret", generation, crypto.HashSize())
			}
		}
	}
	if compared != labelKatSecretTreeComparisons {
		t.Fatalf("compared %d secret-tree answers, want %d", compared, labelKatSecretTreeComparisons)
	}
	if !sawAsymmetric {
		t.Fatalf("no published generation %d, so nothing here separates a big endian generation from a little endian one", labelKatAsymmetricGeneration)
	}
}

func TestExpandWithLabelMatchesTheKeyScheduleVectors(t *testing.T) {
	// the published pin on a context longer than 63 bytes. the group context is 112
	// bytes, so the label's context field takes the two byte prefix here and the one byte
	// prefix in every other vector this package holds. a hand rolled single byte length
	// agrees everywhere else and fails here.
	//
	// the key schedule itself belongs to a later plan. what is consumed is only the steps
	// this task's own primitives compute:
	//
	//	joiner_secret  = ExpandWithLabel(Extract(init_secret_prev, commit_secret), "joiner", group_context, Nh)
	//	member_secret  = Extract(joiner_secret, psk_secret)
	//	welcome_secret = DeriveSecret(member_secret, "welcome")
	//	epoch_secret   = ExpandWithLabel(member_secret, "epoch", group_context, Nh)
	//	<named>        = DeriveSecret(epoch_secret, <label>)
	//	exporter       = ExpandWithLabel(DeriveSecret(exporter_secret, label), "exported", Hash(context), length)
	vectors := []labelKatSchedule{}
	loadLabelKat(t, "key-schedule.json", &vectors)
	compared := 0
	longestContext := 0
	for _, vector := range vectors {
		suite := CipherSuite(vector.CipherSuite)
		if !IsRegisteredSuite(suite) {
			continue
		}
		crypto := mustProvider(t, suite)
		previousInit := mustDecodeHex(t, "initial_init_secret", vector.InitialInitSecret)
		for index, epoch := range vector.Epochs {
			at := fmt.Sprintf(" suite %#04x epoch %d", uint16(suite), index)
			groupContext := mustDecodeHex(t, "group_context", epoch.GroupContext)
			if len(groupContext) > longestContext {
				longestContext = len(groupContext)
			}
			joiner := crypto.ExpandWithLabel(
				crypto.Extract(previousInit, mustDecodeHex(t, "commit_secret", epoch.CommitSecret)),
				"joiner", groupContext, crypto.HashSize())
			assertLabelKat(t, "joiner_secret"+at, joiner, epoch.JoinerSecret)
			member := crypto.Extract(joiner, mustDecodeHex(t, "psk_secret", epoch.PskSecret))
			assertLabelKat(t, "welcome_secret"+at, crypto.DeriveSecret(member, "welcome"), epoch.WelcomeSecret)
			epochSecret := crypto.ExpandWithLabel(member, "epoch", groupContext, crypto.HashSize())
			compared += 2
			for _, derived := range []struct {
				label string
				want  string
			}{
				{label: "sender data", want: epoch.SenderDataSecret},
				{label: "encryption", want: epoch.EncryptionSecret},
				{label: "exporter", want: epoch.ExporterSecret},
				{label: "external", want: epoch.ExternalSecret},
				{label: "confirm", want: epoch.ConfirmationKey},
				{label: "membership", want: epoch.MembershipKey},
				{label: "resumption", want: epoch.ResumptionPsk},
				{label: "authentication", want: epoch.EpochAuthenticator},
				{label: "init", want: epoch.InitSecret},
			} {
				assertLabelKat(t, "derive_secret "+derived.label+at,
					crypto.DeriveSecret(epochSecret, derived.label), derived.want)
				compared++
			}
			exporter := epoch.Exporter
			assertLabelKat(t, "exporter"+at,
				crypto.ExpandWithLabel(
					crypto.DeriveSecret(mustDecodeHex(t, "exporter_secret", epoch.ExporterSecret), exporter.Label),
					"exported", crypto.Hash(mustDecodeHex(t, "exporter context", exporter.Context)), exporter.Length),
				exporter.Secret)
			compared++
			previousInit = mustDecodeHex(t, "init_secret", epoch.InitSecret)
		}
	}
	if compared != labelKatScheduleComparisons {
		t.Fatalf("compared %d key-schedule answers, want %d", compared, labelKatScheduleComparisons)
	}
	if longestContext <= 63 {
		t.Fatalf("the longest published group context is %d bytes, so nothing here reaches the two byte length prefix", longestContext)
	}
}

func TestRefHashDoesNotAddTheMlsPrefix(t *testing.T) {
	// RefHash takes the whole label. MakeKeyPackageRef hands it
	// "MLS 1.0 KeyPackage Reference" already prefixed, and the crypto-basics vector
	// hands it the bare string "RefHash" that must not gain one, so adding the prefix
	// inside RefHash would pass every round trip in this package and fail the vector and
	// every peer.
	//
	// Both halves below build their expected preimage with the same writer RefHash uses,
	// so this separates a prefixed label from a bare one and nothing else: a dropped or
	// narrowed length prefix agrees with itself on both sides. The published corpora are
	// what see that.
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	value := []byte("the value")

	bare := syntax.NewWriter()
	bare.WriteOpaque([]byte("RefHash"))
	bare.WriteOpaque(value)
	input, err := bare.Bytes()
	if err != nil {
		t.Fatalf("encode the bare label input: %v", err)
	}
	if got, want := RefHash(crypto, "RefHash", value), crypto.Hash(input); !bytes.Equal(got, want) {
		t.Fatalf("RefHash = %x, want %x", got, want)
	}

	writer := syntax.NewWriter()
	writer.WriteOpaque([]byte(MlsLabelPrefix + "RefHash"))
	writer.WriteOpaque(value)
	prefixed, err := writer.Bytes()
	if err != nil {
		t.Fatalf("encode the prefixed label input: %v", err)
	}
	if bytes.Equal(RefHash(crypto, "RefHash", value), crypto.Hash(prefixed)) {
		t.Fatalf("RefHash added the MLS 1.0 prefix")
	}
}

func TestRefLabelsAreTheRfcStrings(t *testing.T) {
	// RFC 9420 section 5.2 spells both labels out with the prefix already inside them.
	// This holds the constants to that text, and it is the weakest of the three pins on
	// them: both sides of each comparison are strings this project typed, so a label
	// misspelled the same way in crypto_labels.go and here passes. What separates that
	// reading is TestKeyPackageRefLabelMatchesThePublishedWelcomes and
	// TestProposalRefLabelMatchesThePublishedCommits, where the digest came from
	// somebody else's implementation.
	if KeyPackageRefLabel != "MLS 1.0 KeyPackage Reference" {
		t.Errorf("KeyPackageRefLabel = %q", KeyPackageRefLabel)
	}
	if ProposalRefLabel != "MLS 1.0 Proposal Reference" {
		t.Errorf("ProposalRefLabel = %q", ProposalRefLabel)
	}
	// and they are two labels rather than one written twice, which no comparison of a
	// reference against itself can see
	if KeyPackageRefLabel == ProposalRefLabel {
		t.Errorf("the two reference labels are the same string %q", KeyPackageRefLabel)
	}
}

func TestKeyPackageRefAndProposalRefDiffer(t *testing.T) {
	// the same bytes referenced as a key package and as a proposal must not collide,
	// which is the entire reason the two labels exist. a maker that shared a label with
	// the other still returns 32 bytes, still returns them deterministically and still
	// separates different inputs, so nothing weaker than a comparison of the two makers
	// over one input can see it.
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	value := bytes.Repeat([]byte{0x13}, 64)
	keyPackageRef := MakeKeyPackageRef(crypto, value)
	proposalRef := MakeProposalRef(crypto, value)
	if bytes.Equal(keyPackageRef, proposalRef) {
		t.Fatalf("key package and proposal references collide")
	}
	if len(keyPackageRef) != crypto.HashSize() || len(proposalRef) != crypto.HashSize() {
		t.Fatalf("reference sizes are %d/%d, want %d", len(keyPackageRef), len(proposalRef), crypto.HashSize())
	}
	// and each maker is its own label rather than the other's, which the inequality above
	// holds just as well when the two are swapped
	if !bytes.Equal(keyPackageRef, RefHash(crypto, KeyPackageRefLabel, value)) {
		t.Fatalf("MakeKeyPackageRef is not RefHash with the key package label")
	}
	if !bytes.Equal(proposalRef, RefHash(crypto, ProposalRefLabel, value)) {
		t.Fatalf("MakeProposalRef is not RefHash with the proposal label")
	}
}

func TestRefHashMatchesTheCryptoBasicsVectors(t *testing.T) {
	// the published RefHashInput encoding. every assertion above builds its expected
	// preimage with the writer under test, so a dropped label length, a dropped value
	// length or a transposition of the two fields agrees with all of them; these are the
	// bytes this project did not compute.
	vectors := []labelKatBasics{}
	loadLabelKat(t, "crypto-basics.json", &vectors)
	compared := 0
	for _, vector := range vectors {
		suite := CipherSuite(vector.CipherSuite)
		if !IsRegisteredSuite(suite) {
			continue
		}
		crypto := mustProvider(t, suite)
		refHash := vector.RefHash
		assertLabelKat(t, fmt.Sprintf("ref_hash suite %#04x", uint16(suite)),
			RefHash(crypto, refHash.Label, mustDecodeHex(t, "value", refHash.Value)),
			refHash.Out)
		// the corpus publishes the bare label, which is the other half of why RefHash
		// must not add the prefix: if upstream ever republished a prefixed one, the
		// comparison above would still pass against an implementation that added its own
		if strings.HasPrefix(refHash.Label, MlsLabelPrefix) {
			t.Errorf("suite %#04x publishes ref_hash under the prefixed label %q, so this corpus no longer says RefHash takes a bare one",
				uint16(suite), refHash.Label)
		}
		compared++
	}
	if compared != labelKatRefHashComparisons {
		t.Fatalf("compared %d published ref_hash answers, want %d", compared, labelKatRefHashComparisons)
	}
}

func TestKeyPackageRefLabelMatchesThePublishedWelcomes(t *testing.T) {
	// the key package reference label, pinned to a digest this project did not compute.
	// EncryptedGroupSecrets.new_member is MakeKeyPackageRef over the KeyPackage the
	// Welcome is addressed to (RFC 9420 sections 5.2 and 12.4.3.1), so the reference the
	// generator wrote is in the published Welcome bytes and nothing but the right label
	// over the right encoding reproduces it.
	//
	// It is the only assertion in this package that can see a label misspelled
	// consistently, a swapped pair of labels, or a hand rolled one byte length prefix:
	// the crypto-basics value is 32 bytes and its label is 7, both inside that prefix,
	// while these key packages are hundreds of bytes long.
	vectors := []labelKatWelcome{}
	loadLabelKat(t, "welcome.json", &vectors)
	found := 0
	for _, vector := range vectors {
		suite := CipherSuite(vector.CipherSuite)
		if !IsRegisteredSuite(suite) {
			continue
		}
		crypto := mustProvider(t, suite)
		message := mustDecodeHex(t, "the published key package", vector.KeyPackage)
		welcome := mustDecodeHex(t, "the published welcome", vector.Welcome)
		// the corpus publishes the key package wrapped in an MLSMessage and the
		// reference is over the KeyPackage inside it, so the header comes off first
		if len(message) <= len(mlsMessageKeyPackageHeader) || !bytes.HasPrefix(message, mlsMessageKeyPackageHeader) {
			t.Errorf("suite %#04x publishes a key package of %d bytes headed %x, want the mls10 key package header %x",
				uint16(suite), len(message), message[:min(len(message), len(mlsMessageKeyPackageHeader))], mlsMessageKeyPackageHeader)
			continue
		}
		keyPackage := message[len(mlsMessageKeyPackageHeader):]
		if len(keyPackage) < 64 {
			t.Errorf("suite %#04x publishes a key package of %d bytes, which is inside the one byte length prefix and cannot see a hand rolled one",
				uint16(suite), len(keyPackage))
			continue
		}
		reference := MakeKeyPackageRef(crypto, keyPackage)
		if count := bytes.Count(welcome, reference); count != 1 {
			t.Errorf("suite %#04x: the key package reference %x appears %d times in the published welcome, want once",
				uint16(suite), reference, count)
			continue
		}
		// and the proposal label over the same bytes is not what the Welcome carries,
		// so this fails on a swap rather than finding the reference either way
		if bytes.Contains(welcome, MakeProposalRef(crypto, keyPackage)) {
			t.Errorf("suite %#04x: the published welcome carries the proposal labelled reference of its key package", uint16(suite))
		}
		found++
	}
	if found != labelKatKeyPackageRefs {
		t.Fatalf("found %d published key package references, want %d", found, labelKatKeyPackageRefs)
	}
}

func TestProposalRefLabelMatchesThePublishedCommits(t *testing.T) {
	// the proposal reference label, pinned the same way. a Commit names each by reference
	// proposal as MakeProposalRef over the AuthenticatedContent that framed it (RFC 9420
	// sections 5.2 and 12.4), and passive-client-handling-commit.json publishes both
	// halves: the proposal as an MLSMessage and the commit that references it.
	//
	// The AuthenticatedContent is reachable from the published PublicMessage without any
	// framing code, which this plan does not own:
	//
	//	AuthenticatedContent = wire_format ‖ FramedContent ‖ FramedContentAuthData
	//	MLSMessage           = version ‖ wire_format ‖ FramedContent ‖
	//	                       FramedContentAuthData ‖ membership_tag<V>
	//
	// so it is the published message without its two byte version and without the
	// trailing membership tag (RFC 9420 sections 6.1 and 6.2). Every step of that is
	// asserted below rather than assumed, and a wrong slicing cannot agree with anything:
	// the reference either lands in the commit bytes or it does not.
	vectors := []labelKatPassiveClient{}
	loadLabelKat(t, "passive-client-handling-commit.json", &vectors)
	found := 0
	for _, vector := range vectors {
		suite := CipherSuite(vector.CipherSuite)
		if !IsRegisteredSuite(suite) {
			continue
		}
		crypto := mustProvider(t, suite)
		// the membership tag is a mac of the suite's hash size carried as a vector, and
		// at 32 bytes its length prefix is the one byte form
		membershipTag := 1 + crypto.HashSize()
		for epochIndex, epoch := range vector.Epochs {
			commit := mustDecodeHex(t, "the published commit", epoch.Commit)
			for _, published := range epoch.Proposals {
				at := fmt.Sprintf("suite %#04x epoch %d", uint16(suite), epochIndex)
				message := mustDecodeHex(t, "the published proposal", published)
				if len(message) <= len(mlsMessagePublicMessageHeader)+membershipTag ||
					!bytes.HasPrefix(message, mlsMessagePublicMessageHeader) {
					t.Errorf("%s: the proposal is %d bytes headed %x, want an mls10 public message",
						at, len(message), message[:min(len(message), len(mlsMessagePublicMessageHeader))])
					continue
				}
				if tag := message[len(message)-membershipTag]; int(tag) != crypto.HashSize() {
					t.Errorf("%s: the proposal ends in a vector of %d bytes, want the %d byte membership tag",
						at, tag, crypto.HashSize())
					continue
				}
				authenticatedContent := message[mlsMessageVersionLength : len(message)-membershipTag]
				reference := MakeProposalRef(crypto, authenticatedContent)
				if count := bytes.Count(commit, reference); count != 1 {
					t.Errorf("%s: the proposal reference %x appears %d times in the published commit, want once",
						at, reference, count)
					continue
				}
				// and the key package label over the same content is not what the commit
				// carries, so a swapped pair fails here rather than matching either way
				if bytes.Contains(commit, MakeKeyPackageRef(crypto, authenticatedContent)) {
					t.Errorf("%s: the published commit carries the key package labelled reference of a proposal", at)
				}
				found++
			}
		}
	}
	if found != labelKatProposalRefs {
		t.Fatalf("found %d published proposal references, want %d", found, labelKatProposalRefs)
	}
}
