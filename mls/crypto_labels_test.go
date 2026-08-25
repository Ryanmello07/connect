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
// something. The digests of all five are pinned by TestVectorFilesArePinned in
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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// One crypto-basics entry, reduced to the six constructions this file owns, which is now
// every field the published object carries.
type labelKatBasics struct {
	CipherSuite      uint16                   `json:"cipher_suite"`
	ExpandWithLabel  labelKatExpandWithLabel  `json:"expand_with_label"`
	DeriveSecret     labelKatDeriveSecret     `json:"derive_secret"`
	DeriveTreeSecret labelKatDeriveTreeSecret `json:"derive_tree_secret"`
	RefHash          labelKatRefHash          `json:"ref_hash"`
	SignWithLabel    labelKatSignWithLabel    `json:"sign_with_label"`
	EncryptWithLabel labelKatEncryptWithLabel `json:"encrypt_with_label"`
}

// An EncryptWithLabel known answer: the recipient's key pair, the label and context the
// message was sealed under, and the message itself.
//
// It is a known answer in the opening direction only. Sealing draws a fresh ephemeral key,
// so no published ciphertext can be reproduced by running EncryptWithLabel, and what this
// entry pins is that DecryptWithLabel rebuilds the EncryptContext the publisher sealed
// under. That makes it the only thing in this file which can see whether the context
// travels in the hpke info or in the aead's aad: both round trip against themselves, and
// only one of them opens this message.
type labelKatEncryptWithLabel struct {
	Label      string `json:"label"`
	Context    string `json:"context"`
	Priv       string `json:"priv"`
	Pub        string `json:"pub"`
	KemOutput  string `json:"kem_output"`
	Ciphertext string `json:"ciphertext"`
	Plaintext  string `json:"plaintext"`
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
// publishes thirteen transcripts per registered suite, of which six reference no proposal
// at all, six reference exactly one and one references six, so twelve land per suite.
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
		{
			name: "the sign content's content field",
			room: syntax.MaxVectorLength,
			call: func(n int) { mlsSignContent("label", make([]byte, n)) },
		},
		{
			// sign content carries the "MLS 1.0 " prefix as the kdf label does, so its
			// own boundary sits that many bytes below the limit
			name: "the sign content's label field",
			room: syntax.MaxVectorLength - len(MlsLabelPrefix),
			call: func(n int) { mlsSignContent(strings.Repeat("x", n), nil) },
		},
		{
			name: "the encrypt context's context field",
			room: syntax.MaxVectorLength,
			call: func(n int) { mlsEncryptContext("label", make([]byte, n)) },
		},
		{
			// and the same prefix again, so the encrypt context's label boundary sits
			// where the kdf label's and the sign content's do
			name: "the encrypt context's label field",
			room: syntax.MaxVectorLength - len(MlsLabelPrefix),
			call: func(n int) { mlsEncryptContext(strings.Repeat("x", n), nil) },
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
		// the proposal label over the same bytes is not what the Welcome carries, and
		// this is read before the count below rather than after it: the count reports
		// and moves on to the next suite, so a check written under it is one no failing
		// input ever reaches
		if bytes.Contains(welcome, MakeProposalRef(crypto, keyPackage)) {
			t.Errorf("suite %#04x: the published welcome carries the proposal labelled reference of its key package", uint16(suite))
		}
		reference := MakeKeyPackageRef(crypto, keyPackage)
		if count := bytes.Count(welcome, reference); count != 1 {
			t.Errorf("suite %#04x: the key package reference %x appears %d times in the published welcome, want once",
				uint16(suite), reference, count)
			continue
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
				// the key package label over the same content is not what the commit
				// carries, and this is read before the count below rather than after it:
				// the count reports and moves on to the next proposal, so a check written
				// under it is one no failing input ever reaches
				if bytes.Contains(commit, MakeKeyPackageRef(crypto, authenticatedContent)) {
					t.Errorf("%s: the published commit carries the key package labelled reference of a proposal", at)
				}
				reference := MakeProposalRef(crypto, authenticatedContent)
				if count := bytes.Count(commit, reference); count != 1 {
					t.Errorf("%s: the proposal reference %x appears %d times in the published commit, want once",
						at, reference, count)
					continue
				}
				found++
			}
		}
	}
	if found != labelKatProposalRefs {
		t.Fatalf("found %d published proposal references, want %d", found, labelKatProposalRefs)
	}
}

// A construction that takes a provider and is not held to using it, named with the reason.
// Nothing is excusable today; the map exists so that a construction which cannot be held
// is a line somebody writes on purpose rather than one left out of the table below.
var labelConstructionsOverAnyProvider = map[string]string{}

// A construction handed a provider computes with that provider and not with one of its
// own.
//
// This is the property the parameter exists for. RefHash, MakeKeyPackageRef and
// MakeProposalRef take a CryptoProvider rather than hanging off one because the tree and
// the framing layers hold the interface, and a construction that reached for
// crypto/sha256 directly, or built a provider out of a hardcoded suite, agrees with every
// byte in this file: the corpora are all X25519/SHA-256, which is the suite it would have
// hardcoded. Every known answer, every published reference and every argument gate here
// passes over it. So does go vet, and so does gofmt.
//
// What separates the two is a provider that answers differently. Over the tagging provider
// a construction that routed through its parameter answers with different bytes, and one
// that ignored the parameter answers with the same bytes it answered over the real one.
// The call log goes into the failure because the two ways of getting this wrong read
// differently there: a construction that ignored its parameter outright called nothing,
// and one that used it for a size and then hashed on its own called only a size method.
//
// The table is checked against every package level function of this package's source that
// takes a CryptoProvider, read off the parse tree. That is what makes the gate demand the
// next one: plan task 15 adds EncryptWithLabel and DecryptWithLabel with this same
// signature, and they fail here until somebody writes them a row, whichever file they land
// in.
func TestEveryConstructionHandedAProviderRoutesThroughIt(t *testing.T) {
	// the provider underneath draws from a constant reader, because EncryptWithLabel
	// encapsulates to a fresh ephemeral key and would otherwise answer differently on
	// every call whatever provider it was handed — which is a row that separates nothing
	// while looking like the loudest one here
	plain := mustProviderOver(t, CipherSuiteX25519ChaCha20Sha256Ed25519, constantReader{value: 0x35})
	value := bytes.Repeat([]byte{0x21}, 96)
	priv, pub, err := plain.DeriveKeyPair(bytes.Repeat([]byte{0x22}, 32))
	if err != nil {
		t.Fatalf("derive the key pair the labelled encryption rows are built over: %v", err)
	}
	sealedKemOutput, sealedCiphertext, err := EncryptWithLabel(plain, pub, "UpdatePathNode", value, []byte("secret"))
	if err != nil {
		t.Fatalf("seal the message the DecryptWithLabel row reads: %v", err)
	}
	covered := []string{}
	for _, testCase := range []struct {
		name string
		call func(crypto CryptoProvider) []byte
	}{
		{name: "RefHash", call: func(crypto CryptoProvider) []byte {
			return RefHash(crypto, "MLS 1.0 a label", value)
		}},
		{name: "MakeKeyPackageRef", call: func(crypto CryptoProvider) []byte {
			return MakeKeyPackageRef(crypto, value)
		}},
		{name: "MakeProposalRef", call: func(crypto CryptoProvider) []byte {
			return MakeProposalRef(crypto, value)
		}},
		{name: "EncryptWithLabel", call: func(crypto CryptoProvider) []byte {
			_, ciphertext, encryptErr := EncryptWithLabel(crypto, pub, "UpdatePathNode", value, []byte("secret"))
			if encryptErr != nil {
				t.Fatalf("EncryptWithLabel: %v", encryptErr)
			}
			return ciphertext
		}},
		{name: "DecryptWithLabel", call: func(crypto CryptoProvider) []byte {
			plaintext, decryptErr := DecryptWithLabel(crypto, priv, "UpdatePathNode", value,
				sealedKemOutput, sealedCiphertext)
			if decryptErr != nil {
				t.Fatalf("DecryptWithLabel: %v", decryptErr)
			}
			return plaintext
		}},
	} {
		covered = append(covered, testCase.name)
		tagging := &taggingCryptoProvider{inner: plain}
		overTheRealProvider := testCase.call(plain)
		overTheTaggingProvider := testCase.call(tagging)
		if len(overTheRealProvider) == 0 {
			t.Errorf("%s answered with nothing, so this row observed nothing", testCase.name)
			continue
		}
		if bytes.Equal(overTheRealProvider, overTheTaggingProvider) {
			t.Errorf("%s answered the same bytes over a provider that flips every answer, so it did not route through the provider it was handed; it called %v",
				testCase.name, tagging.calls)
		}
	}
	// and the table names every construction of this package that takes a provider rather
	// than the ones this test happened to think of
	declared := packageLevelFunctionsTaking(t, "CryptoProvider")
	want := []string{}
	for _, name := range declared {
		if _, isExcused := labelConstructionsOverAnyProvider[name]; !isExcused {
			want = append(want, name)
		}
	}
	slices.Sort(covered)
	if !slices.Equal(covered, want) {
		t.Errorf("this gate covers %v, and the package declares %v", covered, want)
	}
	for name := range labelConstructionsOverAnyProvider {
		if !slices.Contains(declared, name) {
			t.Errorf("the gate excuses %s, which no function of this package declares", name)
		}
	}
}

// The parameter scan reads a type however the signature was spaced.
//
// Go lets a run of parameters share one type, and a construction written
// func MakeSharedRef(first, second CryptoProvider) declares two providers off one written
// type. A scan that read the type once per field rather than once per name would report a
// signature this package does not have, and a scan that read only the first or the last
// name of a group would drop constructions out of the enumeration above entirely — which
// shrinks what that gate demands without changing anything it reports.
//
// The rows are the whole parameter list rather than a yes or a no on one type, because
// the miscount is invisible to a membership test: a grouped pair read once still contains
// a provider. The control declares both spellings, a grouped pair, and one construction
// that takes no provider at all.
func TestTheParameterScanReadsEveryNameOfAGroupedParameter(t *testing.T) {
	parsed := mustParseText(t, "the grouped parameter control", groupedParameterControl)
	read := map[string][]string{}
	for _, function := range packageLevelFunctionsIn(parsed, "the grouped parameter control") {
		read[function.name] = function.parameters
	}
	for _, testCase := range []struct {
		name       string
		parameters []string
	}{
		{name: "MakeSpacedRef", parameters: []string{"CryptoProvider", "[]byte"}},
		{name: "MakeGroupedRef", parameters: []string{"string", "CryptoProvider"}},
		{name: "MakeSharedRef", parameters: []string{"CryptoProvider", "CryptoProvider"}},
		{name: "MakeGroupedBytes", parameters: []string{"[]byte", "[]byte", "int"}},
		{name: "MakeUnprovidedRef", parameters: []string{"[]byte"}},
	} {
		if !slices.Equal(read[testCase.name], testCase.parameters) {
			t.Errorf("the parameter scan read %s as taking %v, want %v",
				testCase.name, read[testCase.name], testCase.parameters)
		}
	}
	if len(read) != 5 {
		t.Errorf("the parameter scan read %d functions out of the control, want 5", len(read))
	}
	// and the type filter the gate above runs on picks exactly the three that take one
	found := []string{}
	for name, parameters := range read {
		if slices.Contains(parameters, "CryptoProvider") {
			found = append(found, name)
		}
	}
	slices.Sort(found)
	if want := []string{"MakeGroupedRef", "MakeSharedRef", "MakeSpacedRef"}; !slices.Equal(found, want) {
		t.Errorf("the type filter read %v out of the control, want %v", found, want)
	}
}

// Constructions in every spelling a parameter list can take: one type per name, a type
// written after another parameter, two names sharing one type, two byte slices sharing
// one type, and one construction that takes no provider. Every scan and every filter above
// runs on this as well, so one that stopped reading a spelling fails here rather than
// issuing the real package a clean bill.
const groupedParameterControl = `package mls

func MakeSpacedRef(crypto CryptoProvider, value []byte) []byte { return nil }

func MakeGroupedRef(label string, crypto CryptoProvider) []byte { return nil }

func MakeSharedRef(first, second CryptoProvider) []byte { return nil }

func MakeGroupedBytes(label, value []byte, length int) []byte { return nil }

func MakeUnprovidedRef(value []byte) []byte { return nil }
`

// One SignWithLabel known answer: every argument, and the signature it must produce.
//
// Ed25519 is deterministic, so this is a byte for byte answer rather than something that
// can only be verified against. That matters more here than anywhere else in this file:
// signing and then verifying one's own signature passes for an implementation that
// dropped the "MLS 1.0 " prefix, dropped either length prefix, transposed the two fields
// or signed the content alone, and every one of those is a different protocol. The
// published bytes are the only thing that separates them.
//
// The published private key is 32 bytes, which is also what says MLS carries the RFC 8032
// seed rather than go's 64 byte seed followed by public key.
type labelKatSignWithLabel struct {
	Label     string `json:"label"`
	Content   string `json:"content"`
	Priv      string `json:"priv"`
	Pub       string `json:"pub"`
	Signature string `json:"signature"`
}

// The published signatures the corpus must contribute, counted for the same reason as
// every other total here. crypto-basics publishes one sign_with_label answer per suite and
// two of its seven suites are registered.
const labelKatSignatureComparisons = 2

// The RFC 9420 section 2.1.2 variable length integer, written out here rather than taken
// from syntax.
//
// An encoder compared against the encoder it is built out of agrees with itself however
// either of them is wrong, which is why mls/syntax carries its own known answers. What a
// second implementation buys here is the shape no corpus in this tree reaches:
// crypto-basics signs one label of thirteen bytes over a content of thirty two, and the
// rows below pin four more, so five (label length, content length) pairs are pinned out of
// the thirty seven this package exercises. An encoder wrong only outside those five agrees
// with every byte this project can compare and with no other implementation alive —
// measured, a label written raw for exactly the lengths the corpora never use passed all
// 2257 tests before this sweep existed.
func referenceVarint(length int) []byte {
	switch {
	case length <= 0x3f:
		return []byte{byte(length)}
	case length <= 0x3fff:
		return []byte{byte(length>>8) | 0x40, byte(length)}
	default:
		return []byte{byte(length>>24) | 0x80, byte(length >> 16), byte(length >> 8), byte(length)}
	}
}

// struct { opaque label<V>; opaque content<V> } SignContent, assembled without syntax.
func referenceSignContent(label string, content []byte) []byte {
	prefixed := []byte(MlsLabelPrefix + label)
	return concatBytes(referenceVarint(len(prefixed)), prefixed, referenceVarint(len(content)), content)
}

// A field of a given length whose bytes all differ, so a prefix describing the right count
// of the wrong bytes is visible. The first byte is the caller's, which is what lets a sweep
// vary where a label starts as well as how long it is.
func sweptBytes(first byte, length int) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = first + byte(i)
	}
	return out
}

// What the two sweeps below compare, counted for the same reason as every other total
// here: a loop that stopped iterating reports exactly what a complete one reports.
const (
	// label lengths 0..60 against content lengths 0..70, which carries both fields across
	// the one to two octet varint boundary at 64
	signContentLengthSweepComparisons = 61 * 71
	// every first byte at the short lengths, which is what a narrow band encoder keyed on
	// a label's leading byte rather than on its length hides behind
	signContentByteSweepComparisons = 9 * 5 * 256
)

// mlsSignContent agrees with an independently written encoder over a swept space rather
// than at the handful of shapes anybody wrote down.
//
// The two sweeps are different classes and neither contains the other. The first varies
// both lengths, which separates a hand rolled single octet prefix from the varint at 64 and
// an omitted field from an empty one at 0. The second varies the leading byte at short
// lengths, because a defect can be keyed on what a label says rather than on how long it
// is, and every label in every corpus vendored here begins with a capital letter.
func TestSignContentMatchesAnIndependentEncoder(t *testing.T) {
	compared := 0
	for labelLength := 0; labelLength <= 60; labelLength++ {
		label := string(sweptBytes(0x40, labelLength))
		for contentLength := 0; contentLength <= 70; contentLength++ {
			compared++
			content := sweptBytes(0x80, contentLength)
			got := mlsSignContent(label, content)
			if want := referenceSignContent(label, content); !bytes.Equal(got, want) {
				t.Fatalf("mlsSignContent over a %d byte label and a %d byte content = %x, want %x",
					labelLength, contentLength, got, want)
			}
		}
	}
	if compared != signContentLengthSweepComparisons {
		t.Fatalf("the length sweep compared %d encodings, want %d", compared, signContentLengthSweepComparisons)
	}
	compared = 0
	for labelLength := 0; labelLength <= 8; labelLength++ {
		for contentLength := 0; contentLength <= 4; contentLength++ {
			for first := 0; first < 256; first++ {
				compared++
				label := string(sweptBytes(byte(first), labelLength))
				content := sweptBytes(byte(first)^0x55, contentLength)
				got := mlsSignContent(label, content)
				if want := referenceSignContent(label, content); !bytes.Equal(got, want) {
					t.Fatalf("mlsSignContent over a %d byte label beginning %#02x and a %d byte content = %x, want %x",
						labelLength, first, contentLength, got, want)
				}
			}
		}
	}
	if compared != signContentByteSweepComparisons {
		t.Fatalf("the byte sweep compared %d encodings, want %d", compared, signContentByteSweepComparisons)
	}
	// and the reference is not the implementation written a second time: it must disagree
	// with an encoder that dropped a length prefix, or the sweeps above compare nothing
	if bytes.Equal(referenceSignContent("a", []byte("bc")), concatBytes([]byte(MlsLabelPrefix+"a"), []byte("bc"))) {
		t.Errorf("the reference encoder builds the unframed concatenation, so it frames nothing")
	}
}

func TestSignContentEncoding(t *testing.T) {
	// SignContent is { opaque label<V>; opaque content<V> } and the label carries the
	// "MLS 1.0 " prefix. These rows are read off RFC 9420 section 5.1.2 rather than
	// published, so TestSignWithLabelMatchesTheCryptoBasicsVectors is the authority and
	// this is what says which field moved when it fails.
	for _, testCase := range []struct {
		name    string
		label   string
		content []byte
		want    []byte
	}{
		{
			name:    "a two byte content",
			label:   "FramedContentTBS",
			content: []byte{0xbe, 0xef},
			want: concatBytes([]byte{byte(len(MlsLabelPrefix + "FramedContentTBS"))},
				[]byte(MlsLabelPrefix+"FramedContentTBS"), []byte{0x02, 0xbe, 0xef}),
		},
		{
			// an empty content still writes its length byte, which is the one shape a
			// round trip cannot see: with no content bytes the readings "field omitted"
			// and "field present and empty" differ only by this 0x00.
			name:    "an empty label and an empty content",
			label:   "",
			content: nil,
			want:    concatBytes([]byte{byte(len(MlsLabelPrefix))}, []byte(MlsLabelPrefix), []byte{0x00}),
		},
		{
			// a content of 64 bytes crosses into the two byte prefix, so a hand rolled
			// single byte length encodes 0x40 here and describes a preimage 63 bytes long
			name:    "a content at the two byte prefix boundary",
			label:   "y",
			content: bytes.Repeat([]byte{0x5a}, 64),
			want: concatBytes([]byte{byte(len(MlsLabelPrefix + "y"))}, []byte(MlsLabelPrefix+"y"),
				[]byte{0x40, 0x40}, bytes.Repeat([]byte{0x5a}, 64)),
		},
	} {
		if got := mlsSignContent(testCase.label, testCase.content); !bytes.Equal(got, testCase.want) {
			t.Errorf("%s: mlsSignContent = %x, want %x", testCase.name, got, testCase.want)
		}
	}
}

// Where the boundary between the label and the content falls is part of what is signed.
//
// The four splits in the first table are one run of bytes divided four ways, so an encoder
// that dropped both length prefixes produces the same preimage for all of them and one
// signature covers all four readings. That is a signature bypass primitive rather than a
// cosmetic difference: a peer that splits the run differently reads a leaf node signature
// as a framed content signature over content the signer never saw.
//
// Both prefixes, not either. Measured, an encoder that dropped one alone leaves all four
// rows distinct — the surviving prefix byte differs between them, 0x0b/0x0c/0x0a/0x0d for
// the label and 0x02/0x01/0x03/0x00 for the content — and passes this table. The second
// table is what separates a dropped label prefix on its own: two pairs whose preimages
// collide the moment the label is written raw, so one signature really does cover both
// readings there.
//
// There is no third table because a dropped content prefix admits no collision at all. The
// content is the last field, so a preimage of the form { varint length; label; content }
// still decodes one way: the varint fixes where the label ends and everything after it is
// the content. Dropping it is a protocol split rather than a bypass, and what holds it is
// the published signature in TestSignWithLabelMatchesTheCryptoBasicsVectors and the swept
// comparison in TestSignContentMatchesAnIndependentEncoder, neither of which needs a
// collision to see it.
func TestSignContentSeparatesTheLabelFromTheContent(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	priv, pub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("SignatureKeyPair: %v", err)
	}
	splits := []struct {
		label   string
		content []byte
	}{
		{label: "abc", content: []byte("de")},
		{label: "abcd", content: []byte("e")},
		{label: "ab", content: []byte("cde")},
		{label: "abcde", content: nil},
	}
	preimages := [][]byte{}
	signatures := [][]byte{}
	for _, split := range splits {
		// the rows really are one run of bytes divided differently, or the framing is not
		// what separates them and this test proves something easier
		unframed := concatBytes([]byte(MlsLabelPrefix+split.label), split.content)
		if !bytes.Equal(unframed, []byte(MlsLabelPrefix+"abcde")) {
			t.Fatalf("the split %q over %x concatenates to %x rather than to the one run of bytes",
				split.label, split.content, unframed)
		}
		signature, err := crypto.SignWithLabel(priv, split.label, split.content)
		if err != nil {
			t.Fatalf("sign under %q: %v", split.label, err)
		}
		preimages = append(preimages, mlsSignContent(split.label, split.content))
		signatures = append(signatures, signature)
	}
	for i := range splits {
		for j := range splits {
			if i != j && bytes.Equal(preimages[i], preimages[j]) {
				t.Errorf("the splits %q and %q build the same preimage %x",
					splits[i].label, splits[j].label, preimages[i])
			}
			err := crypto.VerifyWithLabel(pub, splits[j].label, splits[j].content, signatures[i])
			if i == j && err != nil {
				t.Errorf("the signature under %q was refused under its own split: %v", splits[i].label, err)
			}
			if i != j && !errors.Is(err, ErrCryptoBadSignature) {
				t.Errorf("the signature under %q verified under the split %q: error = %v, want ErrCryptoBadSignature",
					splits[i].label, splits[j].label, err)
			}
		}
	}
	// the second table: two pairs that build one preimage the moment the label's own
	// length prefix is dropped. The label of the second row ends in the length byte the
	// first row's content begins with, so a raw label swallows the boundary and the two
	// readings become the same bytes.
	collidingLabels := []string{"ab", "ab\x03"}
	collidingContents := [][]byte{{0x02, 'c', 'd'}, {'c', 'd'}}
	rawFramed := [][]byte{}
	for i := range collidingLabels {
		rawFramed = append(rawFramed, concatBytes([]byte(MlsLabelPrefix+collidingLabels[i]),
			referenceVarint(len(collidingContents[i])), collidingContents[i]))
	}
	if !bytes.Equal(rawFramed[0], rawFramed[1]) {
		t.Fatalf("the two rows build %x and %x with the label written raw, so they separate nothing",
			rawFramed[0], rawFramed[1])
	}
	collidingSignature, err := crypto.SignWithLabel(priv, collidingLabels[0], collidingContents[0])
	if err != nil {
		t.Fatalf("sign under %q: %v", collidingLabels[0], err)
	}
	if err := crypto.VerifyWithLabel(pub, collidingLabels[0], collidingContents[0], collidingSignature); err != nil {
		t.Fatalf("the signature under %q was refused under its own pair: %v", collidingLabels[0], err)
	}
	if err := crypto.VerifyWithLabel(pub, collidingLabels[1], collidingContents[1], collidingSignature); !errors.Is(err, ErrCryptoBadSignature) {
		t.Errorf("the signature under %q over %x verified under %q over %x: error = %v, want ErrCryptoBadSignature",
			collidingLabels[0], collidingContents[0], collidingLabels[1], collidingContents[1], err)
	}
}

// The one published pin on the whole SignContent construction, and the only thing in this
// file that separates the encoding from every plausible variant of it.
//
// The comparison is against the published signature itself rather than against a verify,
// because ed25519 is deterministic and the stronger comparison is available: a signer that
// framed the preimage differently produces different bytes here even though it would go on
// verifying against itself all day.
func TestSignWithLabelMatchesTheCryptoBasicsVectors(t *testing.T) {
	entries := []labelKatBasics{}
	loadLabelKat(t, "crypto-basics.json", &entries)
	compared := 0
	for _, entry := range entries {
		suite := CipherSuite(entry.CipherSuite)
		if !IsRegisteredSuite(suite) {
			continue
		}
		crypto := mustProvider(t, suite)
		vector := entry.SignWithLabel
		what := fmt.Sprintf("suite %#04x sign_with_label", uint16(suite))
		priv := SignaturePrivateKey(mustDecodeHex(t, what+" priv", vector.Priv))
		pub := SignaturePublicKey(mustDecodeHex(t, what+" pub", vector.Pub))
		content := mustDecodeHex(t, what+" content", vector.Content)
		published := mustDecodeHex(t, what+" signature", vector.Signature)
		signature, err := crypto.SignWithLabel(priv, vector.Label, content)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		assertLabelKat(t, what, signature, vector.Signature)
		compared++
		// and the verifier accepts the published signature under the published key, which
		// is what says it rebuilds the preimage the publisher signed rather than only the
		// one this package's own signer builds
		if err := crypto.VerifyWithLabel(pub, vector.Label, content, published); err != nil {
			t.Errorf("%s: the published signature was refused: %v", what, err)
		}
		// and refuses it under a label the publisher did not sign under, over bytes this
		// project did not compute
		if err := crypto.VerifyWithLabel(pub, vector.Label+"x", content, published); !errors.Is(err, ErrCryptoBadSignature) {
			t.Errorf("%s: the published signature verified under another label: error = %v, want ErrCryptoBadSignature",
				what, err)
		}
	}
	if compared != labelKatSignatureComparisons {
		t.Fatalf("compared %d published signatures, want %d", compared, labelKatSignatureComparisons)
	}
}

func TestSignatureRoundTrip(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	priv, pub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("SignatureKeyPair: %v", err)
	}
	if len(priv) != 32 || len(pub) != 32 {
		t.Fatalf("key sizes are %d/%d, want 32/32, the private key being the RFC 8032 seed",
			len(priv), len(pub))
	}
	content := []byte("the signed content")
	sig, err := crypto.SignWithLabel(priv, "LeafNodeTBS", content)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("signature is %d bytes, want 64", len(sig))
	}
	if err := crypto.VerifyWithLabel(pub, "LeafNodeTBS", content, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// and a second key pair is a different key pair, so a generator answering with one
	// fixed pair fails here rather than round tripping forever
	otherPriv, otherPub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("SignatureKeyPair a second time: %v", err)
	}
	if bytes.Equal(priv, otherPriv) || bytes.Equal(pub, otherPub) {
		t.Fatalf("two key pairs from the process entropy source repeated each other")
	}
}

func TestSignatureIsLabelBound(t *testing.T) {
	// a signature made under one label must not verify under another. without this the
	// label is decoration and a leaf node signature could be replayed as a framed content
	// signature.
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	priv, pub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("SignatureKeyPair: %v", err)
	}
	content := []byte("the signed content")
	sig, err := crypto.SignWithLabel(priv, "LeafNodeTBS", content)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := crypto.VerifyWithLabel(pub, "FramedContentTBS", content, sig); !errors.Is(err, ErrCryptoBadSignature) {
		t.Fatalf("wrong label verified: error = %v, want ErrCryptoBadSignature", err)
	}
	if err := crypto.VerifyWithLabel(pub, "LeafNodeTBS", append(bytes.Clone(content), '!'), sig); !errors.Is(err, ErrCryptoBadSignature) {
		t.Fatalf("wrong content verified: error = %v, want ErrCryptoBadSignature", err)
	}
	tampered := bytes.Clone(sig)
	tampered[0] ^= 0x01
	if err := crypto.VerifyWithLabel(pub, "LeafNodeTBS", content, tampered); !errors.Is(err, ErrCryptoBadSignature) {
		t.Fatalf("tampered signature verified: error = %v, want ErrCryptoBadSignature", err)
	}
	// and a label that only extends the one signed under is refused as well, so a
	// verifier comparing prefixes rather than the whole preimage is caught too
	if err := crypto.VerifyWithLabel(pub, "LeafNodeTBS2", content, sig); !errors.Is(err, ErrCryptoBadSignature) {
		t.Fatalf("an extended label verified: error = %v, want ErrCryptoBadSignature", err)
	}
}

// Every alteration of what a verify is handed is refused, one at a time.
//
// A verify that returns nil for everything passes a test that signs and then verifies its
// own signature, and it is the single worst defect this package could ship: every leaf
// node, every commit and every proposal in the protocol is authenticated by this call. So
// each of the four inputs is altered on its own, with a control row that must still be
// accepted so the table cannot be satisfied by a verify that refuses everything either.
func TestVerifyWithLabelRefusesEveryAlteration(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	priv, pub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("SignatureKeyPair: %v", err)
	}
	otherPriv, otherPub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("SignatureKeyPair a second time: %v", err)
	}
	label := "LeafNodeTBS"
	content := []byte("the signed content")
	sig, err := crypto.SignWithLabel(priv, label, content)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	otherSig, err := crypto.SignWithLabel(otherPriv, label, content)
	if err != nil {
		t.Fatalf("sign under the other key: %v", err)
	}
	// the control first: what follows is only meaningful against a verify that accepts
	// the one thing it should
	if err := crypto.VerifyWithLabel(pub, label, content, sig); err != nil {
		t.Fatalf("the signature this key made over this content was refused: %v", err)
	}
	refusals := 0
	refuse := func(name string, key SignaturePublicKey, under string, over []byte, signature []byte) {
		refusals++
		if err := crypto.VerifyWithLabel(key, under, over, signature); !errors.Is(err, ErrCryptoBadSignature) {
			t.Errorf("%s verified: error = %v, want ErrCryptoBadSignature", name, err)
		}
	}
	// every byte of the signature, so a verify that reads only a prefix of it is caught
	// wherever it stopped reading
	for i := range sig {
		altered := bytes.Clone(sig)
		altered[i] ^= 0x80
		refuse(fmt.Sprintf("a signature with byte %d altered", i), pub, label, content, altered)
	}
	// every byte of the content, for the same reason
	for i := range content {
		altered := bytes.Clone(content)
		altered[i] ^= 0x20
		refuse(fmt.Sprintf("content with byte %d altered", i), pub, label, altered, sig)
	}
	// every byte of the public key, which is what says the verify reads the whole key
	// rather than enough of it to look right
	for i := range pub {
		altered := bytes.Clone(pub)
		altered[i] ^= 0x01
		refuse(fmt.Sprintf("a public key with byte %d altered", i), altered, label, content, sig)
	}
	refuse("another key's signature", pub, label, content, otherSig)
	refuse("this signature under another key", otherPub, label, content, sig)
	refuse("an all zero signature", pub, label, content, make([]byte, len(sig)))
	refuse("a signature of every one bit", pub, label, content, bytes.Repeat([]byte{0xff}, len(sig)))
	refuse("an empty content", pub, label, nil, sig)
	if want := len(sig) + len(content) + len(pub) + 5; refusals != want {
		t.Fatalf("the table refused %d alterations, want %d", refusals, want)
	}
}

// One demanded pair the refusal class below is generated around.
//
// One pair is not enough. A fallback can be conditional on what it is handed, and a verify
// lenient only for labels of eleven bytes passes a probe that only ever uses two —
// measured, exactly that mutant survived all 2257 tests of the version this replaces. So
// the generators run over a table: a real RFC label, a two byte pair, an empty pair, and a
// label carrying whitespace over a content past the one octet prefix boundary.
//
// The sweep flag says whether the exhaustive single edit neighbourhood runs on a pair, and
// rawSweep the same for the neighbourhood of the preimage itself. Both are the field length
// times the whole byte alphabet and every member costs a signature and a verification, so
// they run where the fields are short and one real label, while the generators that cost
// nothing run everywhere.
//
// The second field is the content of a SignContent and the context of an EncryptContext.
// The two structures have the same shape, so one table of pairs describes both classes and
// the encoder is what says which is being generated.
type signatureProbePair struct {
	name     string
	label    string
	content  []byte
	sweep    bool
	rawSweep bool
}

// The pairs, and how many of them there are, asserted where they are used.
func signatureProbePairs() []signatureProbePair {
	return []signatureProbePair{
		{name: "an RFC label", label: "LeafNodeTBS", content: []byte("sig"), sweep: true},
		{name: "two byte fields", label: "Ab", content: []byte("Cd"), sweep: true, rawSweep: true},
		{name: "empty fields", label: "", content: nil, sweep: true, rawSweep: true},
		{name: "a spaced label over a content past the one octet prefix",
			label: " FramedContentTBS ", content: bytes.Repeat([]byte{0x5a}, 64)},
	}
}

// Every field one byte away from this one, over the whole alphabet: each deletion, each
// substitution and each insertion, at every position.
//
// This is the class rather than a list. A fallback that appends any byte, drops any byte or
// changes any byte is a member whether or not that byte is one somebody would have written
// down, which is exactly the difference between this and the seven named labels it
// replaces: a fallback to the label plus "x" died on that list and one to the label plus
// "y" passed everything.
func singleByteEdits(field []byte) [][]byte {
	edits := [][]byte{}
	for i := range field {
		edits = append(edits, concatBytes(field[:i], field[i+1:]))
	}
	for i := range field {
		for b := 0; b < 256; b++ {
			if byte(b) == field[i] {
				continue
			}
			edits = append(edits, concatBytes(field[:i], []byte{byte(b)}, field[i+1:]))
		}
	}
	for i := 0; i <= len(field); i++ {
		for b := 0; b < 256; b++ {
			edits = append(edits, concatBytes(field[:i], []byte{byte(b)}, field[i:]))
		}
	}
	return edits
}

// The bytes a rewrite may add, taken from the field rather than chosen: every byte it
// carries, each of those with its case bit flipped, and the two extremes. An alphabet
// somebody picked would be one more list to keep in step with the fields it is used on.
func rewriteAlphabet(field []byte) []byte {
	alphabet := []byte{0x00, 0xff}
	for _, b := range field {
		alphabet = append(alphabet, b, b^0x20)
	}
	slices.Sort(alphabet)
	return slices.Compact(alphabet)
}

// Every whole field rewrite, as operations over the field rather than as values.
//
// A single byte edit cannot reach a doubled field, a reversed one or a case folded one, and
// those are the shapes a lenient verify is actually written with. Naming the operation
// rather than the result is what keeps this a class: the same repertoire over a different
// demanded pair yields different values with nothing edited here.
func fieldRewrites(field []byte) [][]byte {
	half := len(field) / 2
	reversed := bytes.Clone(field)
	slices.Reverse(reversed)
	sorted := bytes.Clone(field)
	slices.Sort(sorted)
	rewrites := [][]byte{
		nil,
		field[:len(field)-min(1, len(field))],
		field[min(1, len(field)):],
		field[:half],
		field[half:],
		reversed,
		sorted,
		bytes.ToLower(field),
		bytes.ToUpper(field),
		bytes.Repeat(field, 2),
		bytes.Repeat(field, 3),
		bytes.Repeat(field, 4),
		make([]byte, len(field)),
		bytes.Repeat([]byte{0xff}, len(field)),
		bytes.TrimSpace(field),
		concatBytes([]byte(MlsLabelPrefix), field),
		bytes.TrimPrefix(field, []byte(MlsLabelPrefix)),
	}
	for _, b := range rewriteAlphabet(field) {
		rewrites = append(rewrites, concatBytes(field, []byte{b}), concatBytes([]byte{b}, field))
	}
	return rewrites
}

// Every arrangement of the fields a signer holds, in either framing.
//
// The rows a reader writes out — the content alone, the prefixed label alone, the two
// unframed, the two transposed, one prefix dropped — are all members of this, and so are
// the arrangements nobody writes out. Generating it is what makes the claim "every
// reframing of these fields" rather than "these nine".
func fieldArrangements(label string, content []byte) [][]byte {
	framed := [][]byte{}
	for _, field := range [][]byte{[]byte(MlsLabelPrefix + label), []byte(label), content, nil} {
		framed = append(framed, bytes.Clone(field), concatBytes(referenceVarint(len(field)), field))
	}
	arrangements := [][]byte{}
	for _, first := range framed {
		arrangements = append(arrangements, first)
		for _, second := range framed {
			arrangements = append(arrangements, concatBytes(first, second))
		}
	}
	return arrangements
}

// The deterministic source the walk below draws from.
//
// A 64 bit xorshift rather than a math/rand Rand, for the reason mls/syntax records for the
// same choice: a corpus that is byte for byte the same on every platform and every
// toolchain is what makes a failure reproducible from a seed alone. Zero is xorshift's
// fixed point and would emit one value forever, so it is replaced rather than accepted.
type labelProbeRand struct {
	state uint64
}

func newLabelProbeRand(seed uint64) *labelProbeRand {
	if seed == 0 {
		seed = 0x9e3779b97f4a7c15
	}
	return &labelProbeRand{state: seed}
}

// The next word, and a value below a bound. The modulo is biased for a bound that does not
// divide the word size, which is irrelevant to a corpus generator and would not be to
// anything carrying a security property.
func (self *labelProbeRand) below(bound int) int {
	self.state ^= self.state << 13
	self.state ^= self.state >> 7
	self.state ^= self.state << 17
	if bound <= 0 {
		return 0
	}
	return int(self.state % uint64(bound))
}

// One edit of a field, drawn from the same repertoire the generators above enumerate.
func (self *labelProbeRand) edit(field []byte) []byte {
	switch self.below(7) {
	case 0:
		if len(field) == 0 {
			return field
		}
		at := self.below(len(field))
		return concatBytes(field[:at], field[at+1:])
	case 1:
		at := self.below(len(field) + 1)
		return concatBytes(field[:at], []byte{byte(self.below(256))}, field[at:])
	case 2:
		if len(field) == 0 {
			return field
		}
		at := self.below(len(field))
		return concatBytes(field[:at], []byte{byte(self.below(256))}, field[at+1:])
	case 3:
		return field[:self.below(len(field)+1)]
	case 4:
		return field[self.below(len(field)+1):]
	case 5:
		return bytes.Repeat(field, 2+self.below(3))
	default:
		if len(field) == 0 {
			return field
		}
		folded := bytes.Clone(field)
		folded[self.below(len(folded))] ^= 0x20
		return folded
	}
}

// How many pairs the walk draws per demanded pair, and the seed it draws them from. The
// seed is written down so a failure reproduces from this line rather than from a lucky run.
const (
	labelProbeWalkSteps = 1500
	labelProbeWalkSeed  = 0x5d1e4b7c9a30f682
)

// One to four edits applied to both fields at once, drawn deterministically.
//
// The three generators above are each complete over the shapes they describe and silent
// about every other. This samples outside them: a fallback two edits away in each field, or
// one that combines a rewrite with an insertion, is reached here or not at all.
func walkedPairs(random *labelProbeRand, pair signatureProbePair, encode func(string, []byte) []byte) [][]byte {
	preimages := [][]byte{}
	for step := 0; step < labelProbeWalkSteps; step++ {
		otherLabel := []byte(pair.label)
		otherContent := bytes.Clone(pair.content)
		for edit := 0; edit <= random.below(4); edit++ {
			if random.below(2) == 0 {
				otherLabel = random.edit(otherLabel)
			} else {
				otherContent = random.edit(otherContent)
			}
		}
		preimages = append(preimages, encode(string(otherLabel), otherContent))
	}
	return preimages
}

// Every preimage the class holds for one demanded pair, under one of the two labelled
// encodings.
//
// The encoder is a parameter because RFC 9420 gives section 5.1.2's SignContent and
// section 5.1.3's EncryptContext the same two field shape over two different second
// fields, so the same repertoire of edits describes the class for both. Passing it rather
// than naming one is what lets the encryption class be generated instead of listed, which
// is the whole lesson of the seven named labels this replaced.
func alternativePreimages(random *labelProbeRand, pair signatureProbePair, encode func(string, []byte) []byte) [][]byte {
	label := []byte(pair.label)
	demanded := encode(pair.label, pair.content)
	preimages := [][]byte{}
	if pair.sweep {
		for _, edited := range singleByteEdits(label) {
			preimages = append(preimages, encode(string(edited), pair.content))
		}
		for _, edited := range singleByteEdits(pair.content) {
			preimages = append(preimages, encode(pair.label, edited))
		}
	}
	if pair.rawSweep {
		// the same edits over the preimage itself, which reaches what no (label, content)
		// pair can: a truncation, an extension, a byte changed inside a length prefix
		preimages = append(preimages, singleByteEdits(demanded)...)
	}
	for _, otherLabel := range fieldRewrites(label) {
		for _, otherContent := range fieldRewrites(pair.content) {
			preimages = append(preimages, encode(string(otherLabel), otherContent))
		}
	}
	preimages = append(preimages, fieldRewrites(demanded)...)
	preimages = append(preimages, fieldArrangements(pair.label, pair.content)...)
	preimages = append(preimages, walkedPairs(random, pair, encode)...)
	return preimages
}

// What the generated class holds, pinned so a generator that degenerated fails rather than
// reporting exactly what a working one reports.
//
// Two numbers, because they fail differently. The built total counts what the generators
// emitted and depends on nothing but their own shape, so it moves when a generator stops
// generating. The distinct total counts what survived deduplication, which is the one that
// matters — a repertoire whose operations all collapsed to the identity would emit the
// same number of values and refuse one — and it also moves when mlsSignContent's encoding
// changes, since two candidates that encoded apart may now encode the same. A run where
// only the second moved is that, and is worth reading as such rather than re-pinning.
const (
	signatureBuiltPreimages   = 35226
	signatureRefusedPreimages = 29183
)

// A signature this key really made, over a preimage the verifier does not demand, is
// refused.
//
// This is the direction a lenient verifier is invisible in, and the one this project has
// now paid for twice. Task 8's aad and info binding was walked in one direction only and
// twelve lenient fallback mutants passed the whole suite. Then the first answer to that
// here was a cross product of seven named labels and five named contents, which is a list
// of seven wearing a cross product's clothes: a verify falling back to the label plus "x"
// died on it and one falling back to the label plus "y" passed all 2257 tests, along with
// forty more of the same shape, each accepting a signature the key really made under
// another label.
//
// So the refused set is generated. The named rows below stay, because a failure among them
// says which reframing was accepted rather than only that one was, but they are no longer
// what the claim rests on. Four generators carry that, none of which names a value:
// singleByteEdits over the whole alphabet, fieldRewrites as operations rather than results,
// fieldArrangements over both framings of both fields, and a deterministic multi edit walk
// outside all three.
//
// What no generator can do is enumerate every preimage, so two things bound it. The count
// of distinct ones is asserted, and TestTheSignatureMethodsAreOnlyTheirOwnPreimage covers
// what a neighbourhood cannot by reading the method's own statements.
func TestVerifyWithLabelRefusesSignaturesOverOtherPreimages(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	priv, pub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("SignatureKeyPair: %v", err)
	}
	label := "LeafNodeTBS"
	content := []byte("the signed content")
	key := ed25519.NewKeyFromSeed(priv)
	prefixed := []byte(MlsLabelPrefix + label)
	demanded := mlsSignContent(label, content)
	for _, testCase := range []struct {
		name     string
		preimage []byte
	}{
		{name: "the content alone", preimage: content},
		{name: "the prefixed label alone", preimage: prefixed},
		{name: "the prefixed label and the content, unframed", preimage: concatBytes(prefixed, content)},
		{name: "the bare label and the content, unframed", preimage: concatBytes([]byte(label), content)},
		{name: "SignContent over the bare label", preimage: concatBytes([]byte{byte(len(label))},
			[]byte(label), []byte{byte(len(content))}, content)},
		{name: "SignContent with the content's length prefix dropped", preimage: concatBytes(
			[]byte{byte(len(prefixed))}, prefixed, content)},
		{name: "SignContent with the label's length prefix dropped", preimage: concatBytes(
			prefixed, []byte{byte(len(content))}, content)},
		{name: "SignContent with its two fields transposed", preimage: concatBytes(
			[]byte{byte(len(content))}, content, []byte{byte(len(prefixed))}, prefixed)},
		{name: "the digest of SignContent", preimage: crypto.Hash(demanded)},
	} {
		if bytes.Equal(testCase.preimage, demanded) {
			t.Errorf("%s is the preimage the verifier demands, so this row separates nothing", testCase.name)
			continue
		}
		signature := ed25519.Sign(key, testCase.preimage)
		if err := crypto.VerifyWithLabel(pub, label, content, signature); !errors.Is(err, ErrCryptoBadSignature) {
			t.Errorf("a signature over %s verified: error = %v, want ErrCryptoBadSignature", testCase.name, err)
		}
	}
	// the rows above are shapes somebody thought of, and a fallback aimed at a shape nobody
	// listed survives all of them. So the rest is generated, over every demanded pair in
	// the table, and every generated preimage the same key can build is refused.
	random := newLabelProbeRand(labelProbeWalkSeed)
	refused := 0
	built := 0
	for _, pair := range signatureProbePairs() {
		pairDemanded := mlsSignContent(pair.label, pair.content)
		// the control first, per pair: what follows is only meaningful against a verify
		// that accepts the one preimage it should
		if err := crypto.VerifyWithLabel(pub, pair.label, pair.content, ed25519.Sign(key, pairDemanded)); err != nil {
			t.Fatalf("%s: the signature over the demanded preimage was refused: %v", pair.name, err)
		}
		tried := map[string]bool{string(pairDemanded): true}
		generated := alternativePreimages(random, pair, mlsSignContent)
		if len(generated) == 0 {
			t.Fatalf("%s: the generators built nothing, so this pair observed nothing", pair.name)
		}
		built += len(generated)
		for _, preimage := range generated {
			if tried[string(preimage)] {
				continue
			}
			tried[string(preimage)] = true
			refused++
			if err := crypto.VerifyWithLabel(pub, pair.label, pair.content, ed25519.Sign(key, preimage)); !errors.Is(err, ErrCryptoBadSignature) {
				t.Errorf("%s: a signature over %x verified as one under %q over %x: error = %v, want ErrCryptoBadSignature",
					pair.name, preimage, pair.label, pair.content, err)
			}
		}
	}
	if built != signatureBuiltPreimages {
		t.Fatalf("the generators built %d preimages, want %d", built, signatureBuiltPreimages)
	}
	if refused != signatureRefusedPreimages {
		t.Fatalf("the generated class refused %d distinct preimages, want %d", refused, signatureRefusedPreimages)
	}
	// and the control for the whole test: a signature over the preimage the verifier does
	// demand is accepted, so nothing above is satisfied by a verify that refuses everything
	if err := crypto.VerifyWithLabel(pub, label, content, ed25519.Sign(key, demanded)); err != nil {
		t.Errorf("the signature over the demanded preimage was refused: %v", err)
	}
}

func TestSignatureRejectsWrongKeySizes(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	for _, n := range []int{0, 31, 33, 64} {
		if _, err := crypto.SignWithLabel(make(SignaturePrivateKey, n), "x", nil); !errors.Is(err, ErrBadSignatureKey) {
			t.Errorf("sign with a %d-byte key error = %v, want ErrBadSignatureKey", n, err)
		}
		if err := crypto.VerifyWithLabel(make(SignaturePublicKey, n), "x", nil, make([]byte, 64)); !errors.Is(err, ErrBadSignatureKey) {
			t.Errorf("verify with a %d-byte key error = %v, want ErrBadSignatureKey", n, err)
		}
	}
	priv, pub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("SignatureKeyPair: %v", err)
	}
	for _, n := range []int{0, 63, 65} {
		if err := crypto.VerifyWithLabel(pub, "x", nil, make([]byte, n)); !errors.Is(err, ErrCryptoBadSignature) {
			t.Errorf("verify a %d-byte signature error = %v, want ErrCryptoBadSignature", n, err)
		}
	}
	// a truncated or extended copy of a real signature is refused for the same reason,
	// and it is the version a length check written after the verify would let through
	sig, err := crypto.SignWithLabel(priv, "x", nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	for _, altered := range [][]byte{sig[:63], append(bytes.Clone(sig), 0x00)} {
		if err := crypto.VerifyWithLabel(pub, "x", nil, altered); !errors.Is(err, ErrCryptoBadSignature) {
			t.Errorf("a %d-byte copy of a real signature error = %v, want ErrCryptoBadSignature", len(altered), err)
		}
	}
	// and the control: the lengths the suite does fix are accepted, so the rows above are
	// not satisfied by a verify that refuses every signature it is handed
	if err := crypto.VerifyWithLabel(pub, "x", nil, sig); err != nil {
		t.Errorf("a key and a signature of the suite's own lengths were refused: %v", err)
	}
}

// The seed a key pair is built from is drawn from the provider's reader, is exactly the
// bytes that reader offered, and is drawn in order.
//
// This is the property a constant reader cannot see, and the one this project has now paid
// for twice. Task 4's generator was tested against a constant reader, where reversing,
// rotating and sorting the scalar are all the identity, and every one of those weakenings
// passed. Task 11's entropy test asked only whether two providers disagree with each
// other, and a process global counter passed all 113 tests. So the windows are asserted to
// be none of their own permutations before anything is asserted with them.
func TestSignatureKeyPairConsumesItsReaderInOrder(t *testing.T) {
	script := randomScript(t)
	firstSeed, secondSeed := script[:32], script[32:64]
	assertProbeIsNotItsOwnPermutation(t, "the first seed window of the script", firstSeed)
	assertProbeIsNotItsOwnPermutation(t, "the second seed window of the script", secondSeed)
	if bytes.Equal(firstSeed, secondSeed) {
		t.Fatalf("the two seed windows are equal, so a generator that restarted its reader would be invisible")
	}
	crypto := mustProviderOver(t, CipherSuiteX25519ChaCha20Sha256Ed25519, bytes.NewReader(script))
	for _, want := range [][]byte{firstSeed, secondSeed} {
		priv, pub, err := crypto.SignatureKeyPair()
		if err != nil {
			t.Fatalf("SignatureKeyPair: %v", err)
		}
		if !bytes.Equal(priv, want) {
			t.Errorf("the seed drawn was %x, want the %x the reader offered", priv, want)
		}
		expanded := ed25519.NewKeyFromSeed(want)
		if !bytes.Equal(pub, expanded[ed25519.SeedSize:]) {
			t.Errorf("the public key was %x, want the %x that seed expands to", pub, expanded[ed25519.SeedSize:])
		}
	}
	// two seeds of 32 leave 32 of the 96 byte script, so a generator that drew more than
	// the seed it answered with has already moved the reader past them
	if got := crypto.Random(32); !bytes.Equal(got, script[64:]) {
		t.Errorf("after two key pairs the reader stood at %x, want %x", got, script[64:])
	}
}

// A short or failing source must not yield a key pair. Unlike Random this method has an
// error return, so the refusal is an error rather than a panic, and the keys alongside it
// are nil: a caller that read the slices instead of the error would otherwise sign under a
// seed of zeroes and report success.
func TestSignatureKeyPairRefusesAShortOrFailingReader(t *testing.T) {
	script := randomScript(t)
	for _, testCase := range []struct {
		name   string
		reader io.Reader
	}{
		{name: "an exhausted reader", reader: bytes.NewReader(nil)},
		{name: "a reader one byte short", reader: bytes.NewReader(script[:31])},
		{name: "a reader that fails at once", reader: failingReader{err: errors.New("entropy source is down")}},
		{name: "a reader that stalls then ends", reader: &dribblingReader{remaining: bytes.Clone(script[:7]), stalls: 2}},
	} {
		crypto := mustProviderOver(t, CipherSuiteX25519ChaCha20Sha256Ed25519, testCase.reader)
		priv, pub, err := crypto.SignatureKeyPair()
		if err == nil {
			t.Errorf("SignatureKeyPair over %s answered with a key pair instead of an error", testCase.name)
		}
		if priv != nil || pub != nil {
			t.Errorf("SignatureKeyPair over %s answered with %d and %d bytes alongside its error",
				testCase.name, len(priv), len(pub))
		}
	}
	// the control: a reader with enough bytes must not be refused, or the table above is
	// satisfied by a generator that refuses everything
	crypto := mustProviderOver(t, CipherSuiteX25519ChaCha20Sha256Ed25519, bytes.NewReader(script))
	if _, _, err := crypto.SignatureKeyPair(); err != nil {
		t.Errorf("SignatureKeyPair over a sufficient reader failed: %v", err)
	}
	// and a provider handed no reader does not fall back to the process entropy source,
	// which is exactly what crypto/ed25519.GenerateKey does when it is passed a nil one
	substituting := mustProviderOver(t, CipherSuiteX25519ChaCha20Sha256Ed25519, nil)
	if recovered := recoveredPanic(func() { substituting.SignatureKeyPair() }); recovered == nil {
		t.Errorf("SignatureKeyPair over a nil reader answered, so it read something else")
	}
}

// Neither half of a key pair carries storage past its own length.
//
// go's ed25519 private key is the seed followed by the public key, so a generator handing
// back expanded[:32] rather than the seed buffer answers thirty two bytes that read
// identically and carry thirty two more behind their length. The bytes agree every time —
// that mutant passed every other test in this package — and what separates it is a caller
// that appends: the append lands in the spare capacity, which is the public half of the
// same key, and the pair the caller holds stops agreeing with itself.
//
// Both halves are asserted, over more than one pair, because the two are built differently
// and only one of them is a make of the exact size.
func TestSignatureKeyPairAnswersStorageOfItsOwn(t *testing.T) {
	crypto := mustProviderOver(t, CipherSuiteX25519ChaCha20Sha256Ed25519, bytes.NewReader(randomScript(t)))
	for pair := 0; pair < 3; pair++ {
		priv, pub, err := crypto.SignatureKeyPair()
		if err != nil {
			t.Fatalf("SignatureKeyPair: %v", err)
		}
		if cap(priv) != len(priv) {
			t.Errorf("pair %d: the private key is %d bytes with room for %d, so a caller appending to it writes into whatever follows",
				pair, len(priv), cap(priv))
		}
		if cap(pub) != len(pub) {
			t.Errorf("pair %d: the public key is %d bytes with room for %d, so a caller appending to it writes into whatever follows",
				pair, len(pub), cap(pub))
		}
		// and the control: the two halves really are the halves of one expanded key, so the
		// rows above are about where the storage came from rather than about the bytes
		if expanded := ed25519.NewKeyFromSeed(priv); !bytes.Equal(pub, expanded[ed25519.SeedSize:]) {
			t.Errorf("pair %d: the public key is not the one this seed expands to", pair)
		}
	}
}

// Every registered suite names the signature scheme this file computes.
//
// The two entries agree on ed25519 and on 32 byte keys, so nothing here can tell
// self.params.NsigPriv from a literal 32 and no input separates a length check that reads
// the registry from one that does not. A third suite naming another scheme would reach
// ed25519.NewKeyFromSeed with a seed of the wrong length and panic inside the standard
// library rather than being refused, so the guard reads the registry rather than this
// file, in the shape TestEverySuiteNamesTheHashTheProviderComputes already uses for the
// hash.
func TestEverySuiteNamesTheSignatureSchemeTheProviderComputes(t *testing.T) {
	suites := Suites()
	if len(suites) == 0 {
		t.Fatalf("the registry named no suite, so this gate checked nothing")
	}
	for _, suite := range suites {
		params, err := LookupSuite(suite)
		if err != nil {
			t.Fatalf("look up %#04x: %v", uint16(suite), err)
		}
		if params.SignatureId != SignatureSchemeEd25519 {
			t.Errorf("%s names signature scheme %#04x, and this package signs with ed25519",
				params.Name, params.SignatureId)
		}
		if params.NsigPriv != ed25519.SeedSize {
			t.Errorf("%s fixes a %d byte private signature key, and ed25519 seeds are %d",
				params.Name, params.NsigPriv, ed25519.SeedSize)
		}
		if params.NsigPub != ed25519.PublicKeySize {
			t.Errorf("%s fixes a %d byte public signature key, and ed25519 public keys are %d",
				params.Name, params.NsigPub, ed25519.PublicKeySize)
		}
	}
}

// The file declaring one method of the provider, found rather than named.
//
// Task 12 shipped a gate that was told which file to read, and the implementation moved:
// the identical defect failed in crypto.go and passed all 2230 tests in crypto_labels.go. A
// gate that finds its own subject cannot be walked away from, and a subject that is in no
// file, or in two, is fatal rather than clean.
func sourceDeclaringProviderMethod(t *testing.T, name string) parsedSource {
	t.Helper()
	found := []parsedSource{}
	declaring := []string{}
	for _, path := range packageSourcePaths(t) {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		parsed := mustParseSource(t, path)
		if slices.Contains(parsed.methodsOn(providerReceiver), name) {
			found = append(found, parsed)
			declaring = append(declaring, path)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s is declared on %s in %v, want exactly one file of this package", name, providerReceiver, declaring)
	}
	return found[0]
}

// The three signature methods, statement by statement.
//
// Everything above walks the two directions a lenient verify can be caught in, and the class
// it walks is generated rather than listed — but a class is still a neighbourhood, and the
// shapes outside it are exactly the ones nobody thought to generate. A verify falling back
// to the preimage over the digest of the content is a member of no generator in this file.
//
// Three further weakenings are behaviourally invisible altogether, and were measured to be:
//
//   - the key length gates read self.params, and both registered suites fix 32 and 32, so a
//     literal ed25519.SeedSize in their place agrees with every input there is. Measured,
//     eight such mutants survive every test in this package.
//   - the signature length gate changes no answer at all, which crypto_labels.go says in as
//     many words: crypto/ed25519 refuses every length but 64 as the first statement of its
//     own verify.
//   - the public half is cloned out of the expanded key rather than sliced from it, and a
//     slice would keep the secret seed alive behind a public key with nothing able to see
//     the difference.
//
// So the bodies are pinned as shapes, in the form TestMacVerifyIsOnlyTheConstantTimeComparison
// already uses for the same reason. Each control below is a body that passes every other
// test in this package, which is what says the pin carries something they do not.
var signWithLabelStatements = []string{
	"if len(priv) != self.params.NsigPriv {\n\treturn nil, ErrBadSignatureKey\n}",
	"return ed25519.Sign(ed25519.NewKeyFromSeed(priv), mlsSignContent(label, content)), nil",
}

var verifyWithLabelStatements = []string{
	"if len(pub) != self.params.NsigPub {\n\treturn ErrBadSignatureKey\n}",
	"if len(sig) != ed25519.SignatureSize {\n\treturn ErrCryptoBadSignature\n}",
	"if !ed25519.Verify(ed25519.PublicKey(pub), mlsSignContent(label, content), sig) {\n\treturn ErrCryptoBadSignature\n}",
	"return nil",
}

var signatureKeyPairStatements = []string{
	"seed := make([]byte, self.params.NsigPriv)",
	"if _, err := io.ReadFull(self.random, seed); err != nil {\n\treturn nil, nil, err\n}",
	"expanded := ed25519.NewKeyFromSeed(seed)",
	"return SignaturePrivateKey(seed), SignaturePublicKey(bytes.Clone(expanded[ed25519.SeedSize:])), nil",
}

// A verify that round trips, stays label bound, refuses every alteration, matches the
// published vector, and accepts a signature the key really made under a different label.
//
// The fallback is the preimage over the digest of the content, which is outside every
// generator above: no sequence of edits to a three byte content produces a thirty two byte
// digest of it. This is the shape the pin exists for.
const lenientVerifyControl = `package mls

func (self *suiteCryptoProvider) VerifyWithLabel(pub SignaturePublicKey, label string, content []byte, sig []byte) error {
	if len(pub) != self.params.NsigPub {
		return ErrBadSignatureKey
	}
	if len(sig) != ed25519.SignatureSize {
		return ErrCryptoBadSignature
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), mlsSignContent(label, content), sig) {
		if ed25519.Verify(ed25519.PublicKey(pub), mlsSignContent(label, self.Hash(content)), sig) {
			return nil
		}
		return ErrCryptoBadSignature
	}
	return nil
}
`

// A sign whose length gate reads ed25519 rather than the suite it was built for. Every
// registered suite fixes 32, so no input tells the two apart; a suite naming another scheme
// would reach ed25519.NewKeyFromSeed and panic either way, which is what the comment on the
// gate says and what this control keeps honest.
const registryBlindSignControl = `package mls

func (self *suiteCryptoProvider) SignWithLabel(priv SignaturePrivateKey, label string, content []byte) ([]byte, error) {
	if len(priv) != ed25519.SeedSize {
		return nil, ErrBadSignatureKey
	}
	return ed25519.Sign(ed25519.NewKeyFromSeed(priv), mlsSignContent(label, content)), nil
}
`

// A generator whose public half is a window onto the expanded key rather than a copy of it.
// The bytes are the same, the capacity is the same, and the sixty four byte array whose
// first half is the secret seed stays reachable for as long as the public key does.
const slicedPublicKeyControl = `package mls

func (self *suiteCryptoProvider) SignatureKeyPair() (SignaturePrivateKey, SignaturePublicKey, error) {
	seed := make([]byte, self.params.NsigPriv)
	if _, err := io.ReadFull(self.random, seed); err != nil {
		return nil, nil, err
	}
	expanded := ed25519.NewKeyFromSeed(seed)
	return SignaturePrivateKey(seed), SignaturePublicKey(expanded[ed25519.SeedSize:]), nil
}
`

// The provider methods this file declares, pinned whole rather than filtered by name. Plan
// task 15 adds EncryptWithLabel and DecryptWithLabel; whichever file they land in, they fail
// here until somebody decides whether they belong in the pin above.
var labelProviderMethods = []string{
	"DeriveSecret", "DeriveTreeSecret", "ExpandWithLabel", "SignWithLabel", "SignatureKeyPair", "VerifyWithLabel",
}

func TestTheSignatureMethodsAreOnlyTheirOwnPreimage(t *testing.T) {
	for _, testCase := range []struct {
		name string
		want []string
	}{
		{name: "SignWithLabel", want: signWithLabelStatements},
		{name: "VerifyWithLabel", want: verifyWithLabelStatements},
		{name: "SignatureKeyPair", want: signatureKeyPairStatements},
	} {
		source := sourceDeclaringProviderMethod(t, testCase.name)
		if got := source.statementsOf(t, providerReceiver, testCase.name); !slices.Equal(got, testCase.want) {
			t.Errorf("%s is\n%s\nwant\n%s", testCase.name,
				strings.Join(got, "\n"), strings.Join(testCase.want, "\n"))
		}
	}
	// and the matcher reads each control as the different body it is, so a matcher that
	// stopped matching fails here rather than issuing the real bodies a clean bill
	for _, testCase := range []struct {
		name    string
		method  string
		control string
		want    []string
	}{
		{name: "a verify with a fallback preimage", method: "VerifyWithLabel",
			control: lenientVerifyControl, want: verifyWithLabelStatements},
		{name: "a sign reading its length from ed25519", method: "SignWithLabel",
			control: registryBlindSignControl, want: signWithLabelStatements},
		{name: "a generator slicing its public half", method: "SignatureKeyPair",
			control: slicedPublicKeyControl, want: signatureKeyPairStatements},
	} {
		control := mustParseText(t, testCase.name, testCase.control)
		if slices.Equal(control.statementsOf(t, providerReceiver, testCase.method), testCase.want) {
			t.Errorf("the matcher read %s as the shape above", testCase.name)
		}
	}
	// and the pin names every provider method of the file it reads, so a construction added
	// beside these three is a decision somebody writes down rather than a gap
	declaring := sourceDeclaringProviderMethod(t, "VerifyWithLabel")
	if declared := declaring.methodsOn(providerReceiver); !slices.Equal(declared, labelProviderMethods) {
		t.Errorf("the file declaring VerifyWithLabel declares %v, and this gate knows of %v",
			declared, labelProviderMethods)
	}
}

// struct { opaque label<V>; opaque context<V> } EncryptContext, assembled without syntax.
//
// It builds the same bytes as referenceSignContent, and that is a fact about RFC 9420
// rather than a shortcut taken here: section 5.1.2's SignContent and section 5.1.3's
// EncryptContext are two structs of the same shape over two different second fields. The
// coincidence is exactly why this is written out a second time instead of calling that
// one. A reference that delegated could not tell an EncryptContext encoder which had
// become an alias of the SignContent one from an encoder that agreed with it, and the two
// are separate structures which a later revision of either may move apart.
func referenceEncryptContext(label string, context []byte) []byte {
	prefixed := []byte(MlsLabelPrefix + label)
	return concatBytes(referenceVarint(len(prefixed)), prefixed, referenceVarint(len(context)), context)
}

// What the two sweeps below compare, counted for the same reason as every other total in
// this file: a loop that stopped iterating reports exactly what a complete one reports.
// The spaces are the two the SignContent sweeps cover, because the field shapes and the
// varint boundary they cross are the same.
const (
	encryptContextLengthSweepComparisons = 61 * 71
	encryptContextByteSweepComparisons   = 9 * 5 * 256
)

// mlsEncryptContext agrees with an independently written encoder over a swept space
// rather than at the handful of shapes anybody wrote down.
//
// The two sweeps are the ones TestSignContentMatchesAnIndependentEncoder runs and for the
// same two reasons. The first varies both lengths, which separates a hand rolled single
// octet prefix from the varint at 64 and an omitted field from an empty one at 0. The
// second varies the leading byte at short lengths, because a defect can be keyed on what
// a label says rather than on how long it is, and every label in every corpus vendored
// here begins with a capital letter.
func TestEncryptContextMatchesAnIndependentEncoder(t *testing.T) {
	compared := 0
	for labelLength := 0; labelLength <= 60; labelLength++ {
		label := string(sweptBytes(0x40, labelLength))
		for contextLength := 0; contextLength <= 70; contextLength++ {
			compared++
			context := sweptBytes(0x80, contextLength)
			got := mlsEncryptContext(label, context)
			if want := referenceEncryptContext(label, context); !bytes.Equal(got, want) {
				t.Fatalf("mlsEncryptContext over a %d byte label and a %d byte context = %x, want %x",
					labelLength, contextLength, got, want)
			}
		}
	}
	if compared != encryptContextLengthSweepComparisons {
		t.Fatalf("the length sweep compared %d encodings, want %d", compared, encryptContextLengthSweepComparisons)
	}
	compared = 0
	for labelLength := 0; labelLength <= 8; labelLength++ {
		for contextLength := 0; contextLength <= 4; contextLength++ {
			for first := 0; first < 256; first++ {
				compared++
				label := string(sweptBytes(byte(first), labelLength))
				context := sweptBytes(byte(first)^0x55, contextLength)
				got := mlsEncryptContext(label, context)
				if want := referenceEncryptContext(label, context); !bytes.Equal(got, want) {
					t.Fatalf("mlsEncryptContext over a %d byte label beginning %#02x and a %d byte context = %x, want %x",
						labelLength, first, contextLength, got, want)
				}
			}
		}
	}
	if compared != encryptContextByteSweepComparisons {
		t.Fatalf("the byte sweep compared %d encodings, want %d", compared, encryptContextByteSweepComparisons)
	}
	// and the reference is not the implementation written a second time: it must disagree
	// with an encoder that dropped a length prefix, or the sweeps above compare nothing
	if bytes.Equal(referenceEncryptContext("a", []byte("bc")), concatBytes([]byte(MlsLabelPrefix+"a"), []byte("bc"))) {
		t.Errorf("the reference encoder builds the unframed concatenation, so it frames nothing")
	}
}

func TestEncryptContextEncoding(t *testing.T) {
	// EncryptContext is { opaque label<V>; opaque context<V> } and the label carries the
	// "MLS 1.0 " prefix. This becomes the hpke info, and RFC 9420 section 5.1.3 seals
	// with an empty aead aad: the context travels through info and never through aad.
	//
	// These rows are read off the RFC rather than published, so
	// TestDecryptWithLabelMatchesTheCryptoBasicsVectors is the authority and this is what
	// says which field moved when it fails.
	for _, testCase := range []struct {
		name    string
		label   string
		context []byte
		want    []byte
	}{
		{
			name:    "a two byte context",
			label:   "UpdatePathNode",
			context: []byte{0xca, 0xfe},
			want: concatBytes([]byte{byte(len(MlsLabelPrefix + "UpdatePathNode"))},
				[]byte(MlsLabelPrefix+"UpdatePathNode"), []byte{0x02, 0xca, 0xfe}),
		},
		{
			// an empty context still writes its length byte, which is the one shape a
			// round trip cannot see: with no context bytes the readings "field omitted"
			// and "field present and empty" differ only by this 0x00.
			name:    "an empty label and an empty context",
			label:   "",
			context: nil,
			want:    concatBytes([]byte{byte(len(MlsLabelPrefix))}, []byte(MlsLabelPrefix), []byte{0x00}),
		},
		{
			// a context of 64 bytes crosses into the two byte prefix, so a hand rolled
			// single byte length encodes 0x40 here and describes a context 63 bytes long
			name:    "a context at the two byte prefix boundary",
			label:   "y",
			context: bytes.Repeat([]byte{0x5a}, 64),
			want: concatBytes([]byte{byte(len(MlsLabelPrefix + "y"))}, []byte(MlsLabelPrefix+"y"),
				[]byte{0x40, 0x40}, bytes.Repeat([]byte{0x5a}, 64)),
		},
	} {
		if got := mlsEncryptContext(testCase.label, testCase.context); !bytes.Equal(got, testCase.want) {
			t.Errorf("%s: mlsEncryptContext = %x, want %x", testCase.name, got, testCase.want)
		}
	}
}

func TestEncryptWithLabelRoundTrip(t *testing.T) {
	for _, suite := range Suites() {
		crypto := mustProvider(t, suite)
		params, err := LookupSuite(suite)
		if err != nil {
			t.Fatalf("suite %#04x: %v", uint16(suite), err)
		}
		priv, pub, err := crypto.DeriveKeyPair(bytes.Repeat([]byte{0x14}, 32))
		if err != nil {
			t.Fatalf("suite %#04x DeriveKeyPair: %v", uint16(suite), err)
		}
		context := []byte("the group context")
		plaintext := bytes.Repeat([]byte{0x15}, 32)
		kemOutput, ciphertext, err := EncryptWithLabel(crypto, pub, "UpdatePathNode", context, plaintext)
		if err != nil {
			t.Fatalf("suite %#04x encrypt: %v", uint16(suite), err)
		}
		// the two results are both byte slices, so a transposed return compiles and the
		// round trip below catches it only while the two lengths happen to differ. what
		// says which is which is the kem's Nenc and the aead's expansion by Nt.
		if len(kemOutput) != params.Nenc {
			t.Errorf("suite %#04x encapsulated key is %d bytes, want Nenc = %d",
				uint16(suite), len(kemOutput), params.Nenc)
		}
		if len(ciphertext) != len(plaintext)+params.Nt {
			t.Errorf("suite %#04x ciphertext is %d bytes, want the plaintext plus Nt = %d",
				uint16(suite), len(ciphertext), len(plaintext)+params.Nt)
		}
		back, err := DecryptWithLabel(crypto, priv, "UpdatePathNode", context, kemOutput, ciphertext)
		if err != nil {
			t.Fatalf("suite %#04x decrypt: %v", uint16(suite), err)
		}
		if !bytes.Equal(back, plaintext) {
			t.Fatalf("suite %#04x round trip returned %x", uint16(suite), back)
		}
		// and a second call to the same key under the same label is a second
		// encapsulation, so an implementation that cached a context or an ephemeral key
		// fails here rather than sealing two plaintexts under one key and one nonce
		otherKemOutput, otherCiphertext, err := EncryptWithLabel(crypto, pub, "UpdatePathNode", context, plaintext)
		if err != nil {
			t.Fatalf("suite %#04x encrypt a second time: %v", uint16(suite), err)
		}
		if bytes.Equal(kemOutput, otherKemOutput) || bytes.Equal(ciphertext, otherCiphertext) {
			t.Errorf("suite %#04x sealed the same plaintext to the same key twice identically", uint16(suite))
		}
	}
}

func TestEncryptWithLabelIsLabelAndContextBound(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	priv, pub, err := crypto.DeriveKeyPair(bytes.Repeat([]byte{0x16}, 32))
	if err != nil {
		t.Fatalf("DeriveKeyPair: %v", err)
	}
	kemOutput, ciphertext, err := EncryptWithLabel(crypto, pub, "UpdatePathNode", []byte("context a"), []byte("secret"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// the control first: what follows is only meaningful against a decrypt that opens the
	// one message it should
	if _, err := DecryptWithLabel(crypto, priv, "UpdatePathNode", []byte("context a"), kemOutput, ciphertext); err != nil {
		t.Fatalf("the message sealed under this label and context was refused: %v", err)
	}
	if _, err := DecryptWithLabel(crypto, priv, "Welcome", []byte("context a"), kemOutput, ciphertext); !errors.Is(err, ErrAeadOpen) {
		t.Errorf("wrong label decrypted: error = %v, want ErrAeadOpen", err)
	}
	if _, err := DecryptWithLabel(crypto, priv, "UpdatePathNode", []byte("context b"), kemOutput, ciphertext); !errors.Is(err, ErrAeadOpen) {
		t.Errorf("wrong context decrypted: error = %v, want ErrAeadOpen", err)
	}
}

func TestProviderHpkeSealUsesAnEmptyAadForLabelledEncryption(t *testing.T) {
	// EncryptWithLabel must reach HpkeSeal with a nil aad. sealing the context into aad
	// instead of info would round trip inside this implementation and fail every peer,
	// which is exactly the class of bug the interop harness is slow to find.
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	priv, pub, err := crypto.DeriveKeyPair(bytes.Repeat([]byte{0x17}, 32))
	if err != nil {
		t.Fatalf("DeriveKeyPair: %v", err)
	}
	context := []byte("the group context")
	kemOutput, ciphertext, err := EncryptWithLabel(crypto, pub, "UpdatePathNode", context, []byte("secret"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	back, err := crypto.HpkeOpen(priv, kemOutput, mlsEncryptContext("UpdatePathNode", context), nil, ciphertext)
	if err != nil {
		t.Fatalf("open with info=EncryptContext and aad=nil failed: %v", err)
	}
	if !bytes.Equal(back, []byte("secret")) {
		t.Fatalf("open returned %q", back)
	}
	// and the transposition itself, walked from the peer's side rather than from this
	// one. the row above says the labelled seal is openable the way the RFC says; these
	// say the other two placements are not, so an implementation that put the context in
	// aad is refused here instead of talking happily to itself.
	for _, testCase := range []struct {
		name string
		info []byte
		aad  []byte
	}{
		{name: "a message carrying its context in aad", info: nil, aad: mlsEncryptContext("UpdatePathNode", context)},
		{name: "a message carrying its context in info and aad",
			info: mlsEncryptContext("UpdatePathNode", context),
			aad:  mlsEncryptContext("UpdatePathNode", context)},
	} {
		otherKemOutput, otherCiphertext, err := crypto.HpkeSeal(pub, testCase.info, testCase.aad, []byte("secret"))
		if err != nil {
			t.Fatalf("%s: seal: %v", testCase.name, err)
		}
		if _, err := DecryptWithLabel(crypto, priv, "UpdatePathNode", context,
			otherKemOutput, otherCiphertext); !errors.Is(err, ErrAeadOpen) {
			t.Errorf("%s decrypted: error = %v, want ErrAeadOpen", testCase.name, err)
		}
	}
}

// What the tamper table below refuses, counted for the same reason as every other total
// here: a loop that stopped iterating reports exactly what a complete one reports. The
// two byte sweeps and the truncations are sized from the message they run on, so the
// total is assembled at the call site rather than written out as a number here.
const (
	// an empty kem output, one byte short of Nenc, one byte over, and twice Nenc
	decryptKemOutputLengthRefusals = 4
	// another recipient's key, an all zero ciphertext, an all one ciphertext, and one
	// byte appended to a ciphertext that was otherwise authentic
	decryptNamedRefusals = 4
)

// A ciphertext this key really was sent, altered anywhere, is refused, and so is an
// authentic one opened with another key.
//
// This is the half a round trip cannot see at all. A DecryptWithLabel returning nil, nil
// passes any test that encrypts and then decrypts its own message: the plaintext compares
// equal to nothing only when somebody looks, and the error is the only thing separating an
// authentic empty message from every forgery of exactly tag length. So every row here
// reads the error and the returned slice both, and the slice must be nil: a caller that
// branches on the bytes rather than on the error accepts whatever the last row produced.
//
// Every byte of the ciphertext and every byte of the encapsulated key are walked rather
// than one of each. A decrypt that authenticated a prefix of its ciphertext is caught
// wherever it stopped reading, and one that read only part of the encapsulated key is
// caught the same way — neither is visible from a single altered byte somebody picked.
func TestDecryptWithLabelRefusesEveryTamperedCiphertext(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("look up the suite this table is built over: %v", err)
	}
	priv, pub, err := crypto.DeriveKeyPair(bytes.Repeat([]byte{0x18}, 32))
	if err != nil {
		t.Fatalf("DeriveKeyPair: %v", err)
	}
	otherPriv, _, err := crypto.DeriveKeyPair(bytes.Repeat([]byte{0x19}, 32))
	if err != nil {
		t.Fatalf("DeriveKeyPair a second time: %v", err)
	}
	label := "UpdatePathNode"
	context := []byte("the group context")
	plaintext := []byte("the sealed secret")
	kemOutput, ciphertext, err := EncryptWithLabel(crypto, pub, label, context, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// the control first: what follows is only meaningful against a decrypt that opens the
	// one message it should
	if back, err := DecryptWithLabel(crypto, priv, label, context, kemOutput, ciphertext); err != nil {
		t.Fatalf("the authentic message was refused: %v", err)
	} else if !bytes.Equal(back, plaintext) {
		t.Fatalf("the authentic message opened as %x", back)
	}
	refusals := 0
	refuse := func(name string, key HpkePrivateKey, kem []byte, sealed []byte, want error) {
		refusals++
		back, err := DecryptWithLabel(crypto, key, label, context, kem, sealed)
		if !errors.Is(err, want) {
			t.Errorf("%s decrypted: error = %v, want %v", name, err, want)
		}
		if back != nil {
			t.Errorf("%s was refused and still answered %x; the error is the only thing separating "+
				"an authentic empty message from a forgery", name, back)
		}
	}
	// every byte of the ciphertext, which covers the aead body and its tag alike
	for i := range ciphertext {
		altered := bytes.Clone(ciphertext)
		altered[i] ^= 0x80
		refuse(fmt.Sprintf("a ciphertext with byte %d altered", i), priv, kemOutput, altered, ErrAeadOpen)
	}
	// every byte of the encapsulated key, which is what says the decapsulation reads the
	// whole of it rather than enough of it to look right
	for i := range kemOutput {
		altered := bytes.Clone(kemOutput)
		altered[i] ^= 0x01
		refuse(fmt.Sprintf("an encapsulated key with byte %d altered", i), priv, altered, ciphertext, ErrAeadOpen)
	}
	// every prefix of the ciphertext, including the empty one: a decrypt that stopped
	// authenticating at some offset is refused wherever that offset falls
	for i := range ciphertext {
		refuse(fmt.Sprintf("a ciphertext truncated to %d bytes", i), priv, kemOutput, ciphertext[:i], ErrAeadOpen)
	}
	refuse("a ciphertext with a byte appended", priv, kemOutput, concatBytes(ciphertext, []byte{0x00}), ErrAeadOpen)
	refuse("another recipient's key", otherPriv, kemOutput, ciphertext, ErrAeadOpen)
	refuse("an all zero ciphertext", priv, kemOutput, make([]byte, len(ciphertext)), ErrAeadOpen)
	refuse("a ciphertext of every one bit", priv, kemOutput, bytes.Repeat([]byte{0xff}, len(ciphertext)), ErrAeadOpen)
	// and an encapsulated key of the wrong length stops at the kem's own gate rather than
	// reaching the aead, which is a different sentinel and says so
	for _, n := range []int{0, params.Nenc - 1, params.Nenc + 1, 2 * params.Nenc} {
		refuse(fmt.Sprintf("a %d byte encapsulated key", n), priv, make([]byte, n), ciphertext, ErrBadKemOutput)
	}
	if want := 2*len(ciphertext) + len(kemOutput) + decryptNamedRefusals + decryptKemOutputLengthRefusals; refusals != want {
		t.Fatalf("the table refused %d alterations, want %d", refusals, want)
	}
	// and the control for the whole test: the authentic message still opens, so nothing
	// above is satisfied by a decrypt that refuses everything
	if back, err := DecryptWithLabel(crypto, priv, label, context, kemOutput, ciphertext); err != nil {
		t.Errorf("the authentic message was refused after the table: %v", err)
	} else if !bytes.Equal(back, plaintext) {
		t.Errorf("the authentic message opened as %x after the table", back)
	}
}

// One encapsulation to one recipient, reused across a whole class of infos.
//
// Every ciphertext it produces is one a peer could really have sent. RFC 9180 base mode
// derives the key schedule from the shared secret and the info, and the encapsulated key
// depends on neither, so sealing under ten thousand infos to one recipient is one
// encapsulation and ten thousand key schedules. That is what makes the class below
// affordable: the alternative is an x25519 multiplication per candidate on the sending
// side as well as on the receiving one, and the receiving one is the side under test.
//
// TestTheLabelledSealerIsHpkeSealBase is what says this really is the sending half rather
// than something shaped like it, by building one over a fixed ephemeral key and comparing
// against HpkeSealBase over the same one.
type labelledSealer struct {
	params    *SuiteParams
	kemOutput []byte
	secret    []byte
}

// A sealer over one encapsulation drawn from a caller's reader, so a fixed reader gives a
// sealer whose messages are byte for byte reproducible.
func newLabelledSealer(t *testing.T, params *SuiteParams, random io.Reader, pub HpkePublicKey) *labelledSealer {
	t.Helper()
	secret, kemOutput, err := hpkeEncap(random, params, pub)
	if err != nil {
		t.Fatalf("encapsulate the shared secret the class is sealed under: %v", err)
	}
	return &labelledSealer{params: params, kemOutput: kemOutput, secret: secret}
}

// One message under one info, sealed at sequence zero with an empty aad, which is what
// RFC 9420 section 5.1.3 puts on the wire.
func (self *labelledSealer) seal(t *testing.T, info []byte, plaintext []byte) []byte {
	t.Helper()
	context, err := hpkeKeySchedule(self.params, self.secret, info)
	if err != nil {
		t.Fatalf("key schedule over a %d byte info: %v", len(info), err)
	}
	ciphertext, err := context.Seal(nil, plaintext)
	if err != nil {
		t.Fatalf("seal under a %d byte info: %v", len(info), err)
	}
	return ciphertext
}

// The sealer is the sending half of hpke and not a second implementation of it.
//
// Without this the class below is a class of messages nothing else produces, and a decrypt
// that refused all of them would prove nothing about the messages a peer really sends. The
// comparison is against HpkeSealBase over the same ephemeral key, so the two agree byte for
// byte or the sealer is not what it claims.
func TestTheLabelledSealerIsHpkeSealBase(t *testing.T) {
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("look up the suite: %v", err)
	}
	_, pub, err := HpkeDeriveKeyPair(params, bytes.Repeat([]byte{0x1a}, 32))
	if err != nil {
		t.Fatalf("HpkeDeriveKeyPair: %v", err)
	}
	plaintext := []byte("the sealed secret")
	compared := 0
	for _, info := range [][]byte{nil, {}, []byte("info"), mlsEncryptContext("UpdatePathNode", []byte("context"))} {
		compared++
		sealer := newLabelledSealer(t, params, constantReader{value: 0x88}, pub)
		kemOutput, ciphertext, err := HpkeSealBase(constantReader{value: 0x88}, params, pub, info, nil, plaintext)
		if err != nil {
			t.Fatalf("HpkeSealBase over a %d byte info: %v", len(info), err)
		}
		if !bytes.Equal(sealer.kemOutput, kemOutput) {
			t.Errorf("the sealer encapsulated %x and HpkeSealBase %x over one ephemeral key",
				sealer.kemOutput, kemOutput)
		}
		if got := sealer.seal(t, info, plaintext); !bytes.Equal(got, ciphertext) {
			t.Errorf("the sealer produced %x over a %d byte info and HpkeSealBase %x", got, len(info), ciphertext)
		}
	}
	if compared != 4 {
		t.Fatalf("compared %d infos, want 4", compared)
	}
}

// How many infos the walk draws per demanded pair, and the seed it draws them from.
//
// A seed of its own rather than the signature walk's, so the two classes are two samples
// of the neighbourhood rather than one sample used twice. The seed is written down so a
// failure reproduces from this line rather than from a lucky run.
const encryptProbeWalkSeed = 0x2f8c61a4e97d05b3

// What the generated class holds, pinned so a generator that degenerated fails rather than
// reporting exactly what a working one reports. Two numbers, for the reason
// signatureBuiltPreimages records: the built total moves when a generator stops
// generating, and the distinct total moves when the encoding changes under it.
const (
	encryptBuiltContexts   = 35226
	encryptRefusedContexts = 29145
)

// A message this recipient's key really can decapsulate, sealed under an info the receiver
// does not demand, is refused.
//
// This is the direction the attacker picks, and the one this project has now paid for
// twice. Task 8's aad and info binding was walked in one direction only — a message sealed
// under the demanded info, opened while demanding another — and twelve lenient fallback
// mutants passed all 78 tests, each of them accepting a message sealed with no info at
// all. Walking it that way cannot see any of them: the fallback fires on the receiving
// side, and a receiver that retries with nil info still opens the message that was sealed
// with the right one. What sees it is a message sealed with the wrong info, or with none,
// arriving at a receiver demanding the right one.
//
// So the class is generated on the sending side. Four generators carry it, none of which
// names a value: singleByteEdits over the whole alphabet, fieldRewrites as operations
// rather than results, fieldArrangements over both framings of both fields, and a
// deterministic multi edit walk outside all three. The infos an implementer would fall
// back to — nil, the empty vector, the bare label, the unframed concatenation, the context
// alone — are all members, and so are the ones nobody would write down.
//
// What no generator can do is enumerate every info, so two things bound it. The count of
// distinct ones is asserted, and TestTheLabelledEncryptionIsOnlyItsOwnContext covers what a
// neighbourhood cannot by reading the constructions' own statements.
func TestDecryptWithLabelRefusesCiphertextsSealedUnderAnyOtherContext(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("look up the suite this class is built over: %v", err)
	}
	priv, pub, err := crypto.DeriveKeyPair(bytes.Repeat([]byte{0x1b}, 32))
	if err != nil {
		t.Fatalf("DeriveKeyPair: %v", err)
	}
	plaintext := []byte("the sealed secret")
	sealer := newLabelledSealer(t, params, rand.Reader, pub)
	random := newLabelProbeRand(encryptProbeWalkSeed)
	refused := 0
	built := 0
	for _, pair := range signatureProbePairs() {
		demanded := mlsEncryptContext(pair.label, pair.content)
		// the control first, per pair: what follows is only meaningful against a decrypt
		// that opens the one message it should, and it is also what says this sealer's
		// messages reach the receiver at all
		if back, err := DecryptWithLabel(crypto, priv, pair.label, pair.content,
			sealer.kemOutput, sealer.seal(t, demanded, plaintext)); err != nil {
			t.Fatalf("%s: the message sealed under the demanded context was refused: %v", pair.name, err)
		} else if !bytes.Equal(back, plaintext) {
			t.Fatalf("%s: the message sealed under the demanded context opened as %x", pair.name, back)
		}
		tried := map[string]bool{string(demanded): true}
		generated := alternativePreimages(random, pair, mlsEncryptContext)
		if len(generated) == 0 {
			t.Fatalf("%s: the generators built nothing, so this pair observed nothing", pair.name)
		}
		built += len(generated)
		for _, info := range generated {
			if tried[string(info)] {
				continue
			}
			tried[string(info)] = true
			refused++
			back, err := DecryptWithLabel(crypto, priv, pair.label, pair.content,
				sealer.kemOutput, sealer.seal(t, info, plaintext))
			if !errors.Is(err, ErrAeadOpen) {
				t.Errorf("%s: a message sealed under info %x opened as one under %q over %x: error = %v, want ErrAeadOpen",
					pair.name, info, pair.label, pair.content, err)
			}
			if back != nil {
				t.Errorf("%s: a message sealed under info %x was refused and still answered %x",
					pair.name, info, back)
			}
		}
	}
	if built != encryptBuiltContexts {
		t.Fatalf("the generators built %d contexts, want %d", built, encryptBuiltContexts)
	}
	if refused != encryptRefusedContexts {
		t.Fatalf("the generated class refused %d distinct contexts, want %d", refused, encryptRefusedContexts)
	}
	// and the control for the whole test: a message sealed under the info the receiver
	// does demand still opens, so nothing above is satisfied by a decrypt that refuses
	// everything
	demanded := mlsEncryptContext("UpdatePathNode", []byte("the group context"))
	if back, err := DecryptWithLabel(crypto, priv, "UpdatePathNode", []byte("the group context"),
		sealer.kemOutput, sealer.seal(t, demanded, plaintext)); err != nil {
		t.Errorf("the message sealed under the demanded context was refused: %v", err)
	} else if !bytes.Equal(back, plaintext) {
		t.Errorf("the message sealed under the demanded context opened as %x", back)
	}
}

// The published DecryptWithLabel answers the corpus must contribute, counted for the same
// reason as every other total here. crypto-basics publishes one encrypt_with_label entry
// per suite and two of its seven suites are registered.
const labelKatEncryptComparisons = 2

// The RFC 9420 section 5.1.3 encryption, held to bytes this project did not compute.
//
// Nothing else in this file can hold it. EncryptWithLabel draws a fresh ephemeral key, so
// its output is not a known answer and cannot be compared against one; what is published
// is a message somebody else sealed, and opening that is the only direction in which the
// construction meets bytes from outside this tree. An implementation that put the context
// in the aad, dropped the "MLS 1.0 " prefix, dropped either length prefix or transposed the
// two fields round trips against itself perfectly and fails here, which is the whole reason
// the corpus is vendored.
func TestDecryptWithLabelMatchesTheCryptoBasicsVectors(t *testing.T) {
	entries := []labelKatBasics{}
	loadLabelKat(t, "crypto-basics.json", &entries)
	compared := 0
	for _, entry := range entries {
		suite := CipherSuite(entry.CipherSuite)
		if !IsRegisteredSuite(suite) {
			continue
		}
		crypto := mustProvider(t, suite)
		vector := entry.EncryptWithLabel
		what := fmt.Sprintf("suite %#04x encrypt_with_label", uint16(suite))
		priv := HpkePrivateKey(mustDecodeHex(t, what+" priv", vector.Priv))
		pub := HpkePublicKey(mustDecodeHex(t, what+" pub", vector.Pub))
		context := mustDecodeHex(t, what+" context", vector.Context)
		kemOutput := mustDecodeHex(t, what+" kem_output", vector.KemOutput)
		ciphertext := mustDecodeHex(t, what+" ciphertext", vector.Ciphertext)
		plaintext, err := DecryptWithLabel(crypto, priv, vector.Label, context, kemOutput, ciphertext)
		if err != nil {
			t.Fatalf("%s: the published message was refused: %v", what, err)
		}
		assertLabelKat(t, what, plaintext, vector.Plaintext)
		compared++
		// the published pair really is a pair, which is what says this package reads the
		// private key the way the publisher wrote it rather than agreeing by accident with
		// a scalar it never checked
		key, err := X25519PrivateKey(priv)
		if err != nil {
			t.Fatalf("%s: the published private key was refused: %v", what, err)
		}
		if got := key.PublicKey().Bytes(); !bytes.Equal(got, pub) {
			t.Errorf("%s: the published private key belongs to %x, and the published public key is %x",
				what, got, pub)
		}
		// and the published message does not open under a label the publisher did not
		// seal under, over bytes this project did not compute
		if _, err := DecryptWithLabel(crypto, priv, vector.Label+"x", context, kemOutput,
			ciphertext); !errors.Is(err, ErrAeadOpen) {
			t.Errorf("%s: the published message opened under another label: error = %v, want ErrAeadOpen",
				what, err)
		}
		// and not under a context the publisher did not seal under either
		if _, err := DecryptWithLabel(crypto, priv, vector.Label, concatBytes(context, []byte{0x00}),
			kemOutput, ciphertext); !errors.Is(err, ErrAeadOpen) {
			t.Errorf("%s: the published message opened under another context: error = %v, want ErrAeadOpen",
				what, err)
		}
	}
	if compared != labelKatEncryptComparisons {
		t.Fatalf("compared %d published encryptions, want %d", compared, labelKatEncryptComparisons)
	}
}

// The file declaring one package level function, found rather than named, for the reason
// sourceDeclaringProviderMethod records: a gate told which file to read reports a clean
// bill on a file the implementation has moved out of. A subject in no file, or in two, is
// fatal rather than clean.
func sourceDeclaringPackageFunction(t *testing.T, name string) parsedSource {
	t.Helper()
	found := []parsedSource{}
	declaring := []string{}
	for _, path := range packageSourcePaths(t) {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		parsed := mustParseSource(t, path)
		for _, function := range packageLevelFunctionsIn(parsed, path) {
			if function.name != name {
				continue
			}
			found = append(found, parsed)
			declaring = append(declaring, path)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s is declared in %v, want exactly one file of this package", name, declaring)
	}
	return found[0]
}

// The three constructions of RFC 9420 section 5.1.3, statement by statement.
var mlsEncryptContextStatements = []string{
	"writer := syntax.NewWriter()",
	"writer.WriteOpaque([]byte(MlsLabelPrefix + label))",
	"writer.WriteOpaque(context)",
	"return mlsLabelBytes(writer)",
}

var encryptWithLabelStatements = []string{
	"return crypto.HpkeSeal(pub, mlsEncryptContext(label, context), nil, plaintext)",
}

var decryptWithLabelStatements = []string{
	"return crypto.HpkeOpen(priv, kemOutput, mlsEncryptContext(label, context), nil, ciphertext)",
}

// The three provider methods they reach hpke through.
var hpkeSealStatements = []string{
	"return HpkeSealBase(self.random, self.params, pub, info, aad, plaintext)",
}

var hpkeOpenStatements = []string{
	"return HpkeOpenBase(self.params, priv, kemOutput, info, aad, ciphertext)",
}

var deriveKeyPairStatements = []string{
	"return HpkeDeriveKeyPair(self.params, ikm)",
}

// An open that retries with no info at all when the first attempt fails.
//
// This is the shape task 8 measured twelve of, and every one of them is caught behaviourally
// by TestDecryptWithLabelRefusesCiphertextsSealedUnderAnyOtherContext, since nil is a member
// of the generated class. It is written out anyway because the pin has to be shown reading a
// body it must reject, and because the next fallback somebody writes will not be this one.
const lenientHpkeOpenControl = `package mls

func (self *suiteCryptoProvider) HpkeOpen(priv HpkePrivateKey, kemOutput []byte, info []byte, aad []byte, ciphertext []byte) ([]byte, error) {
	plaintext, err := HpkeOpenBase(self.params, priv, kemOutput, info, aad, ciphertext)
	if err != nil {
		return HpkeOpenBase(self.params, priv, kemOutput, nil, aad, ciphertext)
	}
	return plaintext, nil
}
`

// An open that retries under the digest of the info it was handed.
//
// No sequence of edits to a label or a context produces the thirty two byte digest of the
// preimage they encode to, so this is outside every generator in this file — the shape the
// pin exists for rather than the shape the class already covers.
const digestFallbackHpkeOpenControl = `package mls

func (self *suiteCryptoProvider) HpkeOpen(priv HpkePrivateKey, kemOutput []byte, info []byte, aad []byte, ciphertext []byte) ([]byte, error) {
	plaintext, err := HpkeOpenBase(self.params, priv, kemOutput, info, aad, ciphertext)
	if err != nil {
		return HpkeOpenBase(self.params, priv, kemOutput, self.Hash(info), aad, ciphertext)
	}
	return plaintext, nil
}
`

// A seal that draws its ephemeral key from the process entropy source rather than from the
// provider's own.
//
// It seals correctly, opens correctly, matches every published message and passes every
// round trip: the encapsulated key is a fresh x25519 key either way, and nothing about a
// ciphertext says which stream produced it. What it costs is everything
// NewCryptoProviderWithRandom exists for. A caller's provider stops being reproducible, and
// the two gates that compare a construction's answer over two providers stop being able to
// see anything, because the answer differs on every call whatever provider was handed in.
const processRandomSealControl = `package mls

func (self *suiteCryptoProvider) HpkeSeal(pub HpkePublicKey, info []byte, aad []byte, plaintext []byte) ([]byte, []byte, error) {
	return HpkeSealBase(rand.Reader, self.params, pub, info, aad, plaintext)
}
`

// An encryption that carries its context in the aead's aad rather than in the hpke info.
// It round trips against itself, matches no published message and talks to no peer, which
// is what TestDecryptWithLabelMatchesTheCryptoBasicsVectors is for; the pin is what says so
// without needing a corpus.
const aadCarryingEncryptControl = `package mls

func EncryptWithLabel(crypto CryptoProvider, pub HpkePublicKey, label string, context []byte, plaintext []byte) ([]byte, []byte, error) {
	return crypto.HpkeSeal(pub, nil, mlsEncryptContext(label, context), plaintext)
}
`

// A decrypt that answers with whatever the open produced and no error. Every refusal in
// this file reads the error, so this dies behaviourally as well; it is here because it is
// the smallest version of "a decrypt that does not decrypt" and the pin has to be shown
// rejecting it.
const errorDiscardingDecryptControl = `package mls

func DecryptWithLabel(crypto CryptoProvider, priv HpkePrivateKey, label string, context []byte, kemOutput []byte, ciphertext []byte) ([]byte, error) {
	plaintext, _ := crypto.HpkeOpen(priv, kemOutput, mlsEncryptContext(label, context), nil, ciphertext)
	return plaintext, nil
}
`

// The package level constructions the file declaring DecryptWithLabel holds, pinned whole
// rather than filtered by name, for the reason labelProviderMethods is: a labelled
// construction added beside these is a decision somebody writes down rather than a gap.
var labelPackageFunctions = []string{
	"DecryptWithLabel", "EncryptWithLabel", "MakeKeyPackageRef", "MakeProposalRef", "RefHash",
	"mlsEncryptContext", "mlsKdfLabel", "mlsLabelBytes", "mlsSignContent",
}

// The labelled encryption is its own EncryptContext and nothing else.
//
// Everything above walks the direction an attacker picks — a message sealed under some
// other info arriving at a receiver demanding the real one — and the class it walks is
// generated rather than listed. But a class is still a neighbourhood, and the shapes
// outside it are exactly the ones nobody thought to generate: an open that retries under
// the digest of the info it was handed is a member of no generator in this file, because no
// sequence of edits to a label or a context produces a digest of the preimage they encode
// to.
//
// Two further weakenings are behaviourally invisible in the other direction. Which of info
// and aad the context travels in is invisible to any test that seals and opens with this
// same implementation, and is visible only against the published message in
// TestDecryptWithLabelMatchesTheCryptoBasicsVectors and against the transposition rows in
// TestProviderHpkeSealUsesAnEmptyAadForLabelledEncryption. And a fresh ephemeral key per
// call is what keeps two messages to one recipient off one nonce, which no equality test
// can see.
//
// So the bodies are pinned as shapes, in the form TestTheSignatureMethodsAreOnlyTheirOwnPreimage
// already uses for the same reason. Each control below is a body that passes a great deal
// of this package, which is what says the pin carries something those tests do not.
func TestTheLabelledEncryptionIsOnlyItsOwnContext(t *testing.T) {
	for _, testCase := range []struct {
		name string
		want []string
	}{
		{name: "mlsEncryptContext", want: mlsEncryptContextStatements},
		{name: "EncryptWithLabel", want: encryptWithLabelStatements},
		{name: "DecryptWithLabel", want: decryptWithLabelStatements},
	} {
		source := sourceDeclaringPackageFunction(t, testCase.name)
		if got := source.statementsOf(t, "", testCase.name); !slices.Equal(got, testCase.want) {
			t.Errorf("%s is\n%s\nwant\n%s", testCase.name,
				strings.Join(got, "\n"), strings.Join(testCase.want, "\n"))
		}
	}
	for _, testCase := range []struct {
		name string
		want []string
	}{
		{name: "HpkeSeal", want: hpkeSealStatements},
		{name: "HpkeOpen", want: hpkeOpenStatements},
		{name: "DeriveKeyPair", want: deriveKeyPairStatements},
	} {
		source := sourceDeclaringProviderMethod(t, testCase.name)
		if got := source.statementsOf(t, providerReceiver, testCase.name); !slices.Equal(got, testCase.want) {
			t.Errorf("%s is\n%s\nwant\n%s", testCase.name,
				strings.Join(got, "\n"), strings.Join(testCase.want, "\n"))
		}
	}
	// and the matcher reads each control as the different body it is, so a matcher that
	// stopped matching fails here rather than issuing the real bodies a clean bill
	for _, testCase := range []struct {
		name     string
		receiver string
		method   string
		control  string
		want     []string
	}{
		{name: "an open that retries with no info", receiver: providerReceiver, method: "HpkeOpen",
			control: lenientHpkeOpenControl, want: hpkeOpenStatements},
		{name: "an open that retries under the digest of its info", receiver: providerReceiver, method: "HpkeOpen",
			control: digestFallbackHpkeOpenControl, want: hpkeOpenStatements},
		{name: "a seal drawing from the process entropy source", receiver: providerReceiver, method: "HpkeSeal",
			control: processRandomSealControl, want: hpkeSealStatements},
		{name: "an encryption carrying its context in aad", receiver: "", method: "EncryptWithLabel",
			control: aadCarryingEncryptControl, want: encryptWithLabelStatements},
		{name: "a decrypt that discards its error", receiver: "", method: "DecryptWithLabel",
			control: errorDiscardingDecryptControl, want: decryptWithLabelStatements},
	} {
		control := mustParseText(t, testCase.name, testCase.control)
		if slices.Equal(control.statementsOf(t, testCase.receiver, testCase.method), testCase.want) {
			t.Errorf("the matcher read %s as the shape above", testCase.name)
		}
	}
	// and the pin names every package level construction of the file it reads, so a
	// labelled construction added beside these is a decision somebody writes down
	declaring := sourceDeclaringPackageFunction(t, "DecryptWithLabel")
	declared := []string{}
	for _, function := range packageLevelFunctionsIn(declaring, "the file declaring DecryptWithLabel") {
		declared = append(declared, function.name)
	}
	slices.Sort(declared)
	if !slices.Equal(declared, labelPackageFunctions) {
		t.Errorf("the file declaring DecryptWithLabel declares %v, and this gate knows of %v",
			declared, labelPackageFunctions)
	}
}

// The label and context lengths the sweep below walks, and the leading bytes it walks at
// short lengths. Both totals are asserted where they are used, for the reason every other
// total in this file is: a loop that stopped iterating reports what a complete one reports.
const (
	unboundSweepLabelLengths   = 21
	unboundSweepContextLengths = 71
	unboundSweepBytes          = 256
	unboundSweepByteLengths    = 3
	unboundSweepCoarsePoints   = 77
	// what the three sweeps refuse between them. seven reframings at each of 2259 points,
	// less the ones that coincided with the info the receiver demanded and were skipped,
	// which is why this is a measured number rather than a product
	unboundSweepRefusals = 16351
)

// The reframings of one demanded pair that carry no binding the receiver demanded, built
// as operations on the pair rather than as values.
//
// These are the infos an implementation falls back to: none at all, an empty one, the
// context raw, the prefixed label alone, the two unframed, the two transposed, and the
// digest of the preimage. Each is skipped where it happens to coincide with the demanded
// info, so a row can never be satisfied by opening the message it was supposed to refuse.
func unboundEncryptContexts(crypto CryptoProvider, label string, context []byte) [][]byte {
	prefixed := []byte(MlsLabelPrefix + label)
	demanded := mlsEncryptContext(label, context)
	candidates := [][]byte{
		nil,
		{},
		bytes.Clone(context),
		prefixed,
		concatBytes(prefixed, context),
		mlsEncryptContext(string(context), []byte(label)),
		crypto.Hash(demanded),
	}
	unbound := [][]byte{}
	for _, candidate := range candidates {
		if bytes.Equal(candidate, demanded) {
			continue
		}
		unbound = append(unbound, candidate)
	}
	return unbound
}

// A message carrying no binding, at every field length the sweep reaches, is refused.
//
// The generated class is four demanded pairs deep, and four pairs fix four label lengths
// and four context lengths. A fallback conditional on what it is handed is invisible to
// all of them: task 14 measured a lenient verify that fired only for labels of eleven
// bytes surviving all 2257 tests of a probe that only ever used two. So this sweeps the
// lengths instead of sampling them, and sweeps the plaintext length with them so the
// ciphertext length moves as well.
//
// The second half sweeps the leading byte at short lengths, because a band can be keyed on
// what a label says rather than on how long it is, and every label in every corpus vendored
// here begins with a capital letter.
//
// What this cannot reach is a band keyed on a length past the end of the sweep. The pin in
// TestTheLabelledEncryptionIsOnlyItsOwnContext is what covers that, by reading the bodies
// rather than by asking them a question they can decline to answer.
func TestDecryptWithLabelRefusesAnUnboundMessageAtEveryFieldLength(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("look up the suite this sweep is built over: %v", err)
	}
	priv, pub, err := crypto.DeriveKeyPair(bytes.Repeat([]byte{0x1c}, 32))
	if err != nil {
		t.Fatalf("DeriveKeyPair: %v", err)
	}
	sealer := newLabelledSealer(t, params, rand.Reader, pub)
	refused := 0
	points := 0
	sweep := func(label string, context []byte, plaintext []byte) {
		points++
		demanded := mlsEncryptContext(label, context)
		// the control at every point: what follows is only meaningful against a decrypt
		// that opens the one message it should, and a control per point is what says the
		// refusals below are about the info rather than about the point
		if back, err := DecryptWithLabel(crypto, priv, label, context,
			sealer.kemOutput, sealer.seal(t, demanded, plaintext)); err != nil {
			t.Fatalf("a %d byte label over a %d byte context: the bound message was refused: %v",
				len(label), len(context), err)
		} else if !bytes.Equal(back, plaintext) {
			t.Fatalf("a %d byte label over a %d byte context: the bound message opened as %x",
				len(label), len(context), back)
		}
		for _, info := range unboundEncryptContexts(crypto, label, context) {
			refused++
			back, err := DecryptWithLabel(crypto, priv, label, context,
				sealer.kemOutput, sealer.seal(t, info, plaintext))
			if !errors.Is(err, ErrAeadOpen) {
				t.Fatalf("a message sealed under info %x opened as one under a %d byte label over a %d byte context: error = %v, want ErrAeadOpen",
					info, len(label), len(context), err)
			}
			if back != nil {
				t.Fatalf("a message sealed under info %x was refused and still answered %x", info, back)
			}
		}
	}
	for labelLength := 0; labelLength < unboundSweepLabelLengths; labelLength++ {
		for contextLength := 0; contextLength < unboundSweepContextLengths; contextLength++ {
			// the plaintext length moves with the point, so a band keyed on how long the
			// ciphertext is has no fixed value to sit at either
			sweep(string(sweptBytes(0x41, labelLength)), sweptBytes(0x80, contextLength),
				sweptBytes(0x30, 1+(labelLength*contextLength)%40))
		}
	}
	if points != unboundSweepLabelLengths*unboundSweepContextLengths {
		t.Fatalf("the length sweep visited %d points, want %d",
			points, unboundSweepLabelLengths*unboundSweepContextLengths)
	}
	lengthPoints := points
	for first := 0; first < unboundSweepBytes; first++ {
		for labelLength := 1; labelLength <= unboundSweepByteLengths; labelLength++ {
			sweep(string(sweptBytes(byte(first), labelLength)),
				sweptBytes(byte(first)^0x55, labelLength), []byte("plaintext"))
		}
	}
	if want := lengthPoints + unboundSweepBytes*unboundSweepByteLengths; points != want {
		t.Fatalf("the length and byte sweeps visited %d points, want %d", points, want)
	}
	bytePoints := points
	// and a coarse tail past where a dense sweep is affordable. a fallback conditional on
	// what it is handed has to sit at some length, and the dense sweep above ends at 20
	// and 70 — which is a place for one to sit rather than a bound on where one can be.
	// these are the lengths a label or a context in this protocol plausibly reaches: past
	// the two octet varint boundary at 16383 is where a dense sweep stops being the point
	// and the statement pin takes over.
	for _, labelLength := range []int{0, 1, 14, 20, 32, 64, 100} {
		for _, contextLength := range []int{100, 150, 200, 250, 300, 400, 500, 700, 1000, 1500, 2000} {
			sweep(string(sweptBytes(0x41, labelLength)), sweptBytes(0x80, contextLength),
				sweptBytes(0x30, 1+(labelLength+contextLength)%40))
		}
	}
	if want := bytePoints + unboundSweepCoarsePoints; points != want {
		t.Fatalf("the three sweeps visited %d points, want %d", points, want)
	}
	if refused != unboundSweepRefusals {
		t.Fatalf("the three sweeps refused %d unbound messages, want %d", refused, unboundSweepRefusals)
	}
}
