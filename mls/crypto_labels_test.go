// The RFC 9420 section 5.1 labelled kdf, held to published bytes.
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
// Three vendored corpora carry that weight, and each of them is the only source for
// something. The digests of all three are pinned by TestVectorFilesArePinned in
// vectors_pin_test.go, so vendored here means the bytes that manifest names.
//
//   - crypto-basics.json is the direct one: one published answer each for
//     ExpandWithLabel, DeriveSecret and DeriveTreeSecret, per suite. It is the only
//     corpus that names the three functions of this file.
//   - secret-tree.json is the only published pin on the generation's byte order. Every
//     derive_tree_secret vector in crypto-basics uses generation 0xa0a0a0a0, which is its
//     own reversal, so that corpus cannot tell a big endian uint32 from a little endian
//     one or from one repeated byte. The single leaf secret-tree entries publish keys at
//     generation 15, which is 0x0000000f and is not its own reversal.
//   - key-schedule.json is the only published context longer than 63 bytes. Its group
//     context is 112 bytes, so a hand rolled one byte length prefix in place of
//     WriteOpaque agrees with every other vector here and disagrees there.
//
// The counts are asserted rather than assumed. A loader that filtered every entry away
// reports exactly what a clean run reports, so each vector test counts the comparisons it
// actually made and fails if the number moved.
package mls

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// One crypto-basics entry, reduced to the three constructions this file owns. The other
// fields of the published object belong to tasks 13 and 14 and are not read here.
type labelKatBasics struct {
	CipherSuite      uint16                   `json:"cipher_suite"`
	ExpandWithLabel  labelKatExpandWithLabel  `json:"expand_with_label"`
	DeriveSecret     labelKatDeriveSecret     `json:"derive_secret"`
	DeriveTreeSecret labelKatDeriveTreeSecret `json:"derive_tree_secret"`
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
	// and label and context are two fields rather than one concatenation. a transposed
	// pair of writes keeps every length and produces a well formed preimage.
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
