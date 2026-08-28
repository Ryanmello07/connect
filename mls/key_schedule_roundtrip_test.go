// Gate 4 properties 1 and 2, deterministically and over a corpus that is on disk, for the
// two structures the key schedule owns: no panic on adversarial input, and byte exact
// round trip stability. MLS signs over serialized forms, so a decoder that accepts two
// encodings of one object is a signature bypass primitive rather than a leniency.
//
// The randomized form of these properties is p8's FuzzGroupContextRoundTrip and
// FuzzPreSharedKeyIdRoundTrip. p8 owns all nine Gate 4 targets (registry section 9.5) and
// declaring one here would be a second declaration of a name it already has in package
// mls, so what this file contributes is the part only it can: the committed seed corpus
// those targets read, and the deterministic form of the same two properties on every run
// rather than only when the fuzzer runs.
//
// The corpus is the load bearing half, and p1 measured why. Uniform random bytes reach the
// round trip property 14 times in 4096 -- 0.34 percent -- against the SIMPLEST type in the
// tree, because the length prefix rejects them first; a structured generator reaches it
// 4096 times in 4096. A target seeded only with random bytes therefore spends its budget
// rediscovering the varint, and a seed corpus is not an optimisation.
//
// Two consequences run through everything below. Every property here counts what it
// actually reached and fails at zero, because a target that decoded nothing reports exactly
// what a target that decoded everything reports. And the corpus is COMMITTED and compared
// against the generator rather than regenerated per run: a corpus regenerated from the same
// encoder it checks agrees with that encoder by construction, so a field dropped from both
// halves of the codec would round trip perfectly and change nothing anybody could see. The
// files on disk were written by yesterday's encoder, which is what makes them evidence.
package mls

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// The two p8 target names. The folder is named for the TARGET rather than for the structure
// because p8's loader joins testdata/corpus with the target's own name, and the seeds have
// to be where the thing that reads them looks.
const (
	groupContextSeedTarget   = "FuzzGroupContextRoundTrip"
	preSharedKeyIdSeedTarget = "FuzzPreSharedKeyIdRoundTrip"
)

// seedCorpusWriteEnv rewrites the committed corpus from the generator. A run with it set
// never reports success -- see TestTheCommittedSeedCorpusIsExactlyTheGeneratedCorpus --
// because a run that rewrites the artefact it is checking has checked nothing.
const seedCorpusWriteEnv = "URMSG_MLS_WRITE_CORPUS"

// seedWideOpaqueLength is the first length whose varint prefix needs four octets. One seed
// carries it per target rather than a whole axis: every seed carrying it costs 16 KiB in
// the repository, and the prefix width is a property of the prefix rather than of the field
// in front of it.
const seedWideOpaqueLength = 16384

// seedCorpusDirectory is where one target's seeds live.
func seedCorpusDirectory(target string) string {
	return filepath.Join("testdata", "corpus", target)
}

// ---------------------------------------------------------------------------
// the axes
// ---------------------------------------------------------------------------

// seedOpaqueLengths are the lengths the RFC 9420 section 2.1.2 varint length prefix
// branches on: absent, one octet, the last length a one octet prefix can express, and the
// first that needs two. These are the shapes p1's measurement says a fuzzer cannot find on
// its own in any reasonable budget, which is the whole reason the corpus exists.
func seedOpaqueLengths() []int {
	return []int{0, 1, 63, 64}
}

// seedOpaques is that axis as field values. The zero length case is nil rather than empty
// so the generated VALUES carry the distinction the wire format does not; the empty non nil
// form is added separately, since on disk the two are one seed.
func seedOpaques() [][]byte {
	opaques := [][]byte{}
	for index, length := range seedOpaqueLengths() {
		if length == 0 {
			opaques = append(opaques, nil)
			continue
		}
		opaques = append(opaques, repeatByte(byte(0xa0+index), length))
	}
	return opaques
}

// seedEpochs are the uint64 boundaries: zero, one, the last value a uint32 holds, the first
// it does not, the sign bit, and the maximum. Those are the values a field narrowed to 32
// bits, or read as signed, would move -- and both epoch fields here are covered by a
// signature, so a value that moves is a member deriving a different secret.
func seedEpochs() []uint64 {
	return []uint64{0, 1, math.MaxUint32, uint64(math.MaxUint32) + 1, 1 << 63, math.MaxUint64}
}

// seedGroupContexts is the cross product of the registry enums with the varint width
// boundaries of the opaque fields, the uint64 boundaries of the epoch, and the extension
// vector shapes.
//
// The enum axes are DERIVED from the package's own constant declarations rather than
// listed, for the reason rule 5 names: a hand picked table is a claim about which cases
// matter made by whoever also wrote the code, and on this project that claim has understated
// the real class fourteen times. A code point added to any of these registries enters this
// corpus in the commit that declares it, and the coverage gate below turns a corpus that has
// not caught up red.
func seedGroupContexts(t *testing.T) []*GroupContext {
	t.Helper()

	// 0xffff is not a registry member and is here for the opposite reason to the derived
	// ones: the codec does not decide policy, so an unregistered code point has to survive
	// a round trip for validation to be able to refuse it by name.
	versions := append(sortedValues(registryConstantsOfType(t, "ProtocolVersion")), 0xffff)
	suites := append(sortedValues(registryConstantsOfType(t, "CipherSuite")), 0xffff)
	extensionTypes := sortedValues(registryConstantsOfType(t, "ExtensionType"))

	opaques := seedOpaques()
	epochs := seedEpochs()

	// the extension vector shapes: the absent vector, one entry per derived code point,
	// the body lengths the varint branches on, and a two entry vector -- the vector length
	// prefix counts BYTES rather than elements, and a corpus of single element vectors
	// cannot tell those two readings apart.
	first := ExtensionType(extensionTypes[0])
	last := ExtensionType(extensionTypes[len(extensionTypes)-1])
	extensionLists := [][]Extension{nil}
	for _, extensionType := range extensionTypes {
		extensionLists = append(extensionLists, []Extension{
			{ExtensionType: ExtensionType(extensionType), ExtensionData: repeatByte(0xb1, 3)},
		})
	}
	extensionLists = append(extensionLists,
		[]Extension{{ExtensionType: first, ExtensionData: nil}},
		[]Extension{{ExtensionType: first, ExtensionData: repeatByte(0xb2, 63)}},
		[]Extension{{ExtensionType: first, ExtensionData: repeatByte(0xb3, 64)}},
		[]Extension{
			{ExtensionType: first, ExtensionData: repeatByte(0xb4, 3)},
			{ExtensionType: last, ExtensionData: nil},
		},
	)

	corpus := []*GroupContext{}
	rotation := 0
	for _, version := range versions {
		for _, suite := range suites {
			for groupIdIndex, groupId := range opaques {
				for epochIndex, epoch := range epochs {
					// the three opaque fields and the extension vector rotate through
					// their own axes rather than being crossed with each other, which
					// would raise the corpus to a power to buy nothing: they go through
					// the same encoder, so a length that works in one position works in
					// all of them. Rotating puts every value of every axis in every
					// position across the product, which is what the coverage gate below
					// then asserts rather than assumes.
					corpus = append(corpus, &GroupContext{
						Version:                 ProtocolVersion(version),
						CipherSuite:             CipherSuite(suite),
						GroupId:                 groupId,
						Epoch:                   epoch,
						TreeHash:                opaques[(groupIdIndex+epochIndex)%len(opaques)],
						ConfirmedTranscriptHash: opaques[(groupIdIndex+epochIndex+1)%len(opaques)],
						Extensions:              extensionLists[rotation%len(extensionLists)],
					})
					rotation++
				}
			}
		}
	}

	// the empty non nil field. It is a different go value from the absent one and the same
	// bytes on the wire, so it is here for the value direction; on disk the dedupe folds it
	// into the nil case, which is correct -- one encoding is one seed.
	corpus = append(corpus, &GroupContext{
		Version:                 ProtocolVersion(versions[0]),
		CipherSuite:             CipherSuite(suites[0]),
		GroupId:                 []byte{},
		Epoch:                   0,
		TreeHash:                []byte{},
		ConfirmedTranscriptHash: []byte{},
		Extensions:              []Extension{},
	})
	corpus = append(corpus, &GroupContext{
		Version:                 ProtocolVersion(versions[0]),
		CipherSuite:             CipherSuite(suites[0]),
		GroupId:                 repeatByte(0xb5, seedWideOpaqueLength),
		Epoch:                   1 << 40,
		TreeHash:                repeatByte(0xb6, 32),
		ConfirmedTranscriptHash: repeatByte(0xb7, 32),
		Extensions:              []Extension{{ExtensionType: first, ExtensionData: repeatByte(0xb8, 3)}},
	})
	return corpus
}

// seedPreSharedKeyIds is the same product over the section 8.4 id: both arms of the
// select(), every derived usage code point, the varint width boundaries and the uint64
// boundaries of the epoch.
//
// Each entry is in canonical form for its arm -- the fields the arm does not encode are left
// at their zero values -- so that "decoding reproduces every field" is a claim the corpus can
// actually make.
func seedPreSharedKeyIds(t *testing.T) []*PreSharedKeyId {
	t.Helper()

	pskTypes := registryConstantsOfType(t, "PskType")
	external, isExternal := pskTypes["PskTypeExternal"]
	resumption, isResumption := pskTypes["PskTypeResumption"]
	if !isExternal || !isResumption {
		t.Fatalf("the derivation read %v, which does not name both arms of the section 8.4 select(); a corpus built from it would exercise one decoder", pskTypes)
	}

	// the usage axis is the derived registry plus the two ends of the octet, because the
	// codec carries usage opaquely: a value outside the registry has to survive a round trip
	// for ValSem402 to be able to refuse it by name.
	usages := append(sortedValues(registryConstantsOfType(t, "ResumptionPskUsage")), 0x00, 0xff)
	slices.Sort(usages)

	opaques := seedOpaques()
	// KDF.Nh is the only nonce length ValSem401 accepts and therefore the only one that
	// occurs in production, so it sits on the axis beside the varint boundaries.
	nonces := append(append([][]byte{}, opaques...), repeatByte(0xc0, 32))
	epochs := seedEpochs()

	corpus := []*PreSharedKeyId{}
	for _, pskId := range opaques {
		for _, nonce := range nonces {
			corpus = append(corpus, &PreSharedKeyId{
				PskType:  PskType(external),
				PskId:    pskId,
				PskNonce: nonce,
			})
		}
	}
	for _, usage := range usages {
		for groupIdIndex, groupId := range opaques {
			for epochIndex, epoch := range epochs {
				corpus = append(corpus, &PreSharedKeyId{
					PskType:    PskType(resumption),
					Usage:      ResumptionPskUsage(usage),
					PskGroupId: groupId,
					PskEpoch:   epoch,
					PskNonce:   nonces[(groupIdIndex+epochIndex)%len(nonces)],
				})
			}
		}
	}
	corpus = append(corpus,
		&PreSharedKeyId{PskType: PskType(external), PskId: []byte{}, PskNonce: []byte{}},
		&PreSharedKeyId{
			PskType:  PskType(external),
			PskId:    repeatByte(0xc1, seedWideOpaqueLength),
			PskNonce: repeatByte(0xc2, 32),
		},
	)
	return corpus
}

// ---------------------------------------------------------------------------
// the two codecs, as one table
// ---------------------------------------------------------------------------

// seedCodec is one structure's half of this file: its target name, its generator, and the
// three entry points every property below reaches it through. The table exists so each
// property is written once over both structures rather than twice over one, which is how the
// second copy comes to assert less than the first.
type seedCodec struct {
	target         string
	values         func(t *testing.T) []any
	decode         func(bs []byte) (any, error)
	encode         func(value any) ([]byte, error)
	checkRoundTrip func(bs []byte) error
	describe       func(value any) string
}

func seedCodecs() []seedCodec {
	return []seedCodec{
		{
			target: groupContextSeedTarget,
			values: func(t *testing.T) []any {
				values := []any{}
				for _, value := range seedGroupContexts(t) {
					values = append(values, value)
				}
				return values
			},
			decode: func(bs []byte) (any, error) {
				parsed := &GroupContext{}
				return parsed, syntax.Unmarshal(bs, parsed)
			},
			encode:         func(value any) ([]byte, error) { return syntax.Marshal(value.(*GroupContext)) },
			checkRoundTrip: syntax.CheckRoundTrip[GroupContext, *GroupContext],
			describe:       func(value any) string { return describeGroupContext(value.(*GroupContext)) },
		},
		{
			target: preSharedKeyIdSeedTarget,
			values: func(t *testing.T) []any {
				values := []any{}
				for _, value := range seedPreSharedKeyIds(t) {
					values = append(values, value)
				}
				return values
			},
			decode: func(bs []byte) (any, error) {
				parsed := &PreSharedKeyId{}
				return parsed, syntax.Unmarshal(bs, parsed)
			},
			encode:         func(value any) ([]byte, error) { return syntax.Marshal(value.(*PreSharedKeyId)) },
			checkRoundTrip: syntax.CheckRoundTrip[PreSharedKeyId, *PreSharedKeyId],
			describe:       func(value any) string { return describePreSharedKeyId(value.(*PreSharedKeyId)) },
		},
	}
}

// seedFileName names the index'th seed. Ordinal rather than content addressed, because the
// generator's order is deterministic and a stable name makes a diff of this folder readable.
func seedFileName(index int) string {
	return fmt.Sprintf("seed%03d", index+1)
}

// generatedSeedFiles is the corpus this file would write, as it would appear on disk.
//
// Two values that differ only in nil versus empty are one encoding, and one encoding is one
// seed: a fuzzer handed the same bytes twice learns nothing the second time, and a corpus
// that grew by duplicates would report a count without carrying information.
func generatedSeedFiles(t *testing.T, codec seedCodec) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	seen := map[string]bool{}
	for index, value := range codec.values(t) {
		encoded, err := codec.encode(value)
		if err != nil {
			t.Fatalf("%s: value %d %s: encode: %v", codec.target, index, codec.describe(value), err)
		}
		if seen[string(encoded)] {
			continue
		}
		seen[string(encoded)] = true
		files[seedFileName(len(files))] = encoded
	}
	if len(files) == 0 {
		t.Fatalf("%s: the generator produced no seed, so every property over this corpus would hold vacuously", codec.target)
	}
	return files
}

// readSeedCorpus reads one target's committed seeds. A missing folder, a folder holding a
// subdirectory, and an empty folder are all failures rather than fallbacks: the corpus is
// committed so that a crasher is reproducible from a clean checkout, and a target that
// silently fell back to no seeds is a target that reports green having decoded nothing.
func readSeedCorpus(t *testing.T, target string) ([]string, map[string][]byte) {
	t.Helper()
	directory := seedCorpusDirectory(target)
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read the committed seed corpus %s: %v; it is committed rather than generated per run, so a missing one is a failure and not a fresh checkout", directory, err)
	}
	names := []string{}
	bodies := map[string][]byte{}
	for _, entry := range entries {
		if entry.IsDir() {
			// p8's loader adds every file in this folder as a seed and does not recurse,
			// so anything under a subdirectory here is a seed nobody reads.
			t.Fatalf("%s holds the directory %q; the loader that reads this folder does not recurse", directory, entry.Name())
		}
		body, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatalf("read seed %s: %v", entry.Name(), err)
		}
		names = append(names, entry.Name())
		bodies[entry.Name()] = body
	}
	if len(names) == 0 {
		t.Fatalf("%s holds no seed. an empty corpus is indistinguishable from a complete one at the reporting layer: every target reading it passes having exercised nothing", directory)
	}
	slices.Sort(names)
	return names, bodies
}

// ---------------------------------------------------------------------------
// the derived value comparison
// ---------------------------------------------------------------------------

// seedValuesAgree compares two values by walking the struct definition rather than naming
// its fields.
//
// The field list is derived because a hand written one is exactly the defect the task 13
// review found on this project: a round trip test that compared encoded against re-encoded
// and never compared the decoded VALUE with the original, so a field silently dropped by both
// halves of the codec round tripped byte exact and nothing said so. A comparison that names
// three of a structure's seven fields has the same shape one field later.
//
// A nil slice and an empty one compare equal, because the wire format has one spelling for
// both and the decoder always produces the non nil form; that is a property of the encoding
// and not a leniency in the comparison. An unexported field is fatal rather than skipped: a
// field this cannot read is a field it would report equal whatever it held.
func seedValuesAgree(t *testing.T, path string, left reflect.Value, right reflect.Value) bool {
	if left.Type() != right.Type() {
		t.Fatalf("%s: comparing a %s with a %s", path, left.Type(), right.Type())
	}
	switch left.Kind() {
	case reflect.Pointer, reflect.Interface:
		if left.IsNil() != right.IsNil() {
			return false
		}
		if left.IsNil() {
			return true
		}
		return seedValuesAgree(t, path, left.Elem(), right.Elem())
	case reflect.Struct:
		if left.NumField() == 0 {
			t.Fatalf("%s: %s declares no field, so this comparison walked nothing", path, left.Type())
		}
		for index := 0; index < left.NumField(); index++ {
			field := left.Type().Field(index)
			if !field.IsExported() {
				t.Fatalf("%s.%s is unexported, so this comparison cannot read it and would report two values that differ in it equal",
					path, field.Name)
			}
			if !seedValuesAgree(t, path+"."+field.Name, left.Field(index), right.Field(index)) {
				return false
			}
		}
		return true
	case reflect.Slice:
		if left.Type().Elem().Kind() == reflect.Uint8 {
			// the same comparison the general arm makes, in one call rather than one per
			// octet; bytes.Equal already treats nil and empty as equal.
			return bytes.Equal(left.Bytes(), right.Bytes())
		}
		if left.Len() != right.Len() {
			return false
		}
		for index := 0; index < left.Len(); index++ {
			if !seedValuesAgree(t, fmt.Sprintf("%s[%d]", path, index), left.Index(index), right.Index(index)) {
				return false
			}
		}
		return true
	default:
		if !left.Comparable() {
			t.Fatalf("%s: a %s is not comparable, so this walk has no answer for it", path, left.Type())
		}
		return left.Equal(right)
	}
}

// ---------------------------------------------------------------------------
// the properties
// ---------------------------------------------------------------------------

// TestTheCommittedSeedCorpusIsExactlyTheGeneratedCorpus is what makes every other property
// in this file evidence rather than a tautology.
//
// The seeds on disk were written by the encoder as it stood when they were committed. A
// corpus regenerated from the encoder it is checking agrees with that encoder by
// construction, so a field dropped from BOTH halves of the codec -- the mutation this file
// exists to catch -- would round trip perfectly, regenerate consistently, and change nothing
// anybody could see. Comparing the two is what turns that mutation into a diff.
//
// A deliberate generator change is therefore expected to fail here, and the fix is to
// regenerate in the same commit rather than to relax the comparison.
func TestTheCommittedSeedCorpusIsExactlyTheGeneratedCorpus(t *testing.T) {
	rewrite := os.Getenv(seedCorpusWriteEnv) != ""
	for _, codec := range seedCodecs() {
		generated := generatedSeedFiles(t, codec)
		if rewrite {
			directory := seedCorpusDirectory(codec.target)
			if err := os.RemoveAll(directory); err != nil {
				t.Fatalf("clear %s: %v", directory, err)
			}
			if err := os.MkdirAll(directory, 0o755); err != nil {
				t.Fatalf("create %s: %v", directory, err)
			}
			for _, name := range slices.Sorted(maps.Keys(generated)) {
				if err := os.WriteFile(filepath.Join(directory, name), generated[name], 0o600); err != nil {
					t.Fatalf("write %s: %v", name, err)
				}
			}
			t.Logf("%s: wrote %d seeds", codec.target, len(generated))
			continue
		}

		names, onDisk := readSeedCorpus(t, codec.target)
		for _, name := range names {
			want, expected := generated[name]
			if !expected {
				t.Errorf("%s/%s is on disk and the generator does not produce it; a seed nothing generates is a seed nothing keeps honest",
					codec.target, name)
				continue
			}
			if !bytes.Equal(onDisk[name], want) {
				t.Errorf("%s/%s differs from the generated seed:\n on disk %x\ngenerated %x\nthe codec moved under a committed corpus; regenerate with %s=1 in the commit that moved it",
					codec.target, name, onDisk[name], want, seedCorpusWriteEnv)
			}
		}
		for _, name := range slices.Sorted(maps.Keys(generated)) {
			if _, present := onDisk[name]; !present {
				t.Errorf("%s/%s is generated and is not committed; regenerate with %s=1",
					codec.target, name, seedCorpusWriteEnv)
			}
		}
		t.Logf("%s: %d committed seeds, %d generated", codec.target, len(names), len(generated))
	}
	if rewrite {
		t.Fatalf("the corpus was rewritten from the generator because %s is set; unset it and re-run. A run that rewrites the artefact it checks has checked nothing, and reporting success for it is how a stale corpus survives",
			seedCorpusWriteEnv)
	}
}

// TestEverySeedInTheCommittedCorpusReEncodesToItsOwnBytes is gate 4 property 2 -- encode of
// decode of x equals x -- over every committed seed, plus the same claim through
// syntax.CheckRoundTrip, which is the helper every one of p8's targets reaches this codec
// through. A codec that satisfied the property here and not there would leave those targets
// green and empty.
//
// The decoded count is asserted rather than logged. A loop whose body never ran reports
// exactly what a loop that checked every seed reports, and on this project that is not a
// hypothetical: three CheckRoundTrip tests once passed against a helper that evaluated the
// comparison, discarded the result and returned nil.
func TestEverySeedInTheCommittedCorpusReEncodesToItsOwnBytes(t *testing.T) {
	for _, codec := range seedCodecs() {
		names, onDisk := readSeedCorpus(t, codec.target)
		decoded := 0
		for _, name := range names {
			body := onDisk[name]
			value, err := codec.decode(body)
			if err != nil {
				t.Errorf("%s/%s: the committed seed did not decode: %v", codec.target, name, err)
				continue
			}
			decoded++
			reencoded, err := codec.encode(value)
			if err != nil {
				t.Errorf("%s/%s: %s decoded and would not re-encode: %v", codec.target, name, codec.describe(value), err)
				continue
			}
			if !bytes.Equal(reencoded, body) {
				t.Errorf("%s/%s: %s round tripped to different bytes:\n got %x\nwant %x",
					codec.target, name, codec.describe(value), reencoded, body)
				continue
			}
			if err := codec.checkRoundTrip(body); err != nil {
				t.Errorf("%s/%s: syntax.CheckRoundTrip: %v", codec.target, name, err)
			}
		}
		if decoded == 0 {
			t.Fatalf("%s: not one of the %d committed seeds decoded, so this property reached nothing; a corpus of bytes no decoder accepts makes every target trivially green",
				codec.target, len(names))
		}
		if decoded != len(names) {
			t.Errorf("%s: %d of %d committed seeds decoded", codec.target, decoded, len(names))
		}
		t.Logf("%s: %d seeds re-encoded to their own bytes", codec.target, decoded)
	}
}

// TestEveryGeneratedSeedValueIsRecoveredByDecodingItsEncoding is the OTHER direction, and it
// is a different claim: decode of encode of v equals v. A codec can satisfy one and not the
// other, and the task 13 review found exactly that shape here -- the plan's round trip test
// compared encoded against re-encoded and never compared the decoded value with the original,
// so a field dropped by both halves round tripped byte exact.
//
// The comparison walks the struct definition rather than naming fields, so a field added to
// either structure later is covered by the commit that adds it.
func TestEveryGeneratedSeedValueIsRecoveredByDecodingItsEncoding(t *testing.T) {
	for _, codec := range seedCodecs() {
		values := codec.values(t)
		if len(values) == 0 {
			t.Fatalf("%s: the generator produced no value, so this property compared nothing", codec.target)
		}
		compared := 0
		for index, value := range values {
			encoded, err := codec.encode(value)
			if err != nil {
				t.Errorf("%s: value %d %s: encode: %v", codec.target, index, codec.describe(value), err)
				continue
			}
			parsed, err := codec.decode(encoded)
			if err != nil {
				t.Errorf("%s: value %d %s: our own encoding was refused by our decoder: %v",
					codec.target, index, codec.describe(value), err)
				continue
			}
			compared++
			if !seedValuesAgree(t, codec.target, reflect.ValueOf(value), reflect.ValueOf(parsed)) {
				t.Errorf("%s: value %d %s decoded as %s", codec.target, index,
					codec.describe(value), codec.describe(parsed))
			}
		}
		if compared != len(values) {
			t.Errorf("%s: %d of %d generated values reached the comparison", codec.target, compared, len(values))
		}
		t.Logf("%s: %d generated values recovered from their own encodings", codec.target, compared)
	}
}

// TestTheCommittedSeedCorpusCoversEveryRegistryCodePointAndEveryBoundary is the rule 5 gate
// on the corpus itself, and it reads the SEEDS ON DISK rather than the generator's output.
//
// The class is derived from the package's own constant declarations, so a code point added to
// any of these five registries turns this red until the corpus catches up -- which is the
// only mechanism that keeps a committed corpus from ageing into a list of the code points
// that existed when somebody wrote it. The length and epoch boundaries are asserted the same
// way, against the axes rather than against a second copy of them.
func TestTheCommittedSeedCorpusCoversEveryRegistryCodePointAndEveryBoundary(t *testing.T) {
	observed := map[string]map[uint64]bool{
		"ProtocolVersion":    {},
		"CipherSuite":        {},
		"ExtensionType":      {},
		"PskType":            {},
		"ResumptionPskUsage": {},
	}
	lengths := map[string]map[int]bool{
		groupContextSeedTarget:   {},
		preSharedKeyIdSeedTarget: {},
	}
	epochs := map[string]map[uint64]bool{
		groupContextSeedTarget:   {},
		preSharedKeyIdSeedTarget: {},
	}

	groupContextNames, groupContextSeeds := readSeedCorpus(t, groupContextSeedTarget)
	for _, name := range groupContextNames {
		parsed := &GroupContext{}
		if err := syntax.Unmarshal(groupContextSeeds[name], parsed); err != nil {
			t.Fatalf("%s/%s: %v", groupContextSeedTarget, name, err)
		}
		observed["ProtocolVersion"][uint64(parsed.Version)] = true
		observed["CipherSuite"][uint64(parsed.CipherSuite)] = true
		epochs[groupContextSeedTarget][parsed.Epoch] = true
		for _, field := range [][]byte{parsed.GroupId, parsed.TreeHash, parsed.ConfirmedTranscriptHash} {
			lengths[groupContextSeedTarget][len(field)] = true
		}
		for _, extension := range parsed.Extensions {
			observed["ExtensionType"][uint64(extension.ExtensionType)] = true
			lengths[groupContextSeedTarget][len(extension.ExtensionData)] = true
		}
	}

	pskNames, pskSeeds := readSeedCorpus(t, preSharedKeyIdSeedTarget)
	for _, name := range pskNames {
		parsed := &PreSharedKeyId{}
		if err := syntax.Unmarshal(pskSeeds[name], parsed); err != nil {
			t.Fatalf("%s/%s: %v", preSharedKeyIdSeedTarget, name, err)
		}
		observed["PskType"][uint64(parsed.PskType)] = true
		for _, field := range [][]byte{parsed.PskId, parsed.PskGroupId, parsed.PskNonce} {
			lengths[preSharedKeyIdSeedTarget][len(field)] = true
		}
		if parsed.PskType != PskTypeResumption {
			// the external arm encodes neither field, so a value read back from one is
			// the decoder's zero rather than something the corpus carried.
			continue
		}
		observed["ResumptionPskUsage"][uint64(parsed.Usage)] = true
		epochs[preSharedKeyIdSeedTarget][parsed.PskEpoch] = true
	}

	for _, typeName := range slices.Sorted(maps.Keys(observed)) {
		derived := registryConstantsOfType(t, typeName)
		for _, name := range slices.Sorted(maps.Keys(derived)) {
			if !observed[typeName][derived[name]] {
				t.Errorf("no committed seed carries %s = %#x; a registry member the corpus does not encode is a decoder arm the fuzzer starts blind to, and regenerating with %s=1 is the fix",
					name, derived[name], seedCorpusWriteEnv)
			}
		}
		t.Logf("%s: %d code points declared, all present among the %d distinct values the corpus carries",
			typeName, len(derived), len(observed[typeName]))
	}

	for _, target := range []string{groupContextSeedTarget, preSharedKeyIdSeedTarget} {
		for _, length := range append(seedOpaqueLengths(), seedWideOpaqueLength) {
			if !lengths[target][length] {
				t.Errorf("%s: no committed seed carries a variable length field of %d octets, which is one of the widths the varint prefix branches on",
					target, length)
			}
		}
		for _, epoch := range seedEpochs() {
			if !epochs[target][epoch] {
				t.Errorf("%s: no committed seed carries the epoch boundary %#016x", target, epoch)
			}
		}
	}
}

// TestEverySeedInTheCommittedCorpusRefusesEveryTruncationAndAnyExtension is gate 4 property 1
// over a bounded input set, on every run, without waiting for the fuzzer: every prefix of a
// valid encoding and every one octet extension of it is refused rather than accepted as a
// second encoding of the same object.
//
// The extension half is the one that matters most. A decoder that ignores a tail accepts two
// encodings of one object, and MLS signs over serialized forms, so that is a signature bypass
// primitive and not a leniency.
func TestEverySeedInTheCommittedCorpusRefusesEveryTruncationAndAnyExtension(t *testing.T) {
	for _, codec := range seedCodecs() {
		names, onDisk := readSeedCorpus(t, codec.target)
		prefixes, extensions := 0, 0
		for _, name := range names {
			body := onDisk[name]
			for n := 0; n < len(body); n++ {
				if _, err := codec.decode(body[:n]); err == nil {
					t.Errorf("%s/%s: the first %d of %d octets parsed as a whole structure",
						codec.target, name, n, len(body))
					continue
				}
				prefixes++
			}
			extended := append(append([]byte(nil), body...), 0x00)
			if _, err := codec.decode(extended); err == nil {
				t.Errorf("%s/%s: a trailing octet was accepted, so this structure has two encodings",
					codec.target, name)
				continue
			}
			extensions++
		}
		if prefixes == 0 || extensions == 0 {
			t.Fatalf("%s: %d prefixes and %d extensions were refused across %d seeds; this property reached nothing",
				codec.target, prefixes, extensions, len(names))
		}
		t.Logf("%s: %d prefixes and %d extensions refused", codec.target, prefixes, extensions)
	}
}

// ---------------------------------------------------------------------------
// the control on the shared helper
// ---------------------------------------------------------------------------

// canonicalSeedProbe, nonCanonicalSeedProbe and unstableSeedProbe are three one octet codecs
// that exist only to ask syntax.CheckRoundTrip whether it can still say no.
//
// They are here because nothing else in this package can ask that question. Both real codecs
// are canonical, so CheckRoundTrip returns nil for every input they are given -- and it also
// returns nil for every input if it evaluates its comparisons and throws the results away.
// That is not a hypothetical defect: a version of this helper that did all the work, computed
// the comparison, discarded it and returned nil passed all three of p1's round trip tests,
// and every one of p8's nine targets calls it.
type canonicalSeedProbe struct{ value uint8 }

func (self *canonicalSeedProbe) MarshalMLS(w *syntax.Writer) error {
	w.WriteUint8(self.value)
	return nil
}

func (self *canonicalSeedProbe) UnmarshalMLS(r *syntax.Reader) error {
	value, err := r.ReadUint8()
	if err != nil {
		return err
	}
	self.value = value
	return nil
}

// nonCanonicalSeedProbe re-encodes what it decoded as different bytes, which is exactly the
// shape gate 4 property 2 forbids.
type nonCanonicalSeedProbe struct{ value uint8 }

func (self *nonCanonicalSeedProbe) MarshalMLS(w *syntax.Writer) error {
	w.WriteUint8(self.value ^ 0xff)
	return nil
}

func (self *nonCanonicalSeedProbe) UnmarshalMLS(r *syntax.Reader) error {
	value, err := r.ReadUint8()
	if err != nil {
		return err
	}
	self.value = value
	return nil
}

// unstableSeedProbeEncodes is the hidden state unstableSeedProbe carries between calls -- a
// map ranged during encode, a registry consulted at decode, a buffer shared across calls.
// That defect is invisible to the byte exactness check, which sees one encode, and the second
// pass inside CheckRoundTrip is the only thing that looks for it.
var unstableSeedProbeEncodes int

type unstableSeedProbe struct{ value uint8 }

func (self *unstableSeedProbe) MarshalMLS(w *syntax.Writer) error {
	unstableSeedProbeEncodes++
	if unstableSeedProbeEncodes > 1 {
		w.WriteUint8(self.value ^ 0xff)
		return nil
	}
	w.WriteUint8(self.value)
	return nil
}

func (self *unstableSeedProbe) UnmarshalMLS(r *syntax.Reader) error {
	value, err := r.ReadUint8()
	if err != nil {
		return err
	}
	self.value = value
	return nil
}

// TestCheckRoundTripReportsTheViolationsItIsHanded is the positive control on the helper the
// two properties above and all nine of p8's targets are stated through.
func TestCheckRoundTripReportsTheViolationsItIsHanded(t *testing.T) {
	if err := syntax.CheckRoundTrip[canonicalSeedProbe, *canonicalSeedProbe]([]byte{0x2a}); err != nil {
		t.Errorf("a codec that reproduces its own bytes was reported as a violation: %v", err)
	}
	// an input that does not decode carries no obligation; reporting one would make every
	// target noisy on exactly the inputs a fuzzer spends most of its budget on.
	if err := syntax.CheckRoundTrip[canonicalSeedProbe, *canonicalSeedProbe](nil); err != nil {
		t.Errorf("an input that does not decode was reported as a round trip violation: %v", err)
	}
	if err := syntax.CheckRoundTrip[nonCanonicalSeedProbe, *nonCanonicalSeedProbe]([]byte{0x00}); !errors.Is(err, syntax.ErrRoundTripNotByteExact) {
		t.Errorf("CheckRoundTrip answered %v for a codec whose re-encoding is not its input, want syntax.ErrRoundTripNotByteExact; every seed in this corpus is checked through this helper, so a helper that computes the comparison and discards it reports the whole corpus clean having compared nothing",
			err)
	}
	unstableSeedProbeEncodes = 0
	if err := syntax.CheckRoundTrip[unstableSeedProbe, *unstableSeedProbe]([]byte{0x00}); !errors.Is(err, syntax.ErrRoundTripNotStable) {
		t.Errorf("CheckRoundTrip answered %v for a codec that encodes the same value differently on its second call, want syntax.ErrRoundTripNotStable", err)
	}
}

// TestTheCommittedSeedCorpusIsPinnedAsBinary is the one property in this file that is not
// about the codec, and it is here because the corpus stops being evidence the moment a
// checkout is allowed to rewrite it.
//
// core.autocrlf=true is set at system scope on the windows boxes that build this repository,
// and git decides text from binary by looking for a NUL octet in a file's first 8000. Every
// seed committed today holds one, so nothing is being converted right now -- but the corpus
// is REGENERATED whenever an axis moves, and a seed that happens to hold no NUL and does hold
// an 0x0a would be rewritten on checkout into bytes no decoder accepts. That failure arrives
// as a corpus that stops decoding on somebody else's machine, which reads as a codec bug.
func TestTheCommittedSeedCorpusIsPinnedAsBinary(t *testing.T) {
	attributes := filepath.Join("..", ".gitattributes")
	body, err := os.ReadFile(attributes)
	if err != nil {
		t.Fatalf("read %s: %v", attributes, err)
	}
	pinned := ""
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if !strings.HasPrefix(fields[0], filepath.ToSlash(filepath.Join("mls", "testdata", "corpus"))) {
			continue
		}
		for _, attribute := range fields[1:] {
			if attribute == "-text" || attribute == "binary" {
				pinned = line
			}
		}
	}
	if pinned == "" {
		t.Fatalf("%s carries no rule marking mls/testdata/corpus as binary; with core.autocrlf on, a seed git reads as text is rewritten on checkout and the committed corpus stops being what was committed",
			attributes)
	}

	// measured rather than asserted, so the log says whether the rule above is currently
	// carrying weight or is prophylactic.
	convertible := 0
	seeds := 0
	for _, codec := range seedCodecs() {
		names, onDisk := readSeedCorpus(t, codec.target)
		for _, name := range names {
			seeds++
			body := onDisk[name]
			head := body
			if len(head) > 8000 {
				head = head[:8000]
			}
			if !bytes.Contains(head, []byte{0x00}) && bytes.ContainsAny(body, "\r\n") {
				convertible++
			}
		}
	}
	t.Logf("%q pins the corpus; %d of %d seeds would otherwise be eligible for end of line conversion", pinned, convertible, seeds)
}
