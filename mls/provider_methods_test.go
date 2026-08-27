// The gates over the METHODS of this package that are handed a CryptoProvider.
//
// Every derived provider gate this package already carries reads the package level half of
// the surface and stops there. packageLevelFunctionsIn skips a declaration carrying a
// receiver, and providerConstructions skips one the type checker reads as a method; the
// three gates built on them -- TestEveryConstructionInThisPackageLeavesItsInputAlone,
// TestEveryConstructionHandedAProviderRoutesThroughIt and
// TestEveryConstructionHandedAProviderReadsKdfNhFromIt -- therefore demand nothing of a
// method, and a method cannot be given a row in them even if somebody wanted to.
//
// That is a class boundary rather than an enumeration, and it is the right one for those
// gates: a construction is called by name and a method is called on a receiver, so the two
// need different tables. What was missing is the other half of the partition. A receiver was
// the whole of what it took to sit outside every one of them, and the two methods the
// transcript adds are exactly the shape those gates exist for -- they read KDF.Nh off the
// provider they are handed, they compute the one value a group cannot disagree about and
// recover from, and one of them RETAINS a caller's array for the lifetime of the group.
// Measured, not supposed: nh := crypto.HashSize() replaced by nh := 32 in
// (*TranscriptHashes).SetFromGroupInfo, and its defensive copy of the GroupInfo's confirmed
// transcript hash deleted, each left the whole of mls green.
//
// So this file states the other half. The class is read off the type checker -- every method
// of this package's non test source whose parameters include a CryptoProvider -- each member
// has to have a row, and TestEveryDeclarationTakingAProviderIsHeldByExactlyOneOfTheTwoClasses
// compares the two halves against the whole so a declaration cannot fall between them.
package mls

import (
	"bytes"
	"go/types"
	"slices"
	"testing"
)

// One value a method left behind, named.
//
// The values are read one at a time rather than concatenated, and that is the difference
// between this gate and a weaker one. A method leaving two values behind, one computed
// through the provider it was handed and one computed through a provider of its own, answers
// a DIFFERENT concatenation over a provider that flips every answer -- the half that routed
// correctly moves and carries the joined comparison with it. Measured, not supposed: with the
// values joined, an Update building its own provider out of a hardcoded suite for the
// confirmed hash and routing only the interim hash through its parameter passed this file.
type providerDrivenMethodValue struct {
	name    string
	content []byte
	// carried marks a value the method was HANDED rather than one it computed. The routing
	// differential is the wrong instrument for one: a copy of an argument is the same bytes
	// over every provider, so requiring it to move would report every possible
	// implementation as defective. The flag is not taken on trust -- the routing gate holds
	// a carried value to being identical across the two providers and every other value to
	// being different, so a flag set on the wrong value fails rather than exempting it.
	carried bool
}

// One method of this package that is handed a provider, and how to drive it.
//
// The row answers what the RECEIVER holds after the call rather than a return value, because
// what these methods are for is state: two of the three answer nothing but an error, and
// every property below -- routing, KDF.Nh and retention -- is a property of what was left
// behind. Bytes the caller owns go through take, so the recorder the retention gate hands in
// sees exactly the arrays a caller would still own after the call and no others.
type providerDrivenMethodRow struct {
	name string
	call func(t *testing.T, crypto CryptoProvider, take func(content []byte) []byte) ([]providerDrivenMethodValue, error)
}

// providerDrivenMethodRows is the table, one row per member of the derived class.
//
// Every value a row is built out of is cut to the provider's own KDF.Nh rather than to 32,
// which is what lets the same rows run over the wide provider below. A row that wrote a
// length down would be refused there for a reason that is this file's rather than the
// method's, and the differential would read as a defect that is not there.
func providerDrivenMethodRows() []providerDrivenMethodRow {
	return []providerDrivenMethodRow{
		// psk.go's ValSem401. The nonce is the receiver's own field rather than a
		// parameter, so it is not taken through the recorder and this row is outside the
		// retention gate's derived class by the same reading that puts it inside the other
		// two: it is handed no caller array it could keep.
		{name: "(*PreSharedKeyId).Validate", call: func(t *testing.T, crypto CryptoProvider, take func([]byte) []byte) ([]providerDrivenMethodValue, error) {
			id := &PreSharedKeyId{
				PskType:  PskTypeExternal,
				PskId:    bytes.Repeat([]byte{0x11}, 16),
				PskNonce: bytes.Repeat([]byte{0x12}, crypto.HashSize()),
			}
			if err := id.Validate(crypto); err != nil {
				return nil, err
			}
			// a validator computes nothing: both values are the ones it was given, which
			// is why the routing gate cannot hold this row at all
			return []providerDrivenMethodValue{
				{name: "PskId", content: id.PskId, carried: true},
				{name: "PskNonce", content: id.PskNonce, carried: true},
			}, nil
		}},
		// the transcript's own advance. Both arguments are the caller's -- the serialized
		// ConfirmedTranscriptHashInput is the framed commit it goes on to verify a signature
		// over, and the confirmation tag is compared against a freshly computed one
		// afterwards -- and both hashes it leaves behind are read.
		//
		// The input is 64 octets: deliberately neither KDF.Nh of the two providers below, so
		// no comparison there reports a coincidence belonging to a length this file chose.
		{name: "(*TranscriptHashes).Update", call: func(t *testing.T, crypto CryptoProvider, take func([]byte) []byte) ([]providerDrivenMethodValue, error) {
			hashes := InitialTranscriptHashes()
			err := hashes.Update(crypto,
				take(bytes.Repeat([]byte{0x21}, 64)),
				take(bytes.Repeat([]byte{0x22}, crypto.HashSize())))
			if err != nil {
				return nil, err
			}
			return []providerDrivenMethodValue{
				{name: "Confirmed", content: hashes.Confirmed},
				{name: "Interim", content: hashes.Interim},
			}, nil
		}},
		// the joiner's seeding, which is the one long lived retention of somebody else's
		// bytes in this package: the confirmed transcript hash it is handed is a field of a
		// decoded GroupInfo whose buffer the caller still owns, and what it keeps is carried
		// into every later epoch of the group.
		//
		// Confirmed is marked carried because it is the GroupInfo's value and not a
		// derivation -- a joiner that recomputed it would hold a hash the group does not.
		// The routing gate therefore reads it as a value that must NOT move across the two
		// providers, which is a real assertion rather than an exemption.
		{name: "(*TranscriptHashes).SetFromGroupInfo", call: func(t *testing.T, crypto CryptoProvider, take func([]byte) []byte) ([]providerDrivenMethodValue, error) {
			nh := crypto.HashSize()
			joiner := InitialTranscriptHashes()
			err := joiner.SetFromGroupInfo(crypto,
				take(bytes.Repeat([]byte{0x31}, nh)),
				take(bytes.Repeat([]byte{0x32}, nh)))
			if err != nil {
				return nil, err
			}
			return []providerDrivenMethodValue{
				{name: "Confirmed", content: joiner.Confirmed, carried: true},
				{name: "Interim", content: joiner.Interim},
			}, nil
		}},
	}
}

// providerDrivenMethods is every method this package's non test source declares whose
// parameters include a CryptoProvider, read off the type checker.
//
// The same reading providerConstructions makes, with the receiver filter turned the other
// way round. It is the compiler's view of the signature rather than the spelling the line
// gives the parameter, so a method taking an interface that embeds the provider is a member
// of the class and a method taking something merely named CryptoProvider is not.
//
// Absence is fatal, for the reason every other derivation here is: a filter that stopped
// matching leaves the gates reading it demanding nothing, and a gate that demands nothing
// reports exactly what a complete one reports.
func providerDrivenMethods(t *testing.T) []declaredFunction {
	t.Helper()
	provider := providerInterfaceType(t)
	methods := []declaredFunction{}
	for _, function := range declaredFunctionsOf(t, cryptoOwnRoot) {
		if !function.method || len(function.takes(provider)) == 0 {
			continue
		}
		methods = append(methods, function)
	}
	if len(methods) == 0 {
		t.Fatalf("no method of this package takes a %s, so every gate in this file demands nothing",
			providerInterfaceName)
	}
	return methods
}

// The names of those methods, sorted.
func providerDrivenMethodNames(t *testing.T) []string {
	t.Helper()
	names := []string{}
	for _, method := range providerDrivenMethods(t) {
		names = append(names, method.name)
	}
	slices.Sort(names)
	return names
}

// isByteSliceType reports whether the compiler reads a type as a slice of octets, under
// whatever name it is spelled.
//
// Underlying on both halves is what makes a named storage type a member: HpkePublicKey is a
// caller's array exactly as a []byte is, and a filter matching the spelling alone would drop
// it. The element is compared as a kind rather than as a name, because byte and uint8 are one
// type written two ways.
func isByteSliceType(of types.Type) bool {
	slice, isSlice := of.Underlying().(*types.Slice)
	if !isSlice {
		return false
	}
	element, isBasic := slice.Elem().Underlying().(*types.Basic)
	return isBasic && element.Kind() == types.Uint8
}

// providerDrivenMethodNamesTakingCallerBytes is the subset of the class above that is handed
// an array the caller still owns.
//
// Derived rather than listed, and derived as the property itself: a method handed no byte
// slice cannot write into a caller's array and cannot keep one, so it is outside the
// retention gate by what its signature is rather than by an excuse somebody wrote.
func providerDrivenMethodNamesTakingCallerBytes(t *testing.T) []string {
	t.Helper()
	names := []string{}
	for _, method := range providerDrivenMethods(t) {
		for i := 0; i < method.signature.Params().Len(); i++ {
			if isByteSliceType(method.signature.Params().At(i).Type()) {
				names = append(names, method.name)
				break
			}
		}
	}
	if len(names) == 0 {
		t.Fatalf("no method of this package is handed both a %s and a caller's array, so the retention gate demands nothing",
			providerInterfaceName)
	}
	slices.Sort(names)
	return names
}

// The rows this file declares, checked against the class and answered in the class's order.
//
// Both directions are checked. A member with no row is a method nothing below runs, and a row
// naming a method this package does not declare is a row that outlived what it covered.
func providerDrivenMethodRowsFor(t *testing.T, gate string, class []string) []providerDrivenMethodRow {
	t.Helper()
	byName := map[string]providerDrivenMethodRow{}
	for _, row := range providerDrivenMethodRows() {
		if _, repeated := byName[row.name]; repeated {
			t.Fatalf("providerDrivenMethodRows declares %s twice, so one of the two is never run", row.name)
		}
		byName[row.name] = row
	}
	declared := providerDrivenMethodNames(t)
	for name := range byName {
		if !slices.Contains(declared, name) {
			t.Errorf("providerDrivenMethodRows names %s, and no method of this package takes a %s under that name",
				name, providerInterfaceName)
		}
	}
	rows := []providerDrivenMethodRow{}
	for _, name := range class {
		row, written := byName[name]
		if !written {
			t.Errorf("%s: %s is handed a %s and has no row, so nothing holds it",
				gate, name, providerInterfaceName)
			continue
		}
		rows = append(rows, row)
	}
	return rows
}

// A method handed a provider that the routing gate cannot hold, named with the reason. Every
// name here is checked against the derived class below, AND against the row's own shape, so
// an entry cannot outlive the method it excuses and cannot excuse one that has provider
// derived state to compare.
var providerDrivenMethodsOverAnyProvider = map[string]string{
	// Validate reaches the provider for a length and for nothing else, and leaves nothing
	// behind but what it was given. The tagging provider passes HashSize through -- it has
	// no bytes to flip in an int -- so what this holds after a call over the tagging
	// provider is what it holds after a call over the real one, and a row here would report
	// "did not route through its provider" for every possible implementation. It is the
	// same limit labelConstructionsOverAnyProvider records for ZeroSecret, and it is not
	// unheld: the KDF.Nh gate below holds the length it refuses against a provider whose Nh
	// is not 32, which is the whole of what it uses the provider for.
	"(*PreSharedKeyId).Validate": "reads a length off the provider and nothing else, so a provider that flips every answer cannot separate it from a literal",
}

// TestEveryMethodHandedAProviderRoutesThroughIt is
// TestEveryConstructionHandedAProviderRoutesThroughIt over the other half of the partition.
//
// The property is the one the parameter exists for. A method that reached for crypto/sha256
// directly, or built a provider out of a hardcoded suite, agrees with every corpus in this
// package, because the corpora are all X25519/SHA-256 -- the suite it would have hardcoded.
// It matters most on the transcript: the transcript is the one value a group cannot disagree
// about and recover from, so a hash taken under a suite of the method's own choosing is a
// permanent fork rather than a retryable failure.
//
// What separates the two is a provider that answers differently. Over the tagging provider a
// value the method derived through its parameter moves, and one it derived through a provider
// of its own does not. Each value is compared on its own, because a method that routed one of
// two through its parameter is exactly the defect a joined comparison cannot see.
func TestEveryMethodHandedAProviderRoutesThroughIt(t *testing.T) {
	class := providerDrivenMethodNames(t)
	want := []string{}
	for _, name := range class {
		if _, isExcused := providerDrivenMethodsOverAnyProvider[name]; !isExcused {
			want = append(want, name)
		}
	}
	// the provider underneath draws from a constant reader so nothing a row reaches can
	// answer differently on a second call for a reason that is the entropy's
	plain := mustProviderOver(t, CipherSuiteX25519ChaCha20Sha256Ed25519, constantReader{value: 0x35})
	held := func(row providerDrivenMethodRow, crypto CryptoProvider) []providerDrivenMethodValue {
		values, err := row.call(t, crypto, func(content []byte) []byte { return content })
		if err != nil {
			t.Fatalf("%s: %v", row.name, err)
		}
		return values
	}
	compared := 0
	for _, row := range providerDrivenMethodRowsFor(t, "the routing gate", want) {
		tagging := &taggingCryptoProvider{inner: plain}
		// with a panic caught rather than taken, for the reason recoveringRow gives: a row
		// that panics on inputs this test chose would otherwise take the test binary down
		// and every gate declared after this one with it
		overTheRealProvider, raised := recoveringRow(func() []providerDrivenMethodValue { return held(row, plain) })
		if raised != nil {
			t.Errorf("%s panicked with %v rather than answering", row.name, raised)
			continue
		}
		overTheTaggingProvider, raised := recoveringRow(func() []providerDrivenMethodValue { return held(row, tagging) })
		if raised != nil {
			t.Errorf("%s panicked with %v over the tagging provider; it called %v", row.name, raised, tagging.calls)
			continue
		}
		if len(overTheRealProvider) == 0 || len(overTheTaggingProvider) != len(overTheRealProvider) {
			t.Errorf("%s left %d values behind over the real provider and %d over the tagging one, so nothing below is compared",
				row.name, len(overTheRealProvider), len(overTheTaggingProvider))
			continue
		}
		derived := 0
		for i, value := range overTheRealProvider {
			flipped := overTheTaggingProvider[i]
			if len(value.content) == 0 {
				t.Errorf("%s left nothing behind in %s, so that value observed nothing", row.name, value.name)
				continue
			}
			if value.carried {
				if !bytes.Equal(value.content, flipped.content) {
					t.Errorf("%s is named as carrying %s through rather than deriving it, and it came back %x over the real provider and %x over one that flips every answer",
						row.name, value.name, value.content, flipped.content)
				}
				continue
			}
			derived++
			if bytes.Equal(value.content, flipped.content) {
				t.Errorf("%s left the same %s behind over a provider that flips every answer, so that value did not route through the provider it was handed; it called %v",
					row.name, value.name, tagging.calls)
			}
		}
		if derived == 0 {
			t.Errorf("%s leaves nothing behind that it derived, so this row holds it to nothing; excuse it in providerDrivenMethodsOverAnyProvider or give it a value to compare",
				row.name)
			continue
		}
		compared++
	}
	// and the excuse is held to the row's own shape as well as to the class: a method left
	// out of the differential must have nothing for the differential to read
	for name, reason := range providerDrivenMethodsOverAnyProvider {
		if !slices.Contains(class, name) {
			t.Errorf("the gate excuses %s, and no method of this package takes a %s under that name",
				name, providerInterfaceName)
			continue
		}
		for _, row := range providerDrivenMethodRows() {
			if row.name != name {
				continue
			}
			for _, value := range held(row, plain) {
				if !value.carried {
					t.Errorf("%s is excused from the routing differential as %q, and its row leaves %s behind as a derived value, which the differential could have held",
						name, reason, value.name)
				}
			}
		}
	}
	if compared != len(want) {
		t.Fatalf("%d of the %d methods the routing differential covers were compared", compared, len(want))
	}
	t.Logf("%d of the %d methods handed a %s held to routing through it", len(want), len(class), providerInterfaceName)
}

// TestEveryMethodHandedAProviderReadsKdfNhFromIt is the differential the registered suites
// cannot supply, over the method half of the partition.
//
// Both registered suites fix KDF.Nh at 32, so nothing already in this tree separates a method
// that reads the length off the provider it was handed from one that writes 32 down. The
// second provider is the registered suite with its whole hash and kdf surface one width up,
// and the rows are cut to whichever provider they are running under.
//
// Two things are compared, because KDF.Nh governs two separate things here. A method that
// wrote the length down REFUSES an input cut to the wide provider's own Nh, which is the
// refusal the first half reads; and a method that read the provider for its refusal and wrote
// 32 down for what it produced leaves a value of the wrong width behind, which is what
// kdfNhCoincidences reads. Either half alone is satisfiable by the other mistake.
func TestEveryMethodHandedAProviderReadsKdfNhFromIt(t *testing.T) {
	class := providerDrivenMethodNames(t)
	narrow := mustProviderOver(t, CipherSuiteX25519ChaCha20Sha256Ed25519, constantReader{value: 0x35})
	wide := &wideKdfProvider{CryptoProvider: narrow}
	if narrow.HashSize() == wide.HashSize() {
		t.Fatalf("both providers answer KDF.Nh %d, so every row below compares a length against itself",
			narrow.HashSize())
	}
	contents := func(values []providerDrivenMethodValue) [][]byte {
		out := [][]byte{}
		for _, value := range values {
			out = append(out, value.content)
		}
		return out
	}
	compared := 0
	for _, row := range providerDrivenMethodRowsFor(t, "the KDF.Nh gate", class) {
		overTheNarrowProvider, err := row.call(t, narrow, func(content []byte) []byte { return content })
		if err != nil {
			t.Errorf("%s refused inputs cut to the narrow provider's KDF.Nh of %d: %v",
				row.name, narrow.HashSize(), err)
			continue
		}
		overTheWideProvider, err := row.call(t, wide, func(content []byte) []byte { return content })
		if err != nil {
			t.Errorf("%s refused inputs cut to the KDF.Nh of %d the provider it was handed answers, so it is holding a length of its own rather than reading that provider: %v",
				row.name, wide.HashSize(), err)
			continue
		}
		if len(overTheNarrowProvider) == 0 || len(overTheWideProvider) != len(overTheNarrowProvider) {
			t.Errorf("%s left %d values behind over the narrow provider and %d over the wide one, so nothing below is compared",
				row.name, len(overTheNarrowProvider), len(overTheWideProvider))
			continue
		}
		for _, at := range kdfNhCoincidences(contents(overTheNarrowProvider), contents(overTheWideProvider),
			narrow.HashSize(), wide.HashSize()) {
			t.Errorf("%s left %s behind at %d bytes over a provider whose KDF.Nh is %d and at %d bytes over one whose KDF.Nh is %d; one of the two is a length written down rather than read",
				row.name, overTheNarrowProvider[at].name, len(overTheNarrowProvider[at].content),
				narrow.HashSize(), len(overTheWideProvider[at].content), wide.HashSize())
		}
		compared++
	}
	if compared != len(class) {
		t.Fatalf("%d of the %d methods handed a %s were compared across the two providers",
			compared, len(class), providerInterfaceName)
	}
}

// TestNoMethodHandedAProviderRetainsOrRewritesTheCallerBytes is
// TestEveryConstructionInThisPackageLeavesItsInputAlone over the other half of the partition,
// and it is the half where retention actually happens.
//
// A construction answers and is done with what it was handed. A method leaves state behind,
// and state outlives the array it was cut from. The joiner's confirmed transcript hash is the
// case: it is a field of a decoded GroupInfo, the caller still owns the message it decoded it
// out of and goes on reading later fields from that buffer, and a joiner that kept the slice
// holds a transcript that changes underneath it with no error path anywhere. The next commit
// is then chained from bytes no peer has, which is a permanent fork rather than an operation
// that failed.
//
// Both directions of sharing are read. The recorder's arrays carry a pattern in their spare
// capacity rather than zeros, so a method that appended a byte to save an allocation is
// visible; and every byte the receiver holds is compared against every byte of every argument,
// so state cut from the middle of a caller's buffer is as visible as state cut from its front.
func TestNoMethodHandedAProviderRetainsOrRewritesTheCallerBytes(t *testing.T) {
	class := providerDrivenMethodNamesTakingCallerBytes(t)
	crypto := mustProviderOver(t, CipherSuiteX25519ChaCha20Sha256Ed25519, constantReader{value: 0x35})
	compared := 0
	for _, row := range providerDrivenMethodRowsFor(t, "the retention gate", class) {
		recorder := &argumentRecorder{}
		held, err := row.call(t, crypto, recorder.take)
		if err != nil {
			t.Errorf("%s: %v", row.name, err)
			continue
		}
		if len(recorder.arrays) == 0 {
			t.Errorf("%s was handed nothing through the recorder, so this row observed nothing", row.name)
			continue
		}
		if changed := recorder.changed(); len(changed) != 0 {
			t.Errorf("%s wrote into the storage behind arguments %v of the %d it was handed",
				row.name, changed, len(recorder.arrays))
		}
		if len(held) == 0 {
			t.Errorf("%s left nothing behind, so this row observed nothing", row.name)
			continue
		}
		for _, value := range held {
			if len(value.content) == 0 {
				t.Errorf("%s left nothing behind in %s, so that value observed nothing", row.name, value.name)
				continue
			}
			if recorder.aliases(value.content) {
				t.Errorf("%s kept %s over the storage of one of the arrays it was handed; that array is its caller's and the state outlives the call",
					row.name, value.name)
			}
		}
		compared++
	}
	if compared != len(class) {
		t.Fatalf("%d of the %d methods handed a %s and a caller's array were run through the recorder",
			compared, len(class), providerInterfaceName)
	}
}

// TestEveryDeclarationTakingAProviderIsHeldByExactlyOneOfTheTwoClasses is what records the
// boundary the package level gates draw, so it cannot be widened or narrowed in silence.
//
// packageLevelFunctionsIn and providerConstructions each skip a declaration carrying a
// receiver. That skip is invisible from the gates reading them: they compare their tables
// against a class that never contained a method, find it matches, and report the clean run a
// complete gate reports. What says otherwise is this -- the whole of what the type checker
// reads as taking a provider, split by the same receiver test, with each half compared against
// the class the gates for that half actually run over.
//
// A declaration in neither half is one nothing holds. A declaration in both is a gate reading
// a class it was not built for. Either is a failure here rather than a coverage report that
// happens to be short.
func TestEveryDeclarationTakingAProviderIsHeldByExactlyOneOfTheTwoClasses(t *testing.T) {
	provider := providerInterfaceType(t)
	constructions := []string{}
	methods := []string{}
	for _, function := range declaredFunctionsOf(t, cryptoOwnRoot) {
		if len(function.takes(provider)) == 0 {
			continue
		}
		if function.method {
			methods = append(methods, function.name)
			continue
		}
		constructions = append(constructions, function.name)
	}
	if len(constructions) == 0 || len(methods) == 0 {
		t.Fatalf("the whole of what takes a %s reads as %d constructions and %d methods, so one of the two halves below is compared against nothing",
			providerInterfaceName, len(constructions), len(methods))
	}
	slices.Sort(constructions)
	slices.Sort(methods)
	if declared := packageLevelFunctionsTaking(t, providerInterfaceName); !slices.Equal(constructions, declared) {
		t.Errorf("the type checker reads %v as the constructions taking a %s and the package level scan the construction gates run over reads %v",
			constructions, providerInterfaceName, declared)
	}
	if held := providerDrivenMethodNames(t); !slices.Equal(methods, held) {
		t.Errorf("the type checker reads %v as the methods taking a %s and the gates in this file run over %v",
			methods, providerInterfaceName, held)
	}
	for _, name := range methods {
		if slices.Contains(constructions, name) {
			t.Errorf("%s reads as both a construction and a method, so one of the two gate families is running over a class it was not built for", name)
		}
	}
	// and the retention gate's narrower class is a subset of this one rather than a second
	// reading that could drift away from it
	for _, name := range providerDrivenMethodNamesTakingCallerBytes(t) {
		if !slices.Contains(methods, name) {
			t.Errorf("the retention gate runs over %s, which is not one of the methods taking a %s", name, providerInterfaceName)
		}
	}
	t.Logf("%d constructions and %d methods take a %s", len(constructions), len(methods), providerInterfaceName)
}

// TestTheByteSliceReadingAgreesWithTheSpellingBasedOne cross checks the two readings of
// "handed a caller's array" over the surface where both exist.
//
// The retention gate's class is read off the type checker; the construction gate's is read off
// the parse tree, matching []byte and the byte slice type names this package declares. Two
// readings of one property drift, and a reading that stopped matching shrinks the class it
// feeds while every gate over it goes on reporting a clean run. They share nothing but the
// package's source, so a filter that broke in either one is a disagreement here.
func TestTheByteSliceReadingAgreesWithTheSpellingBasedOne(t *testing.T) {
	typeChecked := []string{}
	for _, function := range declaredFunctionsOf(t, cryptoOwnRoot) {
		if function.method {
			continue
		}
		for i := 0; i < function.signature.Params().Len(); i++ {
			if isByteSliceType(function.signature.Params().At(i).Type()) {
				typeChecked = append(typeChecked, function.name)
				break
			}
		}
	}
	slices.Sort(typeChecked)
	if len(typeChecked) == 0 {
		t.Fatal("the type checked reading found no construction handed a caller's array, so this comparison holds for a filter that matches nothing")
	}
	if spelled := packageLevelFunctionsTakingCallerBytes(t); !slices.Equal(typeChecked, spelled) {
		t.Errorf("the type checked reading of the constructions handed a caller's array is %v and the spelling based one is %v",
			typeChecked, spelled)
	}
}
