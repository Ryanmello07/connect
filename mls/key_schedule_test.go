// Tests for the RFC 9420 section 8 key schedule. This task covers only the two pieces
// every later one rests on: the typed errors and the zeroize helper.
//
// On what the zeroize tests do and do not claim. Reading a secret back through the same
// slice header proves a write happened; it says nothing about whether the caller's
// secret is gone, because a secret that was copied, appended or converted to a string
// lives in a second array this helper was never given. The tests below therefore assert
// the three things go can actually observe — every byte of the given slice becomes zero,
// a slice header taken over the same array BEFORE the call sees those zeros, and nothing
// outside the given slice is touched — and the limit beyond that is written down in
// secret_zeroize.go rather than dressed up as a test. See that file's comment.
//
// The fourth thing that file's argument rests on is the //go:noinline directive, and it
// is read out of the source here rather than left to prose. No go test can observe a
// store being elided; what a test can observe is whether the one mechanism the file says
// prevents the elision is still written down.
//
// On the error list. keyScheduleOwnedErrors below is a transcription, and a transcription
// of a class that exists in the tree is the failure mode this repository has paid for
// fourteen times. It is held to errors_key_schedule.go's own declarations by
// TestKeyScheduleOwnedErrorsIsEveryDeclarationOfItsFile, so the two sweeps that run over
// it — distinctness, and the exclusivity of syntax.ErrTrailingBytes — run over the class
// rather than over a copy of it that an eleventh error can be left out of.
package mls

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// TestZeroizeSecretClearsEveryByteItWasGiven sweeps lengths rather than testing one,
// because the mistakes this helper invites are off by one at an end: a loop stopping a
// byte short, a loop starting at one. Every byte starts non zero, so "already zero"
// cannot be mistaken for "cleared".
func TestZeroizeSecretClearsEveryByteItWasGiven(t *testing.T) {
	for _, length := range []int{0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 33, 64, 255} {
		secret := make([]byte, length)
		for i := range secret {
			secret[i] = byte(i%251) + 1
		}
		zeroizeSecret(secret)
		for i, b := range secret {
			if b != 0 {
				t.Fatalf("length %d: byte %d is %d after zeroize, want 0", length, i, b)
			}
		}
	}
}

// TestZeroizeSecretIsVisibleThroughASliceTakenBeforeTheCall is the closest go lets a
// test come to "the caller's secret is gone": a second header over the same backing
// array, created before the call, must observe the zeros. An implementation that
// erased a copy of its argument — zeroing append([]byte(nil), secret...) rather than
// secret — passes a read back through the argument and fails here.
func TestZeroizeSecretIsVisibleThroughASliceTakenBeforeTheCall(t *testing.T) {
	backing := make([]byte, 8)
	for i := range backing {
		backing[i] = byte(i) + 1
	}
	alias := backing[2:6]
	zeroizeSecret(backing)
	for i, b := range alias {
		if b != 0 {
			t.Fatalf("alias byte %d is %d; the caller's own view of the secret survived the erase", i, b)
		}
	}
}

// TestZeroizeSecretTouchesNothingOutsideTheSliceItWasGiven pins the other direction.
// The window has capacity past its length, so an implementation reaching for
// secret[:cap(secret)] — a plausible "erase everything the array could hold" — would
// clobber bytes the caller still owns. Erasing too much is a data corruption bug, not
// an over eager security measure.
func TestZeroizeSecretTouchesNothingOutsideTheSliceItWasGiven(t *testing.T) {
	backing := make([]byte, 8)
	for i := range backing {
		backing[i] = byte(i) + 1
	}
	window := backing[2:6]
	if cap(window) <= len(window) {
		t.Fatalf("window has cap %d and len %d, so the reslice past len this test is about is unreachable",
			cap(window), len(window))
	}
	zeroizeSecret(window)
	for i := range backing {
		want := byte(i) + 1
		if 2 <= i && i < 6 {
			want = 0
		}
		if backing[i] != want {
			t.Fatalf("backing byte %d is %d, want %d; zeroize did not stop at the slice it was given",
				i, backing[i], want)
		}
	}
}

// TestZeroizeSecretAcceptsNilAndEmpty asserts the no-guard-at-the-call-site contract.
// An implementation indexing before it checks the length panics here.
func TestZeroizeSecretAcceptsNilAndEmpty(t *testing.T) {
	zeroizeSecret(nil)
	zeroizeSecret([]byte{})
	zeroizeSecret(make([]byte, 0, 16))
}

// secretZeroizeFile is the file the erase helpers live in. The gate below reads the file
// rather than naming zeroizeSecret, because the rule is a property of what that file is
// for — a store the caller drops immediately afterwards — and not of one name. A second
// erase helper landing beside it is held to the same rule without anyone remembering to
// extend a list.
const secretZeroizeFile = "secret_zeroize.go"

// noInlineDirective is the compiler directive, matched as a whole line. secret_zeroize.go
// argues from the directive by name twice in prose, so a substring search over the file is
// answered by the argument for the directive rather than by the directive, and deleting
// the line leaves both mentions behind. That is why this is compared against a comment of
// the syntax tree, and against the whole of it.
const noInlineDirective = "//go:noinline"

// noInlineControl holds one of each shape the matcher has to tell apart: the directive
// present, the directive named only in prose, and no doc comment at all. Without it a
// matcher that had stopped matching — a doc group no longer populated because the parse
// dropped comments — would report the source clean and pass, which is the one outcome a
// gate must never be able to reach by accident.
const noInlineControl = "package control\n" +
	"\n" +
	"// erasedWithTheDirective is what this gate wants: the directive on a line of its own,\n" +
	"// contiguous with the declaration.\n" +
	"//\n" +
	"//go:noinline\n" +
	"func erasedWithTheDirective(secret []byte) {}\n" +
	"\n" +
	"// erasedWithOnlyProse argues from the noinline directive and does not carry it. This is\n" +
	"// the shape a search for the text noinline cannot tell from the one above.\n" +
	"func erasedWithOnlyProse(secret []byte) {}\n" +
	"\n" +
	"func erasedWithNoDocAtAll(secret []byte) {}\n"

// carriesTheNoInlineDirective reports whether a doc group holds the directive as one of
// its own lines. The text is trimmed because this repository is checked out with
// core.autocrlf on, and a carriage return on the end of the line is what makes an exact
// comparison silently answer no on windows and yes everywhere else.
func carriesTheNoInlineDirective(doc *ast.CommentGroup) bool {
	if doc == nil {
		return false
	}
	for _, comment := range doc.List {
		if strings.TrimSpace(comment.Text) == noInlineDirective {
			return true
		}
	}
	return false
}

// functionsWithoutTheNoInlineDirective names every function a parsed file declares whose
// doc comment does not carry the directive, in declaration order.
func functionsWithoutTheNoInlineDirective(file *ast.File) []string {
	missing := []string{}
	for _, declaration := range file.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if !isFunction {
			continue
		}
		if !carriesTheNoInlineDirective(function.Doc) {
			missing = append(missing, function.Name.Name)
		}
	}
	return missing
}

// TestEveryEraseHelperCarriesTheNoInlineDirective observes the one mechanism
// secret_zeroize.go's argument rests on.
//
// What that file claims is that the stores reach memory. A compiler may delete a write to
// memory it can prove is never read again, and in a caller that drops the secret straight
// afterwards these writes are exactly that; across a call it cannot inline it cannot make
// the proof. So the directive is not decoration, it is the whole mechanism — and before
// this test, deleting the line changed nothing any test could see.
//
// The honest limit, stated rather than hidden: no go test can observe an elision, so this
// asserts the presence of the mechanism and not the effect. That is a proxy. It is the
// proxy the file's own argument is made of, which is why its absence has to fail here.
func TestEveryEraseHelperCarriesTheNoInlineDirective(t *testing.T) {
	fileSet := token.NewFileSet()
	control, err := parser.ParseFile(fileSet, "noinline_control.go", noInlineControl,
		parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse the control: %v", err)
	}
	want := []string{"erasedWithOnlyProse", "erasedWithNoDocAtAll"}
	if got := functionsWithoutTheNoInlineDirective(control); !slices.Equal(got, want) {
		t.Fatalf("the matcher read %v out of the control, want %v; it is not telling the directive from the prose that argues for it",
			got, want)
	}

	parsed, err := parser.ParseFile(fileSet, secretZeroizeFile, nil,
		parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", secretZeroizeFile, err)
	}
	declared := 0
	for _, declaration := range parsed.Decls {
		if _, isFunction := declaration.(*ast.FuncDecl); isFunction {
			declared++
		}
	}
	if declared == 0 {
		t.Fatalf("%s declares no function, so this gate examined nothing", secretZeroizeFile)
	}
	if missing := functionsWithoutTheNoInlineDirective(parsed); len(missing) != 0 {
		t.Errorf("%s declares %v without a %s line of their own; that directive is the only thing between these stores and a compiler entitled to delete them, and the file's own comment says so",
			secretZeroizeFile, missing, noInlineDirective)
	}
}

// keyScheduleErrorsFile is the single file this plan declares its typed errors in. Every
// gate below derives its class from that file rather than from the list, which is the
// difference between sweeping the class and sweeping a copy of it.
const keyScheduleErrorsFile = "errors_key_schedule.go"

// keyScheduleOwnedErrors is registry section 5.6's ten plus ErrNilGroupContext, keyed by
// the name each is declared under so the derivation below can compare the two sets by name.
// ErrPskNonceLength, ErrPskType and ErrDuplicatePsk are deliberately absent — they are
// ValSem401, ValSem402 and ValSem403 and belong to the validation plan's errors.go.
//
// ErrNilGroupContext is the one name here the registry does not carry. It is not a protocol
// condition; it is the refusal that stands where DeriveJoinerSecret used to raise a nil
// pointer dereference out of syntax.Marshal, and it is declared beside the others because
// this file is where the key schedule's errors live and a second declaration site is how
// two sentinels for one condition happen.
//
// Nothing here is trusted: TestKeyScheduleOwnedErrorsIsEveryDeclarationOfItsFile holds
// this map to what errors_key_schedule.go actually declares, in both directions.
var keyScheduleOwnedErrors = map[string]error{
	"ErrSecretLength":                 ErrSecretLength,
	"ErrExportLength":                 ErrExportLength,
	"ErrGroupContextTrailingBytes":    ErrGroupContextTrailingBytes,
	"ErrNilGroupContext":              ErrNilGroupContext,
	"ErrTranscriptHashLength":         ErrTranscriptHashLength,
	"ErrPskCount":                     ErrPskCount,
	"ErrSecretTreeLeafOutOfRange":     ErrSecretTreeLeafOutOfRange,
	"ErrSecretTreeConsumed":           ErrSecretTreeConsumed,
	"ErrRatchetGenerationConsumed":    ErrRatchetGenerationConsumed,
	"ErrRatchetGenerationTooFarAhead": ErrRatchetGenerationTooFarAhead,
	"ErrRatchetExhausted":             ErrRatchetExhausted,
}

// TestKeyScheduleOwnedErrorsIsEveryDeclarationOfItsFile derives the class the two sweeps
// below run over instead of trusting the transcription of it.
//
// This is the half that was missing and it is the half with the consequence. An eleventh
// error declared in errors_key_schedule.go and left off the list is judged by neither
// sweep: distinctness never sees it, and the exclusivity sweep — the one that says only
// ErrGroupContextTrailingBytes may answer to syntax.ErrTrailingBytes — counts one match
// and passes while two errors in production answer to that sentinel, which is exactly the
// condition it exists to forbid. A count assertion cannot close that, because it has the
// wrong polarity: it fails on adding an error and remembering the list, and stays quiet on
// adding one and forgetting it.
//
// The derivation is every package level name the file declares, not every name that looks
// like an error, because that file holds nothing else by design and a name this gate
// cannot classify should be loud. A helper or a type landing there fails here too, which
// says either move it or widen the rule on purpose.
func TestKeyScheduleOwnedErrorsIsEveryDeclarationOfItsFile(t *testing.T) {
	declared := packageLevelDeclarations(t, ".")
	fromFile := map[string]bool{}
	for name, file := range declared {
		if file == keyScheduleErrorsFile {
			fromFile[name] = true
		}
	}
	if len(fromFile) == 0 {
		t.Fatalf("the scan found nothing declared in %s, so this gate compared the list against an empty set",
			keyScheduleErrorsFile)
	}
	if !fromFile["ErrSecretLength"] {
		t.Fatalf("the scan did not find ErrSecretLength among the declarations of %s, which certainly declares it, so it is reading something other than that file",
			keyScheduleErrorsFile)
	}
	for _, name := range slices.Sorted(maps.Keys(fromFile)) {
		if _, listed := keyScheduleOwnedErrors[name]; !listed {
			t.Errorf("%s declares %s and keyScheduleOwnedErrors does not list it, so neither the distinctness sweep nor the syntax.ErrTrailingBytes exclusivity sweep judges it; add it there",
				keyScheduleErrorsFile, name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(keyScheduleOwnedErrors)) {
		if !fromFile[name] {
			t.Errorf("keyScheduleOwnedErrors lists %s and %s does not declare it, so the sweeps run over a name this file does not own",
				name, keyScheduleErrorsFile)
		}
	}
}

// TestKeyScheduleErrorsAreDistinct asserts no two of the typed errors alias each other,
// so a test asserting a specific failure cannot be answered yes by the wrong one. Two
// vars sharing one errors.New value make a length failure indistinguishable from an
// exhaustion failure at every call site that branches on them.
//
// The count assertion pins the file: a name added to it is a change somebody has to make
// deliberately, in the same commit, with a reason. What stops the list shrinking, and what
// stops it lagging behind the file, is the derivation above rather than this number.
//
// Eleven rather than the ten of registry section 5.6: ErrNilGroupContext is the twelfth
// name this file could have carried and the first one added here that the registry does not
// list, because it names an argument that was missing rather than a protocol condition.
func TestKeyScheduleErrorsAreDistinct(t *testing.T) {
	if len(keyScheduleOwnedErrors) != 11 {
		t.Fatalf("this plan owns %d errors, want the 10 of registry section 5.6 plus ErrNilGroupContext", len(keyScheduleOwnedErrors))
	}
	names := slices.Sorted(maps.Keys(keyScheduleOwnedErrors))
	for i, name := range names {
		first := keyScheduleOwnedErrors[name]
		if first == nil {
			t.Fatalf("%s is nil", name)
		}
		if first.Error() == "" {
			t.Fatalf("%s has an empty message", name)
		}
		for j, other := range names {
			if i == j {
				continue
			}
			second := keyScheduleOwnedErrors[other]
			if errors.Is(first, second) {
				t.Errorf("%s aliases %s: %v", name, other, first)
			}
			if first.Error() == second.Error() {
				t.Errorf("%s and %s carry the same message %q, so a log cannot tell them apart",
					name, other, first.Error())
			}
		}
	}
}

// TestGroupContextTrailingBytesWrapsTheSyntaxError asserts the group context trailing
// byte condition is reachable through the syntax package's own sentinel, so a caller
// that only knows syntax.ErrTrailingBytes still matches it. Two names exist because
// syntax.Unmarshal is what enforces full consumption while this value is what names the
// condition for the group context specifically.
func TestGroupContextTrailingBytesWrapsTheSyntaxError(t *testing.T) {
	if !errors.Is(ErrGroupContextTrailingBytes, syntax.ErrTrailingBytes) {
		t.Fatal("ErrGroupContextTrailingBytes does not wrap syntax.ErrTrailingBytes")
	}
}

// TestOnlyTheGroupContextErrorAnswersToTheSyntaxSentinel is the other half, and it is
// the half that has teeth. Wrapping is useful only while it stays exclusive: a second
// error of this file wrapping syntax.ErrTrailingBytes would make a caller asking "was
// this a trailing byte problem" get yes for a length mistake. The sweep is over the same
// map as the distinctness test, and that map is held to errors_key_schedule.go's own
// declarations, so what is judged here is what production declares.
func TestOnlyTheGroupContextErrorAnswersToTheSyntaxSentinel(t *testing.T) {
	matched := 0
	for _, name := range slices.Sorted(maps.Keys(keyScheduleOwnedErrors)) {
		err := keyScheduleOwnedErrors[name]
		if !errors.Is(err, syntax.ErrTrailingBytes) {
			continue
		}
		matched++
		if err != ErrGroupContextTrailingBytes {
			t.Errorf("%s (%v) also answers to syntax.ErrTrailingBytes; only ErrGroupContextTrailingBytes may",
				name, err)
		}
	}
	if matched != 1 {
		t.Fatalf("%d of the errors %s declares answer to syntax.ErrTrailingBytes, want exactly 1",
			matched, keyScheduleErrorsFile)
	}
}

// One test this task's plan asked for is not here, and this is the note that says so
// rather than letting its absence look like an oversight.
//
// TestPskSentinelsBelongToTheValidationPlan asserts that ErrPskNonceLength, ErrPskType
// and ErrDuplicatePsk resolve to the validation plan's declarations and that
// ValSem(ValSem401, detail) preserves its detail under errors.Is. None of those five
// names exists in this package yet, so the test cannot compile, and an undefined name
// takes the whole package down rather than showing up as one red test.
//
// It is not forgotten: all five are in crossPlanSymbolsNotYetLanded in
// key_schedule_deps_test.go, so the moment the validation plan lands them that gate fails
// and names them. Whoever answers it writes their pins and this test in the same commit.

// ---------------------------------------------------------------------------
// task 5: ZeroSecret and DeriveJoinerSecret
// ---------------------------------------------------------------------------

// TestZeroSecretIsKdfNhZeroBytesForEverySuite asserts the three things a test can honestly
// observe about the all-zero secret: it is KDF.Nh bytes long, every one of them is zero,
// and two calls do not share storage.
//
// The suites are read out of the registry rather than listed, so a third registered suite
// with a different Nh is judged here instead of being quietly skipped.
//
// What is deliberately NOT claimed, for the reason key_schedule.go's comment gives: that
// this is the RIGHT zero. One run of Nh zero bytes is indistinguishable from another, so
// nothing about the returned value says it is the substitute RFC 9420 makes for a missing
// commit secret or a missing psk. The published corpora that expand over it say that, and
// they belong to the tasks that consume this function. A test here asserting more would be
// reassuring rather than checking, which is the shape task 2 wrote down instead of faking.
func TestZeroSecretIsKdfNhZeroBytesForEverySuite(t *testing.T) {
	suites := Suites()
	if len(suites) == 0 {
		t.Fatal("the registry named no suite, so this test examined nothing")
	}
	for _, suite := range suites {
		crypto := mustProvider(t, suite)
		if crypto.HashSize() == 0 {
			t.Fatalf("suite %#04x reports a hash size of 0, so an empty slice would satisfy every assertion below",
				uint16(suite))
		}
		zero := ZeroSecret(crypto)
		if len(zero) != crypto.HashSize() {
			t.Errorf("suite %#04x: ZeroSecret is %d bytes, want KDF.Nh = %d",
				uint16(suite), len(zero), crypto.HashSize())
			continue
		}
		for i, b := range zero {
			if b != 0 {
				t.Errorf("suite %#04x: byte %d of ZeroSecret is %d, want 0", uint16(suite), i, b)
				break
			}
		}
		// the key schedule erases what it has finished with, so a shared constant would
		// come back cleared on every later call with nothing to say why.
		zero[0] = 0xff
		again := ZeroSecret(crypto)
		if again[0] != 0 {
			t.Errorf("suite %#04x: ZeroSecret hands out storage a previous caller can write through",
				uint16(suite))
		}
		if &again[0] == &zero[0] {
			t.Errorf("suite %#04x: two calls to ZeroSecret returned the same backing array", uint16(suite))
		}
	}
}

// keyScheduleKatFile is the mlswg family the published joiner secrets live in, and
// keyScheduleKatJoinerComparisons is how many of them this package's registered suites
// account for: two suites, five epochs each.
//
// The count is asserted rather than assumed. A filter that stopped matching — a suite
// renumbered, a json field renamed so every string decodes empty — turns a known answer
// test into a loop that runs zero times and reports PASS, which is the one outcome a known
// answer test must not be able to reach.
const (
	keyScheduleKatFile              = "key-schedule.json"
	keyScheduleKatJoinerComparisons = 10
)

// keyScheduleKatVectors returns the published key schedule entries, having first checked
// that the file on disk is the blob mlswg published at the commit interop/PINS.md pins.
//
// Which file and which entries, written down rather than left to be reconstructed: this is
// testdata/vectors/key-schedule.json from mlswg/mls-implementations test-vectors at the
// commit mlswgVectorUpstreamCommit names, and what is read from it are the entries whose
// cipher_suite this package registers, all five epochs of each, fields initial_init_secret,
// commit_secret, group_context, joiner_secret and init_secret.
//
// The provenance is verified here rather than left to the upstream anchor test. That test
// failing does not stop this one running, and a known answer test that compares against a
// file it did not authenticate is a known answer test that an edit to the file can make
// agree with anything. VECTORS.sha256 would not close it either: it is a digest of the
// local bytes, so re-recording one line of it makes a rewritten corpus verify. The digest
// used here is the one read out of upstream's git object store.
func keyScheduleKatVectors(t *testing.T) []labelKatSchedule {
	t.Helper()
	want, anchored := mlswgVectorUpstreamSha256[keyScheduleKatFile]
	if !anchored {
		t.Fatalf("%s carries no upstream digest, so the answers below would be compared against an unauthenticated file",
			keyScheduleKatFile)
	}
	raw, err := os.ReadFile(filepath.Join(mlswgVectorDirectory, keyScheduleKatFile))
	if err != nil {
		t.Fatalf("read %s: %v", keyScheduleKatFile, err)
	}
	digest := sha256.Sum256(normalisedLineEndings(raw))
	if got := hex.EncodeToString(digest[:]); got != want {
		t.Fatalf("%s hashes to %s with its line endings normalised; %s/%s at %s published %s. These are not the answers mlswg published, so nothing below is a known answer test",
			keyScheduleKatFile, got, mlswgVectorUpstreamRepository, mlswgVectorUpstreamDirectory,
			mlswgVectorUpstreamCommit, want)
	}
	vectors := []labelKatSchedule{}
	loadLabelKat(t, keyScheduleKatFile, &vectors)
	if len(vectors) == 0 {
		t.Fatalf("%s parsed to no entries", keyScheduleKatFile)
	}
	return vectors
}

// TestDeriveJoinerSecretMatchesTheMlswgKeySchedule is the known answer test guardrail 1
// exists for, and it is the deliverable of this task.
//
// joiner_secret is Extract(init_secret_[n-1], commit_secret) expanded under "joiner". Both
// Extract arguments are KDF.Nh secrets, so transposing them compiles, returns 32 bytes, and
// produces a value that is deterministic, that differs for differing inputs, that round
// trips and that satisfies every self consistency check this package could write. Nothing
// separates the two except a value neither side of the swap invented.
//
// Three things stop the comparison passing vacuously. The corpus is authenticated against
// upstream before it is read. The number of comparisons is counted and asserted, and the
// suites the loop matched are compared against the registry. And each epoch's two Extract
// inputs are required to differ, because an epoch whose init secret happened to equal its
// commit secret would agree with a swapped implementation and pin nothing.
//
// The group context goes in as the decoded structure, which is what DeriveJoinerSecret's
// signature takes, so this walks the section 8.1 codec as well. The re-encoding is asserted
// against the published bytes first: a codec that disagreed would otherwise be reported
// here as a key schedule failure, which is the wrong sentence about the wrong file.
func TestDeriveJoinerSecretMatchesTheMlswgKeySchedule(t *testing.T) {
	compared := 0
	matched := []CipherSuite{}
	for _, vector := range keyScheduleKatVectors(t) {
		suite := CipherSuite(vector.CipherSuite)
		if !IsRegisteredSuite(suite) {
			continue
		}
		matched = append(matched, suite)
		crypto := mustProvider(t, suite)
		previousInit := mustDecodeHex(t, "initial_init_secret", vector.InitialInitSecret)
		for index, epoch := range vector.Epochs {
			at := fmt.Sprintf(" suite %#04x epoch %d", uint16(suite), index)
			commitSecret := mustDecodeHex(t, "commit_secret"+at, epoch.CommitSecret)
			if bytes.Equal(previousInit, commitSecret) {
				t.Errorf("%s: the init secret and the commit secret are the same bytes, so this epoch agrees with a swapped Extract and pins nothing about the argument order",
					at)
			}
			publishedContext := mustDecodeHex(t, "group_context"+at, epoch.GroupContext)
			groupContext := &GroupContext{}
			if err := syntax.Unmarshal(publishedContext, groupContext); err != nil {
				t.Fatalf("%s: decode the published group context: %v", at, err)
			}
			reEncoded, err := syntax.Marshal(groupContext)
			if err != nil {
				t.Fatalf("%s: re-encode the decoded group context: %v", at, err)
			}
			if !bytes.Equal(reEncoded, publishedContext) {
				t.Fatalf("%s: the group context codec re-encodes to %x and the corpus published %x, so a joiner mismatch below would be the codec and not the key schedule",
					at, reEncoded, publishedContext)
			}
			joiner, err := DeriveJoinerSecret(crypto, previousInit, commitSecret, groupContext)
			if err != nil {
				t.Fatalf("%s: DeriveJoinerSecret: %v", at, err)
			}
			assertLabelKat(t, "joiner_secret"+at, joiner, epoch.JoinerSecret)
			compared++
			previousInit = mustDecodeHex(t, "init_secret"+at, epoch.InitSecret)
		}
	}
	if compared != keyScheduleKatJoinerComparisons {
		t.Fatalf("compared %d published joiner secrets, want %d; the loop matched %v",
			compared, keyScheduleKatJoinerComparisons, matched)
	}
	if got := slices.Sorted(slices.Values(matched)); !slices.Equal(got, Suites()) {
		t.Fatalf("the corpus answered for %v and this package registers %v", got, Suites())
	}
}

// independentJoinerSecret is RFC 9420's joiner derivation written out from the two RFCs it
// is made of, using crypto/hmac and nothing this package computes.
//
// It is here because the corpus and the implementation could in principle agree for a
// reason other than being right: a vendored file is bytes on disk, and the whole argument
// that they are mlswg's bytes is a digest comparison against a commit this repository only
// records the name of. This is a second statement of the same answer that a reader can
// check line by line without fetching anything:
//
//	RFC 5869 section 2.2      HKDF-Extract(salt, IKM) = HMAC-Hash(key = salt, data = IKM)
//	RFC 9420 section 8        the salt is init_secret_[n-1]; the IKM is commit_secret
//	RFC 9420 section 8        joiner = ExpandWithLabel(prk, "joiner", GroupContext, KDF.Nh)
//	RFC 9420 section 5.1      ExpandWithLabel expands under the serialization of
//	                          struct { uint16 length; opaque label<V>; opaque context<V> },
//	                          the label carrying the "MLS 1.0 " prefix
//	RFC 9420 section 2.1.2    opaque<V> takes a variable length integer prefix: one octet
//	                          with prefix bits 0b00 below 64, two with 0b01 up to 16383
//	RFC 5869 section 2.3      HKDF-Expand's first block is HMAC(prk, info || 0x01), and 32
//	                          octets is exactly that first block under sha256
//
// so for the 14 octet label "MLS 1.0 joiner" and a 112 octet group context the info is
//
//	00 20      the requested output length, 32, big endian uint16
//	0e         label<V> byte length 14; 14 < 64 so one octet, prefix bits 0b00
//	4d 4c ..   the 14 label octets, "MLS 1.0 joiner"
//	40 70      context<V> byte length 112; 112 > 63 so two octets: 0x40|(112>>8), 112&0xff
//	00 01 ..   the 112 group context octets
//
// Every part of that is a hazard with no other witness in this package. A single octet
// length on a 112 byte context, a label without the "MLS 1.0 " prefix, a length field
// holding the label's size instead of the output's, or the two opaque fields transposed all
// produce a perfectly well formed 32 byte secret.
func independentJoinerSecret(t *testing.T, initSecretPrev []byte, commitSecret []byte, groupContext []byte) []byte {
	t.Helper()
	// HKDF-Extract: the salt is the hmac key and the input keying material is the message
	extract := hmac.New(sha256.New, initSecretPrev)
	extract.Write(commitSecret)
	prk := extract.Sum(nil)

	label := []byte("MLS 1.0 joiner")
	if len(label) >= 64 {
		t.Fatalf("the label is %d octets, so the one octet varint written below is the wrong encoding", len(label))
	}
	if len(groupContext) < 64 || len(groupContext) > 16383 {
		t.Fatalf("the group context is %d octets, so the two octet varint written below is the wrong encoding",
			len(groupContext))
	}
	info := []byte{}
	info = append(info, byte(sha256.Size>>8), byte(sha256.Size))
	info = append(info, byte(len(label)))
	info = append(info, label...)
	info = append(info, 0x40|byte(len(groupContext)>>8), byte(len(groupContext)))
	info = append(info, groupContext...)

	// HKDF-Expand, first and only block: 32 octets is one sha256 output
	expand := hmac.New(sha256.New, prk)
	expand.Write(info)
	expand.Write([]byte{0x01})
	return expand.Sum(nil)
}

// TestDeriveJoinerSecretMatchesAnIndependentDerivation runs that derivation against every
// published epoch and requires all three — this package, the corpus, and the hand written
// HKDF — to agree.
//
// The swapped call is checked first on the hand written side. A derivation that gave the
// same answer with its two Extract arguments transposed could not see the defect this whole
// task exists for, and would agree with a swapped implementation while looking like a
// second opinion.
func TestDeriveJoinerSecretMatchesAnIndependentDerivation(t *testing.T) {
	compared := 0
	for _, vector := range keyScheduleKatVectors(t) {
		suite := CipherSuite(vector.CipherSuite)
		if !IsRegisteredSuite(suite) {
			continue
		}
		crypto := mustProvider(t, suite)
		previousInit := mustDecodeHex(t, "initial_init_secret", vector.InitialInitSecret)
		for index, epoch := range vector.Epochs {
			at := fmt.Sprintf(" suite %#04x epoch %d", uint16(suite), index)
			commitSecret := mustDecodeHex(t, "commit_secret"+at, epoch.CommitSecret)
			publishedContext := mustDecodeHex(t, "group_context"+at, epoch.GroupContext)
			groupContext := &GroupContext{}
			if err := syntax.Unmarshal(publishedContext, groupContext); err != nil {
				t.Fatalf("%s: decode the published group context: %v", at, err)
			}
			want := independentJoinerSecret(t, previousInit, commitSecret, publishedContext)
			if swapped := independentJoinerSecret(t, commitSecret, previousInit, publishedContext); bytes.Equal(swapped, want) {
				t.Fatalf("%s: the hand written derivation gives one answer for both argument orders, so it cannot see a transposition",
					at)
			}
			got, err := DeriveJoinerSecret(crypto, previousInit, commitSecret, groupContext)
			if err != nil {
				t.Fatalf("%s: DeriveJoinerSecret: %v", at, err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s: DeriveJoinerSecret = %x and the hand written HKDF gives %x", at, got, want)
			}
			assertLabelKat(t, "the hand written HKDF against the published joiner_secret"+at, want, epoch.JoinerSecret)
			compared++
			previousInit = mustDecodeHex(t, "init_secret"+at, epoch.InitSecret)
		}
	}
	if compared != keyScheduleKatJoinerComparisons {
		t.Fatalf("compared %d epochs, want %d", compared, keyScheduleKatJoinerComparisons)
	}
}

// TestDeriveJoinerSecretRefusesSecretsThatAreNotKdfNh sweeps lengths on both arguments
// rather than testing one short case.
//
// HKDF-Extract accepts every length of either argument, so a truncated init secret produces
// a perfectly well formed pseudorandom key and an epoch nobody else derives; the mistake
// then surfaces epochs later as an undecryptable message. The nil result is asserted
// alongside the error, since a caller reading the slice rather than the error would
// otherwise take a full length secret out of a refused call.
//
// The accepting control runs first, so the refusals below are attributable to the lengths
// rather than to something else about the call.
func TestDeriveJoinerSecretRefusesSecretsThatAreNotKdfNh(t *testing.T) {
	for _, suite := range Suites() {
		crypto := mustProvider(t, suite)
		nh := crypto.HashSize()
		good := bytes.Repeat([]byte{0xa5}, nh)
		other := bytes.Repeat([]byte{0x5a}, nh)
		groupContext := ksVectorEpoch0GroupContext(t)
		if _, err := DeriveJoinerSecret(crypto, good, other, groupContext); err != nil {
			t.Fatalf("suite %#04x: two KDF.Nh secrets were refused: %v", uint16(suite), err)
		}
		for _, length := range []int{0, 1, nh - 1, nh + 1, 2 * nh} {
			wrong := bytes.Repeat([]byte{0xa5}, length)
			for _, testCase := range []struct {
				name   string
				init   []byte
				commit []byte
			}{
				{name: "init secret", init: wrong, commit: other},
				{name: "commit secret", init: good, commit: wrong},
			} {
				secret, err := DeriveJoinerSecret(crypto, testCase.init, testCase.commit, groupContext)
				if !errors.Is(err, ErrSecretLength) {
					t.Errorf("suite %#04x: a %d byte %s gave err = %v, want ErrSecretLength",
						uint16(suite), length, testCase.name, err)
				}
				if secret != nil {
					t.Errorf("suite %#04x: a %d byte %s was refused and %d bytes of secret came back beside the error",
						uint16(suite), length, testCase.name, len(secret))
				}
			}
		}
		// nil is the zero length case arriving with no storage at all, which a length
		// check written as a nil check would answer differently
		for _, testCase := range []struct {
			name   string
			init   []byte
			commit []byte
		}{
			{name: "init secret", init: nil, commit: other},
			{name: "commit secret", init: good, commit: nil},
		} {
			if _, err := DeriveJoinerSecret(crypto, testCase.init, testCase.commit, groupContext); !errors.Is(err, ErrSecretLength) {
				t.Errorf("suite %#04x: a nil %s gave err = %v, want ErrSecretLength",
					uint16(suite), testCase.name, err)
			}
		}
	}
}

// mutatedGroupContexts returns one copy of the context per field of GroupContext, each with
// exactly that field changed, keyed by the field's name.
//
// The fields are read off the type rather than listed. This project has been walked past a
// hand written list of a class fourteen times, and here the consequence is specific: a
// field added to GroupContext by a later plan and left out of a list is a field nothing
// requires to be in the preimage, which is two members deriving different secrets from
// contexts they both consider equal.
//
// An unhandled kind is fatal rather than skipped, because a skipped field is a field this
// gate stops judging in silence.
func mutatedGroupContexts(t *testing.T, base *GroupContext) map[string]*GroupContext {
	t.Helper()
	contextType := reflect.TypeOf(GroupContext{})
	if contextType.NumField() == 0 {
		t.Fatal("GroupContext declares no field, so this gate would compare nothing")
	}
	extensionType := reflect.TypeOf(Extension{})
	mutated := map[string]*GroupContext{}
	for i := range contextType.NumField() {
		name := contextType.Field(i).Name
		clone := base.Clone()
		target := reflect.ValueOf(clone).Elem().Field(i)
		switch {
		case target.CanUint():
			target.SetUint(target.Uint() + 1)
		case target.Kind() == reflect.Slice && target.Type().Elem().Kind() == reflect.Uint8:
			target.Set(reflect.AppendSlice(target, reflect.ValueOf([]byte{0x7f})))
		case target.Kind() == reflect.Slice && target.Type().Elem() == extensionType:
			target.Set(reflect.Append(target, reflect.ValueOf(Extension{
				ExtensionType: ExtensionType(0xf00d),
				ExtensionData: []byte{0x01},
			})))
		default:
			t.Fatalf("GroupContext.%s is a %s and this gate does not know how to change one; teach it rather than letting the field go unjudged",
				name, target.Type())
		}
		mutated[name] = clone
	}
	return mutated
}

// TestDeriveJoinerSecretReadsEveryFieldOfTheGroupContext walks what the published corpus
// cannot.
//
// Every mlswg key schedule vector carries one protocol version, one cipher suite, one group
// id per entry and an empty extensions vector, so four of GroupContext's seven fields never
// move anywhere in the whole corpus. An implementation that dropped the version, the cipher
// suite, the group id or the extensions out of the preimage matches every published joiner
// secret there is, and splits from any peer whose group differs from the vector's in one of
// them.
//
// The two secrets and the argument order are checked here too. The transposition assertion
// is necessary and not sufficient — it says the two arguments are not interchangeable, and
// says nothing about which way round is right. The known answer tests above are what say
// that; this one is what fails first and most legibly when they cannot run.
func TestDeriveJoinerSecretReadsEveryFieldOfTheGroupContext(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	base := ksVectorEpoch0GroupContext(t)
	initSecret := bytes.Repeat([]byte{0xa5}, crypto.HashSize())
	commitSecret := bytes.Repeat([]byte{0x5a}, crypto.HashSize())
	want, err := DeriveJoinerSecret(crypto, initSecret, commitSecret, base)
	if err != nil {
		t.Fatalf("DeriveJoinerSecret over the base context: %v", err)
	}

	cases := mutatedGroupContexts(t, base)
	if fields := reflect.TypeOf(GroupContext{}).NumField(); len(cases) != fields {
		t.Fatalf("GroupContext declares %d fields and this gate built %d cases", fields, len(cases))
	}
	for _, name := range slices.Sorted(maps.Keys(cases)) {
		got, err := DeriveJoinerSecret(crypto, initSecret, commitSecret, cases[name])
		if err != nil {
			t.Errorf("GroupContext.%s changed: DeriveJoinerSecret: %v", name, err)
			continue
		}
		if bytes.Equal(got, want) {
			t.Errorf("changing GroupContext.%s left the joiner secret unchanged, so that field is not in the preimage the epoch is bound to",
				name)
		}
	}

	changedInit := bytes.Clone(initSecret)
	changedInit[0] ^= 0x01
	changedCommit := bytes.Clone(commitSecret)
	changedCommit[len(changedCommit)-1] ^= 0x01
	for _, testCase := range []struct {
		what   string
		init   []byte
		commit []byte
	}{
		{what: "the init secret", init: changedInit, commit: commitSecret},
		{what: "the commit secret", init: initSecret, commit: changedCommit},
		{what: "the two Extract arguments transposed", init: commitSecret, commit: initSecret},
	} {
		got, err := DeriveJoinerSecret(crypto, testCase.init, testCase.commit, base)
		if err != nil {
			t.Errorf("%s: DeriveJoinerSecret: %v", testCase.what, err)
			continue
		}
		if bytes.Equal(got, want) {
			t.Errorf("%s left the joiner secret unchanged", testCase.what)
		}
	}
}

// TestDeriveJoinerSecretLeavesTheCallersInputsAlone. The function erases the pseudorandom
// key it built, which is right, and the three things it was handed belong to the caller,
// which means it must not.
//
// init_secret_[n-1] in particular is still needed if the commit that produced this joiner
// secret turns out to be invalid: a caller whose init secret came back as KDF.Nh zero bytes
// would derive the next epoch from them, and every derivation downstream would look fine.
// The aliasing half is the same hazard arriving later — a joiner secret that is a window
// onto one of its inputs is one caller's zeroize away from erasing a secret it does not own.
func TestDeriveJoinerSecretLeavesTheCallersInputsAlone(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	initSecret := bytes.Repeat([]byte{0xa5}, crypto.HashSize())
	commitSecret := bytes.Repeat([]byte{0x5a}, crypto.HashSize())
	initBefore := bytes.Clone(initSecret)
	commitBefore := bytes.Clone(commitSecret)
	groupContext := ksVectorEpoch0GroupContext(t)
	contextBefore := groupContext.Clone()

	joiner, err := DeriveJoinerSecret(crypto, initSecret, commitSecret, groupContext)
	if err != nil {
		t.Fatalf("DeriveJoinerSecret: %v", err)
	}
	if !bytes.Equal(initSecret, initBefore) {
		t.Errorf("the caller's init secret is %x after the call and was %x", initSecret, initBefore)
	}
	if !bytes.Equal(commitSecret, commitBefore) {
		t.Errorf("the caller's commit secret is %x after the call and was %x", commitSecret, commitBefore)
	}
	if !reflect.DeepEqual(groupContext, contextBefore) {
		t.Errorf("the group context handed in came back as %+v, having been %+v", groupContext, contextBefore)
	}
	if len(joiner) != crypto.HashSize() {
		t.Fatalf("the joiner secret is %d bytes, want %d", len(joiner), crypto.HashSize())
	}
	// snapshotted after the call rather than compared against initBefore, so this
	// reports aliasing and not an erase the two checks above have already named
	initAfter := bytes.Clone(initSecret)
	commitAfter := bytes.Clone(commitSecret)
	for i := range joiner {
		joiner[i] ^= 0xff
	}
	if !bytes.Equal(initSecret, initAfter) || !bytes.Equal(commitSecret, commitAfter) {
		t.Errorf("writing through the joiner secret changed one of the secrets it was derived from, so it is a window onto storage the caller owns")
	}
}

// extractCapturingProvider keeps the pseudorandom key DeriveJoinerSecret builds, so a test
// can read that storage back after the call has returned.
//
// The slice is returned unchanged rather than copied, and that is the whole mechanism this
// observes: zeroizeSecret writes through the backing array its argument points at, so a
// wrapper that handed the caller a clone would be handing it a different array the erase
// never reaches, and the property would read as absent however the production code behaved.
// The count is kept too, because "the key was erased" means nothing if no key was made.
type extractCapturingProvider struct {
	CryptoProvider
	extracted [][]byte
}

func (self *extractCapturingProvider) Extract(salt []byte, ikm []byte) []byte {
	prk := self.CryptoProvider.Extract(salt, ikm)
	self.extracted = append(self.extracted, prk)
	return prk
}

// TestDeriveJoinerSecretErasesThePseudorandomKey observes the sentence key_schedule.go
// writes above DeriveJoinerSecret: "The pseudorandom key is erased before returning."
//
// Nothing observed it before. Deleting the zeroizeSecret call failed exactly one assertion
// in the whole package -- TestNoStubShapesRemainInSource reporting that zeroizeSecret then
// has no caller -- which is a statement about the call graph and not about the key. That
// catch expires on the next production caller of the helper, and the plan lands six of
// them; this one does not expire, because what it reads is the storage.
//
// The control matters as much as the assertion. A run of Nh zero bytes is what a stub
// answers, so "every byte is zero afterwards" is only evidence if the same Extract over the
// same inputs produces something that is not already zero, and that is asserted first.
func TestDeriveJoinerSecretErasesThePseudorandomKey(t *testing.T) {
	for _, suite := range Suites() {
		inner := mustProvider(t, suite)
		nh := inner.HashSize()
		initSecret := bytes.Repeat([]byte{0xa5}, nh)
		commitSecret := bytes.Repeat([]byte{0x5a}, nh)
		groupContext := ksVectorEpoch0GroupContext(t)

		// the control: the key this call will erase is not zero to begin with
		fresh := inner.Extract(initSecret, commitSecret)
		if !slices.ContainsFunc(fresh, func(b byte) bool { return b != 0 }) {
			t.Fatalf("suite %#04x: Extract over these inputs is already %d zero bytes, so an all zero reading below would say nothing",
				uint16(suite), len(fresh))
		}

		crypto := &extractCapturingProvider{CryptoProvider: inner}
		joiner, err := DeriveJoinerSecret(crypto, initSecret, commitSecret, groupContext)
		if err != nil {
			t.Fatalf("suite %#04x: DeriveJoinerSecret: %v", uint16(suite), err)
		}
		if len(crypto.extracted) != 1 {
			t.Fatalf("suite %#04x: Extract was called %d times, want 1; this gate reads the key that one call returned",
				uint16(suite), len(crypto.extracted))
		}
		prk := crypto.extracted[0]
		if len(prk) != nh {
			t.Fatalf("suite %#04x: the pseudorandom key is %d bytes, want %d", uint16(suite), len(prk), nh)
		}
		for i, b := range prk {
			if b != 0 {
				t.Errorf("suite %#04x: byte %d of the pseudorandom key is %#02x after the call, want 0; it is one HKDF-Expand away from every key of the epoch and nothing downstream needs it",
					uint16(suite), i, b)
				break
			}
		}
		// and the erase reached the key rather than the answer: a joiner secret that came
		// back zero would satisfy the loop above for the wrong reason
		if len(joiner) != nh {
			t.Fatalf("suite %#04x: the joiner secret is %d bytes, want %d", uint16(suite), len(joiner), nh)
		}
		if !slices.ContainsFunc(joiner, func(b byte) bool { return b != 0 }) {
			t.Errorf("suite %#04x: the joiner secret came back as %d zero bytes, so the erase reached the value that was returned",
				uint16(suite), len(joiner))
		}
	}
}

// wideKdfHashSize is a KDF.Nh neither registered suite has.
const wideKdfHashSize = sha512.Size384

// wideKdfProvider is a provider whose KDF.Nh is not 32.
//
// Both registered suites fix Nh at 32, so nothing already in this tree separates a body
// that reads KDF.Nh off the provider it was handed from one that writes 32 down. Measured,
// not supposed: nh := crypto.HashSize() replaced by nh := 32 in DeriveJoinerSecret passed
// every test of this package. This is the input that separates them, and it is the same
// limit the ZeroSecret note in crypto_test.go records.
//
// It is a real kdf rather than a fake answering the right number of bytes: HKDF-SHA384,
// whose Nh is 48, expanding over the same mlsKdfLabel preimage the production provider
// builds. Only the three methods DeriveJoinerSecret reaches are overridden; everything else
// is the registered suite's, so a derivation that grew a fourth call would get a working
// method rather than a nil dereference that reads as this gate's own bug.
//
// The requested expansion lengths are recorded because KDF.Nh governs two separate things
// here -- which lengths are refused, and how many bytes are asked for -- and a body that
// read the provider for the first and wrote 32 for the second would pass a length check
// alone.
type wideKdfProvider struct {
	CryptoProvider
	expandedLengths []int
}

func (self *wideKdfProvider) HashSize() int {
	return wideKdfHashSize
}

// (salt, ikm) in, (ikm, salt) out, which is the swap crypto.go makes and the reason
// guardrail 1 confines the call. Calling the library here is allowed: the confinement gate
// runs over productionSources, which drops every _test.go file.
func (self *wideKdfProvider) Extract(salt []byte, ikm []byte) []byte {
	prk, err := hkdf.Extract(sha512.New384, ikm, salt)
	if err != nil {
		panic("mls test: hkdf-sha384 extract: " + err.Error())
	}
	return prk
}

func (self *wideKdfProvider) ExpandWithLabel(secret []byte, label string, context []byte, length int) []byte {
	self.expandedLengths = append(self.expandedLengths, length)
	out, err := hkdf.Expand(sha512.New384, secret, string(mlsKdfLabel(label, context, length)), length)
	if err != nil {
		panic("mls test: hkdf-sha384 expand: " + err.Error())
	}
	return out
}

// TestDeriveJoinerSecretReadsKdfNhFromTheProvider is the input the registered suites cannot
// supply.
//
// KDF.Nh governs three things in this derivation: whether the init secret is the right
// length, whether the commit secret is, and how many bytes the expansion is asked for. A
// literal 32 answers all three correctly for both registered suites and incorrectly for
// every suite whose hash is not sha256, and the failure would arrive as an epoch that looks
// valid on this side and matches nobody.
//
// Both directions are asserted. A provider whose Nh is 48 must accept 48 byte secrets --
// which a hardcoded 32 refuses -- and must refuse 32 byte ones, which a hardcoded 32
// accepts. Either half alone is satisfiable by a different mistake.
func TestDeriveJoinerSecretReadsKdfNhFromTheProvider(t *testing.T) {
	inner := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	if inner.HashSize() == wideKdfHashSize {
		t.Fatalf("the registered suite's KDF.Nh is already %d, so this gate separates nothing", wideKdfHashSize)
	}
	crypto := &wideKdfProvider{CryptoProvider: inner}
	if crypto.HashSize() != wideKdfHashSize {
		t.Fatalf("the wide provider answers KDF.Nh %d, want %d", crypto.HashSize(), wideKdfHashSize)
	}
	groupContext := ksVectorEpoch0GroupContext(t)

	wideInit := bytes.Repeat([]byte{0xa5}, wideKdfHashSize)
	wideCommit := bytes.Repeat([]byte{0x5a}, wideKdfHashSize)
	joiner, err := DeriveJoinerSecret(crypto, wideInit, wideCommit, groupContext)
	if err != nil {
		t.Fatalf("two %d byte secrets over a provider whose KDF.Nh is %d were refused: %v",
			wideKdfHashSize, wideKdfHashSize, err)
	}
	if len(joiner) != wideKdfHashSize {
		t.Errorf("the joiner secret is %d bytes and the provider's KDF.Nh is %d", len(joiner), wideKdfHashSize)
	}
	if !slices.Equal(crypto.expandedLengths, []int{wideKdfHashSize}) {
		t.Errorf("the expansion was asked for %v bytes, want [%d]; the output length is KDF.Nh as much as the refusals are",
			crypto.expandedLengths, wideKdfHashSize)
	}

	// the other half: 32 bytes is the wrong length for THIS provider, and a hardcoded 32
	// is exactly what takes it
	narrowInit := bytes.Repeat([]byte{0xa5}, inner.HashSize())
	narrowCommit := bytes.Repeat([]byte{0x5a}, inner.HashSize())
	for _, testCase := range []struct {
		name   string
		init   []byte
		commit []byte
	}{
		{name: "init secret", init: narrowInit, commit: wideCommit},
		{name: "commit secret", init: wideInit, commit: narrowCommit},
	} {
		secret, err := DeriveJoinerSecret(crypto, testCase.init, testCase.commit, groupContext)
		if !errors.Is(err, ErrSecretLength) {
			t.Errorf("a %d byte %s over a provider whose KDF.Nh is %d gave err = %v, want ErrSecretLength",
				inner.HashSize(), testCase.name, wideKdfHashSize, err)
		}
		if secret != nil {
			t.Errorf("a %d byte %s was refused and %d bytes of secret came back beside the error",
				inner.HashSize(), testCase.name, len(secret))
		}
	}
}

// TestZeroSecretReadsKdfNhFromTheProvider closes, for ZeroSecret, the limit the registry
// note in crypto_test.go records against it.
//
// ZeroSecret's whole contract is KDF.Nh zero bytes, and both registered suites fix Nh at
// 32, so make([]byte, 32) answers correctly for every input already in this tree. The
// perturbation gate cannot separate the two either: the one argument ZeroSecret takes is a
// provider, and the tagging provider passes a length through unchanged, which is exactly
// why that gate routes ZeroSecret to a registry comparison rather than to a moved input. A
// provider whose Nh is not 32 is the input that separates them, and it is the same one
// DeriveJoinerSecret is held to below.
func TestZeroSecretReadsKdfNhFromTheProvider(t *testing.T) {
	inner := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	if inner.HashSize() == wideKdfHashSize {
		t.Fatalf("the registered suite's KDF.Nh is already %d, so this gate separates nothing", wideKdfHashSize)
	}
	zero := ZeroSecret(&wideKdfProvider{CryptoProvider: inner})
	if len(zero) != wideKdfHashSize {
		t.Errorf("ZeroSecret over a provider whose KDF.Nh is %d answered %d bytes", wideKdfHashSize, len(zero))
	}
	if slices.ContainsFunc(zero, func(b byte) bool { return b != 0 }) {
		t.Errorf("ZeroSecret answered %x, which is not the all zero secret", zero)
	}
}

// joinerSecretRecovering calls DeriveJoinerSecret with a panic caught rather than taken.
//
// A refusal that is not a refusal is exactly what the gate below is looking for, and a test
// binary that died on it would report nothing about the assertions after it -- and would
// report a nil pointer dereference raised inside the syntax package, which names neither
// this function nor the argument that was missing.
func joinerSecretRecovering(
	crypto CryptoProvider,
	initSecretPrev []byte,
	commitSecret []byte,
	groupContext *GroupContext,
) (secret []byte, err error, recovered any) {
	defer func() { recovered = recover() }()
	secret, err = DeriveJoinerSecret(crypto, initSecretPrev, commitSecret, groupContext)
	return secret, err, nil
}

// TestDeriveJoinerSecretRefusesANilGroupContext pins the missing argument as a typed error.
//
// syntax.Marshal is handed a non nil interface holding a nil pointer, so MarshalMLS
// dereferences it and the caller gets a runtime panic out of the syntax package. Every
// caller of this derivation takes its context off a struct field, so an unset field is how
// a nil arrives, and the epoch that field belongs to is the thing a reader needs named.
//
// The accepting control runs first, so the refusals below are attributable to the nil
// rather than to something else about the call.
func TestDeriveJoinerSecretRefusesANilGroupContext(t *testing.T) {
	for _, suite := range Suites() {
		crypto := mustProvider(t, suite)
		nh := crypto.HashSize()
		initSecret := bytes.Repeat([]byte{0xa5}, nh)
		commitSecret := bytes.Repeat([]byte{0x5a}, nh)
		if _, err := DeriveJoinerSecret(crypto, initSecret, commitSecret, ksVectorEpoch0GroupContext(t)); err != nil {
			t.Fatalf("suite %#04x: a real group context was refused: %v", uint16(suite), err)
		}
		// the literal and a nil valued variable of the type are the same argument, and
		// the second is how an unset struct field arrives
		var unset *GroupContext
		for _, testCase := range []struct {
			name    string
			context *GroupContext
		}{
			{name: "a nil literal", context: nil},
			{name: "an unset field", context: unset},
		} {
			secret, err, recovered := joinerSecretRecovering(crypto, initSecret, commitSecret, testCase.context)
			if recovered != nil {
				t.Errorf("suite %#04x: %s panicked with %v rather than being refused",
					uint16(suite), testCase.name, recovered)
				continue
			}
			if !errors.Is(err, ErrNilGroupContext) {
				t.Errorf("suite %#04x: %s gave err = %v, want ErrNilGroupContext", uint16(suite), testCase.name, err)
			}
			if secret != nil {
				t.Errorf("suite %#04x: %s was refused and %d bytes of secret came back beside the error",
					uint16(suite), testCase.name, len(secret))
			}
		}
	}
}
