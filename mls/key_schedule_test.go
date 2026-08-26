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

// ---------------------------------------------------------------------------
// the epoch key schedule
//
// Nine secrets come out of one epoch_secret. They are all KDF.Nh bytes, they are all
// indistinguishable from random, and the only thing that separates any two of them is the
// string handed to DeriveSecret. So a test that reads a length, a non zero-ness, a
// determinism or a round trip passes for all nine no matter which label produced which,
// and two labels swapped between two fields is a change no such test can see.
//
// What sees it is a known answer nothing in this package computed, which is the corpus the
// sweeps below run over: every epoch of every registered suite, driven through the
// KeySchedule type rather than through the primitives — crypto_labels_test.go already holds
// the primitives to the same file, and a schedule that agreed with the primitives while
// wiring them together wrongly would pass that and fail every peer.
//
// The set of nine is read off EpochSecrets by reflection everywhere below rather than
// written out as a list. A list is the shape this repository has paid for fourteen times:
// the tenth secret, or the field renamed, drops out of the class and every sweep goes on
// reporting the clean run a complete sweep reports.
// ---------------------------------------------------------------------------

// keyScheduleKatEpochs is how many epochs of the published corpus this package's registered
// suites account for, and keyScheduleKatEpochComparisons is how many published answers that
// is: joiner_secret, welcome_secret and the nine derived secrets, per epoch.
//
// Both are asserted rather than assumed, for the reason keyScheduleKatJoinerComparisons is.
// A filter that stopped matching — a suite renumbered, a json field renamed so every string
// decodes empty — turns every sweep below into a loop that runs zero times and reports
// PASS, which is the one outcome a known answer test must not be able to reach.
const (
	keyScheduleKatEpochs           = 10
	keyScheduleKatEpochComparisons = 110
)

// One epoch of the authenticated corpus, with the inputs the KeySchedule constructors take
// already decoded and the previous epoch's init secret already chained in.
//
// The published epoch is carried alongside so a sweep can reach whichever answers it needs
// without re-deriving the chain, and the suite and the position travel with it because a
// failure that cannot say which epoch it came from sends a reader to the wrong file.
type ksVectorEpoch struct {
	suite        CipherSuite
	crypto       CryptoProvider
	at           string
	groupContext *GroupContext
	initPrev     []byte
	commitSecret []byte
	pskSecret    []byte
	published    labelKatEpoch
}

// ksVectorEpochs is every epoch of every suite this package registers, taken from the
// corpus keyScheduleKatVectors has already authenticated against upstream's git object
// store.
//
// Three things here stop the sweeps that read this from passing vacuously, and each is a
// property of the corpus rather than of the code under test:
//
//   - the number of epochs is counted and asserted, and the suites that matched are
//     compared against the registry, so a filter that stopped matching is loud;
//   - the group context is re-encoded and compared against the published bytes before it is
//     handed on, so a codec disagreement is reported as a codec disagreement rather than as
//     a key schedule failure in the wrong file;
//   - each of the two Extract calls in the section 8 chain has its two arguments compared,
//     and an epoch whose arguments happened to be equal is reported. Extract(a, b) and
//     Extract(b, a) agree exactly when a == b, so such an epoch pins nothing about the
//     argument order — which is guardrail 1, and the one mistake in this file that a
//     self consistent implementation reproduces perfectly.
func ksVectorEpochs(t *testing.T) []ksVectorEpoch {
	t.Helper()
	epochs := []ksVectorEpoch{}
	matched := []CipherSuite{}
	for _, vector := range keyScheduleKatVectors(t) {
		suite := CipherSuite(vector.CipherSuite)
		if !IsRegisteredSuite(suite) {
			continue
		}
		matched = append(matched, suite)
		crypto := mustProvider(t, suite)
		previousInit := mustDecodeHex(t, "initial_init_secret", vector.InitialInitSecret)
		for index, published := range vector.Epochs {
			at := fmt.Sprintf(" suite %#04x epoch %d", uint16(suite), index)
			commitSecret := mustDecodeHex(t, "commit_secret"+at, published.CommitSecret)
			pskSecret := mustDecodeHex(t, "psk_secret"+at, published.PskSecret)
			publishedJoiner := mustDecodeHex(t, "joiner_secret"+at, published.JoinerSecret)
			if bytes.Equal(previousInit, commitSecret) {
				t.Errorf("%s: init_secret_[n-1] and commit_secret are the same bytes, so this epoch agrees with a transposed Extract in the joiner step and pins nothing about the argument order",
					at)
			}
			if bytes.Equal(publishedJoiner, pskSecret) {
				t.Errorf("%s: joiner_secret and psk_secret are the same bytes, so this epoch agrees with a transposed Extract in the member step and pins nothing about the argument order",
					at)
			}
			publishedContext := mustDecodeHex(t, "group_context"+at, published.GroupContext)
			groupContext := &GroupContext{}
			if err := syntax.Unmarshal(publishedContext, groupContext); err != nil {
				t.Fatalf("%s: decode the published group context: %v", at, err)
			}
			reEncoded, err := syntax.Marshal(groupContext)
			if err != nil {
				t.Fatalf("%s: re-encode the decoded group context: %v", at, err)
			}
			if !bytes.Equal(reEncoded, publishedContext) {
				t.Fatalf("%s: the group context codec re-encodes to %x and the corpus published %x, so a secret mismatch below would be the codec and not the key schedule",
					at, reEncoded, publishedContext)
			}
			epochs = append(epochs, ksVectorEpoch{
				suite:        suite,
				crypto:       crypto,
				at:           at,
				groupContext: groupContext,
				initPrev:     previousInit,
				commitSecret: commitSecret,
				pskSecret:    pskSecret,
				published:    published,
			})
			previousInit = mustDecodeHex(t, "init_secret"+at, published.InitSecret)
		}
	}
	if len(epochs) != keyScheduleKatEpochs {
		t.Fatalf("the corpus answered for %d epochs, want %d; the loop matched %v",
			len(epochs), keyScheduleKatEpochs, matched)
	}
	if got := slices.Sorted(slices.Values(matched)); !slices.Equal(got, Suites()) {
		t.Fatalf("the corpus answered for %v and this package registers %v", got, Suites())
	}
	return epochs
}

// schedule builds the committer's key schedule for this epoch.
func (self ksVectorEpoch) schedule(t *testing.T) *KeySchedule {
	t.Helper()
	schedule, err := NewKeySchedule(
		self.crypto, self.initPrev, self.commitSecret, self.pskSecret, self.groupContext)
	if err != nil {
		t.Fatalf("%s: NewKeySchedule: %v", self.at, err)
	}
	return schedule
}

// epochSecretsByField reads EpochSecrets field by field off the struct rather than off a
// list written here, so a tenth secret added to the type joins every sweep that calls this
// instead of quietly falling outside all of them.
//
// The type of each field is checked as it is read. reflect.Value.Bytes panics on a field
// that is not a byte slice, and a panic inside a helper is a worse sentence than a name and
// a type, so the refusal is written out.
func epochSecretsByField(t *testing.T, secrets *EpochSecrets) map[string][]byte {
	t.Helper()
	if secrets == nil {
		t.Fatal("Secrets() answered nil, so every sweep over the nine would run over nothing")
	}
	value := reflect.ValueOf(*secrets)
	byteSlice := reflect.TypeOf([]byte(nil))
	fields := map[string][]byte{}
	for i := range value.NumField() {
		name := value.Type().Field(i).Name
		field := value.Field(i)
		if field.Type() != byteSlice {
			t.Fatalf("EpochSecrets.%s is %s rather than []byte, so the sweeps over the derived secrets do not cover it",
				name, field.Type())
		}
		fields[name] = field.Bytes()
	}
	if len(fields) == 0 {
		t.Fatal("EpochSecrets read as no fields at all, so every sweep below runs over nothing")
	}
	return fields
}

// publishedEpochSecret is the corpus answer for one field of EpochSecrets.
//
// The switch is exhaustive over the type rather than over a list, because the caller drives
// it with the field names reflection read: a field added to EpochSecrets with no published
// answer arrives at the default case and is reported as unpinned, which is exactly the
// state a new secret is in until somebody finds the corpus field that answers it.
func publishedEpochSecret(t *testing.T, field string, epoch labelKatEpoch) string {
	t.Helper()
	switch field {
	case "SenderData":
		return epoch.SenderDataSecret
	case "Encryption":
		return epoch.EncryptionSecret
	case "Exporter":
		return epoch.ExporterSecret
	case "External":
		return epoch.ExternalSecret
	case "Confirmation":
		return epoch.ConfirmationKey
	case "Membership":
		return epoch.MembershipKey
	case "ResumptionPsk":
		return epoch.ResumptionPsk
	case "EpochAuthenticator":
		return epoch.EpochAuthenticator
	case "InitSecret":
		return epoch.InitSecret
	default:
		t.Fatalf("EpochSecrets.%s has no published answer in %s, so this package derives a secret nobody else's implementation pins",
			field, keyScheduleKatFile)
		return ""
	}
}

// TestKeyScheduleMatchesTheMlswgKeySchedule is the deliverable of this task: every secret
// RFC 9420 section 8 derives for an epoch, compared against the answer mlswg published for
// that epoch, through the type rather than through the primitives.
//
// This is the only test in this file that can tell the nine apart. Each is 32 pseudorandom
// bytes, so "membership_key holds the value confirm produced" is a state in which every
// length check, every distinctness check, every aliasing check and every round trip in this
// package still passes. Two labels transposed between two fields is a two character edit
// that no peer would ever interoperate with and that nothing else here would notice.
//
// The vacuity controls live in ksVectorEpochs, which authenticates the corpus, counts the
// epochs, compares the matched suites against the registry, re-encodes each group context
// against the published bytes and refuses an epoch whose Extract arguments coincide. What
// is counted here is the answers compared, because a sweep whose inner loop stopped
// producing rows reports the clean run a full one reports.
func TestKeyScheduleMatchesTheMlswgKeySchedule(t *testing.T) {
	compared := 0
	for _, epoch := range ksVectorEpochs(t) {
		schedule := epoch.schedule(t)
		assertLabelKat(t, "joiner_secret"+epoch.at, schedule.JoinerSecret(), epoch.published.JoinerSecret)
		assertLabelKat(t, "welcome_secret"+epoch.at, schedule.WelcomeSecret(), epoch.published.WelcomeSecret)
		compared += 2
		fields := epochSecretsByField(t, schedule.Secrets())
		for _, name := range slices.Sorted(maps.Keys(fields)) {
			assertLabelKat(t, "EpochSecrets."+name+epoch.at,
				fields[name], publishedEpochSecret(t, name, epoch.published))
			compared++
		}
	}
	if compared != keyScheduleKatEpochComparisons {
		t.Fatalf("compared %d published answers, want %d", compared, keyScheduleKatEpochComparisons)
	}
}

// TestKeyScheduleGroupContextBytesAreThePublishedEncoding asserts the schedule expanded over
// the bytes the corpus published, and hands back those same bytes.
//
// Both halves matter and they are different claims. The first is that every key of the
// epoch was derived over the encoding a peer will use. The second is that a caller which
// signs or MACs under GroupContextBytes signs under that same encoding rather than under a
// re-encoding of the struct, which is where a second serialization could drift.
func TestKeyScheduleGroupContextBytesAreThePublishedEncoding(t *testing.T) {
	for _, epoch := range ksVectorEpochs(t) {
		published := mustDecodeHex(t, "group_context"+epoch.at, epoch.published.GroupContext)
		if got := epoch.schedule(t).GroupContextBytes(); !bytes.Equal(got, published) {
			t.Errorf("%s: GroupContextBytes = %x, want %x", epoch.at, got, published)
		}
	}
}

// TestNoTwoEpochSecretsAreEqual sweeps the set reflection read rather than nine hand
// written pair comparisons, which is the difference between a gate and a transcription: a
// tenth secret, or a field renamed, joins this sweep by existing.
//
// A label pasted onto the line below it produces two identical secrets, and every
// individual known answer still passes if both published values came from the same run of a
// reference implementation that made the same mistake. Two derived secrets being equal is
// not a coincidence at 32 bytes; it is a copied label.
func TestNoTwoEpochSecretsAreEqual(t *testing.T) {
	for _, epoch := range ksVectorEpochs(t) {
		fields := epochSecretsByField(t, epoch.schedule(t).Secrets())
		names := slices.Sorted(maps.Keys(fields))
		if len(names) < 2 {
			t.Fatalf("%s: EpochSecrets read as %d fields, so no pair exists to compare", epoch.at, len(names))
		}
		for i, first := range names {
			for _, second := range names[i+1:] {
				if bytes.Equal(fields[first], fields[second]) {
					t.Errorf("%s: EpochSecrets.%s and EpochSecrets.%s are the same %d bytes, which at this length is a copied DeriveSecret label rather than a collision",
						epoch.at, first, second, len(fields[first]))
				}
			}
		}
	}
}

// TestEpochSecretsDoNotAliasEachOther is the storage half of the sweep above: two fields
// that hold the same backing array are equal today and are also a pair where erasing one
// silently erases the other, which is what Zeroize will do to this struct.
//
// Distinct values do not imply distinct storage — a field assigned a subslice of another
// starting at a different offset differs in value and still shares the array — so the
// comparison is on the address of the first element rather than on the bytes.
func TestEpochSecretsDoNotAliasEachOther(t *testing.T) {
	for _, epoch := range ksVectorEpochs(t) {
		fields := epochSecretsByField(t, epoch.schedule(t).Secrets())
		names := slices.Sorted(maps.Keys(fields))
		for i, first := range names {
			if len(fields[first]) == 0 {
				t.Fatalf("%s: EpochSecrets.%s is empty, so it has no storage to compare", epoch.at, first)
			}
			for _, second := range names[i+1:] {
				if &fields[first][0] == &fields[second][0] {
					t.Errorf("%s: EpochSecrets.%s and EpochSecrets.%s start in the same array, so erasing one erases the other",
						epoch.at, first, second)
				}
			}
		}
	}
}

// TestEveryEpochSecretIsKdfNhBytes sweeps the reflected set for the one property a
// truncation breaks and a known answer would report as a value mismatch.
//
// It is separate from the known answer test because it says which mistake was made. A
// secret sliced to the AEAD key length is a well formed key that a peer's AEAD will accept
// the wrong number of bytes of, and "want 32 bytes, got 16" is a sentence a reader can act
// on where "these two hex strings differ" is not.
func TestEveryEpochSecretIsKdfNhBytes(t *testing.T) {
	for _, epoch := range ksVectorEpochs(t) {
		nh := epoch.crypto.HashSize()
		fields := epochSecretsByField(t, epoch.schedule(t).Secrets())
		for _, name := range slices.Sorted(maps.Keys(fields)) {
			if len(fields[name]) != nh {
				t.Errorf("%s: EpochSecrets.%s is %d bytes, want KDF.Nh = %d",
					epoch.at, name, len(fields[name]), nh)
			}
		}
	}
}

// deriveSecretRecordingProvider keeps what every DeriveSecret call was handed and what it
// answered, so a test can read the shape of the derivation off the implementation's own
// behaviour instead of transcribing the nine labels a second time.
//
// A second transcription is what makes a label test vacuous: a test holding its own copy of
// the list agrees with whatever the implementation spells as long as both were edited
// together, which is exactly how a swapped pair survives. What is asserted from these
// records is structure — one parent for all nine, distinct labels, a label that matters —
// and the spelling itself is left to the published corpus.
//
// The secret is cloned because member_secret is erased in place immediately after the
// welcome derivation, so a record holding the caller's slice would read back as zeros. The
// answer is NOT cloned: it is the storage the schedule retains, and comparing the address
// of its first element is how a record is matched to the field it became.
type deriveSecretCall struct {
	secret []byte
	label  string
	answer []byte
}

type deriveSecretRecordingProvider struct {
	CryptoProvider
	calls []deriveSecretCall
}

func (self *deriveSecretRecordingProvider) DeriveSecret(secret []byte, label string) []byte {
	answer := self.CryptoProvider.DeriveSecret(secret, label)
	self.calls = append(self.calls, deriveSecretCall{
		secret: bytes.Clone(secret),
		label:  label,
		answer: answer,
	})
	return answer
}

// TestEveryEpochSecretIsDerivedFromOneParentUnderItsOwnLabel observes the three structural
// claims newKeyScheduleFromParts makes, none of which the published answers separate on
// their own once a value has been pinned.
//
//   - every one of the nine is DeriveSecret of the SAME parent. A secret derived from
//     member_secret, from welcome_secret or from another of the nine is still 32
//     pseudorandom bytes, and the corpus only says what the right answer is, not which
//     parent a wrong one came from.
//   - the nine labels are pairwise distinct. This is the same failure the value sweep
//     catches, read at the input rather than at the output, and it names the label.
//   - the label is what separates them: the same parent under a label differing by one
//     character answers with different bytes.
//
// The parent is checked against an independent statement of epoch_secret rather than merely
// against itself, so "all nine came from one parent" cannot be satisfied by all nine coming
// from the wrong one. That statement is RFC 9420 section 8 written out over the corpus's own
// inputs, and both of its steps are already held to the published answers by
// TestExpandWithLabelMatchesTheKeyScheduleVectors.
func TestEveryEpochSecretIsDerivedFromOneParentUnderItsOwnLabel(t *testing.T) {
	for _, epoch := range ksVectorEpochs(t) {
		recording := &deriveSecretRecordingProvider{CryptoProvider: epoch.crypto}
		schedule, err := NewKeySchedule(
			recording, epoch.initPrev, epoch.commitSecret, epoch.pskSecret, epoch.groupContext)
		if err != nil {
			t.Fatalf("%s: NewKeySchedule: %v", epoch.at, err)
		}
		fields := epochSecretsByField(t, schedule.Secrets())

		// the independent parent: Extract(joiner_secret, psk_secret) expanded under
		// "epoch" over the group context, per RFC 9420 section 8
		wantParent := epoch.crypto.ExpandWithLabel(
			epoch.crypto.Extract(
				mustDecodeHex(t, "joiner_secret"+epoch.at, epoch.published.JoinerSecret), epoch.pskSecret),
			"epoch", mustDecodeHex(t, "group_context"+epoch.at, epoch.published.GroupContext),
			epoch.crypto.HashSize())

		labels := map[string]string{}
		for _, name := range slices.Sorted(maps.Keys(fields)) {
			secret := fields[name]
			if len(secret) == 0 {
				t.Fatalf("%s: EpochSecrets.%s is empty, so no record can be matched to it", epoch.at, name)
			}
			matches := []deriveSecretCall{}
			for _, call := range recording.calls {
				if len(call.answer) > 0 && &call.answer[0] == &secret[0] {
					matches = append(matches, call)
				}
			}
			if len(matches) != 1 {
				t.Fatalf("%s: EpochSecrets.%s is the answer of %d recorded DeriveSecret calls, want 1; it is either not a DeriveSecret answer at all or it was copied out of one",
					epoch.at, name, len(matches))
			}
			if !bytes.Equal(matches[0].secret, wantParent) {
				t.Errorf("%s: EpochSecrets.%s was derived from %x and epoch_secret is %x, so it hangs off the wrong parent",
					epoch.at, name, matches[0].secret, wantParent)
			}
			if owner, taken := labels[matches[0].label]; taken {
				t.Errorf("%s: EpochSecrets.%s and EpochSecrets.%s were both derived under %q, so one label was pasted over the other",
					epoch.at, name, owner, matches[0].label)
			}
			labels[matches[0].label] = name

			// and the label is load bearing: one character of it changes the answer
			if altered := epoch.crypto.DeriveSecret(wantParent, matches[0].label+"x"); bytes.Equal(altered, secret) {
				t.Errorf("%s: EpochSecrets.%s is unchanged by altering only its DeriveSecret label, so the label is not what separates it from the other eight",
					epoch.at, name)
			}
		}
		if len(labels) != len(fields) {
			t.Errorf("%s: %d distinct labels produced %d secrets", epoch.at, len(labels), len(fields))
		}
		// the welcome derivation is the tenth recorded call and hangs off member_secret,
		// so a count of exactly ten says nothing else reached for the parent behind the
		// package's back
		if len(recording.calls) != len(fields)+1 {
			t.Errorf("%s: %d DeriveSecret calls, want %d: the nine and welcome_secret",
				epoch.at, len(recording.calls), len(fields)+1)
		}
		if _, welcomeIsAnEpochSecret := labels["welcome"]; welcomeIsAnEpochSecret {
			t.Errorf("%s: an epoch secret was derived under the welcome label", epoch.at)
		}
	}
}

// keyScheduleMethodsTakingArguments names an exported method of *KeySchedule the epoch
// secret sweep below cannot call, with the reason. It is empty at this task: all four
// accessors take the receiver and nothing else.
//
// It exists so that a later task adding an argument taking method — Export and the two tag
// verifiers are in this plan — has to write down why that method cannot be swept, rather
// than have it silently fall outside a gate whose whole subject is what this type is
// allowed to hand out. The map is checked against the type, so an entry cannot outlive the
// method it excuses.
var keyScheduleMethodsTakingArguments = map[string]string{}

// exposedByteSlices flattens everything one call handed back into the byte slices a caller
// can read. A []byte result is one; a pointer to a struct is each of its exported byte
// slice fields, which is the shape Secrets() has.
func exposedByteSlices(t *testing.T, what string, result reflect.Value) [][]byte {
	t.Helper()
	byteSlice := reflect.TypeOf([]byte(nil))
	if result.Type() == byteSlice {
		return [][]byte{result.Bytes()}
	}
	if result.Kind() == reflect.Pointer && result.Type().Elem().Kind() == reflect.Struct {
		if result.IsNil() {
			return nil
		}
		exposed := [][]byte{}
		element := result.Elem()
		for i := range element.NumField() {
			if !element.Type().Field(i).IsExported() {
				continue
			}
			exposed = append(exposed,
				exposedByteSlices(t, what+"."+element.Type().Field(i).Name, element.Field(i))...)
		}
		return exposed
	}
	t.Fatalf("%s answers a %s, which this sweep cannot read for bytes; extend it rather than letting a new result shape fall outside guardrail 6",
		what, result.Type())
	return nil
}

// TestNoExportedSurfaceOfTheKeyScheduleReturnsTheEpochSecret is guardrail G6 read as
// behaviour rather than as a convention.
//
// epoch_secret is the parent of all nine. A caller holding it holds confirmation_key and
// membership_key — the two secrets that authenticate a commit — and every other secret the
// epoch will ever produce, so an accessor returning it is a one line change that gives the
// epoch away while every other test in this file goes on passing. It is also the natural
// thing to add: a constructor wants to return it and a test helper wants to accept it, which
// is why this is written down at the task that first derives it rather than left to the one
// that names the guardrail.
//
// The class is the type's own exported surface read by reflection, not a list of accessors
// written here, so a method added later joins the sweep by existing. What each answer is
// compared against is an independent statement of epoch_secret over the corpus's own inputs,
// and the sweep asserts it found the secrets it should find before concluding it did not
// find the one it should not: a flattener that read nothing reports the same clean run as
// one that read everything.
func TestNoExportedSurfaceOfTheKeyScheduleReturnsTheEpochSecret(t *testing.T) {
	for _, epoch := range ksVectorEpochs(t) {
		schedule := epoch.schedule(t)
		epochSecret := epoch.crypto.ExpandWithLabel(
			epoch.crypto.Extract(
				mustDecodeHex(t, "joiner_secret"+epoch.at, epoch.published.JoinerSecret), epoch.pskSecret),
			"epoch", mustDecodeHex(t, "group_context"+epoch.at, epoch.published.GroupContext),
			epoch.crypto.HashSize())

		scheduleType := reflect.TypeOf(schedule)
		valueType := scheduleType.Elem()
		for i := range valueType.NumField() {
			if valueType.Field(i).IsExported() {
				t.Fatalf("%s: KeySchedule has exported field %s, so its storage is reachable without going through a method this sweep reads",
					epoch.at, valueType.Field(i).Name)
			}
		}

		exposed := [][]byte{}
		swept := []string{}
		for i := range scheduleType.NumMethod() {
			method := scheduleType.Method(i)
			if method.Type.NumIn() != 1 {
				if reason, excused := keyScheduleMethodsTakingArguments[method.Name]; !excused {
					t.Fatalf("%s: (*KeySchedule).%s takes arguments and this sweep calls with none; give it arguments here or write down in keyScheduleMethodsTakingArguments why it cannot surface epoch_secret",
						epoch.at, method.Name)
				} else {
					t.Logf("%s: (*KeySchedule).%s not swept: %s", epoch.at, method.Name, reason)
				}
				continue
			}
			swept = append(swept, method.Name)
			for _, result := range method.Func.Call([]reflect.Value{reflect.ValueOf(schedule)}) {
				exposed = append(exposed,
					exposedByteSlices(t, "(*KeySchedule)."+method.Name, result)...)
			}
		}
		for name := range keyScheduleMethodsTakingArguments {
			if _, found := scheduleType.MethodByName(name); !found {
				t.Errorf("keyScheduleMethodsTakingArguments excuses %s, which *KeySchedule does not declare", name)
			}
		}

		// the controls: the sweep reached the surface, and the flattener really does
		// return the bytes behind it. Without these an accessor that answered nothing,
		// or a flattener that dropped every struct field, reports the same clean run.
		if len(swept) < 4 {
			t.Fatalf("%s: swept %d exported methods of *KeySchedule (%v), and the type declares four accessors at least",
				epoch.at, len(swept), swept)
		}
		fields := epochSecretsByField(t, schedule.Secrets())
		if len(exposed) < len(fields)+2 {
			t.Fatalf("%s: the sweep read %d byte slices off the exported surface and Secrets() alone carries %d, so it is not reading what it claims to",
				epoch.at, len(exposed), len(fields))
		}
		for _, known := range [][]byte{schedule.JoinerSecret(), schedule.Secrets().InitSecret} {
			if !slices.ContainsFunc(exposed, func(b []byte) bool { return bytes.Equal(b, known) }) {
				t.Fatalf("%s: the sweep did not find a secret the type certainly exposes, so a secret it must not expose would be missed too",
					epoch.at)
			}
		}

		for index, secret := range exposed {
			if bytes.Equal(secret, epochSecret) {
				t.Errorf("%s: the exported surface hands out epoch_secret at position %d of %d; it is the parent of every secret of this epoch and G6 says no exported symbol returns it",
					epoch.at, index, len(exposed))
			}
		}
	}
}

// TestNewKeyScheduleErasesTheMemberSecret observes the sentence key_schedule.go writes above
// NewKeyScheduleFromJoiner: member_secret is erased once it has produced the two things it
// feeds.
//
// member_secret is not one of the epoch's secrets and nothing downstream reads it, and it
// reproduces welcome_secret and epoch_secret — which is to say all nine — from one
// HKDF-Expand each. Deleting the zeroizeSecret call changes no answer this package
// computes, so nothing but a read of that storage sees it.
//
// The control is the same one TestDeriveJoinerSecretErasesThePseudorandomKey carries: an all
// zero reading only means something if the key was not already zero, and a returned secret
// that came back zero would satisfy the loop for the wrong reason.
func TestNewKeyScheduleErasesTheMemberSecret(t *testing.T) {
	for _, epoch := range ksVectorEpochs(t) {
		joinerSecret := mustDecodeHex(t, "joiner_secret"+epoch.at, epoch.published.JoinerSecret)

		fresh := epoch.crypto.Extract(joinerSecret, epoch.pskSecret)
		if !slices.ContainsFunc(fresh, func(b byte) bool { return b != 0 }) {
			t.Fatalf("%s: Extract over these inputs is already %d zero bytes, so an all zero reading below would say nothing",
				epoch.at, len(fresh))
		}

		crypto := &extractCapturingProvider{CryptoProvider: epoch.crypto}
		schedule, err := NewKeyScheduleFromJoiner(crypto, joinerSecret, epoch.pskSecret, epoch.groupContext)
		if err != nil {
			t.Fatalf("%s: NewKeyScheduleFromJoiner: %v", epoch.at, err)
		}
		if len(crypto.extracted) != 1 {
			t.Fatalf("%s: Extract was called %d times, want 1; this gate reads the key that one call returned",
				epoch.at, len(crypto.extracted))
		}
		member := crypto.extracted[0]
		for i, b := range member {
			if b != 0 {
				t.Errorf("%s: byte %d of member_secret is %#02x after the call, want 0; it reproduces every secret of the epoch",
					epoch.at, i, b)
				break
			}
		}
		// and the erase reached member_secret rather than what it produced
		if !slices.ContainsFunc(schedule.WelcomeSecret(), func(b byte) bool { return b != 0 }) {
			t.Errorf("%s: welcome_secret came back as %d zero bytes, so the erase reached the values that were kept",
				epoch.at, len(schedule.WelcomeSecret()))
		}
	}
}

// expandCapturingProvider keeps every ExpandWithLabel answer, for the same reason and with
// the same no-copy discipline extractCapturingProvider has: what is read afterwards is the
// storage the production code held, not a clone of it.
type expandCapturingProvider struct {
	CryptoProvider
	expanded [][]byte
}

func (self *expandCapturingProvider) ExpandWithLabel(
	secret []byte, label string, context []byte, length int,
) []byte {
	answer := self.CryptoProvider.ExpandWithLabel(secret, label, context, length)
	self.expanded = append(self.expanded, answer)
	return answer
}

// TestNewKeyScheduleErasesTheJoinerSecretItDerived observes both outcomes of the one
// derivation NewKeySchedule makes on its own account.
//
// On the refusal the joiner secret reached no caller: it is derived before psk_secret is
// looked at, so a psk of the wrong length leaves a live secret behind. On success the
// schedule holds a copy of its own, so the storage this one was computed into is again a
// live secret nothing will ever come back for. Returning without erasing it is the shape
// a reader would not think twice about, and it changes no answer this package computes:
// joiner_secret is one Extract and one Expand from the whole epoch, and a Welcome is
// sealed under what it produces.
//
// The success half also reads the schedule's own joiner secret back, because an erase
// aimed one line wrong would clear that instead and the epoch would go on looking fine
// until a Welcome sealed under zeros.
func TestNewKeyScheduleErasesTheJoinerSecretItDerived(t *testing.T) {
	for _, epoch := range ksVectorEpochs(t) {
		for _, testCase := range []struct {
			what      string
			pskSecret []byte
			refused   bool
		}{
			{what: "refused for a short psk secret", pskSecret: epoch.pskSecret[:len(epoch.pskSecret)-1], refused: true},
			{what: "accepted", pskSecret: epoch.pskSecret},
		} {
			at := epoch.at + " " + testCase.what
			crypto := &expandCapturingProvider{CryptoProvider: epoch.crypto}
			schedule, err := NewKeySchedule(
				crypto, epoch.initPrev, epoch.commitSecret, testCase.pskSecret, epoch.groupContext)
			if testCase.refused {
				if !errors.Is(err, ErrSecretLength) {
					t.Fatalf("%s: err = %v, want ErrSecretLength", at, err)
				}
				if schedule != nil {
					t.Errorf("%s: a schedule came back beside the refusal", at)
				}
			} else if err != nil {
				t.Fatalf("%s: NewKeySchedule: %v", at, err)
			}
			// the joiner expansion is the first, whether or not the epoch expansion follows
			if len(crypto.expanded) == 0 {
				t.Fatalf("%s: ExpandWithLabel was never called, so this row read no joiner secret", at)
			}
			derived := crypto.expanded[0]
			if len(derived) != epoch.crypto.HashSize() {
				t.Fatalf("%s: the captured expansion is %d bytes, want KDF.Nh = %d",
					at, len(derived), epoch.crypto.HashSize())
			}
			for i, b := range derived {
				if b != 0 {
					t.Errorf("%s: byte %d of the derived joiner secret is %#02x afterwards, want 0; nothing will ever come back for that storage",
						at, i, b)
					break
				}
			}
			// and on the accepted path the erase reached that storage rather than the copy
			// the epoch keeps, which is the value a Welcome is sealed under
			if schedule != nil {
				assertLabelKat(t, "joiner_secret"+at, schedule.JoinerSecret(), epoch.published.JoinerSecret)
			}
		}
	}
}

// TestKeyScheduleConstructorsRefuseSecretsThatAreNotKdfNh sweeps every wrong length of every
// secret argument of every constructor, rather than the one short case.
//
// HKDF-Extract accepts any length of either argument and answers with a well formed
// pseudorandom key, so none of these is refused by the arithmetic. A secret one byte short,
// one byte long, empty or absent all produce an epoch that is internally consistent and
// that no peer agrees with, which surfaces as an undecryptable message rather than as the
// length mistake it is.
func TestKeyScheduleConstructorsRefuseSecretsThatAreNotKdfNh(t *testing.T) {
	for _, epoch := range ksVectorEpochs(t) {
		nh := epoch.crypto.HashSize()
		joinerSecret := mustDecodeHex(t, "joiner_secret"+epoch.at, epoch.published.JoinerSecret)
		wrongLengths := map[string][]byte{
			"one byte short": bytes.Repeat([]byte{0x11}, nh-1),
			"one byte long":  bytes.Repeat([]byte{0x11}, nh+1),
			"empty":          {},
			"nil":            nil,
		}
		for _, name := range slices.Sorted(maps.Keys(wrongLengths)) {
			wrong := wrongLengths[name]
			for _, testCase := range []struct {
				what string
				call func() (*KeySchedule, error)
			}{
				{what: "NewKeySchedule init_secret", call: func() (*KeySchedule, error) {
					return NewKeySchedule(epoch.crypto, wrong, epoch.commitSecret, epoch.pskSecret, epoch.groupContext)
				}},
				{what: "NewKeySchedule commit_secret", call: func() (*KeySchedule, error) {
					return NewKeySchedule(epoch.crypto, epoch.initPrev, wrong, epoch.pskSecret, epoch.groupContext)
				}},
				{what: "NewKeySchedule psk_secret", call: func() (*KeySchedule, error) {
					return NewKeySchedule(epoch.crypto, epoch.initPrev, epoch.commitSecret, wrong, epoch.groupContext)
				}},
				{what: "NewKeyScheduleFromJoiner joiner_secret", call: func() (*KeySchedule, error) {
					return NewKeyScheduleFromJoiner(epoch.crypto, wrong, epoch.pskSecret, epoch.groupContext)
				}},
				{what: "NewKeyScheduleFromJoiner psk_secret", call: func() (*KeySchedule, error) {
					return NewKeyScheduleFromJoiner(epoch.crypto, joinerSecret, wrong, epoch.groupContext)
				}},
				{what: "NewKeyScheduleFromEpochSecret epoch_secret", call: func() (*KeySchedule, error) {
					return NewKeyScheduleFromEpochSecret(epoch.crypto, wrong, epoch.groupContext)
				}},
			} {
				schedule, err := testCase.call()
				if !errors.Is(err, ErrSecretLength) {
					t.Errorf("%s: %s %s gave err = %v, want ErrSecretLength",
						epoch.at, testCase.what, name, err)
				}
				if schedule != nil {
					t.Errorf("%s: %s %s was refused and a schedule came back beside the error",
						epoch.at, testCase.what, name)
				}
			}
		}
	}
}

// keyScheduleConstructorsOverAGroupContext is every exported package level function that
// takes a *GroupContext, read off this package's own source rather than listed.
//
// A list would be the fourteenth understatement in this repository. Every one of these
// serializes the context it is handed, syntax.Marshal receives a non nil interface holding a
// nil pointer, and MarshalMLS dereferences it — so the missing one is not a function without
// the guard, it is a function whose caller gets a panic out of the syntax package naming
// neither the function nor the argument that was absent. Every one of them takes its context
// off a struct field, which is exactly where an unset one comes from.
func keyScheduleConstructorsOverAGroupContext(t *testing.T) []string {
	t.Helper()
	exported := []string{}
	for _, name := range packageLevelFunctionsTaking(t, "*GroupContext") {
		if ast.IsExported(name) {
			exported = append(exported, name)
		}
	}
	if len(exported) == 0 {
		t.Fatal("no exported package level function of this package takes a *GroupContext, so the gate below demands nothing")
	}
	return exported
}

// TestEveryConstructorOverAGroupContextRefusesANilOne holds the class the scan above found,
// so a fourth constructor added to this file is refused entry until it is covered here.
func TestEveryConstructorOverAGroupContextRefusesANilOne(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	nh := crypto.HashSize()
	secret := bytes.Repeat([]byte{0x5c}, nh)
	// a nil literal and a nil valued variable of the type are the same argument, and the
	// second is how an unset struct field arrives
	var unset *GroupContext
	covered := map[string]func(context *GroupContext) error{
		"DeriveJoinerSecret": func(context *GroupContext) error {
			_, err := DeriveJoinerSecret(crypto, secret, secret, context)
			return err
		},
		"NewKeySchedule": func(context *GroupContext) error {
			_, err := NewKeySchedule(crypto, secret, secret, secret, context)
			return err
		},
		"NewKeyScheduleFromJoiner": func(context *GroupContext) error {
			_, err := NewKeyScheduleFromJoiner(crypto, secret, secret, context)
			return err
		},
		"NewKeyScheduleFromEpochSecret": func(context *GroupContext) error {
			_, err := NewKeyScheduleFromEpochSecret(crypto, secret, context)
			return err
		},
	}
	found := keyScheduleConstructorsOverAGroupContext(t)
	if got := slices.Sorted(maps.Keys(covered)); !slices.Equal(got, slices.Sorted(slices.Values(found))) {
		t.Fatalf("this gate covers %v and the package's source declares %v as exported functions over a *GroupContext",
			got, found)
	}
	for _, name := range slices.Sorted(maps.Keys(covered)) {
		// the control: a real context is accepted, so a refusal below is the nil and not
		// the other arguments
		if err := covered[name](ksVectorEpoch0GroupContext(t)); err != nil {
			t.Fatalf("%s: a real group context was refused: %v", name, err)
		}
		for _, testCase := range []struct {
			what    string
			context *GroupContext
		}{
			{what: "a nil literal", context: nil},
			{what: "an unset field", context: unset},
		} {
			var err error
			recovered := recoveredPanic(func() { err = covered[name](testCase.context) })
			if recovered != nil {
				t.Errorf("%s: %s panicked with %v rather than being refused", name, testCase.what, recovered)
				continue
			}
			if !errors.Is(err, ErrNilGroupContext) {
				t.Errorf("%s: %s gave err = %v, want ErrNilGroupContext", name, testCase.what, err)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// the group creation entry point
// ---------------------------------------------------------------------------

// TestNewKeyScheduleFromEpochSecretDerivesTheSameNineSecrets asserts the creation path
// reaches the same nine secrets as the commit path, given the epoch_secret the commit path
// computed. Anything else means a group's creator and its first joiner are in different
// epochs from the first message.
//
// The epoch secret is recomputed here from the corpus's own inputs rather than taken off the
// schedule, because the type deliberately never exports it — see
// TestNoExportedSurfaceOfTheKeyScheduleReturnsTheEpochSecret. Widening a signature to make
// this test easier is the thing G6 is about, so the test is written against what the type is
// allowed to expose.
//
// The set compared is the one reflection read, so the two paths are held to agreeing on
// every field EpochSecrets has rather than on the nine that were current when this was
// written.
func TestNewKeyScheduleFromEpochSecretDerivesTheSameNineSecrets(t *testing.T) {
	for _, epoch := range ksVectorEpochs(t) {
		epochSecret := epoch.crypto.ExpandWithLabel(
			epoch.crypto.Extract(
				mustDecodeHex(t, "joiner_secret"+epoch.at, epoch.published.JoinerSecret), epoch.pskSecret),
			"epoch", mustDecodeHex(t, "group_context"+epoch.at, epoch.published.GroupContext),
			epoch.crypto.HashSize())

		fromEpoch, err := NewKeyScheduleFromEpochSecret(epoch.crypto, epochSecret, epoch.groupContext)
		if err != nil {
			t.Fatalf("%s: NewKeyScheduleFromEpochSecret: %v", epoch.at, err)
		}
		fromCommit := epochSecretsByField(t, epoch.schedule(t).Secrets())
		created := epochSecretsByField(t, fromEpoch.Secrets())
		if got, want := slices.Sorted(maps.Keys(created)), slices.Sorted(maps.Keys(fromCommit)); !slices.Equal(got, want) {
			t.Fatalf("%s: the creation path answers with fields %v and the commit path with %v", epoch.at, got, want)
		}
		for _, name := range slices.Sorted(maps.Keys(fromCommit)) {
			if !bytes.Equal(fromCommit[name], created[name]) {
				t.Errorf("%s: EpochSecrets.%s is %x from the commit path and %x from the creation path",
					epoch.at, name, fromCommit[name], created[name])
			}
		}
		if !bytes.Equal(fromEpoch.GroupContextBytes(), mustDecodeHex(t, "group_context"+epoch.at, epoch.published.GroupContext)) {
			t.Errorf("%s: the creation path expanded over %x", epoch.at, fromEpoch.GroupContextBytes())
		}
	}
}

// TestNewKeyScheduleFromEpochSecretHasNoJoinerOrWelcomeSecret asserts the two secrets that
// are undefined on this path read as nil.
//
// A group created from a sampled epoch_secret was never joined, so there is no joiner_secret
// and no welcome_secret to be had. Substituting KDF.Nh zero bytes for either would keep the
// signatures the registry fixes and would seal a Welcome under a run of zeros — a key an
// attacker also has — while every length check in this package passed. Nil is what makes the
// caller's mistake a refusal at the first length check downstream.
func TestNewKeyScheduleFromEpochSecretHasNoJoinerOrWelcomeSecret(t *testing.T) {
	for _, suite := range Suites() {
		crypto := mustProvider(t, suite)
		at := fmt.Sprintf("suite %#04x", uint16(suite))
		schedule, err := NewKeyScheduleFromEpochSecret(
			crypto, crypto.Random(crypto.HashSize()), ksVectorEpoch0GroupContext(t))
		if err != nil {
			t.Fatalf("%s: NewKeyScheduleFromEpochSecret: %v", at, err)
		}
		if schedule.JoinerSecret() != nil {
			t.Errorf("%s: JoinerSecret = %x, want nil on the creation path", at, schedule.JoinerSecret())
		}
		if schedule.WelcomeSecret() != nil {
			t.Errorf("%s: WelcomeSecret = %x, want nil on the creation path", at, schedule.WelcomeSecret())
		}
		// and the nine are there, so the nils above are the two that are undefined rather
		// than a schedule that derived nothing at all
		for _, name := range slices.Sorted(maps.Keys(epochSecretsByField(t, schedule.Secrets()))) {
			if got := epochSecretsByField(t, schedule.Secrets())[name]; len(got) != crypto.HashSize() {
				t.Errorf("%s: EpochSecrets.%s is %d bytes on the creation path, want KDF.Nh = %d",
					at, name, len(got), crypto.HashSize())
			}
		}
	}
}

// TestNewKeyScheduleFromEpochSecretCopiesTheSample observes the sentence
// NewKeyScheduleFromEpochSecret writes: the sample is copied rather than retained.
//
// Retaining it would make the epoch's whole key schedule a window onto a buffer the caller
// still owns, and the caller of this is a NewGroup that just sampled KDF.Nh bytes and is
// about to erase them — which would erase the parent of the live epoch instead.
func TestNewKeyScheduleFromEpochSecretCopiesTheSample(t *testing.T) {
	for _, suite := range Suites() {
		crypto := mustProvider(t, suite)
		at := fmt.Sprintf("suite %#04x", uint16(suite))
		sample := crypto.Random(crypto.HashSize())
		schedule, err := NewKeyScheduleFromEpochSecret(crypto, sample, ksVectorEpoch0GroupContext(t))
		if err != nil {
			t.Fatalf("%s: NewKeyScheduleFromEpochSecret: %v", at, err)
		}
		kept := map[string][]byte{}
		for name, secret := range epochSecretsByField(t, schedule.Secrets()) {
			kept[name] = bytes.Clone(secret)
		}
		// the caller does what a NewGroup does with a sample it has finished handing over
		zeroizeSecret(sample)
		after := epochSecretsByField(t, schedule.Secrets())
		for _, name := range slices.Sorted(maps.Keys(kept)) {
			if !bytes.Equal(after[name], kept[name]) {
				t.Errorf("%s: erasing the caller's sample changed EpochSecrets.%s, so the epoch is a window onto storage the caller owns",
					at, name)
			}
		}
		// and the control: the sample was read at all. a schedule built over the erased
		// buffer must differ, or the comparison above holds for a constructor that never
		// looked at its argument.
		second, err := NewKeyScheduleFromEpochSecret(crypto, sample, ksVectorEpoch0GroupContext(t))
		if err != nil {
			t.Fatalf("%s: NewKeyScheduleFromEpochSecret over the erased sample: %v", at, err)
		}
		if bytes.Equal(second.Secrets().InitSecret, kept["InitSecret"]) {
			t.Errorf("%s: a schedule over KDF.Nh zero bytes derived the same init_secret as one over the sample, so the sample was never read",
				at)
		}
	}
}
