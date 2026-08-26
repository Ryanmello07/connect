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
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
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

// keyScheduleOwnedErrors is registry section 5.6: the ten this plan declares, keyed by the
// name each is declared under so the derivation below can compare the two sets by name.
// ErrPskNonceLength, ErrPskType and ErrDuplicatePsk are deliberately absent — they are
// ValSem401, ValSem402 and ValSem403 and belong to the validation plan's errors.go.
//
// Nothing here is trusted: TestKeyScheduleOwnedErrorsIsEveryDeclarationOfItsFile holds
// this map to what errors_key_schedule.go actually declares, in both directions.
var keyScheduleOwnedErrors = map[string]error{
	"ErrSecretLength":                 ErrSecretLength,
	"ErrExportLength":                 ErrExportLength,
	"ErrGroupContextTrailingBytes":    ErrGroupContextTrailingBytes,
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
// The count assertion pins the registry: section 5.6 names ten, so an eleventh is a change
// to the registry and has to be made deliberately. What stops the list shrinking, and what
// stops it lagging behind the file, is the derivation above rather than this number.
func TestKeyScheduleErrorsAreDistinct(t *testing.T) {
	if len(keyScheduleOwnedErrors) != 10 {
		t.Fatalf("this plan owns %d errors, want the 10 of registry section 5.6", len(keyScheduleOwnedErrors))
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
