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
	"crypto/subtle"
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
	"strconv"
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

// noInlineDirective is the compiler directive, matched as a whole line. secret_zeroize.go
// argues from the directive by name twice in prose, so a substring search over the file is
// answered by the argument for the directive rather than by the directive, and deleting
// the line leaves both mentions behind. That is why this is compared against a comment of
// the syntax tree, and against the whole of it.
const noInlineDirective = "//go:noinline"

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

// mustParseCommented is the shared parse with the doc comments kept.
//
// mustParseSource drops them, because every other gate in this package reads statements
// and types rather than prose. The matcher below reads a compiler directive, which lives
// in a doc comment and nowhere else, and over a tree parsed without comments it would
// answer "absent" for every function in the package -- a gate that reports the whole
// source in violation rather than one that reads it. Its own control is what says the
// difference is being seen.
func mustParseCommented(t *testing.T, name string, source string) parsedSource {
	t.Helper()
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, name, source, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return parsedSource{fileSet: fileSet, file: file}
}

// mustReadCommented is the same over one file of this package's source on disk.
func mustReadCommented(t *testing.T, path string) parsedSource {
	t.Helper()
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return mustParseCommented(t, path, string(source))
}

// rootIdentifierOf reduces the target of a write to the name whose storage is written
// through, so secret[i], secret[1:][i], (secret)[i] and self.secrets.InitSecret[i] all report
// the name they hang off.
//
// Without it a write spelled through a reslice, or through a field of the receiver, sits
// outside the matcher below while landing on exactly the same bytes -- and those are the two
// shapes an erase helper actually takes: a free one is handed the slice, and a method erases
// what its own receiver holds.
func rootIdentifierOf(expr ast.Expr) string {
	switch typed := expr.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.ParenExpr:
		return rootIdentifierOf(typed.X)
	case *ast.IndexExpr:
		return rootIdentifierOf(typed.X)
	case *ast.SliceExpr:
		return rootIdentifierOf(typed.X)
	case *ast.SelectorExpr:
		return rootIdentifierOf(typed.X)
	}
	return ""
}

// storageOutlivingTheCall names the receiver and parameters of one declaration through which
// a write reaches bytes that are still there when the call returns.
//
// Two sources. A parameter whose type is a []byte, or one of this package's own names for a
// []byte -- the named types are read rather than the spelling alone, because HpkePrivateKey
// is the same array to the compiler and an eraser written over one is the same eraser. And
// the receiver, whatever its type, because a method that erases what its own object holds is
// the other shape an erase helper takes -- the (*KeySchedule).Zeroize this plan's task 12
// adds is exactly it, and a class that stopped at parameters would let it land undirected.
func storageOutlivingTheCall(parsed parsedSource, function *ast.FuncDecl, named []string) []string {
	handed := []string{}
	if function.Recv != nil {
		for _, field := range function.Recv.List {
			for _, name := range field.Names {
				if name.Name != "_" {
					handed = append(handed, name.Name)
				}
			}
		}
	}
	if function.Type.Params == nil {
		return handed
	}
	for _, field := range function.Type.Params.List {
		rendered := parsed.render(field.Type)
		if rendered != "[]byte" && !slices.Contains(named, rendered) {
			continue
		}
		for _, name := range field.Names {
			if name.Name != "_" {
				handed = append(handed, name.Name)
			}
		}
	}
	return handed
}

// namesReachingTheSameStorage extends a set of names by the locals cut from them, to a
// fixed point.
//
// A local assigned from a parameter, or from a reslice of one, is the caller's array under
// another name, and an erase written through it is the same erase. One hop is the shape
// that actually gets written -- window := secret[n:] -- and the fixed point follows a chain
// of them. A local built by make or by bytes.Clone roots at a call rather than at a name and
// is correctly not added: that is storage of the function's own.
func namesReachingTheSameStorage(function *ast.FuncDecl, handed []string) []string {
	reaching := map[string]bool{}
	for _, name := range handed {
		reaching[name] = true
	}
	for {
		grew := false
		ast.Inspect(function, func(node ast.Node) bool {
			assignment, isAssignment := node.(*ast.AssignStmt)
			if !isAssignment || len(assignment.Lhs) != len(assignment.Rhs) {
				return true
			}
			for i, right := range assignment.Rhs {
				root := rootIdentifierOf(right)
				if root == "" || !reaching[root] {
					continue
				}
				target, isBare := assignment.Lhs[i].(*ast.Ident)
				if !isBare || target.Name == "_" || reaching[target.Name] {
					continue
				}
				reaching[target.Name] = true
				grew = true
			}
			return true
		})
		if !grew {
			return slices.Sorted(maps.Keys(reaching))
		}
	}
}

// namesWrittenThrough is the subset of those a body writes INTO rather than reads,
// reslices or passes on.
//
// Three spellings reach somebody else's array: an index assignment or an increment of one,
// the clear builtin, and copy with the name as its destination. Rebinding the header --
// secret = something -- is deliberately not one of them: it moves the local name and leaves
// the caller's bytes exactly as they were.
func namesWrittenThrough(function *ast.FuncDecl, reaching []string) []string {
	written := map[string]bool{}
	mark := func(target ast.Expr) {
		if root := rootIdentifierOf(target); root != "" && slices.Contains(reaching, root) {
			written[root] = true
		}
	}
	ast.Inspect(function, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.AssignStmt:
			for _, target := range typed.Lhs {
				if _, isIndex := target.(*ast.IndexExpr); isIndex {
					mark(target)
				}
			}
		case *ast.IncDecStmt:
			if _, isIndex := typed.X.(*ast.IndexExpr); isIndex {
				mark(typed.X)
			}
		case *ast.CallExpr:
			builtin, isName := typed.Fun.(*ast.Ident)
			if isName && len(typed.Args) != 0 && (builtin.Name == "clear" || builtin.Name == "copy") {
				mark(typed.Args[0])
			}
		}
		return true
	})
	return slices.Sorted(maps.Keys(written))
}

// eraseHelpersIn names the functions one parsed file declares that write through storage
// outliving the call, and which of those do not carry the directive.
func eraseHelpersIn(parsed parsedSource, named []string) ([]string, []string) {
	helpers := []string{}
	missing := []string{}
	for _, declaration := range parsed.file.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if !isFunction || function.Body == nil {
			continue
		}
		handed := storageOutlivingTheCall(parsed, function, named)
		if len(handed) == 0 {
			continue
		}
		if len(namesWrittenThrough(function, namesReachingTheSameStorage(function, handed))) == 0 {
			continue
		}
		helpers = append(helpers, function.Name.Name)
		if !carriesTheNoInlineDirective(function.Doc) {
			missing = append(missing, function.Name.Name)
		}
	}
	return helpers, missing
}

// eraseHelperControl holds one of each shape the matchers have to tell apart: the four
// spellings that reach a caller's array, the same write made through a field of the receiver,
// a write into storage the function made for itself, a read of a parameter, a read of the
// receiver, a rebinding of a parameter, a function handed no bytes at all, the directive
// present, and the directive named only in prose.
//
// Without it a matcher that had stopped matching -- a parse that dropped comments, a walk
// that stopped descending into bodies, a type filter that stopped seeing named storage --
// would report the real source clean and pass, which is the one outcome a gate must never
// be able to reach by accident.
const eraseHelperControl = "package control\n" +
	"\n" +
	"type ControlKey []byte\n" +
	"\n" +
	"// erasedWithTheDirective is what this gate wants: a write through a parameter, with\n" +
	"// the directive on a line of its own.\n" +
	"//\n" +
	"//go:noinline\n" +
	"func erasedWithTheDirective(secret []byte) {\n" +
	"\tfor i := range secret {\n" +
	"\t\tsecret[i] = 0\n" +
	"\t}\n" +
	"}\n" +
	"\n" +
	"// erasedWithOnlyProse argues from the noinline directive and does not carry it. This\n" +
	"// is the shape a search for the text noinline cannot tell from the one above.\n" +
	"func erasedWithOnlyProse(secret []byte) {\n" +
	"\tfor i := range secret {\n" +
	"\t\tsecret[i] = 0\n" +
	"\t}\n" +
	"}\n" +
	"\n" +
	"func erasedThroughALocalCutFromTheParameter(secret []byte) {\n" +
	"\twindow := secret[1:]\n" +
	"\twindow[0] = 0\n" +
	"}\n" +
	"\n" +
	"func erasedWithClearOverNamedStorage(key ControlKey) {\n" +
	"\tclear(key)\n" +
	"}\n" +
	"\n" +
	"func erasedWithCopy(secret []byte) {\n" +
	"\tcopy(secret, make([]byte, len(secret)))\n" +
	"}\n" +
	"\n" +
	"func writesOnlyIntoStorageOfItsOwn(secret []byte) []byte {\n" +
	"\tout := make([]byte, len(secret))\n" +
	"\tcopy(out, secret)\n" +
	"\tout[0] = 0\n" +
	"\treturn out\n" +
	"}\n" +
	"\n" +
	"func readsAParameter(secret []byte) byte {\n" +
	"\treturn secret[0]\n" +
	"}\n" +
	"\n" +
	"func rebindsAParameter(secret []byte) []byte {\n" +
	"\tsecret = nil\n" +
	"\treturn secret\n" +
	"}\n" +
	"\n" +
	"func takesNoBytesAtAll(count int) int {\n" +
	"\treturn count + 1\n" +
	"}\n" +
	"\n" +
	"type ControlHolder struct {\n" +
	"\tsecret []byte\n" +
	"}\n" +
	"\n" +
	"// erasedThroughTheReceiver is the shape a Zeroize method takes: the storage is the\n" +
	"// object's own rather than a caller's, and the write is the same write.\n" +
	"func (self *ControlHolder) erasedThroughTheReceiver() {\n" +
	"\tfor i := range self.secret {\n" +
	"\t\tself.secret[i] = 0\n" +
	"\t}\n" +
	"}\n" +
	"\n" +
	"func (self *ControlHolder) readsItsOwnStorageOnly() int {\n" +
	"\treturn len(self.secret)\n" +
	"}\n"

// TestEveryEraseHelperCarriesTheNoInlineDirective observes the one mechanism
// secret_zeroize.go's argument rests on, over every function this package declares rather
// than over one file of it.
//
// What that file claims is that the stores reach memory. A compiler may delete a write to
// memory it can prove is never read again, and in a caller that drops the secret straight
// afterwards these writes are exactly that; across a call it cannot inline it cannot make
// the proof. So the directive is not decoration, it is the whole mechanism.
//
// The class is what a function DOES and not where it is written. The version this replaces
// parsed secret_zeroize.go by name, while its own comment claimed that "a second erase
// helper landing beside it is held to the same rule without anyone remembering to extend a
// list" -- true of a helper landing beside it and false of one landing anywhere else.
// Measured, not supposed: the identical helper declared in key_schedule.go and used to
// erase member_secret left that gate silent, and with the one line exemption a contributor
// would copy verbatim from zeroizeSecret's own row in packageConstructionsOverBorrowedBytes
// the whole package was green -- with member_secret erased by a helper the compiler is
// entitled to inline and elide.
//
// Why "writes through storage its caller owns" is the same set as "erases a secret" here
// rather than a wider one: a construction of this package that writes into an array it was
// handed and is NOT an eraser is already forbidden, by
// TestEveryConstructionInThisPackageLeavesItsInputAlone, whose own excuse for zeroizeSecret
// is that writing into the caller's array is the function. The two gates meet on exactly
// this class, which is why neither of them has to name it.
//
// Two honest limits, stated rather than hidden. No go test can observe an elision, so this
// asserts the presence of the mechanism and not the effect -- the proxy the file's own
// argument is made of. And the write has to be spelled through the name whose storage it
// reaches: a parameter, a local cut from one, or a field of the receiver. A slice handed on
// to a function declared elsewhere and erased there is past what a syntax matcher can
// follow -- though the function it is handed to is itself in this class, and is held here.
func TestEveryEraseHelperCarriesTheNoInlineDirective(t *testing.T) {
	control := mustParseCommented(t, "the erase helper control", eraseHelperControl)
	helpers, missing := eraseHelpersIn(control, []string{"ControlKey"})
	wantHelpers := []string{
		"erasedWithTheDirective",
		"erasedWithOnlyProse",
		"erasedThroughALocalCutFromTheParameter",
		"erasedWithClearOverNamedStorage",
		"erasedWithCopy",
		"erasedThroughTheReceiver",
	}
	if !slices.Equal(helpers, wantHelpers) {
		t.Fatalf("the matcher read %v out of the control as erase helpers, want %v; it is not telling a write through the caller's array from a read of one or from a write into storage of the function's own",
			helpers, wantHelpers)
	}
	wantMissing := []string{
		"erasedWithOnlyProse",
		"erasedThroughALocalCutFromTheParameter",
		"erasedWithClearOverNamedStorage",
		"erasedWithCopy",
		"erasedThroughTheReceiver",
	}
	if !slices.Equal(missing, wantMissing) {
		t.Fatalf("the matcher read %v out of the control as missing the directive, want %v; it is not telling the directive from the prose that argues for it",
			missing, wantMissing)
	}

	named := packageByteSliceTypeNames(t)
	found := []string{}
	unprotected := []string{}
	for _, path := range packageLevelFunctions(t).files {
		declared, without := eraseHelpersIn(mustReadCommented(t, path), named)
		found = append(found, declared...)
		for _, name := range without {
			unprotected = append(unprotected, path+": "+name)
		}
	}
	// the positive control on the real source. This package certainly declares one erase
	// helper, and a scan that had stopped finding it would report the same clean run a
	// complete one reports.
	if !slices.Contains(found, "zeroizeSecret") {
		t.Fatalf("the scan read %v as this package's erase helpers and zeroizeSecret is not among them, so it is not reading what it claims to",
			found)
	}
	if len(unprotected) != 0 {
		t.Errorf("%v write through storage that outlives the call -- a caller's array or the receiver's own -- without a %s line of their own; that directive is the only thing between these stores and a compiler entitled to delete them, and secret_zeroize.go's own comment says so",
			unprotected, noInlineDirective)
	}
	t.Logf("%d erase helpers read out of this package's source: %v", len(found), found)
}

// keyScheduleErrorsFile is the single file this plan declares its typed errors in. Every
// gate below derives its class from that file rather than from the list, which is the
// difference between sweeping the class and sweeping a copy of it.
const keyScheduleErrorsFile = "errors_key_schedule.go"

// keyScheduleOwnedErrors is registry section 5.6's ten plus ErrNilGroupContext and
// ErrEpochErased, keyed by the name each is declared under so the derivation below can
// compare the two sets by name.
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
	"ErrEpochErased":                  ErrEpochErased,
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
// Twelve rather than the ten of registry section 5.6. ErrNilGroupContext names an argument
// that was missing rather than a protocol condition, and ErrEpochErased names a state of the
// epoch itself: both are refusals this package makes for reasons the registry never had to
// write down, and both are declared beside the ten because a second declaration site is how
// two sentinels for one condition happen.
func TestKeyScheduleErrorsAreDistinct(t *testing.T) {
	if len(keyScheduleOwnedErrors) != 12 {
		t.Fatalf("this plan owns %d errors, want the 10 of registry section 5.6 plus ErrNilGroupContext and ErrEpochErased", len(keyScheduleOwnedErrors))
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

// The rest of the hash and kdf surface, at the same width.
//
// A provider that answered KDF.Nh 48 and went on hashing at 32 would be incoherent, and the
// differential gate below reads output LENGTHS: over such a provider RefHash would answer 32
// bytes while the provider claimed 48, and the gate would report a construction that reads
// its length off the provider as one that writes 32 down. Everything Nh governs therefore
// moves together, and nothing here is a fake answering the right number of bytes -- it is
// SHA-384 and HMAC-SHA384 and HKDF-SHA384, the same primitives one width up.
//
// KeySize and NonceSize are deliberately NOT overridden. Nk and Nn are the aead's and have
// nothing to do with the kdf, and a suite whose hash grew does not thereby get a wider aead
// key; moving them would make this provider incoherent in the other direction.
func (self *wideKdfProvider) Hash(data []byte) []byte {
	digest := sha512.Sum384(data)
	return digest[:]
}

func (self *wideKdfProvider) Mac(key []byte, data []byte) []byte {
	mac := hmac.New(sha512.New384, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func (self *wideKdfProvider) MacVerify(key []byte, data []byte, tag []byte) bool {
	expected := self.Mac(key, data)
	if len(tag) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare(expected, tag) == 1
}

func (self *wideKdfProvider) Expand(prk []byte, info []byte, length int) []byte {
	out, err := hkdf.Expand(sha512.New384, prk, string(info), length)
	if err != nil {
		panic("mls test: hkdf-sha384 expand: " + err.Error())
	}
	return out
}

// DeriveSecret is ExpandWithLabel over no context at KDF.Nh, which is the definition
// RFC 9420 gives it and what crypto_labels.go writes. Routed through this type's own
// ExpandWithLabel so the width follows HashSize rather than being written down twice, and so
// the requested lengths are recorded here as well.
func (self *wideKdfProvider) DeriveSecret(secret []byte, label string) []byte {
	return self.ExpandWithLabel(secret, label, nil, self.HashSize())
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

// exportSweepContext is the exporter context the argument rows below carry.
//
// Deliberately not KDF.Nh octets and not empty: it travels into the sweeps as one of the
// things the exporter is handed, and a context that happened to be a kdf length would make
// the differential next door report a coincidence belonging to this test's own choice.
var exportSweepContext = bytes.Repeat([]byte{0x5c}, 19)

// keyScheduleMethodArgumentRows drives an exported method of *KeySchedule that takes
// arguments through the sweeps that read what this type hands out.
//
// A method with arguments cannot be called by a reflection sweep that has none, and the two
// ways out of that buy opposite things. Give it arguments and every byte it answers joins
// guardrail 6 exactly as an accessor's does; write it into
// keyScheduleMethodsTakingArguments instead and it joins nothing, which is only honest for
// a method whose arguments a test cannot supply. Export is driven rather than excused,
// because "the exporter cannot be made to answer epoch_secret" is a claim about the label,
// the context and the length a CALLER chooses, and an excuse is precisely a refusal to try
// any of them.
//
// The rows are built from the schedule rather than written out as constants, and that is
// load bearing twice over. One row asks for KDF.Nh bytes read off the provider, so the
// answer is the same size as the secret guardrail 6 is looking for and the comparison can
// mean something — an export of some other length can never equal epoch_secret whatever the
// implementation does. Another asks for a length that is not KDF.Nh, so the differential in
// TestEveryConstructionHandedAProviderReadsKdfNhFromIt sees an exporter length follow the
// caller's number rather than the provider's. Three rows rather than one, because an
// exporter that ignored its label or its context would answer one secret however it was
// called and a single row could not tell.
var keyScheduleMethodArgumentRows = map[string]func(schedule *KeySchedule) [][]reflect.Value{
	"Export": func(schedule *KeySchedule) [][]reflect.Value {
		nh := schedule.crypto.HashSize()
		return [][]reflect.Value{
			// the MASTER section 7 storage call: the seed recovery label, no context
			{reflect.ValueOf("URmessage/v1/storage"), reflect.ValueOf([]byte(nil)), reflect.ValueOf(nh)},
			// the same label with a context, so the pair differs only in the context
			{reflect.ValueOf("URmessage/v1/storage"), reflect.ValueOf(exportSweepContext), reflect.ValueOf(nh)},
			// a different label at a length that is not KDF.Nh
			{reflect.ValueOf("URmessage/v1/other"), reflect.ValueOf(exportSweepContext), reflect.ValueOf(nh + 8)},
		}
	},
}

// exposedAnswerAt names one answer of one method: the method, and the position of the result
// it came out of.
//
// The position is what makes an excuse per ANSWER rather than per METHOD. ExternalKeyPair
// answers a private key at Nsk and a public key at Npk, neither of which is a kdf length, and
// an excuse keyed on the method alone would go on covering a THIRD answer that is one. The two
// results it has today each carry their own line, and a result added to it is excused by
// nobody until somebody writes one.
type exposedAnswerAt struct {
	method string
	result int
}

func (self exposedAnswerAt) String() string {
	return fmt.Sprintf("(*KeySchedule).%s result %d", self.method, self.result)
}

// exposedSlice is one byte slice a sweep read off an exported surface, with the method it
// came out of, the position of the result it came out of, and the path inside that result.
//
// The provenance travels with the bytes because the sweeps reading these want different
// subsets of them: guardrail 6 asks about every one, and the KDF.Nh differential next door
// has to leave out the answers that are not kdf lengths at all. Carrying the address is what
// lets that second sweep say what it dropped instead of dropping by position.
type exposedSlice struct {
	method string
	result int
	path   string
	bytes  []byte
}

// at is the address the excuse tables below are keyed by.
func (self exposedSlice) at() exposedAnswerAt {
	return exposedAnswerAt{method: self.method, result: self.result}
}

// exposedBytes is the byte slices alone, in order, for a sweep that does not care where each
// of them came from.
func exposedBytes(exposed []exposedSlice) [][]byte {
	raw := make([][]byte, 0, len(exposed))
	for _, one := range exposed {
		raw = append(raw, one.bytes)
	}
	return raw
}

// exposedByteSlices flattens everything one call handed back into the byte slices a caller
// can read. A byte slice result is one; a pointer to a struct is each of its exported byte
// slice fields, which is the shape Secrets() has; a nil error contributes nothing.
//
// A byte slice is recognised by KIND rather than by the spelling []byte. HpkePublicKey and
// HpkePrivateKey are byte slices under names of their own — registry section 3.2, which
// TestConsumedHpkePublicKeyIsASlice holds them to — so a comparison against the unnamed type
// drops exactly the two results ExternalKeyPair answers out of guardrail 6's class, and a
// gate that demands less reports what a complete one reports.
func exposedByteSlices(t *testing.T, what string, result reflect.Value) []exposedSlice {
	t.Helper()
	errorInterface := reflect.TypeOf((*error)(nil)).Elem()
	if result.Type() == errorInterface {
		// every row these sweeps are built from succeeds, so a failure here is the sweep's
		// own bug rather than a place a secret hides
		if !result.IsNil() {
			t.Fatalf("%s answered %v, and the rows this sweep is built from succeed", what, result.Interface())
		}
		return nil
	}
	if result.Kind() == reflect.Slice && result.Type().Elem().Kind() == reflect.Uint8 {
		return []exposedSlice{{path: what, bytes: result.Bytes()}}
	}
	if result.Kind() == reflect.Pointer && result.Type().Elem().Kind() == reflect.Struct {
		if result.IsNil() {
			return nil
		}
		exposed := []exposedSlice{}
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

// recoveringRow runs one row of a package wide sweep with a panic caught rather than taken.
//
// A sweep like the ones below calls production code with inputs the test chose, and a defect
// that panics on one of them takes the test BINARY down: go reports the panicking test as
// the single failure of the run, every test declared after it never runs, and every gate
// those tests hold reports nothing at all. Measured, not supposed: deriving InitSecret from
// the welcome_secret that is nil on the group creation path panicked inside
// TestEveryConstructionHandedAProviderRoutesThroughIt, and a whole package run then reported
// one failure in crypto_labels_test.go, 2325 fewer passes and nothing whatever about the key
// schedule -- while the key schedule's own gates, run on their own, caught that same edit
// three times over. A row that panics is a failure OF THAT ROW, and the rest of the package
// still has to answer for itself.
//
// t.Fatalf inside the call is unaffected: it leaves the goroutine through runtime.Goexit
// rather than through a panic, recover answers nil, and the exit goes on happening.
//
// recoveredPanic in crypto_test.go is the same guard for a call that answers nothing.
func recoveringRow[T any](call func() T) (answer T, raised any) {
	defer func() { raised = recover() }()
	return call(), nil
}

// TestTheSweepRowRecoveryReturnsRatherThanTakingTheBinaryDown is the control on that.
//
// A recovery that had stopped recovering is invisible from every sweep that uses it: the
// binary dies exactly as it did before, and the run reports one failure somewhere else. The
// normal path is asserted alongside, because a helper that swallowed every answer would make
// each of those sweeps compare nothing and report the clean run a working one reports.
func TestTheSweepRowRecoveryReturnsRatherThanTakingTheBinaryDown(t *testing.T) {
	answer, raised := recoveringRow(func() []byte { return []byte{0x11, 0x22} })
	if raised != nil {
		t.Errorf("a call that did not panic reported %v", raised)
	}
	if !bytes.Equal(answer, []byte{0x11, 0x22}) {
		t.Errorf("a call that did not panic answered %x, want 1122", answer)
	}
	answer, raised = recoveringRow(func() []byte { panic("the row panicked") })
	if raised == nil {
		t.Fatal("a call that panicked reported no panic, so every sweep reading this recovery would still take the binary down")
	}
	if raised != "the row panicked" {
		t.Errorf("the recovery reported %v rather than what was raised", raised)
	}
	if answer != nil {
		t.Errorf("a call that panicked answered %x rather than nothing", answer)
	}
}

// epochSecretOfTheEpoch states epoch_secret independently of the type under test, over the
// corpus's own published inputs: Extract(joiner_secret, psk_secret) expanded under "epoch"
// over the published GroupContext bytes.
//
// Independent is the point. A statement read off the schedule would agree with any schedule,
// including one that hands the secret out.
func epochSecretOfTheEpoch(t *testing.T, epoch ksVectorEpoch) []byte {
	t.Helper()
	return epoch.crypto.ExpandWithLabel(
		epoch.crypto.Extract(
			mustDecodeHex(t, "joiner_secret"+epoch.at, epoch.published.JoinerSecret), epoch.pskSecret),
		"epoch", mustDecodeHex(t, "group_context"+epoch.at, epoch.published.GroupContext),
		epoch.crypto.HashSize())
}

// bytesTheScheduleHandsOut is every byte slice reachable through *KeySchedule's own exported
// surface, with the names of the methods that were called.
//
// The class is the type's exported surface read by reflection, not a list of accessors
// written here, so a method added later joins by existing. The exported fields are refused
// outright: storage reachable without going through a method is storage this sweep would
// never call for.
func bytesTheScheduleHandsOut(t *testing.T, at string, schedule *KeySchedule) ([]exposedSlice, []string) {
	t.Helper()
	scheduleType := reflect.TypeOf(schedule)
	valueType := scheduleType.Elem()
	for i := range valueType.NumField() {
		if valueType.Field(i).IsExported() {
			t.Fatalf("%s: KeySchedule has exported field %s, so its storage is reachable without going through a method this sweep reads",
				at, valueType.Field(i).Name)
		}
	}

	exposed := []exposedSlice{}
	swept := []string{}
	for i := range scheduleType.NumMethod() {
		method := scheduleType.Method(i)
		// one row of no arguments for an accessor, and whatever
		// keyScheduleMethodArgumentRows supplies for a method that takes some
		rows := [][]reflect.Value{nil}
		if method.Type.NumIn() != 1 {
			build, driven := keyScheduleMethodArgumentRows[method.Name]
			if !driven {
				if reason, excused := keyScheduleMethodsTakingArguments[method.Name]; !excused {
					t.Fatalf("%s: (*KeySchedule).%s takes arguments and this sweep calls with none; give it rows in keyScheduleMethodArgumentRows or write down in keyScheduleMethodsTakingArguments why it cannot surface epoch_secret",
						at, method.Name)
				} else {
					t.Logf("%s: (*KeySchedule).%s not swept: %s", at, method.Name, reason)
				}
				continue
			}
			rows = build(schedule)
			if len(rows) == 0 {
				t.Fatalf("%s: keyScheduleMethodArgumentRows drives (*KeySchedule).%s with no rows at all, so it is swept in name only",
					at, method.Name)
			}
			// the arity and the types are checked rather than left to reflect.Call, whose
			// answer to a row that does not fit is a panic naming neither the method nor
			// the row that did not fit it
			for _, row := range rows {
				if len(row)+1 != method.Type.NumIn() {
					t.Fatalf("%s: keyScheduleMethodArgumentRows drives (*KeySchedule).%s with %d arguments and it takes %d",
						at, method.Name, len(row), method.Type.NumIn()-1)
				}
				for argument, value := range row {
					if want := method.Type.In(argument + 1); !value.Type().AssignableTo(want) {
						t.Fatalf("%s: keyScheduleMethodArgumentRows hands (*KeySchedule).%s a %s in argument %d, which takes %s",
							at, method.Name, value.Type(), argument, want)
					}
				}
			}
		} else if _, driven := keyScheduleMethodArgumentRows[method.Name]; driven {
			t.Errorf("keyScheduleMethodArgumentRows drives %s, which takes no arguments", method.Name)
		}
		swept = append(swept, method.Name)
		for _, row := range rows {
			for index, result := range method.Func.Call(append([]reflect.Value{reflect.ValueOf(schedule)}, row...)) {
				for _, one := range exposedByteSlices(t, "(*KeySchedule)."+method.Name, result) {
					one.method = method.Name
					one.result = index
					exposed = append(exposed, one)
				}
			}
		}
	}
	for name := range keyScheduleMethodsTakingArguments {
		if _, found := scheduleType.MethodByName(name); !found {
			t.Errorf("keyScheduleMethodsTakingArguments excuses %s, which *KeySchedule does not declare", name)
		}
		if _, driven := keyScheduleMethodArgumentRows[name]; driven {
			t.Errorf("%s is both excused from this sweep and driven through it, so which one holds depends on the order these two maps are read",
				name)
		}
	}
	for name := range keyScheduleMethodArgumentRows {
		if _, found := scheduleType.MethodByName(name); !found {
			t.Errorf("keyScheduleMethodArgumentRows drives %s, which *KeySchedule does not declare", name)
		}
	}
	return exposed, swept
}

// TestNoExportedSurfaceOfTheKeyScheduleReturnsTheEpochSecret is guardrail G6 read as
// behaviour rather than as a convention, over the type's own surface.
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
//
// This half covers what the TYPE hands out. What the PACKAGE hands out is a wider class and
// is covered next door, by TestNoExportedFunctionOfThisPackageHandsOutTheEpochSecret: a free
// function taking a *KeySchedule reaches the same unexported field and is nowhere in this
// reflection.
func TestNoExportedSurfaceOfTheKeyScheduleReturnsTheEpochSecret(t *testing.T) {
	for _, epoch := range ksVectorEpochs(t) {
		schedule := epoch.schedule(t)
		epochSecret := epochSecretOfTheEpoch(t, epoch)
		exposed, swept := bytesTheScheduleHandsOut(t, epoch.at, schedule)

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
			if !slices.ContainsFunc(exposed, func(one exposedSlice) bool { return bytes.Equal(one.bytes, known) }) {
				t.Fatalf("%s: the sweep did not find a secret the type certainly exposes, so a secret it must not expose would be missed too",
					epoch.at)
			}
		}
		// and an answer of KDF.Nh bytes really did go through it. The comparison below is
		// against a secret that is KDF.Nh long, so a sweep in which no answer was ever that
		// length could not have found epoch_secret however this type handed it out.
		if !slices.ContainsFunc(exposed, func(one exposedSlice) bool {
			return len(one.bytes) == epoch.crypto.HashSize()
		}) {
			t.Fatalf("%s: no answer the sweep read is KDF.Nh bytes long, so none of them could equal epoch_secret whatever this type did",
				epoch.at)
		}

		for index, one := range exposed {
			if bytes.Equal(one.bytes, epochSecret) {
				t.Errorf("%s: the exported surface hands out epoch_secret through %s at position %d of %d; it is the parent of every secret of this epoch and G6 says no exported symbol returns it",
					epoch.at, one.path, index, len(exposed))
			}
		}
	}
}

// epochSecretStorageField is the unexported field an epoch keeps its parent secret in.
//
// This names the SUBJECT of G6 and not the class G6 covers. The class — every exported
// symbol through which a caller can reach that storage — is derived below, starting from
// whichever type declares this field, so a free function nobody thought of joins it by
// existing. A rename this cannot find is fatal rather than clean: a gate that lost its
// subject reports exactly the clean run a complete one reports.
const epochSecretStorageField = "epochSecret"

// structTypesIn adds the named struct types one parsed file declares.
func structTypesIn(parsed parsedSource, into map[string]*ast.StructType) {
	for _, declaration := range parsed.file.Decls {
		types, isTypeDeclaration := declaration.(*ast.GenDecl)
		if !isTypeDeclaration || types.Tok != token.TYPE {
			continue
		}
		for _, specification := range types.Specs {
			named, isNamed := specification.(*ast.TypeSpec)
			if !isNamed {
				continue
			}
			if structure, isStruct := named.Type.(*ast.StructType); isStruct {
				into[named.Name.Name] = structure
			}
		}
	}
}

// identifiersNamedIn collects every bare identifier a type expression mentions, so *T, []T,
// map[K]T, T[P] and func(T) all report T.
//
// A rendered string compared with strings.Contains would answer yes for a type whose name
// merely contains another's, and no for one spelled across a line break.
func identifiersNamedIn(expr ast.Expr) []string {
	named := []string{}
	ast.Inspect(expr, func(node ast.Node) bool {
		if identifier, isIdentifier := node.(*ast.Ident); isIdentifier {
			named = append(named, identifier.Name)
		}
		return true
	})
	return named
}

// theTypesHoldingTheEpochSecret is the closure over a set of named struct types of "keeps
// the epoch secret": the type that declares the field, and any type with a field that
// mentions one that does.
//
// A closure rather than the one declaring type, because a struct holding a *KeySchedule
// hands its own holder the same storage, and an exported function taking one of those is
// handed the epoch secret just as surely as one taking the schedule itself.
func theTypesHoldingTheEpochSecret(structs map[string]*ast.StructType) []string {
	holding := map[string]bool{}
	for name, structure := range structs {
		for _, field := range structure.Fields.List {
			for _, declared := range field.Names {
				if declared.Name == epochSecretStorageField {
					holding[name] = true
				}
			}
		}
	}
	for {
		grew := false
		for name, structure := range structs {
			if holding[name] {
				continue
			}
			for _, field := range structure.Fields.List {
				for _, mentioned := range identifiersNamedIn(field.Type) {
					if holding[mentioned] {
						holding[name] = true
						grew = true
					}
				}
			}
		}
		if !grew {
			return slices.Sorted(maps.Keys(holding))
		}
	}
}

// theExportedSurfaceReaching is every exported package level function of the parsed files
// whose signature mentions one of those types, in either direction.
//
// Both directions, because both are ways an exported symbol comes to have an epoch secret
// to give away: a parameter is handed one, and a result hands one out to be read further.
// Methods are excluded and are not uncovered — the exported methods of a holder are swept by
// reflection in the gate above, which is a reading of the compiled type rather than of its
// source and therefore sees an embedded surface this parse would not.
func theExportedSurfaceReaching(files []parsedSource, holders []string) []string {
	reaching := []string{}
	for _, parsed := range files {
		for _, declaration := range parsed.file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Recv != nil || !function.Name.IsExported() {
				continue
			}
			fields := []*ast.Field{}
			if function.Type.Params != nil {
				fields = append(fields, function.Type.Params.List...)
			}
			if function.Type.Results != nil {
				fields = append(fields, function.Type.Results.List...)
			}
			for _, field := range fields {
				if slices.ContainsFunc(identifiersNamedIn(field.Type), func(name string) bool {
					return slices.Contains(holders, name)
				}) {
					reaching = append(reaching, function.Name.Name)
					break
				}
			}
		}
	}
	slices.Sort(reaching)
	return reaching
}

// packageLevelValuesNaming is every package level var or const of the parsed files whose
// declared type, or whose initialiser, mentions one of those names.
//
// A standing value of a holder type would be an epoch secret reachable with no call at all,
// so the sweep below could not see it however complete its rows were. This package declares
// none and this is what says so.
func packageLevelValuesNaming(files []parsedSource, holders []string) []string {
	naming := []string{}
	for _, parsed := range files {
		for _, declaration := range parsed.file.Decls {
			values, isValueDeclaration := declaration.(*ast.GenDecl)
			if !isValueDeclaration || (values.Tok != token.VAR && values.Tok != token.CONST) {
				continue
			}
			for _, specification := range values.Specs {
				value, isValue := specification.(*ast.ValueSpec)
				if !isValue {
					continue
				}
				mentioned := []string{}
				if value.Type != nil {
					mentioned = append(mentioned, identifiersNamedIn(value.Type)...)
				}
				for _, initialiser := range value.Values {
					mentioned = append(mentioned, identifiersNamedIn(initialiser)...)
				}
				if !slices.ContainsFunc(mentioned, func(name string) bool { return slices.Contains(holders, name) }) {
					continue
				}
				for _, declared := range value.Names {
					naming = append(naming, declared.Name)
				}
			}
		}
	}
	slices.Sort(naming)
	return naming
}

// epochSecretHolderControl declares one of each shape the derivation has to tell apart: the
// struct that keeps the secret, a struct that reaches it through a pointer to that one, a
// struct that keeps a byte slice under another name entirely, exported functions taking and
// answering a holder, an unexported one, an exported one over something else, and a package
// level value of a holder type.
//
// Without it a derivation that had stopped deriving — a parse that read no structs, a
// closure that never seeded — would report an empty class, every gate reading it would
// demand nothing, and the run would look exactly like the run of a complete one.
const epochSecretHolderControl = "package control\n" +
	"\n" +
	"type Holder struct {\n" +
	"\tcrypto      int\n" +
	"\tepochSecret []byte\n" +
	"}\n" +
	"\n" +
	"type Wrapper struct {\n" +
	"\tinner *Holder\n" +
	"}\n" +
	"\n" +
	"type Unrelated struct {\n" +
	"\tsecret []byte\n" +
	"}\n" +
	"\n" +
	"var TheStandingHolder = &Holder{}\n" +
	"\n" +
	"func ExportedOverTheHolder(holder *Holder) []byte {\n" +
	"\treturn holder.epochSecret\n" +
	"}\n" +
	"\n" +
	"func ExportedOverTheWrapper(wrapper Wrapper) []byte {\n" +
	"\treturn wrapper.inner.epochSecret\n" +
	"}\n" +
	"\n" +
	"func ExportedAnsweringAHolder(seed []byte) (*Holder, error) {\n" +
	"\treturn nil, nil\n" +
	"}\n" +
	"\n" +
	"func exportedNowhere(holder *Holder) []byte {\n" +
	"\treturn holder.epochSecret\n" +
	"}\n" +
	"\n" +
	"func ExportedOverSomethingElse(unrelated *Unrelated) []byte {\n" +
	"\treturn unrelated.secret\n" +
	"}\n" +
	"\n" +
	"func (self *Holder) Exported() []byte {\n" +
	"\treturn nil\n" +
	"}\n"

// epochSecretHolderSweeps is how this gate reads a value of a type that keeps the epoch
// secret. It is keyed by type name and checked against the derived closure in both
// directions, so a second holder landing in this package fails here until somebody teaches
// the sweep to read one rather than falling outside it in silence.
var epochSecretHolderSweeps = map[string]func(t *testing.T, at string, value reflect.Value) [][]byte{
	"KeySchedule": func(t *testing.T, at string, value reflect.Value) [][]byte {
		t.Helper()
		if value.IsNil() {
			return nil
		}
		schedule, isSchedule := value.Interface().(*KeySchedule)
		if !isSchedule {
			t.Fatalf("%s: the sweep was handed a %s where a *KeySchedule belongs", at, value.Type())
		}
		exposed, _ := bytesTheScheduleHandsOut(t, at, schedule)
		return exposedBytes(exposed)
	},
}

// bytesTheAnswerHandsOut flattens everything one construction answered into the byte slices
// a caller can read off it.
//
// A holder is read through its own exported surface, which is what makes a construction
// answering a *KeySchedule cover the same ground as the reflection sweep. An error is
// required to be nil rather than read: every row here is built out of the published corpus
// and succeeds, so an error is this gate's own bug and not a place a secret hides.
func bytesTheAnswerHandsOut(t *testing.T, at string, name string, results []reflect.Value) [][]byte {
	t.Helper()
	errorInterface := reflect.TypeOf((*error)(nil)).Elem()
	exposed := [][]byte{}
	for _, result := range results {
		if result.Type() == errorInterface {
			if !result.IsNil() {
				t.Fatalf("%s%s answered %v, and the rows here are built out of the published corpus to succeed",
					name, at, result.Interface())
			}
			continue
		}
		held := result.Type()
		if held.Kind() == reflect.Pointer {
			held = held.Elem()
		}
		if sweep, isHolder := epochSecretHolderSweeps[held.Name()]; isHolder {
			exposed = append(exposed, sweep(t, at, result)...)
			continue
		}
		exposed = append(exposed, exposedBytes(exposedByteSlices(t, name+at, result))...)
	}
	return exposed
}

// epochSecretSurfaceRows calls each exported function that can reach an epoch secret and
// hands back what it answered.
//
// The keys are held to the derived class in both directions by the gate below. That is what
// closes the hole the type level sweep alone left: a package level
// func EpochSecretOf(schedule *KeySchedule) []byte compiles, is exported, is exactly the leak
// G6 forbids, and is nowhere in a reflection over (*KeySchedule)'s methods. Measured, not
// supposed: appended to key_schedule.go it left the whole of mls and message green.
//
// NewKeyScheduleFromEpochSecret is driven with the independently derived epoch secret itself
// rather than with an arbitrary sample, so the schedule under it holds the exact value the
// comparison is looking for.
var epochSecretSurfaceRows = map[string]func(t *testing.T, epoch ksVectorEpoch) []reflect.Value{
	"NewKeySchedule": func(t *testing.T, epoch ksVectorEpoch) []reflect.Value {
		schedule, err := NewKeySchedule(
			epoch.crypto, epoch.initPrev, epoch.commitSecret, epoch.pskSecret, epoch.groupContext)
		return []reflect.Value{reflect.ValueOf(schedule), reflect.ValueOf(&err).Elem()}
	},
	"NewKeyScheduleFromJoiner": func(t *testing.T, epoch ksVectorEpoch) []reflect.Value {
		joinerSecret := mustDecodeHex(t, "joiner_secret"+epoch.at, epoch.published.JoinerSecret)
		schedule, err := NewKeyScheduleFromJoiner(
			epoch.crypto, joinerSecret, epoch.pskSecret, epoch.groupContext)
		return []reflect.Value{reflect.ValueOf(schedule), reflect.ValueOf(&err).Elem()}
	},
	"NewKeyScheduleFromEpochSecret": func(t *testing.T, epoch ksVectorEpoch) []reflect.Value {
		schedule, err := NewKeyScheduleFromEpochSecret(
			epoch.crypto, epochSecretOfTheEpoch(t, epoch), epoch.groupContext)
		return []reflect.Value{reflect.ValueOf(schedule), reflect.ValueOf(&err).Elem()}
	},
}

// TestNoExportedFunctionOfThisPackageHandsOutTheEpochSecret is the other half of guardrail
// G6: what the PACKAGE hands out, rather than what the type does.
//
// The gate above sweeps (*KeySchedule)'s own reflected surface, and epoch_secret is an
// unexported field, so every symbol declared in package mls can read it — a free function
// most of all. Measured, not supposed: with
// func EpochSecretOf(schedule *KeySchedule) []byte { return schedule.epochSecret } appended
// to key_schedule.go, the whole of mls and message was green. The one other package wide
// gate that might have seen it, TestEveryConstructionInThisPackageLeavesItsInputAlone,
// collects the constructions that are HANDED bytes, and that one takes only a schedule.
//
// So the class here is derived rather than reflected: every exported package level function
// whose signature mentions a type that keeps the epoch secret, read off the parse tree, with
// the holder types themselves derived by closure from whichever struct declares the storage.
// A function added later joins by existing and fails this until somebody writes the row that
// reads what it answers.
func TestNoExportedFunctionOfThisPackageHandsOutTheEpochSecret(t *testing.T) {
	// the control first: the closure seeds, follows one hop, and the surface filter tells
	// an exported function over a holder from an unexported one and from an exported one
	// over something else
	control := mustParseText(t, "the epoch secret holder control", epochSecretHolderControl)
	controlStructs := map[string]*ast.StructType{}
	structTypesIn(control, controlStructs)
	controlHolders := theTypesHoldingTheEpochSecret(controlStructs)
	if want := []string{"Holder", "Wrapper"}; !slices.Equal(controlHolders, want) {
		t.Fatalf("the closure read %v out of the control as holding the epoch secret, want %v; it is not seeding on the storage or not following a reference to it",
			controlHolders, want)
	}
	controlSurface := theExportedSurfaceReaching([]parsedSource{control}, controlHolders)
	wantSurface := []string{"ExportedAnsweringAHolder", "ExportedOverTheHolder", "ExportedOverTheWrapper"}
	if !slices.Equal(controlSurface, wantSurface) {
		t.Fatalf("the surface filter read %v out of the control, want %v; it is not reading both directions of a signature, or not telling exported from not",
			controlSurface, wantSurface)
	}
	if standing := packageLevelValuesNaming([]parsedSource{control}, controlHolders); !slices.Equal(standing, []string{"TheStandingHolder"}) {
		t.Fatalf("the package level value scan read %v out of the control, want [TheStandingHolder]", standing)
	}

	// then this package's own source
	structs := map[string]*ast.StructType{}
	files := []parsedSource{}
	for _, path := range packageLevelFunctions(t).files {
		parsed := mustParseSource(t, path)
		files = append(files, parsed)
		structTypesIn(parsed, structs)
	}
	holders := theTypesHoldingTheEpochSecret(structs)
	if len(holders) == 0 {
		t.Fatalf("no struct of this package's source declares a field named %s, so the class below is empty and this gate demands nothing; if the storage was renamed, rename it here too",
			epochSecretStorageField)
	}
	for _, holder := range holders {
		if _, known := epochSecretHolderSweeps[holder]; !known {
			t.Fatalf("%s keeps the epoch secret and this gate has no way to read a value of one; add it to epochSecretHolderSweeps rather than letting a second holder fall outside G6",
				holder)
		}
	}
	for name := range epochSecretHolderSweeps {
		if !slices.Contains(holders, name) {
			t.Errorf("epochSecretHolderSweeps reads a %s and no struct of this package keeps the epoch secret under that name", name)
		}
	}
	if standing := packageLevelValuesNaming(files, holders); len(standing) != 0 {
		t.Errorf("%v are package level values of a type that keeps the epoch secret, so one is reachable with no call for this sweep to make",
			standing)
	}

	surface := theExportedSurfaceReaching(files, holders)
	if len(surface) == 0 {
		t.Fatalf("no exported function of this package mentions %v, and this package declares three constructors that answer one, so the scan is reading nothing",
			holders)
	}
	for _, name := range surface {
		if _, covered := epochSecretSurfaceRows[name]; !covered {
			t.Errorf("%s is exported and its signature carries %v, so it can hand out epoch_secret and nothing here calls it; write it a row in epochSecretSurfaceRows",
				name, holders)
		}
	}
	for name := range epochSecretSurfaceRows {
		if !slices.Contains(surface, name) {
			t.Errorf("epochSecretSurfaceRows calls %s, which is not an exported function of this package reaching %v", name, holders)
		}
	}
	t.Logf("guardrail 6 swept over %v, holders %v", surface, holders)

	for _, epoch := range ksVectorEpochs(t) {
		epochSecret := epochSecretOfTheEpoch(t, epoch)
		readAcrossTheRows := [][]byte{}
		for _, name := range surface {
			row, covered := epochSecretSurfaceRows[name]
			if !covered {
				continue
			}
			results, raised := recoveringRow(func() []reflect.Value { return row(t, epoch) })
			if raised != nil {
				t.Errorf("%s%s panicked with %v rather than answering", name, epoch.at, raised)
				continue
			}
			exposed := bytesTheAnswerHandsOut(t, epoch.at, name, results)
			// a row that answered nothing observed nothing, and reports the clean run a
			// row that answered everything reports
			if !slices.ContainsFunc(exposed, func(b []byte) bool { return len(b) != 0 }) {
				t.Errorf("%s%s answered no bytes at all, so this row read nothing to compare",
					name, epoch.at)
				continue
			}
			for index, secret := range exposed {
				if bytes.Equal(secret, epochSecret) {
					t.Errorf("%s%s hands out epoch_secret at position %d of %d; it is the parent of every secret of this epoch and G6 says no exported symbol of this package returns it",
						name, epoch.at, index, len(exposed))
				}
			}
			readAcrossTheRows = append(readAcrossTheRows, exposed...)
		}
		// and the control on the flattener rather than on any one row: a secret these
		// constructions certainly hand out has to come back out of it, or a secret they
		// must not hand out would be missed the same way
		known := epoch.schedule(t).Secrets().InitSecret
		if !slices.ContainsFunc(readAcrossTheRows, func(b []byte) bool { return bytes.Equal(b, known) }) {
			t.Fatalf("%s: the sweep read %d byte slices off %v and init_secret is not among them, so it is not reading what it claims to",
				epoch.at, len(readAcrossTheRows), surface)
		}
	}
}

// sourceDeclaration is one function or method this package's own source declares, with the
// receiver it is written on and the shapes a scan below reads.
//
// Methods travel with functions because the class these build is "what can reach the epoch
// secret", and a method reaches it through a helper function exactly as a function reaches it
// through a helper method. A scan that read only one of the two would report a leak spelled
// through the other as absent.
type sourceDeclaration struct {
	receiver string
	name     string
	exported bool
	params   []string
	results  []string
	body     *ast.BlockStmt
}

// declaredIn is every function and method of one parsed file, with its parameter and result
// types rendered.
//
// Rendered rather than compared as syntax, for the reason packageLevelFunctionsIn renders:
// func f(a, b []byte) and func f(a []byte, b []byte) are the same signature to the compiler
// and a filter over either spelling has to read them the same way.
func declaredIn(parsed parsedSource) []sourceDeclaration {
	declared := []sourceDeclaration{}
	for _, declaration := range parsed.file.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if !isFunction {
			continue
		}
		one := sourceDeclaration{
			receiver: parsed.receiverOf(function),
			name:     function.Name.Name,
			exported: function.Name.IsExported(),
			params:   []string{},
			results:  []string{},
			body:     function.Body,
		}
		if function.Type.Params != nil {
			for _, field := range function.Type.Params.List {
				one.params = append(one.params,
					slices.Repeat([]string{parsed.render(field.Type)}, max(len(field.Names), 1))...)
			}
		}
		if function.Type.Results != nil {
			for _, field := range function.Type.Results.List {
				one.results = append(one.results,
					slices.Repeat([]string{parsed.render(field.Type)}, max(len(field.Names), 1))...)
			}
		}
		declared = append(declared, one)
	}
	return declared
}

// declaredAcross is the same over several files.
func declaredAcross(files []parsedSource) []sourceDeclaration {
	declared := []sourceDeclaration{}
	for _, parsed := range files {
		declared = append(declared, declaredIn(parsed)...)
	}
	return declared
}

// theNamesReachingTheEpochSecret is every declared name whose body can reach the storage
// epochSecretStorageField names: the ones that mention it, closed over the names they call.
//
// One identifier check covers every spelling go has for that storage. ast.Inspect descends
// into a selector's own Sel and into a composite literal's key, so self.epochSecret, the
// epochSecret field of a literal and a local or parameter carrying it are all an *ast.Ident of
// that name. A matcher written against the selector alone would read the first and miss the
// other two.
//
// The closure is over NAMES rather than over resolved callees, which over-approximates: a call
// x.Foo() joins whatever Foo this package declares, on whichever receiver. That is the safe
// direction for a gate -- it can demand too much, and says so by failing with the name it
// objected to -- where a call graph that resolved too little reports exactly the clean run a
// complete one reports. A method value taken without a call is an identifier too, so
// f := self.leak handed somewhere else is read by the same pass.
func theNamesReachingTheEpochSecret(declared []sourceDeclaration) []string {
	mentions := func(body *ast.BlockStmt, wanted map[string]bool) bool {
		if body == nil {
			return false
		}
		found := false
		ast.Inspect(body, func(node ast.Node) bool {
			if identifier, isIdentifier := node.(*ast.Ident); isIdentifier && wanted[identifier.Name] {
				found = true
			}
			return !found
		})
		return found
	}
	reaching := map[string]bool{epochSecretStorageField: true}
	for {
		grew := false
		for _, one := range declared {
			if reaching[one.name] {
				continue
			}
			if mentions(one.body, reaching) {
				reaching[one.name] = true
				grew = true
			}
		}
		if !grew {
			delete(reaching, epochSecretStorageField)
			return slices.Sorted(maps.Keys(reaching))
		}
	}
}

// theExportedMethodsHandingOutWhatTheyReach is every exported method of the parsed files that
// can reach the epoch secret AND has somewhere to put it: a result that is not an error, or a
// byte slice parameter it could write through.
//
// The second half is what makes this a property rather than a list of allowed names. An epoch
// has one legitimate reason for an exported method to touch its parent secret -- erasing it --
// and such a method answers nothing and is handed nothing, so it falls outside this class by
// its own shape rather than by an exemption somebody wrote. Everything else that reaches the
// storage is a way out for it.
//
// The receiver travels with the name because the closure resolves callees by name: two types
// declaring a method of one spelling are reported together, and a reader who is told "Export"
// cannot tell which. That over-report is the price of the safe direction, and naming both is
// what keeps it readable rather than mysterious.
func theExportedMethodsHandingOutWhatTheyReach(declared []sourceDeclaration, byteSlices []string) []string {
	reaching := theNamesReachingTheEpochSecret(declared)
	handingOut := []string{}
	for _, one := range declared {
		if one.receiver == "" || !one.exported || !slices.Contains(reaching, one.name) {
			continue
		}
		somewhereToPutIt := slices.ContainsFunc(one.results, func(result string) bool { return result != "error" })
		for _, parameter := range one.params {
			if slices.Contains(byteSlices, parameter) {
				somewhereToPutIt = true
			}
		}
		if somewhereToPutIt {
			handingOut = append(handingOut, "("+one.receiver+")."+one.name)
		}
	}
	slices.Sort(handingOut)
	return handingOut
}

// epochSecretMethodControl declares one of each shape the derivation has to tell apart: a
// method that reads the storage outright, one that reads it through an unexported method of
// its own, one that reads it through a package level function, one that writes it into an
// array the caller handed in, the erase shape that reaches it and answers nothing, one that
// reaches it and answers an error alone, one that reaches nothing, and an unexported one that
// reads it.
//
// Without it a derivation that had stopped deriving -- a seed that no longer matched, a
// closure that never followed a call -- would report an empty class, and an empty class is
// exactly the clean run a complete one produces.
const epochSecretMethodControl = "package control\n" +
	"\n" +
	"type Holder struct {\n" +
	"\tepochSecret []byte\n" +
	"}\n" +
	"\n" +
	"func (self *Holder) LeaksItDirectly() []byte {\n" +
	"\treturn self.epochSecret\n" +
	"}\n" +
	"\n" +
	"func (self *Holder) LeaksItThroughAMethod() []byte {\n" +
	"\treturn self.reader()\n" +
	"}\n" +
	"\n" +
	"func (self *Holder) reader() []byte {\n" +
	"\treturn self.epochSecret\n" +
	"}\n" +
	"\n" +
	"func (self *Holder) LeaksItThroughAFunction() ([]byte, error) {\n" +
	"\treturn theSecretOf(self), nil\n" +
	"}\n" +
	"\n" +
	"func theSecretOf(holder *Holder) []byte {\n" +
	"\treturn holder.epochSecret\n" +
	"}\n" +
	"\n" +
	"func (self *Holder) LeaksItIntoTheCallersArray(out []byte) {\n" +
	"\tcopy(out, self.epochSecret)\n" +
	"}\n" +
	"\n" +
	"func (self *Holder) Zeroize() {\n" +
	"\tfor i := range self.epochSecret {\n" +
	"\t\tself.epochSecret[i] = 0\n" +
	"\t}\n" +
	"}\n" +
	"\n" +
	"func (self *Holder) AnswersAnErrorAlone() error {\n" +
	"\tif len(self.epochSecret) == 0 {\n" +
	"\t\treturn nil\n" +
	"\t}\n" +
	"\treturn nil\n" +
	"}\n" +
	"\n" +
	"func (self *Holder) ReachesNothing() []byte {\n" +
	"\treturn nil\n" +
	"}\n" +
	"\n" +
	"func (self *Holder) leaksItAndIsUnexported() []byte {\n" +
	"\treturn self.epochSecret\n" +
	"}\n"

// epochSecretHolderTypes is the compiled type behind each source type that keeps the epoch
// secret, so a source reading of a holder's surface can be compared against a reflection of
// the same type. It is checked against the derived closure in both directions, like
// epochSecretHolderSweeps, so a second holder cannot land here unread.
var epochSecretHolderTypes = map[string]reflect.Type{
	"KeySchedule": reflect.TypeOf((*KeySchedule)(nil)),
}

// TestNoExportedMethodOfThisPackageCanReachTheEpochSecret is the half of guardrail G6 that
// covers a method whose ARGUMENTS a sweep cannot exhaust.
//
// The two gates above read what a call ANSWERS and compare it against epoch_secret. For a
// method that takes no arguments that is complete: reflection calls it the one way it can be
// called and there is no second way. The moment Export joined them it stopped being complete,
// because "the exporter cannot be made to answer epoch_secret" is a claim over every (label,
// context, length) a caller may choose and keyScheduleMethodArgumentRows supplies three of
// them. Measured, not supposed: with
//
//	if label == "recovery" { return bytes.Clone(self.epochSecret), nil }
//
// inserted at the top of Export, the whole of mls and message was green, and a direct probe
// confirmed Export("recovery", nil, 32) then answered epoch_secret verbatim. Sampling an
// unbounded argument space is Standing Rule 5's shape one level in: the class is the
// arguments, and seventeen of them had been enumerated.
//
// So this gate reads the SOURCE, where the argument space does not appear at all. An exported
// method that never mentions the storage cannot answer it under any label, and the class of
// "mentions the storage" is derived by closure over the package's own call graph rather than
// written down -- a leak spelled through a helper is a leak.
//
// It covers every exported method of the package rather than the holder's own, because a
// method on some other type that takes a *KeySchedule reaches the same unexported field and is
// nowhere in a reflection over (*KeySchedule). The two behavioural gates stay: this one says
// the bytes cannot travel, and they say the bytes that DO travel are not the secret.
func TestNoExportedMethodOfThisPackageCanReachTheEpochSecret(t *testing.T) {
	// the control first, on both halves: the closure follows a call into a method and into a
	// function, and the shape filter tells a method with somewhere to put the secret from the
	// erase that has nowhere
	control := []parsedSource{mustParseText(t, "the epoch secret method control", epochSecretMethodControl)}
	controlDeclarations := declaredAcross(control)
	wantReaching := []string{
		"AnswersAnErrorAlone",
		"LeaksItDirectly",
		"LeaksItIntoTheCallersArray",
		"LeaksItThroughAFunction",
		"LeaksItThroughAMethod",
		"Zeroize",
		"leaksItAndIsUnexported",
		"reader",
		"theSecretOf",
	}
	if reaching := theNamesReachingTheEpochSecret(controlDeclarations); !slices.Equal(reaching, wantReaching) {
		t.Fatalf("the closure read %v out of the control as reaching the epoch secret, want %v; it is not seeding on the storage or not following a call",
			reaching, wantReaching)
	}
	wantHandingOut := []string{
		"(*Holder).LeaksItDirectly",
		"(*Holder).LeaksItIntoTheCallersArray",
		"(*Holder).LeaksItThroughAFunction",
		"(*Holder).LeaksItThroughAMethod",
	}
	if handingOut := theExportedMethodsHandingOutWhatTheyReach(controlDeclarations, []string{"[]byte"}); !slices.Equal(handingOut, wantHandingOut) {
		t.Fatalf("the shape filter read %v out of the control, want %v; it is not telling an answer from an erase, or not telling exported from not",
			handingOut, wantHandingOut)
	}

	// then this package's own source
	files := []parsedSource{}
	for _, path := range packageLevelFunctions(t).files {
		files = append(files, mustParseSource(t, path))
	}
	declared := declaredAcross(files)
	reaching := theNamesReachingTheEpochSecret(declared)
	// the positive control on the real source: this package certainly assembles an epoch out
	// of a parent secret, and a derivation that had stopped deriving would say it does not
	if len(reaching) == 0 {
		t.Fatalf("no declaration of this package's source mentions %s, so the class below is empty and this gate demands nothing; if the storage was renamed, rename it in epochSecretStorageField too",
			epochSecretStorageField)
	}
	byteSlices := slices.Concat([]string{"[]byte"}, packageByteSliceTypeNames(t))
	if handingOut := theExportedMethodsHandingOutWhatTheyReach(declared, byteSlices); len(handingOut) != 0 {
		t.Errorf("%v are exported methods that can reach %s and have somewhere to put it -- a result that is not an error, or a byte slice to write through; G6 says no exported symbol of this package returns the parent secret, and no sweep over a method's arguments can rule out the label it answers under",
			handingOut, epochSecretStorageField)
	}
	t.Logf("%d declarations of this package reach %s: %v", len(reaching), epochSecretStorageField, reaching)

	// and the source reading covers every exported method the compiled holder has. An embedded
	// field's methods are promoted onto the type and declared somewhere else entirely, so a
	// holder that grew an embedded surface would be swept by the reflection gate next door and
	// invisible to this one.
	structs := map[string]*ast.StructType{}
	for _, parsed := range files {
		structTypesIn(parsed, structs)
	}
	holders := theTypesHoldingTheEpochSecret(structs)
	for _, holder := range holders {
		if _, known := epochSecretHolderTypes[holder]; !known {
			t.Fatalf("%s keeps the epoch secret and epochSecretHolderTypes has no compiled type for it, so this gate cannot check that its source reading is complete",
				holder)
		}
	}
	for name := range epochSecretHolderTypes {
		if !slices.Contains(holders, name) {
			t.Errorf("epochSecretHolderTypes names a %s and no struct of this package keeps the epoch secret under that name", name)
		}
	}
	for _, holder := range holders {
		compiled := epochSecretHolderTypes[holder]
		reflected := []string{}
		for i := range compiled.NumMethod() {
			reflected = append(reflected, compiled.Method(i).Name)
		}
		slices.Sort(reflected)
		inSource := []string{}
		for _, one := range declared {
			if one.exported && (one.receiver == holder || one.receiver == "*"+holder) {
				inSource = append(inSource, one.name)
			}
		}
		slices.Sort(inSource)
		if !slices.Equal(reflected, inSource) {
			t.Errorf("%s has exported methods %v compiled and %v declared in this package's source; the difference is promoted from an embedded field and this source gate never reads it",
				holder, reflected, inSource)
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
		// the other arguments. The control is itself made with a panic caught, because a
		// defect on the accepting path is a failure of this test and not a reason for the
		// test BINARY to stop -- every gate declared after this one would report nothing.
		var accepted error
		if recovered := recoveredPanic(func() { accepted = covered[name](ksVectorEpoch0GroupContext(t)) }); recovered != nil {
			t.Errorf("%s: a real group context panicked with %v", name, recovered)
			continue
		}
		if accepted != nil {
			t.Errorf("%s: a real group context was refused: %v", name, accepted)
			continue
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

// scheduleFromEpochSecretRecovering builds a group creation schedule with a panic caught
// rather than taken.
//
// This is the one entry point whose joiner_secret and welcome_secret are nil, so it is where
// a derivation reaching for the wrong parent raises out of the kdf instead of answering. An
// uncaught raise stops the test BINARY, and every gate declared after it in this package
// then reports nothing at all -- see recoveringRow, which records what that cost. A nil
// answer means this helper already said what went wrong and the caller moves on to the next
// row rather than to the next test.
func scheduleFromEpochSecretRecovering(
	t *testing.T,
	at string,
	crypto CryptoProvider,
	epochSecret []byte,
	groupContext *GroupContext,
) *KeySchedule {
	t.Helper()
	var schedule *KeySchedule
	var err error
	recovered := recoveredPanic(func() {
		schedule, err = NewKeyScheduleFromEpochSecret(crypto, epochSecret, groupContext)
	})
	if recovered != nil {
		t.Errorf("%s: NewKeyScheduleFromEpochSecret panicked with %v rather than answering", at, recovered)
		return nil
	}
	if err != nil {
		t.Errorf("%s: NewKeyScheduleFromEpochSecret: %v", at, err)
		return nil
	}
	return schedule
}

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

		fromEpoch := scheduleFromEpochSecretRecovering(t, epoch.at, epoch.crypto, epochSecret, epoch.groupContext)
		if fromEpoch == nil {
			continue
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
		schedule := scheduleFromEpochSecretRecovering(
			t, at, crypto, crypto.Random(crypto.HashSize()), ksVectorEpoch0GroupContext(t))
		if schedule == nil {
			continue
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
// Retaining it would make the epoch's parent secret a window onto a buffer the caller
// still owns, and the caller of this is a NewGroup that just sampled KDF.Nh bytes and is
// about to erase them — which would erase the live epoch's parent instead of its own copy.
//
// What this reads is the unexported field, because nothing else can see the property. The
// nine are derived at construction, so they are already their own storage whether the
// parent was copied or not: a test that erased the sample and compared the nine passes
// over both implementations, which is what the first version of this test did. Reading
// the field is not a widening of anything — G6 is about what the type EXPORTS, and
// TestNoExportedSurfaceOfTheKeyScheduleReturnsTheEpochSecret is what holds that; a test
// in the same package is where a white box property like this one belongs.
func TestNewKeyScheduleFromEpochSecretCopiesTheSample(t *testing.T) {
	for _, suite := range Suites() {
		crypto := mustProvider(t, suite)
		at := fmt.Sprintf("suite %#04x", uint16(suite))
		sample := crypto.Random(crypto.HashSize())
		kept := bytes.Clone(sample)
		schedule := scheduleFromEpochSecretRecovering(t, at, crypto, sample, ksVectorEpoch0GroupContext(t))
		if schedule == nil {
			continue
		}
		// the control: the sample was read at all, so the comparisons below are not
		// satisfied by a constructor that never looked at its argument
		if len(schedule.epochSecret) != crypto.HashSize() {
			t.Fatalf("%s: the epoch holds %d bytes as its parent, want KDF.Nh = %d",
				at, len(schedule.epochSecret), crypto.HashSize())
		}
		if !bytes.Equal(schedule.epochSecret, kept) {
			t.Fatalf("%s: the epoch's parent is not the sample it was handed", at)
		}
		if &schedule.epochSecret[0] == &sample[0] {
			t.Errorf("%s: the epoch retained the caller's sample rather than copying it", at)
		}
		// and the consequence, read the way a caller would produce it: whoever sampled the
		// secret erases its own copy, and the live epoch is unmoved
		zeroizeSecret(sample)
		if !bytes.Equal(schedule.epochSecret, kept) {
			t.Errorf("%s: erasing the caller's sample cleared the epoch's own parent secret", at)
		}
	}
}

// ---------------------------------------------------------------------------
// KDF.Nh is read off the provider, over every construction handed one
//
// Both registered suites fix Nh at 32, so nothing already in this tree separates a body
// that reads KDF.Nh off the provider it was handed from one that writes 32 down. The two
// gates above supply that input for two hand picked functions. This supplies it for the
// class.
//
// Measured, not supposed: nh := crypto.HashSize() replaced by nh := 32 in
// NewKeyScheduleFromJoiner left the whole of mls and message green, and so did the same
// substitution in NewKeyScheduleFromJoiner and NewKeyScheduleFromEpochSecret at once. Not a
// wrong answer today — it is a gate that would not fire on the day a third suite lands,
// which is the day it exists for, and suite.go's own file comment asserts the class it
// violates: "Every length check in the package reads a field of it rather than a literal, so
// a suite added later cannot leave a hardcoded 32 behind in code that was only ever
// exercised at 32."
// ---------------------------------------------------------------------------

// kdfNhCoincidences is the positions at which two runs of one construction disagree about
// whether a length is KDF.Nh.
//
// The property is stated as an equivalence rather than as a length: an answer that is KDF.Nh
// bytes over one provider must be KDF.Nh bytes over the other, whichever provider that is.
// A body that writes 32 down answers 32 over both, so over the narrow provider the length
// IS Nh and over the wide one it is not, and the position is reported. A body that reads the
// provider answers 32 and then 48 and reports nothing. Both directions are compared, because
// a length hardcoded at 48 is the same defect written the other way round.
func kdfNhCoincidences(narrow [][]byte, wide [][]byte, narrowNh int, wideNh int) []int {
	found := []int{}
	for i := range min(len(narrow), len(wide)) {
		if (len(narrow[i]) == narrowNh) != (len(wide[i]) == wideNh) {
			found = append(found, i)
		}
	}
	return found
}

// constructionsWhoseAnswerOnlyCoincidesWithKdfNh is a construction the equivalence above
// cannot hold, named with the reason. The gate checks every name here against the derived
// class, so an entry cannot outlive the construction it excuses.
var constructionsWhoseAnswerOnlyCoincidesWithKdfNh = map[string]string{
	// the first of its two answers is the KEM output, which is Nenc bytes. X25519 fixes
	// Nenc at 32 and the narrow suite's KDF.Nh is also 32, so the equality is the suite's
	// coincidence rather than anything this construction did; the kdf getting wider does
	// not make an X25519 public key wider. Its other answer is the ciphertext, which is
	// the plaintext plus the aead tag and is not a kdf length either.
	"EncryptWithLabel": "answers a KEM output at Nenc and a ciphertext at Nt, neither of which is KDF.Nh; Nenc coincides with Nh at 32 under the narrow suite",
}

// scheduleAnswersThatAreNotKdfLengths names one ANSWER of an exported method of *KeySchedule
// that the KDF.Nh equivalence below cannot hold, with the reason. It is the same excuse
// constructionsWhoseAnswerOnlyCoincidesWithKdfNh carries for a package level construction,
// one level down: the schedule's answers reach that gate through the rows that build a
// schedule, so a method answering something that is not a kdf length cannot be excused by
// naming the construction without excusing the whole epoch with it.
//
// Keyed per answer rather than per method, which is the tighter form exposedSlice was given a
// position for. Keyed on ExternalKeyPair alone this excused EVERY answer of that method, so a
// third result that IS a kdf length would have joined the excuse by existing and left the
// differential silent about it. Two results today, two lines.
//
// Every entry is checked against the type, against the method's own arity and against the
// sweep's own output, so an excuse cannot outlive the method it names, cannot name a result
// position the method does not have, and cannot sit here excusing nothing.
var scheduleAnswersThatAreNotKdfLengths = map[exposedAnswerAt]string{
	{method: "ExternalKeyPair", result: 0}: "the hpke private key, which is Nsk; X25519 fixes it at 32 and the narrow suite's KDF.Nh is also 32, so the equality is that suite's coincidence rather than anything this method did, and a kdf getting wider does not make an X25519 key wider",
	{method: "ExternalKeyPair", result: 1}: "the hpke public key, which is Npk; the same coincidence at 32 and the same reason a wider kdf does not widen it",
}

// scheduleStorageReaders is how this gate reads each byte slice a *KeySchedule keeps behind
// its accessors.
//
// epoch_secret is where a hardcoded KDF.Nh sits unobserved from outside the type. The nine
// secrets derived from it are expanded at the provider's own width whatever width their
// parent had, and the parent itself must never reach an exported symbol -- that is guardrail
// G6 -- so a parent truncated to 32 bytes under a 48 byte kdf is invisible to every gate that
// reads only what the epoch hands out. This is the reading that sees it, and it is available
// because these tests are the package's own.
//
// The keys are checked against the type's own fields by reflection in both directions, so a
// fifth byte slice field cannot land unread.
var scheduleStorageReaders = map[string]func(schedule *KeySchedule) []byte{
	"groupContextBytes": func(schedule *KeySchedule) []byte { return schedule.groupContextBytes },
	"joinerSecret":      func(schedule *KeySchedule) []byte { return schedule.joinerSecret },
	"welcomeSecret":     func(schedule *KeySchedule) []byte { return schedule.welcomeSecret },
	"epochSecret":       func(schedule *KeySchedule) []byte { return schedule.epochSecret },
}

// bytesTheScheduleKeeps is everything the type holds: what its exported surface hands out,
// followed by the storage behind it, in a fixed order so two runs of one construction compare
// position by position.
func bytesTheScheduleKeeps(t *testing.T, at string, schedule *KeySchedule) [][]byte {
	t.Helper()
	byteSlice := reflect.TypeOf([]byte(nil))
	fields := []string{}
	valueType := reflect.TypeOf(schedule).Elem()
	for i := range valueType.NumField() {
		if valueType.Field(i).Type != byteSlice {
			continue
		}
		name := valueType.Field(i).Name
		fields = append(fields, name)
		if _, read := scheduleStorageReaders[name]; !read {
			t.Fatalf("KeySchedule keeps a []byte field %s that scheduleStorageReaders has no reader for, so its length falls outside every comparison this gate makes",
				name)
		}
	}
	for name := range scheduleStorageReaders {
		if !slices.Contains(fields, name) {
			t.Errorf("scheduleStorageReaders reads %s, which KeySchedule does not declare as a []byte field", name)
		}
	}
	slices.Sort(fields)
	handedOut, _ := bytesTheScheduleHandsOut(t, at, schedule)
	kept := [][]byte{}
	dropped := map[exposedAnswerAt]bool{}
	for _, one := range handedOut {
		if _, notAKdfLength := scheduleAnswersThatAreNotKdfLengths[one.at()]; notAKdfLength {
			dropped[one.at()] = true
			continue
		}
		kept = append(kept, one.bytes)
	}
	for answer, reason := range scheduleAnswersThatAreNotKdfLengths {
		method, found := reflect.TypeOf(schedule).MethodByName(answer.method)
		if !found {
			t.Errorf("scheduleAnswersThatAreNotKdfLengths excuses %s, which *KeySchedule does not declare", answer)
			continue
		}
		// an excuse for a result position the method does not have is an excuse that can
		// never fire, and the sweep below would drop nothing while the table looked complete
		if answer.result >= method.Type.NumOut() {
			t.Errorf("scheduleAnswersThatAreNotKdfLengths excuses %s and that method answers %d results",
				answer, method.Type.NumOut())
			continue
		}
		// an excuse that dropped nothing is an excuse for an answer the sweep is no longer
		// reading, which is the shape that leaves this gate looking complete while covering
		// less than it did
		if !dropped[answer] {
			t.Errorf("scheduleAnswersThatAreNotKdfLengths excuses %s (%s) and the sweep read no such answer to drop",
				answer, reason)
		}
	}
	for _, name := range fields {
		kept = append(kept, scheduleStorageReaders[name](schedule))
	}
	return kept
}

// TestEveryConstructionHandedAProviderReadsKdfNhFromIt is the differential the registered
// suites cannot supply, over the class rather than over two functions of it.
//
// The class is every package level construction of this package that takes a CryptoProvider,
// read off the parse tree by the same scan TestEveryConstructionHandedAProviderRoutesThroughIt
// reads, and each has to have a row here. A construction added later fails this until
// somebody writes one, which is what makes the class the package's rather than this test's.
//
// The two providers are the registered suite and the same suite with its whole hash and kdf
// surface one width up. Coherence matters: see the wide provider's own comment. What is
// compared is only whether a length IS the provider's Nh, so a construction whose answers
// have nothing to do with the kdf reports nothing without needing to be excused for it.
func TestEveryConstructionHandedAProviderReadsKdfNhFromIt(t *testing.T) {
	// the constant reader is what makes EncryptWithLabel answer the same ciphertext twice;
	// over the process entropy source its rows would compare two unrelated messages
	narrow := mustProviderOver(t, CipherSuiteX25519ChaCha20Sha256Ed25519, constantReader{value: 0x35})
	wide := &wideKdfProvider{CryptoProvider: narrow}
	if narrow.HashSize() == wide.HashSize() {
		t.Fatalf("both providers answer KDF.Nh %d, so every row below compares a length against itself",
			narrow.HashSize())
	}

	value := bytes.Repeat([]byte{0x21}, 96)
	priv, pub, err := narrow.DeriveKeyPair(bytes.Repeat([]byte{0x22}, 32))
	if err != nil {
		t.Fatalf("derive the key pair the labelled rows are built over: %v", err)
	}
	// deliberately neither 32 nor 48 long, so the labelled rows do not report a coincidence
	// that belongs to the plaintext this test chose
	plaintext := []byte("seven..")
	sealedKemOutput, sealedCiphertext, err := EncryptWithLabel(narrow, pub, "UpdatePathNode", value, plaintext)
	if err != nil {
		t.Fatalf("seal the message the DecryptWithLabel rows read: %v", err)
	}
	// the serialized group context travels through the schedule rows as one of the answers
	// the epoch hands out, and it is the same bytes over both providers. A context that
	// happened to be KDF.Nh octets long would therefore read as a written down length, so
	// the coincidence is ruled out here rather than discovered as a failure in a row.
	encodedGroupContext, err := syntax.Marshal(ksVectorEpoch0GroupContext(t))
	if err != nil {
		t.Fatalf("encode the group context the schedule rows are built over: %v", err)
	}
	if len(encodedGroupContext) == narrow.HashSize() || len(encodedGroupContext) == wide.HashSize() {
		t.Fatalf("the published epoch 0 group context encodes to %d octets, which is one of the two KDF.Nh values this gate compares against",
			len(encodedGroupContext))
	}

	// every schedule row answers through the type's own exported surface, so the nine
	// derived secrets, the joiner secret and the welcome secret are all read
	scheduleAnswers := func(t *testing.T, at string, schedule *KeySchedule, err error) [][]byte {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", at, err)
		}
		return bytesTheScheduleKeeps(t, " over a provider whose KDF.Nh is "+
			strconv.Itoa(schedule.crypto.HashSize()), schedule)
	}

	covered := []string{}
	compared := 0
	coincidences := 0
	for _, testCase := range []struct {
		name string
		call func(t *testing.T, crypto CryptoProvider) [][]byte
	}{
		{name: "RefHash", call: func(t *testing.T, crypto CryptoProvider) [][]byte {
			return [][]byte{RefHash(crypto, "MLS 1.0 a label", value)}
		}},
		{name: "MakeKeyPackageRef", call: func(t *testing.T, crypto CryptoProvider) [][]byte {
			return [][]byte{MakeKeyPackageRef(crypto, value)}
		}},
		{name: "MakeProposalRef", call: func(t *testing.T, crypto CryptoProvider) [][]byte {
			return [][]byte{MakeProposalRef(crypto, value)}
		}},
		{name: "EncryptWithLabel", call: func(t *testing.T, crypto CryptoProvider) [][]byte {
			kemOutput, ciphertext, sealErr := EncryptWithLabel(crypto, pub, "UpdatePathNode", value, plaintext)
			if sealErr != nil {
				t.Fatalf("EncryptWithLabel: %v", sealErr)
			}
			return [][]byte{kemOutput, ciphertext}
		}},
		{name: "DecryptWithLabel", call: func(t *testing.T, crypto CryptoProvider) [][]byte {
			opened, openErr := DecryptWithLabel(crypto, priv, "UpdatePathNode", value,
				sealedKemOutput, sealedCiphertext)
			if openErr != nil {
				t.Fatalf("DecryptWithLabel: %v", openErr)
			}
			return [][]byte{opened}
		}},
		{name: "ZeroSecret", call: func(t *testing.T, crypto CryptoProvider) [][]byte {
			return [][]byte{ZeroSecret(crypto)}
		}},
		{name: "DeriveJoinerSecret", call: func(t *testing.T, crypto CryptoProvider) [][]byte {
			nh := crypto.HashSize()
			joiner, joinerErr := DeriveJoinerSecret(crypto,
				bytes.Repeat([]byte{0x71}, nh), bytes.Repeat([]byte{0x72}, nh),
				ksVectorEpoch0GroupContext(t))
			if joinerErr != nil {
				t.Fatalf("DeriveJoinerSecret: %v", joinerErr)
			}
			return [][]byte{joiner}
		}},
		{name: "NewKeySchedule", call: func(t *testing.T, crypto CryptoProvider) [][]byte {
			nh := crypto.HashSize()
			schedule, scheduleErr := NewKeySchedule(crypto,
				bytes.Repeat([]byte{0x73}, nh), bytes.Repeat([]byte{0x74}, nh),
				bytes.Repeat([]byte{0x75}, nh), ksVectorEpoch0GroupContext(t))
			return scheduleAnswers(t, "NewKeySchedule", schedule, scheduleErr)
		}},
		{name: "NewKeyScheduleFromJoiner", call: func(t *testing.T, crypto CryptoProvider) [][]byte {
			nh := crypto.HashSize()
			schedule, scheduleErr := NewKeyScheduleFromJoiner(crypto,
				bytes.Repeat([]byte{0x76}, nh), bytes.Repeat([]byte{0x77}, nh),
				ksVectorEpoch0GroupContext(t))
			return scheduleAnswers(t, "NewKeyScheduleFromJoiner", schedule, scheduleErr)
		}},
		{name: "NewKeyScheduleFromEpochSecret", call: func(t *testing.T, crypto CryptoProvider) [][]byte {
			schedule, scheduleErr := NewKeyScheduleFromEpochSecret(crypto,
				bytes.Repeat([]byte{0x78}, crypto.HashSize()), ksVectorEpoch0GroupContext(t))
			return scheduleAnswers(t, "NewKeyScheduleFromEpochSecret", schedule, scheduleErr)
		}},
		{name: "newKeyScheduleFromParts", call: func(t *testing.T, crypto CryptoProvider) [][]byte {
			nh := crypto.HashSize()
			schedule := newKeyScheduleFromParts(crypto, encodedGroupContext,
				bytes.Repeat([]byte{0x79}, nh), bytes.Repeat([]byte{0x7a}, nh),
				bytes.Repeat([]byte{0x7b}, nh))
			return scheduleAnswers(t, "newKeyScheduleFromParts", schedule, nil)
		}},
	} {
		covered = append(covered, testCase.name)
		overTheNarrowProvider, raised := recoveringRow(func() [][]byte { return testCase.call(t, narrow) })
		if raised != nil {
			t.Errorf("%s panicked with %v over a provider whose KDF.Nh is %d", testCase.name, raised, narrow.HashSize())
			continue
		}
		overTheWideProvider, raised := recoveringRow(func() [][]byte { return testCase.call(t, wide) })
		if raised != nil {
			t.Errorf("%s panicked with %v over a provider whose KDF.Nh is %d; a construction that reads its lengths off the provider it was handed works at either width",
				testCase.name, raised, wide.HashSize())
			continue
		}
		if len(overTheNarrowProvider) != len(overTheWideProvider) {
			t.Errorf("%s answered %d results at KDF.Nh %d and %d at KDF.Nh %d",
				testCase.name, len(overTheNarrowProvider), narrow.HashSize(),
				len(overTheWideProvider), wide.HashSize())
			continue
		}
		if len(overTheNarrowProvider) == 0 {
			t.Errorf("%s answered nothing, so this row compared no length", testCase.name)
			continue
		}
		for _, answer := range overTheNarrowProvider {
			compared++
			if len(answer) == narrow.HashSize() {
				coincidences++
			}
		}
		if reason, excused := constructionsWhoseAnswerOnlyCoincidesWithKdfNh[testCase.name]; excused {
			t.Logf("%s not held to the KDF.Nh equivalence: %s", testCase.name, reason)
			continue
		}
		for _, at := range kdfNhCoincidences(overTheNarrowProvider, overTheWideProvider,
			narrow.HashSize(), wide.HashSize()) {
			t.Errorf("%s answered %d bytes in result %d over a provider whose KDF.Nh is %d and %d bytes over one whose KDF.Nh is %d; exactly one of those is KDF.Nh, so that length is written down rather than read off the provider",
				testCase.name, len(overTheNarrowProvider[at]), at, narrow.HashSize(),
				len(overTheWideProvider[at]), wide.HashSize())
		}
	}

	// the control on the comparison itself. A gate that reported the package clean having
	// compared nothing reports exactly what a complete one reports, so the shape it exists
	// to catch is run through it here and has to be caught, and a shape it must not catch
	// is run through it too.
	writtenDown := func(crypto CryptoProvider) [][]byte { return [][]byte{make([]byte, 32)} }
	if found := kdfNhCoincidences(writtenDown(narrow), writtenDown(wide),
		narrow.HashSize(), wide.HashSize()); !slices.Equal(found, []int{0}) {
		t.Fatalf("the comparison reported %v for a construction that answers a written down 32 bytes whatever provider it is handed, want [0]",
			found)
	}
	readOff := func(crypto CryptoProvider) [][]byte { return [][]byte{ZeroSecret(crypto)} }
	if found := kdfNhCoincidences(readOff(narrow), readOff(wide),
		narrow.HashSize(), wide.HashSize()); len(found) != 0 {
		t.Fatalf("the comparison reported %v for a construction that reads its length off the provider, so every row above is reporting a defect that is not there",
			found)
	}
	// and the rows really did put KDF.Nh lengths through it: a sweep in which no answer was
	// ever Nh long would satisfy the equivalence for every possible implementation
	if coincidences == 0 {
		t.Fatalf("%d answers were compared and none of them was KDF.Nh bytes long over either provider, so this gate held nothing",
			compared)
	}
	t.Logf("%d answers compared across %d constructions, %d of them KDF.Nh bytes at %d",
		compared, len(covered), coincidences, narrow.HashSize())

	// and the table names every construction of this package that takes a provider rather
	// than the ones this test happened to think of
	declared := packageLevelFunctionsTaking(t, providerInterfaceName)
	slices.Sort(covered)
	if !slices.Equal(covered, declared) {
		t.Errorf("this gate covers %v, and the package declares %v", covered, declared)
	}
	for name := range constructionsWhoseAnswerOnlyCoincidesWithKdfNh {
		if !slices.Contains(declared, name) {
			t.Errorf("the gate excuses %s from the KDF.Nh equivalence, and no construction of this package declares it", name)
		}
	}
}

// TestEveryAccessorAnsweringAPointerAnswersIntoTheSchedulesOwnStorage observes the sentence
// above Secrets(): "The pointer is into the schedule's own storage, which is what lets the
// epoch erase them in place."
//
// A body that answered a pointer to a COPY of the struct — copied := self.secrets; return
// &copied — still shares the nine backing arrays, so an erase that overwrites bytes stays
// visible and every other test of this package passes. Measured, not supposed: the whole of
// mls and message was green over that edit. What it breaks is the other spelling of the erase
// this plan's task 12 will write: a Zeroize that NILS the fields leaves the
// returned copy holding nine live keys, and the caller reading through it has an epoch's
// worth of secrets the group believes are gone.
//
// The class is read off the type rather than named: every exported method of *KeySchedule
// that takes no argument and answers a pointer, so an accessor added later joins by
// existing. Three things are asserted, because each is satisfiable by a different wrong
// implementation — two calls answer the same pointer, a write through it is visible to the
// next call, and two schedules answer different pointers, which is what separates "into the
// schedule's own storage" from "into a package level singleton".
func TestEveryAccessorAnsweringAPointerAnswersIntoTheSchedulesOwnStorage(t *testing.T) {
	epochs := ksVectorEpochs(t)
	if len(epochs) < 2 {
		t.Fatalf("the corpus answered for %d epochs and the last assertion here needs two schedules", len(epochs))
	}
	answered := []string{}
	scheduleType := reflect.TypeOf((*KeySchedule)(nil))
	for i := range scheduleType.NumMethod() {
		method := scheduleType.Method(i)
		if method.Type.NumIn() != 1 || method.Type.NumOut() != 1 || method.Type.Out(0).Kind() != reflect.Pointer {
			continue
		}
		answered = append(answered, method.Name)
		pointerOf := func(schedule *KeySchedule) uintptr {
			return method.Func.Call([]reflect.Value{reflect.ValueOf(schedule)})[0].Pointer()
		}
		schedule := epochs[0].schedule(t)
		first, second := pointerOf(schedule), pointerOf(schedule)
		if first == 0 {
			t.Errorf("(*KeySchedule).%s answered nil, so this row observed nothing", method.Name)
			continue
		}
		if first != second {
			t.Errorf("(*KeySchedule).%s answered a different address on each call, so it is handing back a copy rather than the schedule's own storage; an erase that nils the fields would leave that copy holding live keys",
				method.Name)
		}
		if other := pointerOf(epochs[1].schedule(t)); other == first {
			t.Errorf("(*KeySchedule).%s answered the same address for two different schedules, so it is not answering into either one's own storage",
				method.Name)
		}
	}
	if len(answered) == 0 {
		t.Fatal("no exported method of *KeySchedule answers a pointer, so this gate swept nothing; Secrets() is one")
	}

	// and the write through, which is the property the aliasing exists for. Reflection can
	// say two calls agree on an address; only a write says the address is the storage the
	// schedule itself reads.
	schedule := epochs[0].schedule(t)
	secrets := schedule.Secrets()
	kept := secrets.InitSecret
	secrets.InitSecret = nil
	if schedule.Secrets().InitSecret != nil {
		t.Error("a field nilled through the pointer Secrets() answered is still set when the schedule is asked again, so that pointer is not into the schedule's own storage")
	}
	secrets.InitSecret = kept
	if !bytes.Equal(schedule.Secrets().InitSecret, kept) {
		t.Error("restoring the field through the same pointer did not reach the schedule, so this row proved nothing about either direction")
	}
}

// TestPastEpochWindowIsThePromisedThirtyTwoEpochs pins the exported constant.
//
// Nothing consumes it yet — the retention it bounds is this plan's task 12 — so there is no
// behaviour to observe and until that task lands the value can be changed to anything with
// the whole package green. Measured, not supposed: 32 replaced by 8 left green the whole of
// mls and message.
//
// It is pinned rather than left because it is already exported, and because the number is a
// product promise rather than a tuning constant: key_schedule.go's own comment argues for it
// against exactly the value a mutation restores — "Thirty-two rather than eight because the
// window is a product promise about how long a laptop may stay closed, and an active group
// can burn eight epochs in a day." A task that means to change it changes this line in the
// same commit, which is a line a reviewer sees.
func TestPastEpochWindowIsThePromisedThirtyTwoEpochs(t *testing.T) {
	if PastEpochWindow != 32 {
		t.Errorf("PastEpochWindow is %d and the promise written above it is thirty-two epochs; if the window is meant to change, change the comment that argues for it and this line together",
			PastEpochWindow)
	}
}

// Task 7: the committer's path and the joiner's path reach one epoch.
//
// This is the first property in this file about two derivations rather than one, and the
// shape it invites cannot fail. The two paths share code -- NewKeySchedule is
// DeriveJoinerSecret followed by NewKeyScheduleFromJoiner -- so
//
//	committer, _ := NewKeySchedule(crypto, initPrev, commitSecret, pskSecret, groupContext)
//	joiner, _ := NewKeyScheduleFromJoiner(crypto, committer.JoinerSecret(), pskSecret, groupContext)
//
// compares one deterministic function against itself on one argument. It reports PASS
// against every implementation of NewKeyScheduleFromJoiner there is, including one that
// derives the epoch from the joiner secret rather than the member secret, one that drops
// psk_secret, and one that returns nine copies of the same byte. That is the shape the plan
// hands this task, and it is written down here rather than fixed silently because the same
// shape will be reachable again in p5 and p6 wherever a joiner is checked against a
// committer.
//
// What separates the two paths is a third derivation neither of them performs: RFC 9420
// section 8 written out below in terms of crypto/hmac, which this package does not derive
// with. The joiner is handed a joiner_secret that reference produced rather than one the
// committer produced, and both schedules are compared against the reference as well as
// against each other -- so an epoch reached by the wrong route disagrees with it even when
// both paths take that route together.
//
// The reference is admissible only because it is anchored outside this tree:
// TestTheHandWrittenSectionEightDerivationReproducesThePublishedEpochs requires it to
// reproduce all 110 answers mlswg published before any comparison below rests on it. A
// second copy of the same mistake agrees with the first, and only somebody else's numbers
// separate them.

// ksGeneratedEpochCases is how many generated epochs each registered suite contributes to
// the space the two paths are compared over.
//
// A worked example pins the epoch it was taken from. What the RFC lets vary here is the
// previous init secret, the commit secret, the psk secret and every field of the
// GroupContext -- and the published corpus holds four of the context's seven fixed across
// all ten of its epochs, so the space below is where an epoch number in the high half, an
// unregistered version, a non empty extensions vector and a group id of another length
// reach the joiner path at all.
const ksGeneratedEpochCases = 24

// ksStream is the deterministic byte source the generated space is drawn from: sha256 over
// a seed and a counter.
//
// Deterministic rather than random, because a failing case has to reproduce. A generated
// space drawn from crypto/rand finds the defect once, on somebody's machine, and the next
// run is a different space that says nothing about whether the fix worked.
type ksStream struct {
	seed    string
	counter uint64
	buffer  []byte
}

// take answers the next n bytes of the stream. Blocks are consumed in order and a partial
// block is carried, so the same seed yields the same bytes whatever sizes the caller asks
// for them in.
func (self *ksStream) take(n int) []byte {
	out := make([]byte, 0, n)
	for len(out) < n {
		if len(self.buffer) == 0 {
			block := sha256.Sum256(fmt.Appendf(nil, "%s/%d", self.seed, self.counter))
			self.counter++
			self.buffer = block[:]
		}
		taken := min(n-len(out), len(self.buffer))
		out = append(out, self.buffer[:taken]...)
		self.buffer = self.buffer[taken:]
	}
	return out
}

// ksHandVarint is the RFC 9420 section 2.1.2 variable length prefix, written here rather
// than reached through syntax so the preimages below owe nothing to the encoder this
// package derives with.
//
// Only the one and two octet forms are written and a longer field is fatal rather than
// truncated. A prefix written at the wrong width produces a perfectly well formed secret
// that no peer derives, which is the failure mode this file exists to catch, and a
// reference that could commit it silently would agree with an implementation that had.
func ksHandVarint(t *testing.T, what string, length int) []byte {
	t.Helper()
	switch {
	case length < 64:
		return []byte{byte(length)}
	case length < 16384:
		return []byte{0x40 | byte(length>>8), byte(length)}
	default:
		t.Fatalf("%s is %d octets, past the two octet prefix this hand written encoder writes", what, length)
		return nil
	}
}

// ksHandExtract is HKDF-Extract: HMAC with the salt as the key and the input keying
// material as the message, in the (salt, ikm) order every spec text writes.
//
// Written out rather than delegated to crypto/hkdf, which takes those two the other way
// round. That transposition is guardrail 1 and it is the one mistake in this package a
// self consistent implementation reproduces perfectly, so a reference that called the
// library would reproduce it too and report agreement.
func ksHandExtract(salt []byte, ikm []byte) []byte {
	extract := hmac.New(sha256.New, salt)
	extract.Write(ikm)
	return extract.Sum(nil)
}

// ksHandExpandWithLabel is ExpandWithLabel: HKDF-Expand over the serialized
// struct { uint16 length; opaque label<V>; opaque context<V> }, with the "MLS 1.0 " prefix
// spelled out here rather than read from MlsLabelPrefix.
//
// One output block only. Every expansion section 8 performs asks for KDF.Nh bytes and
// KDF.Nh is one sha256 output, so the RFC 5869 counter loop would be untested code in a
// reference whose only job is to be obviously right; a longer request is refused instead.
func ksHandExpandWithLabel(t *testing.T, secret []byte, label string, context []byte, length int) []byte {
	t.Helper()
	if length <= 0 || length > sha256.Size {
		t.Fatalf("the hand written expansion was asked for %d octets and writes one sha256 block of %d",
			length, sha256.Size)
	}
	labelled := "MLS 1.0 " + label
	info := []byte{byte(length >> 8), byte(length)}
	info = append(info, ksHandVarint(t, "the label "+labelled, len(labelled))...)
	info = append(info, labelled...)
	info = append(info, ksHandVarint(t, "the context", len(context))...)
	info = append(info, context...)
	expand := hmac.New(sha256.New, secret)
	expand.Write(info)
	expand.Write([]byte{0x01})
	return expand.Sum(nil)[:length]
}

// ksHandDeriveSecret is DeriveSecret: ExpandWithLabel at KDF.Nh over an EMPTY context,
// which is one zero length prefix octet and not an absent field. The difference is one
// byte of preimage and nothing but a published answer can see it.
func ksHandDeriveSecret(t *testing.T, secret []byte, label string) []byte {
	t.Helper()
	return ksHandExpandWithLabel(t, secret, label, nil, sha256.Size)
}

// ksHandJoinerSecret is the half of the section 8 chain only a committer performs:
//
//	joiner_secret = ExpandWithLabel(
//	    KDF.Extract(init_secret_[n-1], commit_secret), "joiner", GroupContext_[n], KDF.Nh)
func ksHandJoinerSecret(t *testing.T, initSecretPrev []byte, commitSecret []byte, groupContext []byte) []byte {
	t.Helper()
	return ksHandExpandWithLabel(
		t, ksHandExtract(initSecretPrev, commitSecret), "joiner", groupContext, sha256.Size)
}

// ksHandEpochLabels is the RFC 9420 section 8 label each field of EpochSecrets is expanded
// under, keyed by the field name so the map is comparable with the type rather than with a
// reading of key_schedule.go.
//
// This is a transcription and it is meant to be one: it is a SECOND independent reading of
// the RFC, which is what a differential comparison is made of. What stops it drifting into
// a copy of the implementation's list is that neither side reads the other, and that both
// are held to the published corpus by the anchor test below. What stops it going stale is
// ksHandEpochSecrets, which requires the two key sets to match exactly in both directions.
var ksHandEpochLabels = map[string]string{
	"SenderData":         "sender data",
	"Encryption":         "encryption",
	"Exporter":           "exporter",
	"External":           "external",
	"Confirmation":       "confirm",
	"Membership":         "membership",
	"ResumptionPsk":      "resumption",
	"EpochAuthenticator": "authentication",
	"InitSecret":         "init",
}

// ksHandEpoch is one epoch derived by hand: the welcome secret and every derived secret,
// keyed by the EpochSecrets field the answer belongs to.
//
// epoch_secret is deliberately not a field, for the reason EpochSecrets does not carry one
// (guardrail 6). The reference has no more need to hand it out than the implementation
// does.
type ksHandEpoch struct {
	welcomeSecret []byte
	secrets       map[string][]byte
}

// ksHandEpochSecrets is the half of the section 8 chain a member added by Welcome
// performs, and the only half it can:
//
//	member_secret  = KDF.Extract(joiner_secret, psk_secret)
//	welcome_secret = DeriveSecret(member_secret, "welcome")
//	epoch_secret   = ExpandWithLabel(member_secret, "epoch", GroupContext_[n], KDF.Nh)
//
// The nine are driven by the field names reflection read off EpochSecrets, and a field
// with no label here is fatal rather than skipped: a tenth secret added to the type would
// otherwise fall outside every comparison below while all of them still reported PASS. The
// count is checked in the other direction too, because a label left behind by a field that
// was renamed is a derivation nothing compares against anything.
func ksHandEpochSecrets(t *testing.T, joinerSecret []byte, pskSecret []byte, groupContext []byte) ksHandEpoch {
	t.Helper()
	memberSecret := ksHandExtract(joinerSecret, pskSecret)
	epochSecret := ksHandExpandWithLabel(t, memberSecret, "epoch", groupContext, sha256.Size)
	epoch := ksHandEpoch{
		welcomeSecret: ksHandDeriveSecret(t, memberSecret, "welcome"),
		secrets:       map[string][]byte{},
	}
	for _, field := range epochSecretFieldNames(t) {
		label, written := ksHandEpochLabels[field]
		if !written {
			t.Fatalf("EpochSecrets.%s has no label in ksHandEpochLabels, so the hand written derivation answers nothing for it and every comparison below would pass over the field in silence",
				field)
		}
		epoch.secrets[field] = ksHandDeriveSecret(t, epochSecret, label)
	}
	if len(epoch.secrets) != len(ksHandEpochLabels) {
		t.Fatalf("EpochSecrets declares %d secrets and ksHandEpochLabels holds %d labels; a label with no field is a derivation nothing is compared against",
			len(epoch.secrets), len(ksHandEpochLabels))
	}
	return epoch
}

// epochSecretFieldNames is the set of secrets an epoch holds, read off the type in sorted
// order so a sweep runs over the class rather than over a list of it. A tenth secret joins
// every sweep that calls this by existing.
func epochSecretFieldNames(t *testing.T) []string {
	t.Helper()
	return slices.Sorted(maps.Keys(epochSecretsByField(t, &EpochSecrets{})))
}

// TestTheHandWrittenSectionEightDerivationReproducesThePublishedEpochs is what makes the
// reference admissible as a second opinion, and it runs before anything rests on it.
//
// A hand written derivation is only a second opinion if it can be wrong in a different way
// from the implementation. Anchoring it on the mlswg corpus is what says it is not a
// paraphrase of key_schedule.go: it reproduces all 110 answers somebody else published, or
// no comparison in the two tests below means anything.
//
// Both Extract calls are checked for symmetry first. A reference that answered the same for
// (a, b) and (b, a) could not see the transposition guardrail 1 exists for, and would agree
// with a swapped implementation while looking like an independent opinion.
func TestTheHandWrittenSectionEightDerivationReproducesThePublishedEpochs(t *testing.T) {
	compared := 0
	for _, epoch := range ksVectorEpochs(t) {
		publishedContext := mustDecodeHex(t, "group_context"+epoch.at, epoch.published.GroupContext)
		joinerSecret := ksHandJoinerSecret(t, epoch.initPrev, epoch.commitSecret, publishedContext)
		if swapped := ksHandJoinerSecret(t, epoch.commitSecret, epoch.initPrev, publishedContext); bytes.Equal(swapped, joinerSecret) {
			t.Fatalf("%s: the hand written joiner derivation answers the same for both Extract argument orders, so it cannot see a transposition",
				epoch.at)
		}
		assertLabelKat(t, "the hand written joiner_secret"+epoch.at, joinerSecret, epoch.published.JoinerSecret)
		compared++

		hand := ksHandEpochSecrets(t, joinerSecret, epoch.pskSecret, publishedContext)
		swapped := ksHandEpochSecrets(t, epoch.pskSecret, joinerSecret, publishedContext)
		if bytes.Equal(swapped.welcomeSecret, hand.welcomeSecret) {
			t.Fatalf("%s: the hand written member derivation answers the same for both Extract argument orders, so it cannot see a transposition",
				epoch.at)
		}
		assertLabelKat(t, "the hand written welcome_secret"+epoch.at, hand.welcomeSecret, epoch.published.WelcomeSecret)
		compared++

		for _, field := range epochSecretFieldNames(t) {
			assertLabelKat(t, "the hand written EpochSecrets."+field+epoch.at,
				hand.secrets[field], publishedEpochSecret(t, field, epoch.published))
			compared++
		}
	}
	if compared != keyScheduleKatEpochComparisons {
		t.Fatalf("compared %d published answers, want %d", compared, keyScheduleKatEpochComparisons)
	}
}

// One generated epoch: the inputs both paths are given, and the encoding of the group
// context they must both expand over.
//
// The encoding is carried rather than re-derived at each use, because the hand written
// reference and the implementation have to be handed the same context bytes for the
// comparison to be about the key schedule. syntax.Marshal is the one thing the reference
// shares with the code under test, and deliberately: the section 8.1 codec has its own
// known answer tests, and a second hand written encoder here would report a codec
// disagreement as a key schedule failure in the wrong file.
type ksGeneratedEpoch struct {
	at           string
	crypto       CryptoProvider
	groupContext *GroupContext
	encoded      []byte
	initPrev     []byte
	commitSecret []byte
	pskSecret    []byte
}

// ksGeneratedEpochs is the space the two paths are compared over: every registered suite,
// crossed with ksGeneratedEpochCases epochs whose secrets and whose whole group context are
// drawn from the deterministic stream.
//
// The suites are taken from the registry rather than named, and the one assumption the
// hand written reference makes -- that the suite's kdf is HKDF-SHA256 at Nh 32 -- is
// asserted against each suite's own parameters. A third suite with another kdf fails here
// and says what to do about it, rather than being compared against a reference computing a
// different primitive.
//
// Two vacuity controls travel with the space. Every case's inputs are required to be
// distinct from every other's, since a generator that had stopped advancing would run the
// same epoch 48 times and report the clean run a varied space reports. And each epoch's two
// Extract arguments are required to differ, because Extract(a, b) and Extract(b, a) agree
// exactly when a == b, so a case whose init and commit secrets coincided would pin nothing
// about the argument order.
func ksGeneratedEpochs(t *testing.T) []ksGeneratedEpoch {
	t.Helper()
	epochs := []ksGeneratedEpoch{}
	for _, suite := range Suites() {
		params, err := LookupSuite(suite)
		if err != nil {
			t.Fatalf("look up suite %#04x: %v", uint16(suite), err)
		}
		if params.KdfId != HpkeKdfHkdfSha256 || params.Nh != sha256.Size {
			t.Fatalf("suite %#04x names kdf %#04x at KDF.Nh %d and the hand written derivation these epochs are compared against is HKDF-SHA256 at %d; teach the reference the new kdf rather than letting the suite go unjudged",
				uint16(suite), uint16(params.KdfId), params.Nh, sha256.Size)
		}
		crypto := mustProvider(t, suite)
		nh := crypto.HashSize()
		stream := &ksStream{seed: fmt.Sprintf("mls/key_schedule/task7/%#04x", uint16(suite))}
		for index := range ksGeneratedEpochCases {
			// the epoch number, big endian off the stream, with the three the corpus can
			// never reach written in: zero, one, and one whose high half is not zero
			epochNumber := uint64(0)
			for _, b := range stream.take(8) {
				epochNumber = epochNumber<<8 | uint64(b)
			}
			switch index {
			case 0:
				epochNumber = 0
			case 1:
				epochNumber = 1
			case 2:
				epochNumber = ^uint64(0)
			}
			// an unregistered version and an unregistered suite code point on some cases:
			// the context carries what it was given, and a preimage that normalised either
			// would still match every published vector, all of which are 0x0001 and 0x0003
			version := ProtocolVersionMls10
			if index%5 == 4 {
				version = ProtocolVersion(0xfafb)
			}
			contextSuite := suite
			if index%7 == 3 {
				contextSuite = CipherSuite(0xf00d)
			}
			// absent, empty, one and two extensions. Every published key schedule vector
			// carries an empty extensions vector, so this is the only place the extension
			// codec reaches an epoch derivation at all.
			var extensions []Extension
			switch index % 4 {
			case 1:
				extensions = []Extension{}
			case 2:
				extensions = []Extension{
					{ExtensionType: ExtensionTypeUrmessageGroupPolicy, ExtensionData: stream.take(1 + index%9)},
				}
			case 3:
				extensions = []Extension{
					{ExtensionType: ExtensionTypeRatchetTree, ExtensionData: stream.take(index % 5)},
					{ExtensionType: ExtensionType(0xf00d), ExtensionData: stream.take(1 + index%13)},
				}
			}
			groupContext := &GroupContext{
				Version:                 version,
				CipherSuite:             contextSuite,
				GroupId:                 stream.take(1 + index%23),
				Epoch:                   epochNumber,
				TreeHash:                stream.take(nh),
				ConfirmedTranscriptHash: stream.take(nh),
				Extensions:              extensions,
			}
			encoded, err := syntax.Marshal(groupContext)
			if err != nil {
				t.Fatalf("suite %#04x generated epoch %d: marshal the group context: %v",
					uint16(suite), index, err)
			}
			epochs = append(epochs, ksGeneratedEpoch{
				at:           fmt.Sprintf(" suite %#04x generated epoch %d", uint16(suite), index),
				crypto:       crypto,
				groupContext: groupContext,
				encoded:      encoded,
				initPrev:     stream.take(nh),
				commitSecret: stream.take(nh),
				pskSecret:    stream.take(nh),
			})
		}
	}
	if want := len(Suites()) * ksGeneratedEpochCases; len(epochs) != want {
		t.Fatalf("the generated space holds %d epochs, want %d", len(epochs), want)
	}
	seen := map[string]string{}
	for _, epoch := range epochs {
		if bytes.Equal(epoch.initPrev, epoch.commitSecret) {
			t.Fatalf("%s: init_secret_[n-1] and commit_secret are the same bytes, so this case agrees with a transposed Extract and pins nothing about the argument order",
				epoch.at)
		}
		key := fmt.Sprintf("%x/%x/%x/%x", epoch.encoded, epoch.initPrev, epoch.commitSecret, epoch.pskSecret)
		if first, repeated := seen[key]; repeated {
			t.Fatalf("%s and %s were generated with identical inputs, so this space is smaller than the count above says",
				first, epoch.at)
		}
		seen[key] = epoch.at
	}
	return epochs
}

// TestTheJoinerPathAndTheCommitterPathReachOneEpoch is the deliverable of this task: a
// member who was in the group at the commit and a member who arrived by Welcome hold the
// same nine secrets, over a generated space rather than at one worked example.
//
// The joiner is handed a joiner_secret the hand written reference produced, NOT the one the
// committer's schedule carries. That is the difference between this test and one that
// cannot fail: NewKeySchedule ends in NewKeyScheduleFromJoiner, so feeding the joiner the
// committer's own answer runs one deterministic function twice on one argument and compares
// the results.
//
// Three comparisons are made per secret and they fail on different mistakes. Committer
// against joiner is the property in the name. Joiner against the reference is what sees a
// mistake INSIDE the shared constructor -- a parent that is not member_secret, a psk secret
// dropped, a label pasted from the line above -- which both paths would otherwise commit
// together and agree about. Committer against the reference is the same for the half of the
// chain only the committer runs, so a joiner derivation that agreed with the reference
// while the committer reached it by another route is still reported.
//
// The nine are driven by the field names reflection read off EpochSecrets rather than by a
// list, so a tenth secret is compared by existing rather than by somebody remembering to
// add it here. The number of comparisons is counted against that field count and against
// the size of the space, because a sweep whose inner loop stopped producing rows reports
// exactly what a complete one reports.
func TestTheJoinerPathAndTheCommitterPathReachOneEpoch(t *testing.T) {
	names := epochSecretFieldNames(t)
	if len(names) == 0 {
		t.Fatal("EpochSecrets read as no fields, so this sweep compares nothing")
	}
	generated := ksGeneratedEpochs(t)
	compared := 0
	for _, epoch := range generated {
		joinerSecret := ksHandJoinerSecret(t, epoch.initPrev, epoch.commitSecret, epoch.encoded)
		if len(joinerSecret) != epoch.crypto.HashSize() {
			t.Fatalf("%s: the hand written joiner secret is %d bytes and KDF.Nh is %d",
				epoch.at, len(joinerSecret), epoch.crypto.HashSize())
		}
		committer, err := NewKeySchedule(
			epoch.crypto, epoch.initPrev, epoch.commitSecret, epoch.pskSecret, epoch.groupContext)
		if err != nil {
			t.Fatalf("%s: NewKeySchedule: %v", epoch.at, err)
		}
		// the joiner is given its own copy of the context, as a real one would be: it
		// decodes the GroupInfo it was sent rather than sharing the committer's struct
		joiner, err := NewKeyScheduleFromJoiner(
			epoch.crypto, joinerSecret, epoch.pskSecret, epoch.groupContext.Clone())
		if err != nil {
			t.Fatalf("%s: NewKeyScheduleFromJoiner: %v", epoch.at, err)
		}
		hand := ksHandEpochSecrets(t, joinerSecret, epoch.pskSecret, epoch.encoded)

		// the committer must have derived the very joiner secret the joiner was handed, or
		// the agreement below would be two schedules agreeing about different epochs
		if !bytes.Equal(committer.JoinerSecret(), joinerSecret) {
			t.Fatalf("%s: the committer derived joiner_secret %x and section 8 gives %x, so the schedules compared below are not two paths into one epoch",
				epoch.at, committer.JoinerSecret(), joinerSecret)
		}
		if !bytes.Equal(committer.WelcomeSecret(), joiner.WelcomeSecret()) {
			t.Errorf("%s: welcome_secret differs between the paths: committer %x, joiner %x",
				epoch.at, committer.WelcomeSecret(), joiner.WelcomeSecret())
		}
		if !bytes.Equal(joiner.WelcomeSecret(), hand.welcomeSecret) {
			t.Errorf("%s: the joiner path derived welcome_secret %x and section 8 gives %x",
				epoch.at, joiner.WelcomeSecret(), hand.welcomeSecret)
		}
		// both paths must have expanded over the same context bytes, and over the ones the
		// codec produces for the context they were given: two schedules that agreed on nine
		// secrets derived over two different preimages would be a coincidence worth hearing
		// about rather than the property in the name
		if !bytes.Equal(committer.GroupContextBytes(), joiner.GroupContextBytes()) {
			t.Errorf("%s: the two paths expanded over different group context bytes: %x and %x",
				epoch.at, committer.GroupContextBytes(), joiner.GroupContextBytes())
		}
		if !bytes.Equal(joiner.GroupContextBytes(), epoch.encoded) {
			t.Errorf("%s: the joiner expanded over %x and the context encodes to %x",
				epoch.at, joiner.GroupContextBytes(), epoch.encoded)
		}

		committerSecrets := epochSecretsByField(t, committer.Secrets())
		joinerSecrets := epochSecretsByField(t, joiner.Secrets())
		for _, name := range names {
			want, derived := hand.secrets[name]
			if !derived {
				t.Fatalf("%s: the hand written derivation answers nothing for EpochSecrets.%s", epoch.at, name)
			}
			if !bytes.Equal(committerSecrets[name], joinerSecrets[name]) {
				t.Errorf("%s: %s differs between the paths: committer %x, joiner %x",
					epoch.at, name, committerSecrets[name], joinerSecrets[name])
			}
			if !bytes.Equal(joinerSecrets[name], want) {
				t.Errorf("%s: the joiner path derived %s = %x and section 8 gives %x",
					epoch.at, name, joinerSecrets[name], want)
			}
			if !bytes.Equal(committerSecrets[name], want) {
				t.Errorf("%s: the committer path derived %s = %x and section 8 gives %x",
					epoch.at, name, committerSecrets[name], want)
			}
			compared++
		}
	}
	if want := len(generated) * len(names); compared != want {
		t.Fatalf("compared %d secrets, want %d", compared, want)
	}
}

// TestTheJoinerPathBindsEveryFieldOfTheGroupContext walks what the corpus cannot: a joiner
// handed the right joiner_secret and a group context that differs in one field must derive
// a different epoch.
//
// This is the failure a joiner cannot detect for itself. It has no previous epoch to
// compare against and no commit to reprocess; the GroupInfo it was sent is the whole of
// what it knows about the group. If a field of that context is not in the preimage, a
// joiner handed a swapped tree hash or a stale epoch number derives the epoch anyway, is
// admitted, and reads traffic from a group whose membership it never verified.
//
// The fields come from mutatedGroupContexts, which builds one case per declared field, so a
// field added to GroupContext by a later plan is judged by existing. Each is required to
// move ALL nine secrets rather than one of them, since epoch_secret is the parent of all
// nine and a field that moved only some of them would mean something stranger than an
// unbound field.
//
// welcome_secret is required NOT to move, which is the same claim from the other side.
// member_secret is Extract(joiner_secret, psk_secret) and the group context enters only at
// the epoch expansion, so a welcome secret that followed the context would be a Welcome no
// peer could open -- and mixing the context in "for safety" is exactly the shape that would
// pass a test asserting only that things change.
func TestTheJoinerPathBindsEveryFieldOfTheGroupContext(t *testing.T) {
	names := epochSecretFieldNames(t)
	fields := reflect.TypeOf(GroupContext{}).NumField()
	if fields == 0 {
		t.Fatal("GroupContext declares no field, so this gate compares nothing")
	}
	generated := ksGeneratedEpochs(t)
	observed := 0
	for _, epoch := range generated {
		joinerSecret := ksHandJoinerSecret(t, epoch.initPrev, epoch.commitSecret, epoch.encoded)
		base, err := NewKeyScheduleFromJoiner(
			epoch.crypto, joinerSecret, epoch.pskSecret, epoch.groupContext)
		if err != nil {
			t.Fatalf("%s: NewKeyScheduleFromJoiner over the base context: %v", epoch.at, err)
		}
		baseSecrets := epochSecretsByField(t, base.Secrets())
		cases := mutatedGroupContexts(t, epoch.groupContext)
		if len(cases) != fields {
			t.Fatalf("%s: GroupContext declares %d fields and this gate built %d cases",
				epoch.at, fields, len(cases))
		}
		for _, field := range slices.Sorted(maps.Keys(cases)) {
			changed, err := NewKeyScheduleFromJoiner(
				epoch.crypto, joinerSecret, epoch.pskSecret, cases[field])
			if err != nil {
				t.Errorf("%s: GroupContext.%s changed: NewKeyScheduleFromJoiner: %v", epoch.at, field, err)
				continue
			}
			changedSecrets := epochSecretsByField(t, changed.Secrets())
			for _, name := range names {
				if bytes.Equal(changedSecrets[name], baseSecrets[name]) {
					t.Errorf("%s: changing GroupContext.%s left %s unchanged, so a joiner handed a swapped %s derives the epoch anyway and joins a group it never agreed to",
						epoch.at, field, name, field)
				}
				observed++
			}
			if !bytes.Equal(changed.WelcomeSecret(), base.WelcomeSecret()) {
				t.Errorf("%s: changing GroupContext.%s moved welcome_secret from %x to %x; member_secret is Extract(joiner_secret, psk_secret) and the context enters only at the epoch expansion, so a Welcome sealed under this key opens for nobody",
					epoch.at, field, base.WelcomeSecret(), changed.WelcomeSecret())
			}
		}
	}
	if want := len(generated) * fields * len(names); observed != want {
		t.Fatalf("observed %d field comparisons, want %d", observed, want)
	}
}

// ---------------------------------------------------------------------------
// Task 8: MLS-Exporter, RFC 9420 section 8.5.
//
// This is the one primitive of the key schedule that carries a PRODUCT feature rather than
// only the protocol. MLS specifies no delivery service and no long term storage, so
// URmessage layers seed recovery on the exporter: each epoch's exported secret is wrapped to
// the member's recovery key, and a defect here is a defect in the ability to restore an
// account from a seedphrase. Its known answer therefore matters exactly as much as the key
// schedule's own, and the three separations it rests on — the label, the context and the
// length — are each observed on their own below, because each is a different mistake and
// each is invisible to the other two.
//
// The corpus pins one exporter answer per epoch, at a length that IS KDF.Nh for both
// registered suites. So the known answer alone cannot see a body that hands back KDF.Nh
// bytes whatever it was asked for, and TestKeyScheduleExportHonoursTheRequestedLengthExactly
// is what does.
// ---------------------------------------------------------------------------

// exporterOf is the corpus's published exporter question and its answer for one epoch.
//
// The label is read as the ASCII STRING the mlswg format documents it to be. It happens to be
// spelled in hex digits and every sibling field of it is hex, so reading it as hex is the
// natural mistake; it builds a different preimage and matches nothing.
// TestKeyScheduleExportReadsTheVectorLabelAsAStringAndNotAsHex is what says the two readings
// really do differ, rather than leaving that to this comment.
//
// Both halves of the question are checked as they are decoded. An epoch whose label were
// empty would agree with an implementation that ignored the label, and one whose context were
// empty would be weaker against an implementation that ignored the context, so a corpus that
// stopped carrying either is reported here rather than quietly making the sweep below softer.
func exporterOf(t *testing.T, epoch ksVectorEpoch) (label string, context []byte, length int, want string) {
	t.Helper()
	published := epoch.published.Exporter
	if published.Label == "" {
		t.Fatalf("%s: the corpus exporter label is empty, so an implementation that ignored the label would agree with this epoch",
			epoch.at)
	}
	if published.Length <= 0 {
		t.Fatalf("%s: the corpus exporter length is %d, so this epoch pins nothing about how many bytes are produced",
			epoch.at, published.Length)
	}
	// mustDecodeHex refuses a context that decodes to nothing, which is the other half of
	// the same vacuity check
	return published.Label,
		mustDecodeHex(t, "exporter context"+epoch.at, published.Context),
		published.Length,
		published.Secret
}

// TestKeyScheduleExportMatchesTheMlswgKeySchedule is the deliverable of this task: the
// exporter answer mlswg published for every epoch of the corpus, through the KeySchedule type
// rather than through the primitives.
//
// crypto_labels_test.go already holds the same answers to the primitives. This is a different
// claim: that the type wires them together in the right order, over the right one of its nine
// secrets, with the caller's context hashed and the inner "exported" label supplied. Every one
// of those is a change of two characters or fewer that produces a perfectly well formed
// secret, and the only thing that separates the right one from the wrong one is a value
// somebody else published.
func TestKeyScheduleExportMatchesTheMlswgKeySchedule(t *testing.T) {
	compared := 0
	for _, epoch := range ksVectorEpochs(t) {
		label, context, length, want := exporterOf(t, epoch)
		exported, err := epoch.schedule(t).Export(label, context, length)
		if err != nil {
			t.Fatalf("%s: Export: %v", epoch.at, err)
		}
		assertLabelKat(t, "exporter"+epoch.at, exported, want)
		compared++
	}
	if compared != keyScheduleKatEpochs {
		t.Fatalf("compared %d published exporter answers, want %d", compared, keyScheduleKatEpochs)
	}
}

// TestKeyScheduleExportReadsTheVectorLabelAsAStringAndNotAsHex is what makes the known answer
// above mean something.
//
// The corpus label is 64 ASCII characters that are all hex digits, sitting in a json object
// where every other string is hex. An implementation — or a test — that decoded it would build
// a 32 byte label, expand over a different preimage and get a different answer, and the whole
// weight of the vector rests on which of the two readings is the right one. This asserts they
// really are different answers, so a KAT that passed under one reading could not also have
// passed under the other.
func TestKeyScheduleExportReadsTheVectorLabelAsAStringAndNotAsHex(t *testing.T) {
	rows := 0
	for _, epoch := range ksVectorEpochs(t) {
		label, context, length, _ := exporterOf(t, epoch)
		decoded, err := hex.DecodeString(label)
		if err != nil {
			t.Fatalf("%s: the corpus label %q does not decode as hex at all, so this gate separates nothing; it exists because the label IS spelled in hex digits",
				epoch.at, label)
		}
		schedule := epoch.schedule(t)
		asString, err := schedule.Export(label, context, length)
		if err != nil {
			t.Fatalf("%s: Export under the label as a string: %v", epoch.at, err)
		}
		asHex, err := schedule.Export(string(decoded), context, length)
		if err != nil {
			t.Fatalf("%s: Export under the hex decoded label: %v", epoch.at, err)
		}
		if bytes.Equal(asString, asHex) {
			t.Errorf("%s: the label read as a string and the same label hex decoded produce one answer, so the label is not reaching the derivation and the published exporter value pins nothing",
				epoch.at)
		}
		rows++
	}
	if rows == 0 {
		t.Fatal("no epoch reached the comparison, so this gate held nothing")
	}
}

// exportGridLabels and exportGridContexts are the grid the separation gate below sweeps.
//
// The labels include a pair differing in one character and a pair where one is a prefix of the
// other, because ExpandWithLabel length prefixes its fields and a body that concatenated them
// instead would collide exactly on the second pair. The contexts include one byte, two bytes
// and ninety seven bytes for the same reason on the other side, and a one byte difference so
// the property is not satisfied by a body that only reads the context's length.
var (
	exportGridLabels = []string{
		"",
		"URmessage/v1/storage",
		"URmessage/v1/storagf",
		"URmessage/v1/storage/",
	}
	exportGridContexts = [][]byte{
		{0x00},
		{0x01},
		{0x01, 0x00},
		bytes.Repeat([]byte{0xa5}, 97),
	}
)

// TestKeyScheduleExportSeparatesItsLabelAndItsContextIndependently observes the property the
// known answer cannot: that BOTH inputs reach the derivation, and each on its own.
//
// A body that ignored the context hands every caller under one label the same secret however
// they varied it, which is a set of exports that look distinct at every call site and are one
// key. A body that ignored the label does the same thing one level up. Neither shows up in a
// vector that varies both at once, and neither shows up in a round trip, a length check or a
// distinctness check over a single call — which is why the grid varies one at a time and every
// pair is compared.
//
// The nil and empty contexts are asserted to AGREE rather than to differ, because the context
// is hashed: Hash(nil) and Hash([]byte{}) are one value, so a caller writing the MASTER
// section 7 storage call either way gets one secret. A body that passed the context through
// instead of hashing it would separate those two, which is the opposite failure.
func TestKeyScheduleExportSeparatesItsLabelAndItsContextIndependently(t *testing.T) {
	type gridKey struct {
		label   int
		context int
	}
	compared := 0
	for _, epoch := range ksVectorEpochs(t) {
		schedule := epoch.schedule(t)
		length := epoch.crypto.HashSize()
		exported := map[gridKey][]byte{}
		for i, label := range exportGridLabels {
			for j, context := range exportGridContexts {
				answer, err := schedule.Export(label, context, length)
				if err != nil {
					t.Fatalf("%s: Export(%q, %x, %d): %v", epoch.at, label, context, length, err)
				}
				if len(answer) != length {
					t.Fatalf("%s: Export(%q, %x, %d) answered %d bytes",
						epoch.at, label, context, length, len(answer))
				}
				exported[gridKey{label: i, context: j}] = answer
			}
		}
		for first, firstAnswer := range exported {
			for second, secondAnswer := range exported {
				if first == second {
					continue
				}
				compared++
				if !bytes.Equal(firstAnswer, secondAnswer) {
					continue
				}
				switch {
				case first.label == second.label:
					t.Errorf("%s: two exports under label %q with contexts %x and %x are the same secret, so the context is not reaching the derivation and every 'different' export under this label is one key",
						epoch.at, exportGridLabels[first.label],
						exportGridContexts[first.context], exportGridContexts[second.context])
				case first.context == second.context:
					t.Errorf("%s: two exports under labels %q and %q with one context are the same secret, so the label is not reaching the derivation",
						epoch.at, exportGridLabels[first.label], exportGridLabels[second.label])
				default:
					t.Errorf("%s: Export(%q, %x) and Export(%q, %x) are the same secret",
						epoch.at, exportGridLabels[first.label], exportGridContexts[first.context],
						exportGridLabels[second.label], exportGridContexts[second.context])
				}
			}
		}

		// the other direction: the context is HASHED, so its two spellings of "no context"
		// are one context
		none, err := schedule.Export("URmessage/v1/storage", nil, length)
		if err != nil {
			t.Fatalf("%s: Export over a nil context: %v", epoch.at, err)
		}
		empty, err := schedule.Export("URmessage/v1/storage", []byte{}, length)
		if err != nil {
			t.Fatalf("%s: Export over an empty context: %v", epoch.at, err)
		}
		if !bytes.Equal(none, empty) {
			t.Errorf("%s: a nil context and an empty one answered different secrets, so the context is being passed through rather than hashed and the MASTER section 7 storage call depends on which spelling its caller used",
				epoch.at)
		}
	}
	// the grid really ran: a sweep whose inner loops produced no pair reports the clean run a
	// full one reports
	if want := keyScheduleKatEpochs * len(exportGridLabels) * len(exportGridContexts) *
		(len(exportGridLabels)*len(exportGridContexts) - 1); compared != want {
		t.Fatalf("compared %d pairs of exports, want %d", compared, want)
	}
}

// TestKeyScheduleExportHashesItsContextSoACallerMayPassAnyLength observes the sentence
// Export's own comment writes, and it is the one claim about the context that nothing in the
// corpus can make: every published exporter context is KDF.Nh octets long.
//
// The context reaches the expansion as an opaque<V> field of the KDFLabel preimage, and that
// field's length prefix is bounded by syntax.MaxVectorLength. So a body that passed the
// caller's context THROUGH instead of hashing it reproduces nothing published — the known
// answer catches it — but a body that hashed it in the corpus's range and passed it through
// outside would not be caught by any comparison against the corpus at all, and would panic out
// of the syntax package the first time a caller passed a context bigger than a megabyte.
// For URmessage's seed recovery that context is a caller's data and not this package's.
//
// Hashing first makes the field KDF.Nh octets whatever arrived, and the second half asserts
// the whole of the caller's context reached the hash rather than a prefix of it.
func TestKeyScheduleExportHashesItsContextSoACallerMayPassAnyLength(t *testing.T) {
	epoch := ksVectorEpochs(t)[0]
	schedule := epoch.schedule(t)
	length := epoch.crypto.HashSize()
	// one octet past the longest vector the preimage encoder will write, so a context that
	// reached that encoder unhashed could not be encoded at all
	oversized := bytes.Repeat([]byte{0x77}, syntax.MaxVectorLength+1)
	// with the panic caught rather than taken: the failure this row exists for IS a panic,
	// raised inside the syntax package, and taking it would end the test binary and every
	// gate declared after this one with it
	answer, raised := recoveringRow(func() exportAnswer {
		exported, err := schedule.Export("URmessage/v1/storage", oversized, length)
		return exportAnswer{exported: exported, err: err}
	})
	if raised != nil {
		t.Fatalf("Export over a %d octet context panicked with %v; the context is reaching the KDFLabel preimage unhashed, where syntax.MaxVectorLength of %d bounds it",
			len(oversized), raised, syntax.MaxVectorLength)
	}
	if answer.err != nil {
		t.Fatalf("Export over a %d octet context: %v", len(oversized), answer.err)
	}
	if len(answer.exported) != length {
		t.Fatalf("Export over a %d octet context answered %d bytes, want %d",
			len(oversized), len(answer.exported), length)
	}
	// and the whole of it was hashed: one octet changed at the far end changes the answer,
	// which a body that hashed a prefix of the caller's context would not
	altered := bytes.Clone(oversized)
	altered[len(altered)-1] ^= 0x01
	other, err := schedule.Export("URmessage/v1/storage", altered, length)
	if err != nil {
		t.Fatalf("Export over the altered context: %v", err)
	}
	if bytes.Equal(answer.exported, other) {
		t.Error("changing the last octet of the context did not change the export, so only a prefix of the caller's context reaches the derivation")
	}
}

// TestKeyScheduleExportHonoursTheRequestedLengthExactly is the property the corpus cannot
// hold, because both registered suites publish their exporter answer at exactly KDF.Nh bytes.
//
// So a body that expanded at KDF.Nh whatever it was asked for reproduces all ten published
// answers, passes every separation above, and hands a caller asking for 64 bytes of key
// material 32 bytes of it — or, spelled the other way, truncates a longer request to the hash
// size and returns short. URmessage's seed recovery asks for what its own format needs, which
// is a caller's number and not the suite's.
//
// The lengths are read off the provider so the row set moves with the suite, and they
// deliberately straddle KDF.Nh in both directions and include the 255*KDF.Nh ceiling, which is
// the largest HKDF-Expand can produce.
//
// The prefix comparison at the end is a separate claim: MLS binds the length INTO the
// expansion's preimage, so two lengths under one label and context are unrelated secrets
// rather than one stream cut to two sizes. A body that expanded once at the ceiling and
// sliced would satisfy every length check above and disagree with every peer.
func TestKeyScheduleExportHonoursTheRequestedLengthExactly(t *testing.T) {
	compared := 0
	for _, epoch := range ksVectorEpochs(t) {
		schedule := epoch.schedule(t)
		nh := epoch.crypto.HashSize()
		if nh < 4 {
			t.Fatalf("%s: KDF.Nh is %d, and the rows below assume a hash with room either side of it", epoch.at, nh)
		}
		answers := map[int][]byte{}
		for _, length := range []int{0, 1, nh - 1, nh, nh + 1, 2 * nh, 2*nh + 7, 255 * nh} {
			exported, err := schedule.Export("URmessage/v1/storage", exportSweepContext, length)
			if err != nil {
				t.Fatalf("%s: Export at %d bytes: %v", epoch.at, length, err)
			}
			if len(exported) != length {
				t.Errorf("%s: Export asked for %d bytes answered %d; a caller of the exporter gets the length it asked for or an error, never a different length",
					epoch.at, length, len(exported))
			}
			answers[length] = exported
			compared++
		}
		short, long := answers[nh], answers[2*nh]
		if len(short) != nh || len(long) != 2*nh {
			continue
		}
		if bytes.Equal(long[:nh], short) {
			t.Errorf("%s: the %d byte export is the first %d bytes of the %d byte one, so the length is not bound into the expansion's preimage and two lengths under one label are one secret",
				epoch.at, nh, nh, 2*nh)
		}
	}
	if want := keyScheduleKatEpochs * 8; compared != want {
		t.Fatalf("compared %d lengths, want %d", compared, want)
	}
}

// exportAnswer is one Export result carried through recoveringRow, which is generic over a
// single value and cannot carry a pair.
type exportAnswer struct {
	exported []byte
	err      error
}

// TestKeyScheduleExportRefusesALengthOutsideTheKdfRange asserts the two ends of the range are
// typed refusals rather than a panic out of the provider or a silently different length.
//
// CryptoProvider.Expand panics on both, which is right for the call sites that ask for a length
// their suite fixes and wrong for this one: the exporter's length is a CALLER's number, so it
// arrives as an error a caller can handle. The negative side matters as much as the positive
// one — crypto/hkdf reaches make([]byte, 0, keyLen) before any check of its own, so a negative
// length that got past here is a makeslice panic from inside the standard library.
func TestKeyScheduleExportRefusesALengthOutsideTheKdfRange(t *testing.T) {
	refused := 0
	for _, epoch := range ksVectorEpochs(t) {
		schedule := epoch.schedule(t)
		nh := epoch.crypto.HashSize()
		for _, length := range []int{-1, -nh, 255*nh + 1, 1 << 30} {
			// with the panic caught rather than taken, for the reason recoveringRow gives.
			// A length gate that stopped gating does not answer a wrong error here: the
			// negative rows reach make([]byte, 0, keyLen) inside crypto/hkdf, which is a
			// panic, and a panic in this row would take the test BINARY down and with it
			// every gate declared after it. Measured, not supposed: dropping the negative
			// half of the gate ran 8 of the 14 tests of this sweep before the binary died.
			answer, raised := recoveringRow(func() exportAnswer {
				exported, err := schedule.Export("URmessage/v1/storage", exportSweepContext, length)
				return exportAnswer{exported: exported, err: err}
			})
			refused++
			if raised != nil {
				t.Errorf("%s: Export at %d bytes panicked with %v; a length outside the kdf's range is a caller's number and comes back as ErrExportLength",
					epoch.at, length, raised)
				continue
			}
			if !errors.Is(answer.err, ErrExportLength) {
				t.Errorf("%s: Export at %d bytes answered %v, want ErrExportLength", epoch.at, length, answer.err)
			}
			if answer.exported != nil {
				t.Errorf("%s: Export at %d bytes refused and answered %d bytes as well",
					epoch.at, length, len(answer.exported))
			}
		}
		// and the boundary itself is inside the range rather than one past it
		if exported, err := schedule.Export("URmessage/v1/storage", exportSweepContext, 255*nh); err != nil {
			t.Errorf("%s: Export at 255*KDF.Nh = %d bytes was refused with %v, and that is exactly what HKDF-Expand can produce",
				epoch.at, 255*nh, err)
		} else if len(exported) != 255*nh {
			t.Errorf("%s: Export at 255*KDF.Nh answered %d bytes, want %d", epoch.at, len(exported), 255*nh)
		}
	}
	if want := keyScheduleKatEpochs * 4; refused != want {
		t.Fatalf("%d lengths were refused, want %d", refused, want)
	}
}

// TestKeyScheduleExportReadsItsCeilingFromTheProvider is the input the registered suites
// cannot supply: both fix KDF.Nh at 32, so 255*KDF.Nh is 8160 for both and a body that wrote
// 8160 down — or wrote 32 down and multiplied — answers correctly for every suite this package
// registers and incorrectly for the first one it does not.
//
// Both directions are asserted, because either alone is satisfiable by a different mistake. A
// length inside the wide provider's range and outside the narrow one's must be ACCEPTED over
// the wide provider, which a written down 8160 refuses; and the wide provider's own ceiling
// must still be refused one past it, so the number moved rather than disappearing.
func TestKeyScheduleExportReadsItsCeilingFromTheProvider(t *testing.T) {
	narrow := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	wide := &wideKdfProvider{CryptoProvider: narrow}
	if narrow.HashSize() == wide.HashSize() {
		t.Fatalf("both providers answer KDF.Nh %d, so this gate separates nothing", narrow.HashSize())
	}
	groupContext := ksVectorEpoch0GroupContext(t)
	narrowSchedule, err := NewKeyScheduleFromEpochSecret(
		narrow, bytes.Repeat([]byte{0x61}, narrow.HashSize()), groupContext)
	if err != nil {
		t.Fatalf("build the schedule over the narrow provider: %v", err)
	}
	wideSchedule, err := NewKeyScheduleFromEpochSecret(
		wide, bytes.Repeat([]byte{0x62}, wide.HashSize()), groupContext)
	if err != nil {
		t.Fatalf("build the schedule over the wide provider: %v", err)
	}

	beyondTheNarrowCeiling := 255*narrow.HashSize() + 1
	if _, err := narrowSchedule.Export("URmessage/v1/storage", nil, beyondTheNarrowCeiling); !errors.Is(err, ErrExportLength) {
		t.Errorf("a provider whose KDF.Nh is %d accepted %d bytes, which is past its own 255*KDF.Nh, answering %v",
			narrow.HashSize(), beyondTheNarrowCeiling, err)
	}
	exported, err := wideSchedule.Export("URmessage/v1/storage", nil, beyondTheNarrowCeiling)
	if err != nil {
		t.Errorf("a provider whose KDF.Nh is %d refused %d bytes with %v, and that is inside its own 255*KDF.Nh of %d; the ceiling is written down rather than read off the provider",
			wide.HashSize(), beyondTheNarrowCeiling, err, 255*wide.HashSize())
	} else if len(exported) != beyondTheNarrowCeiling {
		t.Errorf("the wide provider answered %d bytes for a request of %d", len(exported), beyondTheNarrowCeiling)
	}
	if _, err := wideSchedule.Export("URmessage/v1/storage", nil, 255*wide.HashSize()+1); !errors.Is(err, ErrExportLength) {
		t.Errorf("a provider whose KDF.Nh is %d accepted %d bytes, one past its own 255*KDF.Nh, answering %v; the ceiling moved with the provider in one direction and disappeared in the other",
			wide.HashSize(), 255*wide.HashSize()+1, err)
	}
}

// TestKeyScheduleExportLeavesItsContextAloneAndAnswersStorageOfItsOwn covers the three
// aliasing claims the package wide gate next door cannot make about this one, because that
// gate's class is package level FUNCTIONS handed a caller's bytes and Export is a method.
//
// Each is a different wrong implementation. A context written through is a caller's buffer
// changed by a read only operation. Two calls answering out of one array is an earlier export
// overwritten by a later one, which a caller holding both would discover as a key that changed
// under it. An answer that aliased one of the epoch's own secrets would be handed to a caller
// that then owns storage the epoch erases when it ages out of PastEpochWindow.
func TestKeyScheduleExportLeavesItsContextAloneAndAnswersStorageOfItsOwn(t *testing.T) {
	epochs := ksVectorEpochs(t)
	epoch := epochs[0]
	schedule := epoch.schedule(t)
	length := epoch.crypto.HashSize()
	context := bytes.Repeat([]byte{0x3d}, 40)
	handed := bytes.Clone(context)

	first, err := schedule.Export("URmessage/v1/storage", context, length)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if !bytes.Equal(context, handed) {
		t.Errorf("Export changed the storage behind the context it was handed: %x, was %x", context, handed)
	}
	second, err := schedule.Export("URmessage/v1/storage", context, length)
	if err != nil {
		t.Fatalf("Export a second time: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("two calls with one label, context and length answered %x and %x", first, second)
	}
	if len(first) == 0 || len(second) == 0 {
		t.Fatal("Export answered nothing, so the aliasing checks below observe nothing")
	}
	if &first[0] == &second[0] {
		t.Error("two calls to Export answered out of one array, so a caller holding an earlier export has it overwritten by a later one")
	}
	if &context[0] == &first[0] {
		t.Error("Export answered over the context it was handed")
	}
	for name, secret := range epochSecretsByField(t, schedule.Secrets()) {
		if len(secret) != 0 && &secret[0] == &first[0] {
			t.Errorf("Export answered over EpochSecrets.%s, which the epoch erases when it ages out of PastEpochWindow", name)
		}
	}
}

// TestKeyScheduleExportNeverAnswersASecretTheEpochKeeps is guardrail G6 read at the one
// exported surface a caller controls the arguments of.
//
// The sweep in bytesTheScheduleHandsOut drives Export through rows this file chose and holds
// its answers to G6 alongside the accessors'. This is the complement: a wider set of labels and
// contexts, compared against the whole of what the epoch holds rather than against epoch_secret
// alone. Both are needed — a body that answered self.epochSecret is caught by either, and one
// that answered confirmation_key under some particular label is caught only here.
//
// The length is KDF.Nh so the comparisons can bite at all: every secret compared against is
// KDF.Nh bytes, and an export of any other length could not equal one however wrong the body
// was.
func TestKeyScheduleExportNeverAnswersASecretTheEpochKeeps(t *testing.T) {
	compared := 0
	for _, epoch := range ksVectorEpochs(t) {
		schedule := epoch.schedule(t)
		length := epoch.crypto.HashSize()
		forbidden := map[string][]byte{
			"epoch_secret":   epochSecretOfTheEpoch(t, epoch),
			"joiner_secret":  schedule.JoinerSecret(),
			"welcome_secret": schedule.WelcomeSecret(),
		}
		for name, secret := range epochSecretsByField(t, schedule.Secrets()) {
			forbidden["EpochSecrets."+name] = secret
		}
		if len(forbidden) < 12 {
			t.Fatalf("%s: the epoch reads as %d secrets, and it keeps the nine derived ones plus three more",
				epoch.at, len(forbidden))
		}
		for _, label := range []string{"", "exported", "exporter", "epoch", "URmessage/v1/storage"} {
			for _, context := range [][]byte{nil, {}, exportSweepContext} {
				exported, err := schedule.Export(label, context, length)
				if err != nil {
					t.Fatalf("%s: Export(%q, %x, %d): %v", epoch.at, label, context, length, err)
				}
				for name, secret := range forbidden {
					if len(secret) == 0 {
						continue
					}
					compared++
					if bytes.Equal(exported, secret) {
						t.Errorf("%s: Export(%q, %x, %d) answered %s itself; the exporter hands out material derived FROM the epoch and never the epoch's own secrets",
							epoch.at, label, context, length, name)
					}
				}
			}
		}
	}
	if compared == 0 {
		t.Fatal("no export was compared against any secret, so this gate held nothing")
	}
}

// ---------------------------------------------------------------------------
// Task 9: the external key pair.
//
// This is the only place in the key schedule that reaches into HPKE, and deliberately the only
// one: everything else in key_schedule.go is arithmetic over byte slices, which is what keeps
// it auditable against RFC 9420 section 8 line by line.
//
// v1 refuses external commits, so this key pair is never advertised in a GroupInfo and never
// used to accept an ExternalInit. It is derived anyway because key-schedule.json checks
// external_pub, and because a DeriveKeyPair that disagrees here disagrees everywhere else it is
// used. p7's TestExternalPubIsNotAdvertised is the counterpart assertion, on the other side of
// the boundary.
// ---------------------------------------------------------------------------

// TestKeyScheduleExternalKeyPairMatchesTheMlswgKeySchedule pins external_pub against the
// answer mlswg published for every epoch of the corpus.
//
// external_secret is 32 pseudorandom bytes and so is every other secret of the epoch, so
// DeriveKeyPair over the wrong one answers a perfectly well formed public key of the right
// length. Nothing about the value says which secret it came from, which is why the published
// answer is what holds this.
func TestKeyScheduleExternalKeyPairMatchesTheMlswgKeySchedule(t *testing.T) {
	compared := 0
	for _, epoch := range ksVectorEpochs(t) {
		_, pub, err := epoch.schedule(t).ExternalKeyPair()
		if err != nil {
			t.Fatalf("%s: ExternalKeyPair: %v", epoch.at, err)
		}
		assertLabelKat(t, "external_pub"+epoch.at, pub, epoch.published.ExternalPub)
		compared++
	}
	if compared != keyScheduleKatEpochs {
		t.Fatalf("compared %d published external_pub answers, want %d", compared, keyScheduleKatEpochs)
	}
}

// TestKeyScheduleExternalKeyPairIsDerivedFromTheExternalSecretAndNothingElse states the same
// claim independently of the corpus, and states it as an exclusion rather than as an equality.
//
// The candidate set is read off the type by reflection — the nine derived secrets, plus the
// three other byte slices the epoch keeps — so a tenth secret joins by existing rather than by
// somebody remembering to add it here. Exactly one candidate may reproduce the answered public
// key, and it must be external_secret. That is what a KAT alone cannot say: a KAT compares one
// value and is silent about which of twelve equally well formed inputs produced it, so on the
// day the corpus is re-vendored or a suite is added, this is the statement that still holds.
func TestKeyScheduleExternalKeyPairIsDerivedFromTheExternalSecretAndNothingElse(t *testing.T) {
	for _, epoch := range ksVectorEpochs(t) {
		schedule := epoch.schedule(t)
		_, pub, err := schedule.ExternalKeyPair()
		if err != nil {
			t.Fatalf("%s: ExternalKeyPair: %v", epoch.at, err)
		}
		candidates := map[string][]byte{
			"epoch_secret":        epochSecretOfTheEpoch(t, epoch),
			"joiner_secret":       schedule.JoinerSecret(),
			"welcome_secret":      schedule.WelcomeSecret(),
			"group_context_bytes": schedule.GroupContextBytes(),
		}
		for name, secret := range epochSecretsByField(t, schedule.Secrets()) {
			candidates["EpochSecrets."+name] = secret
		}
		if len(candidates) < 13 {
			t.Fatalf("%s: the epoch reads as %d candidate inputs, and it keeps the nine derived secrets plus four more",
				epoch.at, len(candidates))
		}
		matched := []string{}
		for name, ikm := range candidates {
			if len(ikm) == 0 {
				continue
			}
			_, candidatePub, deriveErr := epoch.crypto.DeriveKeyPair(ikm)
			if deriveErr != nil {
				t.Fatalf("%s: DeriveKeyPair over %s: %v", epoch.at, name, deriveErr)
			}
			if bytes.Equal(candidatePub, pub) {
				matched = append(matched, name)
			}
		}
		if want := []string{"EpochSecrets.External"}; !slices.Equal(slices.Sorted(slices.Values(matched)), want) {
			t.Errorf("%s: external_pub is DeriveKeyPair of %v, and RFC 9420 section 8 derives it from external_secret and nothing else",
				epoch.at, matched)
		}
	}
}

// TestKeyScheduleExternalKeyPairIsDeterministicAndItsTwoHalvesAgree covers the half of this
// method the corpus is silent about.
//
// key-schedule.json publishes external_pub and no private key, so a body that answered the
// right public key beside an unrelated private one passes every comparison above. What says the
// two halves are halves of one pair is a seal to the public key opened with the private one,
// and that is not a round trip of this function — it goes out through HPKE and comes back.
//
// Determinism is the other claim and it is not implied by the first: a body that sampled a
// fresh pair per call would still seal and open, and would answer a different external_pub
// every time it was asked. Nothing in this derivation may read entropy.
func TestKeyScheduleExternalKeyPairIsDeterministicAndItsTwoHalvesAgree(t *testing.T) {
	info := []byte("the info every external key pair row carries")
	aad := []byte("the aad every external key pair row carries")
	plaintext := []byte("sealed to external_pub, opened with the half nobody published")
	for _, epoch := range ksVectorEpochs(t) {
		schedule := epoch.schedule(t)
		firstPriv, firstPub, err := schedule.ExternalKeyPair()
		if err != nil {
			t.Fatalf("%s: ExternalKeyPair: %v", epoch.at, err)
		}
		secondPriv, secondPub, err := schedule.ExternalKeyPair()
		if err != nil {
			t.Fatalf("%s: ExternalKeyPair a second time: %v", epoch.at, err)
		}
		if !bytes.Equal(firstPub, secondPub) || !bytes.Equal(firstPriv, secondPriv) {
			t.Errorf("%s: two calls answered different key pairs, so something in this derivation reads entropy and every member of the epoch would hold a different external_pub",
				epoch.at)
			continue
		}
		if len(firstPriv) == 0 || len(firstPub) == 0 {
			t.Fatalf("%s: ExternalKeyPair answered a %d byte private key and a %d byte public key",
				epoch.at, len(firstPriv), len(firstPub))
		}
		// the private half is the private half OF THAT public key
		kemOutput, ciphertext, err := epoch.crypto.HpkeSeal(firstPub, info, aad, plaintext)
		if err != nil {
			t.Fatalf("%s: seal to external_pub: %v", epoch.at, err)
		}
		opened, err := epoch.crypto.HpkeOpen(secondPriv, kemOutput, info, aad, ciphertext)
		if err != nil {
			t.Errorf("%s: the private key this method answered does not open a message sealed to the public key it answered beside it: %v",
				epoch.at, err)
			continue
		}
		if !bytes.Equal(opened, plaintext) {
			t.Errorf("%s: opening with the answered private key produced %x, want %x", epoch.at, opened, plaintext)
		}
		// and DeriveKeyPair was applied rather than external_secret handed back under a
		// different name
		external := schedule.Secrets().External
		if bytes.Equal(firstPriv, external) {
			t.Errorf("%s: the external private key IS external_secret, so DeriveKeyPair is not being applied to it", epoch.at)
		}
		if len(external) != 0 && &external[0] == &firstPriv[0] {
			t.Errorf("%s: the external private key is a view over external_secret, which the epoch erases when it ages out of PastEpochWindow",
				epoch.at)
		}
	}
}

// deriveSecretCapturingProvider keeps every secret DeriveSecret answers, so a test can read
// that storage back after the call that computed it has returned.
//
// The slice is returned unchanged rather than copied, and that is the whole mechanism:
// zeroizeSecret writes through the backing array its argument points at, so a wrapper handing
// the caller a clone would be handing it a different array the erase never reaches, and the
// property would read as absent however the production code behaved. This is
// extractCapturingProvider one derivation over.
type deriveSecretCapturingProvider struct {
	CryptoProvider
	derived [][]byte
}

func (self *deriveSecretCapturingProvider) DeriveSecret(secret []byte, label string) []byte {
	answer := self.CryptoProvider.DeriveSecret(secret, label)
	self.derived = append(self.derived, answer)
	return answer
}

// TestKeyScheduleExportErasesThePerLabelSecret observes the sentence key_schedule.go writes
// inside Export: "the per label secret is one HKDF-Expand away from every export under that
// label and nothing downstream needs it, so the storage it was computed into is erased rather
// than left for the collector."
//
// Nothing observed it. Measured, not supposed: deleting the zeroizeSecret(derived) line left
// the whole of mls and message green, while the package tests every other erase it performs --
// TestNewKeyScheduleErasesTheMemberSecret, TestNewKeyScheduleErasesTheJoinerSecretItDerived
// and TestDeriveJoinerSecretErasesThePseudorandomKey. A claim the code makes in prose that no
// test observes is a claim the next edit deletes for free.
//
// What that secret is worth to whoever finds it: DeriveSecret(exporter_secret, Label) is the
// parent of every export under that label, at every length and over every context, so a reader
// of it reproduces the seed recovery key URmessage wraps to this epoch without ever seeing the
// epoch.
//
// The nine the constructor derived are dropped before the call, because they are the epoch's
// own and stay; what this reads is the one derivation Export itself makes. The control is the
// one TestDeriveJoinerSecretErasesThePseudorandomKey carries: an all zero reading only means
// something if the secret was not already zero, and an export that came back zero would
// satisfy the loop for the wrong reason.
func TestKeyScheduleExportErasesThePerLabelSecret(t *testing.T) {
	const label = "URmessage/v1/storage"
	for _, epoch := range ksVectorEpochs(t) {
		crypto := &deriveSecretCapturingProvider{CryptoProvider: epoch.crypto}
		schedule, err := NewKeySchedule(
			crypto, epoch.initPrev, epoch.commitSecret, epoch.pskSecret, epoch.groupContext)
		if err != nil {
			t.Fatalf("%s: NewKeySchedule: %v", epoch.at, err)
		}
		// the control: the secret this call will erase is not zero to begin with
		fresh := epoch.crypto.DeriveSecret(schedule.Secrets().Exporter, label)
		if !slices.ContainsFunc(fresh, func(b byte) bool { return b != 0 }) {
			t.Fatalf("%s: DeriveSecret over exporter_secret under %q is already %d zero bytes, so an all zero reading below would say nothing",
				epoch.at, label, len(fresh))
		}

		crypto.derived = nil
		exported, err := schedule.Export(label, exportSweepContext, epoch.crypto.HashSize())
		if err != nil {
			t.Fatalf("%s: Export: %v", epoch.at, err)
		}
		if len(crypto.derived) != 1 {
			t.Fatalf("%s: Export made %d DeriveSecret calls, want 1; this gate reads the secret that one call answered",
				epoch.at, len(crypto.derived))
		}
		derived := crypto.derived[0]
		if len(derived) != epoch.crypto.HashSize() {
			t.Fatalf("%s: the per label secret is %d bytes, want %d",
				epoch.at, len(derived), epoch.crypto.HashSize())
		}
		for i, b := range derived {
			if b != 0 {
				t.Errorf("%s: byte %d of the per label secret is %#02x after Export returned, want 0; it is one HKDF-Expand away from every export under %q and nothing downstream needs it",
					epoch.at, i, b, label)
				break
			}
		}
		// and the erase reached that secret rather than the answer: an export that came back
		// zero would satisfy the loop above for the wrong reason
		if !slices.ContainsFunc(exported, func(b byte) bool { return b != 0 }) {
			t.Errorf("%s: Export answered %d zero bytes, so the erase reached the value that was returned",
				epoch.at, len(exported))
		}
		// and exporter_secret itself is the epoch's and stays, which is what Export's own
		// comment says one line further on
		if !slices.ContainsFunc(schedule.Secrets().Exporter, func(b byte) bool { return b != 0 }) {
			t.Errorf("%s: exporter_secret is all zero after one Export, so the erase reached the epoch's own secret rather than the per label one",
				epoch.at)
		}
	}
}

// epochSecretsStorageFieldIn is the field of a holder that carries the nine derived secrets,
// found rather than written down: the field whose declared type is the compiled name of
// EpochSecrets.
//
// Both halves are derived. The type name comes off reflection, so renaming the type moves this
// with it, and the field name comes off the holder's own declaration, so renaming the field
// does too. A gate anchored on the spelling "secrets" would go on reading nothing after either
// rename and would report the clean run a working one reports.
func epochSecretsStorageFieldIn(t *testing.T, structs map[string]*ast.StructType, holder string) string {
	t.Helper()
	wanted := reflect.TypeOf(EpochSecrets{}).Name()
	declared, isDeclared := structs[holder]
	if !isDeclared {
		t.Fatalf("this package's source declares no struct named %s", holder)
	}
	for _, field := range declared.Fields.List {
		if !slices.Contains(identifiersNamedIn(field.Type), wanted) {
			continue
		}
		for _, name := range field.Names {
			return name.Name
		}
	}
	t.Fatalf("no field of %s is declared as a %s, so the class below would be empty and this gate would demand nothing",
		holder, wanted)
	return ""
}

// theMethodsDerivingFromOneOfTheNine is every exported method of the parsed files whose body
// reaches PAST the storage that carries the epoch's nine secrets and into one of them.
//
// One selector down is the whole distinction. Secrets() answers the struct and derives nothing
// from it — a caller that erased what it was handed did that to itself — while Export and
// ExternalKeyPair read a named secret out of it and expand something over the value. Only the
// second kind can answer a derivation of a secret that is no longer there, so only the second
// kind is what the gate below holds.
func theMethodsDerivingFromOneOfTheNine(declared []sourceDeclaration, storage string) []string {
	deriving := []string{}
	for _, one := range declared {
		if !one.exported || one.body == nil {
			continue
		}
		found := false
		ast.Inspect(one.body, func(node ast.Node) bool {
			outer, isSelector := node.(*ast.SelectorExpr)
			if !isSelector {
				return true
			}
			if inner, isNested := outer.X.(*ast.SelectorExpr); isNested && inner.Sel.Name == storage {
				found = true
			}
			return !found
		})
		if found {
			deriving = append(deriving, one.name)
		}
	}
	slices.Sort(deriving)
	return deriving
}

// erasedEpochControl declares one of each shape that derivation has to tell apart: a method
// that reads a named secret out of the storage, one that answers the storage whole, one that
// reads something else entirely, and an unexported one that reads a named secret.
const erasedEpochControl = "package control\n" +
	"\n" +
	"type EpochSecrets struct {\n" +
	"\tExporter []byte\n" +
	"}\n" +
	"\n" +
	"type Holder struct {\n" +
	"\tsecrets EpochSecrets\n" +
	"\tother   []byte\n" +
	"}\n" +
	"\n" +
	"func (self *Holder) DerivesFromOneOfThem() []byte {\n" +
	"\treturn expand(self.secrets.Exporter)\n" +
	"}\n" +
	"\n" +
	"func (self *Holder) AnswersTheStorageWhole() *EpochSecrets {\n" +
	"\treturn &self.secrets\n" +
	"}\n" +
	"\n" +
	"func (self *Holder) ReadsSomethingElse() []byte {\n" +
	"\treturn self.other\n" +
	"}\n" +
	"\n" +
	"func (self *Holder) derivesButIsUnexported() []byte {\n" +
	"\treturn expand(self.secrets.Exporter)\n" +
	"}\n" +
	"\n" +
	"func expand(secret []byte) []byte {\n" +
	"\treturn secret\n" +
	"}\n"

// scheduleMethodResults calls one exported method of *KeySchedule with every row the sweeps
// drive it by — or once with no arguments if it takes none — and splits each answer into the
// bytes a caller can read and the error beside them.
//
// The rows are keyScheduleMethodArgumentRows, the same ones guardrail 6 is driven through, so
// a method that gains an argument is driven here by writing that row once rather than twice.
func scheduleMethodResults(t *testing.T, at string, schedule *KeySchedule, name string) [][][]byte {
	t.Helper()
	method, found := reflect.TypeOf(schedule).MethodByName(name)
	if !found {
		t.Fatalf("%s: *KeySchedule declares no method %s", at, name)
	}
	rows := [][]reflect.Value{nil}
	if method.Type.NumIn() != 1 {
		build, driven := keyScheduleMethodArgumentRows[name]
		if !driven {
			t.Fatalf("%s: %s takes arguments and keyScheduleMethodArgumentRows has no rows for it, so this gate cannot call it",
				at, name)
		}
		rows = build(schedule)
	}
	errorInterface := reflect.TypeOf((*error)(nil)).Elem()
	answers := [][][]byte{}
	for _, row := range rows {
		read := [][]byte{}
		refused := false
		for _, result := range method.Func.Call(append([]reflect.Value{reflect.ValueOf(schedule)}, row...)) {
			if result.Type() == errorInterface {
				if !result.IsNil() {
					refused = true
					if !errors.Is(result.Interface().(error), ErrEpochErased) {
						t.Errorf("%s: %s answered %v, and the only refusal this gate expects is ErrEpochErased",
							at, name, result.Interface())
					}
				}
				continue
			}
			read = append(read, exposedBytes(exposedByteSlices(t, "(*KeySchedule)."+name, result))...)
		}
		if refused {
			// a refusal that came back with bytes beside it is the leak this gate is about,
			// wearing an error
			for _, secret := range read {
				if len(secret) != 0 {
					t.Errorf("%s: %s refused and %d bytes came back beside the refusal", at, name, len(secret))
				}
			}
			answers = append(answers, nil)
			continue
		}
		answers = append(answers, read)
	}
	return answers
}

// TestEveryMethodDerivingFromTheEpochsSecretsRefusesAnErasedEpoch is the erased epoch read as
// behaviour, over the class of methods that can hit it rather than over the one that was found
// hitting it.
//
// An epoch leaving PastEpochWindow has its nine secrets zeroized in place — key_schedule.go
// says so, and Secrets() hands out the pointer that makes it reachable today. A derivation over
// KDF.Nh zero bytes is not a weakened secret, it is a PUBLIC one: measured, not supposed, with
// the nine erased in place Export("URmessage/v1/storage", nil, 32) returned err == nil and a
// value byte identical to MLS-Exporter over 32 zero bytes. URmessage wraps seed recovery to
// each epoch's export, so a recovery blob taken from an aged out epoch would be wrapped to a
// key the attacker also holds and nothing would report an error.
//
// The class is every exported method whose body reads one of the nine by name, derived off the
// package's own source. Enumerating it would be the mistake this project has paid for
// repeatedly: the defect was reported against Export, and ExternalKeyPair — which derives an
// HPKE key pair from external_secret and would answer a key pair whose private half every party
// can recompute — is the same defect one method over and was in no report.
//
// Both directions are asserted. A live epoch must answer, or a method that refused everything
// would satisfy the erased half for the wrong reason; and the nine really are zero after the
// erase, or the refusal would be about some other condition.
func TestEveryMethodDerivingFromTheEpochsSecretsRefusesAnErasedEpoch(t *testing.T) {
	// the control first: the matcher tells a read of a named secret from an answer of the
	// storage whole, and exported from not
	control := mustParseText(t, "the erased epoch control", erasedEpochControl)
	controlStructs := map[string]*ast.StructType{}
	structTypesIn(control, controlStructs)
	if storage := epochSecretsStorageFieldIn(t, controlStructs, "Holder"); storage != "secrets" {
		t.Fatalf("the storage field scan read %q out of the control, want \"secrets\"", storage)
	}
	controlDeriving := theMethodsDerivingFromOneOfTheNine(declaredIn(control), "secrets")
	if want := []string{"DerivesFromOneOfThem"}; !slices.Equal(controlDeriving, want) {
		t.Fatalf("the matcher read %v out of the control as deriving from one of the nine, want %v; it is not telling a read of a named secret from an answer of the storage whole",
			controlDeriving, want)
	}

	// then this package's own source
	structs := map[string]*ast.StructType{}
	files := []parsedSource{}
	for _, path := range packageLevelFunctions(t).files {
		parsed := mustParseSource(t, path)
		files = append(files, parsed)
		structTypesIn(parsed, structs)
	}
	holders := theTypesHoldingTheEpochSecret(structs)
	if len(holders) != 1 {
		t.Fatalf("this package's source has %v keeping the epoch secret and this gate reads one holder", holders)
	}
	storage := epochSecretsStorageFieldIn(t, structs, holders[0])
	deriving := theMethodsDerivingFromOneOfTheNine(declaredAcross(files), storage)
	if len(deriving) == 0 {
		t.Fatalf("no exported method of this package reads %s.<one of the nine>, and this package declares Export and ExternalKeyPair, so the scan is reading nothing",
			storage)
	}
	for _, name := range deriving {
		if _, found := reflect.TypeOf(&KeySchedule{}).MethodByName(name); !found {
			t.Fatalf("%s derives from one of the nine and *KeySchedule does not declare it, so this gate cannot call it", name)
		}
	}
	t.Logf("%d exported methods derive from one of the nine: %v", len(deriving), deriving)

	for _, epoch := range ksVectorEpochs(t) {
		schedule := epoch.schedule(t)
		// the live control: every one of them answers bytes before the erase, so a refusal
		// afterwards is the erase and not a method that refuses everything
		for _, name := range deriving {
			for index, answer := range scheduleMethodResults(t, epoch.at, schedule, name) {
				if !slices.ContainsFunc(answer, func(b []byte) bool { return len(b) != 0 }) {
					t.Fatalf("%s: %s row %d answered no bytes over a live epoch, so a refusal after the erase would say nothing",
						epoch.at, name, index)
				}
			}
		}

		// the erase the epoch performs on itself when it leaves PastEpochWindow, over the nine
		// read by reflection rather than named here
		secrets := reflect.ValueOf(schedule.Secrets()).Elem()
		for i := range secrets.NumField() {
			zeroizeSecret(secrets.Field(i).Bytes())
		}
		for name, secret := range epochSecretsByField(t, schedule.Secrets()) {
			if slices.ContainsFunc(secret, func(b byte) bool { return b != 0 }) {
				t.Fatalf("%s: EpochSecrets.%s is not zero after the erase, so what the calls below answer is not an erased epoch",
					epoch.at, name)
			}
		}

		for _, name := range deriving {
			for index, answer := range scheduleMethodResults(t, epoch.at, schedule, name) {
				for _, secret := range answer {
					if len(secret) != 0 {
						t.Errorf("%s: %s row %d answered %d bytes over an epoch whose secrets are erased; a derivation over KDF.Nh zero bytes is publicly computable, so this is a secret handed out with err == nil",
							epoch.at, name, index, len(secret))
					}
				}
			}
		}
	}
}
