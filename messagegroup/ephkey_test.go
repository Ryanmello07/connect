// The key schedule and the seal lift of 2026-09-13, and the four properties they owe.
//
// P5: EphKey reads no clock, with the class of clock sources derived off this package's own
// source rather than listed as three names.
//
// P6: bucket 0 and an off ladder bucket are distinguishable, HERE in the caller that has to tell
// them apart -- the value half is connect/message's and ephbucket_test.go holds it.
//
// P7: the opener's ahead refusal is reachable AND the behind case is not a refusal. Both halves,
// because a refusal nothing can reach is one defect and a refusal that fires on the legitimate
// case is the other.
//
// P8: the seal lift admits every class spec A section 5.3 lifts and still refuses what ledger
// open item 185 refuses.
package messagegroup

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/connect/message"
)

// ---------------------------------------------------------------------------
// the derivation itself, against an implementation written outside this module
// ---------------------------------------------------------------------------

// K_eph[n][b][t] for the fixture's own eph_root, computed by a python program that reads MASTER
// section 8.1 and RFC 5869 and no Go file at all.
//
// WHY A HEX STRING AND NOT A SECOND EXPANSION IN THIS FILE. An expansion written here would run
// on the same understanding of the same three things the subject does -- the info's field order,
// each field's width, and the byte order of a u64 -- so it would agree with a transposed
// implementation as readily as with a correct one. What these strings commit to is the
// specification: "eph/v1" then u8(b) then u64(t) BIG ENDIAN, expanded under HMAC-SHA-256 to
// thirty two octets. A build that wrote the window little endian, or the bucket after the window,
// or the info without the label, answers something else here.
//
// The program:
//
//	def expand(prk, info, L):        # RFC 5869 section 2.3
//	    out=b''; t=b''; i=1
//	    while len(out)<L:
//	        t = hmac.new(prk, t+info+bytes([i]), hashlib.sha256).digest(); out += t; i += 1
//	    return out[:L]
//	info = b"eph/v1" + struct.pack(">B", b) + struct.pack(">Q", t)
//	root = bytes((0xE0 + i) & 0xFF for i in range(32))       # testEphRoot()
const (
	ephKeyKatBucket0Window0     = "be056c0605b17ef6b10d7a2c8a2d4ae30a49e46cc234dcf18f1fcb0df19c78b2"
	ephKeyKatBucket1Window0     = "8b1a94286ea26028829cfccee9dfbdf2bab556bfa7f42fcc85c7229af2505070"
	ephKeyKatBucket1Window1     = "72d2fe4145819b2b81be3418110f38dc47b5f7ec6f15cc751863d13fed12d4b2"
	ephKeyKatBucket5Window709   = "282933d8669601c264bc5a6dfcc83f0dc16402527cdf1442b69758547708fb47"
	ephKeyKatBucket5WindowWideT = "25fd9ad113f67c2b9f351a66ce3ad99885df5cea56deda7245087cab6e04f129"
	// the info octets for b = 1, t = 1, so a reader can see where the KATs come from and a
	// width error is visible as a length rather than only as a different key.
	ephKeyKatInfoBucket1Window1 = "6570682f7631010000000000000001"
)

// TestEphKeyIsMasterSection81sDerivationAndNotThisPackagesOpinionOfIt holds all five.
//
// The wide window is the one that says the field is eight octets and big endian:
// 0x0102030405060708 has a non zero octet at every position, so a build that wrote four octets,
// or wrote them in the other order, is a different info and a different key.
func TestEphKeyIsMasterSection81sDerivationAndNotThisPackagesOpinionOfIt(t *testing.T) {
	root := testEphRoot()
	for _, one := range []struct {
		bucket uint8
		window uint64
		want   string
	}{
		{0, 0, ephKeyKatBucket0Window0},
		{1, 0, ephKeyKatBucket1Window0},
		{1, 1, ephKeyKatBucket1Window1},
		{5, 709, ephKeyKatBucket5Window709},
		{5, 0x0102030405060708, ephKeyKatBucket5WindowWideT},
	} {
		got := hex.EncodeToString(EphKey(root, one.bucket, one.window))
		if got != one.want {
			t.Errorf("EphKey(root, %d, %d) = %s, want %s -- computed from MASTER section 8.1 and RFC 5869 outside this module",
				one.bucket, one.window, got, one.want)
		}
	}
	// and the info itself, so a failure above says WHICH of the three things moved
	if got := hex.EncodeToString(ephLabelledInfo(1, 1)); got != ephKeyKatInfoBucket1Window1 {
		t.Errorf("the info for bucket 1 window 1 is %s, want %s = \"eph/v1\" then u8(1) then eight octets of big endian u64(1)",
			got, ephKeyKatInfoBucket1Window1)
	}
}

// TestEphKeyRefusesEveryOffLadderBucketAndAcceptsTheTransientRung is P6 where it bites in
// production code rather than in a value test.
//
// -- CLASS: every uint8 that names no rung, derived from connect/message's own retention split.
// -- SCOPE: all 256 values of the argument type, offered one at a time.
// -- PROPERTY: EphKey answers a key for every rung INCLUDING bucket 0, and panics with
// ErrEphBucketOffLadder for every value that is not a rung. The two halves are what make the
// 2026-09-13 sentinel ruling load bearing: refuseOffLadderBucket asks EphBucketSeconds, and under
// the single shared sentinel the answer for bucket 0 and for bucket 6 was identical, so this
// function could only have been written to refuse both or to admit all 256.
func TestEphKeyRefusesEveryOffLadderBucketAndAcceptsTheTransientRung(t *testing.T) {
	root := testEphRoot()
	// the rungs, derived by asking connect/message's own split which buckets a wire byte can
	// name. Not "0 through 5": the ladder's length is the split's answer and reading it here is
	// how this gate stays true if a rung is ever added or removed.
	rungs := map[uint8]bool{}
	for candidate := 0; candidate <= 0xFF; candidate += 1 {
		class, bucket, err := message.RetentionClassOf(byte(candidate))
		if err == nil && class == message.RetentionEph {
			rungs[bucket] = true
		}
	}
	ladder, offLadder := []uint8{}, []uint8{}
	for candidate := 0; candidate <= 0xFF; candidate += 1 {
		bucket := uint8(candidate)
		if rungs[bucket] {
			ladder = append(ladder, bucket)
		} else {
			offLadder = append(offLadder, bucket)
		}
	}
	if len(ladder) == 0 || len(offLadder) == 0 {
		t.Fatalf("the wire split named %d rungs and %d non rungs; one of the two halves of this gate read nothing",
			len(ladder), len(offLadder))
	}
	if want := 256 - len(ladder); len(offLadder) != want {
		t.Fatalf("%d rungs and %d non rungs do not partition the 256 values of a uint8", len(ladder), len(offLadder))
	}
	printed := ""
	for _, bucket := range offLadder {
		printed += fmt.Sprintf("%02x", bucket)
	}
	t.Logf("class: EphKey answers for the %d rungs %v", len(ladder), ladder)
	t.Logf("complement: it refuses the %d values that name no rung, %s", len(offLadder), printed)

	for _, bucket := range ladder {
		key := EphKey(root, bucket, 0)
		if len(key) != ephKeyBytes {
			t.Errorf("EphKey answered %d octets for rung %d, want %d", len(key), bucket, ephKeyBytes)
		}
	}
	for _, bucket := range offLadder {
		func() {
			defer func() {
				recovered := recover()
				if recovered == nil {
					t.Errorf("EphKey answered a key for bucket %d, which names no rung; a key under a bucket no wire byte can carry is a key no peer ever derives", bucket)
					return
				}
				err, isError := recovered.(error)
				if !isError || !errors.Is(err, ErrEphBucketOffLadder) {
					t.Errorf("EphKey panicked on bucket %d with %v, want ErrEphBucketOffLadder", bucket, recovered)
				}
			}()
			EphKey(root, bucket, 0)
		}()
	}
	// and the transient rung is IN the class that answers, which is the half a gate written
	// against the pre-ruling sentinel would have got backwards.
	if !slices.Contains(ladder, uint8(0)) {
		t.Error("bucket 0 is not in the class EphKey answers for; the transient rung is a rung with a real key, and refusing it would make an EPH(0) delivery receipt unsealable")
	}
}

// TestTheWindowArithmeticIsThreeAnswersOverTheLaddersThree is EphWindowAt against the three cells
// message.EphBucketSeconds partitions a uint8 into, which is the caller the ruling was made for.
func TestTheWindowArithmeticIsThreeAnswersOverTheLaddersThree(t *testing.T) {
	const reading int64 = 1_700_000_000_000
	// the transient rung: window 0 and NO division, so the reading is not consulted at all.
	for _, other := range []int64{0, 1, reading, 1 << 60} {
		window, err := EphWindowAt(0, other)
		if err != nil {
			t.Errorf("EphWindowAt(0, %d): %v; bucket 0's window is 0 by definition and is never computed", other, err)
		}
		if window != 0 {
			t.Errorf("EphWindowAt(0, %d) = %d, want 0 -- MASTER section 8.1 makes bucket 0 one window for the life of eph_root", other, window)
		}
	}
	// the rungs that carry a window: floor of the division, with the divisor read off the
	// ladder rather than written here.
	for bucket := uint8(1); bucket <= 5; bucket += 1 {
		seconds := message.EphBucketSeconds(bucket)
		if seconds <= 0 {
			t.Fatalf("bucket %d answers %d seconds, so there is no divisor to check the arithmetic against", bucket, seconds)
		}
		divisor := uint64(seconds) * 1000
		window, err := EphWindowAt(bucket, reading)
		if err != nil {
			t.Fatalf("EphWindowAt(%d, %d): %v", bucket, reading, err)
		}
		if want := uint64(reading) / divisor; window != want {
			t.Errorf("EphWindowAt(%d, %d) = %d, want floor(%d / %d) = %d", bucket, reading, window, reading, divisor, want)
		}
		// the boundary in both directions, which is what says the divisor is this rung's
		// and not some other number that happens to agree at one instant
		first := int64(window * divisor)
		if got, _ := EphWindowAt(bucket, first); got != window {
			t.Errorf("the first millisecond of window %d on bucket %d falls in window %d", window, bucket, got)
		}
		if got, _ := EphWindowAt(bucket, first-1); got != window-1 {
			t.Errorf("the millisecond before window %d on bucket %d falls in window %d, want %d", window, bucket, got, window-1)
		}
	}
	// and the values that are not rungs
	for candidate := 6; candidate <= 0xFF; candidate += 1 {
		if _, err := EphWindowAt(uint8(candidate), reading); !errors.Is(err, ErrEphBucketOffLadder) {
			t.Errorf("EphWindowAt(%d, ...) answered %v, want ErrEphBucketOffLadder", candidate, err)
		}
	}
	// a reading before the unix epoch is refused rather than wrapped
	if _, err := EphWindowAt(1, -1); !errors.Is(err, ErrEphWindowSentAt) {
		t.Errorf("EphWindowAt(1, -1) answered %v, want ErrEphWindowSentAt", err)
	}
}

// ---------------------------------------------------------------------------
// P5: EphKey reads no clock
// ---------------------------------------------------------------------------

// Every import path this package's production source names, each classified as answering the
// current instant or not.
//
// THE TABLE IS THE LITERAL AND ITS LEVEL IS THE POINT. There is no way to read "answers the
// current instant" off a syntax tree, so the derivation stops here -- and it stops at a place
// where being wrong is visible: the gate below requires EVERY import path of the package to have
// a row, fatals on one that does not, and prints both halves with their counts. An import added
// to this package fails this gate on the commit that adds it, and whoever adds it has to say
// which half it belongs in. A three name list of time.Now, time.Since and time.Until -- which is
// the shape this project has shipped and regretted nine times -- would have been silent about
// runtime.nanotime, about a clock reached through a helper, and about an import nobody thought of.
var ephClockAnsweringImports = map[string]bool{
	"crypto/cipher":                        false,
	"crypto/ecdh":                          false,
	"crypto/mlkem":                         false,
	"crypto/sha256":                        false,
	"crypto/sha3":                          false,
	"crypto/subtle":                        false,
	"encoding/binary":                      false,
	"errors":                               false,
	"fmt":                                  false,
	"github.com/urnetwork/connect/message": false,
	"github.com/urnetwork/connect/mls":     false,
	"github.com/urnetwork/connect/mls/syntax": false,
	"golang.org/x/crypto/chacha20poly1305":    false,
	"io":                                      false,
	"sync":                                    false,
	// the two that would answer one. Neither is imported by this package today and both have
	// rows anyway, because a row that appears only when the import does is a row nobody
	// writes: the map would simply gain a `false` beside "time" on the commit that made the
	// mistake. These are what the gate is FOR.
	"time":    true,
	"runtime": true,
}

// ephClockSources is the three clause derivation of "this expression yields the current instant",
// computed over this package's production source.
type ephClockSources struct {
	// clause 1: the package qualifiers of imports classified as answering the instant.
	qualifiers map[string]string
	// clause 2: the NAMES of every declaration whose type is the package's clock shape,
	// func() int64 -- struct fields and function parameters alike. This is how self.nowMs()
	// and a nowMs parameter are found without either word appearing in this file.
	clockValueNames map[string]bool
	// every import path read, and the two halves of the classification, for printing.
	allImports   []string
	answering    []string
	notAnswering []string
	clockShapeAt []string
}

// ephReadClockSources builds the three clauses.
func ephReadClockSources(t *testing.T) *ephClockSources {
	t.Helper()
	fileSet, sources := messagegroupProductionSources(t)
	found := &ephClockSources{
		qualifiers:      map[string]string{},
		clockValueNames: map[string]bool{},
	}
	seen := map[string]bool{}
	for _, source := range sources {
		for _, spec := range source.parsed.Imports {
			path := strings.Trim(spec.Path.Value, "\"")
			if !seen[path] {
				seen[path] = true
				found.allImports = append(found.allImports, path)
			}
			answers, classified := ephClockAnsweringImports[path]
			if !classified {
				t.Fatalf("%s imports %q and ephClockAnsweringImports has no row for it. The class of clock sources is derived from that table, so an unclassified import is a hole in it: say whether that package can answer the current instant",
					source.path, path)
			}
			if !answers {
				continue
			}
			qualifier := path[strings.LastIndex(path, "/")+1:]
			if spec.Name != nil {
				qualifier = spec.Name.Name
			}
			found.qualifiers[qualifier] = path
		}
		// clause 2: every field or parameter whose type is func() int64
		ast.Inspect(source.parsed, func(node ast.Node) bool {
			field, isField := node.(*ast.Field)
			if !isField || !ephIsClockShape(field.Type) {
				return true
			}
			for _, name := range field.Names {
				found.clockValueNames[name.Name] = true
				found.clockShapeAt = append(found.clockShapeAt,
					fmt.Sprintf("%s (%s:%d)", name.Name, source.path, fileSet.Position(name.Pos()).Line))
			}
			return true
		})
	}
	slices.Sort(found.allImports)
	for _, path := range found.allImports {
		if ephClockAnsweringImports[path] {
			found.answering = append(found.answering, path)
		} else {
			found.notAnswering = append(found.notAnswering, path)
		}
	}
	slices.Sort(found.clockShapeAt)
	return found
}

// ephIsClockShape is "func() int64", which is the shape this package's own rule names: doc.go
// says "no function here takes a clock -- one that needs the time takes an injected
// nowMs func() int64". It is read off the type and not off the name, so a second clock called
// something else is in the class.
func ephIsClockShape(expr ast.Expr) bool {
	function, isFunction := expr.(*ast.FuncType)
	if !isFunction {
		return false
	}
	if function.Params != nil && 0 < len(function.Params.List) {
		return false
	}
	if function.Results == nil || len(function.Results.List) != 1 {
		return false
	}
	name, isIdent := function.Results.List[0].Type.(*ast.Ident)
	return isIdent && name.Name == "int64"
}

// ephCallGraph answers, for every function and method this package declares in production source,
// the set of names it calls -- both plain calls and selector calls, keyed by the selected name so
// that self.nowMs() and keyScheduleExpand(...) are both edges.
func ephCallGraph(t *testing.T, clocks *ephClockSources) (map[string][]string, map[string]bool, map[string]string) {
	t.Helper()
	fileSet, sources := messagegroupProductionSources(t)
	calls := map[string][]string{}
	readsClock := map[string]bool{}
	where := map[string]string{}
	for _, source := range sources {
		for _, declaration := range source.parsed.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			name := function.Name.Name
			where[name] = fmt.Sprintf("%s:%d", source.path, fileSet.Position(function.Pos()).Line)
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, isCall := node.(*ast.CallExpr)
				if !isCall {
					return true
				}
				switch callee := call.Fun.(type) {
				case *ast.Ident:
					calls[name] = append(calls[name], callee.Name)
					if clocks.clockValueNames[callee.Name] {
						readsClock[name] = true
					}
				case *ast.SelectorExpr:
					calls[name] = append(calls[name], callee.Sel.Name)
					if clocks.clockValueNames[callee.Sel.Name] {
						readsClock[name] = true
					}
					if qualifier, isIdent := callee.X.(*ast.Ident); isIdent {
						if _, isClockPackage := clocks.qualifiers[qualifier.Name]; isClockPackage {
							readsClock[name] = true
						}
					}
				}
				return true
			})
			// a clock package reached without a call at all -- time.Now is a call, but
			// a package level variable or a method value is not -- is still a reach.
			ast.Inspect(function.Body, func(node ast.Node) bool {
				selector, isSelector := node.(*ast.SelectorExpr)
				if !isSelector {
					return true
				}
				qualifier, isIdent := selector.X.(*ast.Ident)
				if !isIdent {
					return true
				}
				if _, isClockPackage := clocks.qualifiers[qualifier.Name]; isClockPackage {
					readsClock[name] = true
				}
				return true
			})
		}
	}
	// the fixed point: a function that calls a function that reads a clock reads a clock.
	for moved := true; moved; {
		moved = false
		for name, callees := range calls {
			if readsClock[name] {
				continue
			}
			for _, callee := range callees {
				if readsClock[callee] {
					readsClock[name] = true
					moved = true
					break
				}
			}
		}
	}
	return calls, readsClock, where
}

// TestEphKeyReachesNoClockSourceInThisPackage is P5.
//
// -- CLASS (of clock sources). Three clauses, all computed: the qualifiers of every import
//
//	classified as answering the current instant; the names of every declaration whose TYPE is
//	this package's clock shape, func() int64; and, by a fixed point over the package's own call
//	graph, every function that reaches either. Not a list of three time.* spellings.
//
// -- SCOPE. Every non test .go file in this package's directory, read with os.ReadDir at run
//
//	time. Not a list of files.
//
// -- PROPERTY. The transitive call closure of EphKey contains no member of that class. And the
//
//	class is required to be NON EMPTY over the package as a whole, which is the positive
//	control: this package really does read a clock, in the sealer and in the opener, so a
//	reachability analysis that found nothing found nothing because it is broken.
func TestEphKeyReachesNoClockSourceInThisPackage(t *testing.T) {
	clocks := ephReadClockSources(t)
	if len(clocks.allImports) == 0 {
		t.Fatal("no import was read out of this package's production source, so the classification below classified nothing")
	}
	if len(clocks.clockValueNames) == 0 {
		t.Fatal("no declaration of type func() int64 was found in this package's production source, so clause 2 of the clock class is empty and an injected clock would be invisible to this gate")
	}
	t.Logf("scope: %d import path(s) in production source", len(clocks.allImports))
	t.Logf("class, clause 1: %d import(s) that answer the current instant, %v", len(clocks.answering), clocks.answering)
	t.Logf("complement, clause 1: the %d that do not, %v", len(clocks.notAnswering), clocks.notAnswering)
	t.Logf("class, clause 2: %d declaration(s) of the clock shape func() int64, %v", len(clocks.clockShapeAt), clocks.clockShapeAt)

	calls, readsClock, where := ephCallGraph(t, clocks)
	if len(calls) == 0 {
		t.Fatal("no function body was read out of this package, so the closure below is empty for a reason that has nothing to do with EphKey")
	}
	readers := []string{}
	for name := range readsClock {
		readers = append(readers, name)
	}
	slices.Sort(readers)
	if len(readers) == 0 {
		t.Fatal("no function in this package reaches a clock source at all. This package DOES read a clock -- the sealer computes eph_window from it and the opener makes the ahead refusal with it -- so an empty answer here is a broken reachability walk reporting a clean bill, which is the failure this project's house rule is named for")
	}
	t.Logf("class, clause 3: %d function(s) in this package reach a clock source, %v", len(readers), readers)

	// EphKey's own closure, computed the same way.
	closure := map[string]bool{}
	frontier := []string{"EphKey"}
	for 0 < len(frontier) {
		name := frontier[0]
		frontier = frontier[1:]
		if closure[name] {
			continue
		}
		closure[name] = true
		frontier = append(frontier, calls[name]...)
	}
	if !closure["EphKey"] {
		t.Fatal("EphKey is not in its own closure, so this package declares no EphKey and this gate cleared a function that does not exist")
	}
	inClosure := []string{}
	for name := range closure {
		if _, isDeclaredHere := calls[name]; isDeclaredHere {
			inClosure = append(inClosure, name)
		}
	}
	slices.Sort(inClosure)
	if len(inClosure) < 2 {
		t.Fatalf("EphKey's closure over this package's own declarations is %v; a closure of one is a walk that followed no edge, and EphKey calls at least the width refusals and the expansion", inClosure)
	}
	t.Logf("EphKey's closure over this package's own declarations: %d, %v", len(inClosure), inClosure)
	for _, name := range inClosure {
		if readsClock[name] {
			t.Errorf("EphKey reaches %s (%s), which reads a clock. The window is the RECORD'S OWN eph_window field and never a value this derivation computes: a window EphKey derived for itself would differ from the sender's on every record that crossed a bucket boundary, and the AEAD tag would be the only thing in the system that said so",
				name, where[name])
		}
	}
}

// ---------------------------------------------------------------------------
// P7: the ahead refusal is reachable, the behind case is not a refusal
// ---------------------------------------------------------------------------

// The sentinels connect/messagegroup's record AEAD can answer, derived off recordaead.go rather
// than listed, so "separable from every AEAD failure" is a claim about the whole class.
//
// The registry below is held to that reading in BOTH directions: a sentinel recordaead.go names
// with no row here fails, and a row here for a sentinel recordaead.go no longer names fails. It
// is the shape entropy_test.go's probe table already uses, for the same reason -- a table that
// has fallen behind its subject is a gate reporting a clean bill over a class it is not holding.
var ephAeadSentinels = map[string]error{
	"ErrRecordAeadKeyLength":   ErrRecordAeadKeyLength,
	"ErrRecordAeadNonceLength": ErrRecordAeadNonceLength,
	"ErrRecordAeadAadMissing":  ErrRecordAeadAadMissing,
	"ErrRecordAeadOpen":        ErrRecordAeadOpen,
}

// ephAeadSentinelNames reads the sentinel names recordaead.go actually names.
func ephAeadSentinelNames(t *testing.T) []string {
	t.Helper()
	_, sources := messagegroupProductionSources(t)
	names := []string{}
	read := false
	for _, source := range sources {
		if source.path != "recordaead.go" {
			continue
		}
		read = true
		ast.Inspect(source.parsed, func(node ast.Node) bool {
			ident, isIdent := node.(*ast.Ident)
			if !isIdent || !strings.HasPrefix(ident.Name, "ErrRecordAead") {
				return true
			}
			if !slices.Contains(names, ident.Name) {
				names = append(names, ident.Name)
			}
			return true
		})
	}
	if !read {
		t.Fatal("recordaead.go was not among this package's production sources, so the class of AEAD failures was read off nothing")
	}
	slices.Sort(names)
	return names
}

// TestTheAheadRefusalIsReachableAndSeparableAndTheBehindCaseIsNot is P7, both halves.
//
// -- CLASS. The AEAD failure class is derived off recordaead.go's own source; the registry above
//
//	is held to it in both directions.
//
// -- SCOPE. Windows relative to the opener's own: far behind, one behind, exactly the opener's,
//
//	one ahead, two ahead, and far ahead. The boundary is what separates "more than one ahead"
//	from "one ahead", and it is asked on both sides of itself.
//
// -- PROPERTY. Two ahead and beyond is ErrEphWindowAhead and matches no member of the AEAD class;
//
//	one ahead, the opener's own, one behind and far behind are NOT that refusal at all.
func TestTheAheadRefusalIsReachableAndSeparableAndTheBehindCaseIsNot(t *testing.T) {
	names := ephAeadSentinelNames(t)
	if len(names) == 0 {
		t.Fatal("recordaead.go names no ErrRecordAead sentinel, so the class this refusal must be separable FROM is empty and the separability assertion below is vacuous")
	}
	registered := slices.Sorted(func(yield func(string) bool) {
		for name := range ephAeadSentinels {
			if !yield(name) {
				return
			}
		}
	})
	if !slices.Equal(names, registered) {
		t.Fatalf("recordaead.go names %v and ephAeadSentinels registers %v; the separability claim is over the whole AEAD failure class and a class read off a stale table is not that class",
			names, registered)
	}
	t.Logf("class: the %d AEAD failure sentinels recordaead.go names, %v", len(names), names)

	const bucket uint8 = 1
	fixture := newTestSession(t, "ahead-refusal")
	fixture.installEphRoot(t)
	own := ephWindowNow(t, bucket)
	if own < 2 {
		t.Fatalf("the fixture clock falls in window %d on bucket %d, so there is no window behind it to test the other half of the asymmetry with", own, bucket)
	}

	// the control: an EPH record at the opener's own window round trips, so every refusal
	// below is about the window and not about the class.
	fixture.trackOwnLadder(t, message.RetentionEph, bucket, own)
	record, err := fixture.session.SealRecord(message.RetentionEph, bucket, false,
		[]byte("head"), []byte("body"), 0, nil)
	if err != nil {
		t.Fatalf("sealing an EPH(%d) record at the opener's own window: %v", bucket, err)
	}
	if record.Header.EphWindow != own {
		t.Fatalf("the sealer wrote window %d and this opener is in window %d; the control is not at the window this case thinks it is",
			record.Header.EphWindow, own)
	}
	if _, _, err := fixture.session.OpenRecord(record); err != nil {
		t.Fatalf("the control record does not open: %v", err)
	}

	for _, one := range []struct {
		name     string
		window   uint64
		refusing bool
	}{
		{"far behind", 0, false},
		{"one behind", own - 1, false},
		{"the opener's own", own, false},
		{"one ahead", own + 1, false},
		{"two ahead", own + 2, true},
		{"far ahead", own + (1 << 32), true},
	} {
		moved := *record
		moved.Header.EphWindow = one.window
		_, _, err := fixture.session.OpenRecord(&moved)
		isRefusal := errors.Is(err, ErrEphWindowAhead)
		if isRefusal != one.refusing {
			if one.refusing {
				t.Errorf("%s (window %d against the opener's %d) answered %v and is not ErrEphWindowAhead; a refusal nothing can reach is the defect spec A section 5.3's asymmetry exists to avoid",
					one.name, one.window, own, err)
			} else {
				t.Errorf("%s (window %d against the opener's %d) answered ErrEphWindowAhead; a window behind the opener's own is NOT a refusal in any amount, and one ahead is inside MASTER section 9.2's plus-or-minus one, so this refusal is firing on the legitimate case",
					one.name, one.window, own)
			}
		}
		if !isRefusal {
			continue
		}
		// SEPARABILITY, over the whole derived class rather than over one sentinel.
		for _, name := range names {
			if errors.Is(err, ephAeadSentinels[name]) {
				t.Errorf("%s answered an error that errors.Is matches %s as well as ErrEphWindowAhead; spec A section 5.3 requires the ahead refusal to be separable by errors.Is from every AEAD failure, and a caller rendering it as a gap with reason malformed cannot tell them apart",
					one.name, name)
			}
		}
	}
	t.Logf("bucket %d, opener in window %d: refused at %d and beyond, admitted at %d and below", bucket, own, own+2, own+1)
}

// ephReproduceRecordKey rebuilds one EPH record's rung from the outside: the root, the bucket, a
// window, the leaf and the record's own stream index, with nothing taken from the session.
//
// The walk is what makes stream_index a key input rather than a label -- a record at index k is
// sealed under the k'th rung and under no other -- and it is spelled here rather than shared with
// the sealer, which is the whole point of a reproduction.
func ephReproduceRecordKey(ephRoot []byte, bucket uint8, window uint64, leaf uint32,
	streamIndex uint64) []byte {

	recordKey := RecordKeyZero(EphKey(ephRoot, bucket, window), leaf)
	for walked := uint64(0); walked < streamIndex; walked += 1 {
		recordKey = RecordKeyNext(recordKey)
	}
	return recordKey
}

// TestAnEphRecordIsSealedUnderItsOwnWindowsKeyAndUnderNoOther is the property a round trip cannot
// see, and it is here because a mutation escaped without it.
//
// THE ESCAPE, RECORDED BECAUSE IT IS THE REASON THIS CASE EXISTS. classKeyOnLoop was changed to
// derive EphKey(eph_root, bucket, 0) -- the window written into the header, onto the wire, into
// both AADs and into the write_auth preimage, and IGNORED by the key -- and the whole suite over
// ./message/ and ./messagegroup/ stayed GREEN. It has to: the sealer and the opener are the same
// two lines of this package, so they agree with each other about the wrong key and every record
// round trips perfectly. What such a build produces is a record no second implementation can ever
// open, and a disappearing-message guarantee that is gone -- every window of a bucket would share
// one key, so destroying a window would destroy nothing.
//
// -- CLASS. Every eph bucket that carries a window, derived off connect/message's ladder.
// -- SCOPE. Each record's own wire window, and two windows that are NOT it -- zero, which is the
// value the escaping mutation used, and the next one up. Both halves are needed: the first says
// the right key opens the record, the second says a wrong one does not, and the first alone is
// satisfied by a build that ignores the window entirely whenever the window happens to be zero.
// -- PROPERTY. ct_head and ct_body open under the rung rebuilt from the record's OWN eph_window
// and under no other window's, using the package's exported derivations and the record's own
// header, with no value taken from the session that sealed it.
func TestAnEphRecordIsSealedUnderItsOwnWindowsKeyAndUnderNoOther(t *testing.T) {
	headPlain := []byte("the head this record carries")
	bodyPlain := []byte("the body this record carries")
	root := testEphRoot()
	buckets := []uint8{}
	for candidate := 0; candidate <= 0xFF; candidate += 1 {
		class, bucket, err := message.RetentionClassOf(byte(candidate))
		if err != nil || class != message.RetentionEph {
			continue
		}
		if !slices.Contains(buckets, bucket) {
			buckets = append(buckets, bucket)
		}
	}
	if len(buckets) == 0 {
		t.Fatal("the wire admits no eph bucket, so this reproduction rebuilt nothing")
	}
	slices.Sort(buckets)
	opened := 0
	for _, bucket := range buckets {
		fixture := newTestSession(t, fmt.Sprintf("own-window-key-%d", bucket))
		fixture.installEphRoot(t)
		window := ephWindowNow(t, bucket)
		fixture.trackOwnLadder(t, message.RetentionEph, bucket, window)
		record, err := fixture.session.SealRecord(message.RetentionEph, bucket, false,
			headPlain, bodyPlain, 0, nil)
		if err != nil {
			t.Fatalf("bucket %d: seal: %v", bucket, err)
		}
		leaf := fixture.handle.OwnLeafIndex()
		aadHead, err := message.AADHead(RecordAeadAlgId, &record.Header, record.Header.ServerAttachment)
		if err != nil {
			t.Fatalf("bucket %d: AADHead: %v", bucket, err)
		}
		aadBody, err := message.AADBody(RecordAeadAlgId, record.Header.BodyBinding())
		if err != nil {
			t.Fatalf("bucket %d: AADBody: %v", bucket, err)
		}

		// the record's OWN window: both ciphertexts must open.
		rung := ephReproduceRecordKey(root, bucket, record.Header.EphWindow, leaf, record.Header.StreamIndex)
		headKey, headNonce := RecordAeadHead(rung)
		gotHead, err := openRecordAead(headKey, headNonce, aadHead, record.CtHead)
		if err != nil {
			t.Errorf("bucket %d, window %d: ct_head does not open under the rung rebuilt from the record's own eph_window: %v. The class key of an EPH record is EphKey(eph_root, bucket, the record's own window) -- a sealer that passed some other window produces a record that round trips against itself and that no second implementation can open",
				bucket, record.Header.EphWindow, err)
			continue
		}
		if !bytes.Equal(gotHead, headPlain) {
			t.Errorf("bucket %d: ct_head opened to different octets", bucket)
			continue
		}
		bodyKey, bodyNonce := RecordAeadBody(rung)
		padded, err := openRecordAead(bodyKey, bodyNonce, aadBody, record.CtBody)
		if err != nil {
			t.Errorf("bucket %d, window %d: ct_body does not open under the rung rebuilt from the record's own eph_window: %v",
				bucket, record.Header.EphWindow, err)
			continue
		}
		gotBody, err := unpadBody(record.Header.SizeBucket, padded)
		if err != nil || !bytes.Equal(gotBody, bodyPlain) {
			t.Errorf("bucket %d: ct_body opened to %q (%v)", bucket, gotBody, err)
			continue
		}
		opened += 1

		// AND UNDER NO OTHER WINDOW. Zero is the value the escaping mutation used, so it is
		// asked of every bucket including the one whose real window IS zero -- where the two
		// coincide and the case below is legitimately skipped, which is printed rather than
		// silently passed over.
		for _, other := range []uint64{0, record.Header.EphWindow + 1} {
			if other == record.Header.EphWindow {
				t.Logf("bucket %d: window %d is the record's own, so it is not a wrong window to try", bucket, other)
				continue
			}
			wrong := ephReproduceRecordKey(root, bucket, other, leaf, record.Header.StreamIndex)
			wrongKey, wrongNonce := RecordAeadHead(wrong)
			if _, err := openRecordAead(wrongKey, wrongNonce, aadHead, record.CtHead); err == nil {
				t.Errorf("bucket %d: ct_head sealed at window %d ALSO opens under window %d's key; the window is then not an input to the key at all, and destroying one window's key would destroy nothing",
					bucket, record.Header.EphWindow, other)
			}
		}
	}
	if opened == 0 {
		t.Fatal("no record was rebuilt at all, so this reproduction reported clean having opened nothing")
	}
	t.Logf("%d of %d eph buckets rebuilt from the outside: EphKey(root, bucket, the record's own eph_window), RecordKeyZero, the walk to stream_index, then both aead derivations",
		opened, len(buckets))
}

// TestAnOpenerTakesTheWireWindowAndNeverRecomputesOne is the half of P7 a FIXED clock cannot see,
// and it is here because a mutation escaped without it.
//
// THE ESCAPE, RECORDED BECAUSE IT IS THE REASON THIS CASE EXISTS. The opener's ratchet lookup was
// changed to recompute the window from its own clock instead of reading header.EphWindow -- the
// exact defect spec A section 5.3 and MASTER section 8 name in capitals, "AN OPENER TAKES THE WIRE
// VALUE AND NEVER RECOMPUTES IT" -- and the whole suite over ./message/ and ./messagegroup/ stayed
// GREEN. Every fixture in this package seals and opens under one fixed clock reading, so the
// recomputed window and the wire window are the same number in every case that existed, and a
// property about them DIFFERING had nothing to differ.
//
// -- CLASS. Every eph bucket that carries a window, derived off connect/message's own ladder, so a
// rung added or removed is inside this case without an edit.
// -- SCOPE. A clock that moves ONE window forward between the seal and the open, and one that moves
// a thousand windows forward. Two points, because one of them is the boundary and the other says
// the property is not about the boundary.
// -- PROPERTY. The record opens, head and body byte for byte, at an opener whose own window is not
// the record's. It is the strong form of "a window behind the opener's own is not a refusal in any
// amount": not merely that the typed refusal does not fire, but that the record still reads.
func TestAnOpenerTakesTheWireWindowAndNeverRecomputesOne(t *testing.T) {
	headPlain := []byte("the head this record carries")
	bodyPlain := []byte("the body this record carries")
	buckets := []uint8{}
	for candidate := 0; candidate <= 0xFF; candidate += 1 {
		class, bucket, err := message.RetentionClassOf(byte(candidate))
		if err != nil || class != message.RetentionEph {
			continue
		}
		if 0 < message.EphBucketSeconds(bucket) && !slices.Contains(buckets, bucket) {
			buckets = append(buckets, bucket)
		}
	}
	if len(buckets) == 0 {
		t.Fatal("no eph bucket carries a window, so there is no window for a clock to move across and this case observed nothing")
	}
	slices.Sort(buckets)
	t.Logf("class: the %d eph buckets that carry a window, %v", len(buckets), buckets)

	for _, bucket := range buckets {
		for _, forward := range []uint64{1, 1000} {
			at := testClock()()
			now := func() int64 { return at }
			fixture := newTestSessionAtClock(t, fmt.Sprintf("wire-window-%d-%d", bucket, forward), now)
			fixture.installEphRoot(t)
			sealedAt, err := EphWindowAt(bucket, at)
			if err != nil {
				t.Fatalf("EphWindowAt(%d): %v", bucket, err)
			}
			fixture.trackOwnLadder(t, message.RetentionEph, bucket, sealedAt)
			record, err := fixture.session.SealRecord(message.RetentionEph, bucket, false,
				headPlain, bodyPlain, 0, nil)
			if err != nil {
				t.Fatalf("bucket %d: seal: %v", bucket, err)
			}
			if record.Header.EphWindow != sealedAt {
				t.Fatalf("bucket %d: the sealer wrote window %d and the clock falls in %d",
					bucket, record.Header.EphWindow, sealedAt)
			}
			// the clock moves forward by whole windows. Nothing sleeps and nothing is
			// timed: the value the closure reads is set here.
			divisor := int64(message.EphBucketSeconds(bucket)) * 1000
			at += int64(forward) * divisor
			movedTo, err := EphWindowAt(bucket, at)
			if err != nil {
				t.Fatalf("EphWindowAt(%d) after the move: %v", bucket, err)
			}
			if movedTo != sealedAt+forward {
				t.Fatalf("bucket %d: the clock moved to window %d, want %d", bucket, movedTo, sealedAt+forward)
			}
			gotHead, gotBody, err := fixture.session.OpenRecord(record)
			if err != nil {
				t.Errorf("bucket %d: a record sealed in window %d does not open at an opener in window %d: %v. The opener must take the record's own eph_window off the wire; one it recomputed from its own clock is a different window on every record that crossed a boundary, and the AEAD tag would be the only thing that said so",
					bucket, sealedAt, movedTo, err)
				continue
			}
			if !bytes.Equal(gotHead, headPlain) || !bytes.Equal(gotBody, bodyPlain) {
				t.Errorf("bucket %d: the record opened to different octets at an opener in window %d", bucket, movedTo)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// P8: the seal lift, and the one record ledger open item 185 still refuses
// ---------------------------------------------------------------------------

// TestEverySealableClassRoundTripsAndTheWrapItemOneEightyFiveRefusesDoesNot is P8.
//
// -- CLASS. Every retention wire byte connect/message's own split accepts, walked over all 256
//
//	octets. Not a list of four class names: the eph buckets are six of the nine and they arrived
//	in this class on 2026-09-13, which is exactly the kind of widening a written list misses.
//
// -- SCOPE. All 256 octets, offered to RetentionClassOf, whose acceptances are the alphabet.
// -- PROPERTY. Every accepted byte seals AND opens, byte for byte, at a session holding an
//
//	eph_root -- which is spec A section 5.3's "SealRecord and OpenRecord may seal and open EVERY
//	retention class". And the eph_root device wrap is refused: an EPH record carrying a WrapTag,
//	ledger open item 185, filed and not ruled. Its complement is printed and pinned -- the
//	PERMANENT wrap, which is the pq_secret device wrap and is unaffected.
func TestEverySealableClassRoundTripsAndTheWrapItemOneEightyFiveRefusesDoesNot(t *testing.T) {
	accepted := []byte{}
	for candidate := 0; candidate <= 0xFF; candidate += 1 {
		if _, _, err := message.RetentionClassOf(byte(candidate)); err == nil {
			accepted = append(accepted, byte(candidate))
		}
	}
	if len(accepted) == 0 {
		t.Fatal("the retention split accepts no wire byte at all, so this gate walked an empty alphabet")
	}
	t.Logf("class: the %d retention wire bytes the split accepts, %#x", len(accepted), accepted)

	headPlain := []byte("the head this record carries")
	bodyPlain := []byte("the body this record carries")
	sealed := []byte{}
	for _, wire := range accepted {
		class, bucket, err := message.RetentionClassOf(wire)
		if err != nil {
			t.Fatalf("wire %#02x: %v", wire, err)
		}
		// a session per byte, because each class takes its own ladder and a receiver
		// ratchet has to be installed at the window the sealer will write.
		fixture := newTestSession(t, fmt.Sprintf("lift-%02x", wire))
		fixture.installEphRoot(t)
		window := uint64(0)
		if class == message.RetentionEph {
			window = ephWindowNow(t, bucket)
		}
		fixture.trackOwnLadder(t, class, bucket, window)
		record, err := fixture.session.SealRecord(class, bucket, false, headPlain, bodyPlain, 0, nil)
		if err != nil {
			t.Errorf("wire %#02x (class %d bucket %d) was refused by the sealer: %v; spec A section 5.3 lifts the class refusal in full",
				wire, class, bucket, err)
			continue
		}
		if record.Header.EphWindow != window {
			t.Errorf("wire %#02x sealed with window %d, want %d -- MASTER section 8's presence rule is zero off EPH(1..5) and the bucket's own window on it",
				wire, record.Header.EphWindow, window)
		}
		gotHead, gotBody, err := fixture.session.OpenRecord(record)
		if err != nil {
			t.Errorf("wire %#02x (class %d bucket %d) sealed and does not open: %v", wire, class, bucket, err)
			continue
		}
		if !bytes.Equal(gotHead, headPlain) || !bytes.Equal(gotBody, bodyPlain) {
			t.Errorf("wire %#02x round tripped to different octets", wire)
			continue
		}
		sealed = append(sealed, wire)
	}
	if !bytes.Equal(sealed, accepted) {
		t.Errorf("%#x sealed and opened, want the whole accepted alphabet %#x", sealed, accepted)
	}

	// ITEM 185. The eph_root device wrap is an EPH record carrying a WrapTag; the pq_secret
	// device wrap is the same attachment on a PERMANENT record and seals. Both halves are
	// walked over the same alphabet, so the refused set and its complement are computed rather
	// than asserted one at a time.
	wrapTag := &message.ServerAttachment{
		Kind: message.AttachmentWrap,
		Wrap: &message.WrapTag{WrapTargetHandle: make([]byte, 16)},
	}
	refusedWrap, sealedWrap := []byte{}, []byte{}
	for _, wire := range accepted {
		class, bucket, err := message.RetentionClassOf(wire)
		if err != nil {
			t.Fatalf("wire %#02x: %v", wire, err)
		}
		fixture := newTestSession(t, fmt.Sprintf("wrap-%02x", wire))
		fixture.installEphRoot(t)
		_, err = fixture.session.SealRecord(class, bucket, false, headPlain, bodyPlain, 0, wrapTag)
		switch {
		case errors.Is(err, ErrEphWrapWindowUnruled):
			refusedWrap = append(refusedWrap, wire)
		case err == nil:
			sealedWrap = append(sealedWrap, wire)
		default:
			t.Errorf("wire %#02x carrying a wrap tag answered %v, which is neither a sealed wrap nor item 185's refusal", wire, err)
		}
	}
	wantRefused, wantSealed := []byte{}, []byte{}
	for _, wire := range accepted {
		class, _, _ := message.RetentionClassOf(wire)
		if class == message.RetentionEph {
			wantRefused = append(wantRefused, wire)
		} else {
			wantSealed = append(wantSealed, wire)
		}
	}
	if len(wantRefused) == 0 || len(wantSealed) == 0 {
		t.Fatalf("the alphabet split into %d eph and %d non eph bytes, so one half of item 185's refusal read nothing", len(wantRefused), len(wantSealed))
	}
	if !bytes.Equal(refusedWrap, wantRefused) {
		t.Errorf("a wrap tag was refused on %#x, want exactly the eph bytes %#x; ledger open item 185 says a builder MUST NOT publish the eph_root device wrap until its own eph_window value is ruled",
			refusedWrap, wantRefused)
	}
	if !bytes.Equal(sealedWrap, wantSealed) {
		t.Errorf("a wrap tag sealed on %#x, want exactly the non eph bytes %#x; the pq_secret device wrap is PERMANENT, carries the presence rule's zero and is unaffected by item 185",
			sealedWrap, wantSealed)
	}
	t.Logf("item 185: a wrap tag is refused on the %d eph bytes %#x; complement, it seals on the %d non eph bytes %#x",
		len(refusedWrap), refusedWrap, len(sealedWrap), sealedWrap)

	// AND THE REFUSAL READS BOTH HALVES OF THE ATTACHMENT'S OWN PRESENCE RULE. An attachment
	// carrying a WrapTag body under some other tag is a wrap by the rule connect/message
	// computes, and item 185's refusal runs BEFORE EncodeServerAttachment -- so without the
	// body half of the check this record would still be refused, but as a tag mismatch, which
	// is a different sentence about a different problem. A builder meeting item 185 is owed
	// item 185's reason.
	misTagged := &message.ServerAttachment{
		Kind: message.AttachmentNone,
		Wrap: &message.WrapTag{WrapTargetHandle: make([]byte, 16)},
	}
	mis := newTestSession(t, "wrap-mistagged")
	mis.installEphRoot(t)
	if _, err := mis.session.SealRecord(message.RetentionEph, 5, false, headPlain, bodyPlain, 0,
		misTagged); !errors.Is(err, ErrEphWrapWindowUnruled) {
		t.Errorf("an EPH(5) record carrying a WrapTag BODY under a different tag answered %v, want ErrEphWrapWindowUnruled; the presence rule connect/message computes is what says a record is a wrap, and item 185's refusal reads it rather than the tag alone", err)
	}
}

// TestTwoEphWindowsOfOneBucketAreTwoLadders is the consequence of the ruling that a round trip
// cannot see, because a round trip inside one window never crosses one.
//
// K_eph[n][b][t] takes t, so a record written in window t+1 is sealed under a different class key
// from one written in window t -- which means a different ladder, a different record_key[0] and a
// different rung. A session that cached its ladders by the retention wire byte alone would hand
// the second record the first window's ladder: a record whose wire says t+1 and whose key is t's,
// which this session would seal happily and which no member of the group including the sender
// could ever open.
func TestTwoEphWindowsOfOneBucketAreTwoLadders(t *testing.T) {
	const bucket uint8 = 1
	fixture := newTestSession(t, "two-windows")
	fixture.installEphRoot(t)
	root := testEphRoot()
	here := ephWindowNow(t, bucket)
	if EphKey(root, bucket, here) == nil {
		t.Fatal("EphKey answered nothing")
	}
	if bytes.Equal(EphKey(root, bucket, here), EphKey(root, bucket, here+1)) {
		t.Fatal("two windows of one bucket derive one class key, so nothing below could tell two ladders apart")
	}
	var first, second *SenderRatchet
	if postErr := fixture.session.do(func() {
		wire, err := message.RetentionClassWire(message.RetentionEph, bucket)
		if err != nil {
			t.Errorf("RetentionClassWire: %v", err)
			return
		}
		first, err = fixture.session.senderRatchetOnLoop(message.RetentionEph, wire, bucket, here)
		if err != nil {
			t.Errorf("the ladder for window %d: %v", here, err)
			return
		}
		second, err = fixture.session.senderRatchetOnLoop(message.RetentionEph, wire, bucket, here+1)
		if err != nil {
			t.Errorf("the ladder for window %d: %v", here+1, err)
			return
		}
	}); postErr != nil {
		t.Fatalf("post the ratchet command: %v", postErr)
	}
	if first == nil || second == nil {
		t.Fatal("one of the two ladders was not built")
	}
	if first == second {
		t.Error("one bucket's two windows were handed ONE sender ladder; the second window's records would be sealed under the first window's class key, which is a record the wire says t+1 for and nothing can derive a key for")
	}
	// and they reserve in the SAME stream, which is ruling A1: the counter is class blind and
	// window blind, one per (group_id, sender_handle).
	if first.stream != second.stream {
		t.Error("one bucket's two windows reserve in two different streams; ruling A1 makes the counter class blind, and a client counting per window has its next window's first record refused by the server as a stream index regression")
	}
}

// TestTheEphRootDoorRefusesAWrongWidthAndTheEpochChangeDropsIt holds the two clauses of
// InstallEphRoot that nothing else in this suite reaches.
//
// BOTH WERE MEASURED DEAD BEFORE THIS CASE EXISTED. Deleting the width refusal turned nothing red,
// and so did deleting the erase-and-drop in installEpochOnLoop. A clause nothing can turn red is a
// clause that defends nothing, so either it goes or something holds it, and both of these are
// worth holding.
//
// THE WIDTH. eph_root is the root of every ephemeral key of an epoch. A short one expands to a
// perfectly well formed thirty two octet class key that this session and nothing else in the world
// derives, and the value arrives from outside this package -- a committer's draw, or an eph_root
// device wrap decoded out of a record -- so a wrong width is a thing that can actually happen.
//
// THE DROP. eph_root[n] is scoped to epoch n: MASTER invariant I4 makes it fresh CSPRNG at the
// commit that opens the epoch, so it is not re-derivable and installEpochOnLoop cannot replace it
// the way it replaces every other key beside it. Carrying it across would seal an epoch n+1 record
// under a key epoch n promised to destroy -- a record no other member could open, on a key that
// outlives the epoch it belongs to. The refusal after an epoch change is what says it was dropped.
func TestTheEphRootDoorRefusesAWrongWidthAndTheEpochChangeDropsIt(t *testing.T) {
	fixture := newTestSession(t, "eph-root-door")
	// every width that is not the right one, either side of it and at the two ends
	for _, width := range []int{0, 1, EphRootBytes - 1, EphRootBytes + 1, 64} {
		if err := fixture.session.InstallEphRoot(make([]byte, width)); !errors.Is(err, ErrEphRootLength) {
			t.Errorf("InstallEphRoot of %d octets answered %v, want ErrEphRootLength; a short root expands to a well formed class key that no peer derives", width, err)
		}
	}
	if err := fixture.session.InstallEphRoot(nil); !errors.Is(err, ErrEphRootLength) {
		t.Errorf("InstallEphRoot(nil) answered %v, want ErrEphRootLength", err)
	}
	// the control: the right width is accepted, so the refusals above are about the width and
	// not about a door that refuses everything.
	fixture.installEphRoot(t)
	if _, err := fixture.session.SealRecord(message.RetentionEph, 1, false,
		[]byte("head"), []byte("body"), 0, nil); err != nil {
		t.Fatalf("after a good install an EPH record is still refused: %v", err)
	}

	// AND THE EPOCH CHANGE DROPS IT. The handle moves first -- an empty commit, merged -- and
	// then the session installs the epoch the handle is now at, which is the body that drops
	// every key of the epoch it is leaving.
	if _, _, _, err := fixture.handle.Commit(nil); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := fixture.handle.MergePendingCommit(); err != nil {
		t.Fatalf("MergePendingCommit: %v", err)
	}
	if err := fixture.session.AdvanceEpoch(testPqSecret()); err != nil {
		t.Fatalf("AdvanceEpoch: %v", err)
	}
	if _, err := fixture.session.SealRecord(message.RetentionEph, 1, false,
		[]byte("head"), []byte("body"), 0, nil); !errors.Is(err, ErrNoEphRoot) {
		t.Errorf("after an epoch change an EPH record sealed with %v, want ErrNoEphRoot; eph_root[n] is fresh CSPRNG at the commit that opens epoch n and cannot be re-derived, so carrying it across seals an epoch n+1 record under a key epoch n promised to destroy", err)
	}
	// and the non eph classes are unaffected, which is what says the drop is the eph root's
	// and not the whole schedule's
	if _, err := fixture.session.SealRecord(message.RetentionDurable, 0, false,
		[]byte("head"), []byte("body"), 0, nil); err != nil {
		t.Errorf("after an epoch change a DURABLE record answered %v; the three class keys are re-derived from the new storage root and only eph_root is dropped", err)
	}
}

// ---------------------------------------------------------------------------
// the stale citations the ruling leaves behind
// ---------------------------------------------------------------------------

// The two dates the owner ruled on. A citation of a closed item has to carry one of them.
//
// DATES AND NOT WORDS, and the reason is a measured false negative rather than a preference. The
// first shape of this gate asked whether the citing comment said "ruled", and doc.go's own stale
// sentence -- "open item M1-6 has NOT ruled which record key seals ct_head", of an item ruled
// 2026-09-07 and reversed 2026-09-13 -- satisfied it, because "has not ruled" contains the word
// "ruled". Every polarity carrying word has that problem and the
// fix is not a longer list of phrases: a date has no polarity. It is also the thing a reader
// actually needs, because what makes a citation safe is not the word "ruled" but knowing WHICH
// ruling, on a corpus where one of these two was ruled and then reversed six days later.
var ephRulingDates = []string{"2026-09-07", "2026-09-13"}

// How far either side of the citing line a date counts as being beside it.
//
// Two lines, and the number is small on purpose. The unit this gate judges is the SENTENCE a
// reader lands on, not the comment group: doc.go's header is one hundred and thirty unbroken
// comment lines and go's parser makes all of it ONE group, so a group wide reading would clear a
// stale sentence at line 98 because of a date at line 12. That is the same distance failure the
// corpus itself keeps filing -- a rule and its carve-out seventy lines apart -- and it is why the
// window is a handful of lines rather than a paragraph.
const ephCitationWindowLines = 2

// TestEveryCitationOfTheRuledItemsCarriesItsRulingDate is the gate the item-152 cleanup owes.
//
// -- CLASS. Every comment LINE in this package that cites ledger item 152 or m1 open item M1-6.
// Both are closed -- M1-6 ruled 2026-09-07 and REVERSED 2026-09-13, 152 ruled 2026-09-13 -- so a
// citation of either is a citation of a closed item, and one that reads as though the item were
// open is the pre-amendment-comment trap this corpus keeps filing (ledger 141's class). The class
// is the citations themselves and not a list of files: a stale line moved to a new file is still
// in it.
//
// -- SCOPE. Every .go file in this package's directory, TEST FILES INCLUDED, read with os.ReadDir
// at run time. It is wider than messagegroupProductionSources on purpose: four of the six files
// that carried a stale citation were _test.go files, and a gate over production source alone
// would have reported clean over four of them.
//
// -- PROPERTY. Every citing line carries a ruling date within two lines of itself. The class is
// required to be NON EMPTY -- the two items really are cited here, and a run that found no
// citation would be a walk that read nothing -- and the complement, the citations with no date
// beside them, is printed line by line rather than counted.
func TestEveryCitationOfTheRuledItemsCarriesItsRulingDate(t *testing.T) {
	fileSet, sources := ephAllPackageSources(t)
	cited := []string{}
	undated := []string{}
	for _, source := range sources {
		for _, group := range source.parsed.Comments {
			lines := group.List
			for index, line := range lines {
				text := strings.ToLower(line.Text)
				if !strings.Contains(text, "item 152") && !strings.Contains(text, "m1-6") {
					continue
				}
				at := fmt.Sprintf("%s:%d", source.path, fileSet.Position(line.Pos()).Line)
				cited = append(cited, at)
				window := ""
				for offset := -ephCitationWindowLines; offset <= ephCitationWindowLines; offset += 1 {
					if neighbour := index + offset; 0 <= neighbour && neighbour < len(lines) {
						window += lines[neighbour].Text + " "
					}
				}
				dated := false
				for _, date := range ephRulingDates {
					if strings.Contains(window, date) {
						dated = true
					}
				}
				if !dated {
					undated = append(undated, at)
				}
			}
		}
	}
	slices.Sort(cited)
	slices.Sort(undated)
	if len(cited) == 0 {
		t.Fatal("no comment line in this package cites ledger item 152 or m1 open item M1-6 at all. Both are the subject of the ruling this commit implements and both are cited here, so an empty class is a walk that read nothing rather than a package with nothing to check")
	}
	t.Logf("class: %d comment line(s) cite ledger item 152 or M1-6", len(cited))
	t.Logf("complement: %d of them carry no ruling date within %d lines, %v", len(undated), ephCitationWindowLines, undated)
	for _, at := range undated {
		t.Errorf("%s cites ledger item 152 or m1 open item M1-6 with no ruling date beside it. M1-6 was ruled 2026-09-07 and REVERSED 2026-09-13; 152 was ruled 2026-09-13 and the EPH seal refusal it held is lifted in full. An undated citation of a closed item is the trap that let a source comment quote a pre-amendment interface and be the stale copy, and the date is what tells a reader WHICH of the two rulings on this item is the one that stands",
			at)
	}
}

// ephAllPackageSources is messagegroupProductionSources widened to the test files.
//
// It is a separate reading and not a parameter on that one, because every other gate in this
// package means PRODUCTION source when it says source and a flag on the shared helper would be a
// flag somebody passes wrongly. What makes this one wider is stated in the gate above rather than
// here: the stale citations this package carried were mostly in _test.go files.
func ephAllPackageSources(t *testing.T) (*token.FileSet, []messagegroupSource) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read this package's directory: %v", err)
	}
	fileSet := token.NewFileSet()
	sources := []messagegroupSource{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		path := filepath.ToSlash(filepath.Join(".", name))
		parsed, err := parser.ParseFile(fileSet, path, nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		sources = append(sources, messagegroupSource{path: path, parsed: parsed})
	}
	if len(sources) == 0 {
		t.Fatal("no go file was read out of this package, so the gate written over this reading cleared its subject having read nothing")
	}
	return fileSet, sources
}
