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
	"io/fs"
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

// The import paths that answer the current instant. THIS IS THE ONLY LITERAL LEFT IN THIS
// DERIVATION, and where it sits is the whole repair.
//
// WHAT STOOD HERE BEFORE AND HOW IT WAS EVADED, LIVE. This was a boolean table keyed on IMPORT
// PATH, one row per package this package names, and "github.com/urnetwork/connect/message" had
// false beside it. A row like that is a claim about ANOTHER PACKAGE'S CONTENTS asserted in this
// file, and nothing checked it. A reviewer added a SenderClockMs to connect/message that answers
// time.Now().UnixMilli(), made EphKey overwrite its window argument from it, and this gate stayed
// GREEN over a live clock read inside the subject function, printing "clause 1: 0 import(s) that
// answer the current instant, []". Nobody had to lie in the table: the clock went in a package the
// table already rowed clean. connect/mls is rowed the same way and ALREADY calls time.Now.
//
// THE FIX IS THE LEVEL AND NOT THE ROW. No package OF THIS MODULE is answered by a literal any
// more. Its directory is resolved off go.mod at run time, its production source is parsed, and
// its functions are judged by the same three clauses, so a clock function in connect/message
// resolves to its own declaration, that declaration is seen to reach time.Now, and the edge lands
// inside EphKey's closure. What is left is the irreducible sentence that time and runtime are what
// answer the instant in the first place -- two names, about the standard library, stated once and
// printed at run time. Being wrong about THAT is visible in a way the old table was not: the graph
// below is REQUIRED to find a clock through these two names in a package other than this one, so a
// reading that lost them fails closed instead of reporting a clean bill.
//
// WHAT IT STILL DOES NOT SEE, stated because an unstated boundary is the next hole: a package
// OUTSIDE this module could answer the instant without being named here. That half is not left to
// a literal either -- it is held as a SCOPE pin rather than as a truth claim, by
// ephKeyExternalReach below, which fixes the exact set of out-of-module packages EphKey's closure
// is allowed to reach and prints the complement.
var ephClockPackages = []string{"runtime", "time"}

// ephIsClockPackage is clause 1 of the class, and it is the same two names everywhere.
func ephIsClockPackage(path string) bool {
	return slices.Contains(ephClockPackages, path)
}

// The out-of-module packages EphKey's transitive closure is allowed to reach.
//
// THIS IS A SCOPE PIN AND NOT A CLASSIFICATION. It does not say these packages answer no instant;
// it says that the set of packages this gate cannot read is exactly this one and has not grown. A
// clock reached through a package outside this module is the one shape the derivation above cannot
// compute, and this is what makes that shape cost a red test on the commit that introduces it
// rather than nothing at all. Its complement -- every out-of-module package in scope that the
// closure does NOT reach -- is printed member by member, because a pin that only ever prints what
// it admitted says nothing about what it removed.
// RE-MEASURED. This was [crypto/hkdf fmt strconv] while the walk followed calls out of function
// bodies only. It is seven now because the closure below is taken over package level declarations
// too: EphKey reads keyScheduleCrypto and Suite, whose initialisers run mls.NewCryptoProvider and
// mls.LookupSuite, and those reach crypto/rand, crypto/sha256, encoding/binary and errors. The
// four new members are not new code -- they are code EphKey always depended on and this gate could
// not see. None of the seven answers the current instant.
//
//	query: go test -run TestEphKeyReachesNoClockSourceInThisPackage -v ./messagegroup/, the
//	"class: the N out-of-module package(s)" line.
var ephKeyExternalReach = []string{
	"crypto/hkdf", "crypto/rand", "crypto/sha256", "encoding/binary", "errors", "fmt", "strconv",
}

// The names CALLED inside EphKey's closure that resolve to no declaration of any package this gate
// read: builtins, conversions, and methods on types outside this module.
//
// THIS LIST IS PINNED AND NOT MERELY PRINTED, and that is the whole of finding F2. It was computed
// and logged member by member before, and asserted against nothing -- and under four separate
// clock plants it grew by exactly one name, printed the escape BY NAME (UnixMilli, ephNow, NowMs,
// Micros), and the test passed. A complement that is printed and unasserted is a complement that
// answers to nobody; the sibling pin two logs above it has always been an Errorf and that is the
// difference. The edge widening above catches those four shapes by resolving them instead, so this
// pin is now the SECOND net rather than the first: an escape has to both resolve nowhere in scope
// and leave this list unchanged, and the two failures are not the same failure.
//
// It carries a maintenance tax -- a new builtin or a new external method in the closure is a red
// test on the commit that adds it. That is the price the external pin above already pays, for the
// same reason: this is the boundary of what the walk can read, and a boundary that moves silently
// is not a boundary.
//
//	query: the "boundary: N call name(s)" line of the same run.
var ephKeyUnresolvedNames = []string{
	"AppendUint64", "Error", "append", "int", "len", "make", "panic", "string", "uint16",
}

// One production .go file of one package of this module, with the import qualifiers THAT FILE
// declares.
//
// Per file and not per package, because a qualifier is a file scoped name: an import renamed in
// one file of a package binds nothing in the others, and a package level map of them would resolve
// a selector against an alias that is not in scope where it was written.
type ephSourceFile struct {
	path       string
	parsed     *ast.File
	qualifiers map[string]string
}

// One package of this module, read from its own directory.
type ephPackage struct {
	importPath      string
	dir             string
	files           []ephSourceFile
	declared        map[string]bool
	clockValueNames map[string]bool
	clockShapeAt    []string
	imports         []string
	// the package level var and const names this package declares, and whether it declares an
	// init. A package level var is a DECLARATION like any other here: it has a node, its
	// initialiser is walked, and reading it is an edge to it.
	valueNames map[string]bool
	hasInit    bool
}

// The call graph of this module's own source, as far as this package's imports reach.
//
// Nodes are "<import path>.<name>", so message.EphBucketSeconds and messagegroup.EphKey are
// different nodes and a name declared in two packages is two nodes. Within one package a method
// and a function of the same name are ONE node, which over approximates reachability; that is the
// safe direction for a gate whose answer is "nothing here reaches a clock".
type ephModuleGraph struct {
	fileSet       *token.FileSet
	modulePath    string
	self          string
	packages      map[string]*ephPackage
	order         []string
	calls         map[string][]string
	readsClock    map[string]bool
	where         map[string]string
	external      []string
	clockImports  []string
	unresolved    map[string][]string
	externalCalls map[string][]string
	// the vertices FILE SCOPE contributed, recorded where they are created rather than looked up
	// by name afterwards. By name is not the same question: a method and a package level var of
	// one package may share a name -- mls declares both a Suite var and a Suite method -- so a
	// lookup of "does a node with this value's name exist" is answered by the METHOD, and the
	// guard below would clear a run in which no value declaration became a vertex at all. That
	// is measured: disabling the value arm of the edge pass left the by-name form green.
	valueNodes []string
}

// ephModule answers this module's path, this package's own import path within it, and the module
// root as a path relative to this package's directory.
//
// NOTHING HERE IS WRITTEN DOWN. keysource_test.go's keySourceModuleRoot already walks up to the
// go.mod that declares the module and reads the path out of it, so this reuses that rather than
// restating it -- for the reason that gate gives, that a module path typed into a test is a second
// statement of the module's identity which goes stale silently the day the module moves, and for
// one more: a ".." written here would be a second statement of where this package sits inside its
// own module, which is the same defect one level down. This package's own import path is derived
// the same way, off the directory it is actually in.
func ephModule(t *testing.T) (string, string, string) {
	t.Helper()
	moduleDir, modulePath := keySourceModuleRoot(t)
	here, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("resolve this package's own directory: %v", err)
		return "", "", ""
	}
	within, err := filepath.Rel(moduleDir, here)
	if err != nil {
		t.Fatalf("place %s inside %s: %v", here, moduleDir, err)
		return "", "", ""
	}
	root, err := filepath.Rel(here, moduleDir)
	if err != nil {
		t.Fatalf("place %s above %s: %v", moduleDir, here, err)
		return "", "", ""
	}
	self := modulePath
	if within = filepath.ToSlash(within); within != "." {
		self = modulePath + "/" + within
	}
	return modulePath, self, root
}

// ephDeclareNode gives one declaration a vertex and a source position, once.
func (self *ephModuleGraph) ephDeclareNode(node string, at string) {
	if _, already := self.calls[node]; !already {
		self.calls[node] = []string{}
		self.where[node] = at
	}
}

// ephAddEdge records one edge, once.
func (self *ephModuleGraph) ephAddEdge(node string, callee string) {
	if !slices.Contains(self.calls[node], callee) {
		self.calls[node] = append(self.calls[node], callee)
	}
}

// ephInModule is "this import path names a package whose source this gate reads".
func (self *ephModuleGraph) ephInModule(path string) bool {
	return path == self.modulePath || strings.HasPrefix(path, self.modulePath+"/")
}

// ephReadPackage parses one package of this module out of its own directory.
func (self *ephModuleGraph) ephReadPackage(t *testing.T, importPath string, moduleRoot string) *ephPackage {
	t.Helper()
	dir := moduleRoot
	if relative := strings.TrimPrefix(strings.TrimPrefix(importPath, self.modulePath), "/"); relative != "" {
		dir = filepath.Join(moduleRoot, filepath.FromSlash(relative))
	}
	if importPath == self.self {
		dir = "."
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s, the directory of %s: %v. An import of this module whose source cannot be read is a package this gate would have to take on trust, which is the hole it exists to close", dir, importPath, err)
		return nil
	}
	pkg := &ephPackage{
		importPath:      importPath,
		dir:             filepath.ToSlash(dir),
		declared:        map[string]bool{},
		clockValueNames: map[string]bool{},
		valueNames:      map[string]bool{},
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.ToSlash(filepath.Join(dir, name))
		parsed, err := parser.ParseFile(self.fileSet, path, nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
			return nil
		}
		file := ephSourceFile{path: path, parsed: parsed, qualifiers: map[string]string{}}
		for _, spec := range parsed.Imports {
			imported := strings.Trim(spec.Path.Value, "\"")
			// the qualifier is the last path element unless the import renames it, which is
			// go's own rule for every import in this module today.
			qualifier := imported[strings.LastIndex(imported, "/")+1:]
			if spec.Name != nil {
				qualifier = spec.Name.Name
			}
			file.qualifiers[qualifier] = imported
			if !seen[imported] {
				seen[imported] = true
				pkg.imports = append(pkg.imports, imported)
			}
		}
		pkg.files = append(pkg.files, file)
	}
	if len(pkg.files) == 0 {
		t.Fatalf("no non test go file was read out of %s (%s), so every rule written over that package's contents cleared it having read nothing", importPath, dir)
		return nil
	}
	slices.Sort(pkg.imports)
	return pkg
}

// ephIsClockShape is "func() int64", which is the shape this package's own rule names: doc.go says
// "no function here takes a clock -- one that needs the time takes an injected nowMs func() int64".
// It is read off the type and not off the name, so a second clock called something else is in the
// class.
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

// ephWalkBody records every edge out of ONE DECLARATION of this module -- a function body, or the
// initialiser and declared type of one package level var or const.
//
// -- CLASS (of edge). A REFERENCE, and not a call. Every *ast.Ident and every *ast.SelectorExpr
//
//	inside the declaration is resolved, whether it sits in a call position or not. The previous
//	shape of this walk recorded an edge only for an *ast.CallExpr, and five clock shapes walked
//	past it on that one word: a package level `var ephNow func() int64 = message.SenderClockMs`
//	read as `ephNow()` is a CALL of a local name and a READ of a package level one, and only the
//	second is the edge that leads anywhere. "Reads" is the verb the property needs -- a value
//	that was obtained from a clock has already read it, and no call site shows that.
//
// -- SCOPE (of resolution). THE WHOLE SET OF PACKAGES THIS GATE READ, and not the calling
//
//	package's import list. A bare name is this package's declaration if it has one, and it is
//	also a method or field name on a value whose type this walk does not resolve, so every
//	package in scope that declares the name becomes an edge -- all of them and not the first that
//	matches. The narrower rule (this package plus the packages IT imports) is the same defect the
//	scope repair fixed one level up: connect/mls/atkclock is in scope because connect/mls imports
//	it, and a method declared there and read here resolved to nothing at all.
//
// The ONE position that still reports a boundary is the call position: a name that is CALLED and
// resolves to no declaration in scope is a builtin, a local func value, or a method on a type
// outside this module, and those are printed AND pinned as ephKeyUnresolvedNames. A name merely
// READ and resolving nowhere is a local, a parameter or a field name, which is every other
// identifier in the file and says nothing; it is not on the boundary list for that reason.
func (self *ephModuleGraph) ephWalkBody(pkg *ephPackage, file ephSourceFile, node string, tree ast.Node) {
	note := func(bag map[string][]string, what string) {
		if !slices.Contains(bag[node], what) {
			bag[node] = append(bag[node], what)
		}
	}
	// clause 2, MODULE WIDE. The clock shape func() int64 is collected in every package in scope,
	// not only in the one being walked: the shape is this module's convention for an injected
	// clock, and a field of that shape declared in connect/message is the same clock when it is
	// read from here. Collected per calling package -- which is what this was -- the scope of the
	// class was narrower than the scope of the walk that uses it.
	//
	// NAMED AS UNDEMONSTRATED, under the house rule that a clause nothing goes red without is a
	// clause that defends nothing. Narrowed back to pkg.clockValueNames[name], the baseline stays
	// green AND every one of the four interface- and field-shaped clock plants stays red, because
	// the reference edges above reach them first: A2a-simple, A2a-hard, A2f and A2g are all caught
	// by the graph naming the plant's own file and line. Two further shapes were built to isolate
	// it -- a clock-shaped field in connect/message read through a package level value, and the
	// same with a same-named harmless declaration in scope to absorb the bare name -- and both
	// were caught by the graph as well. It is kept because it is a statement of what the CLASS is
	// rather than an extra net: the class is "a read of a declaration of the clock shape", the
	// scope of the walk is the module, and the scope of the class was the package. Those two being
	// different sets is the defect the reviewer named, whether or not a shape exists that only it
	// catches. The count it produces is printed, cross package, so an empty answer is visible.
	readsClockShape := func(name string) bool {
		for _, other := range self.packages {
			if other != nil && other.clockValueNames[name] {
				return true
			}
		}
		return false
	}
	// every declaration in scope that this bare name could be, as an edge each.
	resolveName := func(name string) {
		for _, importPath := range self.order {
			if other := self.packages[importPath]; other != nil && other.declared[name] {
				self.ephAddEdge(node, importPath+"."+name)
			}
		}
	}
	resolvesInScope := func(name string) bool {
		for _, other := range self.packages {
			if other != nil && other.declared[name] {
				return true
			}
		}
		return false
	}
	var visit func(n ast.Node) bool
	visit = func(n ast.Node) bool {
		switch expression := n.(type) {
		case *ast.CallExpr:
			// the boundary is a property of the CALL position only, and it is noted here rather
			// than inside the resolution below so that a name merely read does not land on it.
			switch callee := expression.Fun.(type) {
			case *ast.Ident:
				if !resolvesInScope(callee.Name) {
					note(self.unresolved, callee.Name)
				}
			case *ast.SelectorExpr:
				if qualifier, isIdent := callee.X.(*ast.Ident); isIdent {
					if _, isImport := file.qualifiers[qualifier.Name]; isImport {
						return true
					}
				}
				if !resolvesInScope(callee.Sel.Name) {
					note(self.unresolved, callee.Sel.Name)
				}
			}
			return true
		case *ast.SelectorExpr:
			if readsClockShape(expression.Sel.Name) {
				self.readsClock[node] = true
			}
			if qualifier, isIdent := expression.X.(*ast.Ident); isIdent {
				if imported, isImport := file.qualifiers[qualifier.Name]; isImport {
					switch {
					case ephIsClockPackage(imported):
						// clause 1. time.Now() is a call, time.Now is a value and
						// time.Time is a type; all three are this package answering the instant.
						self.readsClock[node] = true
					case self.ephInModule(imported):
						if other := self.packages[imported]; other != nil && other.declared[expression.Sel.Name] {
							self.ephAddEdge(node, imported+"."+expression.Sel.Name)
						} else {
							note(self.unresolved, imported+"."+expression.Sel.Name)
						}
					default:
						note(self.externalCalls, imported)
					}
					// the qualifier names a package and not a value, so there is nothing
					// under it to read.
					return false
				}
			}
			// x.Sel where x is a VALUE: both halves are names of this module until something
			// says otherwise -- Sel as a method or field, and everything under x as an
			// expression, which is how message.Wall.NowMs finds message.Wall.
			resolveName(expression.Sel.Name)
			ast.Inspect(expression.X, visit)
			return false
		case *ast.Ident:
			if readsClockShape(expression.Name) {
				self.readsClock[node] = true
			}
			resolveName(expression.Name)
			return false
		}
		return true
	}
	ast.Inspect(tree, visit)
}

// ephBuildModuleGraph reads this package and, transitively, every package of this module it
// imports, and answers the call graph with the clock reaching nodes already marked.
func ephBuildModuleGraph(t *testing.T) *ephModuleGraph {
	t.Helper()
	modulePath, self, moduleRoot := ephModule(t)
	graph := &ephModuleGraph{
		fileSet:       token.NewFileSet(),
		modulePath:    modulePath,
		self:          self,
		packages:      map[string]*ephPackage{},
		calls:         map[string][]string{},
		readsClock:    map[string]bool{},
		where:         map[string]string{},
		unresolved:    map[string][]string{},
		externalCalls: map[string][]string{},
	}
	externalSeen, clockSeen := map[string]bool{}, map[string]bool{}
	for frontier := []string{graph.self}; 0 < len(frontier); {
		importPath := frontier[0]
		frontier = frontier[1:]
		if graph.packages[importPath] != nil {
			continue
		}
		pkg := graph.ephReadPackage(t, importPath, moduleRoot)
		graph.packages[importPath] = pkg
		graph.order = append(graph.order, importPath)
		for _, path := range pkg.imports {
			switch {
			case ephIsClockPackage(path):
				if !clockSeen[path] {
					clockSeen[path] = true
					graph.clockImports = append(graph.clockImports, path)
				}
			case graph.ephInModule(path):
				frontier = append(frontier, path)
			default:
				if !externalSeen[path] {
					externalSeen[path] = true
					graph.external = append(graph.external, path)
				}
			}
		}
	}
	slices.Sort(graph.order)
	slices.Sort(graph.external)
	slices.Sort(graph.clockImports)
	// the declarations and the clock shaped values of every package, before any edge is drawn,
	// so a call into a package read later in the walk still resolves.
	for _, importPath := range graph.order {
		pkg := graph.packages[importPath]
		for _, file := range pkg.files {
			for _, declaration := range file.parsed.Decls {
				switch declaration := declaration.(type) {
				case *ast.FuncDecl:
					if declaration.Body == nil {
						continue
					}
					pkg.declared[declaration.Name.Name] = true
					if declaration.Recv == nil && declaration.Name.Name == "init" {
						pkg.hasInit = true
					}
				case *ast.GenDecl:
					// a package level var or const is a declaration of this package, so a
					// reference to it resolves and gets a node of its own below. Without this
					// the whole of file scope was invisible to the walk: the gate read only
					// *ast.FuncDecl bodies, and a clock bound into a package level var was a
					// clock the graph had no vertex for.
					if declaration.Tok != token.VAR && declaration.Tok != token.CONST {
						continue
					}
					for _, spec := range declaration.Specs {
						values, isValues := spec.(*ast.ValueSpec)
						if !isValues {
							continue
						}
						for _, name := range values.Names {
							if name.Name == "_" {
								continue
							}
							pkg.declared[name.Name] = true
							pkg.valueNames[name.Name] = true
						}
						// clause 2 reads the TYPE, so a package level value of the clock
						// shape is in the class exactly as a struct field of it is.
						if values.Type == nil || !ephIsClockShape(values.Type) {
							continue
						}
						for _, name := range values.Names {
							pkg.clockValueNames[name.Name] = true
							pkg.clockShapeAt = append(pkg.clockShapeAt,
								fmt.Sprintf("%s (%s:%d)", name.Name, file.path, graph.fileSet.Position(name.Pos()).Line))
						}
					}
				}
			}
			ast.Inspect(file.parsed, func(node ast.Node) bool {
				field, isField := node.(*ast.Field)
				if !isField || !ephIsClockShape(field.Type) {
					return true
				}
				for _, name := range field.Names {
					pkg.clockValueNames[name.Name] = true
					pkg.clockShapeAt = append(pkg.clockShapeAt,
						fmt.Sprintf("%s (%s:%d)", name.Name, file.path, graph.fileSet.Position(name.Pos()).Line))
				}
				return true
			})
		}
		slices.Sort(pkg.clockShapeAt)
	}
	for _, importPath := range graph.order {
		pkg := graph.packages[importPath]
		for _, file := range pkg.files {
			for _, declaration := range file.parsed.Decls {
				switch declaration := declaration.(type) {
				case *ast.FuncDecl:
					if declaration.Body == nil {
						continue
					}
					node := importPath + "." + declaration.Name.Name
					graph.ephDeclareNode(node, fmt.Sprintf("%s:%d", file.path, graph.fileSet.Position(declaration.Pos()).Line))
					graph.ephWalkBody(pkg, file, node, declaration.Body)
				case *ast.GenDecl:
					if declaration.Tok != token.VAR && declaration.Tok != token.CONST {
						continue
					}
					for _, spec := range declaration.Specs {
						values, isValues := spec.(*ast.ValueSpec)
						if !isValues {
							continue
						}
						for index, name := range values.Names {
							if name.Name == "_" {
								continue
							}
							node := importPath + "." + name.Name
							graph.ephDeclareNode(node, fmt.Sprintf("%s:%d", file.path, graph.fileSet.Position(name.Pos()).Line))
							graph.valueNodes = append(graph.valueNodes, node)
							// A PACKAGE LEVEL VAR IS WRITTEN BY ITS PACKAGE'S init, and no
							// call site says so: init is called by the runtime, from nowhere
							// this graph can see, so an edge FROM the variable TO init is what
							// makes "this variable holds whatever init put in it" reachable.
							// It is every init of the package and not only the ones that
							// assign this name, which over approximates in the direction this
							// gate is allowed to be wrong in.
							if declaration.Tok == token.VAR && pkg.hasInit {
								graph.ephAddEdge(node, importPath+".init")
							}
							if values.Type != nil {
								graph.ephWalkBody(pkg, file, node, values.Type)
							}
							switch {
							case len(values.Values) == len(values.Names):
								graph.ephWalkBody(pkg, file, node, values.Values[index])
							default:
								// one call feeding several names: every name takes it.
								for _, value := range values.Values {
									graph.ephWalkBody(pkg, file, node, value)
								}
							}
						}
					}
				}
			}
		}
	}
	// the fixed point: a function that calls a function that reads a clock reads a clock, and it
	// crosses package boundaries because the nodes do.
	for moved := true; moved; {
		moved = false
		for node, callees := range graph.calls {
			if graph.readsClock[node] {
				continue
			}
			for _, callee := range callees {
				if graph.readsClock[callee] {
					graph.readsClock[node] = true
					moved = true
					break
				}
			}
		}
	}
	return graph
}

// ephClockReaders answers the clock reaching nodes declared by one package, sorted.
func (self *ephModuleGraph) ephClockReaders(importPath string) []string {
	readers := []string{}
	for node := range self.readsClock {
		name, isHere := strings.CutPrefix(node, importPath+".")
		if isHere && !strings.Contains(name, ".") {
			readers = append(readers, node)
		}
	}
	slices.Sort(readers)
	return readers
}

// TestEphKeyReachesNoClockSourceInThisPackage is P5.
//
// -- CLASS (of clock source). Three clauses, all computed, none of them a list of time.*
//
//	spellings. Clause 1: an expression qualified by an import of time or runtime -- the two names
//	above, which are the only literal in this derivation and are about the standard library
//	rather than about any package of this repository. It is any expression and not a call:
//	time.Now(), the func value time.Now, and the type time.Time are one clause. Clause 2: a READ
//	of any declaration whose TYPE is this module's clock shape, func() int64, collected in EVERY
//	package in scope -- which is how self.nowMs() and a nowMs parameter are found without either
//	word appearing here, and how a clock shaped field declared in connect/message is found when
//	it is read from this one. Clause 3: a fixed point over the reference graph, so a declaration
//	that reaches a declaration that reaches either reaches it too.
//
// -- CLASS (of edge), stated apart from the clock class because it is where the last five escapes
//
//	lived. A REFERENCE, not a call; and out of ANY declaration, not only out of a function body.
//	See ephWalkBody. The old edge was "*ast.CallExpr inside an *ast.FuncDecl body", and that is
//	two separate holes: a package level `var x = <expr>` is an *ast.ValueSpec at file scope and
//	was never walked, and reading such a variable is an *ast.Ident in a non-call position, which
//	was not an edge even when the declaration that wrote it had already been classified as a
//	clock reader. Package level vars and consts are vertices here, their initialisers and their
//	declared types are walked, and a var is given an edge to its package's init because init is
//	what writes it from a call site no graph can see.
//
// -- SCOPE (of source). Every non test .go file of this package AND of every package OF THIS
//
//	MODULE this package transitively imports, each directory resolved off go.mod's module path
//	with os.ReadDir at run time. Not a list of files and NOT A TABLE OF PACKAGES: the previous
//	shape of this gate rowed connect/message as answering no clock, and a live clock added to
//	connect/message and called from EphKey passed it.
//
// -- SCOPE (of name resolution), stated apart from the source scope because these two were not
//
//	the same set and the difference was a hole. A bare name is resolved against EVERY package
//	this gate read, not against the calling package's import list. connect/mls/atkclock is in
//	scope when connect/mls imports it; a method declared there and read from here resolved to
//	nothing under the narrower rule, and a clock behind it was invisible.
//
// -- PROPERTY. The transitive reference closure of EphKey, taken over that whole graph, contains
//
//	no member of the clock class; the out-of-module packages that closure reaches are exactly
//	ephKeyExternalReach; and the names it calls that resolve nowhere in scope are exactly
//	ephKeyUnresolvedNames. Those two pins are the two boundaries of the walk, and both are
//	asserted -- printing one and asserting the other is how four clock plants were named by this
//	gate, in its own output, under a passing test.
//
// -- FAIL CLOSED, six ways, because each is a shape that would report a clean bill having read
//
//	nothing: more than one package of this module must be read; time or runtime must be found
//	among the imports of some package in scope; package level value declarations must have become
//	vertices, or the whole of file scope was walked past again; the boundary list must be
//	non-empty, because the closure calls len and append at the very least; this package must have
//	clock reaching functions of its own (it does -- the sealer and the opener); and SOME OTHER
//	package in scope must have them too (connect/mls does), which is what says the cross package
//	half of the walk is working
//	rather than silently resolving nothing.
func TestEphKeyReachesNoClockSourceInThisPackage(t *testing.T) {
	graph := ephBuildModuleGraph(t)
	if len(graph.order) < 2 {
		t.Fatalf("only %v was read, so the cross package half of this class was computed over nothing. This package imports connect/message, connect/mls and connect/mls/syntax, and a clock inside any of them is what the previous shape of this gate could not see", graph.order)
	}
	if len(graph.clockImports) == 0 {
		t.Fatalf("no package in scope imports any of %v, so clause 1 of the class is empty. connect/mls calls time.Now in its own production source, so an empty answer here is a reading that lost the imports rather than a module with no clock in it", ephClockPackages)
	}
	self := graph.packages[graph.self]
	if self == nil || len(self.clockValueNames) == 0 {
		t.Fatal("no declaration of type func() int64 was found in this package's production source, so clause 2 of the clock class is empty and an injected clock would be invisible to this gate")
	}
	// the vertices file scope contributes. An empty answer here is the exact state this gate was
	// in when five clock shapes walked past it: package level declarations were parsed, and the
	// walk that draws edges looked only at *ast.FuncDecl bodies, so nothing at file scope was a
	// vertex and no edge could lead to one.
	valueNodes := slices.Clone(graph.valueNodes)
	slices.Sort(valueNodes)
	valueNodes = slices.Compact(valueNodes)
	if len(valueNodes) == 0 {
		t.Fatal("no package level var or const in scope became a vertex of this graph, so file scope was walked past entirely. This package declares ErrEphBucketOffLadder, Suite and keyScheduleCrypto at file scope, and a clock bound into any of them is the shape this gate now exists to see")
	}
	if len(self.valueNames) == 0 {
		t.Fatal("this package declares no package level var or const at all, which it does; an empty answer is a declaration pass that read no *ast.GenDecl")
	}
	if !self.declared["EphKey"] {
		t.Fatal("this package declares no EphKey, so the closure below cleared a function that does not exist")
	}
	packagesRead := []string{}
	for _, importPath := range graph.order {
		pkg := graph.packages[importPath]
		packagesRead = append(packagesRead, fmt.Sprintf("%s at %s (%d file(s))", importPath, pkg.dir, len(pkg.files)))
	}
	t.Logf("scope: %d package(s) of this module read from source, %v", len(graph.order), packagesRead)
	t.Logf("class, clause 1: %d import path(s) answer the current instant, %v; reached in scope: %v",
		len(ephClockPackages), ephClockPackages, graph.clockImports)
	t.Logf("complement, clause 1: the %d out-of-module import path(s) in scope whose source this gate does not read, %v",
		len(graph.external), graph.external)
	t.Logf("class, clause 2: %d declaration(s) of the clock shape func() int64 in this package, %v",
		len(self.clockShapeAt), self.clockShapeAt)
	elsewhereShaped := []string{}
	for _, importPath := range graph.order {
		if importPath != graph.self {
			elsewhereShaped = append(elsewhereShaped, graph.packages[importPath].clockShapeAt...)
		}
	}
	slices.Sort(elsewhereShaped)
	t.Logf("class, clause 2, cross package: %d declaration(s) of the clock shape elsewhere in scope, %v",
		len(elsewhereShaped), elsewhereShaped)
	t.Logf("vertices from file scope: %d package level var/const declaration(s) in scope are nodes of this graph",
		len(valueNodes))

	here := graph.ephClockReaders(graph.self)
	if len(here) == 0 {
		t.Fatal("no function in this package reaches a clock source at all. This package DOES read a clock -- the sealer computes eph_window from it and the opener makes the ahead refusal with it -- so an empty answer here is a broken reachability walk reporting a clean bill, which is the failure this project's house rule is named for")
	}
	elsewhere := []string{}
	for _, importPath := range graph.order {
		if importPath == graph.self {
			continue
		}
		elsewhere = append(elsewhere, graph.ephClockReaders(importPath)...)
	}
	slices.Sort(elsewhere)
	if len(elsewhere) == 0 {
		t.Fatal("no function in ANY OTHER package of this module reaches a clock source. connect/mls calls time.Now in its own production source, so an empty answer here is a cross package walk that resolved nothing -- which is exactly the state this gate was in on the day a clock added to connect/message and called from EphKey passed it")
	}
	t.Logf("class, clause 3: %d function(s) in this package reach a clock source, %v", len(here), here)
	t.Logf("class, clause 3, cross package: %d function(s) elsewhere in this module reach one; the first %d are %v",
		len(elsewhere), min(6, len(elsewhere)), elsewhere[:min(6, len(elsewhere))])

	// EphKey's own closure, over the WHOLE graph and not only over this package.
	closure := map[string]bool{}
	for frontier := []string{graph.self + ".EphKey"}; 0 < len(frontier); {
		node := frontier[0]
		frontier = frontier[1:]
		if closure[node] {
			continue
		}
		closure[node] = true
		frontier = append(frontier, graph.calls[node]...)
	}
	inClosure := []string{}
	for node := range closure {
		if _, isDeclaredInModule := graph.calls[node]; isDeclaredInModule {
			inClosure = append(inClosure, node)
		}
	}
	slices.Sort(inClosure)
	if len(inClosure) < 2 {
		t.Fatalf("EphKey's closure over this module's own declarations is %v; a closure of one is a walk that followed no edge, and EphKey calls at least the width refusals and the expansion", inClosure)
	}
	t.Logf("EphKey's closure over this module's own declarations: %d, %v", len(inClosure), inClosure)
	for _, node := range inClosure {
		if graph.readsClock[node] {
			t.Errorf("EphKey reaches %s (%s), which reads a clock. The window is the RECORD'S OWN eph_window field and never a value this derivation computes: a window EphKey derived for itself would differ from the sender's on every record that crossed a bucket boundary, and the AEAD tag would be the only thing in the system that said so",
				node, graph.where[node])
		}
	}

	// the boundary of the walk, pinned rather than described.
	reached, unresolved := []string{}, []string{}
	for _, node := range inClosure {
		for _, path := range graph.externalCalls[node] {
			if !slices.Contains(reached, path) {
				reached = append(reached, path)
			}
		}
		for _, name := range graph.unresolved[node] {
			if !slices.Contains(unresolved, name) {
				unresolved = append(unresolved, name)
			}
		}
	}
	slices.Sort(reached)
	slices.Sort(unresolved)
	notReached := []string{}
	for _, path := range graph.external {
		if !slices.Contains(reached, path) {
			notReached = append(notReached, path)
		}
	}
	if len(notReached) == 0 {
		t.Fatalf("EphKey's closure reaches every one of the %d out-of-module package(s) in scope, so the pin below removed nothing and says nothing", len(graph.external))
	}
	t.Logf("class: the %d out-of-module package(s) EphKey's closure reaches, %v", len(reached), reached)
	t.Logf("complement: the %d out-of-module package(s) in scope it does not reach, %v", len(notReached), notReached)
	t.Logf("boundary: %d call name(s) inside the closure resolve to no declaration of this module, %v",
		len(unresolved), unresolved)
	if len(unresolved) == 0 {
		t.Fatalf("no name called inside EphKey's closure resolves outside this module, so the boundary pin removed nothing and says nothing. The closure calls len, make and append at the very least, so an empty answer here is a walk that visited no call expression rather than a closure that makes none")
	}
	if !slices.Equal(unresolved, ephKeyUnresolvedNames) {
		t.Errorf("the names called inside EphKey's closure that resolve nowhere in scope are %v, and ephKeyUnresolvedNames pins %v. A name that resolves nowhere is the one kind of callee this walk cannot follow, so the set of them is pinned rather than printed: a clock reached through a new one is a clock this gate would otherwise report a clean bill over",
			unresolved, ephKeyUnresolvedNames)
	}
	if !slices.Equal(reached, ephKeyExternalReach) {
		t.Errorf("EphKey's closure reaches the out-of-module packages %v, and ephKeyExternalReach pins %v. A package outside this module is the one thing the derivation above cannot read, so the set of them this closure touches is pinned instead: say why the new one cannot answer the current instant, or take the call back out",
			reached, ephKeyExternalReach)
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

// The two closed ledger items this gate is about, each with the date of the ruling that STANDS.
//
// DATES AND NOT WORDS, and the reason is a measured false negative rather than a preference. The
// first shape of this gate asked whether the citing comment said "ruled", and doc.go's own stale
// sentence -- of an item ruled 2026-09-07 and reversed 2026-09-13 -- satisfied it, because "has
// not ruled" contains the word "ruled". Every polarity carrying word has that problem and the fix
// is not a longer list of phrases: a date has no polarity. It is also the thing a reader actually
// needs, because what makes a citation safe is not the word "ruled" but knowing WHICH ruling, on a
// corpus where one of these two was ruled and then reversed six days later.
//
// THE STANDING RULING AND NOT EITHER RULING, which is this round's narrowing. The gate used to
// accept either date beside either citation, so "M1-6, ruled 2026-09-07" -- the reading the owner
// REVERSED on 2026-09-13 -- passed as a dated citation. A citation dated with a ruling that was
// itself later overturned is the exact trap this gate exists for, wearing the gate's own uniform.
// Each row now carries the one date that is still good for that item, and the reversed one is
// written into the row's note so the message a reader meets says why the earlier date is not
// enough. MEASURED ON THE TREE IT WAS TIGHTENED ON: all 34 citing comment lines then present
// already carried 2026-09-13 within two lines, so the narrowing cost nothing on the day it landed
// and is a floor afterwards. The count as it stands is printed by the gate rather than written
// here, because a count in a comment is the thing this file keeps finding stale.
//
// THE MARKERS ARE BUILT BY CONCATENATION so that this file is not a member of its own class. It is
// the same device enginejoin_test.go's denial table uses, for the same reason doc.go gives for
// describing its retracted sentence instead of quoting it: a gate whose own source matches its
// predicate either fails forever or gets taught to ignore the place it lives, and the second is
// how a gate stops covering the file it is written in.
var ephStandingRulings = []struct {
	marker string
	stands string
	note   string
}{
	{marker: "item " + "152", stands: "2026-09-13", note: "ruled 2026-09-13, and the EPH seal refusal it held is lifted in full"},
	{marker: "m1" + "-6", stands: "2026-09-13", note: "ruled 2026-09-07 and REVERSED 2026-09-13, so the earlier date alone is the overturned reading"},
}

// ephCitationMarkers is the markers alone, for a message that must not spell them.
func ephCitationMarkers() []string {
	markers := []string{}
	for _, ruling := range ephStandingRulings {
		markers = append(markers, ruling.marker)
	}
	return markers
}

// How far either side of the citing line a date counts as being beside it.
//
// Two lines, and the number is small on purpose. The unit this gate judges is the SENTENCE a
// reader lands on, not the comment group: doc.go's header is ONE unbroken comment group of 174
// lines -- re-measured for this commit, and the query is
// awk '/^\/\//{n++;m=(n>m?n:m);next}{n=0}END{print m}' doc.go, which said 130 when this comment
// was first written and says 174 now -- and go's parser makes all of it one group, so a group wide
// reading would clear a stale sentence near the end because of a date near the start. That is the
// same distance failure the corpus itself keeps filing -- a rule and its carve-out seventy lines
// apart -- and it is why the window is a handful of lines rather than a paragraph.
const ephCitationWindowLines = 2

// One citation found by the gate below.
type ephCitation struct {
	at     string
	marker string
	stands string
	note   string
	kind   string
	dated  bool
}

// ephCitationsIn judges one line of text against every row of the table.
//
// The text and the window are separate arguments because they are different readings of the same
// place: the text is what a reader meets on that line, and the window is the two lines either side
// of it that a date may live in.
func ephCitationsIn(text string, window string, at string, kind string) []ephCitation {
	found := []ephCitation{}
	lowered := strings.ToLower(text)
	for _, ruling := range ephStandingRulings {
		if !strings.Contains(lowered, strings.ToLower(ruling.marker)) {
			continue
		}
		found = append(found, ephCitation{
			at:     at,
			marker: ruling.marker,
			stands: ruling.stands,
			note:   ruling.note,
			kind:   kind,
			dated:  strings.Contains(window, ruling.stands),
		})
	}
	return found
}

// ephFileLines is one source file's own lines, for the string literal half of the scope: a literal
// is positioned in the FILE and its neighbours are file lines, where a comment's neighbours are the
// other comments of its group.
func ephFileLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s for the lines around its string literals: %v", path, err)
		return nil
	}
	return strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
}

// TestEveryCitationOfTheRuledItemsCarriesItsRulingDate is the gate the item-152 cleanup owes.
//
// -- CLASS. Every line of this package that cites either of the two closed items in the table
//
//	above, in a COMMENT or in a STRING LITERAL. Both items are closed and one of them was ruled
//	and then reversed, so a citation of either is a citation of a closed item, and one that reads
//	as though the item were open is the pre-amendment-comment trap this corpus keeps filing
//	(ledger 141's class). The class is the citations themselves and not a list of files: a stale
//	line moved to a new file is still in it.
//
// -- WHY THE STRING LITERALS ARE IN IT, measured rather than argued. The first shape of this gate
//
//	walked *ast.Comment only, and seal_test.go carried a subtest whose NAME stated the reversed
//	item's overturned reading -- printed on every -v run, in a file this commit's parent had
//	edited. It is DESCRIBED and not quoted here, for doc.go's reason: a gate that quotes the
//	sentence it refuses is a gate that fails forever or is taught to skip its own file. A citation
//	a reader meets in the suite's output is a citation, and widening the scope to *ast.BasicLit of
//	kind STRING found that one and two more: two error messages that cite a ruled item and carry
//	no date. The half is required to be NON EMPTY below, because a
//	widening that finds nothing is a widening that defends nothing.
//
// -- SCOPE. Every .go file in this package's directory, TEST FILES INCLUDED, read with os.ReadDir
//
//	at run time. It is wider than messagegroupProductionSources on purpose: four of the six files
//	that carried a stale citation were _test.go files, and a gate over production source alone
//	would have reported clean over four of them.
//
// -- PROPERTY. Every citing line carries the date of the ruling that STANDS for the item it cites,
//
//	within two lines of itself. Both halves of the class are required to be non empty, and the
//	complement -- the citations with no standing date beside them -- is printed line by line with
//	its count rather than counted alone.
//
// -- WHAT THIS GATE CANNOT SEE is written out under BOUNDARY below, because the class it holds is
//
//	narrower than the class a reader will assume from its name, and an unstated boundary is the
//	next hole.
func TestEveryCitationOfTheRuledItemsCarriesItsRulingDate(t *testing.T) {
	fileSet, sources := ephAllPackageSources(t)
	if len(ephStandingRulings) == 0 {
		t.Fatal("the table of closed items is empty, so this gate judged nothing")
	}
	cited := []ephCitation{}
	// the comment half. The window is the comment GROUP's own lines, which for a group of
	// consecutive comment lines is the same two lines either side that a reader sees.
	for _, source := range sources {
		for _, group := range source.parsed.Comments {
			lines := group.List
			for index, line := range lines {
				window := ""
				for offset := -ephCitationWindowLines; offset <= ephCitationWindowLines; offset += 1 {
					if neighbour := index + offset; 0 <= neighbour && neighbour < len(lines) {
						window += lines[neighbour].Text + " "
					}
				}
				at := fmt.Sprintf("%s:%d", source.path, fileSet.Position(line.Pos()).Line)
				cited = append(cited, ephCitationsIn(line.Text, window, at, "comment")...)
			}
		}
	}
	// the string literal half, which is this round's widening.
	for _, source := range sources {
		fileLines := ephFileLines(t, source.path)
		ast.Inspect(source.parsed, func(node ast.Node) bool {
			literal, isLiteral := node.(*ast.BasicLit)
			if !isLiteral || literal.Kind != token.STRING {
				return true
			}
			position := fileSet.Position(literal.Pos())
			window := ""
			for offset := -ephCitationWindowLines; offset <= ephCitationWindowLines; offset += 1 {
				if neighbour := position.Line - 1 + offset; 0 <= neighbour && neighbour < len(fileLines) {
					window += fileLines[neighbour] + " "
				}
			}
			at := fmt.Sprintf("%s:%d", source.path, position.Line)
			cited = append(cited, ephCitationsIn(literal.Value, window, at, "string")...)
			return true
		})
	}
	fromComments, fromStrings := []string{}, []string{}
	undated := []string{}
	for _, citation := range cited {
		if citation.kind == "comment" {
			fromComments = append(fromComments, citation.at)
		} else {
			fromStrings = append(fromStrings, citation.at)
		}
		if !citation.dated {
			undated = append(undated, citation.at)
		}
	}
	slices.Sort(fromComments)
	slices.Sort(fromStrings)
	slices.Sort(undated)
	undated = slices.Compact(undated)
	if len(fromComments) == 0 {
		t.Fatalf("no comment line in this package cites either of %v. Both are the subject of the ruling this package implements and both are cited here, so an empty class is a walk that read nothing rather than a package with nothing to check", ephCitationMarkers())
	}
	if len(fromStrings) == 0 {
		t.Fatalf("no string literal in this package cites either of %v. The stale subtest name this scope was widened for lived in one, and two error messages that cite a ruled item live in others, so an empty string half is a *ast.BasicLit walk that found nothing rather than a package whose literals are clean", ephCitationMarkers())
	}
	t.Logf("class: %d citation(s) of the closed items, %d in comments and %d in string literals",
		len(cited), len(fromComments), len(fromStrings))
	t.Logf("class, the string half: %v", slices.Compact(slices.Clone(fromStrings)))
	t.Logf("complement: %d of them carry no STANDING ruling date within %d lines, %v",
		len(undated), ephCitationWindowLines, undated)
	for _, citation := range cited {
		if citation.dated {
			continue
		}
		t.Errorf("%s (in a %s) cites %q with no %s beside it. That item is %s. An undated citation of a closed item is the trap that let a source comment quote a pre-amendment interface and be the stale copy, and the date is what tells a reader WHICH ruling on this item is the one that stands",
			citation.at, citation.kind, citation.marker, citation.stands, citation.note)
	}
}

// ---------------------------------------------------------------------------
// The retracted sentinel name, held by the query that publishes its count
// ---------------------------------------------------------------------------

// The file whose job is to record retracted names, and which therefore contains them.
const ephInventoryFile = "messagegroup/doc.go"

// TestTheRetractedSentinelSurvivesOnlyInTheParagraphThatRetractsIt runs the query doc.go publishes.
//
// -- CLASS. Every line of every .go file of THIS MODULE that contains the retracted sentinel name,
//
//	test files included, because a retracted name left in a test is a caller of it. The needle is
//	assembled at run time from two halves rather than written as one literal, so THIS FILE IS NOT
//	IN ITS OWN ANSWER by construction rather than by an exclusion list -- which is the whole
//	point of the finding: doc.go published "answers one line" and the paragraph publishing it was
//	the second and third lines of the answer. A count whose query matches the claim is the
//	self-match item 152 -- ruled 2026-09-13 -- filed for handle_link.
//
// -- SCOPE. The module root resolved off go.mod at run time by keySourceModuleRoot, walked with
//
//	filepath.WalkDir. The whole module and not this directory: the claim doc.go publishes is
//	about connect, so the reading has to be about connect. The ../sdk half of the published query
//	is NOT held here -- sdk is another repository, its checkout is not implied by this one, and a
//	gate that read it would be green on a machine where it is absent, which is a gate that says
//	nothing. doc.go states that half as a measurement rather than as a gate for that reason.
//
// -- PROPERTY. Excluding the inventory file, the name survives on exactly one line, and that line
//
//	is in errors.go -- the paragraph that describes the retraction. The complement, every line
//	the exclusion removed, is printed member by member and asserted non-empty.
//
// -- FAIL CLOSED, three ways: the walk must have read .go files at all; the name must be found
//
//	SOMEWHERE, or the reading found nothing and would clear any claim; and the exclusion must
//	have removed something, or it is decoration rather than a guard and the inventory has stopped
//	recording the rename it exists to record.
func TestTheRetractedSentinelSurvivesOnlyInTheParagraphThatRetractsIt(t *testing.T) {
	// two halves, so this file is not a hit of its own query.
	retracted := "ErrRetentionClass" + "Unruled"
	// the rename is only a rename if the new name is really declared; this is a compile time
	// assertion of the other half of doc.go's claim.
	_ = ErrRetentionClassUnknown

	moduleDir, modulePath := keySourceModuleRoot(t)
	read, kept, removed := 0, []string{}, []string{}
	err := filepath.WalkDir(moduleDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		read++
		within, err := filepath.Rel(moduleDir, path)
		if err != nil {
			return err
		}
		within = filepath.ToSlash(within)
		for number, line := range strings.Split(string(body), "\n") {
			if !strings.Contains(line, retracted) {
				continue
			}
			at := fmt.Sprintf("%s:%d", within, number+1)
			if within == ephInventoryFile {
				removed = append(removed, at)
			} else {
				kept = append(kept, at)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s, the root of %s: %v", moduleDir, modulePath, err)
	}
	if read == 0 {
		t.Fatalf("no .go file was read out of %s, so this gate counted occurrences of %s in nothing", moduleDir, retracted)
	}
	slices.Sort(kept)
	slices.Sort(removed)
	t.Logf("scope: %d .go file(s) of %s read from %s", read, modulePath, moduleDir)
	t.Logf("class: %d line(s) outside the inventory still carry the retracted name, %v", len(kept), kept)
	t.Logf("complement: %d line(s) the exclusion of %s removed, %v", len(removed), ephInventoryFile, removed)
	if len(kept)+len(removed) == 0 {
		t.Fatalf("the retracted name is nowhere in %s at all. errors.go's retraction paragraph names it, and doc.go's inventory entry names it twice, so an empty answer is a reading that found nothing rather than a module that has finished with the name", modulePath)
	}
	if len(removed) == 0 {
		t.Fatalf("excluding %s removed no line, so the exclusion in the published query guards nothing. That file is the inventory: it records the rename and it quotes the query, and if it has stopped naming the retracted name then the entry doc.go publishes has gone", ephInventoryFile)
	}
	if len(kept) != 1 {
		t.Errorf("the retracted name survives on %d line(s) outside the inventory, %v, and doc.go publishes ONE. Either a caller of the retracted name came back, or the retraction paragraph moved: correct the number where it is published, and keep the query one whose own answer does not contain it",
			len(kept), kept)
		return
	}
	if !strings.HasPrefix(kept[0], "messagegroup/errors.go:") {
		t.Errorf("the one surviving line is %s, and doc.go publishes it as the paragraph in errors.go that describes the retraction", kept[0])
	}
}

// ---------------------------------------------------------------------------
// BOUNDARY: what the citation gates see, what they cannot, and why
// ---------------------------------------------------------------------------
//
// THIS IS THE ANSWER TO A FINDING AND NOT A PREAMBLE. A reviewer planted, in seal.go's PRODUCTION
// prose, a three line sentence saying that one retention class alone reaches the wire and that the
// other three are turned away because nothing has settled which rung their head takes -- the
// retracted reading, in fresh words, naming no item number and reusing none of the phrasings the
// inventory gate registers. A full unfiltered run of this package exited 0 with no output. It was
// replanted against THIS tree, after the widening above, and exited 0 again.
//
// The plant is DESCRIBED and not quoted, which is doc.go's rule and is load bearing here of all
// places: a boundary paragraph carrying a verbatim retracted sentence would put that sentence back
// into the tree, one grep away from a reader who never reached this line, in the one file whose
// job is to say the sentence is wrong.
//
// That measurement is correct and it is NOT repaired below. It is stated instead, because a gate
// that pretended to close it would be worth less than the sentence you are reading.
//
// THERE ARE TWO HONESTY GATES OVER THIS PACKAGE'S PROSE AND BETWEEN THEM THEY COVER TWO SHAPES.
//
//   - THIS ONE covers a CITATION: a line naming one of the two closed items by number. Its
//     membership predicate is those two numbers, and its judgement is CO-LOCATION with the
//     standing ruling's date, within two lines. THAT IS WEAKER THAN "the citation agrees with the
//     ruling" AND THE DIFFERENCE IS MEASURED, not guessed: a comment asserting the reversed
//     reading and carrying 2026-09-13 on the same line passes, and so does one carrying it on the
//     next line as an unrelated aside. A date has no polarity, which is exactly why it is proof
//     against the "has not ruled" false negative a word list walked into -- and it is the same
//     property that stops it refusing a sentence whose words disagree with it. What this gate
//     delivers is that a reader who meets a citation of a reversed item is shown WHICH ruling is
//     current; what it does not deliver is that the citation says what that ruling says.
//     Classifying prose is outside it, for the reason the paragraph above gives. Scope is every
//     .go file of this directory, comments and string literals alike.
//
//   - TestTheInventoryDoesNotDenyWhatThisPackageProves (enginejoin_test.go) covers a DENIAL: a
//     production sentence that contradicts a claim some named case proves. Its membership
//     predicate is a hand written list of the exact phrasings the retracted sentences took,
//     normalised. It is exact and it is the reason the retracted inventory sentence cannot come
//     back in the shape it had.
//
// WHAT NEITHER OF THEM CAN SEE IS A PARAPHRASE THAT CITES NO NUMBER. The planted sentence names no
// item, so it is not a citation and this gate never looks at it; and it is worded unlike any of
// the four registered denials, so the inventory gate does not match it. Both gates bottom out in a
// literal at the CLASS level -- two item numbers here, four phrasings there -- and a paraphrase is
// outside both by construction.
//
// WHY IT IS NOT CLOSED RATHER THAN NOT YET CLOSED. Every candidate repair moves the literal
// without removing it. A list of refusal verbs ("refused", "turned away", "only the durable") is a
// list whose omissions are invisible, which is the nine-times defect of this project restated. A
// rule that no production sentence may put a retention class name near a refusal word needs that
// same verb list. Deriving the vocabulary from the package's own sentinel messages does not reach
// it either: "turned away at the door" appears in no error this package declares. Classifying
// arbitrary prose as an assertion about behaviour is the part no gate in this tree can do, and the
// honest statement of the residue is:
//
//	THE CLASS "stale prose about the seal lift that cites no item number and reuses no registered
//	phrasing" IS UNCAUGHT. The two exact shapes that existed on 2026-09-13 are caught, the
//	citations are caught in comments and in string literals, and a paraphrase is not.
//
// TWO SMALLER RESIDUES, named so they are not discovered as surprises. A citation split across a
// concatenation -- "ledger item " + "152" -- matches no single literal and is outside this gate;
// that is deliberate, it is how this file opts its own table out, and it is also an escape hatch
// somebody could use by accident. And the date this gate requires is the date of the ruling that
// stands TODAY: if 2026-09-13 is itself reversed, every citation carrying it passes until this
// table is edited. A gate in this repository cannot know about a ruling made in another one, and
// what makes that survivable is that the table is three lines long and is the first thing a reader
// of this file meets.

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
