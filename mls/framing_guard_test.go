// Guardrail 8's last shape, and the framing structure's committed fuzz seed corpus.
//
// Spec A 5.9 G8 asks that every comparison of a tag go through
// crypto/subtle.ConstantTimeCompare, reached by CryptoProvider.MacVerify. Four gates already
// answer parts of that question, and this file deliberately answers none of them again:
//
//   - TestNothingThisPackageShipsComparesDataOutsideConstantTime derives eighteen comparators
//     from the packages this one imports and bans every CALL to one, in every production file,
//     package level initializers included. That is the half that reads every call site.
//   - TestEveryKeyQuestionOverTheRatchetTreeIsAnsweredInConstantTime holds the declarations that
//     hold a key and answer over a ratchet tree, with an equality rule, a foreign call rule and
//     a reachability rule.
//   - TestEveryTagVerifierComparesThroughMacVerifyAndNothingElse holds the exported bools that
//     reach into the epoch's nine secrets.
//   - TestEveryMembershipTagRefusalIsDecidedByMacVerifyAndNothingElse holds everything that can
//     answer errBadMembershipTag, the shape of the refusal included.
//
// What is left is the shape the FIRST of those names out loud in its own header and does not
// read: "a comparison written as a byte loop in this package's own source names no comparator
// and is in no class derived from imports ... A gate that reads every call is not a gate that
// reads every comparison, and the difference is one hand written loop." The three narrower gates
// close that loop for three CLASSES -- a key plus a tree, an epoch secret plus a bool, an
// errBadMembershipTag -- and the whole framing surface is outside all three but for the one
// membership tag chain.
//
// Measured rather than argued. framing_protect.go's CheckFramedContentContext decides ValSem002
// with subtle.ConstantTimeCompare over a group id, it is in none of those three classes, and
// rewriting that comparison as string(content.GroupId) != string(groupId) leaves every test of
// ./mls/... and ./message/... passing.
//
// So this is the fourth reading of the same guardrail and the first over the shape that names
// nothing: a comparison of octets spelled as ordinary go equality. It is package wide and over
// both roots the forbidden call scan reads, because a comparison of octets is no more allowed in
// ../message than it is here, and it is TYPE DIRECTED rather than textual -- an operand is
// judged by what the compiler says it is, so a tag behind three named types is in the class and
// a comparison of two lengths is not.
//
// The plan's own version of this test was seven file names and a strings.Contains over three
// comparator spellings. That is strictly weaker than the gate next door in every dimension it
// has -- three comparators against eighteen, seven files against every one, substring against
// syntax -- and there is no edit it could fail for that the existing gate would not already have
// caught. It is replaced rather than added.
//
// The second half of this file is the framing structure's committed fuzz seed corpus, joined to
// the table p4 and p5 built rather than kept in a second one.
package mls

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// ---------------------------------------------------------------------------
// the type checked reading of a root, bodies included
// ---------------------------------------------------------------------------

// checkedBodies is one root's non test source with its function bodies type checked.
//
// A second reading rather than a use of typeCheckedRoot, because that one sets IgnoreFuncBodies
// -- right for every gate that judges signatures, and it leaves every expression inside a body
// with no type at all. Every comparison this file is about is inside a body.
type checkedBodies struct {
	root    string
	paths   []string
	fileSet *token.FileSet
	files   []*ast.File
	info    *types.Info
	source  map[string][]byte
}

// render answers the source text one node was written as, read back off the file it came out of
// rather than printed from the syntax tree, so a report names what a reviewer will find.
func (self checkedBodies) render(node ast.Node) string {
	from, to := self.fileSet.Position(node.Pos()), self.fileSet.Position(node.End())
	body, held := self.source[from.Filename]
	if !held || to.Offset > len(body) {
		return "?"
	}
	return strings.Join(strings.Fields(string(body[from.Offset:to.Offset])), " ")
}

// where names the line a report is about.
func (self checkedBodies) where(node ast.Node) string {
	return self.fileSet.Position(node.Pos()).String()
}

var checkedBodiesCache = map[string]checkedBodies{}

// typeCheckedBodiesOf type checks one root's non test source with its bodies, once.
//
// A refused check is fatal rather than a fall back to reading spellings, for the reason
// typeCheckedRoot gives: a gate that cannot resolve its subject must fail, and one that quietly
// reverted to matching text would go on reporting the clean run of a complete gate while holding
// a narrower class.
func typeCheckedBodiesOf(t *testing.T, root string) checkedBodies {
	t.Helper()
	cryptoTypeCheckMutex.Lock()
	defer cryptoTypeCheckMutex.Unlock()
	if checked, done := checkedBodiesCache[root]; done {
		return checked
	}
	checked := typeCheckBodies(t, root, rootSourcePaths(t, root), nil)
	checkedBodiesCache[root] = checked
	return checked
}

// typeCheckedBodiesOfText is the same over text a control holds, so the matcher runs on a package
// known to violate the rule as well as on the real one.
func typeCheckedBodiesOfText(t *testing.T, name string, source string) checkedBodies {
	t.Helper()
	cryptoTypeCheckMutex.Lock()
	defer cryptoTypeCheckMutex.Unlock()
	return typeCheckBodies(t, name, []string{name}, map[string]string{name: source})
}

// typeCheckBodies is the shared body of the two above. The caller holds the importer mutex: the
// source importer carries a cache and is not safe to enter twice at once.
func typeCheckBodies(t *testing.T, path string, names []string, text map[string]string) checkedBodies {
	t.Helper()
	fileSet := token.NewFileSet()
	files := []*ast.File{}
	source := map[string][]byte{}
	for _, name := range names {
		body, written := text[name]
		if !written {
			read, err := os.ReadFile(name)
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			body = string(read)
		}
		file, err := parser.ParseFile(fileSet, name, body, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, file)
		source[name] = []byte(body)
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}}
	refused := []string{}
	config := types.Config{
		Importer: importer.ForCompiler(fileSet, "source", nil),
		Error:    func(err error) { refused = append(refused, err.Error()) },
	}
	if _, err := config.Check(path, fileSet, files, info); err != nil || len(refused) != 0 {
		t.Fatalf("type check %s with its bodies: %v %s", path, err, strings.Join(refused, "; "))
	}
	if len(info.Types) == 0 {
		t.Fatalf("the type checker recorded no expression for %s, so every rule below would read nothing", path)
	}
	return checkedBodies{root: path, paths: names, fileSet: fileSet, files: files, info: info, source: source}
}

// ---------------------------------------------------------------------------
// what an octet comparison is, derived from the compiler's own types
// ---------------------------------------------------------------------------

// The two shapes this gate reports, named so the control can require each half to report
// something of its own: a half that reports nothing can be deleted with the control still
// matching.
const (
	// wholeOctetComparison is a value whose EQUALITY is decided by comparing octets: a string, a
	// byte or rune array, or any aggregate holding one. go compiles each of those to a memequal
	// that returns at the first differing octet.
	wholeOctetComparison = "whole"
	// offsetOctetComparison is a comparison of an octet READ AT AN OFFSET out of such a value,
	// which is the byte loop. What it answers is not whether two strings are equal but WHERE
	// they stopped being equal, and that is the answer per query a timing side channel wants.
	offsetOctetComparison = "offset"
)

// comparesOctets answers whether go's == on this type is a comparison of octets.
//
// It reads the type the compiler assigned rather than the spelling, so a tag behind three named
// types is in the class; and it recurses through arrays and structs, because an aggregate
// holding a tag compares that tag when the aggregate is compared. A slice and a map are not
// comparable in go at all and can never reach an ==, so nothing here has to say anything about
// them.
//
// A struct of nothing but integers is deliberately NOT in the class, and that is the boundary
// rather than an oversight. Comparing two node indices, two epochs or two code points is a
// decision about numbers this package puts on the wire in the clear; a rule that swept them in
// would need an exemption list, which is the shape of gate that gets an exemption added rather
// than a bug fixed. What makes a comparison this gate's business is that an octet string is on
// one side of it.
func comparesOctets(one types.Type, seen map[types.Type]bool) bool {
	if seen[one] {
		return false
	}
	seen[one] = true
	switch spelled := types.Unalias(one).Underlying().(type) {
	case *types.Basic:
		return spelled.Kind() == types.String || spelled.Kind() == types.UntypedString
	case *types.Array:
		if isOctet(spelled.Elem()) {
			return true
		}
		return comparesOctets(spelled.Elem(), seen)
	case *types.Struct:
		for index := range spelled.NumFields() {
			if comparesOctets(spelled.Field(index).Type(), seen) {
				return true
			}
		}
	}
	return false
}

// isOctet is one element of an octet string.
func isOctet(one types.Type) bool {
	basic, isBasic := types.Unalias(one).Underlying().(*types.Basic)
	return isBasic && (basic.Kind() == types.Byte || basic.Kind() == types.Rune)
}

// holdsOctets is a value an octet can be read out of at an offset: a slice or an array of
// octets, or a string. It is the base of the index expression a byte loop is written with.
func holdsOctets(one types.Type) bool {
	switch spelled := types.Unalias(one).Underlying().(type) {
	case *types.Slice:
		return isOctet(spelled.Elem())
	case *types.Array:
		return isOctet(spelled.Elem())
	case *types.Basic:
		return spelled.Kind() == types.String || spelled.Kind() == types.UntypedString
	}
	return false
}

// octetComparison is one comparison the rule reports, with where it was written, because a gate
// that reports a violation has to say which line to open.
type octetComparison struct {
	shape    string
	where    string
	rendered string
}

// octetComparisonsIn reports every comparison of octets written without a comparator inside one
// syntax node.
//
// A SWITCH is read as the comparisons it is. go's expression switch compares its tag against
// each case with ==, so `switch string(tag) { case string(mine): }` is the same comparison as
// `string(tag) == string(mine)`, and a rule that read only a BinaryExpr would let it through.
// That is not thoroughness for its own sake: a comparison spelled as control flow is exactly
// what the earlier version of the tag verifier gate next door was walked past by.
func octetComparisonsIn(checked checkedBodies, node ast.Node) []octetComparison {
	found := []octetComparison{}
	judge := func(at ast.Node, left ast.Expr, right ast.Expr) {
		leftType, rightType := checked.info.Types[left].Type, checked.info.Types[right].Type
		if leftType == nil || rightType == nil {
			return
		}
		shape := ""
		switch {
		case comparesOctets(leftType, map[types.Type]bool{}) && comparesOctets(rightType, map[types.Type]bool{}):
			shape = wholeOctetComparison
		case indexesOctets(checked, left) || indexesOctets(checked, right):
			shape = offsetOctetComparison
		default:
			return
		}
		found = append(found, octetComparison{
			shape:    shape,
			where:    checked.where(at),
			rendered: checked.render(at),
		})
	}
	ast.Inspect(node, func(one ast.Node) bool {
		switch spelled := one.(type) {
		case *ast.BinaryExpr:
			if spelled.Op == token.EQL || spelled.Op == token.NEQ {
				judge(spelled, spelled.X, spelled.Y)
			}
		case *ast.SwitchStmt:
			if spelled.Tag == nil || spelled.Body == nil {
				return true
			}
			for _, statement := range spelled.Body.List {
				clause, isClause := statement.(*ast.CaseClause)
				if !isClause {
					continue
				}
				for _, value := range clause.List {
					judge(value, spelled.Tag, value)
				}
			}
		}
		return true
	})
	return found
}

// indexesOctets answers whether an operand is an octet read at an offset out of an octet string.
func indexesOctets(checked checkedBodies, one ast.Expr) bool {
	index, isIndex := one.(*ast.IndexExpr)
	if !isIndex {
		return false
	}
	base := checked.info.Types[index.X].Type
	return base != nil && holdsOctets(base)
}

// octetComparisonsByDeclaration reads one root and answers, per top level declaration that can
// hold an expression, the comparisons reported inside it.
//
// Per DECLARATION rather than per function, because a package level var initialised with
// string(a) == string(b) is in the outside of every class of functions there is -- the same
// reason the comparator gate next door reads whole files rather than declarations.
func octetComparisonsByDeclaration(checked checkedBodies) map[string][]octetComparison {
	found := map[string][]octetComparison{}
	for _, file := range checked.files {
		for _, declaration := range file.Decls {
			switch spelled := declaration.(type) {
			case *ast.FuncDecl:
				found[spelled.Name.Name] = octetComparisonsIn(checked, spelled)
			case *ast.GenDecl:
				for _, one := range spelled.Specs {
					value, isValue := one.(*ast.ValueSpec)
					if !isValue || len(value.Values) == 0 {
						continue
					}
					for _, name := range value.Names {
						found[name.Name] = octetComparisonsIn(checked, value)
					}
				}
			}
		}
	}
	return found
}

// shapesOf is the distinct shapes a set of reports names, sorted, which is what an expectation is
// stated in: a position moves whenever a line above it does and is not the property asserted.
func shapesOf(reports []octetComparison) []string {
	shapes := []string{}
	for _, one := range reports {
		if !slices.Contains(shapes, one.shape) {
			shapes = append(shapes, one.shape)
		}
	}
	slices.Sort(shapes)
	return shapes
}

// ---------------------------------------------------------------------------
// the control fixture
// ---------------------------------------------------------------------------

// octetComparisonControl declares one of every shape the rule has to tell apart, so a matcher
// that stopped matching fails here rather than issuing the real source the clean bill a working
// one issues.
//
// Every member is here because some half of the rule has to be the only thing reporting it, or
// the only thing NOT reporting it:
//
//   - ComparesTwoStringsMadeOfOctets is the rewrite that actually survives on this project:
//     string(a) == string(b) names no comparator, so the derived comparator ban next door reads
//     clean over it, and it was measured surviving in tree.go and in treekem.go.
//   - ComparesTwoTagArrays and ComparesTwoEnvelopesHoldingATag are the same comparison one and
//     two levels of aggregate out. A rule reading only `string` would miss both, and a tag
//     declared as [32]byte is the likeliest way for one to appear.
//   - ComparesOctetByOctet is the hand written loop the comparator gate's own header says it
//     cannot see, and ComparesOneOctetAgainstAConstant is that loop's body with the second
//     operand folded to a literal -- still one answer per query about where the tag differs.
//   - SwitchesOnAStringOfOctets is the same comparison spelled as control flow.
//   - comparesInAWrapper is the byte loop moved out of the function that answers, and
//     LoopsInsideAHelper is that function: the rule must report the WRAPPER and not its caller,
//     because reading whole roots is what makes hiding it in a helper pointless.
//   - acceptsEverything is the same comparison in a package level initializer, which is what
//     says the rule reads declarations of every kind rather than function bodies.
//
// And the six that must NOT be reported, each of which is a real shape of this package's
// production source:
//
//   - ComparesWithTheSanctionedCall is subtle.ConstantTimeCompare's answer against 1.
//   - AccumulatesAndComparesAgainstZero is framing_protect.go's own padding check: the whole
//     buffer is folded with |= and the ACCUMULATOR is compared, so the comparison reads no
//     offset and the time does not vary with where the first non zero octet sits. It is the
//     sanctioned way to write what ComparesOneOctetAgainstAConstant writes badly, and a rule
//     that could not tell the two apart would be a rule this package could not obey.
//   - ComparesTwoLengths, ComparesTwoCounts and ComparesACodePoint are decisions about numbers
//     that travel in the clear.
//   - LooksUpAMapKeyedByOctets is the shape this gate deliberately does not read, and it is
//     named here so a reader cannot mistake silence for coverage. A map keyed by string is a
//     variable time comparison of octets; this package's sixteen of them are uniqueness scans
//     over PUBLIC tree keys and psk ids, and a rule reporting them would be a rule with sixteen
//     exemptions, which is the gate that stops being read. Nothing catches a secret put through
//     one, and that is written down rather than left implied.
const octetComparisonControl = `package control

import "crypto/subtle"

type Tag [32]byte

type Envelope struct {
	Tag   Tag
	Epoch uint64
}

type CodePoint uint16

var chosen = []byte{0x00}

var chosenOther = []byte{0x01}

var acceptsEverything = string(chosen) == string(chosenOther)

func ComparesTwoStringsMadeOfOctets(a []byte, b []byte) bool {
	return string(a) == string(b)
}

func ComparesTwoTagArrays(a Tag, b Tag) bool {
	return a == b
}

func ComparesTwoEnvelopesHoldingATag(a Envelope, b Envelope) bool {
	return a == b
}

func ComparesOctetByOctet(a []byte, b []byte) bool {
	same := len(a) == len(b)
	for at := range a {
		if at < len(b) && a[at] != b[at] {
			same = false
		}
	}
	return same
}

func ComparesOneOctetAgainstAConstant(tag []byte) bool {
	return len(tag) != 0 && tag[0] == 0x01
}

func SwitchesOnAStringOfOctets(a []byte, b []byte) bool {
	switch string(a) {
	case string(b):
		return true
	}
	return false
}

func LoopsInsideAHelper(a []byte, b []byte) bool {
	return comparesInAWrapper(a, b)
}

func comparesInAWrapper(a []byte, b []byte) bool {
	for at := range a {
		if a[at] != b[at] {
			return false
		}
	}
	return true
}

func ComparesWithTheSanctionedCall(a []byte, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func AccumulatesAndComparesAgainstZero(padding []byte) bool {
	var accumulated byte
	for _, octet := range padding {
		accumulated |= octet
	}
	return accumulated != 0
}

func ComparesTwoLengths(a []byte, b []byte) bool {
	return len(a) == len(b)
}

func ComparesTwoCounts(a uint32, b uint32) bool {
	return a == b
}

func ComparesACodePoint(a CodePoint) bool {
	switch a {
	case 1, 2:
		return true
	}
	return false
}

func LooksUpAMapKeyedByOctets(seen map[string]bool, key []byte) bool {
	return seen[string(key)]
}
`

// octetComparisonControlReports is the shapes each control declaration must draw, exactly rather
// than as a floor.
//
// A control is the one thing in a derived gate that cannot itself be derived from the rule it
// controls, so it is written out; and it is stated for EVERY declaration that can hold an
// expression rather than only for the offending ones, because a rule that widened to report
// every comparison it reads fails here as surely as one that stopped matching.
var octetComparisonControlReports = map[string][]string{
	"chosen":                            {},
	"chosenOther":                       {},
	"acceptsEverything":                 {wholeOctetComparison},
	"ComparesTwoStringsMadeOfOctets":    {wholeOctetComparison},
	"ComparesTwoTagArrays":              {wholeOctetComparison},
	"ComparesTwoEnvelopesHoldingATag":   {wholeOctetComparison},
	"ComparesOctetByOctet":              {offsetOctetComparison},
	"ComparesOneOctetAgainstAConstant":  {offsetOctetComparison},
	"SwitchesOnAStringOfOctets":         {wholeOctetComparison},
	"LoopsInsideAHelper":                {},
	"comparesInAWrapper":                {offsetOctetComparison},
	"ComparesWithTheSanctionedCall":     {},
	"AccumulatesAndComparesAgainstZero": {},
	"ComparesTwoLengths":                {},
	"ComparesTwoCounts":                 {},
	"ComparesACodePoint":                {},
	"LooksUpAMapKeyedByOctets":          {},
}

// TestTheOctetComparisonGateFlagsItsControlFixture is the matcher's own control, and it runs
// before the gate over the real source so that a rule which stopped matching fails here rather
// than issuing this package a clean bill.
func TestTheOctetComparisonGateFlagsItsControlFixture(t *testing.T) {
	checked := typeCheckedBodiesOfText(t, "the octet comparison control", octetComparisonControl)
	reported := octetComparisonsByDeclaration(checked)
	if len(reported) != len(octetComparisonControlReports) {
		t.Fatalf("the rule read %v out of the control and the control declares %d bodies it must judge; a declaration it does not read is a shape the real source can be written in",
			slices.Sorted(maps.Keys(reported)), len(octetComparisonControlReports))
	}
	for _, name := range slices.Sorted(maps.Keys(octetComparisonControlReports)) {
		got, read := reported[name]
		if !read {
			t.Errorf("the rule did not read %s out of the control", name)
			continue
		}
		if want := octetComparisonControlReports[name]; !slices.Equal(shapesOf(got), want) {
			t.Errorf("the rule reports %s with %v, want %v; a half of it that reports nothing of its own can be deleted with this control still matching",
				name, shapesOf(got), want)
		}
	}
	// both halves have to report something, said as a count rather than left to the table above:
	// a table can be edited to agree with a rule that has gone quiet, and a zero cannot.
	for _, shape := range []string{wholeOctetComparison, offsetOctetComparison} {
		drawn := 0
		for _, reports := range reported {
			for _, one := range reports {
				if one.shape == shape {
					drawn++
				}
			}
		}
		if drawn == 0 {
			t.Errorf("the %s half of the rule reported nothing over a control written to violate it", shape)
		}
	}
}

// TestFramingUsesConstantTimeComparison is Spec A 5.9 G8 over the shape that names no comparator,
// across every production file of this package and of ../message.
//
// The name is the one the interface registry pins for this plan, and the scope is wider than the
// name: framing is where the demand comes from, and a rule that read only the seven framing files
// the plan lists would be the hand written class rule 5 forbids. The framing files are covered
// because they are non test go files of this package's directory and for no other reason, which
// is what the file count below is asserted for.
//
// This package obeys the rule literally today: it holds no comparison of octets spelled as
// ordinary go equality at all, in either root, and its six comparisons of octets are all
// crypto/subtle.ConstantTimeCompare.
func TestFramingUsesConstantTimeComparison(t *testing.T) {
	roots := forbiddenScanRoots
	if len(roots) == 0 {
		t.Fatal("the scan reads no root at all, so this gate cleared every comparison having read nothing")
	}
	judged := 0
	for _, root := range roots {
		checked := typeCheckedBodiesOf(t, root)
		onDisk := rootSourcePaths(t, root)
		if !slices.Equal(checked.paths, onDisk) {
			t.Fatalf("%s: the gate read %v and the directory holds %v; a production file outside this reading is a file the rule cleared without opening",
				root, checked.paths, onDisk)
		}
		judged += len(checked.paths)
		reported := 0
		for name, comparisons := range octetComparisonsByDeclaration(checked) {
			for _, one := range comparisons {
				reported++
				t.Errorf("%s at %s decides %q, which is a %s comparison of octets in variable time; every comparison of octets in this tree goes through %s, reached by CryptoProvider.MacVerify where a tag is what is being compared",
					name, one.where, one.rendered, one.shape, theSanctionedComparison())
			}
		}
		t.Logf("%s: %d production files read with their bodies type checked, %d comparisons of octets spelled as ordinary go equality",
			root, len(checked.paths), reported)
	}
	if judged == 0 {
		t.Fatal("no production file was judged, so this gate reported clean having read nothing")
	}
}

// ---------------------------------------------------------------------------
// the framing structure's committed seed corpus
// ---------------------------------------------------------------------------

// privateMessageSeedTarget is the target name the seeds live under, because p8's loader and the
// one in key_schedule_roundtrip_test.go both join testdata/corpus with the target's own name.
//
// It is NOT one of the nine names the interface registry gives p8 -- FuzzExtensionDecode,
// FuzzKeyPackageDecode, FuzzMlsMessageDecode, FuzzProposalDecode and FuzzWelcomeDecode with their
// Bytes twins -- and that is the whole reason this structure is the one seeded here. A corpus
// committed under a target this plan is forbidden to declare is 287 files no fuzz engine ever
// opens, which is what p5's review found and what the plan's own version of this task would have
// repeated: it writes four seeds flat into testdata/corpus, where nothing looks, for the
// MLSMessage and Proposal grammars, whose targets belong to p8 and to task 18.
const privateMessageSeedTarget = "FuzzPrivateMessageRoundTrip"

// seedPrivateMessages is the generator for that corpus: the registry axis crossed with the varint
// width boundaries of the three opaque fields and the uint64 boundaries of the epoch, plus the
// structure an mlswg implementation actually wrote.
//
// PrivateMessage is the framing structure this corpus is over, and the choice is not arbitrary.
// Under A-ASSUME-4 it is the only format v1 puts on the wire, so it is the structure every octet
// a stranger can send passes through; its cleartext header is four fields a message server reads
// without holding a key; and its registry closure is one enum, which is what makes the derived
// coverage gates over this table satisfiable at all. The other framing structures are either one
// of p8's nine, or reachable only through a codec that takes an argument (FramedContentAuthData
// needs the content type), or carry neither a varint prefixed field nor a uint64 and so cannot
// meet the two axes those gates state unconditionally.
//
// The content type axis is DERIVED from the package's own constant declarations rather than
// listed, for the reason rule 5 names. It carries no unregistered code point, and that is a
// property of this codec rather than a thinness here: MarshalMLS refuses one before it writes and
// UnmarshalMLS refuses one at the octet it is read at, so an unregistered value has no encoding
// to seed with.
func seedPrivateMessages(t *testing.T) []*PrivateMessage {
	t.Helper()

	contentTypes := sortedValues(registryConstantsOfType(t, "ContentType"))
	if len(contentTypes) == 0 {
		t.Fatal("the derivation read no ContentType code point, so this corpus would exercise one decoder arm")
	}
	opaques := seedOpaques()
	epochs := seedEpochs()

	corpus := []*PrivateMessage{}
	for contentIndex, contentType := range contentTypes {
		for groupIdIndex, groupId := range opaques {
			for epochIndex, epoch := range epochs {
				corpus = append(corpus, &PrivateMessage{
					GroupId:             groupId,
					Epoch:               epoch,
					ContentType:         ContentType(contentType),
					AuthenticatedData:   opaques[(groupIdIndex+epochIndex)%len(opaques)],
					EncryptedSenderData: opaques[(groupIdIndex+contentIndex)%len(opaques)],
					Ciphertext:          opaques[(epochIndex+contentIndex)%len(opaques)],
				})
			}
		}
	}
	// the empty non nil forms, which are one seed with the nil ones on disk and two distinct
	// values in the generator, and the one seed carrying the first length whose varint prefix
	// needs four octets -- one rather than an axis, because every seed carrying it costs 16 KiB
	// in the repository and the prefix width is a property of the prefix.
	corpus = append(corpus,
		&PrivateMessage{
			GroupId:             []byte{},
			Epoch:               1,
			ContentType:         ContentType(contentTypes[0]),
			AuthenticatedData:   []byte{},
			EncryptedSenderData: []byte{},
			Ciphertext:          []byte{},
		},
		&PrivateMessage{
			GroupId:             repeatByte(0xd0, 32),
			Epoch:               1,
			ContentType:         ContentType(contentTypes[len(contentTypes)-1]),
			AuthenticatedData:   repeatByte(0xd1, 1),
			EncryptedSenderData: repeatByte(0xd2, 32),
			Ciphertext:          repeatByte(0xd3, seedWideOpaqueLength),
		},
	)
	corpus = append(corpus, privateMessageFromTheVectors(t))
	return corpus
}

// privateMessageFromTheVectors is the seed this plan actually owns the knowledge of: the
// PrivateMessage an mlswg implementation published in the pinned messages vector.
//
// Every other seed above is this package's encoder writing out this package's own axes, and p5's
// header says what that is worth on its own -- a corpus generated from the encoder it checks
// agrees with that encoder by construction. This one is the other kind of evidence: octets
// written by an implementation that has never seen this codec, decoded here and put back on the
// axis list so the committed corpus carries a structure nothing in this tree invented.
//
// TestTheCommittedFramingSeedFromTheVectorsIsTheVectorsOwnOctets is what holds that claim, and it
// is a separate property because this function alone cannot: a decode that silently dropped a
// field would still produce a value, and a value re encoded is not the octets it came from.
func privateMessageFromTheVectors(t *testing.T) *PrivateMessage {
	t.Helper()
	raws := LoadVectorFile(t, "messages.json")
	if len(raws) == 0 {
		t.Fatal("messages.json holds no vector, so the seed taken from it is taken from nothing")
	}
	vector := messagesVector{}
	if err := json.Unmarshal(raws[0], &vector); err != nil {
		t.Fatalf("parse the messages vector: %v", err)
	}
	if vector.PrivateMessage == "" {
		t.Fatal("the messages vector publishes no private_message, so this seed would be this package's own encoder again")
	}
	message, err := ParseMLSMessage(MustHex(t, vector.PrivateMessage))
	if err != nil {
		t.Fatalf("the vector's private_message did not parse: %v", err)
	}
	if message.PrivateMessage == nil {
		t.Fatalf("the vector's private_message parsed as a %#04x message carrying no PrivateMessage", message.WireFormat)
	}
	return message.PrivateMessage
}

// framingSeedCodecs is this plan's row of the shared table. Joining that table rather than
// restating its properties is the point: the nine properties p4 and p5 state over seedCodecs --
// the corpus equals the generator, every seed re encodes to its own octets, every generated value
// survives its encoding, every registry code point is carried, every varint width and epoch
// boundary is carried, every field varies, every truncation and extension is refused, the folder
// is pinned as binary, and the folder is read by a declared target -- all hold over this corpus
// the moment it is in the table, and a second table is a second place for the same property to be
// stated more weakly.
func framingSeedCodecs() []seedCodec {
	return []seedCodec{
		{
			target:    privateMessageSeedTarget,
			structure: func() any { return &PrivateMessage{} },
			values: func(t *testing.T) []any {
				values := []any{}
				for _, value := range seedPrivateMessages(t) {
					values = append(values, value)
				}
				return values
			},
			decode: func(bs []byte) (any, error) {
				parsed := &PrivateMessage{}
				return parsed, syntax.Unmarshal(bs, parsed)
			},
			encode:         func(value any) ([]byte, error) { return syntax.Marshal(value.(*PrivateMessage)) },
			checkRoundTrip: syntax.CheckRoundTrip[PrivateMessage, *PrivateMessage],
			describe:       describePrivateMessage,
		},
	}
}

// describePrivateMessage names one seed value in a failure, since an index into a generated cross
// product says nothing about which case broke.
func describePrivateMessage(value any) string {
	one := value.(*PrivateMessage)
	return fmt.Sprintf("content type %d, epoch %#016x, group id %d octets, authenticated data %d, sender data %d, ciphertext %d",
		one.ContentType, one.Epoch, len(one.GroupId), len(one.AuthenticatedData),
		len(one.EncryptedSenderData), len(one.Ciphertext))
}

// TestTheCommittedFramingSeedFromTheVectorsIsTheVectorsOwnOctets is what makes one seed of this
// corpus independent evidence rather than a second copy of this package's encoder.
//
// It states the claim at the octet level in both directions: the PrivateMessage this package
// decodes out of the pinned vector re encodes to exactly the octets the vector publishes inside
// its MLSMessage framing, and the committed corpus holds those octets. A decoder that dropped a
// field would produce a value that re encodes to something shorter, and a corpus regenerated from
// a drifted encoder would hold that shorter form; either way the two comparisons below part
// company with the vector.
func TestTheCommittedFramingSeedFromTheVectorsIsTheVectorsOwnOctets(t *testing.T) {
	fromVector := privateMessageFromTheVectors(t)
	encoded, err := syntax.Marshal(fromVector)
	if err != nil {
		t.Fatalf("re encode the vector's private message: %v", err)
	}

	// the octets the vector publishes for this structure, cut out of the MLSMessage framing it
	// travels in rather than taken from a second hex literal here: the framing is a version, a
	// wire format and the body, so the body is the tail, and a tail that did not match would be
	// a codec disagreeing with the vector rather than a transcription error.
	raws := LoadVectorFile(t, "messages.json")
	vector := messagesVector{}
	if err := json.Unmarshal(raws[0], &vector); err != nil {
		t.Fatalf("parse the messages vector: %v", err)
	}
	published := MustHex(t, vector.PrivateMessage)
	if len(published) <= len(encoded) {
		t.Fatalf("the vector's private_message is %d octets and the PrivateMessage this package re encodes is %d; the body cannot be the tail of its own framing",
			len(published), len(encoded))
	}
	body := published[len(published)-len(encoded):]
	if !bytes.Equal(body, encoded) {
		t.Fatalf("this package re encodes the vector's private message to %x and the vector publishes %x", encoded, body)
	}

	_, onDisk := readSeedCorpus(t, privateMessageSeedTarget)
	carried := false
	for _, seed := range onDisk {
		if bytes.Equal(seed, encoded) {
			carried = true
			break
		}
	}
	if !carried {
		t.Errorf("no committed %s seed holds the %d octets the messages vector publishes for its private_message; the corpus is this package's own encoder end to end, and regenerating with %s=1 is the fix",
			privateMessageSeedTarget, len(encoded), seedCorpusWriteEnv)
	}
	t.Logf("%s: the messages vector's own %d octet private message is among the %d committed seeds",
		privateMessageSeedTarget, len(encoded), len(onDisk))
}

// FuzzPrivateMessageRoundTrip is gate 4 properties 1 and 2 on the section 6.3 PrivateMessage in
// their randomized form: no panic on adversarial input, and an encoding that decodes must re
// encode to the octets it came from.
//
// Through fuzzTheCommittedSeedCorpus, which loads the committed seeds, hands them to the engine
// and then asserts from the FAR SIDE that the engine ran them -- and through syntax.CheckRoundTrip
// rather than an open coded comparison, because that helper is the one every gate 4 target in
// this tree reaches its codec through and a target restating the comparison locally would be
// green against a helper that had stopped making it.
//
// The bool is the reachability count and it is the half this task adds. CheckRoundTrip returns
// nil for an input that does not decode -- correct against its contract, and silent -- so a
// target handed a corpus of octets none of which decode states its property over nothing and
// reports exactly what a complete run reports. p1 measured uniform random bytes reaching the
// round trip property 14 times in 4096 against the simplest structure in the tree, so that is
// not a hypothetical corpus; it is what an unseeded run of this target looks like.
func FuzzPrivateMessageRoundTrip(f *testing.F) {
	fuzzTheCommittedSeedCorpus(f, privateMessageSeedTarget, func(t *testing.T, encoded []byte) bool {
		if err := syntax.CheckRoundTrip[PrivateMessage, *PrivateMessage](encoded); err != nil {
			t.Fatalf("%d octets %x: %v", len(encoded), encoded, err)
		}
		return syntax.Unmarshal(encoded, &PrivateMessage{}) == nil
	})
}

// ---------------------------------------------------------------------------
// the corpus folders, and that each of them has somewhere to be read from
// ---------------------------------------------------------------------------

// TestEveryCommittedCorpusFolderIsCarriedByTheSharedCodecTable is the other half of
// TestEveryCommittedCorpusFolderIsReadByAFuzzTarget, and it is a different question.
//
// That one asks whether a folder has a fuzz TARGET; this one asks whether it has a CODEC in the
// shared table, which is what every property stated over the corpus is stated through. A folder
// with a target and no codec is a folder the engine reads and no test on a plain go test run
// does: the corpus equality, the re encode, the registry coverage, the field variation and the
// truncation refusal all iterate seedCodecs, so a corpus outside it is exercised only under
// -fuzz, which CI does not run on every commit.
//
// Both sides are derived -- the folders on disk, and the table -- because a list of "the corpora
// we have" is the enumeration rule 5 forbids and it is a list that stays green after the entry it
// names has been deleted.
func TestEveryCommittedCorpusFolderIsCarriedByTheSharedCodecTable(t *testing.T) {
	table := map[string]bool{}
	for _, codec := range seedCodecs() {
		if table[codec.target] {
			t.Errorf("%s is in the shared codec table twice, so one of the two entries states every property over the other's corpus", codec.target)
		}
		table[codec.target] = true
	}
	if len(table) == 0 {
		t.Fatal("the shared codec table is empty, so every property stated over it holds vacuously")
	}

	root := filepath.Join("testdata", "corpus")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	folders := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		folders++
		if !table[entry.Name()] {
			t.Errorf("%s/%s holds committed seeds and no entry of the shared codec table names %s; every property this package states over a corpus iterates that table, so those seeds are read by nothing a plain go test run executes",
				root, entry.Name(), entry.Name())
		}
	}
	if folders == 0 {
		t.Fatalf("%s holds no corpus folder, so this gate asserted nothing", root)
	}
	if folders != len(table) {
		t.Errorf("%d corpus folders are on disk and the shared codec table holds %d entries; an entry with no folder is a property stated over a corpus that is not committed",
			folders, len(table))
	}
	t.Logf("%d committed corpus folders, each carried by one of the %d entries of the shared codec table", folders, len(table))
}
