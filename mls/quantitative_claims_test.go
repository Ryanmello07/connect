package mls

// The arithmetic this source states IN PROSE, held against the arithmetic it runs.
//
// WHY THIS FILE EXISTS. Five rounds running, this package shipped a disclosure whose numbers
// nothing measured. The shape was the same every time: a comment states a formula or a bound, and
// the test that guards it exercises ONE POINT. The catch-up disclosure in (*Group).LoadGroup said a
// receiver behind by n loses ceil(n/MaxGenerationSkip) messages -- wrong at seven of ten distances,
// and nothing measured any of them until somebody ran it. The sentence that replaced it said a
// retransmission "opens rather than being refused again" -- true, and only inside
// 2*MaxGenerationSkip -- guarded at a distance of MaxGenerationSkip+2, which is inside the window
// where it holds.
//
// SO THE INSTRUMENT IS NOT "BE CAREFUL". A formula written in go cannot drift from itself, and a
// test can evaluate it at as many points as it likes; a formula written in English can drift from
// everything and is evaluated nowhere. This gate requires the pairing: where a production comment
// states arithmetic over a quantity this source NAMES, the same comment has to name a test, and
// that test has to reach the constant through arithmetic of its own.
//
// THE CLASS IS DERIVED AND SO IS THE SCOPE, which is the rule a hand-written list has understated
// on this project over and over. The class is not a list of formulas: it is every
// maximal span of a comment that PARSES as a go expression, carries a binary arithmetic operator,
// and names a constant declared by this source -- so a formula spelled in a way nobody anticipated
// is in the class by parsing, and a constant added tomorrow joins the operand universe by being
// declared. The scope is not "doc comments in mls": it is every comment of every production file
// under forbiddenScanRoots, INCLUDING comments inside function bodies, because the live instance
// that prompted this file is a body comment in (*Group).LoadGroup and a gate scoped to doc comments
// would have reported the source clean.
//
// WHAT THIS GATE CANNOT SEE, written down here rather than left for the next round to discover:
//
//   - a claim with no operator. "it is the only thing here that is" is a count, and a false one,
//     and no reading of the expression grammar finds it. So is "the ciphertext is dropped inside
//     this function". Prose that asserts a property without arithmetic is outside this class
//     entirely, and the only instrument for that is an assertion which observes the property --
//     see TestSealAndRecordDropsTheCiphertextWhoseGenerationItCouldNotRecord, which is what closing
//     one of those cost.
//   - arithmetic written entirely in literals. "2^32-1" is a fact about a uint32 that the compiler
//     already holds; the class is drawn at arithmetic over a quantity THIS SOURCE NAMES because
//     that is the arithmetic a change to this source can falsify.
//   - comments in test files. A test's own prose stands beside the assertion it describes, and the
//     assertion is the check. This is a real hole and it has been paid for: the header on
//     sealSiteDoor named a property nothing here asserted, was rewritten, and named a different
//     one, twice before it was written down as what the field reads.
//   - whether the named test's arithmetic is the SAME arithmetic. The gate requires the constant to
//     be reached through an operator; it cannot require the expression to be equal, because a
//     ceiling written in prose as ceil(a/b) is written in go as (a+b-1)/b and a structural
//     comparison would demand that the prose be wrong. What it buys is that a formula stated over a
//     constant no test computes with is reported -- which is every one of the live instances.
//   - a claim whose comment names a test measuring something ELSE. Naming is checked; aim is not. A
//     reviewer still has to read the sentence. Measured, because the first attempt at mutating this
//     gate hit it: a false formula pasted INTO a comment group that already cites a test is
//     discharged by that citation and this gate stays green. The same formula in a group of its
//     own is reported. So this buys the paragraph a test, not the sentence.
//
// AND THE OTHER DIRECTION IS CHECKED TOO. Every test this source's prose names, by the shape a test
// name has, must exist -- so prose left behind by a rename is reported rather than quietly becoming
// a reference to nothing.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"maps"
	"slices"
	"strings"
	"testing"
	"unicode"
)

// ---------------------------------------------------------------------------
// reading arithmetic out of prose
// ---------------------------------------------------------------------------

// claimToken is one atom of a comment: an operand (a name or a number) or an operator.
//
// The distinction is the whole of how a span of prose is cut down to a size a parser can be asked
// about. Two operands cannot stand next to each other in any go expression -- "member behind by n
// generations" is five operands in a row and no substring of it spanning two of them is an
// expression -- so an operand followed by an operand is a boundary, and every span between two
// boundaries is short whatever the sentence around it does.
type claimToken struct {
	text    string
	operand bool
}

// claimTokensIn cuts one comment into runs of atoms.
//
// A run ends at any character that cannot appear in an expression -- a comma, a full stop, a
// quotation mark -- and at this source's em dash. THE EM DASH IS A BREAK AND NOT AN OPERATOR: `a --
// b` parses as `a - (-b)` and would otherwise glue the two halves of every sentence in this package
// into one expression, which is how a first reading of this source reported "MaxRatchetTreeLength -
// -the" as a formula. Go's own grammar agrees, `--` being a statement token and never an expression
// one, so this is the lexer telling the truth about the language rather than a special case.
func claimTokensIn(text string) [][]claimToken {
	runs := [][]claimToken{}
	current := []claimToken{}
	flush := func() {
		if len(current) != 0 {
			runs = append(runs, current)
			current = []claimToken{}
		}
	}
	runes := []rune(text)
	for i := 0; i < len(runes); {
		r := runes[i]
		switch {
		case unicode.IsLetter(r) || r == '_':
			j := i
			for j < len(runes) && (unicode.IsLetter(runes[j]) || unicode.IsDigit(runes[j]) || runes[j] == '_') {
				j += 1
			}
			current = append(current, claimToken{text: string(runes[i:j]), operand: true})
			i = j
		case unicode.IsDigit(r):
			j := i
			for j < len(runes) && unicode.IsDigit(runes[j]) {
				j += 1
			}
			current = append(current, claimToken{text: string(runes[i:j]), operand: true})
			i = j
		case r == '-' && i+1 < len(runes) && runes[i+1] == '-':
			flush()
			for i < len(runes) && runes[i] == '-' {
				i += 1
			}
		case strings.ContainsRune("+-*/%^()", r):
			current = append(current, claimToken{text: string(r), operand: false})
			i += 1
		case r == ' ' || r == '\t' || r == '\n':
			i += 1
		default:
			flush()
			i += 1
		}
	}
	flush()
	return runs
}

// claimSegmentsIn cuts each run at every operand that follows an operand, for the reason claimToken
// states.
func claimSegmentsIn(runs [][]claimToken) [][]claimToken {
	segments := [][]claimToken{}
	for _, run := range runs {
		start := 0
		for i := 1; i < len(run); i += 1 {
			if run[i-1].operand && run[i].operand {
				segments = append(segments, run[start:i])
				start = i
			}
		}
		segments = append(segments, run[start:])
	}
	return segments
}

// claimSourceOf is one span written back out as something a parser can read.
func claimSourceOf(segment []claimToken) string {
	parts := make([]string, 0, len(segment))
	for _, atom := range segment {
		parts = append(parts, atom.text)
	}
	return strings.Join(parts, " ")
}

// statedFormula is one arithmetic claim a comment makes, and the constants of this source it is
// stated over.
type statedFormula struct {
	text      string
	constants []string
}

// formulasStatedIn is every arithmetic claim one comment makes.
//
// THE LONGEST SPAN WINS at each position, because a formula's own sub-expressions are not separate
// claims: ceil((n-MaxGenerationSkip)/(MaxGenerationSkip-1)) states one thing, and reporting the
// expressions nested inside it as well would make the count a count of parentheses.
func formulasStatedIn(text string, constants map[string]bool) []statedFormula {
	stated := []statedFormula{}
	for _, segment := range claimSegmentsIn(claimTokensIn(text)) {
		for start := 0; start < len(segment); start += 1 {
			for end := len(segment); end > start+2; end -= 1 {
				expr, err := parser.ParseExpr(claimSourceOf(segment[start:end]))
				if err != nil || !claimHoldsArithmetic(expr) {
					continue
				}
				named := claimConstantsIn(expr, constants)
				if len(named) == 0 {
					continue
				}
				var written strings.Builder
				if err := printer.Fprint(&written, token.NewFileSet(), expr); err != nil {
					continue
				}
				stated = append(stated, statedFormula{text: written.String(), constants: named})
				start = end - 1
				break
			}
		}
	}
	return stated
}

// claimHoldsArithmetic reports whether an expression computes rather than merely names.
//
// The operator set is go/token's own arithmetic class rather than a spelling of it: a comparison or
// a logical operator states a relation between two things already written down, and what this file
// is about is a value the prose worked out.
func claimHoldsArithmetic(expr ast.Expr) bool {
	arithmetic := false
	ast.Inspect(expr, func(node ast.Node) bool {
		binary, isBinary := node.(*ast.BinaryExpr)
		if !isBinary {
			return true
		}
		switch binary.Op {
		case token.ADD, token.SUB, token.MUL, token.QUO, token.REM,
			token.XOR, token.SHL, token.SHR, token.AND, token.OR:

			arithmetic = true
		}
		return true
	})
	return arithmetic
}

// claimConstantsIn is the constants of this source an expression is stated over, sorted and without
// repeats. A selector reports its FIELD -- syntax.MaxVectorLength is MaxVectorLength -- because the
// constant is the same constant whichever package the prose reached it through.
func claimConstantsIn(expr ast.Expr, constants map[string]bool) []string {
	named := []string{}
	ast.Inspect(expr, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.SelectorExpr:
			if typed.Sel != nil && constants[typed.Sel.Name] {
				named = append(named, typed.Sel.Name)
			}
			return false
		case *ast.Ident:
			if constants[typed.Name] {
				named = append(named, typed.Name)
			}
		}
		return true
	})
	slices.Sort(named)
	return slices.Compact(named)
}

// ---------------------------------------------------------------------------
// the source this reading is taken over
// ---------------------------------------------------------------------------

// claimReading is the production prose of both roots, the operand universe it is read against, and
// everything needed to decide whether a claim is discharged.
type claimReading struct {
	// every comment of every production file, with where it stands.
	comments []claimComment
	// the operand universe: every constant this source declares, in either root.
	constants map[string]bool
	// every test function of either root, by name.
	tests map[string]bool
	// every declaration of either root that has a body, by name. A name can carry more than one
	// declaration -- two types with a method of the same name -- and all of them are held,
	// because a reachability reading that dropped one would report a discharged claim as
	// undischarged.
	bodies map[string][]*ast.FuncDecl
}

// claimComment is one comment group of the production source.
type claimComment struct {
	path string
	line int
	text string
}

// claimReadingOf parses the production prose and the declarations of both roots.
//
// BOTH ROOTS, and every file of them, for eraseReadingOf's reason: a rule scoped to the directory
// its first instance happened to sit in is a defect this project has paid for repeatedly.
func claimReadingOf(t *testing.T) claimReading {
	t.Helper()
	reading := claimReading{
		constants: map[string]bool{},
		tests:     map[string]bool{},
		bodies:    map[string][]*ast.FuncDecl{},
	}
	scan := mustScanSources(t, forbiddenScanRoots)
	production := productionSources(scan.sourceTexts)
	for _, path := range slices.Sorted(maps.Keys(scan.sourceTexts)) {
		if _, isProduction := production[path]; !isProduction {
			claimCollectDeclarations(&reading, mustParseSource(t, path))
			continue
		}
		parsed := mustReadCommented(t, path)
		claimCollectDeclarations(&reading, parsed)
		for _, declaration := range parsed.file.Decls {
			general, isGeneral := declaration.(*ast.GenDecl)
			if !isGeneral || general.Tok != token.CONST {
				continue
			}
			for _, spec := range general.Specs {
				value, isValue := spec.(*ast.ValueSpec)
				if !isValue {
					continue
				}
				for _, name := range value.Names {
					reading.constants[name.Name] = true
				}
			}
		}
		for _, group := range parsed.file.Comments {
			reading.comments = append(reading.comments, claimComment{
				path: path,
				line: parsed.fileSet.Position(group.Pos()).Line,
				text: group.Text(),
			})
		}
	}
	if len(reading.constants) == 0 || len(reading.tests) == 0 || len(reading.comments) == 0 {
		t.Fatalf("this reading found %d constant(s), %d test(s) and %d production comment(s); a reading missing any of the three certifies every claim below without having read the source",
			len(reading.constants), len(reading.tests), len(reading.comments))
	}
	return reading
}

// claimCollectDeclarations indexes one parsed file's functions, and its tests.
func claimCollectDeclarations(reading *claimReading, parsed parsedSource) {
	for _, declaration := range parsed.file.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if !isFunction || function.Body == nil {
			continue
		}
		reading.bodies[function.Name.Name] = append(reading.bodies[function.Name.Name], function)
		if function.Recv == nil && claimIsTestName(function.Name.Name) {
			reading.tests[function.Name.Name] = true
		}
	}
}

// claimIsTestName reports whether a name has the shape of a test of this source.
//
// THE SHAPE AND NOT A LOOKUP, because this predicate has to answer for a name found in PROSE as
// well as for a declaration. "Testing" is an English word and "TestTheCatchUpLoses..." is a
// reference; what separates them is go's own exported-name convention, an upper case letter
// immediately after the prefix, which no English word beginning "test" has.
func claimIsTestName(name string) bool {
	if !strings.HasPrefix(name, "Test") || len(name) <= len("Test") {
		return false
	}
	return unicode.IsUpper(rune(name[len("Test")]))
}

// claimTestNamesIn is every test this comment names.
func claimTestNamesIn(text string) []string {
	named := []string{}
	for _, run := range claimTokensIn(text) {
		for _, atom := range run {
			if atom.operand && claimIsTestName(atom.text) {
				named = append(named, atom.text)
			}
		}
	}
	slices.Sort(named)
	return slices.Compact(named)
}

// claimReachesConstant reports whether a declaration, or anything it calls, computes with one
// constant.
//
// TRANSITIVE, because the arithmetic a test is responsible for is routinely one call away -- the
// catch-up disclosure's formula lives in stMessagesLostCatchingUp and the case that drives it
// merely calls it, which is the shape this whole file is asking for. Every declaration sharing a
// name is walked rather than one of them, so a method name shared by two types cannot make a
// discharged claim read as undischarged.
func claimReachesConstant(reading claimReading, from string, constant string) bool {
	wanted := map[string]bool{constant: true}
	seen := map[string]bool{}
	var walk func(string) bool
	walk = func(name string) bool {
		if seen[name] {
			return false
		}
		seen[name] = true
		for _, function := range reading.bodies[name] {
			calls := []string{}
			computes := false
			ast.Inspect(function.Body, func(node ast.Node) bool {
				switch typed := node.(type) {
				case *ast.BinaryExpr:
					if claimHoldsArithmetic(typed) && len(claimConstantsIn(typed, wanted)) != 0 {
						computes = true
					}
				case *ast.CallExpr:
					switch called := typed.Fun.(type) {
					case *ast.Ident:
						calls = append(calls, called.Name)
					case *ast.SelectorExpr:
						if called.Sel != nil {
							calls = append(calls, called.Sel.Name)
						}
					}
				}
				return true
			})
			if computes {
				return true
			}
			for _, call := range calls {
				if walk(call) {
					return true
				}
			}
		}
		return false
	}
	return walk(from)
}

// ---------------------------------------------------------------------------
// the gate
// ---------------------------------------------------------------------------

// claimUndischarged is one claim and what is missing from it, as the failures below report it.
type claimUndischarged struct {
	at       string
	formula  string
	constant string
	named    []string
}

func (self claimUndischarged) String() string {
	if len(self.named) == 0 {
		return fmt.Sprintf("%s states %q over %s and names no test at all",
			self.at, self.formula, self.constant)
	}
	return fmt.Sprintf("%s states %q over %s and the test(s) it names -- %v -- reach no arithmetic over that constant",
		self.at, self.formula, self.constant, self.named)
}

// theUndischargedClaimsOf is the reading both the gate and its control run.
func theUndischargedClaimsOf(reading claimReading) (found []claimUndischarged, claims int) {
	for _, comment := range reading.comments {
		named := claimTestNamesIn(comment.text)
		for _, formula := range formulasStatedIn(comment.text, reading.constants) {
			claims += 1
			for _, constant := range formula.constants {
				discharged := false
				for _, name := range named {
					if reading.tests[name] && claimReachesConstant(reading, name, constant) {
						discharged = true
						break
					}
				}
				if discharged {
					continue
				}
				found = append(found, claimUndischarged{
					at:       fmt.Sprintf("%s:%d", comment.path, comment.line),
					formula:  formula.text,
					constant: constant,
					named:    named,
				})
			}
		}
	}
	return found, claims
}

// TestEveryFormulaThisSourceStatesInProseIsMeasuredByATestItNames is the gate.
//
// A production comment that works a quantity out over a constant this source declares has to name
// the test that computes the same quantity in go. What that buys is not that the sentence is true
// -- no gate reads English -- it is that the arithmetic exists somewhere a test can evaluate it at
// more than the one point the sentence happened to be checked at, and that deleting or renaming
// that test breaks the build rather than orphaning the paragraph.
func TestEveryFormulaThisSourceStatesInProseIsMeasuredByATestItNames(t *testing.T) {
	reading := claimReadingOf(t)
	undischarged, claims := theUndischargedClaimsOf(reading)
	if claims == 0 {
		t.Fatalf("this reading found no arithmetic at all in %d production comment(s) over %d constant(s); a reading that finds nothing reports every claim discharged",
			len(reading.comments), len(reading.constants))
	}
	for _, one := range undischarged {
		t.Errorf("%s. Move the arithmetic into a function a test evaluates, and name that test here: a formula that exists only in prose is checked at whatever single point somebody last thought of",
			one)
	}
	t.Logf("%d quantitative claim(s) over this source's own constants, in %d production comment(s), each measured by a test it names",
		claims, len(reading.comments))
}

// TestEveryTestAProductionCommentNamesExists is the other direction.
//
// Prose in this package cites tests constantly, and a citation that stopped resolving is worse than
// no citation: a reader follows it, finds nothing, and cannot tell whether the property was dropped
// or the name was changed. A rename breaks this rather than the paragraph.
func TestEveryTestAProductionCommentNamesExists(t *testing.T) {
	reading := claimReadingOf(t)
	references := 0
	for _, comment := range reading.comments {
		for _, name := range claimTestNamesIn(comment.text) {
			references += 1
			if !reading.tests[name] {
				t.Errorf("%s:%d names %s and no test of either root declares it",
					comment.path, comment.line, name)
			}
		}
	}
	if references == 0 {
		t.Fatal("no production comment of either root names a test, so this reading is not finding the citations it is stated over")
	}
	t.Logf("%d test citation(s) in production prose, every one of them resolving", references)
}

// ---------------------------------------------------------------------------
// the control
// ---------------------------------------------------------------------------

// A source holding one of each shape the reading has to separate.
//
// Every line of it is a shape this package's real prose actually contains, and three of them are
// shapes a first reading of that prose got wrong: "SHA-256" and "ML-KEM-768" parse as subtraction,
// "a catch-up -- and the rest" parses as a subtraction of a negation across the em dash, and
// "2^32-1" is arithmetic that names nothing this source declares. A reading that reported any of
// those would put the whole package in the class and the class would be abandoned within a week,
// which is the failure mode of a gate that is too loud rather than too quiet.
const quantitativeClaimControl = `package control

// ControlBound is what the prose below is stated over.
const ControlBound = 8

// a receiver behind by n loses ceil((n-ControlBound)/(ControlBound-1)) messages, and this
// paragraph names no test at all.
func undischarged() {}

// the window peaks at ControlBound+1 entries between a peek and its erase.
// TestControlMeasuresTheBound holds it.
func discharged() {}

// the window peaks at ControlBound+1 entries. TestControlNamesNoArithmetic holds it.
func namedButNotMeasured() {}

// SHA-256 over an ML-KEM-768 key package, a non-empty A-ASSUME-4 catch-up -- and the value
// MaxVectorLength names, at ValSem002-011.
func prose() {}

// the counter stops at 2^32-1, which is a fact about a uint32 and not about this source.
func literalsOnly() {}

// TestControlThatWasRenamed is what said so.
func citesNothing() {}
`

// The test half of the control, which is where a discharge lives: one test that computes with the
// constant and one that merely exists.
const quantitativeClaimControlTests = `package control

func TestControlMeasuresTheBound(t *testing.T) {
	if controlWindowPeak() != ControlBound+1 {
		panic("no")
	}
}

func controlWindowPeak() int { return 9 }

func TestControlNamesNoArithmetic(t *testing.T) {
	if controlWindowPeak() != 9 {
		panic("no")
	}
}
`

// claimControlReading builds a reading over the control alone, so the assertions below are about
// the rule and not about the package it happens to run over.
func claimControlReading(t *testing.T) claimReading {
	t.Helper()
	reading := claimReading{
		constants: map[string]bool{},
		tests:     map[string]bool{},
		bodies:    map[string][]*ast.FuncDecl{},
	}
	production := mustParseCommented(t, "control.go", quantitativeClaimControl)
	claimCollectDeclarations(&reading, production)
	claimCollectDeclarations(&reading, mustParseCommented(t, "control_test.go", quantitativeClaimControlTests))
	for _, declaration := range production.file.Decls {
		general, isGeneral := declaration.(*ast.GenDecl)
		if !isGeneral || general.Tok != token.CONST {
			continue
		}
		for _, spec := range general.Specs {
			value, isValue := spec.(*ast.ValueSpec)
			if !isValue {
				continue
			}
			for _, name := range value.Names {
				reading.constants[name.Name] = true
			}
		}
	}
	for _, group := range production.file.Comments {
		reading.comments = append(reading.comments, claimComment{
			path: "control.go",
			line: production.fileSet.Position(group.Pos()).Line,
			text: group.Text(),
		})
	}
	return reading
}

// TestTheProseReadingReportsTheControlAndNothingElseInIt is the vacuity guard on everything above.
//
// EXACTLY AND NOT AS A FLOOR, in both directions. A reading that reported every comment would
// satisfy a floor and be useless; a reading that reported none would satisfy the gate above on any
// source at all, which is precisely how a matcher that stopped matching goes unnoticed. So the
// control names the three claims it holds and the four shapes it does not, and the case fails if
// the reading answers any other set.
func TestTheProseReadingReportsTheControlAndNothingElseInIt(t *testing.T) {
	reading := claimControlReading(t)
	if !reading.constants["ControlBound"] || !reading.tests["TestControlMeasuresTheBound"] {
		t.Fatalf("the control reading found constants %v and tests %v; it is not reading the control at all",
			slices.Sorted(maps.Keys(reading.constants)), slices.Sorted(maps.Keys(reading.tests)))
	}

	claimed := []string{}
	for _, comment := range reading.comments {
		for _, formula := range formulasStatedIn(comment.text, reading.constants) {
			claimed = append(claimed, formula.text)
		}
	}
	slices.Sort(claimed)
	wantClaimed := []string{
		"ControlBound + 1",
		"ControlBound + 1",
		"ceil((n - ControlBound) / (ControlBound - 1))",
	}
	if !slices.Equal(claimed, wantClaimed) {
		t.Errorf("the reading finds %v in the control and the control states %v; a shape it added is prose it will demand a test for, and a shape it dropped is a claim it cannot see",
			claimed, wantClaimed)
	}

	undischarged, claims := theUndischargedClaimsOf(reading)
	if claims != len(wantClaimed) {
		t.Errorf("the reading counted %d claim(s) over the control's %d", claims, len(wantClaimed))
	}
	reported := []string{}
	for _, one := range undischarged {
		reported = append(reported, one.at+" "+one.formula)
	}
	slices.Sort(reported)
	wantReported := []string{
		"control.go:14 ControlBound + 1",
		"control.go:6 ceil((n - ControlBound) / (ControlBound - 1))",
	}
	if !slices.Equal(reported, wantReported) {
		t.Errorf("the gate reports %v over the control and the control holds %v: the undischarged claim naming no test and the one naming a test that computes nothing are what it has to separate from the claim beside them that is measured",
			reported, wantReported)
	}

	dangling := []string{}
	for _, comment := range reading.comments {
		for _, name := range claimTestNamesIn(comment.text) {
			if !reading.tests[name] {
				dangling = append(dangling, name)
			}
		}
	}
	if !slices.Equal(dangling, []string{"TestControlThatWasRenamed"}) {
		t.Errorf("the citation reading reports %v over the control, want exactly the one name nothing declares",
			dangling)
	}
}
