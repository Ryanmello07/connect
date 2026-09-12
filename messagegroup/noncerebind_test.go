// S2-2: the nonce that moves, the one field it moves, and the two files that may not move it.
//
// WHAT THE DEFECT WAS. GroupSession.serverNonce was fixed at construction with no setter, and
// spec A section 5.7 has the server draw a fresh nonce at EVERY Hello and carry it in
// HelloResponse. write_auth is a mac over that nonce, so the first reconnect invalidated every
// record the session had sealed since it opened: any session that outlived one connection was
// wrong. RebindServerNonce is the setter and ReauthRecord is what makes a rebind observable on a
// record that was already sealed.
//
// THE BLAST RADIUS, DERIVED AGAINST THE TREE RATHER THAN TRANSCRIBED FROM THE PLAN. The query is
//
//	git grep -n 'serverNonce' -- 'messagegroup/*.go' | grep -v _test
//
// and its production READS are one: seal.go's authenticate, handing the field to
// message.ComputeWriteAuth, whose answer lands in record.WriteAuth. The nonce is not an input to
// AADHead, AADBody, RecordAeadHead, RecordAeadBody, StorageRoot, DeriveClassKeys, message.WriteKey,
// message.ReadKey, SenderHandle or StreamKey, and openRecordOnLoop never reads write_auth at all.
// So exactly ONE sealed value binds the nonce, a rebind must recompute exactly that one, and
// nothing already sealed becomes unopenable -- which is the last clause held as a property below
// and not as a sentence here.
//
// WHAT IS OBSERVED THROUGH WHAT. The setter's principal clause cannot be seen without the re-auth:
// there is no route on which the nonce is the sole free variable that does not re-authenticate one
// record, because sealing a second record instead moves stream_index, which moves record_key[i],
// which moves both ciphertexts and the handle -- a difference no assertion could attribute to the
// nonce. That is why the two land together and why the setter's own commit could not claim it.
package messagegroup

import (
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
)

// A second nonce, distinct from testServerNonce() in both its octets and its length, so a case
// that rebinds to it is changing something a mac can see and a case that compares the two cannot
// be satisfied by a reslice.
func noncerebindSecondNonce() []byte {
	return []byte("second-connection-hello-nonce")
}

// ---------------------------------------------------------------------------
// Task 3 Property 1: the setter replaces the field and refuses what the
// constructor refuses, with the constructor's own sentinel
// ---------------------------------------------------------------------------

// noncerebindConstructorTakes answers whether NewGroupSession accepts a nonce of these octets,
// asked WITHOUT building a session.
//
// The constructor checks the nonce and then checks pq_secret, so a nil pq_secret makes the NEXT
// refusal the answer to this question: ErrSessionServerNonce means the nonce was refused and
// ErrNilPqSecret means it was accepted. Anything else is this probe having stopped measuring what
// it claims, and is a fatal rather than a false.
//
// The handle is never touched on either path -- both returns are above the constructor's first
// handle.GroupId() call -- which is what makes it legal to ask this about a handle a live session
// already owns, and what keeps the probe from being a second session over one group.
func noncerebindConstructorTakes(t *testing.T, handle GroupHandle, nonce []byte) bool {
	t.Helper()
	session, err := NewGroupSession(handle, nil, nil, newStreamIndexMemory(), testClock(), nonce)
	if session != nil {
		session.Close()
		t.Fatalf("the width probe built a session over a nil pq_secret, so it is no longer measuring the nonce door")
	}
	switch {
	case errors.Is(err, ErrSessionServerNonce):
		return false
	case errors.Is(err, ErrNilPqSecret):
		return true
	}
	t.Fatalf("the width probe got %v, which is neither of the two refusals it reads the constructor's answer off; it has stopped measuring the nonce door", err)
	return false
}

// Property 1, the emptiness half: the two spellings of "no nonce" are refused with the sentinel
// NewGroupSession refuses an empty one with.
func TestTheRebindRefusesAnEmptyNonceWithTheConstructorsOwnSentinel(t *testing.T) {
	fixture := newTestSession(t, "rebind-empty")
	for _, empty := range []struct {
		name  string
		nonce []byte
	}{
		{name: "nil", nonce: nil},
		{name: "a zero length slice", nonce: []byte{}},
	} {
		err := fixture.session.RebindServerNonce(empty.nonce)
		if !errors.Is(err, ErrSessionServerNonce) {
			t.Errorf("RebindServerNonce(%s) = %v, want %v; the field write_auth is macced over cannot be emptied, and without this refusal message.ComputeWriteAuth panics on the next seal rather than answering a bad mac",
				empty.name, err, ErrSessionServerNonce)
		}
	}
	// and the field is untouched: a good nonce still seals, which is what says the refusal
	// returned before the erase rather than after it.
	if err := fixture.session.RebindServerNonce(noncerebindSecondNonce()); err != nil {
		t.Fatalf("RebindServerNonce after two refusals: %v; the refusal reached the field", err)
	}
}

// Property 1, the agreement half: TWO DOORS ONTO ONE FIELD, ONE RULE.
//
// The class is derived rather than listed: every width from zero to sixty four is put to the
// constructor and to the setter, and the two answers must agree at every one of them. A setter
// that refused a nonce the constructor accepts -- a width check, say -- is two rules over one
// field, and a reader meeting a thirty one octet nonce would have to derive which door it arrived
// through.
//
// WHAT THIS DELIBERATELY DOES NOT ASSERT is that a nonce is thirty two octets. MASTER section 7
// and spec A section 5.7 both fix the width there; this package's constructor checks only
// emptiness, and making the setter stricter than the constructor is the defect above. The
// disagreement between the specification and the package is real, is not this gate's to rule, and
// is open item K1-2 -- which is why it is written down here beside the gate that would otherwise
// look like it had ruled it.
func TestTheRebindAndTheConstructorRefuseExactlyTheSameNonces(t *testing.T) {
	fixture := newTestSession(t, "rebind-agreement")
	disagreed := []int{}
	accepted := []int{}
	for width := 0; width <= 64; width += 1 {
		nonce := make([]byte, width)
		for i := range nonce {
			nonce[i] = byte(0x40 + i)
		}
		byTheConstructor := noncerebindConstructorTakes(t, fixture.handle, nonce)
		refusal := fixture.session.RebindServerNonce(nonce)
		byTheSetter := refusal == nil
		if !byTheSetter && !errors.Is(refusal, ErrSessionServerNonce) {
			t.Fatalf("RebindServerNonce of %d octets refused with %v, which is not the nonce sentinel at all", width, refusal)
		}
		if byTheConstructor != byTheSetter {
			disagreed = append(disagreed, width)
		}
		if byTheSetter {
			accepted = append(accepted, width)
		}
	}
	if len(disagreed) != 0 {
		t.Errorf("the constructor and the setter disagree about %d width(s): %v; two doors onto serverNonce with two rules is two rules, and open item K1-2 is where the specification's thirty two octets get ruled -- not here",
			len(disagreed), disagreed)
	}
	if len(accepted) == 0 {
		t.Fatal("neither door accepted a nonce of any width from 0 to 64, so this gate agreed about nothing")
	}
	if slices.Contains(accepted, 0) {
		t.Error("width 0 was accepted by both doors, so the agreement this gate reports is agreement that the field may be emptied")
	}
	t.Logf("widths 0..64: %d accepted by both doors (%v), %d disagreement(s)", len(accepted), accepted, len(disagreed))
}

// ---------------------------------------------------------------------------
// Task 3 Property 3: a closed session refuses the rebind
// ---------------------------------------------------------------------------

// A rebind on a closed session is refused, and what the refusal is standing in front of is worth
// naming: zeroizeOnLoop has already erased writeKey, so the next ReauthRecord would reach
// message.ComputeWriteAuth with a zero length key and PANIC rather than refuse, on whichever
// goroutine posted it.
//
// The refusal comes back out of do, whose send sees stopped closed. The self.closing clause in the
// posted body is unreachable in this tree for the reason EpochKeys's comment measures, and this
// case does not claim to drive it.
func TestAClosedSessionRefusesTheRebind(t *testing.T) {
	fixture := newTestSession(t, "rebind-closed")
	if err := fixture.session.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := fixture.session.RebindServerNonce(noncerebindSecondNonce()); !errors.Is(err, ErrSessionClosed) {
		t.Errorf("RebindServerNonce after Close = %v, want %v", err, ErrSessionClosed)
	}
	// and an empty nonce on a closed session is still a closed session: the refusals are
	// ordered, and a door that answered the argument's problem first would be a door that
	// reached a closed session's state to find it.
	if err := fixture.session.RebindServerNonce(nil); !errors.Is(err, ErrSessionClosed) {
		t.Errorf("RebindServerNonce(nil) after Close = %v, want %v", err, ErrSessionClosed)
	}
}

// ---------------------------------------------------------------------------
// Task 3 Property 3, the half a behavioural case cannot reach: the write to
// the field stands on the loop
// ---------------------------------------------------------------------------

// A rebind whose WRITE stood off the loop would be a write racing the goroutine that seals, and
// nothing behavioural in this package would say so: the closed-session refusal comes back out of
// do whether or not the body that do posts is the body that writes, so Property 3 stays green over
// a setter that posts an empty command and then assigns the field on the caller's goroutine.
//
// MEASURED, AND IT IS WHY THIS GATE EXISTS RATHER THAN BEING LEFT TO THE LANDED ONE.
// TestEveryMethodOfAGroupSessionReachesItsStateOnlyOnTheLoop derives its loop-owned field set from
// the fields some on-loop body TOUCHES, so a field that no on-loop body touches is in no class at
// all -- and serverNonce was exactly that field before this slice: the constructor writes it in a
// composite literal and seal.go's authenticate reads it through builder.session, neither of which
// is a self.<field> mention. Moving this setter's write out of its posted closure therefore
// survived an unfiltered run of this package. It does not survive this one.
//
// THE CLASS IS THE WRITES AND THE COMPLEMENT IS THE READS, printed. The scope is this package's
// production source; the class is every assignment in it whose left hand side is a selector named
// serverNonce; the complement is every other mention of that name, which this gate does NOT hold
// and names so that a reader knows it.
func TestEveryWriteToTheSessionsServerNonceStandsOnTheLoop(t *testing.T) {
	fileSet, sources := messagegroupProductionSources(t)
	onLoop := []string{}
	offLoop := []string{}
	notWrites := []string{}
	for _, source := range sources {
		for _, declaration := range source.parsed.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			inside := map[ast.Node]bool{}
			for _, closure := range sessionDoClosures(function.Body) {
				ast.Inspect(closure, func(node ast.Node) bool {
					inside[node] = true
					return true
				})
			}
			wholeBodyOnLoop := sessionRunsOnTheLoop(function)
			ast.Inspect(function.Body, func(node ast.Node) bool {
				assignment, isAssignment := node.(*ast.AssignStmt)
				if !isAssignment {
					if selector, isSelector := node.(*ast.SelectorExpr); isSelector && selector.Sel.Name == "serverNonce" {
						notWrites = append(notWrites, noncerebindWhere(fileSet, source.path, function.Name.Name, selector.Pos()))
					}
					return true
				}
				for _, target := range assignment.Lhs {
					selector, isSelector := target.(*ast.SelectorExpr)
					if !isSelector || selector.Sel.Name != "serverNonce" {
						continue
					}
					where := noncerebindWhere(fileSet, source.path, function.Name.Name, selector.Pos())
					if wholeBodyOnLoop || inside[node] {
						onLoop = append(onLoop, where)
					} else {
						offLoop = append(offLoop, where)
					}
				}
				return true
			})
		}
	}
	// the left hand side of a write is itself a selector, so it is cut from the complement here
	// rather than counted on both sides of the split the gate is reporting.
	for _, where := range append(append([]string{}, onLoop...), offLoop...) {
		notWrites = slices.DeleteFunc(notWrites, func(mention string) bool { return mention == where })
	}
	if len(onLoop)+len(offLoop) == 0 {
		t.Fatal("no assignment to a serverNonce field was read out of this package's production source, so this gate is holding an empty class and would report the same clean run over a setter that writes the field from any goroutine at all")
	}
	slices.Sort(notWrites)
	t.Logf("%d write(s) to serverNonce stand on the loop: %v; %d stand off it: %v; the COMPLEMENT this gate does not hold is the %d mention(s) that are not writes: %v",
		len(onLoop), onLoop, len(offLoop), offLoop, len(notWrites), slices.Compact(notWrites))
	for _, where := range offLoop {
		t.Errorf("%s writes serverNonce without posting a command; seal.go's authenticate reads that field on the loop goroutine, so a write anywhere else is a write racing a seal -- and the landed loop gate cannot see this one, because it derives its field set from the fields an on-loop body touches and this is the write that would have put serverNonce in it",
			where)
	}
}

// noncerebindWhere is one mention, spelled file:line (declaration), so a failure names the site
// rather than the field.
func noncerebindWhere(fileSet *token.FileSet, path string, declaration string, at token.Pos) string {
	return fmt.Sprintf("%s:%d (%s)", path, fileSet.Position(at).Line, declaration)
}

// ---------------------------------------------------------------------------
// Task 3 Property 4: no exported method of GroupSession answers the nonce
// ---------------------------------------------------------------------------

// The number of exported methods on *GroupSession this slice's commits make, pinned so that a
// method added without a thought about this gate moves a number rather than sliding in under a
// class the gate derives.
//
// The query is
//
//	git grep -n 'func (self \*GroupSession) [A-Z]' -- 'messagegroup/*.go' | grep -v _test
//
// and R6 clause (a) beside it: piping that through grep -c 'RebindServerNonce' returns 1, so the
// answer contains the member this task added rather than merely counting to nine. Task 4's
// ReauthRecord is the next method to move the number.
const noncerebindExportedSessionMethods = 9

// Property 4 -- THE NARROWING, AND IT IS THE ONE PLACE IN THIS FILE WHERE AN EMPTINESS IS THE
// PROPERTY RATHER THAN A DEFECT IN IT.
//
// The class is every exported method of *GroupSession, read off the syntax tree. Out of it is
// carved the set that ANSWERS OCTETS -- a result that is a []byte or a [N]byte -- and out of THAT
// the set whose body also reaches self.serverNonce. The last set must be empty.
//
// The gate fatals on an empty enclosing class and on an empty octet-answering set, and both
// fatals are the point: a gate that derived no exported method at all, or that found no method
// answering octets at all, would report exactly the same clean run over a surface that had grown a
// getter. The complement is PRINTED -- the exported methods that do answer octets and do not
// answer the nonce -- because a narrowing whose complement is empty is a narrowing that has
// covered everything, and a reader must not have to infer which reading this is.
//
// WHAT THE BAN BUYS, stated so it is not mistaken for tidiness: keysource_test.go's reproduction is
// handed server_nonce as one of the three values THE TEST INJECTED, and a getter is the one thing
// that would let a fixture hand it the value the session HOLDS instead -- at which point the third
// input stops being independent and the subject starts agreeing with itself.
//
// The reach is a FIELD MENTION and not a dataflow, which widens the answering set rather than
// narrowing it: a method that answers octets and merely names the nonce is reported. That is the
// direction a gate may be wrong in.
func TestNoExportedMethodOfAGroupSessionAnswersTheServerNonce(t *testing.T) {
	_, sources := messagegroupProductionSources(t)
	exported := []string{}
	answersOctets := []string{}
	answersTheNonce := []string{}
	for _, source := range sources {
		for _, declaration := range source.parsed.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil || sessionReceiverName(function) != "GroupSession" {
				continue
			}
			if !ast.IsExported(function.Name.Name) {
				continue
			}
			exported = append(exported, function.Name.Name)
			if !noncerebindAnswersOctets(function) {
				continue
			}
			answersOctets = append(answersOctets, function.Name.Name)
			if noncerebindMentionsTheNonce(function.Body) {
				answersTheNonce = append(answersTheNonce, function.Name.Name)
			}
		}
	}
	slices.Sort(exported)
	slices.Sort(answersOctets)
	slices.Sort(answersTheNonce)
	if len(exported) == 0 {
		t.Fatal("no exported method of *GroupSession was read out of this package's production source, so the subset this gate requires to be empty is empty because the gate read nothing")
	}
	if len(answersOctets) == 0 {
		t.Fatal("no exported method of *GroupSession answers a []byte or a [N]byte at all, so the nonce answering subset is empty for a reason that has nothing to do with the nonce; this gate would report the same clean run over a surface carrying a getter")
	}
	complement := []string{}
	for _, name := range answersOctets {
		if !slices.Contains(answersTheNonce, name) {
			complement = append(complement, name)
		}
	}
	if len(complement) == 0 {
		t.Fatal("every exported method of *GroupSession that answers octets answers the nonce, so the complement of this narrowing is empty -- which is the reading a gate must say out loud rather than leave a reader to infer")
	}
	t.Logf("%d exported method(s) on *GroupSession: %v; %d answer octets: %v; the COMPLEMENT of the ban is those %d (%v) and the banned subset is %v",
		len(exported), exported, len(answersOctets), answersOctets, len(complement), complement, answersTheNonce)
	for _, name := range answersTheNonce {
		t.Errorf("(*GroupSession).%s is exported, answers octets and reaches self.serverNonce; there is no getter for the nonce on purpose -- a fixture that could ask the session for it would hand keysource_test.go's reproduction the value the subject holds instead of the value the test injected, and the third of its three independent inputs would become the subject agreeing with itself",
			name)
	}
	if len(exported) != noncerebindExportedSessionMethods {
		t.Errorf("%d exported methods are declared on *GroupSession and this slice's commits make it %d; the number moves by one per exported method and a method that arrived without moving it arrived without a thought about this narrowing",
			len(exported), noncerebindExportedSessionMethods)
	}
	for _, added := range []string{"RebindServerNonce"} {
		if !slices.Contains(exported, added) {
			t.Errorf("no exported method named %s is declared on *GroupSession, so this gate is holding a class that does not contain the members this slice added and would report clean having read some other surface",
				added)
		}
	}
}

// noncerebindAnswersOctets is whether any result of this declaration is a []byte or a [N]byte.
//
// It is read off the type and not off a name, so message.RetentionClass and every other named
// type stays outside: what the ban is about is a method that hands a caller the octets, and
// [16]byte -- SenderHandle's answer -- is as much a hand-off as []byte is.
func noncerebindAnswersOctets(function *ast.FuncDecl) bool {
	if function.Type.Results == nil {
		return false
	}
	for _, result := range function.Type.Results.List {
		array, isArray := result.Type.(*ast.ArrayType)
		if !isArray {
			continue
		}
		element, isName := array.Elt.(*ast.Ident)
		if !isName || element.Name != "byte" {
			continue
		}
		if array.Len == nil {
			return true
		}
		if _, isLiteral := array.Len.(*ast.BasicLit); isLiteral {
			return true
		}
	}
	return false
}

// noncerebindMentionsTheNonce is whether a body names self.serverNonce anywhere, inside a posted
// closure or out of one.
func noncerebindMentionsTheNonce(body ast.Node) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		selector, isSelector := node.(*ast.SelectorExpr)
		if !isSelector || selector.Sel.Name != "serverNonce" {
			return true
		}
		if name, isName := selector.X.(*ast.Ident); isName && name.Name == "self" {
			found = true
		}
		return true
	})
	return found
}

// ---------------------------------------------------------------------------
// Task 3 Property 5: the two test files whose own correctness needs the
// INJECTED nonce may not rebind it
// ---------------------------------------------------------------------------

// The two files, and each is named for what its own correctness rests on rather than by taste.
//
// keysource_test.go's reproduction is handed server_nonce as one of THREE INJECTED VALUES and its
// header says so in as many words -- "the value the constructor was injected with". Before this
// slice that sentence was true because no setter existed. After it, it is true because of this
// gate.
//
// sessionfixture_test.go is the constructor every session in this package is built through, so a
// rebind in it is a rebind in every case in the package at once, including the five of
// keysource_test.go.
var noncerebindBannedCallers = []string{"keysource_test.go", "sessionfixture_test.go"}

// Property 5, held mechanically off the test source.
//
// THE SCOPE IS DERIVED SEPARATELY FROM THE CLASS: the scope is every _test.go file of this
// package, counted at run time rather than transcribed, because the plan's own count for it was
// taken at an older commit and is stale by three. The CLASS is the two files above. THE COMPLEMENT
// IS EVERY OTHER TEST FILE AND THIS GATE PRINTS IT BY NAME -- an empty complement would mean the
// ban had grown to cover the package, and that is the reading a gate must say rather than a reader
// infer.
//
// The gate is vacuous unless something calls the setter at all, so it fatals when no test file
// does, and errors when the file this slice added is not among the callers.
func TestTheTwoTestFilesWhoseCorrectnessNeedsTheInjectedNonceNeverRebindIt(t *testing.T) {
	fileSet := token.NewFileSet()
	scope := []string{}
	callers := []string{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read this package's directory: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		scope = append(scope, name)
		parsed, parseErr := parser.ParseFile(fileSet, filepath.ToSlash(filepath.Join(".", name)), nil,
			parser.SkipObjectResolution)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", name, parseErr)
		}
		if noncerebindCallsTheSetter(parsed) {
			callers = append(callers, name)
		}
	}
	slices.Sort(scope)
	slices.Sort(callers)
	if len(scope) == 0 {
		t.Fatal("no _test.go file was read out of this package, so every rule this gate holds over that source cleared its subject having read nothing")
	}
	for _, banned := range noncerebindBannedCallers {
		if !slices.Contains(scope, banned) {
			t.Fatalf("%s is not in this package's test source, so the ban this gate holds names a file that is not there", banned)
		}
	}
	if len(callers) == 0 {
		t.Fatal("no test file of this package calls RebindServerNonce, so a ban on two of them is a ban over an empty class and would report clean whatever those two did")
	}
	complement := []string{}
	for _, name := range scope {
		if !slices.Contains(noncerebindBannedCallers, name) {
			complement = append(complement, name)
		}
	}
	if len(complement) == 0 {
		t.Fatal("every test file of this package is banned from calling RebindServerNonce, so the complement of this ban is empty and the ban has grown to cover the package")
	}
	t.Logf("scope: %d test file(s); the ban is %d of them (%v); the COMPLEMENT is the other %d, which may call the setter freely: %v; the callers today are %v",
		len(scope), len(noncerebindBannedCallers), noncerebindBannedCallers, len(complement), complement, callers)
	for _, banned := range noncerebindBannedCallers {
		if slices.Contains(callers, banned) {
			t.Errorf("%s calls RebindServerNonce; its own correctness rests on server_nonce being the value the constructor was INJECTED with, and a rebind there makes the third of the reproduction's three independent inputs a value the subject chose",
				banned)
		}
	}
	if !slices.Contains(callers, "noncerebind_test.go") {
		t.Error("noncerebind_test.go does not call RebindServerNonce, so this gate's non-vacuity rests on some other file and the properties above are no longer observing the setter")
	}
}

// noncerebindCallsTheSetter is whether one parsed file contains a CALL of RebindServerNonce.
//
// It is a call site and not a mention, so the name appearing in this file's own failure messages
// and in its banned-caller list is not a call -- which is the difference between a gate that reads
// the source and one that greps it.
func noncerebindCallsTheSetter(parsed *ast.File) bool {
	found := false
	ast.Inspect(parsed, func(node ast.Node) bool {
		call, isCall := node.(*ast.CallExpr)
		if !isCall {
			return true
		}
		if selector, isSelector := call.Fun.(*ast.SelectorExpr); isSelector {
			if selector.Sel.Name == "RebindServerNonce" {
				found = true
			}
			return true
		}
		if name, isName := call.Fun.(*ast.Ident); isName && name.Name == "RebindServerNonce" {
			found = true
		}
		return true
	})
	return found
}
