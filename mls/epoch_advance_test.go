// The derived answer to "who clears the proposal cache when the epoch advances".
//
// The rule: a ProposalCache belongs to one epoch of one group, and a cache that outlives that
// epoch answers the closed epoch's references to a commit of the new one. Resolve refuses that at
// the lookup now -- errProposalResolvedOutOfEpoch, proposal_list.go -- so the group cannot apply a
// replayed proposal even when nobody cleared. What is still needed, and what this file derives, is
// that the boundary itself is not left to memory: every declaration that moves a group to another
// epoch has to END the binding, or a member spends the whole of the new epoch unable to resolve
// any commit that names a proposal, and the first fix anybody reaches for is to weaken the door.
//
// Why it is derived rather than written down. The mitigation on offer was `self.proposals.Clear()`
// at two hand written call sites, which is an enumeration of the paths that advance an epoch --
// the shape rule 5 exists to refuse, and the shape that has understated its class fourteen times
// on this project: a constant time gate banning six comparator names that missed bytes.HasPrefix
// where the derived version finds eighteen; a table calling itself "every rule of the CreateGroup
// carve-out" that held five of six. Two call sites is a list of the epoch boundaries somebody had
// thought of. p7 has fifteen tasks left, and MergePendingCommit, a rollback, a state restore and a
// re-join are all shaped like an epoch boundary.
//
// So the class is what a declaration DOES. A declaration moves a group between epochs when it
// writes a GroupContext, or one of the two fields the cache binds to, into storage that outlives
// the call: `self.context = staged.context` and `self.context.Epoch++` are the two spellings, and
// both are assignments to a SELECTOR. An assignment to a bare identifier is excluded on purpose --
// a local or a parameter is a value the declaration is constructing, and every commit path in this
// plan builds its next GroupContext as a local before anything is allowed near the live group.
// That is the same line the erase helper gate draws between the caller's storage and the
// function's own, for the same reason.
//
// WHAT IS TRUE TODAY, said out loud rather than hidden by a green run. Not one declaration of
// either scanned root is classified as moving a group between epochs: the only member of the
// class is the group context DECODER, which writes an epoch it read out of the caller's own
// octets. So the second half of this gate -- every mover ends the binding -- runs on the control
// package and on nothing else, and the control is therefore not decoration. It is the whole of the
// evidence that the demand exists at all, and the commit that lands MergePendingCommit is the one
// that will be met by it.
package mls

import (
	"bytes"
	"errors"
	"go/ast"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// The three names this file's derivations are written against, and the one place they are
// spelled. Each is checked against the compiler's reading below rather than trusted: a rename that
// left these behind would empty both classes, and an empty class is what a package with no movers
// and a broken matcher both look like.
const (
	epochGroupContextTypeName = "GroupContext"
	epochCacheTypeName        = "ProposalCache"
)

// The fields of a GroupContext the proposal cache binds itself to.
//
// Both, and never the epoch alone: every group this client is a member of runs an epoch 7, so a
// declaration that rewrote a live context's group id in place has moved the group as surely as one
// that bumped its epoch, and the cache bound to the old pair answers references belonging to
// neither. bindingHolds compares exactly these two.
var epochBoundFields = []string{"GroupId", "Epoch"}

// epochMoverRoots is where the rule is stated: it IS forbiddenScanRoots, and not a copy.
//
// An alias for the reason extensionTypeSelectionRoots is one -- a restatement is held by nothing,
// and narrowing forbiddenScanRoots itself fails TestHkdfExtractHasOnlyTwoCallSites, so borrowing
// that value borrows a scope something already pins. ../message declares no GroupContext today and
// cannot: it imports mls/syntax and not mls, and mls must not import it back. That is not a reason
// to leave it out. A scope that covers only what is already written is a scope that stops covering
// the first thing added, and the group lifecycle is the layer most likely to grow a second holder
// of a group's epoch.
var epochMoverRoots = forbiddenScanRoots

// epochMoverFinding is one declaration's membership: where the write is, how it is written, and
// the call that ends the cache binding if the declaration makes one.
type epochMoverFinding struct {
	where string
	how   string
	ends  string
}

// epochMoverScan is what one scan read: the declarations that move a group between epochs, and how
// many field writes were resolved at all.
//
// The write count is carried for the reason extensionTypeSelectionScan carries its read count. A
// matcher that stopped resolving its subject reports an EMPTY class, and an empty class is exactly
// what a package with no movers reports -- so "nothing moves" and "nothing was read" have to be
// distinguishable, and only the second is a broken gate.
type epochMoverScan struct {
	moving map[string]epochMoverFinding
	writes int
}

// epochWriteTarget unwraps an assignment's left hand side to the selector it ultimately writes
// through.
//
// A map insert is a write of what the container holds -- `self.byRef[key] = entry` changes the
// cache as surely as `self.byRef = nil` does -- and so is a store through a pointer. A matcher
// that read only the bare selector form would report a clean run over a method that did all of its
// writing through an index expression, which is the shape (*ProposalCache).Store is half written
// in.
func epochWriteTarget(expr ast.Expr) *ast.SelectorExpr {
	for {
		expr = extensionTypeSelectionUnparenthesised(expr)
		switch node := expr.(type) {
		case *ast.IndexExpr:
			expr = node.X
		case *ast.StarExpr:
			expr = node.X
		case *ast.SelectorExpr:
			return node
		default:
			return nil
		}
	}
}

// epochAssignedTargets answers the left hand sides one statement writes, for the two statement
// kinds that write: an assignment and an increment.
//
// `self.context.Epoch++` carries no right hand side and is not an *ast.AssignStmt at all, and a
// rule that read only assignments would walk past the cheapest way there is to advance an epoch.
func epochAssignedTargets(node ast.Node) []ast.Expr {
	switch statement := node.(type) {
	case *ast.AssignStmt:
		return statement.Lhs
	case *ast.IncDecStmt:
		return []ast.Expr{statement.X}
	}
	return nil
}

// epochMoversIn is the rule: every declaration of one checked package that writes a group context,
// or one of the fields the cache binds to, into storage that outlives the call.
//
// The cache type and the methods that END a binding are parameters rather than constants, because
// this matcher is run on a control package that declares its own of each. A matcher that could
// only read the real names would have nothing to prove itself against, and the half of this gate
// that has no member in the real source is precisely the half the control exists to run.
func epochMoversIn(checked checkedBodies, cacheType string, enders []string) epochMoverScan {
	scan := epochMoverScan{moving: map[string]epochMoverFinding{}}
	for _, file := range checked.files {
		for _, declaration := range file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			name := extensionTypeSelectionDeclarationName(checked, function)
			finding := epochMoverFinding{}
			moves := false
			ast.Inspect(function.Body, func(node ast.Node) bool {
				// the call that ends a binding, collected over the same walk so a
				// declaration is judged on one reading of its body
				if call, isCall := node.(*ast.CallExpr); isCall {
					if method, isMethod := extensionTypeSelectionUnparenthesised(call.Fun).(*ast.SelectorExpr); isMethod {
						if slices.Contains(enders, method.Sel.Name) &&
							extensionTypeSelectionNamedAs(checked.info.TypeOf(method.X), cacheType) {
							finding.ends = checked.render(call)
						}
					}
				}
				for _, target := range epochAssignedTargets(node) {
					selector := epochWriteTarget(target)
					if selector == nil {
						// a bare identifier: a local or a parameter, which is
						// storage of this declaration's own and is what every
						// commit path builds its next context in
						continue
					}
					if checked.info.TypeOf(selector) == nil {
						continue
					}
					scan.writes++
					// replacing the group context a value HOLDS
					if extensionTypeSelectionNamedAs(checked.info.TypeOf(selector), epochGroupContextTypeName) {
						moves = true
						finding.how = checked.render(node)
						continue
					}
					// or moving one of the bound fields of a group context in place
					if slices.Contains(epochBoundFields, selector.Sel.Name) &&
						extensionTypeSelectionNamedAs(checked.info.TypeOf(selector.X), epochGroupContextTypeName) {
						moves = true
						finding.how = checked.render(node)
					}
				}
				return true
			})
			if !moves {
				continue
			}
			finding.where = checked.where(function)
			scan.moving[name] = finding
		}
	}
	return scan
}

// epochMoverControl is a package the matcher has never seen, declaring its own group context,
// proposal cache and group, written so that every half of the rule has something to report and
// something to walk past.
//
// It carries the two shapes the real class has no member of -- a merge that ends the binding and a
// merge that does not -- because those are what the second half of this gate demands, and the real
// source will not hold one until p7 task 13 lands MergePendingCommit. A control rather than a
// second opinion about the real source: a matcher that resolved nothing reports an empty class over
// mls too, and the only way to tell that apart from a package with no movers is to run it on source
// known to hold both answers.
const epochMoverControl = `package control

type GroupContext struct {
	GroupId []byte
	Epoch   uint64
	Extras  []byte
}

type ProposalCache struct {
	byRef map[string]int
	epoch uint64
}

func (self *ProposalCache) Clear() {
	self.byRef = map[string]int{}
	self.epoch = 0
}

func (self *ProposalCache) Store(key string, at uint64) {
	self.byRef[key] = 1
	self.epoch = at
}

type Group struct {
	context   *GroupContext
	proposals *ProposalCache
	name      string
}

// the shape p7 task 13 and task 19 both write, without the clear: the live context is replaced
// and the cache goes on holding the epoch that just closed
func (self *Group) mergeWithoutClearing(staged *GroupContext) {
	self.context = staged
	self.name = "merged"
}

// the same with the clear, which is the only shape this gate accepts
func (self *Group) mergeAndClear(staged *GroupContext) {
	self.context = staged
	self.proposals.Clear()
}

// the cheapest advance there is, and it is not an assignment at all
func (self *Group) bumpTheEpochInPlace() {
	self.context.Epoch++
}

// rewriting the group id in place, which moves the group as surely as the epoch does
func (self *Group) rebrand(id []byte) {
	self.context.GroupId = id
}

// the decoder shape: an epoch written into a context out of the caller's own input
func (self *GroupContext) decode(epoch uint64, id []byte) {
	self.Epoch = epoch
	self.GroupId = id
}

// staging a context of its own, which is what every commit path does before anything is allowed
// near the live group. A local is not storage that outlives the call
func (self *Group) stageTheNextContext() *GroupContext {
	next := &GroupContext{GroupId: self.context.GroupId, Epoch: self.context.Epoch + 1}
	next.Extras = []byte{0x01}
	return next
}

// writing a field of the live context that the cache binds to nothing of
func (self *Group) annotate(extras []byte) {
	self.context.Extras = extras
}

func (self *Group) readsTheEpoch() uint64 {
	return self.context.Epoch
}

// a Clear on something that is not a proposal cache, so the ender is resolved by TYPE and not by
// the spelling of the call
type Journal struct{ lines []string }

func (self *Journal) Clear() { self.lines = nil }

func (self *Group) mergeAndClearTheWrongThing(staged *GroupContext, journal *Journal) {
	self.context = staged
	journal.Clear()
}
`

// What the matcher must report out of the control, and by omission what it must walk past.
var epochMoverControlReports = []string{
	"(*Group).bumpTheEpochInPlace",
	"(*Group).mergeAndClear",
	"(*Group).mergeAndClearTheWrongThing",
	"(*Group).mergeWithoutClearing",
	"(*Group).rebrand",
	"(*GroupContext).decode",
}

// And which of them the matcher must read as ending the cache binding: exactly the one that calls
// Clear on a ProposalCache. mergeAndClearTheWrongThing calls a method of that NAME on another type
// and is not among them, which is what says the ender is resolved by the compiler's reading rather
// than by the spelling.
var epochMoverControlEnders = []string{"(*Group).mergeAndClear"}

// One classified member of the derived class.
//
// The prose is what a reader gets; movesAGroupBetweenEpochs is the classification a human has to
// make and is what the second half of the gate is stated over; and the probe is what stops the row
// being a label. A row asserting that a declaration only constructs, on a declaration that moves
// the live group, has to fail.
type epochMoverRow struct {
	what                     string
	movesAGroupBetweenEpochs bool
	probe                    func(t *testing.T)
}

// Every declaration of this package and of ../message that writes a group context, or a field the
// proposal cache binds to, into storage that outlives the call.
//
// Held EQUAL to the derived class in both directions by the gate below, so this is a
// classification and not a list: the commit that writes MergePendingCommit either ends the cache
// binding in the same body or fails here until somebody writes down which of the two things it
// does.
var groupContextEpochMovers = map[string]epochMoverRow{
	"(*GroupContext).UnmarshalMLS": {
		what: "the group context DECODER, and the epoch it writes is one it read out of the caller's own octets " +
			"rather than one this client advanced to. It moves no group: the value it writes into is one the " +
			"caller is constructing from a message, no proposal cache is bound to it, and the group whose epoch " +
			"this build actually lives in is not touched. This row is the false positive the rule is deliberately " +
			"too narrow to drop -- a rule that exempted the decoder by name would exempt the first commit path " +
			"that wrote its context field by field -- and it is worth the row",
		movesAGroupBetweenEpochs: false,
		probe: func(t *testing.T) {
			encoded, err := syntax.Marshal(&GroupContext{
				Version:                 ProtocolVersionMls10,
				CipherSuite:             CipherSuiteX25519ChaCha20Sha256Ed25519,
				GroupId:                 []byte("decoded"),
				Epoch:                   9,
				TreeHash:                bytes.Repeat([]byte{0xc0}, 32),
				ConfirmedTranscriptHash: bytes.Repeat([]byte{0xee}, 32),
			})
			if err != nil {
				t.Fatalf("encode the context this probe decodes: %v", err)
			}
			decoded := &GroupContext{}
			if err := syntax.Unmarshal(encoded, decoded); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if decoded.Epoch != 9 || !bytes.Equal(decoded.GroupId, []byte("decoded")) {
				t.Fatalf("the decoder answered epoch %d of group %x, want epoch 9 of \"decoded\"; the epoch it writes is the one the octets carry and that is the whole of this row's classification",
					decoded.Epoch, decoded.GroupId)
			}
			// and the other half of "it constructs": a decode that fails writes nothing at
			// all, so no receiver is left holding an epoch that came from half a message
			holding := &GroupContext{GroupId: []byte("held"), Epoch: 4}
			if err := syntax.Unmarshal(encoded[:len(encoded)-3], holding); err == nil {
				t.Fatal("a truncated group context decoded without error, so this probe observes nothing")
			}
			if holding.Epoch != 4 || !bytes.Equal(holding.GroupId, []byte("held")) {
				t.Errorf("a refused decode left the receiver at epoch %d of group %x, want the epoch 4 of \"held\" it was already holding; a partial write here is a group context moved to an epoch no message named",
					holding.Epoch, holding.GroupId)
			}
		},
	},
}

// epochBindingWriterRow is one method of the proposal cache that writes what the cache holds, with
// what it does to the binding.
type epochBindingWriterRow struct {
	what           string
	endsTheBinding bool
	probe          func(t *testing.T)
}

// Every method of *ProposalCache that writes a field of its own receiver, with what each does to
// the epoch binding.
//
// This is the other half of the derivation and it is what "or rebinding" means: the gate above
// does not demand a call to Clear by name, it demands a call to one of the methods classified HERE
// as ending a binding. A method that rebound the cache to the new epoch instead of emptying it
// would answer the same demand the moment somebody added its row, and until somebody does, adding
// it fails this gate rather than silently widening the other one.
var proposalCacheBindingWriters = map[string]epochBindingWriterRow{
	"(*ProposalCache).Store": {
		what: "binds the cache to the group and epoch of its FIRST entry and refuses every later entry that " +
			"does not match. It writes the binding and it never ends one: a Store that rebound would make the " +
			"binding whatever arrived last, and what arrives is attacker supplied",
		endsTheBinding: false,
		probe: func(t *testing.T) {
			crypto := testCrypto(t)
			cache := NewProposalCache()
			if _, err := cache.Store(crypto, testProposalContentAt(t, 1, []byte("group"), 7,
				testRemoveProposal(LeafIndex(4)))); err != nil {
				t.Fatalf("Store at epoch 7: %v", err)
			}
			if err := cache.CheckEpoch([]byte("group"), 7); err != nil {
				t.Fatalf("the cache did not bind to the epoch of its first entry: %v", err)
			}
			if _, err := cache.Store(crypto, testProposalContentAt(t, 1, []byte("group"), 8,
				testRemoveProposal(LeafIndex(5)))); !errors.Is(err, errProposalCacheEpoch) {
				t.Errorf("Store of an epoch 8 entry into a cache holding epoch 7 answered %v, want errProposalCacheEpoch", err)
			}
			if err := cache.CheckEpoch([]byte("group"), 7); err != nil {
				t.Errorf("the refused store moved the binding: %v; a Store that rebinds hands the binding to whatever arrived last", err)
			}
			if err := cache.CheckEpoch([]byte("group"), 8); !errors.Is(err, errProposalCacheEpoch) {
				t.Errorf("the cache answered for epoch 8 after storing only in epoch 7 = %v, want errProposalCacheEpoch", err)
			}
		},
	},
	"(*ProposalCache).Clear": {
		what: "empties the cache and unbinds it, which is what an epoch boundary owes it. It is the one method " +
			"classified as ending a binding, so it is the one call the gate over the epoch movers accepts",
		endsTheBinding: true,
		probe: func(t *testing.T) {
			crypto := testCrypto(t)
			cache := NewProposalCache()
			ref := testStoredRemove(t, crypto, cache, LeafIndex(1), LeafIndex(4))
			cache.Clear()
			if err := cache.CheckEpoch([]byte("anything"), 4242); err != nil {
				t.Errorf("a cleared cache still reported a binding: %v", err)
			}
			if got := len(cache.Pending()); got != 0 {
				t.Errorf("Clear left %d entries behind, so the references of the closed epoch are still nameable", got)
			}
			// and the entry is gone rather than merely unnamed by Pending, which is what
			// makes the clear a release of the closed epoch's proposals
			if _, err := NewProposalCache().Resolve(crypto, testResolveContext(), LeafIndex(0),
				[]ProposalOrRef{{Type: ProposalOrRefTypeReference, Reference: ref}}); !errors.Is(err, errProposalNotCached) {
				t.Errorf("a reference into a cleared cache answered %v, want errProposalNotCached", err)
			}
		},
	},
}

// proposalCacheBindingWritersOfThisPackage derives the class above: every method of *ProposalCache
// whose body writes a field of its own receiver.
//
// Over the RECEIVER's own object rather than over the spelling `self`, so a method that named its
// receiver something else is in the class and a local shadowing the name is not. No field list is
// involved: a method that can change what this cache holds or which epoch it belongs to is one that
// writes any of its fields, and asking which field would be an enumeration inside the derivation.
func proposalCacheBindingWritersOfThisPackage(t *testing.T) map[string]string {
	t.Helper()
	checked := typeCheckedBodiesOf(t, ".")
	found := map[string]string{}
	for _, file := range checked.files {
		for _, declaration := range file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil || function.Recv == nil {
				continue
			}
			if !strings.Contains(checked.render(function.Recv.List[0].Type), epochCacheTypeName) {
				continue
			}
			receivers := extensionTypeSelectionHandedTo(checked, function)
			name := extensionTypeSelectionDeclarationName(checked, function)
			ast.Inspect(function.Body, func(node ast.Node) bool {
				for _, target := range epochAssignedTargets(node) {
					selector := epochWriteTarget(target)
					if selector == nil {
						continue
					}
					base, isIdent := extensionTypeSelectionUnparenthesised(selector.X).(*ast.Ident)
					if !isIdent {
						continue
					}
					if object := checked.info.Uses[base]; object != nil && receivers[object] {
						if _, already := found[name]; !already {
							found[name] = checked.where(node)
						}
					}
				}
				return true
			})
		}
	}
	return found
}

// TestEveryWriterOfTheProposalCacheBindingIsClassifiedHere is rule 5 over the smaller of the two
// classes: what can change which epoch a cache belongs to.
//
// It is what makes "or rebinding" mean something in the gate below. That gate does not look for a
// call to Clear; it looks for a call to a method this table classifies as ending a binding, and a
// third method of this cache lands here before it can be accepted there.
//
// No control is needed. The derived class is compared against a table with rows in it, so a matcher
// that resolved nothing fails on the emptiness rather than reporting a clean run -- which is the
// failure mode the class over the two roots needs a control to rule out and this one does not.
func TestEveryWriterOfTheProposalCacheBindingIsClassifiedHere(t *testing.T) {
	if _, held := reflect.TypeOf(ProposalCache{}).FieldByName("byRef"); !held {
		t.Fatalf("%s no longer declares byRef, so the derivation below is written against a struct that has changed shape",
			epochCacheTypeName)
	}
	derived := proposalCacheBindingWritersOfThisPackage(t)
	classified := slices.Sorted(maps.Keys(proposalCacheBindingWriters))
	if found := slices.Sorted(maps.Keys(derived)); !slices.Equal(found, classified) {
		t.Fatalf("%v write a field of the cache they are a method of and this table classifies %v; a method with no row is one nobody decided the binding question for, and a row with no method is a classification that outlived what it classified. Locations: %v",
			found, classified, derived)
	}
	ends := []string{}
	for name, one := range proposalCacheBindingWriters {
		if one.endsTheBinding {
			ends = append(ends, name)
		}
		if one.what == "" || one.probe == nil {
			t.Errorf("%s is classified with no account of what it does or no probe of it; a row that states nothing is the enumeration this gate exists to not be", name)
		}
	}
	slices.Sort(ends)
	if !slices.Equal(ends, []string{"(*ProposalCache).Clear"}) {
		t.Errorf("the methods classified as ending the epoch binding are %v, want exactly [(*ProposalCache).Clear]; the gate over the epoch movers accepts a call to any of them, so a name added here widens that gate",
			ends)
	}
	for _, name := range slices.Sorted(maps.Keys(proposalCacheBindingWriters)) {
		one := proposalCacheBindingWriters[name]
		t.Run(name, func(t *testing.T) { one.probe(t) })
	}
}

// epochBindingEnders is the method names the gate below accepts, taken from the table above rather
// than written out: exactly the methods a human has classified as ending a binding.
func epochBindingEnders() []string {
	names := []string{}
	for name, one := range proposalCacheBindingWriters {
		if !one.endsTheBinding {
			continue
		}
		// the bare method name, which is what a call site spells
		names = append(names, name[strings.LastIndex(name, ".")+1:])
	}
	slices.Sort(names)
	return names
}

// epochMoversOfEveryRoot is the derived class over both scanned roots, with what each was found
// doing.
func epochMoversOfEveryRoot(t *testing.T) map[string]epochMoverFinding {
	t.Helper()
	found := map[string]epochMoverFinding{}
	writes := 0
	enders := epochBindingEnders()
	for _, root := range epochMoverRoots {
		checked := typeCheckedBodiesOf(t, root)
		if len(checked.paths) == 0 {
			t.Fatalf("%s holds no non test source, so this gate scanned nothing there", root)
		}
		scan := epochMoversIn(checked, epochCacheTypeName, enders)
		writes += scan.writes
		for name, finding := range scan.moving {
			if held, already := found[name]; already {
				t.Fatalf("%s moves a group between epochs at %s and at %s; this table is keyed by name, so the two would share one row and one of them would go unclassified",
					name, held.where, finding.where)
			}
			found[name] = finding
		}
	}
	if writes == 0 {
		t.Fatalf("no write through a selector was resolved across %v, so this gate would report a clean run over a package that advanced its epoch in every method it has",
			epochMoverRoots)
	}
	t.Logf("%d field writes across %v, of which %d move a group between epochs", writes, epochMoverRoots, len(found))
	return found
}

// TestEveryDeclarationThatMovesAGroupToAnotherEpochEndsTheProposalCacheBinding is rule 5 over the
// question the plan answered with two hand written Clear() calls.
//
// Two call sites is an enumeration of the epoch boundaries somebody thought of, and the thing an
// enumeration cannot do is fail on the third one. This does: a declaration that writes a group
// context, or one of the two fields the cache binds to, into storage that outlives the call either
// carries a row saying it does not move a group between epochs, or it ends the binding in the same
// body.
//
// The matcher runs on the control first, which is what says it reads anything at all -- and here
// that is load bearing rather than customary, because the real source has no member of the class
// this gate's demand is stated over. An empty report over mls and an empty report from a matcher
// that resolved nothing are the same value.
func TestEveryDeclarationThatMovesAGroupToAnotherEpochEndsTheProposalCacheBinding(t *testing.T) {
	for _, field := range epochBoundFields {
		if _, held := reflect.TypeOf(GroupContext{}).FieldByName(field); !held {
			t.Fatalf("%s declares no %s field, so the half of the rule stated over the bound fields matches nothing",
				epochGroupContextTypeName, field)
		}
	}
	// the scope, held to the one the crypto guardrails walk rather than left as an alias a
	// later edit can quietly replace with a literal. Measured on the gate next door: written
	// as a restatement and narrowed to []string{"."}, the whole of ./mls/... and ./message/...
	// stayed green, because ../message declares no group context today -- so the paragraph
	// beside epochMoverRoots would be an argument no test could lose. Narrowing
	// forbiddenScanRoots itself fails TestHkdfExtractHasOnlyTwoCallSites, which is G1 and
	// predates this file, so this borrows a scope something already pins.
	if !slices.Equal(epochMoverRoots, forbiddenScanRoots) {
		t.Fatalf("this gate walks %v and the package's guardrails walk %v; a scope of its own is a scope nothing holds, and the root it would drop first is the one that declares no group context yet",
			epochMoverRoots, forbiddenScanRoots)
	}

	control := epochMoversIn(typeCheckedBodiesOfText(t, "the epoch mover control", epochMoverControl),
		epochCacheTypeName, []string{"Clear"})
	if reported := slices.Sorted(maps.Keys(control.moving)); !slices.Equal(reported, epochMoverControlReports) {
		t.Fatalf("the rule reported %v out of the control, want %v; a rule that reports the staging of a local demands a row for every commit path in this plan, and one that misses the increment form reports a clean run over the cheapest epoch advance there is",
			reported, epochMoverControlReports)
	}
	controlEnders := []string{}
	for name, finding := range control.moving {
		if finding.ends != "" {
			controlEnders = append(controlEnders, name)
		}
	}
	slices.Sort(controlEnders)
	if !slices.Equal(controlEnders, epochMoverControlEnders) {
		t.Fatalf("the rule read %v of the control as ending the cache binding, want %v; one that accepts a Clear on any receiver accepts a merge that clears a log, and one that finds none would refuse every merge ever written",
			controlEnders, epochMoverControlEnders)
	}

	derived := epochMoversOfEveryRoot(t)
	classified := slices.Sorted(maps.Keys(groupContextEpochMovers))
	if found := slices.Sorted(maps.Keys(derived)); !slices.Equal(found, classified) {
		t.Fatalf("%v write a group context or one of its bound fields into storage that outlives the call, and this table classifies %v; a declaration with no row is an epoch boundary nobody decided the cache question for, and a row with no declaration is a classification that outlived what it classified. Locations: %v",
			found, classified, derived)
	}
	// the positive control on the real source. The decoder certainly writes an epoch into a
	// group context, so a scan that had stopped reading this package would report the same
	// clean run a complete one reports over a package with no movers.
	if _, held := derived["(*GroupContext).UnmarshalMLS"]; !held {
		t.Fatalf("the scan read %v as the declarations writing a group context epoch and the decoder is not among them, so it is not reading what it claims to",
			slices.Sorted(maps.Keys(derived)))
	}

	for _, name := range slices.Sorted(maps.Keys(groupContextEpochMovers)) {
		one := groupContextEpochMovers[name]
		finding := derived[name]
		if one.what == "" || one.probe == nil {
			t.Errorf("%s is classified with no account of what it does or no probe of it; a row that states nothing is the enumeration this gate exists to not be", name)
		}
		if one.movesAGroupBetweenEpochs && finding.ends == "" {
			t.Errorf("%s moves a group to another epoch at %s (%s) and ends no proposal cache binding; the cache it leaves behind belongs to the epoch that just closed, and every reference in it is a proposal the group has already applied",
				name, finding.where, finding.how)
		}
		if !one.movesAGroupBetweenEpochs && finding.ends != "" {
			t.Errorf("%s is classified as moving no group between epochs and ends a cache binding at %s; one of the two is wrong and a reader cannot tell which",
				name, finding.ends)
		}
		t.Logf("%s at %s writes %q: %s", name, finding.where, finding.how, one.what)
	}
}

// TestEveryClassifiedEpochMoverBehavesAsItIsClassified runs each row's probe, so a row is an
// assertion rather than a label.
//
// The gate above compares two sets of names and would pass over a table whose every account was
// wrong. What separates "constructs a group context out of a message" from "moves the live group
// to another epoch" is not visible in any name or signature: both write the same field of the same
// type. So each row states its claim as an input and an answer.
func TestEveryClassifiedEpochMoverBehavesAsItIsClassified(t *testing.T) {
	if len(groupContextEpochMovers) == 0 {
		t.Fatal("the classification table is empty, so this runs nothing")
	}
	for _, name := range slices.Sorted(maps.Keys(groupContextEpochMovers)) {
		one := groupContextEpochMovers[name]
		t.Run(name, func(t *testing.T) { one.probe(t) })
	}
}
