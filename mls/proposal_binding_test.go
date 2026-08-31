// Where the proposal cache's epoch binding is allowed to come from, derived off the source.
//
// THE RULE: a ProposalCache's binding -- the group and epoch it belongs to -- may only be written
// from a *GroupContext the writing declaration was HANDED. Not from a message, not from a cache
// entry, not from a constant, and not from anything the declaration read off its own receiver. A
// write that reads nothing the caller named is a violation too, because that is the unbound state
// and the unbound state is where a message used to be able to supply the epoch.
//
// It is a gate rather than a paragraph because this defect has been written twice. The first
// version took the binding from the first entry STORED and checked it against that same entry's
// own epoch, which is self referential and therefore no check at all; the fix for that gave
// Resolve a group context to observe and left the binding exactly where it was, so replaying one
// genuine proposal of a closed epoch into a freshly cleared cache bound the member to the closed
// epoch permanently -- it could then cache nothing of its live epoch and resolve no commit that
// named a proposal, and nothing released it. Both times the defect was one assignment, both times
// its right hand side read content.Content.Epoch, and both times the package was green.
//
// What separates the safe shape from the unsafe one is not visible in the target of the write --
// both spell the same field -- and it is not visible in any signature. It is where the value on
// the RIGHT came from. So that is what this reads, over the compiler's own objects rather than
// over spellings, and it walks the two ways a Go field can be written rather than the one that
// happens to be in the source today: an assignment, and a composite literal.
//
// THE SCOPE IS THIS PACKAGE AND THAT IS A COMPILER FACT rather than a choice. The binding lives
// behind unexported fields of an unexported type, so no declaration outside package mls can write
// it however it is spelled; the gate asserts the fields really are unexported instead of leaving
// that as the reason a narrow scan is enough.
//
// AND THAT RULE IS ABOUT THE WRITE, WHICH IS ONLY HALF OF WHERE THE VALUE CAME FROM. This was
// stated as more than it holds and the overstatement survived a review: proposal_list.go said "there
// is no code path in which a peer's octets decide which epoch this cache belongs to", while the gate
// demanded only that the write read a *GroupContext the writing declaration was HANDED -- a rule
// about the TYPE of the value. This package decodes a GroupContext straight off peer octets, so a
// GroupInfo marshalled with an attacker's group id and an epoch of 1<<40 and round tripped hands
// &decoded.GroupContext to NewProposalCache with both halves of that gate green. A GroupInfo is what
// a joiner is handed inside a Welcome.
//
// So the second half of this file is the CALLER'S rule, stated as a gate of its own rather than as a
// paragraph asking the next author to be careful. It derives the types this package decodes and
// refuses any call of a binding writer whose group context argument was selected out of one. Its
// class over this package's own non test source is EMPTY today -- the group lifecycle that will call
// these two is a later task -- so it is a tripwire, and it is the control below that says the
// matcher reads anything at all. That is stated here rather than left for a reader to discover.
package mls

import (
	"go/ast"
	"go/token"
	"go/types"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The three names this file's derivations are written against, checked against the compiler's
// reading below rather than trusted: a rename that left these behind would empty the class, and an
// empty class is what a package with no binding writes and a broken matcher both look like.
const (
	proposalBindingTypeName    = "proposalCacheBinding"
	proposalBindingFieldName   = "binding"
	proposalBindingContextType = "GroupContext"
)

// proposalBindingWrite is one write of a binding: where it is, how it is spelled, and what the
// value it wrote was read out of.
type proposalBindingWrite struct {
	where string
	how   string
	// the parameters and receiver of the enclosing declaration that the written VALUE reads,
	// each with whether the compiler reads it as a group context. A write is accepted when
	// this holds at least one group context and nothing else.
	reads map[string]bool
}

// fromTheCallersGroupContext is the demand, stated over one write.
//
// Both halves. "Reads a group context" alone would accept a body that read a context and a message
// and wrote the message's epoch, which is the defect with a witness standing next to it. "Reads
// nothing else" alone would accept a write of a constant, which is the unbound state.
func (self proposalBindingWrite) fromTheCallersGroupContext() bool {
	held := false
	for _, isContext := range self.reads {
		if !isContext {
			return false
		}
		held = true
	}
	return held
}

// proposalBindingTarget is one written field with the expression that supplied its value.
type proposalBindingTarget struct {
	node  ast.Node
	value ast.Expr
}

// proposalBindingTargetsOf answers the binding writes one statement or expression makes.
//
// TWO WAYS A FIELD IS WRITTEN, not one. An assignment is the shape the defect took both times, and
// a matcher that read only assignments would report a clean run over a constructor that built the
// whole binding in a composite literal -- which is exactly how NewProposalCache builds it, so the
// half this gate exists to hold would be the half it could not see. The increment form carries no
// right hand side at all and is included for the same reason the epoch mover gate includes it: it
// is the cheapest way there is to move an epoch.
func proposalBindingTargetsOf(checked checkedBodies, node ast.Node) []proposalBindingTarget {
	targets := []proposalBindingTarget{}
	writes := func(target ast.Expr) bool {
		selector := epochWriteTarget(target)
		if selector == nil {
			return false
		}
		// a field of the binding itself -- self.binding.epoch = x
		if extensionTypeSelectionNamedAs(checked.info.TypeOf(selector.X), proposalBindingTypeName) {
			return true
		}
		// or the binding a cache holds -- self.binding = x
		return selector.Sel.Name == proposalBindingFieldName &&
			extensionTypeSelectionNamedAs(checked.info.TypeOf(selector.X), epochCacheTypeName)
	}
	switch statement := node.(type) {
	case *ast.AssignStmt:
		for i, target := range statement.Lhs {
			if !writes(target) {
				continue
			}
			// a multi valued right hand side is one expression for every target, so
			// the whole of it is what the write reads
			value := statement.Rhs[0]
			if len(statement.Rhs) == len(statement.Lhs) {
				value = statement.Rhs[i]
			}
			targets = append(targets, proposalBindingTarget{node: statement, value: value})
		}
	case *ast.IncDecStmt:
		if writes(statement.X) {
			// no value at all: an increment reads the field it writes, which is not a
			// group context however the declaration was called
			targets = append(targets, proposalBindingTarget{node: statement, value: nil})
		}
	case *ast.CompositeLit:
		literalOfBinding := extensionTypeSelectionNamedAs(checked.info.TypeOf(statement), proposalBindingTypeName)
		literalOfCache := extensionTypeSelectionNamedAs(checked.info.TypeOf(statement), epochCacheTypeName)
		if !literalOfBinding && !literalOfCache {
			return targets
		}
		for _, element := range statement.Elts {
			keyed, isKeyed := element.(*ast.KeyValueExpr)
			if !isKeyed {
				continue
			}
			key, isName := keyed.Key.(*ast.Ident)
			if !isName {
				continue
			}
			if literalOfCache && key.Name != proposalBindingFieldName {
				continue
			}
			targets = append(targets, proposalBindingTarget{node: keyed, value: keyed.Value})
		}
	}
	return targets
}

// proposalBindingWritesIn is the rule: every declaration of one checked package that writes the
// cache's binding, with what each write read.
//
// The target count is carried for the reason the other derived gates of this package carry a read
// count. A matcher that stopped resolving its subject reports an EMPTY class, and an empty class is
// exactly what a package that writes no binding reports -- so "nothing writes it" and "nothing was
// read" have to be distinguishable, and only the second is a broken gate.
func proposalBindingWritesIn(checked checkedBodies) (map[string][]proposalBindingWrite, int) {
	found := map[string][]proposalBindingWrite{}
	targets := 0
	for _, file := range checked.files {
		for _, declaration := range file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			name := extensionTypeSelectionDeclarationName(checked, function)
			handed := extensionTypeSelectionHandedTo(checked, function)
			ast.Inspect(function.Body, func(node ast.Node) bool {
				for _, target := range proposalBindingTargetsOf(checked, node) {
					targets += 1
					write := proposalBindingWrite{
						where: checked.where(target.node),
						how:   checked.render(target.node),
						reads: map[string]bool{},
					}
					if target.value != nil {
						ast.Inspect(target.value, func(inner ast.Node) bool {
							name, isName := inner.(*ast.Ident)
							if !isName {
								return true
							}
							// the compiler's object and not the
							// spelling, so a local shadowing a
							// parameter is a different thing
							object := checked.info.Uses[name]
							if object == nil || !handed[object] {
								return true
							}
							write.reads[name.Name] = extensionTypeSelectionNamedAs(
								object.Type(), proposalBindingContextType)
							return true
						})
					}
					found[name] = append(found[name], write)
				}
				return true
			})
		}
	}
	return found, targets
}

// proposalBindingControl is a package the matcher has never seen, written so that every half of
// the rule has something to report and something to walk past.
//
// It carries the two defect shapes the real source must never hold again -- the binding built out
// of a message, and one field of it moved out of a message while a group context sits unread in
// the signature -- because those are what this gate demands, and the real source will not hold one
// unless somebody writes it. A control rather than a second opinion about the real source: a
// matcher that resolved nothing reports a clean run over mls too, and the only way to tell that
// apart from a package that obeys the rule is to run it on source known to hold both answers.
const proposalBindingControl = `package control

type GroupContext struct {
	GroupId []byte
	Epoch   uint64
}

// what a message carries, and it carries exactly the same two fields, which is the whole reason
// this rule is about where a value came from rather than about what it looks like
type Content struct {
	GroupId []byte
	Epoch   uint64
}

type proposalCacheBinding struct {
	groupId []byte
	epoch   uint64
}

type ProposalCache struct {
	byRef   map[string]int
	binding *proposalCacheBinding
}

// the accepted shape, built in a composite literal
func NewFromTheContext(groupContext *GroupContext) *ProposalCache {
	return &ProposalCache{
		byRef:   map[string]int{},
		binding: &proposalCacheBinding{groupId: groupContext.GroupId, epoch: groupContext.Epoch},
	}
}

// the accepted shape, written as an assignment
func (self *ProposalCache) rebindFromTheContext(groupContext *GroupContext) {
	self.binding = &proposalCacheBinding{groupId: groupContext.GroupId, epoch: groupContext.Epoch}
}

// the defect: the binding taken from what arrived
func (self *ProposalCache) bindFromTheMessage(content *Content) {
	self.binding = &proposalCacheBinding{groupId: content.GroupId, epoch: content.Epoch}
}

// the defect with a witness beside it: a group context in the signature, unread, and the epoch
// still taken from the message
func (self *ProposalCache) moveTheEpochFromTheMessage(groupContext *GroupContext, content *Content) {
	self.binding.epoch = content.Epoch
}

// the release that leaves the cache bound to nothing, which is the state a replay used to fill
func (self *ProposalCache) release() {
	self.binding = nil
}

// the cheapest move there is, and it is not an assignment
func (self *ProposalCache) bumpTheBoundEpoch() {
	self.binding.epoch++
}

// a write of what the cache HOLDS, which is not a write of what it belongs to
func (self *ProposalCache) store(key string, at int) {
	self.byRef[key] = at
}

// and a read of the binding, which is not a write of it
func (self *ProposalCache) boundEpoch() uint64 {
	return self.binding.epoch
}
`

// What the matcher must report out of the control, and by omission what it must walk past.
var proposalBindingControlWriters = []string{
	"(*ProposalCache).bindFromTheMessage",
	"(*ProposalCache).bumpTheBoundEpoch",
	"(*ProposalCache).moveTheEpochFromTheMessage",
	"(*ProposalCache).rebindFromTheContext",
	"(*ProposalCache).release",
	"NewFromTheContext",
}

// And which of them it must refuse. rebindFromTheContext and NewFromTheContext are the two shapes
// the real source is written in, so a rule that refused either would refuse the fix as well as the
// defect.
var proposalBindingControlRefused = []string{
	"(*ProposalCache).bindFromTheMessage",
	"(*ProposalCache).bumpTheBoundEpoch",
	"(*ProposalCache).moveTheEpochFromTheMessage",
	"(*ProposalCache).release",
}

// The declarations of this package that write the binding.
//
// Two, and the gate below holds the derived class EQUAL to this in both directions, so a third
// write fails here until somebody says what it is. That is the point: the defect was a write added
// to a method that had every reason to be writing something, and a class that only checked the
// writes it already knew about would not have seen it.
var proposalCacheBindingWriteSites = map[string]string{
	"NewProposalCache": "builds the binding out of the context the caller is in. It is a composite literal " +
		"rather than a field assignment so that the constructor is not a second spelling of Rebind's write",
	"(*ProposalCache).Rebind": "moves the binding to the context the caller names, which is what an epoch " +
		"boundary owes the cache. It is the only write after construction, and it cannot release without " +
		"rebinding -- a cache bound to nothing is where taking the epoch from a message used to be possible",
}

// TestEveryWriteOfTheCacheBindingReadsTheCallersGroupContext is the root cause stated as a gate.
//
// Not "Store does not write the binding" -- that is a fact about one method, and the next method
// is the one that will. The class is every write of the binding there is, and the demand on each
// is about where its value came from.
func TestEveryWriteOfTheCacheBindingReadsTheCallersGroupContext(t *testing.T) {
	// the compiler enforced half of the scope: unexported fields of an unexported type cannot
	// be written from another package however the write is spelled, which is why scanning this
	// package alone is enough rather than merely convenient
	cache, held := reflect.TypeOf(ProposalCache{}).FieldByName(proposalBindingFieldName)
	if !held {
		t.Fatalf("%s no longer declares a %s field, so this gate is written against a struct that has changed shape",
			epochCacheTypeName, proposalBindingFieldName)
	}
	if cache.IsExported() {
		t.Fatalf("%s.%s is exported, so a declaration in any package can write it and a scan of this one is not the class",
			epochCacheTypeName, proposalBindingFieldName)
	}
	binding := reflect.TypeOf(proposalCacheBinding{})
	if binding.NumField() == 0 {
		t.Fatalf("%s declares no field, so there is no binding for this gate to be about", proposalBindingTypeName)
	}
	for i := 0; i < binding.NumField(); i += 1 {
		if binding.Field(i).IsExported() {
			t.Fatalf("%s.%s is exported, so the binding can be written from outside this package",
				proposalBindingTypeName, binding.Field(i).Name)
		}
	}

	// the control first, which is what says the matcher reads anything at all
	control := typeCheckedBodiesOfText(t, "the proposal binding control", proposalBindingControl)
	written, targets := proposalBindingWritesIn(control)
	if targets == 0 {
		t.Fatal("the matcher resolved no binding write in the control, so it would report a clean run over any package at all")
	}
	if reported := slices.Sorted(maps.Keys(written)); !slices.Equal(reported, proposalBindingControlWriters) {
		t.Fatalf("the rule read %v out of the control as writing the binding, want %v; one that reads only assignments walks past the constructor, and one that reads only the cache's own field walks past a write of the binding's",
			reported, proposalBindingControlWriters)
	}
	refused := []string{}
	for name, writes := range written {
		for _, write := range writes {
			if !write.fromTheCallersGroupContext() {
				refused = append(refused, name)
				break
			}
		}
	}
	slices.Sort(refused)
	if !slices.Equal(refused, proposalBindingControlRefused) {
		t.Fatalf("the rule refused %v of the control, want %v; one that accepts a value read off a message accepts the defect, and one that refuses a value read off the caller's context refuses the fix",
			refused, proposalBindingControlRefused)
	}

	// and then the real source
	checked := typeCheckedBodiesOf(t, ".")
	if len(checked.paths) == 0 {
		t.Fatal("this package holds no non test source, so the gate scanned nothing")
	}
	found, realTargets := proposalBindingWritesIn(checked)
	if realTargets == 0 {
		t.Fatalf("no write of the cache binding was resolved in this package, and %s certainly holds several, so this gate is not reading what it claims to",
			epochCacheTypeName)
	}
	classified := slices.Sorted(maps.Keys(proposalCacheBindingWriteSites))
	if names := slices.Sorted(maps.Keys(found)); !slices.Equal(names, classified) {
		t.Fatalf("%v write the cache binding and this table names %v; a write with no row is one nobody said where the value comes from, and a row with no write is a claim that outlived what it described",
			names, classified)
	}
	for _, name := range slices.Sorted(maps.Keys(found)) {
		for _, write := range found[name] {
			if write.fromTheCallersGroupContext() {
				t.Logf("%s at %s writes %q out of %v", name, write.where, write.how,
					slices.Sorted(maps.Keys(write.reads)))
				continue
			}
			t.Errorf("%s at %s writes the cache binding as %q, out of %v; a binding is only worth the authority of the value it was taken from, and the only value with that authority is a *%s the caller handed in. Reading it off a message is the defect this gate exists for, and reading it off nothing leaves the cache unbound, which is the state a message could then fill",
				name, write.where, write.how, slices.Sorted(maps.Keys(write.reads)),
				proposalBindingContextType)
		}
	}
}

// TestNoDeclarationOfThisPackageReadsAStoredEpochIntoTheCacheBinding is the same rule read from the
// other end, and it is here because the gate above can only refuse what it can attribute.
//
// The write it refuses is one it found. A body that copied a message's epoch into a local first and
// wrote the local would read no parameter at all at the write itself, so the gate above would call
// it an unbound write -- which it would still refuse, but for the wrong reason and with a report a
// reader could not act on. This states the fact the fix actually rests on in the plainest form
// there is: the type that owns the binding names no message type at all in any of the declarations
// that write it.
func TestNoDeclarationOfThisPackageReadsAStoredEpochIntoTheCacheBinding(t *testing.T) {
	checked := typeCheckedBodiesOf(t, ".")
	found, _ := proposalBindingWritesIn(checked)
	if len(found) == 0 {
		t.Fatal("no declaration writes the cache binding, so this reads nothing")
	}
	for _, file := range checked.files {
		for _, declaration := range file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			name := extensionTypeSelectionDeclarationName(checked, function)
			if _, writes := found[name]; !writes {
				continue
			}
			// every parameter of a declaration that writes the binding, by the
			// compiler's reading of its type. A body cannot read what it was not handed,
			// so a signature holding nothing but a group context cannot take an epoch off
			// a message however it is written inside.
			for handed := range extensionTypeSelectionHandedTo(checked, function) {
				rendered := handed.Type().String()
				if strings.Contains(rendered, proposalBindingContextType) ||
					strings.Contains(rendered, epochCacheTypeName) {
					continue
				}
				t.Errorf("%s writes the cache binding and is handed %s of type %s; the binding is only as good as the authority of the values in scope where it is written, and a message in that scope is one local away from being the epoch this cache believes it is in",
					name, handed.Name(), rendered)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// where the CALLER got the context, which is the half the gate above does not hold
// ---------------------------------------------------------------------------

// The method that makes a type one this package decodes. It is the one codec convention this package
// pins -- every wire type declares it and asserts syntax.Codec beside itself -- so the class is read
// off the compiler's method sets rather than off a list of type names that would go stale the first
// time a structure was added.
const proposalBindingDecoderMethod = "UnmarshalMLS"

// proposalBindingWireTypesIn is the class: every named type of one checked package that declares the
// decoder method, by the bare name the compiler reads its receiver as.
//
// A type that can be decoded is a type whose fields can be chosen by whoever wrote the octets. That
// is the whole of the property -- a verified GroupInfo's fields were chosen by the same octets, and
// the verification is somewhere else -- so this does not try to tell a checked one from an unchecked
// one and refuses both. See the test for why that is the honest rule and not a lazy one.
func proposalBindingWireTypesIn(checked checkedBodies) map[string]bool {
	wire := map[string]bool{}
	for _, file := range checked.files {
		for _, declaration := range file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Recv == nil || len(function.Recv.List) != 1 {
				continue
			}
			if function.Name.Name != proposalBindingDecoderMethod {
				continue
			}
			if name := proposalBindingTypeNameOf(checked.info.TypeOf(function.Recv.List[0].Type)); name != "" {
				wire[name] = true
			}
		}
	}
	return wire
}

// proposalBindingTypeNameOf names a type the way this file's tables do: the bare name, through any
// number of pointers, and empty for anything that is not a named type.
func proposalBindingTypeNameOf(found types.Type) string {
	for {
		pointer, isPointer := found.(*types.Pointer)
		if !isPointer {
			break
		}
		found = pointer.Elem()
	}
	named, isNamed := found.(*types.Named)
	if !isNamed || named.Obj() == nil {
		return ""
	}
	return named.Obj().Name()
}

// proposalBindingWriterObjects is the class the gate above already derived, as the compiler's own
// function objects, so a CALL can be matched to a writer by identity rather than by spelling.
//
// Derived from proposalBindingWritesIn and not from a second list, which is the whole reason this
// gate stays joined to that one: a third writer landing tomorrow is a third call site to judge
// without anybody extending anything, and a writer that stopped writing drops out of both at once.
func proposalBindingWriterObjects(checked checkedBodies) map[types.Object]string {
	written, _ := proposalBindingWritesIn(checked)
	writers := map[types.Object]string{}
	for _, file := range checked.files {
		for _, declaration := range file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			name := extensionTypeSelectionDeclarationName(checked, function)
			if _, writes := written[name]; !writes {
				continue
			}
			if object := checked.info.Defs[function.Name]; object != nil {
				writers[object] = name
			}
		}
	}
	return writers
}

// proposalBindingCalleeObject answers the declaration one call expression reaches, by the compiler's
// object rather than by the name at the call, so a local shadowing a package function is not
// mistaken for it.
func proposalBindingCalleeObject(checked checkedBodies, call *ast.CallExpr) types.Object {
	switch fun := extensionTypeSelectionUnparenthesised(call.Fun).(type) {
	case *ast.Ident:
		return checked.info.Uses[fun]
	case *ast.SelectorExpr:
		return checked.info.Uses[fun.Sel]
	}
	return nil
}

// proposalBindingArgumentRoot answers the value one argument was ultimately cut from, and whether a
// FIELD SELECTION was crossed on the way.
//
// The second half is what separates the two accepted shapes from the refused one, and neither is
// visible in the argument's own type -- every one of them is a *GroupContext. `groupContext` crosses
// no selection and is the caller's own choice; `&self.context` crosses one and lands on a group;
// `&decoded.GroupContext` crosses one and lands on a structure somebody else's octets filled in.
//
// A call is followed through its FUN, because a method call answers a value of whatever it was
// called on: decoded.GroupContext.Clone() is the decoded context with a copy in front of it, and a
// walk that stopped at the call would report the one laundering shape this package already has a
// method for.
func proposalBindingArgumentRoot(checked checkedBodies, expr ast.Expr) (types.Object, bool) {
	selected := false
	for {
		expr = extensionTypeSelectionUnparenthesised(expr)
		switch node := expr.(type) {
		case *ast.UnaryExpr:
			if node.Op != token.AND {
				return nil, selected
			}
			expr = node.X
		case *ast.StarExpr:
			expr = node.X
		case *ast.IndexExpr:
			expr = node.X
		case *ast.CallExpr:
			expr = node.Fun
		case *ast.SelectorExpr:
			selected = true
			expr = node.X
		case *ast.Ident:
			return checked.info.Uses[node], selected
		default:
			return nil, selected
		}
	}
}

// proposalBindingProvenance is one group context argument handed to a binding writer: where it is,
// how it is written, and what this rule reads its provenance as.
type proposalBindingProvenance struct {
	where    string
	how      string
	caller   string
	writer   string
	accepted bool
	why      string
}

// proposalBindingVerdict is the rule, over one argument.
//
// Three answers and not two, because the three have three remedies. A selection out of a wire type
// is the defect and the remedy is to copy the verified context into the group's own state first. A
// value the declaration was handed crosses no selection and is accepted, because whose context it is
// is then that caller's question and the buck passes up the stack rather than stopping here. And an
// argument this rule cannot attribute -- a context assembled in the body, or the result of a
// function -- is refused rather than assumed, because a context built out of whatever is in scope is
// exactly the laundering shape and there is nothing at the call that tells it from a legitimate one.
func proposalBindingVerdict(wire map[string]bool, root types.Object, selected bool,
	handed map[types.Object]bool) (bool, string) {

	if root == nil {
		return false, "assembled in the body, so there is no value to attribute"
	}
	if selected {
		name := proposalBindingTypeNameOf(root.Type())
		if wire[name] {
			return false, "selected out of a " + name + ", which is a type this package decodes off the wire"
		}
		return true, "selected out of a " + name + ", which this package does not decode"
	}
	if handed[root] {
		return true, "the declaration's own parameter or receiver"
	}
	return false, "a value this declaration chose for itself rather than one it was handed"
}

// proposalBindingProvenanceIn is the scan: every group context argument of every call of a binding
// writer in one checked package, with its verdict, and how many arguments were judged at all.
//
// The judged count is carried for the reason every derived gate of this package carries one. A
// matcher that stopped resolving its subject reports NO findings, and no findings is exactly what a
// package with no such call reports -- so "nothing calls a writer" and "nothing was read" have to be
// distinguishable, and only the second is a broken gate.
func proposalBindingProvenanceIn(checked checkedBodies) ([]proposalBindingProvenance, int) {
	wire := proposalBindingWireTypesIn(checked)
	writers := proposalBindingWriterObjects(checked)
	found := []proposalBindingProvenance{}
	judged := 0
	for _, file := range checked.files {
		for _, declaration := range file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			caller := extensionTypeSelectionDeclarationName(checked, function)
			handed := extensionTypeSelectionHandedTo(checked, function)
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, isCall := node.(*ast.CallExpr)
				if !isCall {
					return true
				}
				writer, writes := writers[proposalBindingCalleeObject(checked, call)]
				if !writes {
					return true
				}
				for _, argument := range call.Args {
					if !extensionTypeSelectionNamedAs(checked.info.TypeOf(argument), proposalBindingContextType) {
						continue
					}
					judged += 1
					root, selected := proposalBindingArgumentRoot(checked, argument)
					accepted, why := proposalBindingVerdict(wire, root, selected, handed)
					found = append(found, proposalBindingProvenance{
						where:    checked.where(argument),
						how:      checked.render(argument),
						caller:   caller,
						writer:   writer,
						accepted: accepted,
						why:      why,
					})
				}
				return true
			})
		}
	}
	return found, judged
}

// proposalBindingProvenanceControl is a package the matcher has never seen, carrying every shape the
// rule has an answer for -- including the reviewer's own demonstration, which the real source will
// not hold unless somebody writes it.
//
// The decoders take no reader. What makes a type a wire type to this matcher is that it declares the
// method the one codec convention names, and a control that reproduced mls/syntax to say so would be
// testing the importer rather than the rule.
const proposalBindingProvenanceControl = `package control

type GroupContext struct {
	GroupId []byte
	Epoch   uint64
}

func (self *GroupContext) UnmarshalMLS() error { return nil }

func (self *GroupContext) Clone() *GroupContext { return self }

// what a joiner is handed inside a Welcome: a decoded structure with a group context inside it
type GroupInfo struct {
	GroupContext GroupContext
	Signature    []byte
}

func (self *GroupInfo) UnmarshalMLS() error { return nil }

// the group's own state, which is not decoded off anything
type Group struct {
	context GroupContext
}

type proposalCacheBinding struct {
	groupId []byte
	epoch   uint64
}

type ProposalCache struct {
	binding *proposalCacheBinding
}

// the two writers, in the two shapes the real ones take
func NewFromTheContext(groupContext *GroupContext) *ProposalCache {
	return &ProposalCache{
		binding: &proposalCacheBinding{groupId: groupContext.GroupId, epoch: groupContext.Epoch},
	}
}

func (self *ProposalCache) rebindFromTheContext(groupContext *GroupContext) {
	self.binding = &proposalCacheBinding{groupId: groupContext.GroupId, epoch: groupContext.Epoch}
}

// accepted: the caller was handed the context and crosses no selection, so whose context it is is
// its own caller's question
func bindFromTheContextItWasHanded(groupContext *GroupContext) *ProposalCache {
	return NewFromTheContext(groupContext)
}

// accepted: selected out of a group, which is not a type this package decodes
func (self *Group) bindFromItsOwnState() *ProposalCache {
	return NewFromTheContext(&self.context)
}

// accepted through the method arm as well, so a rule that read only plain calls is not enough
func rebindFromTheContextItWasHanded(cache *ProposalCache, groupContext *GroupContext) {
	cache.rebindFromTheContext(groupContext)
}

// the defect, and it is the reviewer's demonstration verbatim: the GroupInfo is a parameter, so the
// declaration WAS handed it, and the write inside NewFromTheContext still reads a group context
// parameter. Both halves of the write rule hold and the epoch is the attacker's.
func bindFromADecodedGroupInfo(info *GroupInfo) *ProposalCache {
	return NewFromTheContext(&info.GroupContext)
}

// the same defect through the method arm
func rebindFromADecodedGroupInfo(cache *ProposalCache, info *GroupInfo) {
	cache.rebindFromTheContext(&info.GroupContext)
}

// the defect with the decode in the body rather than in the signature
func bindFromAGroupInfoDecodedHere() *ProposalCache {
	decoded := GroupInfo{}
	decoded.UnmarshalMLS()
	return NewFromTheContext(&decoded.GroupContext)
}

// a copy of a decoded context is still a decoded context, and Clone is the method that makes this
// shape one line away
func bindFromACloneOfADecodedContext(info *GroupInfo) *ProposalCache {
	return NewFromTheContext(info.GroupContext.Clone())
}

// a context decoded straight into a local, which crosses no selection and was handed to nobody
func bindFromALocalItDecodedItself() *ProposalCache {
	local := GroupContext{}
	local.UnmarshalMLS()
	return NewFromTheContext(&local)
}

// a context assembled out of whatever was in scope, which is the laundering shape and is refused
// because nothing at the call tells it from a legitimate one
func bindFromAContextAssembledHere(info *GroupInfo) *ProposalCache {
	return NewFromTheContext(&GroupContext{GroupId: info.GroupContext.GroupId, Epoch: info.GroupContext.Epoch})
}

// and a read of a decoded context that binds nothing, which is not a call of a writer at all
func readsADecodedEpochWithoutBinding(info *GroupInfo) uint64 {
	return info.GroupContext.Epoch
}
`

// What the matcher must accept out of the control, keyed by the declaration the call is in.
var proposalBindingProvenanceControlAccepted = []string{
	"(*Group).bindFromItsOwnState",
	"bindFromTheContextItWasHanded",
	"rebindFromTheContextItWasHanded",
}

// And what it must refuse. bindFromADecodedGroupInfo is the reviewer's demonstration; a rule that
// accepted it is the rule this file already had.
var proposalBindingProvenanceControlRefused = []string{
	"bindFromACloneOfADecodedContext",
	"bindFromAContextAssembledHere",
	"bindFromADecodedGroupInfo",
	"bindFromAGroupInfoDecodedHere",
	"bindFromALocalItDecodedItself",
	"rebindFromADecodedGroupInfo",
}

// TestNoDeclarationOfThisPackageBindsTheCacheToAGroupContextItSelectedOutOfAWireType is the caller's
// half of the binding rule, and it is the half proposal_list.go used to claim in prose.
//
// WHAT IT REFUSES AND WHY THAT IS THE HONEST LINE. It refuses a VERIFIED GroupInfo's context as well
// as an unverified one. That is not the rule being lazy: the two are the same expression at the
// call, so a rule that let one through could not be checked by anything, and "the caller verified it
// first" is exactly the kind of discipline this file exists because nobody kept. What a Welcome path
// does instead is copy the context it verified into the group's own state -- Clone is there for it
// -- and bind from that, which crosses a selection out of a Group rather than out of a GroupInfo and
// is accepted. The difference on the wire is nothing; the difference in the source is that one of
// them is a value this client vouches for.
//
// ITS CLASS OVER THE REAL SOURCE IS EMPTY TODAY and that is said rather than hidden. Nothing in this
// package's non test source calls either writer -- the group lifecycle that will is a later task --
// so the control is what says the matcher resolves anything, and the value of the gate is that it
// fails on the commit that wires the Welcome path the obvious way. A gate written after that commit
// would be a gate written after the defect.
func TestNoDeclarationOfThisPackageBindsTheCacheToAGroupContextItSelectedOutOfAWireType(t *testing.T) {
	control := typeCheckedBodiesOfText(t, "the proposal binding provenance control",
		proposalBindingProvenanceControl)
	wire := proposalBindingWireTypesIn(control)
	for _, name := range []string{"GroupContext", "GroupInfo"} {
		if !wire[name] {
			t.Fatalf("the matcher did not read %s as a wire type of the control, so the class it refuses out of is empty and every call would be accepted",
				name)
		}
	}
	if wire["Group"] {
		t.Fatal("the matcher read Group as a wire type of the control; a rule that treats the group's own state as decoded refuses the fix as well as the defect")
	}
	found, judged := proposalBindingProvenanceIn(control)
	if judged == 0 {
		t.Fatal("the matcher judged no group context argument in the control, so it would report a clean run over any package at all")
	}
	accepted, refused := []string{}, []string{}
	for _, provenance := range found {
		if provenance.accepted {
			accepted = append(accepted, provenance.caller)
			continue
		}
		refused = append(refused, provenance.caller)
	}
	slices.Sort(accepted)
	slices.Sort(refused)
	if !slices.Equal(accepted, proposalBindingProvenanceControlAccepted) {
		t.Fatalf("the rule accepted %v of the control, want %v; one that refuses a context the declaration was handed refuses the fix, and one that refuses a selection out of the group's own state refuses the only shape a lifecycle has",
			accepted, proposalBindingProvenanceControlAccepted)
	}
	if !slices.Equal(refused, proposalBindingProvenanceControlRefused) {
		t.Fatalf("the rule refused %v of the control, want %v; bindFromADecodedGroupInfo is the reviewer's own demonstration and a rule that accepts it is the rule this file already had",
			refused, proposalBindingProvenanceControlRefused)
	}

	// and then the real source. The fact that makes this gate necessary is asserted on it, so a
	// package that stopped decoding a group context off the wire would say so rather than leaving
	// a rule nobody could explain.
	checked := typeCheckedBodiesOf(t, ".")
	realWire := proposalBindingWireTypesIn(checked)
	if len(realWire) == 0 {
		t.Fatal("this package was read as decoding nothing at all, so the gate is not reading what it claims to")
	}
	if !realWire[proposalBindingContextType] {
		t.Fatalf("%s is not read as a wire type of this package; it is what (*GroupInfo).UnmarshalMLS decodes off a reader, and if that has stopped being true this whole gate needs rewriting rather than relaxing",
			proposalBindingContextType)
	}
	carrier, held := reflect.TypeOf(GroupInfo{}).FieldByName(proposalBindingContextType)
	if !held || carrier.Type != reflect.TypeOf(GroupContext{}) {
		t.Fatalf("GroupInfo no longer carries a %s field, so the attack this gate is about has changed shape and the gate should be rewritten against the new one",
			proposalBindingContextType)
	}
	if !realWire["GroupInfo"] {
		t.Fatal("GroupInfo is not read as a wire type of this package, so the one structure a joiner is handed inside a Welcome is outside the class this gate refuses")
	}
	provenance, realJudged := proposalBindingProvenanceIn(checked)
	for _, one := range provenance {
		if one.accepted {
			t.Logf("%s at %s passes %q to %s: %s", one.caller, one.where, one.how, one.writer, one.why)
			continue
		}
		t.Errorf("%s at %s binds the proposal cache through %s to %q, which is %s; a binding is worth the authority of the value it was taken from, and a %s this package decoded is a structure whoever wrote the octets filled in -- an attacker choosing the group id and the epoch this cache then believes it is in. Copy a context you have VERIFIED into this client's own state and bind from that",
			one.caller, one.where, one.writer, one.how, one.why, proposalBindingContextType)
	}
	t.Logf("%d group context arguments judged over %d call sites of a binding writer in this package's non test source",
		realJudged, len(provenance))
}

