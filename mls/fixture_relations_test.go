// The RELATIONS the two doors decide by, and the claim the corpus owes each of them.
//
// THE GATE NEXT DOOR MEASURES EACH DIMENSION ALONE, and that is the hole this file closes. Every
// claim fixture_corpus_test.go states has the shape "no path holds one value across the corpus".
// Separation is not discrimination: a corpus in which two dimensions are separately varied and
// JOINTLY DEGENERATE -- always equal, or never equal -- is one in which a rule comparing them and a
// rule comparing one of them against a constant are the same program, and the dimension claim sees
// nothing wrong with it.
//
// BOTH SURVIVORS OF THE LAST ROUND WERE THAT SHAPE, measured rather than supposed:
//
//	ValSem203PathDecrypt's `if in.Own == in.Committer` -> `if in.Own == LeafIndex(0)`     GREEN
//	                                                   -> `if false`                      GREEN
//	checkExtensionsAreTheSetThisCommitInstalls's `if self.Extensions != nil` -> `if false` GREEN
//
// Own was 0 and Committer 1 in every default fixture, so the two were separated as dimensions and
// pinned as a relation; and every fixture that filled Extensions filled it with the very vector the
// join compares it against, so the join could be deleted outright.
//
// SO THE CLAIM IS STATED OVER THE PAIR. For every pair of paths a rule of this package compares,
// the corpus must hold a fixture where the two are EQUAL and a fixture where they DIFFER. A pair
// that is always equal cannot tell `a == b` from `a == a`; a pair that never is cannot tell it from
// `false`. Both witnesses together are what make the comparison a comparison.
//
// AND THE PAIRS ARE DERIVED, NOT LISTED, which is ledger 21 and is the whole reason this file is
// three hundred lines rather than a table. A written list of pairs understates its class the moment
// a rule grows a clause -- fourteen times on this project -- so the class is read off the AST of
// this package's own source: every equality, every inequality, and every call to a member of the
// comparator class constant_time_test.go already derives from the package's imports, wherever both
// of its operands trace back to a field of a validation input. A rule added tomorrow is in the
// class on the run after it is written, and a rule whose comparison is deleted takes its pair with
// it.
package mls

import (
	"go/ast"
	"go/token"
	"go/types"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// a path into a validation input, as the source spells it
// ---------------------------------------------------------------------------

// pStep is one hop of a path a rule walks: a field selection, a slice expansion, or a method call
// whose arguments are themselves paths into the same input.
type pStep struct {
	kind string // field, elem, call
	name string
	args []pPath
}

// pPath is one whole path from a validation input to a value a rule compares, and length says the
// comparison was over len(...) of it rather than over the value.
type pPath struct {
	steps  []pStep
	length bool
}

// String renders a path the way the source spells it, which is what the failure messages below
// name and what a reviewer greps for.
func (self pPath) String() string {
	out := ""
	for _, step := range self.steps {
		switch step.kind {
		case "field":
			if out == "" {
				out = step.name
			} else {
				out = out + "." + step.name
			}
		case "elem":
			out = out + "[]"
		case "call":
			parts := []string{}
			for _, one := range step.args {
				parts = append(parts, one.String())
			}
			if out == "" {
				out = step.name + "(" + strings.Join(parts, ", ") + ")"
			} else {
				out = out + "." + step.name + "(" + strings.Join(parts, ", ") + ")"
			}
		}
	}
	if self.length {
		return "len(" + out + ")"
	}
	return out
}

// arity is how many positions a path spreads over: one per slice expansion it walks, WHEREVER that
// expansion is written.
//
// AN ARGUMENT'S EXPANSION COUNTS AS MUCH AS THE PATH'S OWN. Tree.Leaf(List.Updates()[].Sender)
// .EncryptionKey answers one value per update, exactly as List.Updates()[].Proposal.Update
// .LeafNode.EncryptionKey does, and validateUpdateChangesTheEncryptionKey compares the two update
// by update. A count that read only the top level would call the first of those a single value and
// pair every update's key against every leaf, which is a weaker demand than the rule makes.
func (self pPath) arity() int {
	count := 0
	for _, step := range self.steps {
		if step.kind == "elem" {
			count += 1
		}
		for _, one := range step.args {
			count += one.arity()
		}
	}
	return count
}

// pathsOf answers every path a validation input reaches an expression by, or nothing where the
// expression is not rooted at one.
//
// SEVERAL PATHS AND NOT ONE, because a local may have been assigned from more than one place and a
// rule that compares such a local compares whichever of them the run took.
func pathsOf(expr ast.Expr, roots map[string]bool, locals map[string][]pPath) []pPath {
	switch node := expr.(type) {
	case *ast.Ident:
		if roots[node.Name] {
			return []pPath{{}}
		}
		return locals[node.Name]
	case *ast.ParenExpr:
		return pathsOf(node.X, roots, locals)
	case *ast.StarExpr:
		return pathsOf(node.X, roots, locals)
	case *ast.UnaryExpr:
		if node.Op == token.AND {
			return pathsOf(node.X, roots, locals)
		}
		return nil
	case *ast.SelectorExpr:
		base := pathsOf(node.X, roots, locals)
		out := []pPath{}
		for _, one := range base {
			if one.length {
				continue
			}
			out = append(out, pPath{steps: append(slices.Clone(one.steps),
				pStep{kind: "field", name: node.Sel.Name})})
		}
		return out
	case *ast.IndexExpr:
		base := pathsOf(node.X, roots, locals)
		out := []pPath{}
		for _, one := range base {
			if one.length {
				continue
			}
			out = append(out, pPath{steps: append(slices.Clone(one.steps), pStep{kind: "elem"})})
		}
		return out
	case *ast.CallExpr:
		if ident, isIdent := node.Fun.(*ast.Ident); isIdent && ident.Name == "len" && len(node.Args) == 1 {
			base := pathsOf(node.Args[0], roots, locals)
			out := []pPath{}
			for _, one := range base {
				if one.length {
					continue
				}
				out = append(out, pPath{steps: one.steps, length: true})
			}
			return out
		}
		selector, isSelector := node.Fun.(*ast.SelectorExpr)
		if !isSelector {
			return nil
		}
		base := pathsOf(selector.X, roots, locals)
		if len(base) == 0 {
			return nil
		}
		args := []pPath{}
		for _, one := range node.Args {
			resolved := pathsOf(one, roots, locals)
			if len(resolved) != 1 {
				return nil
			}
			args = append(args, resolved[0])
		}
		out := []pPath{}
		for _, one := range base {
			if one.length {
				continue
			}
			out = append(out, pPath{steps: append(slices.Clone(one.steps),
				pStep{kind: "call", name: selector.Sel.Name, args: args})})
		}
		return out
	}
	return nil
}

// localsIn answers, for one function body, every local that holds a path into a validation input.
//
// FOUR ROUNDS TO A FIXED POINT rather than one, because a rule routinely names a value through two
// locals -- adds := in.List.Adds() and then kp := &adds[i].Proposal.Add.KeyPackage -- and a single
// pass over the body resolves the second only if it happens to come after the first in AST order.
// Four is past the deepest chain this package writes and is a bound rather than a loop until
// nothing changes, so a body with a cycle in it terminates.
func localsIn(body *ast.BlockStmt, roots map[string]bool) map[string][]pPath {
	locals := map[string][]pPath{}
	remember := func(name string, found []pPath) {
		for _, one := range found {
			if !slices.ContainsFunc(locals[name], func(other pPath) bool {
				return other.String() == one.String()
			}) {
				locals[name] = append(locals[name], one)
			}
		}
	}
	for round := 0; round < 4; round += 1 {
		ast.Inspect(body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				if len(node.Rhs) == len(node.Lhs) {
					for i := range node.Lhs {
						ident, isIdent := node.Lhs[i].(*ast.Ident)
						if !isIdent || ident.Name == "_" {
							continue
						}
						remember(ident.Name, pathsOf(node.Rhs[i], roots, locals))
					}
				} else if len(node.Rhs) == 1 && len(node.Lhs) > 1 {
					// a two value call: the first result is the value, the rest are
					// the error or the presence flag beside it
					ident, isIdent := node.Lhs[0].(*ast.Ident)
					if isIdent && ident.Name != "_" {
						remember(ident.Name, pathsOf(node.Rhs[0], roots, locals))
					}
				}
			case *ast.RangeStmt:
				if node.Value == nil {
					return true
				}
				ident, isIdent := node.Value.(*ast.Ident)
				if !isIdent || ident.Name == "_" {
					return true
				}
				expanded := []pPath{}
				for _, one := range pathsOf(node.X, roots, locals) {
					if one.length {
						continue
					}
					expanded = append(expanded, pPath{steps: append(slices.Clone(one.steps),
						pStep{kind: "elem"})})
				}
				remember(ident.Name, expanded)
			}
			return true
		})
	}
	return locals
}

// ---------------------------------------------------------------------------
// the class: every pair of paths this package's rules compare
// ---------------------------------------------------------------------------

// comparisonPair is one pair of input paths some rule of this package compares, and the function
// it was read out of.
type comparisonPair struct {
	left  pPath
	right pPath
	in    string
}

// String is the pair as the failure messages name it, and it is the key the corpus is measured
// under.
func (self comparisonPair) String() string {
	return self.left.String() + "  <=>  " + self.right.String()
}

// positional is whether the two sides are compared POSITION BY POSITION rather than each against
// each.
//
// EQUAL ARITY IS WHAT SAYS SO. Extensions[].ExtensionType against
// Context.Extensions[].ExtensionType is the join's self.Extensions[i] against installed[i], and
// pairing those across the whole cross product would let a vector of two unlike extensions witness
// "these differ" without any fixture ever announcing a set the commit does not install -- the very
// degeneracy this file exists to refuse. Where the arities differ the rule really is a loop against
// a single value, and the cross product is what it does.
//
// ONE PAIR IS COMPARED MORE LOOSELY THAN THIS DEMANDS and that is deliberate: ValSem203PathDecrypt
// crosses the committer's filtered direct path against this member's, so pairing them by position
// asks the corpus for MORE than the rule reads. More is the safe direction for a corpus claim --
// every positional witness is also a cross-product witness, so nothing this admits would fail the
// rule's own pairing.
func (self comparisonPair) positional() bool {
	return self.left.arity() > 0 && self.left.arity() == self.right.arity()
}

// comparatorClassOf is every function of the packages this one imports that compares two byte
// strings, which is the class constant_time_test.go derives for guardrail 8 and is reused here
// unchanged.
//
// REUSED RATHER THAN RESTATED. A pair hidden behind bytes.Equal is a pair this file must see, and
// the set of spellings that hide one is exactly the set that gate already computes off the imports
// -- so a comparator the standard library ships tomorrow enters both classes on the same run.
func comparatorClassOf(t *testing.T, files []parsedSource) []string {
	t.Helper()
	found := []string{}
	for _, one := range importsOfSources(files) {
		scope := importedPackageOf(t, one.path).Scope()
		for _, name := range scope.Names() {
			function, isFunction := scope.Lookup(name).(*types.Func)
			if isFunction && isDataComparator(function) {
				found = append(found, one.name+"."+name)
			}
		}
	}
	slices.Sort(found)
	return slices.Compact(found)
}

// doorComparisonPairsMemo holds the derivation, which parses every source of this package and type
// checks every package it imports. Both corpora are measured against it and three tests ask for it,
// so it is computed once per run rather than once per asking.
var doorComparisonPairsMemo struct {
	once  sync.Once
	pairs map[string][]comparisonPair
	class []string
}

// doorComparisonPairs answers, for each validation input type this package declares, every pair of
// that input's paths some rule compares.
//
// ONE PASS PER INPUT TYPE rather than one pass over the functions, so that a rule taking two
// different inputs contributes its pairs to each of them under the roots that belong to it. There
// is no such rule today; deriving it this way is what stops the first one from silently landing all
// of its pairs in whichever corpus the walk happened to name.
func doorComparisonPairs(t *testing.T) (map[string][]comparisonPair, []string) {
	t.Helper()
	doorComparisonPairsMemo.once.Do(func() {
		sources := packageSources(t)
		class := comparatorClassOf(t, sources)
		pairs := map[string][]comparisonPair{}
		for _, named := range validationInputTypesInSource(t) {
			seen := map[string]bool{}
			for _, parsed := range sources {
				for _, declared := range parsed.file.Decls {
					function, isFunction := declared.(*ast.FuncDecl)
					if !isFunction || function.Body == nil {
						continue
					}
					roots := rootsOfType(parsed, function, named)
					if len(roots) == 0 {
						continue
					}
					for _, pair := range comparisonsIn(parsed, function, roots, class) {
						if seen[pair.String()] {
							continue
						}
						seen[pair.String()] = true
						pairs[named] = append(pairs[named], pair)
					}
				}
			}
			slices.SortFunc(pairs[named], func(one comparisonPair, other comparisonPair) int {
				return strings.Compare(one.String(), other.String())
			})
		}
		doorComparisonPairsMemo.pairs, doorComparisonPairsMemo.class = pairs, class
	})
	return doorComparisonPairsMemo.pairs, doorComparisonPairsMemo.class
}

// rootsOfType answers the names one function reaches a validation input of the named type by: its
// receiver where it has one of that type, and every parameter of it.
func rootsOfType(parsed parsedSource, function *ast.FuncDecl, named string) map[string]bool {
	roots := map[string]bool{}
	fields := []*ast.Field{}
	if function.Recv != nil {
		fields = append(fields, function.Recv.List...)
	}
	if function.Type.Params != nil {
		fields = append(fields, function.Type.Params.List...)
	}
	for _, field := range fields {
		if strings.TrimPrefix(parsed.render(field.Type), "*") != named {
			continue
		}
		for _, name := range field.Names {
			roots[name.Name] = true
		}
	}
	return roots
}

// comparisonsIn answers every pair of input paths one function compares.
//
// TWO SPELLINGS AND BOTH DERIVED. The equality operators are the language's own, and a call to a
// member of the comparator class is the same question written as a function --
// subtle.ConstantTimeCompare is how this package is required to compare every octet string it
// ships, so a walk that read only the operators would miss every key comparison in both doors.
func comparisonsIn(parsed parsedSource, function *ast.FuncDecl, roots map[string]bool,
	class []string) []comparisonPair {

	locals := localsIn(function.Body, roots)
	found := []comparisonPair{}
	seen := map[string]bool{}
	ast.Inspect(function.Body, func(n ast.Node) bool {
		var left, right []pPath
		switch node := n.(type) {
		case *ast.BinaryExpr:
			if node.Op != token.EQL && node.Op != token.NEQ {
				return true
			}
			left, right = pathsOf(node.X, roots, locals), pathsOf(node.Y, roots, locals)
		case *ast.CallExpr:
			if !slices.Contains(class, parsed.render(node.Fun)) || len(node.Args) < 2 {
				return true
			}
			left, right = pathsOf(node.Args[0], roots, locals), pathsOf(node.Args[1], roots, locals)
		default:
			return true
		}
		for _, one := range left {
			for _, other := range right {
				first, second := one, other
				if first.String() > second.String() {
					first, second = second, first
				}
				// a path against ITSELF is not a relation, and neither is a
				// comparison one side of which never left the input's root
				if first.String() == "" || second.String() == "" ||
					first.String() == second.String() {
					continue
				}
				pair := comparisonPair{left: first, right: second, in: function.Name.Name}
				if seen[pair.String()] {
					continue
				}
				seen[pair.String()] = true
				found = append(found, pair)
			}
		}
		return true
	})
	return found
}

// ---------------------------------------------------------------------------
// what one fixture says about one pair
// ---------------------------------------------------------------------------

// corpusPairVerdict is what one fixture witnesses about one pair: whether the pair was reachable in
// it at all, and whether the values it reached were ever equal and ever unlike.
//
// BOTH FLAGS CAN BE TRUE AT ONCE and that is not a contradiction: a pair spread over a vector is
// compared once per position, so a fixture whose first extension matches and whose second does not
// witnesses both halves by itself. A fixture that reaches neither side witnesses nothing, which is
// why reached is carried rather than inferred from the other two.
type corpusPairVerdict struct {
	reached bool
	equal   bool
	differ  bool
}

// corpusRelationVerdictsOf reduces one built fixture to what it says about every pair its door
// compares.
func corpusRelationVerdictsOf(crypto CryptoProvider, root any,
	pairs []comparisonPair) map[string]corpusPairVerdict {

	out := map[string]corpusPairVerdict{}
	at := reflect.ValueOf(root)
	for _, pair := range pairs {
		left := corpusRenderedAlong(crypto, at, pair.left)
		right := corpusRenderedAlong(crypto, at, pair.right)
		verdict := corpusPairVerdict{}
		if len(left) != 0 && len(right) != 0 {
			verdict.reached = true
			if pair.positional() {
				for i := 0; i < min(len(left), len(right)); i += 1 {
					if left[i] == right[i] {
						verdict.equal = true
					} else {
						verdict.differ = true
					}
				}
			} else {
				for _, one := range left {
					for _, other := range right {
						if one == other {
							verdict.equal = true
						} else {
							verdict.differ = true
						}
					}
				}
			}
		}
		out[pair.String()] = verdict
	}
	return out
}

// corpusRenderedAlong walks one derived path over one fixture and answers the canonical rendering
// of every value it reaches, IN THE ORDER the path reaches them -- which is what makes the
// positional pairing above mean what the rule means.
//
// IT RENDERS THROUGH corpusRenderOf, the same rendering the dimension claim is stated in, so a pair
// and a dimension never disagree about whether two values are the same value. A pointer is followed
// rather than printed, an octet string is one hex value, and a ratchet tree is its tree hash.
func corpusRenderedAlong(crypto CryptoProvider, root reflect.Value, path pPath) []string {
	out := []string{}
	for _, value := range corpusReach(root, []reflect.Value{root}, path.steps) {
		if !path.length {
			out = append(out, corpusRenderOf(crypto, value, corpusRenderBudget))
			continue
		}
		holder := corpusIndirect(value)
		if !holder.IsValid() {
			continue
		}
		switch holder.Kind() {
		case reflect.Slice, reflect.Array, reflect.Map, reflect.String:
			out = append(out, "len:"+corpusRenderOf(crypto,
				reflect.ValueOf(holder.Len()), corpusRenderBudget))
		}
	}
	return out
}

// corpusReach walks the steps of one path, spreading over every position a slice expansion opens.
//
// A STEP THAT REACHES NOTHING DROPS ITS BRANCH rather than answering a zero value, because "the
// field is absent" and "the field is the zero value" are different facts and a fixture with no
// adds must witness nothing about the adds rather than witness a comparison against an empty key.
func corpusReach(root reflect.Value, here []reflect.Value, steps []pStep) []reflect.Value {
	values := here
	for _, step := range steps {
		next := []reflect.Value{}
		for _, value := range values {
			switch step.kind {
			case "field":
				base := corpusIndirect(value)
				if !base.IsValid() || base.Kind() != reflect.Struct {
					continue
				}
				if field := base.FieldByName(step.name); field.IsValid() {
					next = append(next, field)
				}
			case "elem":
				base := corpusIndirect(value)
				if !base.IsValid() ||
					(base.Kind() != reflect.Slice && base.Kind() != reflect.Array) {
					continue
				}
				for i := 0; i < base.Len(); i += 1 {
					next = append(next, base.Index(i))
				}
			case "call":
				next = append(next, corpusCallAlong(root, value, step)...)
			}
		}
		values = next
	}
	return values
}

// corpusCallAlong makes one call of a path, once per combination of the values its arguments
// spread over, so that Tree.Leaf(List.Updates()[].Sender) answers one leaf per update IN THE
// UPDATES' OWN ORDER.
//
// A CALL THAT ANSWERS AN ERROR ANSWERS NOTHING HERE. FilteredDirectPath refuses a leaf outside its
// tree, and a fixture that names one has no value at that path rather than an empty vector at it.
func corpusCallAlong(root reflect.Value, on reflect.Value, step pStep) []reflect.Value {
	method := corpusMethodOf(on, step.name)
	if !method.IsValid() || method.Type().NumIn() != len(step.args) {
		return nil
	}
	spreads := [][]reflect.Value{{}}
	for _, arg := range step.args {
		resolved := corpusReach(root, []reflect.Value{root}, arg.steps)
		grown := [][]reflect.Value{}
		for _, prefix := range spreads {
			for _, one := range resolved {
				grown = append(grown, append(slices.Clone(prefix), one))
			}
		}
		spreads = grown
	}
	out := []reflect.Value{}
	for _, args := range spreads {
		usable := true
		for i := range args {
			if !args[i].IsValid() || !args[i].Type().AssignableTo(method.Type().In(i)) {
				usable = false
			}
		}
		if !usable {
			continue
		}
		if answered, ok := corpusCallSafely(method, args); ok {
			out = append(out, answered...)
		}
	}
	return out
}

// corpusCallSafely makes one call and answers its first result, or nothing where the call refused
// or panicked.
//
// A RECOVER RATHER THAN A PRECONDITION PER METHOD, because the methods a derived path reaches are
// whatever this package writes into a rule and a list of which of them tolerate which receiver is
// the enumeration this file exists not to be. A fixture that cannot answer a path witnesses nothing
// about it; it must not take the run down.
func corpusCallSafely(method reflect.Value, args []reflect.Value) (answered []reflect.Value,
	ok bool) {

	defer func() {
		if recover() != nil {
			answered, ok = nil, false
		}
	}()
	results := method.Call(args)
	if len(results) == 0 {
		return nil, false
	}
	for _, result := range results[1:] {
		if failure, isError := result.Interface().(error); isError && failure != nil {
			return nil, false
		}
	}
	return results[:1], true
}

// corpusMethodOf finds one method on a value however the value is held: directly, through the
// pointer or interface it sits behind, or on the address of it.
//
// A NIL POINTER ANSWERS NO METHOD. Several of this package's methods are written to tolerate a nil
// receiver and several are not, and a walk that called into the second kind would be a corpus gate
// that panics on a fixture whose optional field is empty.
func corpusMethodOf(on reflect.Value, name string) reflect.Value {
	if !on.IsValid() {
		return reflect.Value{}
	}
	if (on.Kind() == reflect.Pointer || on.Kind() == reflect.Interface) && on.IsNil() {
		return reflect.Value{}
	}
	if method := on.MethodByName(name); method.IsValid() {
		return method
	}
	if on.CanAddr() {
		if method := on.Addr().MethodByName(name); method.IsValid() {
			return method
		}
	}
	if on.Kind() == reflect.Pointer || on.Kind() == reflect.Interface {
		return corpusMethodOf(on.Elem(), name)
	}
	return reflect.Value{}
}

// corpusIndirect follows pointers and interfaces to the value underneath, and answers an invalid
// value where the chain ends in a nil.
func corpusIndirect(value reflect.Value) reflect.Value {
	for value.IsValid() && (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) {
		if value.IsNil() {
			return reflect.Value{}
		}
		value = value.Elem()
	}
	return value
}

// ---------------------------------------------------------------------------
// the derivation, held to being a derivation
// ---------------------------------------------------------------------------

// TestEveryDoorComparisonIsReadOffThisPackagesSource is what stops the class above from quietly
// becoming empty.
//
// A DERIVED CLASS THAT DERIVES NOTHING PASSES EVERY CLAIM STATED OVER IT, which is how a gate goes
// green while measuring nothing at all -- so the walk is held to finding pairs at both doors, to
// finding them through the comparator class as well as through the operators, and to reaching a
// pair whose two sides are spread over a vector.
func TestEveryDoorComparisonIsReadOffThisPackagesSource(t *testing.T) {
	pairs, class := doorComparisonPairs(t)
	if len(class) == 0 {
		t.Fatalf("the comparator class derived off this package's imports is empty, so every comparison written as a call is invisible here")
	}
	t.Logf("comparator class (%d): %v", len(class), class)
	declared := validationInputTypesInSource(t)
	if len(declared) < 2 {
		t.Fatalf("this package's source declares %v validation input types; the derivation read something other than the package",
			declared)
	}
	spelledAsACall, spelledAsALength, spreadOverAVector := false, false, false
	for _, named := range declared {
		if len(pairs[named]) == 0 {
			t.Errorf("no rule of this package was read as comparing two paths of a %s, so the relation claim over that door's corpus holds vacuously",
				named)
		}
		for _, pair := range pairs[named] {
			t.Logf("%s: %-72s in %s", named, pair, pair.in)
			// the three shapes the walk has to keep. Each is a separate piece of
			// machinery above and each would leave the walk passing if it broke: the
			// comparator class, the len() arm of pathsOf, and the arity count
			if strings.Contains(pair.String(), "EncryptionKey") {
				spelledAsACall = true
			}
			if pair.left.length || pair.right.length {
				spelledAsALength = true
			}
			if pair.positional() {
				spreadOverAVector = true
			}
		}
	}
	if !spelledAsACall {
		t.Errorf("the walk found no encryption key comparison, so the comparator class is reaching nothing and every subtle.ConstantTimeCompare of these doors is unseen here")
	}
	if !spelledAsALength {
		t.Errorf("the walk found no length comparison, so len(a) != len(b) is being read as something other than a pair")
	}
	if !spreadOverAVector {
		t.Errorf("the walk found no pair whose two sides spread over a vector, so the positional pairing above is dead code")
	}
}
