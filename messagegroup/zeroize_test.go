package messagegroup

import (
	"go/ast"
	"slices"
	"strings"
	"testing"
)

// Property 1: after the call every octet of the BACKING ARRAY is zero.
//
// Read through a second slice header over the same array rather than through the one that was
// passed, which is the whole point of the reading: a helper that reassigned its parameter to a
// fresh allocation satisfies every check made through its own header and leaves the secret
// exactly where it was. The witness is taken before the call and is never handed to it.
func TestZeroizeWritesThroughToTheBackingArray(t *testing.T) {
	for _, length := range []int{1, 2, 7, 32, 56, 1216} {
		backing := make([]byte, length)
		for i := range backing {
			backing[i] = byte(i%255) + 1
		}
		// a second header over the same array, taken now and never passed to zeroize
		witness := backing[:len(backing):len(backing)]
		before := 0
		for _, octet := range witness {
			if octet != 0 {
				before++
			}
		}
		if before != length {
			t.Fatalf("the %d octet fixture starts with %d non zero octets, so this reading would clear a helper that did nothing", length, before)
		}
		zeroize(backing)
		for i, octet := range witness {
			if octet != 0 {
				t.Fatalf("after zeroize of %d octets the backing array holds %#02x at index %d; the write did not reach the array the caller's other headers see",
					length, octet, i)
			}
		}
		// and the array the caller kept is the same array, not a replacement
		if len(backing) != len(witness) || (0 < len(backing) && &backing[0] != &witness[0]) {
			t.Fatalf("zeroize left the caller holding a different array than the one the witness reads")
		}
	}
}

// Property 1, the other half: a slice that is a WINDOW into a larger array erases its own
// octets and no others, so an erase cannot silently blank a neighbouring secret.
func TestZeroizeErasesTheSliceAndNotTheArrayAroundIt(t *testing.T) {
	backing := make([]byte, 96)
	for i := range backing {
		backing[i] = 0xEE
	}
	zeroize(backing[32:64])
	for i, octet := range backing {
		want := byte(0xEE)
		if 32 <= i && i < 64 {
			want = 0
		}
		if octet != want {
			t.Fatalf("index %d is %#02x, want %#02x; the erase reached outside the slice it was handed", i, octet, want)
		}
	}
}

// Property 2: nil and empty are no-ops and neither panics.
func TestZeroizeAcceptsNilAndEmpty(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("zeroize panicked on an empty secret with %v; a double erase on the receive path would then be a crash", recovered)
		}
	}()
	zeroize(nil)
	zeroize([]byte{})
	backing := make([]byte, 8)
	zeroize(backing[:0])
	for i, octet := range backing {
		if octet != 0 {
			t.Errorf("a zero length slice erased index %d of the array behind it", i)
		}
	}
	// erasing twice is the shape every drop site produces, and the second call must be as quiet
	// as the first
	secret := []byte{1, 2, 3}
	zeroize(secret)
	zeroize(secret)
	for i, octet := range secret {
		if octet != 0 {
			t.Errorf("index %d is %#02x after a double erase", i, octet)
		}
	}
}

// The directive this package's erasure rests on, spelled once.
const zeroizeNoinlineDirective = "//go:noinline"

// Property 3: the helper carries the pragma, and it is the package's ONLY zeroizer.
//
// The CLASS is derived and not listed: every function declaration in this package's production
// source whose body assigns the literal zero through an index expression -- which is what
// erasing a byte slice in place looks like, whatever the loop around it is written as. The
// SCOPE, answered separately per R3a, is this package's own directory, because the property is
// about what THIS package ships: connect/mls holds the same rule over its own zeroizer in its
// own suite, and connect/message can neither call this helper nor be called by it. A gate that
// walked both would be asserting one package's pragma from another package's suite, which is
// the shape that leaves a rule with no owner.
//
// Asserted off the source because no behavioural test can see it: the pragma governs what the
// compiler is allowed to prove about stores nobody reads, and a test that observed the stores
// would be observing exactly the thing the directive exists to keep observable.
func TestTheOnlyZeroizerOfThisPackageCarriesTheNoinlineDirective(t *testing.T) {
	_, sources := messagegroupProductionSources(t)
	zeroizing := []string{}
	carrying := map[string]bool{}
	for _, source := range sources {
		for _, declaration := range source.parsed.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			if !zeroizeWritesAZeroThroughAnIndex(function.Body) {
				continue
			}
			name := function.Name.Name
			zeroizing = append(zeroizing, name)
			if function.Doc == nil {
				continue
			}
			for _, line := range function.Doc.List {
				if strings.TrimSpace(line.Text) == zeroizeNoinlineDirective {
					carrying[name] = true
				}
			}
		}
	}
	slices.Sort(zeroizing)
	if len(zeroizing) == 0 {
		t.Fatal("no production function of this package writes a zero through an index, so this gate demanded the pragma of nothing")
	}
	if !slices.Equal(zeroizing, []string{"zeroize"}) {
		t.Errorf("this package's production source erases in %v; there is one zeroizer here on purpose and a second one is a second thing to get the pragma wrong in",
			zeroizing)
	}
	for _, name := range zeroizing {
		if !carrying[name] {
			t.Errorf("%s writes zeros through an index and carries no %s; without it the compiler may delete every store to a secret its caller drops",
				name, zeroizeNoinlineDirective)
		}
	}
}

// Whether a body assigns the untyped literal zero through an index expression, anywhere inside
// it, at any nesting.
//
// This is what erasing in place looks like in go, and it is read as the SHAPE rather than as
// the one loop this package happens to have written: a while form, a copy from a zero buffer
// wrapped around an index write, or a helper that erases two fields all answer yes.
func zeroizeWritesAZeroThroughAnIndex(body ast.Node) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		assignment, isAssignment := node.(*ast.AssignStmt)
		if !isAssignment {
			return true
		}
		for i, target := range assignment.Lhs {
			if _, isIndex := target.(*ast.IndexExpr); !isIndex {
				continue
			}
			if len(assignment.Rhs) <= i {
				continue
			}
			literal, isLiteral := assignment.Rhs[i].(*ast.BasicLit)
			if isLiteral && literal.Value == "0" {
				found = true
			}
		}
		return true
	})
	return found
}
