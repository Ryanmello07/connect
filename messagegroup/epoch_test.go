// Task 13's properties: the pq_secret sampler, and the provisional epoch state G10 destroys.
//
// SIX PROPERTIES AND ONE OF THEM IS ONLY HALF HERE, which is said first because the missing half is
// a scheduling fact and not an omission. Property 4 is G10's "there is no path that reads it
// afterwards", and it has two halves: the value refuses every accessor after its destructor has run,
// which is behavioural and lands here; and every in package READER of the value checks the destroyed
// flag first, which is a derived class and lands in task 15 property 6. It cannot land here because
// at this commit that class is EMPTY -- the readers are task 15's fan out and task 21's retry loop
// and neither exists -- and this tree's house style fatals on an empty derived class rather than
// reporting clean over one (aad_test.go:1293, writeauth_test.go:2451). Task 15 property 6 names this
// property back so the pair is not dropped between the two commits.
//
// AND ONE PROPERTY IS DECIDABLE ONLY IN HALF, which is worth stating in the same breath. Property 2
// is "the only producer of a pq_secret is the sampler, and the sampler's only input is an
// io.Reader". Half A -- the signature -- an AST scan decides. Half B -- the body reaches the reader
// it was handed and reaches no derivation -- an AST scan decides. What NO scan in this tree decides
// is "is the value this function returns a pq_secret", because Go reflection sees neither parameter
// names nor the meaning of returned bytes, and two earlier drafts of this property tried to write
// that question as a derived class and produced classes that convicted five functions this plan
// itself specifies. Both drafts are recorded in the plan; the identity of the value stays with the
// author and with section 5's text, and open item M1-17 carries the specification half.
package messagegroup

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The two directories the rules below run over: this package's own production source, and the
// control fixture the same rules are proved against.
const (
	epochOwnScanDir     = "."
	epochControlScanDir = "testdata/epoch"
)

// The root the two walks start from. It is checked for existence before either walk runs, because a
// rule about the call graph of a function that has been renamed is a rule about nothing and it
// reports clean.
const epochSamplerName = "NewPqSecret"

// The type expression an entropy source is written as, which is entropy_test.go's spelling and is
// repeated rather than shared so that a change to either file's reading is visible as a change.
const epochEntropyExpression = "io.Reader"

// ---------------------------------------------------------------------------
// the scan the walks are built on
// ---------------------------------------------------------------------------

// One directory's non test Go source, indexed by declared function name.
type epochScan struct {
	dir       string
	fileSet   *token.FileSet
	fileCount int
	// every function declaration of the directory, keyed by its own name. Methods are keyed by
	// the method name, which is what an edge in the syntax tree names.
	decls map[string][]*ast.FuncDecl
	// every package level name the directory declares, of any kind, which is what the
	// forbidden-file half resolves an edge against.
	names map[string]string
}

// epochScanSources reads one directory's non test Go source.
//
// A directory that yields no file and a directory that yields no function are both FATAL rather
// than empty, because either one clears every rule written over it while reporting a clean run.
func epochScanSources(t *testing.T, dir string) epochScan {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	scan := epochScan{
		dir:     dir,
		fileSet: token.NewFileSet(),
		decls:   map[string][]*ast.FuncDecl{},
		names:   map[string]string{},
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.ToSlash(filepath.Join(dir, name))
		parsed, err := parser.ParseFile(scan.fileSet, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		scan.fileCount += 1
		for _, declaration := range parsed.Decls {
			switch typed := declaration.(type) {
			case *ast.FuncDecl:
				if typed.Body == nil {
					continue
				}
				scan.decls[typed.Name.Name] = append(scan.decls[typed.Name.Name], typed)
				scan.names[typed.Name.Name] = path
			case *ast.GenDecl:
				for _, spec := range typed.Specs {
					switch value := spec.(type) {
					case *ast.ValueSpec:
						for _, ident := range value.Names {
							scan.names[ident.Name] = path
						}
					case *ast.TypeSpec:
						scan.names[value.Name.Name] = path
					}
				}
			}
		}
	}
	if scan.fileCount == 0 {
		t.Fatalf("%s holds no non test go file, so every rule below cleared its subject having read nothing", dir)
	}
	if len(scan.decls) == 0 {
		t.Fatalf("%s holds no function at all, so every walk over it is vacuous", dir)
	}
	return scan
}

// The text of one type expression, so a parameter list is compared as source rather than as a tree.
func epochRendered(scan epochScan, expr ast.Expr) string {
	text := &strings.Builder{}
	if err := printer.Fprint(text, scan.fileSet, expr); err != nil {
		return ""
	}
	return text.String()
}

// Every identifier one function names, across all of its declarations.
//
// Identifiers rather than call expressions, for writeauth_test.go's reason: a function value
// assigned to a variable, passed as an argument or stored in a table reaches its target just as
// well as a call does, and the selector of a method call is an identifier too.
func epochIdentsIn(decls []*ast.FuncDecl) []string {
	named := map[string]bool{}
	for _, decl := range decls {
		ast.Inspect(decl.Body, func(node ast.Node) bool {
			if ident, isIdent := node.(*ast.Ident); isIdent {
				named[ident.Name] = true
			}
			return true
		})
	}
	return slices.Sorted(maps.Keys(named))
}

// The functions of this directory one function names, which are the edges of the call graph.
func epochEdgesOf(scan epochScan, name string) []string {
	edges := []string{}
	for _, ident := range epochIdentsIn(scan.decls[name]) {
		if ident == name {
			continue
		}
		if _, declared := scan.decls[ident]; declared {
			edges = append(edges, ident)
		}
	}
	return edges
}

// Everything reachable from one function, transitively, including itself.
func epochReachableFrom(t *testing.T, scan epochScan, root string) map[string]bool {
	t.Helper()
	if _, declared := scan.decls[root]; !declared {
		t.Fatalf("%s is not declared in %s, so a walk from it would report clean having walked nothing", root, scan.dir)
	}
	reached := map[string]bool{root: true}
	frontier := []string{root}
	for 0 < len(frontier) {
		name := frontier[len(frontier)-1]
		frontier = frontier[:len(frontier)-1]
		for _, edge := range epochEdgesOf(scan, name) {
			if reached[edge] {
				continue
			}
			reached[edge] = true
			frontier = append(frontier, edge)
		}
	}
	return reached
}

// Every identifier named anywhere in a reachable set, which is what the forbidden-file half reads.
func epochIdentsReachedFrom(scan epochScan, reachable map[string]bool) map[string]bool {
	named := map[string]bool{}
	for name := range reachable {
		for _, ident := range epochIdentsIn(scan.decls[name]) {
			named[ident] = true
		}
	}
	return named
}

// ---------------------------------------------------------------------------
// the derivation class, derived off the OPERATION and over a derived scope
// ---------------------------------------------------------------------------

// The directories this package's production source can reach at all, derived off its own imports.
//
// The SCOPE question (R3a), answered without a list. Every github.com/urnetwork/connect/* import
// this package holds names a sibling directory of the module, so the set of packages a function
// here can call into is read off the import specs rather than written down -- and a third urnetwork
// package imported next week is in scope on the commit that adds it. A gate that derives its class
// and then enumerates its scope is not a derived gate, which is the half of rule 5 this file was
// failing before it was rewritten: the earlier reading named keyschedule.go, handle.go and
// ../message/writeauth.go, and a derivation written in a fourth file was invisible to it.
func epochReachableRoots(t *testing.T) []string {
	t.Helper()
	own := epochScanSources(t, epochOwnScanDir)
	roots := []string{epochOwnScanDir}
	entries, err := os.ReadDir(epochOwnScanDir)
	if err != nil {
		t.Fatalf("read this package's directory: %v", err)
	}
	const modulePrefix = `"github.com/urnetwork/connect/`
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(own.fileSet, filepath.ToSlash(filepath.Join(epochOwnScanDir, name)), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, spec := range parsed.Imports {
			path := spec.Path.Value
			if !strings.HasPrefix(path, modulePrefix) {
				continue
			}
			sibling := "../" + strings.TrimSuffix(strings.TrimPrefix(path, modulePrefix), `"`)
			if info, err := os.Stat(sibling); err != nil || !info.IsDir() {
				t.Fatalf("%s imports %s and %s is not a directory, so the scope this rule walks is not the scope the package reaches",
					name, path, sibling)
			}
			if !slices.Contains(roots, sibling) {
				roots = append(roots, sibling)
			}
		}
	}
	if len(roots) < 2 {
		t.Fatal("this package's production source reads as importing no other urnetwork package, so the scope below is this directory alone and every cross package edge is invisible to it")
	}
	slices.Sort(roots)
	return roots
}

// Every function of one directory that reaches a key derivation, transitively.
//
// The class is derived off the OPERATION and not off a named provider: a body that calls Expand or
// Extract on anything, or that names an hkdf entry point at all, is a derivation, and everything
// that reaches one is in the class with it. That reads the same in this package, where every
// derivation goes through mls.CryptoProvider because guardrail G1 forbids spelling crypto/hkdf, and
// in connect/message, where writeauth.go calls hkdf.Expand directly -- so one rule covers both
// without a row per package and without a row per provider.
//
// It is computed by walking the call graph BACKWARDS from the derivation roots, which is what makes
// it affordable over a directory the size of connect/mls.
func epochDerivationClass(t *testing.T, scan epochScan) []string {
	t.Helper()
	roots := map[string]bool{}
	reverse := map[string][]string{}
	for name := range scan.decls {
		for _, edge := range epochEdgesOf(scan, name) {
			reverse[edge] = append(reverse[edge], name)
		}
		if epochDerives(scan, name) {
			roots[name] = true
		}
	}
	// An EMPTY class is not fatal here and is fatal in the caller, because emptiness means two
	// different things at the two altitudes. One root of the scope may honestly hold no
	// derivation -- mls/syntax is a codec and holds none, measured -- while a scope in which
	// NOTHING derives is a reading that has stopped working. epochScanSources has already made
	// a directory that yielded no file and one that yielded no function fatal, so an empty class
	// here is a fact about the package rather than about the walk.
	class := map[string]bool{}
	frontier := slices.Sorted(maps.Keys(roots))
	for name := range roots {
		class[name] = true
	}
	for 0 < len(frontier) {
		name := frontier[len(frontier)-1]
		frontier = frontier[:len(frontier)-1]
		for _, caller := range reverse[name] {
			if class[caller] {
				continue
			}
			class[caller] = true
			frontier = append(frontier, caller)
		}
	}
	return slices.Sorted(maps.Keys(class))
}

// Whether one declaration performs a key derivation itself.
func epochDerives(scan epochScan, name string) bool {
	derives := false
	for _, decl := range scan.decls[name] {
		ast.Inspect(decl.Body, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.Ident:
				// an hkdf entry point under any spelling of the call
				if typed.Name == "hkdf" {
					derives = true
				}
			case *ast.CallExpr:
				selector, isSelector := typed.Fun.(*ast.SelectorExpr)
				if !isSelector {
					return true
				}
				if selector.Sel.Name == "Expand" || selector.Sel.Name == "Extract" {
					derives = true
				}
			}
			return true
		})
	}
	return derives
}

// ---------------------------------------------------------------------------
// the carrier walk: does the sampler read the source it was HANDED
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

// One positional parameter slot's name, with "" where the declaration named none.
func epochParameterNames(function *ast.FuncDecl) []string {
	names := []string{}
	if function.Type.Params == nil {
		return names
	}
	for _, field := range function.Type.Params.List {
		if len(field.Names) == 0 {
			names = append(names, "")
			continue
		}
		for _, ident := range field.Names {
			names = append(names, ident.Name)
		}
	}
	return names
}

// The parameter names of one declaration whose type is written as an entropy source.
func epochEntropyParameterNames(scan epochScan, function *ast.FuncDecl) []string {
	names := []string{}
	if function.Type.Params == nil {
		return names
	}
	for _, field := range function.Type.Params.List {
		if epochRendered(scan, field.Type) != epochEntropyExpression {
			continue
		}
		for _, ident := range field.Names {
			names = append(names, ident.Name)
		}
	}
	return names
}

// Whether one function reads the entropy source it was handed, following the value through the
// directory's own call graph.
//
// The carrier set is closed to a fixed point: the root's io.Reader parameters seed it; a carrier
// passed as the i-th argument of a call to a function this directory declares adds THAT function's
// i-th parameter; and a carrier assigned to a local name adds the name. A read is io.ReadFull with
// a carrier in the reader position, or a Read call on a carrier.
//
// A body that ignores its argument and answers a constant therefore fails, and so does one that
// draws from a source the caller never named -- which is the fallback shape, and the one every
// behavioural test passes.
func epochReadsTheSourceItWasHanded(t *testing.T, scan epochScan, root string) (bool, int) {
	t.Helper()
	decls, declared := scan.decls[root]
	if !declared {
		t.Fatalf("%s is not declared in %s", root, scan.dir)
	}
	carriers := map[string]map[string]bool{}
	add := func(function string, name string) bool {
		if name == "" || name == "_" {
			return false
		}
		if carriers[function] == nil {
			carriers[function] = map[string]bool{}
		}
		if carriers[function][name] {
			return false
		}
		carriers[function][name] = true
		return true
	}
	seeded := false
	for _, decl := range decls {
		for _, name := range epochEntropyParameterNames(scan, decl) {
			if add(root, name) {
				seeded = true
			}
		}
	}
	if !seeded {
		return false, 0
	}
	reads := false
	followed := 0
	for changed := true; changed; {
		changed = false
		for function := range maps.Clone(carriers) {
			held := maps.Clone(carriers[function])
			for _, decl := range scan.decls[function] {
				ast.Inspect(decl.Body, func(node ast.Node) bool {
					switch typed := node.(type) {
					case *ast.AssignStmt:
						// window := random keeps the same reader, so the name it
						// was given carries it too
						for i, right := range typed.Rhs {
							ident, isIdent := right.(*ast.Ident)
							if !isIdent || !held[ident.Name] || len(typed.Lhs) <= i {
								continue
							}
							if left, isLeft := typed.Lhs[i].(*ast.Ident); isLeft {
								if add(function, left.Name) {
									changed = true
								}
							}
						}
					case *ast.CallExpr:
						switch callee := typed.Fun.(type) {
						case *ast.SelectorExpr:
							qualifier, isIdent := callee.X.(*ast.Ident)
							if !isIdent {
								return true
							}
							// io.ReadFull(random, ...)
							if qualifier.Name == "io" && callee.Sel.Name == "ReadFull" && 0 < len(typed.Args) {
								if arg, isArg := typed.Args[0].(*ast.Ident); isArg && held[arg.Name] {
									reads = true
								}
								return true
							}
							// random.Read(...)
							if callee.Sel.Name == "Read" && held[qualifier.Name] {
								reads = true
							}
						case *ast.Ident:
							target, isDeclared := scan.decls[callee.Name]
							if !isDeclared || len(target) == 0 {
								return true
							}
							parameters := epochParameterNames(target[0])
							for i, argument := range typed.Args {
								ident, isIdent := argument.(*ast.Ident)
								if !isIdent || !held[ident.Name] || len(parameters) <= i {
									continue
								}
								followed += 1
								if add(callee.Name, parameters[i]) {
									changed = true
								}
							}
						}
					}
					return true
				})
			}
		}
	}
	return reads, followed
}

// ---------------------------------------------------------------------------
// property 2, half A: the sampler's parameter list, as a signature
// ---------------------------------------------------------------------------

// What one declaration's parameter list and results read as, for the signature half.
type epochSignature struct {
	parameters []string
	results    []string
}

func epochSignatureOf(t *testing.T, scan epochScan, name string) epochSignature {
	t.Helper()
	decls, declared := scan.decls[name]
	if !declared || len(decls) == 0 {
		t.Fatalf("%s is not declared in %s, so its signature cannot be read and this rule holds nothing", name, scan.dir)
	}
	read := epochSignature{parameters: []string{}, results: []string{}}
	function := decls[0]
	if function.Type.Params != nil {
		for _, field := range function.Type.Params.List {
			count := len(field.Names)
			if count == 0 {
				count = 1
			}
			for i := 0; i < count; i += 1 {
				read.parameters = append(read.parameters, epochRendered(scan, field.Type))
			}
		}
	}
	if function.Type.Results != nil {
		for _, field := range function.Type.Results.List {
			count := len(field.Names)
			if count == 0 {
				count = 1
			}
			for i := 0; i < count; i += 1 {
				read.results = append(read.results, epochRendered(scan, field.Type))
			}
		}
	}
	return read
}

// TestThePqSecretSamplerTakesAnEntropySourceAndNothingElse is property 2 half A.
//
// The defence is the SIGNATURE and not the body, exactly as it is for NewEphRoot and for AADBody
// under G4. A sampler that also took a storage root, an epoch, a class key or a group would compile,
// round trip, agree between two clients and pass every behavioural test in this package while the
// post quantum property was gone -- so the second parameter is refused as a declaration, which a
// syntax tree decides, rather than as a behaviour no test can observe.
func TestThePqSecretSamplerTakesAnEntropySourceAndNothingElse(t *testing.T) {
	scan := epochScanSources(t, epochOwnScanDir)
	signature := epochSignatureOf(t, scan, epochSamplerName)
	if want := []string{epochEntropyExpression}; !slices.Equal(signature.parameters, want) {
		t.Errorf("%s takes %v and section 5.10 E1's sampler takes %v and nothing else: a pq_secret derived from anything durable compiles, round trips and forfeits the PQ property in silence",
			epochSamplerName, signature.parameters, want)
	}
	if want := []string{"[]byte", "error"}; !slices.Equal(signature.results, want) {
		t.Errorf("%s answers %v, want %v: the draw and the refusal, and no third value a caller could mistake for a second secret",
			epochSamplerName, signature.results, want)
	}
	t.Logf("%d files, %d functions, %s%v %v", scan.fileCount, len(scan.decls), epochSamplerName, signature.parameters, signature.results)
}

// The control on the signature reader: a sampler with a second parameter must read as one, and the
// clean one must not, or the rule above is satisfied by a reader that answers the same thing to
// everything.
func TestTheSignatureReaderSeparatesTheControlSamplers(t *testing.T) {
	control := epochScanSources(t, epochControlScanDir)
	clean := epochSignatureOf(t, control, "SamplerThatReads")
	if want := []string{epochEntropyExpression}; !slices.Equal(clean.parameters, want) {
		t.Errorf("the reader read SamplerThatReads as taking %v, want %v", clean.parameters, want)
	}
	tainted := epochSignatureOf(t, control, "SamplerThatDerives")
	if want := []string{epochEntropyExpression, "[]byte"}; !slices.Equal(tainted.parameters, want) {
		t.Errorf("the reader read SamplerThatDerives as taking %v, want %v; a second parameter has to be visible or the rule above holds nothing",
			tainted.parameters, want)
	}
}

// ---------------------------------------------------------------------------
// property 2, half B: the sampler's body reaches the reader and no derivation
// ---------------------------------------------------------------------------

// TestThePqSecretSamplerReachesItsSourceAndNoDerivation is property 2 half B.
//
// Two assertions over the sampler's call graph, and they are independent: a sampler can read its
// source and still derive from a storage root, and the control holds one that does exactly that.
//
//   - it REACHES the entropy source it was handed, so a body that ignores its argument and answers
//     a constant fails, and so does one that draws from a source the caller never named;
//   - it REACHES NOTHING that derives -- not this package's key schedule or handle derivations, not
//     connect/message's write key or read key, not connect/mls's key schedule, and no hkdf entry
//     point at all. That is what refuses a pq_secret computed from storage_root[n], and it refuses
//     it whatever the return type is.
//
// Both the class and the scope are derived. The class is every function that reaches an Expand, an
// Extract or an hkdf entry point, computed backwards from those roots; the scope is this directory
// plus every urnetwork package this one's production source imports, read off the import specs. A
// derivation written in a file nobody has created yet, in any of those packages, is forbidden on
// the commit that writes it.
//
// WHAT THE WALK CANNOT SEE, stated rather than left to be discovered: a derivation reached through
// an interface, through reflection, or out of a package this scan does not read. It sees the source
// where the defect would be written, which is what writeauth_test.go's own walk says of itself.
//
// AND WHAT ITS ANTI-VACUITY PROOF IS. The plan asks for a walk that fatals if it followed no edge at
// all. A CORRECT sampler follows none -- it calls io.ReadFull and returns, and that is the whole of
// it -- so that check would be red against correct code, which is the defect this project keeps
// finding from the other side. What stands in its place is TestTheEpochWalksFlagTheControlFixture,
// which runs the identical rule over a fixture holding five samplers and requires the right two to
// be flagged by each half; a walk that followed no edge fails there rather than passing here.
func TestThePqSecretSamplerReachesItsSourceAndNoDerivation(t *testing.T) {
	scan := epochScanSources(t, epochOwnScanDir)
	reachable := epochReachableFrom(t, scan, epochSamplerName)

	reads, followed := epochReadsTheSourceItWasHanded(t, scan, epochSamplerName)
	if !reads {
		t.Errorf("%s does not read the io.Reader it was handed, so the source a caller names is decoration; a draw that ignores its argument still answers thirty two well formed octets and every round trip still passes",
			epochSamplerName)
	}
	t.Logf("the carrier walk followed %d hand offs out of %s and reached %d functions", followed, epochSamplerName, len(reachable))

	named := epochIdentsReachedFrom(scan, reachable)
	roots := epochReachableRoots(t)
	// the two roots whose derivations this package is actually built on, each named so a reading
	// that stopped working fails loudly rather than clearing everything quietly. They are sanity
	// checks on the READER and not the class, which is computed.
	sanity := map[string]string{epochOwnScanDir: "StorageRoot", "../message": "WriteKey"}
	total := 0
	for _, root := range roots {
		reachedScan := epochScanSources(t, root)
		derivations := epochDerivationClass(t, reachedScan)
		total += len(derivations)
		if expect, isChecked := sanity[root]; isChecked && !slices.Contains(derivations, expect) {
			t.Fatalf("the derived class over %s holds %d functions and does not include %s; the rule is looking for the wrong thing",
				root, len(derivations), expect)
		}
		hit := 0
		for _, deriver := range derivations {
			if !named[deriver] {
				continue
			}
			hit += 1
			t.Errorf("%s reaches %s, declared in %s and in %s's derivation class: spec A section 5.10 E1 has pq_secret arrive under X-Wing, and a pq_secret computed from anything already in the schedule forfeits the post quantum property while every test still passes",
				epochSamplerName, deriver, reachedScan.names[deriver], root)
		}
		t.Logf("%s: %d derivations, %d reached", root, len(derivations), hit)
	}
	if total == 0 {
		t.Fatalf("nothing in %v reaches an Expand, an Extract or an hkdf entry point, so this rule cleared the sampler against an empty class", roots)
	}
}

// The positive control for both halves of the walk. Without it the test above proves nothing: it
// reports clean, and a walk that followed no edge at all reports clean too.
//
// The fixture holds five samplers. Two are clean -- one reading its argument directly and one
// reading it two hops away under two different parameter names, which is what says the carrier is
// followed rather than matched by spelling. Three are tainted, one per shape the rule has to see: a
// body that ignores its reader, a body that reads a package level one, and a body that reads its
// own reader correctly AND derives from a storage root three hops down, which is what says the two
// halves are independent.
func TestTheEpochWalksFlagTheControlFixture(t *testing.T) {
	control := epochScanSources(t, epochControlScanDir)

	derivations := epochDerivationClass(t, control)
	want := []string{"SamplerThatDerives", "derive", "expandFrom", "kdf"}
	if !slices.Equal(derivations, want) {
		t.Fatalf("the derivation class over the control is %v, want %v; the walk is not following the calls", derivations, want)
	}

	for _, entry := range []struct {
		root      string
		reads     bool
		derives   bool
		whyItIsIn string
	}{
		{root: "SamplerThatReads", reads: true, derives: false, whyItIsIn: "it reads its own argument"},
		{root: "SamplerThatReadsViaHelper", reads: true, derives: false, whyItIsIn: "it reads its own argument two hops away"},
		{root: "SamplerThatIgnoresItsReader", reads: false, derives: false, whyItIsIn: "it answers a constant"},
		{root: "SamplerThatReadsAnotherSource", reads: false, derives: false, whyItIsIn: "it draws from a package level source"},
		{root: "SamplerThatDerives", reads: true, derives: true, whyItIsIn: "it reads its own argument and derives as well"},
	} {
		reads, _ := epochReadsTheSourceItWasHanded(t, control, entry.root)
		if reads != entry.reads {
			t.Errorf("the carrier walk read %s as reads=%v, want %v: %s", entry.root, reads, entry.reads, entry.whyItIsIn)
		}
		reachable := epochReachableFrom(t, control, entry.root)
		derives := false
		for _, deriver := range derivations {
			if reachable[deriver] {
				derives = true
				break
			}
		}
		if derives != entry.derives {
			t.Errorf("the derivation walk read %s as derives=%v, want %v: %s", entry.root, derives, entry.derives, entry.whyItIsIn)
		}
	}
}

// ---------------------------------------------------------------------------
// property 1: the draw is the source's, and nothing else's
// ---------------------------------------------------------------------------

// Gate B's own content -- the nil refusal and the exhausted refusal -- is held by
// entropy_test.go's derived class, which this task added a probe row to and which mls's
// TestNoEntropyTakingFunctionLivesWhereThisGateCannotCallIt holds a residual row for. What is here
// is the half those two cannot see: that the value IS the source's bytes.
//
// This is the entropy substitution p5 shipped twice in one task and no correctness test could see,
// because the values were still well formed and still round tripped. A sampler that expanded the
// draw, whitened it, or mixed in a counter would answer thirty two good octets, would still differ
// between two calls, and would still round trip -- and the only assertion that separates it from a
// draw is this one.
func TestAPqSecretIsTheDrawAndNotAnExpansionOfIt(t *testing.T) {
	for _, fill := range []byte{0x00, 0x5a, 0xff} {
		source := bytes.Repeat([]byte{fill}, PqSecretBytes)
		secret, err := NewPqSecret(bytes.NewReader(source))
		if err != nil {
			t.Fatalf("NewPqSecret over a %#02x source: %v", fill, err)
		}
		if !bytes.Equal(secret, source) {
			t.Errorf("NewPqSecret over a %#02x source answered %x, want the source's own %x: MASTER section 7 is a thirty two octet CSPRNG draw and an expansion of it is a different value that passes every round trip",
				fill, secret, source)
		}
	}
	// and the value MOVES with the source, which is what a whitener over a fixed internal seed
	// would fail while the row above passed
	first := make([]byte, PqSecretBytes)
	second := make([]byte, PqSecretBytes)
	for i := range first {
		first[i] = byte(i)
		second[i] = byte(0xff - i)
	}
	a, err := NewPqSecret(bytes.NewReader(first))
	if err != nil {
		t.Fatalf("NewPqSecret: %v", err)
	}
	b, err := NewPqSecret(bytes.NewReader(second))
	if err != nil {
		t.Fatalf("NewPqSecret: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Error("two different sources produced the same pq_secret, so the value does not depend on the source it was drawn from")
	}
}

// A source shorter than the draw is a refusal and never a short secret padded out.
//
// Every prefix from empty to one octet short is tried rather than only the empty one, because the
// empty case is the one entropy_test.go already covers and a fallback triggered by a PARTIAL read is
// the shape it cannot see.
func TestAPqSecretRefusesASourceShorterThanTheDraw(t *testing.T) {
	full := make([]byte, PqSecretBytes)
	for i := range full {
		full[i] = byte(0x10 + i)
	}
	for short := 0; short < PqSecretBytes; short += 1 {
		secret, err := NewPqSecret(bytes.NewReader(full[:short]))
		if err == nil {
			t.Errorf("NewPqSecret over a %d octet source answered %x, so it reached some other source when the caller's ran dry",
				short, secret)
		}
		if secret != nil {
			t.Errorf("NewPqSecret over a %d octet source refused and answered %x alongside the refusal", short, secret)
		}
	}
}

// Two draws from the process source differ.
//
// This is what refuses a memoized sampler -- one that answers the first draw for ever after, which
// is "reuse the previous pq_secret on a retry" written where nothing else in this package can see
// it. Sixteen draws rather than two, because a memo that answered per goroutine or every other call
// would pass a single comparison.
func TestTwoPqSecretDrawsFromTheProcessSourceDiffer(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 16; i += 1 {
		secret, err := NewPqSecret(rand.Reader)
		if err != nil {
			t.Fatalf("NewPqSecret from the process source: %v", err)
		}
		if len(secret) != PqSecretBytes {
			t.Fatalf("NewPqSecret answered %d octets, want %d", len(secret), PqSecretBytes)
		}
		key := fmt.Sprintf("%x", secret)
		if seen[key] {
			t.Fatalf("draw %d repeated an earlier pq_secret, so the sampler is answering a value it kept rather than one it drew", i)
		}
		seen[key] = true
	}
}

// ---------------------------------------------------------------------------
// the fixture the provisional epoch properties run over
// ---------------------------------------------------------------------------

// The label spec A section 5.11 exports env_key[k] under, transcribed from the specification so
// property 6 compares this package against the document and not against itself.
const epochEnvelopeExporterLabel = "URmessage/v1/envelope"

// A real GroupHandle with a counter on the one method the destructor calls.
//
// It EMBEDS the interface rather than standing in for it, so every other method is the real group's
// and a case here cannot pass against a handle that answers made up key material. CP3b's bar is
// "every key real, no test-only key source anywhere on the path", and a stub handle would satisfy
// this file while leaving that bar where it was.
type epochClearCountingHandle struct {
	GroupHandle
	cleared int
}

func (self *epochClearCountingHandle) ClearPendingCommit() {
	self.cleared += 1
	self.GroupHandle.ClearPendingCommit()
}

// One distinguishable thirty two octet value per name, so a failure says which secret survived.
func epochSecretFilled(fill byte) []byte {
	secret := make([]byte, PqSecretBytes)
	for i := range secret {
		secret[i] = fill
	}
	return secret
}

// The four secrets of section 5.12 step 1 and the two wraps, each with a second header over the
// same backing array.
//
// The alias is the whole point, and it is the shape zeroize_test.go uses: a check that read the
// struct's own field after Destroy set it to nil would pass against a destructor that dropped the
// slice and erased nothing, which is a destructor that leaves the epoch's key material live in the
// committer's arrays.
//
// SIX VALUES HERE ARE THE TEST'S AND NOT THE PRODUCT'S, named for the reason sessionfixture_test.go
// names its four: the four secrets and the two wraps are constant fills, because what these cases
// assert is that each one is ERASED and a case comparing six arrays is comparing the destructor
// rather than six draws. None of them is reachable from a production build -- they are declared in a
// _test.go file and NewProvisionalEpoch takes no value of its own -- and the pq_secret of the one
// case that is about the value rather than about the erasure, TestLostCommitResamplesPqSecret, comes
// out of NewPqSecret over crypto/rand. The GROUP HANDLE is real in every case here.
type epochProvisionalFixture struct {
	handle  *epochClearCountingHandle
	value   *ProvisionalEpoch
	aliases map[string][]byte
}

func newEpochProvisionalFixture(t *testing.T, name string) *epochProvisionalFixture {
	t.Helper()
	engine := newTestEngine(t)
	handle := &epochClearCountingHandle{GroupHandle: engine.createGroup(t, name)}
	storageRoot := epochSecretFilled(0x11)
	writeKey := epochSecretFilled(0x22)
	ephRoot := epochSecretFilled(0x33)
	pqSecret := epochSecretFilled(0x44)
	value, err := NewProvisionalEpoch(handle, handle.Epoch()+1, storageRoot, writeKey, ephRoot, pqSecret)
	if err != nil {
		t.Fatalf("NewProvisionalEpoch: %v", err)
	}
	firstWrap := epochSecretFilled(0x55)
	secondWrap := epochSecretFilled(0x66)
	if err := value.InstallWraps([][]byte{firstWrap, secondWrap}); err != nil {
		t.Fatalf("InstallWraps: %v", err)
	}
	return &epochProvisionalFixture{
		handle: handle,
		value:  value,
		aliases: map[string][]byte{
			"storage_root":    storageRoot[:],
			"write_key":       writeKey[:],
			"eph_root":        ephRoot[:],
			"pq_secret":       pqSecret[:],
			"the first wrap":  firstWrap[:],
			"the second wrap": secondWrap[:],
		},
	}
}

// ---------------------------------------------------------------------------
// property 3: the provisional value is destroyed as ONE THING
// ---------------------------------------------------------------------------

// TestDestroyingAProvisionalEpochErasesEverythingAndClearsTheStagedCommit is property 3.
//
// Both halves are asserted from ONE call, which is the point of the property and the reason the mls
// call lives inside the destructor: section 5.12 step 1 lists six things to discard, connect/mls
// knows one of them, and a caller who has to remember two erasures will one day make one. A
// destructor that zeroized and did not clear, or cleared and did not zeroize, fails here.
//
// The per secret half is asserted through an ALIAS over the same backing array, so a destructor
// that dropped the slices and erased nothing cannot satisfy it, and the class of slice fields is
// derived off the type rather than listed, so a seventh field added next week is checked without
// this test being edited.
func TestDestroyingAProvisionalEpochErasesEverythingAndClearsTheStagedCommit(t *testing.T) {
	fixture := newEpochProvisionalFixture(t, "destroy-one-thing")

	fixture.value.Destroy()

	if fixture.handle.cleared != 1 {
		t.Errorf("the destructor called ClearPendingCommit %d times, want 1: G10 names it as the thing that destroys the provisional state, and a zeroization beside it rather than inside it is a pair of erasures a caller has to remember",
			fixture.handle.cleared)
	}
	for what, alias := range fixture.aliases {
		for i, octet := range alias {
			if octet != 0 {
				t.Errorf("%s survived the destructor: octet %d is %#02x. Section 5.12 step 1 discards storage_root[n+1], write_key[n+1], eph_root[n+1], pq_secret[n+1] and every X-Wing wrap, and a half erase leaves the surviving half looking like a value somebody may use",
					what, i, octet)
				break
			}
		}
	}

	// the derived half: every slice typed field of the type is dropped, whatever it is called
	value := reflect.ValueOf(fixture.value).Elem()
	sliceFields := 0
	for i := 0; i < value.NumField(); i += 1 {
		if value.Field(i).Kind() != reflect.Slice {
			continue
		}
		sliceFields += 1
		if !value.Field(i).IsNil() {
			t.Errorf("the field %s is still held after the destructor ran, so a reader that reaches the struct directly still has it",
				value.Type().Field(i).Name)
		}
	}
	if sliceFields == 0 {
		t.Fatal("ProvisionalEpoch declares no slice typed field, so the rule above cleared a type it read nothing of")
	}
	if fixture.handle.Epoch() != 0 {
		t.Errorf("the group moved to epoch %d, and the destructor must drop a STAGED commit rather than the live epoch", fixture.handle.Epoch())
	}
}

// A second Destroy is the same state as the first, and must not clear a commit staged AFTER it.
//
// Section 5.12 step 5 has the losing committer retry -- which stages another commit on the same
// group -- so a destructor that cleared unconditionally on every call would erase the retry's own
// staged epoch if the value were destroyed twice.
func TestDestroyingAProvisionalEpochTwiceClearsOnce(t *testing.T) {
	fixture := newEpochProvisionalFixture(t, "destroy-twice")
	fixture.value.Destroy()
	fixture.value.Destroy()
	if fixture.handle.cleared != 1 {
		t.Errorf("two Destroy calls cleared %d staged commits, want 1: the second call must not reach a commit the retry staged after this state was destroyed",
			fixture.handle.cleared)
	}
}

// The X-Wing wraps are installed once, and a second install is refused rather than dropping the
// first set.
//
// This is the hazard connect/mls's TestEveryPathThatDropsHeldKeyMaterialErasesItFirst derives off
// this package's source, asserted here as behaviour so it is held from both sides: that gate reads
// the syntax tree and would be satisfied by a refusal that refused the wrong thing, and this reads
// the values and would be satisfied by a body the gate cannot see. Neither alone is the property.
func TestTheWrapsOfAProvisionalEpochAreInstalledOnce(t *testing.T) {
	fixture := newEpochProvisionalFixture(t, "wraps-write-once")
	installed, err := fixture.value.Wraps()
	if err != nil {
		t.Fatalf("Wraps: %v", err)
	}
	if len(installed) != 2 {
		t.Fatalf("the fixture installed %d wraps, want 2", len(installed))
	}
	second := [][]byte{epochSecretFilled(0x99)}
	if err := fixture.value.InstallWraps(second); !errors.Is(err, ErrProvisionalEpochWraps) {
		t.Errorf("a second install answered %v, want ErrProvisionalEpochWraps: it would drop the first fan out's wraps with nothing erasing them", err)
	}
	held, err := fixture.value.Wraps()
	if err != nil {
		t.Fatalf("Wraps after the refused install: %v", err)
	}
	if len(held) != 2 || !bytes.Equal(held[0], installed[0]) || !bytes.Equal(held[1], installed[1]) {
		t.Error("the refused install moved the set anyway, so the refusal is a message rather than a guard")
	}
	if !bytes.Equal(second[0], epochSecretFilled(0x99)) {
		t.Error("the refused install erased the caller's own set, which it was never handed ownership of")
	}

	// and an empty install is not an install: it would leave the field nil and let a later one
	// land, which is the write once rule satisfied by a value that was never written
	fresh := newEpochProvisionalFixture(t, "wraps-empty-install")
	fresh.value.Destroy()
	untouched := newTestEngine(t).createGroup(t, "wraps-empty")
	bare, err := NewProvisionalEpoch(untouched, 1, epochSecretFilled(0x01), epochSecretFilled(0x02),
		epochSecretFilled(0x03), epochSecretFilled(0x04))
	if err != nil {
		t.Fatalf("NewProvisionalEpoch: %v", err)
	}
	for _, empty := range [][][]byte{nil, {}} {
		if err := bare.InstallWraps(empty); !errors.Is(err, ErrProvisionalEpochWraps) {
			t.Errorf("installing %d wraps answered %v, want ErrProvisionalEpochWraps", len(empty), err)
		}
	}
	if err := bare.InstallWraps([][]byte{epochSecretFilled(0xaa)}); err != nil {
		t.Errorf("the first real install after two empty ones answered %v", err)
	}
}

// ---------------------------------------------------------------------------
// property 4, behavioural half: nothing answers afterwards
// ---------------------------------------------------------------------------

// Every exported method of *ProvisionalEpoch, read off the type rather than listed.
func epochExportedMethodsOfTheProvisionalValue(t *testing.T) []reflect.Method {
	t.Helper()
	subject := reflect.TypeOf(&ProvisionalEpoch{})
	methods := []reflect.Method{}
	for i := 0; i < subject.NumMethod(); i += 1 {
		methods = append(methods, subject.Method(i))
	}
	if len(methods) == 0 {
		t.Fatal("*ProvisionalEpoch declares no exported method, so every rule below cleared a surface it read nothing of")
	}
	return methods
}

// Whether a method type answers an error, and whether it answers anything that is neither an error
// nor a bool -- which is the shape half of property 4.
func epochMethodResults(signature reflect.Type) (answersError bool, answersState bool) {
	errorType := reflect.TypeOf((*error)(nil)).Elem()
	for i := 0; i < signature.NumOut(); i += 1 {
		out := signature.Out(i)
		if out == errorType {
			answersError = true
			continue
		}
		if out.Kind() == reflect.Bool {
			continue
		}
		answersState = true
	}
	return answersError, answersState
}

// The error among a call's results, or nil.
func epochErrorResultOf(results []reflect.Value) error {
	errorType := reflect.TypeOf((*error)(nil)).Elem()
	for _, result := range results {
		if result.Type() != errorType || result.IsNil() {
			continue
		}
		return result.Interface().(error)
	}
	return nil
}

// TestEveryAccessorOfAProvisionalEpochRefusesOnceItHasBeenDestroyed is property 4's behavioural
// half, which is the half that has a member at this commit.
//
// G10's own words are "there is no path that reads it afterwards". The derived class of in package
// READERS is empty here -- task 15's fan out and task 21's retry loop are the readers and neither
// exists -- so what lands is the value's own refusal, held over the whole exported surface by
// reflection so an accessor added later is in the class without this test being edited. The derived
// class of readers lands in task 15 property 6, which names this property back.
//
// Both directions, because a method that always refused would satisfy the after half vacuously:
// every error answering accessor must ANSWER before the destructor and REFUSE after it.
func TestEveryAccessorOfAProvisionalEpochRefusesOnceItHasBeenDestroyed(t *testing.T) {
	fixture := newEpochProvisionalFixture(t, "refuse-after-destroy")
	methods := epochExportedMethodsOfTheProvisionalValue(t)

	answered := 0
	for i, method := range methods {
		answersError, _ := epochMethodResults(method.Type)
		if !answersError {
			continue
		}
		answered += 1
		bound := reflect.ValueOf(fixture.value).Method(i)
		arguments := []reflect.Value{}
		for j := 0; j < bound.Type().NumIn(); j += 1 {
			arguments = append(arguments, reflect.Zero(bound.Type().In(j)))
		}
		// the DESTROYED refusal specifically, and not any refusal at all. A method called
		// with zero valued arguments may legitimately refuse them -- InstallWraps refuses an
		// empty set and refuses a second install -- and what this half has to rule out is a
		// method that answers G10's sentinel whether or not the destructor has run, which is
		// the shape that would satisfy the half below vacuously.
		if err := epochErrorResultOf(bound.Call(arguments)); errors.Is(err, ErrProvisionalEpochDestroyed) {
			t.Errorf("%s answered ErrProvisionalEpochDestroyed BEFORE the destructor ran, so its refusal afterwards would say nothing about the destructor", method.Name)
		}
	}
	if answered == 0 {
		t.Fatal("no exported method of *ProvisionalEpoch answers an error, so G10's typed refusal has nowhere to be observed")
	}

	fixture.value.Destroy()

	errorType := reflect.TypeOf((*error)(nil)).Elem()
	for i, method := range methods {
		answersError, _ := epochMethodResults(method.Type)
		if !answersError {
			continue
		}
		bound := reflect.ValueOf(fixture.value).Method(i)
		arguments := []reflect.Value{}
		for j := 0; j < bound.Type().NumIn(); j += 1 {
			arguments = append(arguments, reflect.Zero(bound.Type().In(j)))
		}
		results := bound.Call(arguments)
		err := epochErrorResultOf(results)
		if err == nil {
			t.Errorf("%s answered after the destructor ran; G10 is that there is no path that reads it afterwards, and a destroyed value that answered zeros rather than refusing would have a caller seal under thirty two zero octets",
				method.Name)
			continue
		}
		if !errors.Is(err, ErrProvisionalEpochDestroyed) {
			t.Errorf("%s refused with %v, want ErrProvisionalEpochDestroyed; one condition gets one sentinel so a caller matches it with one errors.Is",
				method.Name, err)
		}
		for _, beside := range results {
			if beside.Type() == errorType {
				continue
			}
			if beside.Kind() == reflect.Slice && !beside.IsNil() {
				t.Errorf("%s answered %d octets alongside its refusal", method.Name, beside.Len())
			}
		}
	}

	if !fixture.value.Destroyed() {
		t.Error("Destroyed answered false after the destructor ran, so the flag task 15's readers are held to says the opposite of the truth")
	}
}

// Property 4's shape half: no exported method hands back state without a door to refuse through.
//
// This is what stops the rule above being routed around rather than broken. An accessor declared as
// PqSecret() []byte answers no error, so the refusal test skips it, and it would hand a destroyed
// value's bytes to a caller in silence. The rule is read off the RESULT TYPES and enumerates
// nothing: a method answering anything that is neither an error nor the destroyed flag must answer
// an error beside it.
func TestNoExportedAccessorOfAProvisionalEpochAnswersStateWithoutARefusal(t *testing.T) {
	for _, method := range epochExportedMethodsOfTheProvisionalValue(t) {
		answersError, answersState := epochMethodResults(method.Type)
		if answersState && !answersError {
			t.Errorf("%s answers state and no error, so it has no way to refuse once the destructor has run and G10's rule has no door to close on it",
				method.Name)
		}
	}
}

// The reflected surface and the declared surface are the same surface.
//
// Two readings of "the exported methods of this type" that disagree is one rule holding less than
// the one beside it while both report clean, and the narrower one is invisible from inside itself.
func TestTheReflectedAndDeclaredSurfacesOfAProvisionalEpochAgree(t *testing.T) {
	reflected := []string{}
	for _, method := range epochExportedMethodsOfTheProvisionalValue(t) {
		reflected = append(reflected, method.Name)
	}
	slices.Sort(reflected)

	scan := epochScanSources(t, epochOwnScanDir)
	declared := []string{}
	for name, decls := range scan.decls {
		if !ast.IsExported(name) {
			continue
		}
		for _, decl := range decls {
			if decl.Recv == nil || len(decl.Recv.List) == 0 {
				continue
			}
			if epochRendered(scan, decl.Recv.List[0].Type) != "*ProvisionalEpoch" {
				continue
			}
			declared = append(declared, name)
		}
	}
	slices.Sort(declared)
	if !slices.Equal(reflected, declared) {
		t.Errorf("reflection reads %v off *ProvisionalEpoch and the source declares %v", reflected, declared)
	}
}

// ---------------------------------------------------------------------------
// property 5: a lost commit resamples
// ---------------------------------------------------------------------------

// TestLostCommitResamplesPqSecret is the test spec A section 5.9 G10 and section 11.2 name.
//
// Section 5.12 step 2: the committer MUST NOT reuse the pq_secret it sampled, because it was
// encapsulated to a ratchet tree that no longer exists and carrying it into the real epoch n+1 binds
// one PQ secret across two distinct epochs. Task 21 supplies the retry loop; what is assertable here
// is the state that loop is built on, and it is asserted in three ways rather than one, because "two
// random draws differ" is true of a broken implementation too:
//
//   - the destroyed value REFUSES its pq_secret, so a retry has no door to reuse it through;
//   - the bytes it held are GONE, so a retry holding a stale reference gets zeros rather than the
//     old secret;
//   - and the second commit's value is a different secret from the first's.
func TestLostCommitResamplesPqSecret(t *testing.T) {
	engine := newTestEngine(t)
	handle := &epochClearCountingHandle{GroupHandle: engine.createGroup(t, "lost-commit")}
	epoch := handle.Epoch() + 1

	firstSecret, err := NewPqSecret(rand.Reader)
	if err != nil {
		t.Fatalf("NewPqSecret: %v", err)
	}
	firstAsSampled := append([]byte(nil), firstSecret...)
	first, err := NewProvisionalEpoch(handle, epoch,
		epochSecretFilled(0x01), epochSecretFilled(0x02), epochSecretFilled(0x03), firstSecret)
	if err != nil {
		t.Fatalf("NewProvisionalEpoch: %v", err)
	}
	held, err := first.PqSecret()
	if err != nil {
		t.Fatalf("PqSecret before the loss: %v", err)
	}
	if !bytes.Equal(held, firstAsSampled) {
		t.Fatalf("the provisional value holds %x and the sampler drew %x", held, firstAsSampled)
	}

	// the commit is lost
	first.Destroy()

	if _, err := first.PqSecret(); !errors.Is(err, ErrProvisionalEpochDestroyed) {
		t.Errorf("the losing committer's pq_secret is still reachable, err = %v: section 5.12 step 2 forbids reusing it and the refusal is what leaves a retry unable to",
			err)
	}
	if !bytes.Equal(firstSecret, make([]byte, PqSecretBytes)) {
		t.Errorf("the losing committer's pq_secret survives in the array it was drawn into, %x: a retry holding a stale reference would carry one PQ secret across two epochs",
			firstSecret)
	}

	// the retry, at the SAME epoch
	secondSecret, err := NewPqSecret(rand.Reader)
	if err != nil {
		t.Fatalf("NewPqSecret for the retry: %v", err)
	}
	second, err := NewProvisionalEpoch(handle, epoch,
		epochSecretFilled(0x04), epochSecretFilled(0x05), epochSecretFilled(0x06), secondSecret)
	if err != nil {
		t.Fatalf("NewProvisionalEpoch for the retry: %v", err)
	}
	retried, err := second.PqSecret()
	if err != nil {
		t.Fatalf("PqSecret after the retry: %v", err)
	}
	if bytes.Equal(retried, firstAsSampled) {
		t.Errorf("the retry at epoch %d carries the pq_secret the lost commit sampled, %x: MASTER section 7's per epoch PQ independence is exactly this",
			epoch, firstAsSampled)
	}
	if at, err := second.Epoch(); err != nil || at != epoch {
		t.Errorf("the retry's provisional state is for epoch %d (err %v), and the retry is at %d", at, err, epoch)
	}
}

// ---------------------------------------------------------------------------
// property 6: the destructor does not reach the epoch's cached env_key
// ---------------------------------------------------------------------------

// Every field of ProvisionalEpoch, with the item of section 5.12 step 1 it is.
//
// The CLASS is derived -- it is every field the type declares, read off the type rather than listed
// -- and only the ANSWERS are written down, which is the shape imports_test.go pins this package's
// import set with. That is what makes a cached env_key added here fail on the commit that adds it
// whatever it is called: a field with no row is a failure, and so is a row with no field.
var epochProvisionalFields = map[string]string{
	"handle":      "the MLS surface whose staged epoch is step 1's TreeKEM path secrets, and which the destructor calls ClearPendingCommit on from inside",
	"epoch":       "n+1, the epoch this state was built for and which it may never reach",
	"storageRoot": "storage_root[n+1], step 1",
	"writeKey":    "write_key[n+1], step 1",
	"ephRoot":     "eph_root[n+1], step 1",
	"pqSecret":    "pq_secret[n+1], step 1, and step 2's MUST NOT be reused",
	"wraps":       "every X-Wing wrap it built, step 1's last clause, installed write once",
	"destroyed":   "G10's there is no path that reads it afterwards, as a value rather than as a sentence",
}

// TestAProvisionalEpochDeclaresNoFieldAbleToHoldACachedEnvKey is property 6's SHAPE half, and it is
// the half that must fail first.
//
// Spec A section 5.11 makes caching env_key[k] = MLS-Exporter("URmessage/v1/envelope", "", 32) a
// normative obligation, because (*Group).Export reads the current schedule and connect has no
// ExportAt, so the key is computable only while the group stands at epoch k. That cache is NOT
// provisional committer state: it belongs to an epoch that may already be OPEN, and destroying it
// because a LATER commit was rejected would discard the only route into that epoch's storage_root --
// the same shape as ledger open item 134's conforming client hazard, arrived at from the other side.
//
// The behavioural half below says the destructor leaves a cached env_key alone. This says the type
// cannot hold one, and it is what stops the behavioural half being re-broken by somebody who finds
// it convenient to keep the two together.
func TestAProvisionalEpochDeclaresNoFieldAbleToHoldACachedEnvKey(t *testing.T) {
	subject := reflect.TypeOf(ProvisionalEpoch{})
	if subject.NumField() == 0 {
		t.Fatal("ProvisionalEpoch declares no field, so this rule pinned an empty set")
	}
	declared := []string{}
	for i := 0; i < subject.NumField(); i += 1 {
		name := subject.Field(i).Name
		declared = append(declared, name)
		if _, isRowed := epochProvisionalFields[name]; isRowed {
			continue
		}
		t.Errorf("ProvisionalEpoch declares %s of type %s and section 5.12 step 1 has no such item. If it is the cached env_key[k], it may NOT live here: section 5.11 makes the cache a normative obligation for an epoch that may already be open, and G10's destructor would discard the only route into that epoch's storage_root",
			name, subject.Field(i).Type)
	}
	for name := range epochProvisionalFields {
		if !slices.Contains(declared, name) {
			t.Errorf("this rule carries a row for %s and ProvisionalEpoch declares no such field, so the pin describes a type that no longer exists", name)
		}
	}
	t.Logf("%d fields pinned: %v", len(declared), declared)
}

// TestDestroyingAProvisionalEpochLeavesTheEpochsCachedEnvKeyIntact is property 6's behavioural half.
//
// The group is at epoch k and the provisional state is for k+1. A caller that has done what section
// 5.11 tells it to do -- exported and retained env_key[k] while the group stood at k -- must still
// hold it after a rejected k+1 commit is destroyed, and must still be able to recompute it, because
// the epoch it belongs to never moved.
func TestDestroyingAProvisionalEpochLeavesTheEpochsCachedEnvKeyIntact(t *testing.T) {
	fixture := newEpochProvisionalFixture(t, "env-key-intact")
	cached, err := fixture.handle.Export(epochEnvelopeExporterLabel, nil, 32)
	if err != nil {
		t.Fatalf("export env_key at the live epoch: %v", err)
	}
	if len(cached) != 32 {
		t.Fatalf("env_key is %d octets, want 32", len(cached))
	}
	held := append([]byte(nil), cached...)

	fixture.value.Destroy()

	if !bytes.Equal(cached, held) {
		t.Errorf("the destructor reached the cached env_key: it now reads %x and was %x. Section 5.11's cache belongs to an epoch that may already be open, and it is the only route into that epoch's storage_root once the group has moved",
			cached, held)
	}
	again, err := fixture.handle.Export(epochEnvelopeExporterLabel, nil, 32)
	if err != nil {
		t.Fatalf("export env_key after the destructor: %v", err)
	}
	if !bytes.Equal(again, held) {
		t.Errorf("the group's own env_key moved across the destructor, from %x to %x: Destroy drops a STAGED commit and must not move the live epoch",
			held, again)
	}
}

// ---------------------------------------------------------------------------
// the constructor's refusals
// ---------------------------------------------------------------------------

// Every value of section 5.12 step 1 is thirty two octets, and a short one is refused here rather
// than at whichever expansion happens to meet it first.
func TestAProvisionalEpochRefusesAValueThatIsNotThirtyTwoOctets(t *testing.T) {
	engine := newTestEngine(t)
	handle := engine.createGroup(t, "provisional-widths")
	full := func() []byte { return epochSecretFilled(0x77) }
	for _, wrong := range [][]byte{nil, {}, make([]byte, 31), make([]byte, 33), make([]byte, 64)} {
		for position := 0; position < 4; position += 1 {
			values := [][]byte{full(), full(), full(), full()}
			values[position] = wrong
			value, err := NewProvisionalEpoch(handle, 1, values[0], values[1], values[2], values[3])
			if !errors.Is(err, ErrProvisionalEpochValue) {
				t.Errorf("NewProvisionalEpoch with a %d octet value at position %d answered %v, want ErrProvisionalEpochValue",
					len(wrong), position, err)
			}
			if value != nil {
				t.Errorf("NewProvisionalEpoch refused a %d octet value at position %d and answered a state alongside the refusal",
					len(wrong), position)
			}
		}
	}
	if _, err := NewProvisionalEpoch(nil, 1, full(), full(), full(), full()); !errors.Is(err, ErrNilGroupHandle) {
		t.Errorf("NewProvisionalEpoch with no handle answered %v, want ErrNilGroupHandle: the destructor clears the staged commit from inside and a nil handle would panic there rather than here",
			err)
	}
}
