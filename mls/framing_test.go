// Unit tests for framing.go and framing_errors.go: the three RFC 9420 section 6 framing
// registries, the Sender codec, and the structural refusals this layer declares.
package mls

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// ---------------------------------------------------------------------------
// the widths the wire format gives the three registries
// ---------------------------------------------------------------------------

// The upper half of each width, as a compile time statement. ^T(0) is a typed constant equal
// to the type's own maximum, so converting it to the octet or the pair of octets the wire
// format gives that registry is exactly the sentence "this type is no wider than that", and a
// widened type stops COMPILING here rather than failing a test somewhere else.
//
// A conversion of a literal in the other direction -- SenderType(0xff) -- would say only that
// 255 FITS, which rules out a signed octet and nothing else; it compiles unchanged at uint16
// and at every wider type. That is measured on this project rather than supposed: ContentType
// widened to uint16 built clean and failed exactly one test in this package.
const (
	_ = uint8(^ContentType(0))
	_ = uint8(^SenderType(0))
	_ = uint16(^WireFormat(0))
)

// ---------------------------------------------------------------------------
// the class every table in this file is a claim about
// ---------------------------------------------------------------------------

// framingFile and framingTestFile are named rather than spelled at each call site, because a
// gate whose file no longer exists derives the empty set, and the empty set agrees with an
// empty table.
//
// framingFile is the file the three registry TYPES are declared in, and that is now ALL it is.
// It used to be the derivation root of every gate below as well -- the switches, the codec
// methods, the compile time pins -- which made each of them a claim about one FILE where the
// claim being made is about the package. framing_preimage.go's confirmedTranscriptHashInput
// reads and writes the same wire format registry AuthenticatedContent does, and it was outside
// all of those gates at once: both of its registry switches could be deleted whole with
// ./mls/... and ./message/... byte identically green, while the byte identical switch one file
// over is caught by two of them. Measured, not supposed. The file SET is derived now, by
// framingRegistryFunctions below, off which functions of this package's production source
// actually compute with a framing registry.
const (
	framingFile     = "framing.go"
	framingTestFile = "framing_test.go"
)

// framingRegistryTypesDeclaredIn is every framing registry the named file declares, derived as
// every named type of that file whose underlying type is an unsigned integer.
//
// Derived and not listed, and the hole it closes is measured rather than supposed. Every table
// in this file -- the code points, the section 6.1 arm order, the widths, the compile time pins
// -- is a claim about a SET, and each of the gates joining them iterated the keys of its OWN
// table, so the set of registries was the hand written half of all four at once. A fourth
// registry type declared in framing.go was therefore joined to the RFC by nothing at all: a
// ProposalOrRefType with a deliberately WRONG reference code point, added to framing.go with no
// entry in any table here, left ./mls/... and ./message/... byte identically green.
//
// Unsigned integer rather than extension.go's uint16 exactly, because framing's registries are
// not one width -- WireFormat is the pair of octets section 17 gives it and the other two are
// single octets -- so a filter naming one width would drop two of the three it exists to find.
// Sender is a struct and is not one of these, which is the right cut: a registry is the scalar
// a discriminant is read at, and that is the thing a code point can be wrong about.
func framingRegistryTypesDeclaredIn(t *testing.T, file string) []string {
	t.Helper()
	declared := packageLevelDeclarations(t, ".")
	pkg := typeCheckedPackage(t)
	names := []string{}
	for name, declaredIn := range declared {
		if declaredIn != file {
			continue
		}
		typeName, isType := pkg.Scope().Lookup(name).(*types.TypeName)
		if !isType {
			continue
		}
		basic, isBasic := typeName.Type().Underlying().(*types.Basic)
		if !isBasic || basic.Info()&types.IsUnsigned == 0 {
			continue
		}
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// framingRegistries is that derivation plus the control every caller owes it. An empty result
// is fatal here rather than at each call site: framing.go certainly declares three, so a
// derivation that found none is a reader that broke, and a set join against the empty set is a
// gate reporting green having read nothing.
func framingRegistries(t *testing.T) []string {
	t.Helper()
	declared := framingRegistryTypesDeclaredIn(t, framingFile)
	if len(declared) == 0 {
		t.Fatalf("no registry type was derived from %s, which declares three, so every set join below would compare against nothing",
			framingFile)
	}
	return declared
}

// framingProductionFiles is every production .go file of package mls, read off the directory.
//
// The directory rather than a list, and it is the root of the class every gate below sweeps. A
// class that is "the files somebody remembered" is a class a new file joins by not being
// remembered, which is this project's most repeated failure and was this file's own.
func framingProductionFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package directory: %v", err)
	}
	found := []string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		found = append(found, name)
	}
	slices.Sort(found)
	if len(found) == 0 {
		t.Fatal("no production file was read out of the package directory, so every derivation below would run over the empty set")
	}
	return found
}

// framingRegistryIdentifiers is every identifier whose appearance inside a function makes that
// function a user of a framing registry: the registry TYPE names, and every package level
// constant declared at one of those types.
//
// Both halves, because either alone understates the class. A codec can name the type and no
// constant -- a decoder that reads a uint16 and converts it -- and it can name constants and no
// type, which is the shape of every switch in this package. The union is what these gates are
// about.
func framingRegistryIdentifiers(t *testing.T) map[string]bool {
	t.Helper()
	found := map[string]bool{}
	for _, registry := range framingRegistries(t) {
		found[registry] = true
		for name := range registryConstantsOfType(t, registry) {
			found[name] = true
		}
	}
	if len(found) == 0 {
		t.Fatal("no framing registry identifier was derived, so the function set below would be empty and every gate over it would report green having read nothing")
	}
	return found
}

// mentionsAnyIdentifier reports whether a syntax tree names any of the given identifiers.
func mentionsAnyIdentifier(node ast.Node, wanted map[string]bool) bool {
	found := false
	ast.Inspect(node, func(inner ast.Node) bool {
		if found {
			return false
		}
		if name, isName := inner.(*ast.Ident); isName && wanted[name.Name] {
			found = true
			return false
		}
		return true
	})
	return found
}

// framingRegistryFunction is one function of this package's production source that computes
// with a framing registry: its qualified name, the file that declares it, and its declaration.
type framingRegistryFunction struct {
	name string
	file string
	decl *ast.FuncDecl
}

// framingRegistryFunctions is that class, derived over the whole package rather than over one
// file.
//
// The SIGNATURE and the BODY are read and nothing else is -- not the doc comment, not the rest
// of the file -- because what puts a function in this class is that it computes with a registry,
// not that it sits beside something that does. framing_errors.go spends nine lines on
// ErrUnknownContentType in prose and returns it nowhere, which is exactly the false positive a
// file level text search reports and the one filesRaising further down is written against.
func framingRegistryFunctions(t *testing.T) []framingRegistryFunction {
	t.Helper()
	wanted := framingRegistryIdentifiers(t)
	found := []framingRegistryFunction{}
	for _, file := range framingProductionFiles(t) {
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		for _, declaration := range parsed.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			if !mentionsAnyIdentifier(function.Type, wanted) && !mentionsAnyIdentifier(function.Body, wanted) {
				continue
			}
			name := function.Name.Name
			if function.Recv != nil && len(function.Recv.List) > 0 {
				name = receiverTypeName(function.Recv.List[0].Type) + "." + name
			}
			found = append(found, framingRegistryFunction{name: name, file: file, decl: function})
		}
	}
	slices.SortFunc(found, func(a framingRegistryFunction, b framingRegistryFunction) int {
		return strings.Compare(a.name, b.name)
	})
	if len(found) == 0 {
		t.Fatal("no function of this package's production source computes with a framing registry, and framing.go alone declares nine, so every gate below would run over the empty set")
	}
	return found
}

// framingRegistryBits is the width the type checker reads off a registry's own declaration. It
// is what the compile time pin is held to below, so the pin is joined to the type rather than
// to a fourth transcription of the RFC's octet counts.
func framingRegistryBits(t *testing.T, typeName string) int {
	t.Helper()
	declared, isType := typeCheckedPackage(t).Scope().Lookup(typeName).(*types.TypeName)
	if !isType {
		t.Fatalf("%s is not a type of package mls, so it has no width to read", typeName)
	}
	basic, isBasic := declared.Type().Underlying().(*types.Basic)
	if !isBasic {
		t.Fatalf("%s does not have a basic underlying type, so it is not a registry", typeName)
	}
	switch basic.Kind() {
	case types.Uint8:
		return 8
	case types.Uint16:
		return 16
	case types.Uint32:
		return 32
	case types.Uint64:
		return 64
	}
	t.Fatalf("%s is declared as %s, which is not one of the sized unsigned integers a wire registry can be read at",
		typeName, basic)
	return 0
}

// sizedUnsignedConversionBits is the whole of Go's sized unsigned integer conversions against
// the width each one states. Closed by the language rather than by anybody's judgement, which
// is why it can be written out: uint and uintptr are deliberately absent, since a conversion to
// a platform width bounds a registry at nothing portable.
var sizedUnsignedConversionBits = map[string]int{"uint8": 8, "uint16": 16, "uint32": 32, "uint64": 64}

// widthPinOf recognises exactly the form a width pin has -- uintN(^T(0)) -- and reports T and
// N. Anything else, a bare literal included, is not a pin and is reported as not one.
func widthPinOf(expression ast.Expr) (string, int, bool) {
	conversion, isCall := expression.(*ast.CallExpr)
	if !isCall || len(conversion.Args) != 1 {
		return "", 0, false
	}
	target, isName := conversion.Fun.(*ast.Ident)
	if !isName {
		return "", 0, false
	}
	bits, isSizedUnsigned := sizedUnsignedConversionBits[target.Name]
	if !isSizedUnsigned {
		return "", 0, false
	}
	complement, isUnary := conversion.Args[0].(*ast.UnaryExpr)
	if !isUnary || complement.Op != token.XOR {
		return "", 0, false
	}
	maximum, isInnerCall := complement.X.(*ast.CallExpr)
	if !isInnerCall || len(maximum.Args) != 1 {
		return "", 0, false
	}
	registry, isRegistryName := maximum.Fun.(*ast.Ident)
	if !isRegistryName {
		return "", 0, false
	}
	zero, isLiteral := maximum.Args[0].(*ast.BasicLit)
	if !isLiteral || zero.Kind != token.INT || zero.Value != "0" {
		return "", 0, false
	}
	return registry.Name, bits, true
}

// framingWidthPins reads a test file's own source and returns, for each registry it bounds, the
// width that registry's compile time pin converts to.
//
// Read as a SHAPE rather than counted, and that distinction is this reader's whole reason to
// exist. The package wide guard on the pin block, key_schedule_deps_test.go's
// TestNoPinBlockShrinksWithoutFailing, counts blank identifiers: pinBlockSizes says this file
// holds three and three is what it counts. Rewriting the WireFormat pin to a bare `_ = 0` keeps
// that count at three and leaves the whole package green with the upper bound statement gone --
// measured, not supposed. A pin is its conversion or it is nothing, so this reads the
// conversion.
func framingWidthPins(t *testing.T, file string) map[string]int {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	pins := map[string]int{}
	for _, declaration := range parsed.Decls {
		generic, isGeneric := declaration.(*ast.GenDecl)
		if !isGeneric || (generic.Tok != token.CONST && generic.Tok != token.VAR) {
			continue
		}
		for _, spec := range generic.Specs {
			value, isValue := spec.(*ast.ValueSpec)
			if !isValue || len(value.Names) != 1 || value.Names[0].Name != "_" || len(value.Values) != 1 {
				continue
			}
			registry, bits, isWidthPin := widthPinOf(value.Values[0])
			if !isWidthPin {
				continue
			}
			if other, repeated := pins[registry]; repeated {
				t.Fatalf("%s pins %s twice, at uint%d and at uint%d, so neither line is the statement about its width",
					file, registry, other, bits)
			}
			pins[registry] = bits
		}
	}
	return pins
}

// TestTheWidthPinReaderReadsTheFormAndNotThePresence is the control on that reader. One that
// recognised everything would report three pins out of a file whose pins had all been neutered,
// and one that recognised nothing would report none out of the real file and fail loudly for
// the wrong reason, so both halves are stated over expressions written here.
func TestTheWidthPinReaderReadsTheFormAndNotThePresence(t *testing.T) {
	for _, one := range []struct {
		source   string
		registry string
		bits     int
		isPin    bool
	}{
		{"uint8(^ContentType(0))", "ContentType", 8, true},
		{"uint16(^WireFormat(0))", "WireFormat", 16, true},
		{"uint32(^Something(0))", "Something", 32, true},
		// the neutered pin, which is the survivor this reader exists for
		{"0", "", 0, false},
		// the conversion written the other way round, which says only that the value fits
		{"ContentType(0xff)", "", 0, false},
		{"uint8(^ContentType(1))", "", 0, false},
		{"uint(^ContentType(0))", "", 0, false},
		{"uint8(ContentType(0))", "", 0, false},
		{"^ContentType(0)", "", 0, false},
	} {
		expression, err := parser.ParseExpr(one.source)
		if err != nil {
			t.Fatalf("parse %q: %v", one.source, err)
		}
		registry, bits, isPin := widthPinOf(expression)
		if isPin != one.isPin || registry != one.registry || bits != one.bits {
			t.Errorf("%q read as (%q, %d, %v), want (%q, %d, %v)",
				one.source, registry, bits, isPin, one.registry, one.bits, one.isPin)
		}
	}
}

// TestEveryFramingRegistryCarriesTheCompileTimeWidthPinThatBoundsIt is the derived half of the
// pin block at the top of this file, and it states two things nothing else did.
//
// A registry declared in framing.go with no pin at all is the shape a NEW registry takes, and
// the package wide count cannot see it: pinBlockSizes is one number per file, so a fourth
// registry landing unpinned leaves that number correct. And a pin neutered in place -- the
// conversion replaced by a bare literal -- keeps the count too, which is a survivor this file
// was measured to have rather than a hypothesis about one.
//
// The pin's target width is held to the registry's OWN width rather than to another reading of
// the RFC, because the two ends are already joined:
// TestTheFramingRegistriesAreTheWidthsTheWireFormatGivesThem holds the type's width to the
// number RFC 9420 gives it, and this holds the pin to the type. A pin converting to a width
// wider than its type compiles, says only that the maximum FITS, and goes on compiling through
// the widening it exists to refuse.
func TestEveryFramingRegistryCarriesTheCompileTimeWidthPinThatBoundsIt(t *testing.T) {
	declared := framingRegistries(t)
	pins := framingWidthPins(t, framingTestFile)
	if got := slices.Sorted(maps.Keys(pins)); !slices.Equal(got, declared) {
		t.Fatalf("%s pins the widths of %v and %s declares the registries %v; a registry with no pin is one a widening does not stop compiling, and a pin naming a type that is no registry here is a pin on nothing",
			framingTestFile, got, framingFile, declared)
	}
	for _, name := range declared {
		if want := framingRegistryBits(t, name); pins[name] != want {
			t.Errorf("%s is declared %d bits wide and its compile time pin converts to uint%d; a pin no tighter than its own type still compiles after the widening it exists to refuse",
				name, want, pins[name])
		}
	}
	t.Logf("%d framing registries, each bounded above by a pin of its own width", len(declared))
}

// TestTheFramingRegistriesAreTheWidthsTheWireFormatGivesThem is the lower half, which the
// conversions above cannot give: they hold that the type is no WIDER, and this holds that it is
// no narrower. A registry read at fewer octets than the encoding writes moves every field after
// it in the message.
func TestTheFramingRegistriesAreTheWidthsTheWireFormatGivesThem(t *testing.T) {
	measured := []string{}
	for _, one := range []struct {
		name       string
		codePoints int
		want       int
	}{
		{"ContentType", int(^ContentType(0)) + 1, 256},
		{"SenderType", int(^SenderType(0)) + 1, 256},
		{"WireFormat", int(^WireFormat(0)) + 1, 65536},
	} {
		measured = append(measured, one.name)
		if one.codePoints != one.want {
			t.Errorf("%s holds %d code points and RFC 9420 section 6 gives it %d",
				one.name, one.codePoints, one.want)
		}
	}
	// the sweep above has to name its types, because int(^T(0)) is a conversion the compiler
	// resolves and there is no writing it over a name derived at run time. What CAN be derived
	// is the set it was supposed to cover, so the enumeration is joined to it here: a fourth
	// registry declared in framing.go fails this rather than being a width nothing measures.
	slices.Sort(measured)
	if declared := framingRegistries(t); !slices.Equal(measured, declared) {
		t.Errorf("this sweep measures the widths of %v and %s declares the registries %v; a registry it does not measure is one nothing holds to a lower bound",
			measured, framingFile, declared)
	}
}

// ---------------------------------------------------------------------------
// the framing registries, joined to the RFC by name and out of two readings
// ---------------------------------------------------------------------------

// rfc9420FramingCodePoints is what RFC 9420 assigns the three framing registries, keyed by the
// RFC's OWN name for each code point rather than by the Go identifier that carries it:
// WireFormat out of the section 17 IANA "MLS Wire Formats" registry, ContentType and SenderType
// out of the enum bodies section 6 writes beside FramedContent and Sender.
//
// Keyed by the RFC's name because the join below is BY NAME, and that is the whole of what
// makes this more than a restatement of framing.go. A table keyed by Go identifier can only
// ever agree with whatever the person who wrote the constants believed. This project has the
// receipt: ExtensionTypeExternalSenders shipped at external_pub's 0x0004, and the pin written
// to catch exactly that -- transcribed by the same person out of the same RFC section --
// agreed with the same misreading and passed.
var rfc9420FramingCodePoints = map[string]map[string]uint64{
	"WireFormat": {
		"mls_public_message":  0x0001,
		"mls_private_message": 0x0002,
		"mls_welcome":         0x0003,
		"mls_group_info":      0x0004,
		"mls_key_package":     0x0005,
	},
	"ContentType": {
		"application": 1,
		"proposal":    2,
		"commit":      3,
	},
	"SenderType": {
		"member":              1,
		"external":            2,
		"new_member_proposal": 3,
		"new_member_commit":   4,
	},
}

// rfc9420FramingRegistryPrefix is the prefix the RFC's spelling carries that the Go name does
// not. The wire format registry writes mls_public_message; this package writes
// WireFormatPublicMessage, because the type name already says which protocol it belongs to.
// Stated as data, once, rather than folded into each table entry, so the correspondence is one
// claim that can be read rather than five that can disagree.
var rfc9420FramingRegistryPrefix = map[string]string{"WireFormat": "mls_"}

// rfcNameOfFramingConstant is rfcNameOfRegistryConstant plus that prefix.
func rfcNameOfFramingConstant(typeName string, constantName string) string {
	return rfc9420FramingRegistryPrefix[typeName] + rfcNameOfRegistryConstant(typeName, constantName)
}

// TestEveryFramingRegistryHoldsTheCodePointsRfc9420Assigns joins this package's declared
// constants to the RFC's table by NAME, in both directions at once.
//
// Both directions matter and neither implies the other. A table richer than the source names a
// code point nothing declares; a source richer than the table is a constant no gate checks,
// which is how a swapped pair survives -- and a swapped pair is not a type error, is not a
// round trip failure, and is byte exact against any corpus this implementation produced.
func TestEveryFramingRegistryHoldsTheCodePointsRfc9420Assigns(t *testing.T) {
	// the set of registries first, because the table's KEYS were the hand written part of this
	// gate and a registry absent from them was joined to the RFC by nothing. That is the loud
	// case, in extension_test.go's words, because it is the shape a new registry takes.
	declared := framingRegistries(t)
	if got := slices.Sorted(maps.Keys(rfc9420FramingCodePoints)); !slices.Equal(got, declared) {
		t.Fatalf("rfc9420FramingCodePoints holds %v and %s declares the registries %v; a registry with no entry is one whose code points nothing here reads",
			got, framingFile, declared)
	}
	for _, typeName := range declared {
		derived := registryConstantsOfType(t, typeName)
		byRfcName := map[string]uint64{}
		for _, name := range slices.Sorted(maps.Keys(derived)) {
			rfcName := rfcNameOfFramingConstant(typeName, name)
			if _, clash := byRfcName[rfcName]; clash {
				t.Fatalf("two constants of %s spell the RFC name %s, so the join below cannot tell them apart",
					typeName, rfcName)
			}
			byRfcName[rfcName] = derived[name]
		}
		if want := rfc9420FramingCodePoints[typeName]; !maps.Equal(byRfcName, want) {
			t.Errorf("%s declares\n %v\nand RFC 9420 assigns\n %v", typeName, byRfcName, want)
		}
	}
}

// rfc9420SelectArmOrder is a SECOND reading of two of those registries, out of a different part
// of the RFC and carrying no numbers at all.
//
// RFC 9420 section 6.1 writes the arms of MLSMessage's select and of FramedContent's select in
// registry order, beginning at the first non-reserved code point. That is an ORDER rather than
// a table of values, so it cannot be a second transcription of the same numbers -- which is
// exactly what makes joining it to the table above worth doing. Every transposition of two code
// points in either registry fails here, including the ones no golden in this task can see
// because no codec here writes them yet.
//
// SenderType is deliberately absent, and saying so is more useful than a table that pretended
// otherwise: section 6 writes the Sender select's arms in the order member, external,
// new_member_commit, new_member_proposal, which is NOT the enum's order, so there is no
// ordering statement to join. rfc9420SenderSelectPayloads below is SenderType's second reading
// instead, and it is a weaker one -- it separates the arms that carry a uint32 from the arms
// that carry nothing, so it catches every swap ACROSS that boundary and no swap within it.
// What that leaves open is stated plainly rather than hidden: member against external, and
// new_member_proposal against new_member_commit, rest on one sentence of RFC 9420 in this
// package today, and the vendored message-protection and messages vectors are the outside
// oracle that will close them.
var rfc9420SelectArmOrder = map[string][]string{
	"WireFormat":  {"mls_public_message", "mls_private_message", "mls_welcome", "mls_group_info", "mls_key_package"},
	"ContentType": {"application", "proposal", "commit"},
}

// framingRegistriesWithNoSelectArmOrder is the registries section 6.1 states no ordering for,
// each against the reason there is none.
//
// A waiver rather than an omission, and written where a derivation can see it. The set this
// second reading covered used to be the keys of rfc9420SelectArmOrder alone, so "SenderType is
// deliberately absent" was a sentence in a comment and nothing more -- and a FOURTH registry
// absent for no reason at all read exactly the same to every gate in this file. The two lists
// together must be every registry framing.go declares, which makes leaving one out a sentence
// somebody has to write rather than a line somebody does not.
var framingRegistriesWithNoSelectArmOrder = map[string]string{
	"SenderType": "section 6 writes the Sender select's arms member, external, new_member_commit, " +
		"new_member_proposal, which is not the enum's order, so there is no ordering statement to " +
		"join; rfc9420SenderSelectPayloads is SenderType's second reading instead",
}

// TestTheFramingRegistriesRunInTheOrderSection61WritesTheirArms is that join.
func TestTheFramingRegistriesRunInTheOrderSection61WritesTheirArms(t *testing.T) {
	declared := framingRegistries(t)
	ordered := slices.Sorted(maps.Keys(rfc9420SelectArmOrder))
	waived := slices.Sorted(maps.Keys(framingRegistriesWithNoSelectArmOrder))
	for _, typeName := range ordered {
		if _, alsoWaived := framingRegistriesWithNoSelectArmOrder[typeName]; alsoWaived {
			t.Fatalf("%s is both given an arm order and waived from having one, so the two lists do not partition the registries",
				typeName)
		}
	}
	for _, typeName := range waived {
		if strings.TrimSpace(framingRegistriesWithNoSelectArmOrder[typeName]) == "" {
			t.Errorf("%s is waived from this join with no reason written; a waiver nobody had to justify is an omission wearing a table entry",
				typeName)
		}
	}
	accounted := slices.Concat(ordered, waived)
	slices.Sort(accounted)
	if !slices.Equal(accounted, declared) {
		t.Fatalf("%s declares the registries %v; section 6.1's arm order is joined for %v and waived for %v, and a registry in neither list is one this second reading never sees",
			framingFile, declared, ordered, waived)
	}
	for _, typeName := range ordered {
		arms := rfc9420SelectArmOrder[typeName]
		derived := registryConstantsOfType(t, typeName)
		byRfcName := map[string]uint64{}
		for name, value := range derived {
			byRfcName[rfcNameOfFramingConstant(typeName, name)] = value
		}
		if len(byRfcName) != len(arms) {
			t.Errorf("%s declares %d code points and section 6.1 writes %d arms for it: %v against %v",
				typeName, len(byRfcName), len(arms), slices.Sorted(maps.Keys(byRfcName)), arms)
		}
		for at, arm := range arms {
			value, declared := byRfcName[arm]
			if !declared {
				t.Errorf("section 6.1 writes a %s arm for %s and this package declares no constant that spells it",
					arm, typeName)
				continue
			}
			if want := uint64(at + 1); value != want {
				t.Errorf("%s is the %s %s arm section 6.1 writes, so its code point is %d, and this package declares it at %d",
					arm, ordinalOfSelectArm(at), typeName, want, value)
			}
		}
	}
}

func ordinalOfSelectArm(at int) string {
	for ordinal, name := range []string{"first", "second", "third", "fourth", "fifth"} {
		if ordinal == at {
			return name
		}
	}
	return fmt.Sprintf("%dth", at+1)
}

// rfc9420SenderSelectPayloads is the Sender select of RFC 9420 section 6, read as the number of
// octets each arm carries AFTER the sender_type:
//
//	case member:              uint32 leaf_index      4
//	case external:            uint32 sender_index    4
//	case new_member_commit:                          0
//	case new_member_proposal:                        0
//
// Keyed by the RFC's name and joined against what this package's encoder actually emits, so a
// sender type standing at an arm's code point while carrying a different payload fails here.
var rfc9420SenderSelectPayloads = map[string]int{
	"member":              4,
	"external":            4,
	"new_member_proposal": 0,
	"new_member_commit":   0,
}

// TestEverySenderArmCarriesThePayloadSection6GivesIt measures the payload off the encoder
// rather than reading it out of framing.go, so what it states is a fact about behaviour.
func TestEverySenderArmCarriesThePayloadSection6GivesIt(t *testing.T) {
	derived := registryConstantsOfType(t, "SenderType")
	measured := map[string]int{}
	for _, name := range slices.Sorted(maps.Keys(derived)) {
		encoded, err := syntax.Marshal(testSenderOfType(SenderType(derived[name])))
		if err != nil {
			t.Fatalf("%s: Marshal: %v", name, err)
		}
		if len(encoded) < 1 {
			t.Fatalf("%s: encoded to nothing, so it wrote no discriminant", name)
		}
		if uint64(encoded[0]) != derived[name] {
			t.Errorf("%s: the encoding leads with %#02x and the constant is %#02x",
				name, encoded[0], uint8(derived[name]))
		}
		measured[rfcNameOfFramingConstant("SenderType", name)] = len(encoded) - 1
	}
	if !maps.Equal(measured, rfc9420SenderSelectPayloads) {
		t.Errorf("the Sender encoder writes payloads\n %v\nand RFC 9420 section 6's select gives\n %v",
			measured, rfc9420SenderSelectPayloads)
	}
}

// ---------------------------------------------------------------------------
// the value every golden and every sweep below is built from
// ---------------------------------------------------------------------------

// testSenderOfType is one Sender with BOTH variant fields populated, and populated
// DIFFERENTLY.
//
// Both halves of that matter. Two uint32 fields holding the same octets are encoded identically
// by a codec that wrote one of them twice and by one that swapped them, so the goldens would
// pin nothing -- and LeafIndex and SenderIndex are adjacent fields of the same width, which is
// the one shape five plans of codecs on this project have found no round trip property can see.
// Populating both under EVERY sender type is what the "encoded under the wrong arm" mutation
// needs as well: under new_member_proposal this value carries a leaf index and a sender index
// that must not appear in its encoding at all.
func testSenderOfType(senderType SenderType) *Sender {
	return &Sender{SenderType: senderType, LeafIndex: 0x11223344, SenderIndex: 0x55667788}
}

// senderTypes is the class every sweep below runs over, derived off the type through the
// package's own type checker rather than listed. A fifth sender type declared and left out of a
// hand written list is a sender type nothing here judges.
func senderTypes(t *testing.T) []SenderType {
	t.Helper()
	derived := registryConstantsOfType(t, "SenderType")
	found := []SenderType{}
	for _, value := range derived {
		found = append(found, SenderType(value))
	}
	slices.Sort(found)
	return found
}

// senderVariantPaths is the RFC 9420 section 6 select, written as the field each arm carries.
// The discriminant is not in it: it is written under every arm and belongs to none of them.
var senderVariantPaths = map[SenderType][]string{
	SenderTypeMember:            {"LeafIndex"},
	SenderTypeExternal:          {"SenderIndex"},
	SenderTypeNewMemberProposal: {},
	SenderTypeNewMemberCommit:   {},
}

// senderDiscriminantField is the one field of Sender that is not a variant arm.
const senderDiscriminantField = "SenderType"

// TestTheSenderVariantTableCoversTheTypeAndTheRegistry holds the table above to the two things
// it is a claim about: the declared sender types, and the fields Sender actually has.
//
// Without this the table is a list, and a list is the exemption shape this project keeps
// rediscovering -- a fifth sender type, or a fourth field, silently outside every sweep that
// runs off it.
func TestTheSenderVariantTableCoversTheTypeAndTheRegistry(t *testing.T) {
	declared := senderTypes(t)
	tabled := []SenderType{}
	for senderType := range senderVariantPaths {
		tabled = append(tabled, senderType)
	}
	slices.Sort(tabled)
	if !slices.Equal(declared, tabled) {
		t.Fatalf("the package declares the sender types %v and the variant table covers %v", declared, tabled)
	}
	structType := reflect.TypeOf(Sender{})
	claimed := map[string]int{}
	for _, paths := range senderVariantPaths {
		for _, path := range paths {
			claimed[path] += 1
		}
	}
	for i := 0; i < structType.NumField(); i += 1 {
		name := structType.Field(i).Name
		if name == senderDiscriminantField {
			if claimed[name] != 0 {
				t.Errorf("%s is the discriminant and the variant table lists it as an arm's payload", name)
			}
			delete(claimed, name)
			continue
		}
		switch claimed[name] {
		case 1:
		case 0:
			t.Errorf("Sender.%s is carried by no arm of the variant table, so every sweep run off that table skips it",
				name)
		default:
			t.Errorf("Sender.%s is carried by %d arms of the variant table, and the RFC's select gives each field one",
				name, claimed[name])
		}
		delete(claimed, name)
	}
	for name := range claimed {
		t.Errorf("the variant table names %s and Sender has no such field", name)
	}
}

// ---------------------------------------------------------------------------
// the hand derived goldens
// ---------------------------------------------------------------------------

// handDerivedSenderGolden is one Sender's encoding written out from RFC 9420 section 6 rather
// than read back through the encoder:
//
//	sender_type            uint8                                          1
//	select (member):       uint32 leaf_index    -> 11223344               4
//	select (external):     uint32 sender_index  -> 55667788               4
//	select (new_member_proposal), (new_member_commit):  nothing           0
//
//	member               1 + 4 = 5
//	external             1 + 4 = 5
//	new_member_proposal  1 + 0 = 1
//	new_member_commit    1 + 0 = 1
//
// This is the one test in this file that a symmetric edit cannot survive. Two adjacent
// same-width fields swapped in BOTH halves of the codec round trip perfectly, re-encode byte
// exact, and are invisible to every other property here; so is a field dropped from both
// halves. What separates them is a statement of the encoding written without reference to the
// code, which is what this is.
//
// The octet beside each case name is also what makes an enum transposition visible at the
// codec: the switch is over the CONSTANT and the literal is the RFC's number for that name, so
// two sender types whose values were swapped encode to each other's goldens and fail here.
func handDerivedSenderGolden(senderType SenderType) []byte {
	switch senderType {
	case SenderTypeMember:
		return []byte{0x01, 0x11, 0x22, 0x33, 0x44}
	case SenderTypeExternal:
		return []byte{0x02, 0x55, 0x66, 0x77, 0x88}
	case SenderTypeNewMemberProposal:
		return []byte{0x03}
	case SenderTypeNewMemberCommit:
		return []byte{0x04}
	}
	return nil
}

// handDerivedSenderSizes is the arithmetic in the comment above, stated separately so a
// derivation edited without its comment fails rather than redefining what it is compared to.
var handDerivedSenderSizes = map[SenderType]int{
	SenderTypeMember:            5,
	SenderTypeExternal:          5,
	SenderTypeNewMemberProposal: 1,
	SenderTypeNewMemberCommit:   1,
}

// decodedFormOfSender is what a decode of this sender must produce: the same value with the
// arms the sender type does not carry left at their zero. Derived from the variant table the
// test above holds to the type, so a decoder that filled a field its arm does not carry fails
// without anybody writing a case for it.
func decodedFormOfSender(t *testing.T, sender *Sender) *Sender {
	t.Helper()
	out := *sender
	value := reflect.ValueOf(&out).Elem()
	for senderType, paths := range senderVariantPaths {
		if senderType == sender.SenderType {
			continue
		}
		for _, path := range paths {
			field := value.FieldByName(path)
			if !field.IsValid() {
				t.Fatalf("the variant table names %s and Sender has no such field", path)
			}
			field.Set(reflect.Zero(field.Type()))
		}
	}
	return &out
}

func sameSender(a *Sender, b *Sender) bool {
	return reflect.DeepEqual(a, b)
}

func describeSender(sender *Sender) string {
	return fmt.Sprintf("sender_type=%d leaf_index=%#08x sender_index=%#08x",
		sender.SenderType, uint32(sender.LeafIndex), sender.SenderIndex)
}

// TestSenderMarshalMatchesTheHandDerivedGoldens is the field order and width pin.
func TestSenderMarshalMatchesTheHandDerivedGoldens(t *testing.T) {
	for _, senderType := range senderTypes(t) {
		want := handDerivedSenderGolden(senderType)
		if want == nil {
			t.Fatalf("sender type %d has no hand derived golden, so nothing states its encoding", senderType)
		}
		size, stated := handDerivedSenderSizes[senderType]
		if !stated {
			t.Fatalf("sender type %d has no hand derived size, so its derivation is compared only against itself",
				senderType)
		}
		if len(want) != size {
			t.Fatalf("sender type %d: the hand derivation is %d octets and the arithmetic in its comment says %d",
				senderType, len(want), size)
		}
		encoded, err := syntax.Marshal(testSenderOfType(senderType))
		if err != nil {
			t.Fatalf("sender type %d: Marshal: %v", senderType, err)
		}
		if !bytes.Equal(encoded, want) {
			t.Errorf("sender type %d: Marshal =\n %x\nwant\n %x", senderType, encoded, want)
		}
		decoded := &Sender{}
		if err := syntax.Unmarshal(want, decoded); err != nil {
			t.Fatalf("sender type %d: Unmarshal the golden: %v", senderType, err)
		}
		if expected := decodedFormOfSender(t, testSenderOfType(senderType)); !sameSender(decoded, expected) {
			t.Errorf("sender type %d: the golden decoded to\n %s\nwant\n %s",
				senderType, describeSender(decoded), describeSender(expected))
		}
	}
}

// TestSenderRoundTripEveryType compares the WHOLE decoded value against the original rather
// than the two fields a hand written case would have listed.
//
// The comparison is against the derived expected form and it runs over the derived class, so an
// arm added without a case is swept and a field left standing under an arm that does not carry
// it fails. The whole-value half is what a field dropped from BOTH halves of the codec needs:
// that drop re-encodes byte exact against itself and is simply lost.
func TestSenderRoundTripEveryType(t *testing.T) {
	for _, senderType := range senderTypes(t) {
		in := testSenderOfType(senderType)
		encoded, err := syntax.Marshal(in)
		if err != nil {
			t.Fatalf("sender type %d: Marshal: %v", senderType, err)
		}
		out := &Sender{}
		if err := syntax.Unmarshal(encoded, out); err != nil {
			t.Fatalf("sender type %d: Unmarshal: %v", senderType, err)
		}
		if want := decodedFormOfSender(t, testSenderOfType(senderType)); !sameSender(out, want) {
			t.Errorf("sender type %d: round trip gave\n %s\nwant\n %s",
				senderType, describeSender(out), describeSender(want))
		}
		reencoded, err := syntax.Marshal(out)
		if err != nil {
			t.Fatalf("sender type %d: re-Marshal: %v", senderType, err)
		}
		if !bytes.Equal(reencoded, encoded) {
			t.Errorf("sender type %d: re-encode =\n %x\nwant\n %x", senderType, reencoded, encoded)
		}
	}
}

// TestTheSenderCodecWritesEveryFieldItsArmCarriesAndNoOther sweeps the fields off the TYPE and
// the carriage off the variant table, so neither is a list somebody kept up to date.
//
// This is the property a golden cannot state on its own: the golden says what the bytes are for
// one value, and this says that each field is what those bytes are a function of. A field
// dropped from the encoder is caught by both; a field written under an arm that does not carry
// it is caught here for every arm at once.
func TestTheSenderCodecWritesEveryFieldItsArmCarriesAndNoOther(t *testing.T) {
	structType := reflect.TypeOf(Sender{})
	observed := map[string]bool{}
	for _, senderType := range senderTypes(t) {
		base, err := syntax.Marshal(testSenderOfType(senderType))
		if err != nil {
			t.Fatalf("sender type %d: Marshal: %v", senderType, err)
		}
		for i := 0; i < structType.NumField(); i += 1 {
			name := structType.Field(i).Name
			if name == senderDiscriminantField {
				continue
			}
			varied := testSenderOfType(senderType)
			field := reflect.ValueOf(varied).Elem().Field(i)
			field.SetUint(field.Uint() ^ 0x0a0b0c0d)
			encoded, err := syntax.Marshal(varied)
			if err != nil {
				t.Fatalf("sender type %d: Marshal with %s varied: %v", senderType, name, err)
			}
			changed := !bytes.Equal(encoded, base)
			carried := slices.Contains(senderVariantPaths[senderType], name)
			if carried && !changed {
				t.Errorf("sender type %d carries %s and varying it left the encoding at %x, so nothing writes it",
					senderType, name, encoded)
			}
			if !carried && changed {
				t.Errorf("sender type %d does not carry %s and varying it changed the encoding to %x",
					senderType, name, encoded)
			}
			observed[name] = observed[name] || changed
		}
	}
	for i := 0; i < structType.NumField(); i += 1 {
		name := structType.Field(i).Name
		if name == senderDiscriminantField {
			continue
		}
		if !observed[name] {
			t.Errorf("%s changed no encoding under any declared sender type, so nothing in this package writes it",
				name)
		}
	}
	// the discriminant is covered by the goldens rather than by the sweep, and that has to be
	// true rather than assumed: every golden leads with a different octet.
	leading := map[byte]SenderType{}
	for _, senderType := range senderTypes(t) {
		golden := handDerivedSenderGolden(senderType)
		if len(golden) == 0 {
			t.Fatalf("sender type %d has no golden", senderType)
		}
		if other, clash := leading[golden[0]]; clash {
			t.Errorf("sender types %d and %d both lead with %#02x, so the discriminant is not what separates them",
				other, senderType, golden[0])
		}
		leading[golden[0]] = senderType
	}
}

// ---------------------------------------------------------------------------
// the refusals
// ---------------------------------------------------------------------------

// undeclaredSenderTypeOctets is every octet the SenderType registry does not name, derived over
// the width of the type against the declared set rather than over the three values a hand
// written case would have probed. The reserved zero is one of them and is not special: it is
// undeclared, and so is 0x05, and so is 0xff.
func undeclaredSenderTypeOctets(t *testing.T) []byte {
	t.Helper()
	declared := senderTypes(t)
	found := []byte{}
	for candidate := 0; candidate <= 0xff; candidate += 1 {
		if slices.Contains(declared, SenderType(candidate)) {
			continue
		}
		found = append(found, byte(candidate))
	}
	if len(found)+len(declared) != int(^SenderType(0))+1 {
		t.Fatalf("the derivation split %d code points into %d declared and %d undeclared",
			int(^SenderType(0))+1, len(declared), len(found))
	}
	return found
}

// TestSenderRejectsReservedAndUnknownType sweeps the whole octet space rather than the three
// values the plan probed, and states the refusal on BOTH halves of the codec.
//
// The encode half is not decoration. The sender type is inside every signature preimage this
// layer builds, so an encoder that wrote an unregistered one would produce signed bytes no peer
// can attribute to anybody; and an encoder whose default arm fell through to writing the octet
// is exactly the shape that survives a decode-only test.
//
// Each undeclared octet is offered twice, bare and with a four octet tail, so a refusal that was
// really a truncation cannot pass for a refusal of the TYPE: the tail case has bytes to spare
// and must still name ErrUnknownSenderType.
func TestSenderRejectsReservedAndUnknownType(t *testing.T) {
	undeclared := undeclaredSenderTypeOctets(t)
	if !slices.Contains(undeclared, 0x00) {
		t.Fatal("0 is declared as a sender type, and RFC 9420 section 6 reserves it")
	}
	for _, octet := range undeclared {
		for _, encoded := range [][]byte{{octet}, {octet, 0xde, 0xad, 0xbe, 0xef}} {
			decoded := &Sender{}
			err := syntax.Unmarshal(encoded, decoded)
			if !errors.Is(err, ErrUnknownSenderType) {
				t.Fatalf("decoding %x: got %v, want ErrUnknownSenderType", encoded, err)
			}
		}
		unencodable := &Sender{SenderType: SenderType(octet), LeafIndex: 1, SenderIndex: 2}
		if _, err := syntax.Marshal(unencodable); !errors.Is(err, ErrUnknownSenderType) {
			t.Fatalf("encoding sender type %#02x: got %v, want ErrUnknownSenderType", octet, err)
		}
	}
	t.Logf("%d undeclared sender type octets refused on both halves of the codec", len(undeclared))
}

// TestSenderRejectsATruncatedArm states the other refusal the decoder can make, over every
// proper prefix of every golden rather than over the boundaries somebody thought of.
func TestSenderRejectsATruncatedArm(t *testing.T) {
	cuts := 0
	for _, senderType := range senderTypes(t) {
		golden := handDerivedSenderGolden(senderType)
		for cut := 0; cut < len(golden); cut += 1 {
			decoded := &Sender{}
			if err := syntax.Unmarshal(golden[:cut], decoded); err == nil {
				t.Errorf("sender type %d: %d of %d octets decoded rather than being refused",
					senderType, cut, len(golden))
				continue
			}
			cuts += 1
		}
	}
	if cuts == 0 {
		t.Fatal("no truncation was built, so this observed nothing")
	}
	t.Logf("%d truncations refused", cuts)
}

// TestSenderRefusesTrailingBytes is the full consumption half, and Sender was the one codec
// landed in this package with no statement of it: LeafNode, GroupContext, Extension,
// Capabilities and RequiredCapabilities each have one and this file had none.
//
// Neither refusal already here says it. TestSenderRejectsATruncatedArm runs over proper
// PREFIXES, which is the other side of the length; and the four octet tail in
// TestSenderRejectsReservedAndUnknownType is offered only under UNDECLARED discriminants, where
// the decoder's own default arm answers before full consumption is ever reached. What was left
// unstated is the case with teeth: a VALID sender followed by a stray octet. The sender type
// and its arm are inside every signature preimage this layer builds, so a decoder tolerating a
// tail accepts two encodings of one sender while a signature covers only one of them.
//
// The refusal comes from syntax.UnmarshalLimit joining r.Done() rather than from anything in
// framing.go, which is exactly why it is worth stating here: dropping that join left this
// file's seventeen tests green and failed four OTHER codecs' -- so this layer was being carried
// by tests that name somebody else's type.
func TestSenderRefusesTrailingBytes(t *testing.T) {
	stated := 0
	for _, senderType := range senderTypes(t) {
		golden := handDerivedSenderGolden(senderType)
		for _, tail := range [][]byte{{0x00}, {0xff}, {0x00, 0x00}, repeatByte(0x5a, 17)} {
			longer := joinBytes(golden, tail)
			decoded := &Sender{}
			if err := syntax.Unmarshal(longer, decoded); !errors.Is(err, syntax.ErrTrailingBytes) {
				t.Errorf("sender type %d with %d trailing octets (%x): err = %v, want syntax.ErrTrailingBytes",
					senderType, len(tail), longer, err)
				continue
			}
			stated += 1
		}
	}
	if stated == 0 {
		t.Fatal("no tailed encoding was refused, so this observed nothing")
	}
	t.Logf("%d tailed encodings refused over %d sender types", stated, len(senderTypes(t)))
}

// senderPriorContents is every state a receiver can arrive in that this file can build: the
// zero sender, and one of every declared type. Derived over the class rather than over the one
// prior somebody picks, because the failure is per PAIR -- only a receiver that already held an
// arm's payload can leave that payload standing under a type that does not carry it.
func senderPriorContents(t *testing.T) []*Sender {
	t.Helper()
	priors := []*Sender{{}}
	for _, senderType := range senderTypes(t) {
		priors = append(priors, testSenderOfType(senderType))
	}
	return priors
}

// TestASenderDecodesToTheSameValueWhateverItsReceiverHeld is not a round trip property.
//
// The arms of the decoder assign only the field their own type carries, so a decoder that wrote
// through its receiver as it read leaves the PREVIOUS sender's LeafIndex standing under
// external, or its SenderIndex standing under member. The bytes are unaffected -- the stale
// field is not written under the new arm -- so it round trips, re-encodes byte exact and agrees
// with every golden here. What it disagrees with is the same bytes decoded into a fresh
// receiver, which is a sender comparing unequal to itself depending on where it was decoded.
func TestASenderDecodesToTheSameValueWhateverItsReceiverHeld(t *testing.T) {
	priors := senderPriorContents(t)
	for _, senderType := range senderTypes(t) {
		encoded := handDerivedSenderGolden(senderType)
		fresh := &Sender{}
		if err := syntax.Unmarshal(encoded, fresh); err != nil {
			t.Fatalf("sender type %d: Unmarshal into a fresh receiver: %v", senderType, err)
		}
		for at, prior := range priors {
			reused := *prior
			if err := syntax.Unmarshal(encoded, &reused); err != nil {
				t.Fatalf("sender type %d: Unmarshal into a receiver holding prior %d: %v", senderType, at, err)
			}
			if !sameSender(&reused, fresh) {
				t.Errorf("sender type %d: decoding into a receiver that held\n %s\ngave\n %s\nand the same bytes decoded fresh give\n %s",
					senderType, describeSender(prior), describeSender(&reused), describeSender(fresh))
			}
		}
	}
	t.Logf("%d prior receiver contents over %d sender types", len(priors), len(senderTypes(t)))
}

// senderRefusedEncodingsOf is every input this file can build that a decode must refuse: every
// proper prefix of a golden, and every golden under every octet the registry does not name.
func senderRefusedEncodingsOf(t *testing.T, senderType SenderType) [][]byte {
	t.Helper()
	golden := handDerivedSenderGolden(senderType)
	inputs := [][]byte{}
	for cut := 0; cut < len(golden); cut += 1 {
		inputs = append(inputs, golden[:cut])
	}
	for _, octet := range undeclaredSenderTypeOctets(t) {
		altered := bytes.Clone(golden)
		altered[0] = octet
		inputs = append(inputs, altered)
	}
	return inputs
}

// TestARefusedSenderDecodeLeavesItsReceiverUntouched is the discipline Credential and LeafNode
// already keep, stated for the third decoder of this package so the three do not disagree about
// it with only two of them tested.
//
// A decoder that wrote its fields as it read them would leave a receiver holding a sender type
// out of a message this package REFUSED -- a value that never existed anywhere, assembled out of
// the first octet of somebody else's bytes, sitting in a variable the caller may well reuse,
// with nothing in the returned error saying so.
func TestARefusedSenderDecodeLeavesItsReceiverUntouched(t *testing.T) {
	priors := senderPriorContents(t)
	refused, accepted := 0, 0
	for _, senderType := range senderTypes(t) {
		for _, input := range senderRefusedEncodingsOf(t, senderType) {
			for _, prior := range priors {
				held := *prior
				before := *prior
				if err := syntax.Unmarshal(input, &held); err == nil {
					accepted += 1
					continue
				}
				refused += 1
				if sameSender(&held, &before) {
					continue
				}
				t.Errorf("sender type %d: a refused decode of %x into a receiver that held\n %s\nwrote through it, leaving\n %s",
					senderType, input, describeSender(&before), describeSender(&held))
				return
			}
		}
	}
	if accepted != 0 {
		t.Errorf("%d of the inputs this sweep built decoded rather than being refused, so the property was never stated over them",
			accepted)
	}
	if refused == 0 {
		t.Fatal("no input was refused, so this observed nothing")
	}
	t.Logf("%d refused decodes over %d prior receiver contents left the receiver exactly as they found it",
		refused, len(priors))
}

// ---------------------------------------------------------------------------
// the structural framing errors
// ---------------------------------------------------------------------------

// framingErrorsFile is the single file this plan declares its structural errors in. Every gate
// below derives its class from that file rather than from the list, which is the difference
// between sweeping the class and sweeping a copy of it.
const framingErrorsFile = "framing_errors.go"

// framingOwnedErrors is every name framing_errors.go declares, keyed by that name so the
// derivation below can compare the two sets. Nothing here is trusted:
// TestFramingOwnedErrorsIsEveryDeclarationOfItsFile holds it to what the file actually declares,
// in both directions.
var framingOwnedErrors = map[string]error{
	"ErrUnknownWireFormat":        ErrUnknownWireFormat,
	"ErrUnsupportedVersion":       ErrUnsupportedVersion,
	"ErrUnknownSenderType":        ErrUnknownSenderType,
	"ErrContentArmMismatch":       ErrContentArmMismatch,
	"ErrMissingGroupContext":      ErrMissingGroupContext,
	"ErrUnexpectedGroupContext":   ErrUnexpectedGroupContext,
	"ErrWireFormatMismatch":       ErrWireFormatMismatch,
	"ErrSenderNotMember":          ErrSenderNotMember,
	"ErrInvalidPaddingSize":       ErrInvalidPaddingSize,
	"ErrUnknownProposalOrRefType": ErrUnknownProposalOrRefType,
}

// TestFramingOwnedErrorsIsEveryDeclarationOfItsFile derives the class the sweeps below run over
// instead of trusting the transcription of it. An eleventh error declared in that file and left
// off the list is judged by neither sweep, and a count assertion cannot close that because it
// has the wrong polarity: it fails on adding an error and REMEMBERING the list.
func TestFramingOwnedErrorsIsEveryDeclarationOfItsFile(t *testing.T) {
	declared := packageLevelDeclarations(t, ".")
	fromFile := map[string]bool{}
	for name, file := range declared {
		if file == framingErrorsFile {
			fromFile[name] = true
		}
	}
	if len(fromFile) == 0 {
		t.Fatalf("the scan found nothing declared in %s, so this gate compared the list against an empty set",
			framingErrorsFile)
	}
	if !fromFile["ErrUnknownSenderType"] {
		t.Fatalf("the scan did not find ErrUnknownSenderType among the declarations of %s, which certainly declares it, so it is reading something other than that file",
			framingErrorsFile)
	}
	for _, name := range slices.Sorted(maps.Keys(fromFile)) {
		if _, listed := framingOwnedErrors[name]; !listed {
			t.Errorf("%s declares %s and framingOwnedErrors does not list it, so no sweep below judges it; add it there",
				framingErrorsFile, name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(framingOwnedErrors)) {
		if !fromFile[name] {
			t.Errorf("framingOwnedErrors lists %s and %s does not declare it, so the sweeps run over a name this file does not own",
				name, framingErrorsFile)
		}
	}
}

// TestFramingErrorsAreDistinctAndNamed asserts no two of the structural errors alias each other,
// so a caller branching on one cannot be answered yes by another, and that each names the
// package it came from so a caller logging one at a distance can tell.
//
// The count pins the file: a name added to it is a change somebody makes deliberately, in the
// same commit, with a reason. What stops the list shrinking, and what stops it lagging behind
// the file, is the derivation above rather than this number.
//
// Ten, where the interface registry's section 7.6 block names ten structural errors plus the
// p6-private ErrUnknownProposalOrRefType -- eleven. The one that is not here is
// ErrUnknownContentType, which already existed in errors_key_schedule.go before this file did,
// and the test below is where that is held rather than papered over.
func TestFramingErrorsAreDistinctAndNamed(t *testing.T) {
	if len(framingOwnedErrors) != 10 {
		t.Fatalf("this file owns %d errors, want the nine structural ones of registry section 7.6 that were not already declared elsewhere plus the p6-private ErrUnknownProposalOrRefType; if one landed or left, say so here in the same commit",
			len(framingOwnedErrors))
	}
	names := slices.Sorted(maps.Keys(framingOwnedErrors))
	for i, name := range names {
		first := framingOwnedErrors[name]
		if first == nil {
			t.Fatalf("%s is nil", name)
		}
		if first.Error() == "" {
			t.Fatalf("%s has an empty message", name)
		}
		if !strings.HasPrefix(first.Error(), "mls: ") {
			t.Errorf("%s reads %q; every typed error of this package names the package it came from",
				name, first.Error())
		}
		for j, other := range names {
			if i == j {
				continue
			}
			second := framingOwnedErrors[other]
			if errors.Is(first, second) {
				t.Errorf("%s answers to %s (%v), so a caller branching on the two reads one as the other",
					name, other, first)
			}
			if first.Error() == second.Error() {
				t.Errorf("%s and %s both read %q, so the two are indistinguishable in a log",
					name, other, first.Error())
			}
		}
	}
}

// theTenStructuralFramingErrors is registry section 7.6's block, by name, including the one name
// this plan's own file does not declare.
var theTenStructuralFramingErrors = []string{
	"ErrUnknownWireFormat", "ErrUnsupportedVersion", "ErrUnknownContentType", "ErrUnknownSenderType",
	"ErrContentArmMismatch", "ErrMissingGroupContext", "ErrUnexpectedGroupContext",
	"ErrWireFormatMismatch", "ErrSenderNotMember", "ErrInvalidPaddingSize",
}

// TestEveryStructuralFramingErrorHasExactlyOneDeclarationSite is where this task's one deviation
// from its own plan is held.
//
// The plan says framing_errors.go declares all ten. Nine of them it does. The tenth,
// ErrUnknownContentType, was already declared -- in errors_key_schedule.go, by the plan that
// owns the secret tree, because the secret tree is what refuses a content type with no ratchet
// behind it -- and "a content type this package does not register" is ONE condition whether it
// is reached off the wire at the codec or off a header at the ratchet lookup. Two sentinels for
// one condition is precisely what every error roster in this package exists to prevent, so the
// framing layer consumes that declaration rather than shadowing it.
//
// This test is what makes that a decision rather than an accident: each of the ten resolves,
// each has exactly one declaration site, and ErrUnknownContentType's is named. A later framing
// task that adds a second declaration of it fails here instead of quietly splitting the
// condition in two, which is the failure the deviation was taken to avoid.
func TestEveryStructuralFramingErrorHasExactlyOneDeclarationSite(t *testing.T) {
	declared := packageLevelDeclarations(t, ".")
	for _, name := range theTenStructuralFramingErrors {
		file, found := declared[name]
		if !found {
			t.Errorf("registry section 7.6 names %s and this package declares no such error", name)
			continue
		}
		want := framingErrorsFile
		if name == "ErrUnknownContentType" {
			want = "errors_key_schedule.go"
		}
		if file != want {
			t.Errorf("%s is declared in %s, and the single declaration site for it is %s", name, file, want)
		}
	}
	// the sentinel this plan consumes must still be a value of its own against the nine it
	// declares, which is the property the cross-file split could quietly lose.
	for _, name := range slices.Sorted(maps.Keys(framingOwnedErrors)) {
		if errors.Is(framingOwnedErrors[name], ErrUnknownContentType) ||
			errors.Is(ErrUnknownContentType, framingOwnedErrors[name]) {
			t.Errorf("%s and ErrUnknownContentType answer for each other", name)
		}
	}
}

// ---------------------------------------------------------------------------
// FramedContentAuthData
// ---------------------------------------------------------------------------

// contentTypes is the class every auth data sweep below runs over, derived off the type
// through the package's own type checker rather than listed.
//
// Derived for the reason senderTypes is: a fourth content type declared and left out of a hand
// written list is a content type nothing here judges. It matters more here than it does there,
// because the content type is not carried inside a FramedContentAuthData at all -- it is the
// parameter that decides whether a confirmation tag is read -- so an arm nothing sweeps is an
// arm whose tag handling nothing states.
func contentTypes(t *testing.T) []ContentType {
	t.Helper()
	derived := registryConstantsOfType(t, "ContentType")
	found := []ContentType{}
	for _, value := range derived {
		found = append(found, ContentType(value))
	}
	if len(found) == 0 {
		t.Fatal("no ContentType constant was derived, so every sweep below would run over the empty set")
	}
	slices.Sort(found)
	return found
}

// undeclaredContentTypeOctets is every octet the ContentType registry does not name, derived
// over the width of the type against the declared set. The reserved zero is one of them and is
// not special.
func undeclaredContentTypeOctets(t *testing.T) []ContentType {
	t.Helper()
	declared := contentTypes(t)
	found := []ContentType{}
	for candidate := 0; candidate <= 0xff; candidate += 1 {
		if slices.Contains(declared, ContentType(candidate)) {
			continue
		}
		found = append(found, ContentType(candidate))
	}
	if len(found)+len(declared) != int(^ContentType(0))+1 {
		t.Fatalf("the derivation split %d code points into %d declared and %d undeclared",
			int(^ContentType(0))+1, len(declared), len(found))
	}
	return found
}

// testAuthData is the value every sweep below encodes, populated in BOTH fields under EVERY
// content type.
//
// Both halves of that are load bearing. Signature and ConfirmationTag are the same Go type and
// adjacent, which is the shape no round trip property can see: swapped in both halves of the
// codec they round trip perfectly, re-encode byte exact and agree with every structural test
// here. What separates them is the hand derivation below, and it can only separate them because
// the two values have DIFFERENT LENGTHS -- three octets against two -- so a swap moves the
// length prefixes as well as the bodies.
//
// Populating the tag under application and proposal is what the "written under an arm that does
// not carry it" mutation needs: under those two content types this value holds a confirmation
// tag that must not reach the wire at all.
func testAuthData() *FramedContentAuthData {
	return &FramedContentAuthData{
		Signature:       []byte{0x11, 0x22, 0x33},
		ConfirmationTag: []byte{0x44, 0x55},
	}
}

// handDerivedAuthDataGolden is RFC 9420 section 6's FramedContentAuthData written from the wire
// format, not read back out of framing.go.
//
//	struct {
//	    opaque signature<V>;
//	    select (FramedContentAuthData.content_type) {
//	        case commit:
//	            MAC confirmation_tag;   /* opaque<V> */
//	        case application:
//	        case proposal:
//	    };
//	} FramedContentAuthData;
//
// The octet arithmetic, from the varint length prefix p1 implements: a length below 64 has
// prefix bits 00 and occupies one octet.
//
//	signature<V> over 11 22 33   length 3 -> 1 octet 0x03, body 3 octets = 4
//	confirmation_tag<V> over 44 55  length 2 -> 1 octet 0x02, body 2 octets = 3
//
//	application  4 + 0 = 4
//	proposal     4 + 0 = 4
//	commit       4 + 3 = 7
//
// This is the one statement here that a symmetric edit cannot survive, and this structure needs
// it more than Sender did: there is no discriminant octet in these bytes at all, so a codec
// that read the wrong arm produces no type error anywhere and the ONLY thing separating a
// commit's encoding from a proposal's is the three octets at the end.
func handDerivedAuthDataGolden(contentType ContentType) []byte {
	switch contentType {
	case ContentTypeApplication:
		return []byte{0x03, 0x11, 0x22, 0x33}
	case ContentTypeProposal:
		return []byte{0x03, 0x11, 0x22, 0x33}
	case ContentTypeCommit:
		return []byte{0x03, 0x11, 0x22, 0x33, 0x02, 0x44, 0x55}
	}
	return nil
}

// handDerivedAuthDataSizes is the arithmetic in the comment above, stated separately so a
// derivation edited without its comment fails rather than redefining what it is compared to.
var handDerivedAuthDataSizes = map[ContentType]int{
	ContentTypeApplication: 4,
	ContentTypeProposal:    4,
	ContentTypeCommit:      7,
}

// authDataVariantPaths is the section 6 select above, written as the fields each arm carries.
//
// Unlike senderVariantPaths this table has no discriminant field to exclude, and that absence
// is the whole design of the type: the content type is a parameter of the codec rather than a
// field of the struct, so there is nothing in these bytes that says which arm they are.
var authDataVariantPaths = map[ContentType][]string{
	ContentTypeApplication: {"Signature"},
	ContentTypeProposal:    {"Signature"},
	ContentTypeCommit:      {"Signature", "ConfirmationTag"},
}

// registrySection72AuthDataFields is the field list registry section 7.2 fixes, in wire order.
//
// A transcription rather than a derivation, deliberately, because it is a claim ABOUT the
// registry and there is nothing in this tree to derive it from. It is the one place the two
// fields the validation plan asked for and the registry REFUSED -- MembershipTag, which belongs
// to PublicMessage, and HasConfirmationTag, whose answer is derived from the content type -- can
// be kept out by something other than memory.
var registrySection72AuthDataFields = []string{"Signature", "ConfirmationTag"}

// decodedFormOfAuthData is what a decode of this value under this content type must produce:
// the same value with the fields this content type's arm does not carry left at their zero.
// Derived off the variant table the test below holds to the type, so a decoder that filled a
// field its arm does not carry fails without anybody writing a case for it.
func decodedFormOfAuthData(t *testing.T, auth *FramedContentAuthData, contentType ContentType) *FramedContentAuthData {
	t.Helper()
	out := *auth
	value := reflect.ValueOf(&out).Elem()
	carried := authDataVariantPaths[contentType]
	for i := 0; i < value.NumField(); i += 1 {
		name := value.Type().Field(i).Name
		if slices.Contains(carried, name) {
			continue
		}
		value.Field(i).Set(reflect.Zero(value.Field(i).Type()))
	}
	return &out
}

func sameAuthData(a *FramedContentAuthData, b *FramedContentAuthData) bool {
	return reflect.DeepEqual(a, b)
}

// describeAuthData separates a nil field from an empty one, because the two are different
// statements here -- an absent confirmation tag against one this codec refuses -- and %x spells
// both as the empty string.
func describeAuthData(auth *FramedContentAuthData) string {
	return fmt.Sprintf("signature=%s confirmation_tag=%s",
		describeOptionalOctets(auth.Signature), describeOptionalOctets(auth.ConfirmationTag))
}

func describeOptionalOctets(bs []byte) string {
	if bs == nil {
		return "nil"
	}
	return fmt.Sprintf("%x(len %d)", bs, len(bs))
}

// encodeAuthData is the whole encode: a fresh Writer, the codec, and Bytes.
func encodeAuthData(auth *FramedContentAuthData, contentType ContentType) ([]byte, error) {
	w := syntax.NewWriter()
	if err := auth.MarshalMLS(w, contentType); err != nil {
		return nil, err
	}
	return w.Bytes()
}

// decodeAuthData is the whole decode: the codec, and then the full consumption rule.
//
// Done() is part of acceptance rather than an extra assertion at some call sites, and that is
// the decision this structure turns on. A FramedContentAuthData is the tail of every structure
// that carries it, so a tail this codec leaves behind is a tail the enclosing decode refuses --
// and "accepted" has to mean the same thing in the wrong-content-type sweep as it does in the
// round trip, or that sweep would report a commit's confirmation tag silently dropped by a
// proposal decode as a success.
func decodeAuthData(bs []byte, contentType ContentType) (*FramedContentAuthData, error) {
	decoded := &FramedContentAuthData{}
	r := syntax.NewReader(bs)
	if err := decoded.UnmarshalMLS(r, contentType); err != nil {
		return nil, err
	}
	if err := r.Done(); err != nil {
		return nil, err
	}
	return decoded, nil
}

// TestTheAuthDataVariantTableCoversTheTypeAndTheRegistry holds the table to the two things it
// is a claim about: the declared content types, and the fields FramedContentAuthData has.
//
// Without this the table is a list, and a list is the exemption shape this project keeps
// rediscovering -- a fourth content type, or a third field, silently outside every sweep that
// runs off it. The union clause is the one that matters here: there is no discriminant field to
// carve out, so every field of this struct must be carried by some arm, and a field carried by
// none is a field nothing on the wire is a function of.
func TestTheAuthDataVariantTableCoversTheTypeAndTheRegistry(t *testing.T) {
	declared := contentTypes(t)
	tabled := []ContentType{}
	for contentType := range authDataVariantPaths {
		tabled = append(tabled, contentType)
	}
	slices.Sort(tabled)
	if !slices.Equal(declared, tabled) {
		t.Fatalf("the package declares the content types %v and the auth data variant table covers %v",
			declared, tabled)
	}
	structType := reflect.TypeOf(FramedContentAuthData{})
	fields := []string{}
	for i := 0; i < structType.NumField(); i += 1 {
		fields = append(fields, structType.Field(i).Name)
	}
	if !slices.Equal(fields, registrySection72AuthDataFields) {
		t.Fatalf("FramedContentAuthData has the fields %v and registry section 7.2 fixes %v; MembershipTag belongs to PublicMessage and HasConfirmationTag is derived from the content type, so neither may land here",
			fields, registrySection72AuthDataFields)
	}
	claimed := map[string]bool{}
	for contentType, paths := range authDataVariantPaths {
		for _, path := range paths {
			if !slices.Contains(fields, path) {
				t.Errorf("content type %d claims the field %s and FramedContentAuthData has no such field",
					contentType, path)
			}
			claimed[path] = true
		}
	}
	for _, name := range fields {
		if !claimed[name] {
			t.Errorf("%s is carried by no arm of the variant table, so nothing on the wire is a function of it",
				name)
		}
	}
	// the goldens are the other half of the table and are checked here rather than at each
	// call site, so an arm added to the table without one is not swept against nothing.
	for _, contentType := range declared {
		if handDerivedAuthDataGolden(contentType) == nil {
			t.Errorf("content type %d has no hand derived golden, so nothing states its encoding", contentType)
		}
		if _, stated := handDerivedAuthDataSizes[contentType]; !stated {
			t.Errorf("content type %d has no hand derived size, so its golden is compared only against itself",
				contentType)
		}
	}
	if len(handDerivedAuthDataSizes) != len(declared) {
		t.Errorf("the size table holds %d entries and the package declares %d content types",
			len(handDerivedAuthDataSizes), len(declared))
	}
}

// TestFramedContentAuthDataMarshalMatchesTheHandDerivedGoldens is the field order, the field
// width and the arm selection pin, all three at once.
func TestFramedContentAuthDataMarshalMatchesTheHandDerivedGoldens(t *testing.T) {
	for _, contentType := range contentTypes(t) {
		want := handDerivedAuthDataGolden(contentType)
		if want == nil {
			t.Fatalf("content type %d has no hand derived golden", contentType)
		}
		size, stated := handDerivedAuthDataSizes[contentType]
		if !stated {
			t.Fatalf("content type %d has no hand derived size", contentType)
		}
		if len(want) != size {
			t.Fatalf("content type %d: the hand derivation is %d octets and the arithmetic in its comment says %d",
				contentType, len(want), size)
		}
		encoded, err := encodeAuthData(testAuthData(), contentType)
		if err != nil {
			t.Fatalf("content type %d: marshal: %v", contentType, err)
		}
		if !bytes.Equal(encoded, want) {
			t.Errorf("content type %d: marshal =\n %x\nwant\n %x", contentType, encoded, want)
		}
		decoded, err := decodeAuthData(want, contentType)
		if err != nil {
			t.Fatalf("content type %d: decoding the golden: %v", contentType, err)
		}
		if expected := decodedFormOfAuthData(t, testAuthData(), contentType); !sameAuthData(decoded, expected) {
			t.Errorf("content type %d: the golden decoded to\n %s\nwant\n %s",
				contentType, describeAuthData(decoded), describeAuthData(expected))
		}
	}
}

// TestFramedContentAuthDataRoundTripsEveryContentType compares the WHOLE decoded value against
// the derived expected form rather than the one or two fields a hand written case would list,
// and then re-encodes.
//
// The whole-value half is what a field dropped from BOTH halves of the codec needs: that drop
// re-encodes byte exact against itself and is simply lost, and only a comparison that names no
// field can see it.
func TestFramedContentAuthDataRoundTripsEveryContentType(t *testing.T) {
	for _, contentType := range contentTypes(t) {
		encoded, err := encodeAuthData(testAuthData(), contentType)
		if err != nil {
			t.Fatalf("content type %d: marshal: %v", contentType, err)
		}
		decoded, err := decodeAuthData(encoded, contentType)
		if err != nil {
			t.Fatalf("content type %d: unmarshal: %v", contentType, err)
		}
		if want := decodedFormOfAuthData(t, testAuthData(), contentType); !sameAuthData(decoded, want) {
			t.Errorf("content type %d: round trip gave\n %s\nwant\n %s",
				contentType, describeAuthData(decoded), describeAuthData(want))
		}
		reencoded, err := encodeAuthData(decoded, contentType)
		if err != nil {
			t.Fatalf("content type %d: re-marshal: %v", contentType, err)
		}
		if !bytes.Equal(reencoded, encoded) {
			t.Errorf("content type %d: re-encode =\n %x\nwant\n %x", contentType, reencoded, encoded)
		}
	}
}

// TestTheAuthDataCodecWritesEveryFieldItsContentTypeCarriesAndNoOther sweeps the fields off the
// TYPE and the carriage off the variant table, so neither is a list somebody kept up to date.
//
// This is the property a golden cannot state on its own: the golden says what the bytes are for
// one value, and this says that each field is what those bytes are a function of. It is where
// two of this task's named mutations land for every arm at once -- a confirmation tag written
// under proposal, and a confirmation tag omitted under commit -- because both are exactly
// "varying this field changed the encoding when the arm says it should not", or the reverse.
func TestTheAuthDataCodecWritesEveryFieldItsContentTypeCarriesAndNoOther(t *testing.T) {
	structType := reflect.TypeOf(FramedContentAuthData{})
	replacement := []byte{0x7e, 0x7f, 0x80, 0x81}
	observed := map[string]bool{}
	for _, contentType := range contentTypes(t) {
		base, err := encodeAuthData(testAuthData(), contentType)
		if err != nil {
			t.Fatalf("content type %d: marshal: %v", contentType, err)
		}
		for i := 0; i < structType.NumField(); i += 1 {
			name := structType.Field(i).Name
			varied := testAuthData()
			field := reflect.ValueOf(varied).Elem().Field(i)
			if bytes.Equal(field.Bytes(), replacement) {
				t.Fatalf("%s already holds the replacement value, so varying it varies nothing", name)
			}
			field.SetBytes(bytes.Clone(replacement))
			encoded, err := encodeAuthData(varied, contentType)
			if err != nil {
				t.Fatalf("content type %d: marshal with %s varied: %v", contentType, name, err)
			}
			changed := !bytes.Equal(encoded, base)
			carried := slices.Contains(authDataVariantPaths[contentType], name)
			if carried && !changed {
				t.Errorf("content type %d carries %s and varying it left the encoding at %x, so nothing writes it",
					contentType, name, encoded)
			}
			if !carried && changed {
				t.Errorf("content type %d does not carry %s and varying it changed the encoding to %x, so this codec writes a field the select does not give that arm",
					contentType, name, encoded)
			}
			observed[name] = observed[name] || changed
		}
	}
	for i := 0; i < structType.NumField(); i += 1 {
		name := structType.Field(i).Name
		if !observed[name] {
			t.Errorf("%s changed no encoding under any declared content type, so nothing in this package writes it",
				name)
		}
	}
}

// TestTheAuthDataGoldensSeparateExactlyTheArmsThatDifferOnTheWire is the premise the
// wrong-content-type sweep below rests on, stated rather than assumed.
//
// Application and proposal are the SAME encoding of this structure -- section 6's select gives
// both of them the empty arm -- so no decoder can be asked to tell one from the other, and a
// sweep demanding that every wrong content type be refused would be demanding something false.
// Commit is the arm that differs. Deriving the partition off the hand written goldens rather
// than off framing.go is what keeps it a statement about the RFC: a codec that stopped writing
// the confirmation tag would make all three goldens equal, and this fails before the sweep
// below gets the chance to pass vacuously.
func TestTheAuthDataGoldensSeparateExactlyTheArmsThatDifferOnTheWire(t *testing.T) {
	declared := contentTypes(t)
	distinct := map[string][]ContentType{}
	for _, contentType := range declared {
		key := fmt.Sprintf("%x", handDerivedAuthDataGolden(contentType))
		distinct[key] = append(distinct[key], contentType)
	}
	if len(distinct) < 2 {
		t.Fatalf("all %d content types encode this value identically, so no wrong content type could ever be refused and the sweep below states nothing",
			len(declared))
	}
	if !bytes.Equal(handDerivedAuthDataGolden(ContentTypeApplication), handDerivedAuthDataGolden(ContentTypeProposal)) {
		t.Error("application and proposal are given different encodings here; RFC 9420 section 6 gives both of them the empty arm")
	}
	if bytes.Equal(handDerivedAuthDataGolden(ContentTypeCommit), handDerivedAuthDataGolden(ContentTypeProposal)) {
		t.Error("commit and proposal are given the same encoding here; the confirmation tag is what separates them")
	}
	t.Logf("%d content types over %d distinct encodings", len(declared), len(distinct))
}

// TestAnAuthDataUnderTheWrongContentTypeIsRefusedRatherThanMisParsed is this structure's
// signature failure mode, swept over every ordered pair.
//
// FramedContentAuthData carries no discriminant, so the content type handed to the decoder is
// the only thing that says which arm the bytes are. Two ways of getting that wrong are two
// different bugs and both are here. A commit's bytes read as a proposal must NOT quietly stop
// after the signature and report success -- that is a confirmation tag dropped on the floor,
// which is a commit accepted with its binding to the epoch unread. A proposal's bytes read as a
// commit must not manufacture a tag out of whatever follows.
//
// The expectation is derived from the goldens rather than listed: where two content types share
// an encoding the decode must SUCCEED and give the same value, and where they do not it must be
// refused. A test that demanded refusal everywhere would be false for application against
// proposal; a test that demanded it nowhere would be this bug.
func TestAnAuthDataUnderTheWrongContentTypeIsRefusedRatherThanMisParsed(t *testing.T) {
	declared := contentTypes(t)
	refused, shared := 0, 0
	for _, encodedUnder := range declared {
		golden := handDerivedAuthDataGolden(encodedUnder)
		for _, decodedUnder := range declared {
			if encodedUnder == decodedUnder {
				continue
			}
			decoded, err := decodeAuthData(golden, decodedUnder)
			sameEncoding := bytes.Equal(golden, handDerivedAuthDataGolden(decodedUnder))
			if !sameEncoding {
				if err == nil {
					t.Errorf("the content type %d encoding %x decoded under content type %d as\n %s\nand the two arms do not share an encoding, so it must be refused",
						encodedUnder, golden, decodedUnder, describeAuthData(decoded))
					continue
				}
				refused += 1
				continue
			}
			if err != nil {
				t.Errorf("content types %d and %d share one encoding and decoding %x under %d was refused: %v",
					encodedUnder, decodedUnder, golden, decodedUnder, err)
				continue
			}
			want, wantErr := decodeAuthData(golden, encodedUnder)
			if wantErr != nil {
				t.Fatalf("content type %d could not decode its own golden: %v", encodedUnder, wantErr)
			}
			if !sameAuthData(decoded, want) {
				t.Errorf("content types %d and %d share one encoding and it decoded to\n %s\nunder one and\n %s\nunder the other",
					encodedUnder, decodedUnder, describeAuthData(want), describeAuthData(decoded))
			}
			shared += 1
		}
	}
	if refused == 0 {
		t.Fatal("no cross content type decode was refused, so this observed nothing")
	}
	t.Logf("%d cross content type decodes refused, %d passed as arms sharing one encoding", refused, shared)
}

// TestANonCommitAuthDataDecodeNeverProducesAConfirmationTag is the half of the sweep above that
// survives even where the arms share an encoding.
//
// Stated separately because it is the property with the sharpest failure: a decoder that read a
// tag whenever bytes happened to remain would be caught above only by the r.Done() clause, and a
// later task that gave this codec a bounded sub-Reader -- which is what an enclosing structure
// with fields after the auth data would need -- would remove that clause's teeth without
// touching this file. The value is what is asserted here, not the tail.
func TestANonCommitAuthDataDecodeNeverProducesAConfirmationTag(t *testing.T) {
	inputs := [][]byte{}
	for _, contentType := range contentTypes(t) {
		inputs = append(inputs, handDerivedAuthDataGolden(contentType))
	}
	inputs = append(inputs, joinBytes(handDerivedAuthDataGolden(ContentTypeCommit), repeatByte(0x5a, 9)))
	stated := 0
	for _, contentType := range contentTypes(t) {
		if slices.Contains(authDataVariantPaths[contentType], "ConfirmationTag") {
			continue
		}
		for _, input := range inputs {
			decoded := &FramedContentAuthData{ConfirmationTag: []byte{0xde, 0xad}}
			r := syntax.NewReader(input)
			if err := decoded.UnmarshalMLS(r, contentType); err != nil {
				continue
			}
			if decoded.ConfirmationTag != nil {
				t.Errorf("content type %d decoded %x and produced the confirmation tag %x; that arm carries none",
					contentType, input, decoded.ConfirmationTag)
			}
			stated += 1
		}
	}
	if stated == 0 {
		t.Fatal("no non-commit decode succeeded, so this observed nothing")
	}
	t.Logf("%d non-commit decodes left the confirmation tag absent", stated)
}

// TestFramedContentAuthDataRequiresAConfirmationTagOnACommit states ValSem009's structural half
// on BOTH halves of the codec.
//
// The encode half is not decoration. The confirmation tag is what binds a commit to the epoch it
// creates, so an encoder that wrote a commit's auth data without one would produce a message
// every peer rejects having verified its signature first -- and an encoder whose commit arm fell
// through to the signature-only write is exactly the shape a decode-only test cannot see.
//
// The empty tag is here beside the nil one because they are the same statement on the wire and
// a length check written as a nil check would let one of them through.
func TestFramedContentAuthDataRequiresAConfirmationTagOnACommit(t *testing.T) {
	for _, missing := range []*FramedContentAuthData{
		{Signature: []byte{0x11, 0x22, 0x33}},
		{Signature: []byte{0x11, 0x22, 0x33}, ConfirmationTag: []byte{}},
	} {
		if _, err := encodeAuthData(missing, ContentTypeCommit); !errors.Is(err, errMissingConfirmationTag) {
			t.Errorf("marshalling a commit whose confirmation tag is %s gave %v, want errMissingConfirmationTag",
				describeOptionalOctets(missing.ConfirmationTag), err)
		}
	}
	// the decode half: a wire legal zero length tag is the encoding of "no tag", and what the
	// encoder refuses to write the decoder must refuse to read, or a round trip through this
	// package would produce a value this package will not re-encode.
	emptyTag := []byte{0x03, 0x11, 0x22, 0x33, 0x00}
	if _, err := decodeAuthData(emptyTag, ContentTypeCommit); !errors.Is(err, errMissingConfirmationTag) {
		t.Errorf("decoding %x as a commit gave %v, want errMissingConfirmationTag", emptyTag, err)
	}
	// and the neighbouring refusal, so the one above cannot be passing for a truncation: a
	// commit with no tag field at all ends the input early, which is the SYNTAX layer's refusal
	// and not this one. Asserting only that it was refused states nothing about the difference
	// this case exists to draw -- a decoder that answered errMissingConfirmationTag to every
	// short commit passes that form -- so both directions are named.
	noTagAtAll := []byte{0x03, 0x11, 0x22, 0x33}
	_, truncated := decodeAuthData(noTagAtAll, ContentTypeCommit)
	if errors.Is(truncated, errMissingConfirmationTag) {
		t.Errorf("decoding %x as a commit gave errMissingConfirmationTag; the input ends before the tag field, so this is a truncation, and a caller told otherwise is told a sender omitted a field it did send",
			noTagAtAll)
	}
	if !errors.Is(truncated, syntax.ErrTruncated) {
		t.Errorf("decoding %x as a commit gave %v, want syntax.ErrTruncated; the tag field is absent entirely",
			noTagAtAll, truncated)
	}
}

// TestFramedContentAuthDataRejectsAnUnregisteredContentType sweeps the whole octet space rather
// than the value somebody thought of, and states the refusal on both halves.
//
// The encode half matters for the reason Sender's does: a content type outside the registry has
// no arm, so an encoder whose default fell through to writing the signature alone would emit a
// commit's auth data shorn of its tag under a content type nothing can parse.
//
// The decode half is offered against the full commit golden, which has bytes to spare, so a
// refusal that was really a truncation cannot pass for a refusal of the TYPE.
func TestFramedContentAuthDataRejectsAnUnregisteredContentType(t *testing.T) {
	undeclared := undeclaredContentTypeOctets(t)
	if !slices.Contains(undeclared, ContentType(0)) {
		t.Fatal("0 is declared as a content type, and RFC 9420 section 6 reserves it")
	}
	for _, contentType := range undeclared {
		if _, err := encodeAuthData(testAuthData(), contentType); !errors.Is(err, ErrUnknownContentType) {
			t.Fatalf("marshalling under content type %d gave %v, want ErrUnknownContentType", contentType, err)
		}
		for _, input := range [][]byte{
			nil,
			handDerivedAuthDataGolden(ContentTypeApplication),
			handDerivedAuthDataGolden(ContentTypeCommit),
		} {
			decoded := &FramedContentAuthData{}
			r := syntax.NewReader(input)
			if err := decoded.UnmarshalMLS(r, contentType); !errors.Is(err, ErrUnknownContentType) {
				t.Fatalf("decoding %x under content type %d gave %v, want ErrUnknownContentType",
					input, contentType, err)
			}
			// refused before a single octet is consumed, so an unregistered content type does
			// not half consume the caller's Reader on its way to being refused.
			if r.Offset() != 0 {
				t.Fatalf("decoding under content type %d consumed %d octets before refusing",
					contentType, r.Offset())
			}
		}
	}
	t.Logf("%d unregistered content type octets refused on both halves of the codec", len(undeclared))
}

// TestARefusedAuthDataMarshalWritesNothing is the encoder's other half of the same discipline.
//
// There is no syntax.Marshal for this codec -- that entry point takes a one argument Marshaler
// and this one needs the content type -- so the Writer belongs to the CALLER and survives the
// refusal. An encoder that wrote the signature and then refused would leave a caller holding a
// four octet prefix of a seven octet structure with no sticky error on the Writer to say so,
// which for this structure is precisely "the confirmation tag is gone".
//
// The marker byte written first is what separates "wrote nothing" from "was handed an empty
// Writer": a length compared against zero would pass for an encoder that had truncated
// everything.
func TestARefusedAuthDataMarshalWritesNothing(t *testing.T) {
	type refusal struct {
		auth        *FramedContentAuthData
		contentType ContentType
	}
	refusals := []refusal{{auth: &FramedContentAuthData{Signature: []byte{0x11}}, contentType: ContentTypeCommit}}
	for _, contentType := range undeclaredContentTypeOctets(t) {
		refusals = append(refusals, refusal{auth: testAuthData(), contentType: contentType})
	}
	for _, each := range refusals {
		w := syntax.NewWriter()
		w.WriteUint8(0xa5)
		before := w.Len()
		if err := each.auth.MarshalMLS(w, each.contentType); err == nil {
			t.Fatalf("content type %d: the marshal this sweep expects to be refused was accepted",
				each.contentType)
		}
		if w.Len() != before {
			encoded, _ := w.Bytes()
			t.Fatalf("content type %d: a refused marshal left the Writer holding %x, %d octets past the %d it was handed",
				each.contentType, encoded, w.Len()-before, before)
		}
	}
	t.Logf("%d refused marshals wrote nothing", len(refusals))
}

// authDataRefusedDecode is one input this file can build that the CODEC ITSELF must refuse,
// against the content type it is offered under. The tail rule is deliberately not in here: a
// decode that succeeded and left bytes over is refused by r.Done() rather than by this method,
// and the receiver discipline below is a statement about the method.
type authDataRefusedDecode struct {
	input       []byte
	contentType ContentType
}

// authDataRefusedDecodes is every such input: every proper prefix of every golden, the commit
// encoding whose tag length is zeroed, and every golden under every unregistered content type.
func authDataRefusedDecodes(t *testing.T) []authDataRefusedDecode {
	t.Helper()
	found := []authDataRefusedDecode{}
	for _, contentType := range contentTypes(t) {
		golden := handDerivedAuthDataGolden(contentType)
		for cut := 0; cut < len(golden); cut += 1 {
			// a proper prefix is a refusal only where the arm needs the octets it lost.
			// application and proposal are four octets and every prefix of those is short; the
			// commit golden's four octet prefix is a whole signature and is refused because the
			// tag field is then absent entirely.
			found = append(found, authDataRefusedDecode{input: bytes.Clone(golden[:cut]), contentType: contentType})
		}
		for _, unregistered := range undeclaredContentTypeOctets(t) {
			found = append(found, authDataRefusedDecode{input: bytes.Clone(golden), contentType: unregistered})
		}
	}
	found = append(found, authDataRefusedDecode{
		input:       []byte{0x03, 0x11, 0x22, 0x33, 0x00},
		contentType: ContentTypeCommit,
	})
	return found
}

// authDataPriorContents is every state a receiver can arrive in that this file can build.
// Derived over the class rather than over the one prior somebody picks, because the failure is
// per PAIR: only a receiver that already held a confirmation tag can leave that tag standing
// under an arm that carries none.
func authDataPriorContents(t *testing.T) []*FramedContentAuthData {
	t.Helper()
	priors := []*FramedContentAuthData{{}, testAuthData()}
	for _, contentType := range contentTypes(t) {
		priors = append(priors, decodedFormOfAuthData(t, testAuthData(), contentType))
	}
	return priors
}

// TestARefusedAuthDataDecodeLeavesItsReceiverUntouched is the discipline Sender, Credential and
// LeafNode already keep, stated for this codec because it has an edge those three do not.
//
// The commit arm reads TWO fields. A decoder that assigned as it read would leave a caller's
// value holding the signature out of a message this package REFUSED -- one whose confirmation
// tag was truncated, or empty -- beside a confirmation tag left over from whatever the value
// held before. That pair is a signature and a tag nothing ever carried together, sitting in a
// variable the caller may well reuse, with nothing in the returned error saying so.
func TestARefusedAuthDataDecodeLeavesItsReceiverUntouched(t *testing.T) {
	priors := authDataPriorContents(t)
	refused, accepted := 0, 0
	for _, each := range authDataRefusedDecodes(t) {
		for _, prior := range priors {
			held := *prior
			before := *prior
			if err := held.UnmarshalMLS(syntax.NewReader(each.input), each.contentType); err == nil {
				accepted += 1
				continue
			}
			refused += 1
			if sameAuthData(&held, &before) {
				continue
			}
			t.Fatalf("content type %d: a refused decode of %x into a receiver that held\n %s\nwrote through it, leaving\n %s",
				each.contentType, each.input, describeAuthData(&before), describeAuthData(&held))
		}
	}
	if accepted != 0 {
		t.Errorf("%d of the inputs this sweep built decoded rather than being refused, so the property was never stated over them",
			accepted)
	}
	if refused == 0 {
		t.Fatal("no input was refused, so this observed nothing")
	}
	t.Logf("%d refused decodes over %d prior receiver contents left the receiver exactly as they found it",
		refused, len(priors))
}

// TestAnAuthDataDecodesToTheSameValueWhateverItsReceiverHeld is not a round trip property.
//
// The application and proposal arms assign only the signature, so a decoder that wrote through
// its receiver rather than replacing it leaves the PREVIOUS value's confirmation tag standing
// under an arm that carries none. The bytes are unaffected -- the stale tag is not written under
// that arm -- so it round trips, re-encodes byte exact and agrees with every golden here. What
// it disagrees with is the same bytes decoded into a fresh receiver, which is a proposal's
// authenticators comparing unequal to themselves depending on where they were decoded, and one
// of the two carrying a confirmation tag a later confirmation check would happily consume.
func TestAnAuthDataDecodesToTheSameValueWhateverItsReceiverHeld(t *testing.T) {
	priors := authDataPriorContents(t)
	for _, contentType := range contentTypes(t) {
		encoded := handDerivedAuthDataGolden(contentType)
		fresh, err := decodeAuthData(encoded, contentType)
		if err != nil {
			t.Fatalf("content type %d: decoding into a fresh receiver: %v", contentType, err)
		}
		for at, prior := range priors {
			reused := *prior
			r := syntax.NewReader(encoded)
			if err := reused.UnmarshalMLS(r, contentType); err != nil {
				t.Fatalf("content type %d: decoding into a receiver holding prior %d: %v", contentType, at, err)
			}
			if err := r.Done(); err != nil {
				t.Fatalf("content type %d: prior %d: %v", contentType, at, err)
			}
			if !sameAuthData(&reused, fresh) {
				t.Errorf("content type %d: decoding into a receiver that held\n %s\ngave\n %s\nand the same bytes decoded fresh give\n %s",
					contentType, describeAuthData(prior), describeAuthData(&reused), describeAuthData(fresh))
			}
		}
	}
	t.Logf("%d prior receiver contents over %d content types", len(priors), len(contentTypes(t)))
}

// TestFramedContentAuthDataRefusesATruncatedEncoding runs over every proper prefix of every
// golden rather than over the boundaries somebody thought of, and the bound is derived from the
// encoding's own length.
//
// WHICH refusal each prefix earns is derived too, off the field boundaries of the golden it was
// cut from, and that half is not decoration. A prefix ending exactly where a field begins took
// that field's length prefix away entirely, so the read runs out of input: syntax.ErrTruncated.
// A prefix ending inside a field leaves a length declaring more than remains:
// syntax.ErrLengthExceedsInput. Neither of them is errMissingConfirmationTag, and pinning that
// is the point. Every other refusal in this file is pinned exactly -- ErrTrailingBytes, the
// unregistered content type, the missing tag -- and truncation was the one class stated as a
// bare non-nil, which left the commit arm free to report every short message as a commit
// carrying no tag: a transport failure handed to the caller as ValSem009, about a field the
// sender did send. Measured rather than supposed: dropping the error check on the confirmation
// tag's own read left this package green.
func TestFramedContentAuthDataRefusesATruncatedEncoding(t *testing.T) {
	cuts, atAFieldStart, insideAField := 0, 0, 0
	for _, contentType := range contentTypes(t) {
		for _, golden := range authDataGoldens(t, contentType) {
			starts := authDataFieldStarts(t, golden)
			for cut := 0; cut < len(golden); cut += 1 {
				want := syntax.ErrLengthExceedsInput
				if slices.Contains(starts, cut) {
					want = syntax.ErrTruncated
					atAFieldStart += 1
				} else {
					insideAField += 1
				}
				_, err := decodeAuthData(golden[:cut], contentType)
				if err == nil {
					t.Errorf("content type %d: %d of the %d octets of %x decoded rather than being refused",
						contentType, cut, len(golden), golden)
					continue
				}
				if errors.Is(err, errMissingConfirmationTag) {
					t.Errorf("content type %d: %d of the %d octets of %x was refused as a commit carrying no confirmation tag; the input ended before that field, and a truncation reported as a missing field is a transport failure the caller reads as a structural one",
						contentType, cut, len(golden), golden)
					continue
				}
				if !errors.Is(err, want) {
					t.Errorf("content type %d: %d of the %d octets of %x was refused with %v, want %v",
						contentType, cut, len(golden), golden, err, want)
					continue
				}
				cuts += 1
			}
		}
	}
	if atAFieldStart == 0 || insideAField == 0 {
		t.Fatalf("the sweep built %d prefixes ending at a field start and %d ending inside a field; both are needed, or one of the two refusals is stated by nothing",
			atAFieldStart, insideAField)
	}
	t.Logf("%d truncations refused, %d of them cut at a field start and the rest inside a field",
		cuts, atAFieldStart)
}

// TestFramedContentAuthDataRefusesTrailingBytes is the full consumption half, stated through
// r.Done() because this codec is handed the caller's Reader rather than reached through
// syntax.Unmarshal.
//
// It has teeth of its own here rather than being a copy of Sender's. This structure has no
// discriminant, so a tolerated tail is not merely a second encoding of one object: it is
// exactly how a commit's confirmation tag gets read as somebody else's trailing garbage.
func TestFramedContentAuthDataRefusesTrailingBytes(t *testing.T) {
	stated := 0
	for _, contentType := range contentTypes(t) {
		golden := handDerivedAuthDataGolden(contentType)
		for _, tail := range [][]byte{{0x00}, {0xff}, {0x00, 0x00}, repeatByte(0x5a, 17)} {
			longer := joinBytes(golden, tail)
			if _, err := decodeAuthData(longer, contentType); !errors.Is(err, syntax.ErrTrailingBytes) {
				t.Errorf("content type %d with %d trailing octets (%x): err = %v, want syntax.ErrTrailingBytes",
					contentType, len(tail), longer, err)
				continue
			}
			stated += 1
		}
	}
	if stated == 0 {
		t.Fatal("no tailed encoding was refused, so this observed nothing")
	}
	t.Logf("%d tailed encodings refused over %d content types", stated, len(contentTypes(t)))
}

// TestEverySingleOctetCorruptionOfAnAuthDataIsRefusedOrReEncodesToItself is the other half of
// the length sweep: every input one octet away from a golden, at every position, over every
// value that octet could hold.
//
// The property is the one Gate 4 states over the whole codec table: an accepted input has
// exactly one encoding. Anything else is a second encoding of one object, and MLS signs over
// serialized forms -- so two byte strings this package accepts as the same value are a
// signature that covers one of them and a peer that acted on the other.
func TestEverySingleOctetCorruptionOfAnAuthDataIsRefusedOrReEncodesToItself(t *testing.T) {
	refused, accepted := 0, 0
	for _, contentType := range contentTypes(t) {
		golden := handDerivedAuthDataGolden(contentType)
		for at := 0; at < len(golden); at += 1 {
			for value := 0; value <= 0xff; value += 1 {
				if byte(value) == golden[at] {
					continue
				}
				corrupted := bytes.Clone(golden)
				corrupted[at] = byte(value)
				decoded, err := decodeAuthData(corrupted, contentType)
				if err != nil {
					refused += 1
					continue
				}
				accepted += 1
				reencoded, err := encodeAuthData(decoded, contentType)
				if err != nil {
					t.Fatalf("content type %d: %x was accepted and then would not re-encode: %v",
						contentType, corrupted, err)
				}
				if !bytes.Equal(reencoded, corrupted) {
					t.Fatalf("content type %d: %x was accepted as\n %s\nand re-encodes to %x, so this codec holds two encodings of one value",
						contentType, corrupted, describeAuthData(decoded), reencoded)
				}
			}
		}
	}
	if refused == 0 || accepted == 0 {
		t.Fatalf("the sweep refused %d and accepted %d single octet corruptions; both halves must be exercised or it states only one of them",
			refused, accepted)
	}
	t.Logf("%d single octet corruptions refused, %d accepted and byte exact on re-encode", refused, accepted)
}

// TestFramedContentAuthDataIsDeliberatelyNotASyntaxCodec is registry section 7.2's shape, held
// at run time beside the compile time pins framing.go carries.
//
// The registry refuses this type a discriminant field, which is what makes syntax.Codec
// unreachable for it: both methods need the content type, and Codec's do not take one. A later
// task that "tidied" the two argument methods into Codec's shape would have to store the content
// type somewhere, and that copy would then be what decided which arm was read -- the failure the
// parameter exists to prevent. That change stops compiling in framing.go; this is what states
// why, where a reader will find it.
func TestFramedContentAuthDataIsDeliberatelyNotASyntaxCodec(t *testing.T) {
	codec := reflect.TypeOf((*syntax.Codec)(nil)).Elem()
	if reflect.TypeOf((*FramedContentAuthData)(nil)).Implements(codec) {
		t.Error("*FramedContentAuthData satisfies syntax.Codec, so it has one argument MarshalMLS/UnmarshalMLS methods and is carrying a content type of its own somewhere")
	}
	// the control: the sibling codec of this file does satisfy it, so a false above cannot be
	// an interface this test failed to look up.
	if !reflect.TypeOf((*Sender)(nil)).Implements(codec) {
		t.Fatal("*Sender does not satisfy syntax.Codec, so the assertion above is reading the wrong interface")
	}
}

// ---------------------------------------------------------------------------
// the signature field at length zero
// ---------------------------------------------------------------------------

// handDerivedEmptySignatureAuthDataGolden is section 6's FramedContentAuthData with an EMPTY
// signature, written from the wire format rather than read back out of framing.go.
//
// It is here because signature is an opaque<V> like any other, so "no signature" is a length of
// zero and a body of nothing -- a field that is still THERE, occupying the one octet its length
// prefix takes. Every golden above carries a three octet signature, so an encoder that wrote the
// field only when it had something to put in it agrees with all three of them and with every
// property derived from them. That is measured rather than supposed: both WriteOpaque calls for
// this field wrapped in a length test left ./mls/... and ./message/... green.
//
// What such an encoder produces is not a shorter message, it is a DIFFERENT one. Under
// application the whole structure becomes zero octets, which the enclosing decode meets as the
// end of its input; under commit the confirmation tag's length prefix moves to offset zero,
// where a decoder takes it for the signature's -- a commit whose tag is read as its signature
// and whose signature is gone, with every field after it shifted by one.
//
//	signature<V> over nothing       length 0 -> 1 octet 0x00, body 0 octets = 1
//	confirmation_tag<V> over 44 55  length 2 -> 1 octet 0x02, body 2 octets = 3
//
//	application  1 + 0 = 1
//	proposal     1 + 0 = 1
//	commit       1 + 3 = 4
func handDerivedEmptySignatureAuthDataGolden(contentType ContentType) []byte {
	switch contentType {
	case ContentTypeApplication:
		return []byte{0x00}
	case ContentTypeProposal:
		return []byte{0x00}
	case ContentTypeCommit:
		return []byte{0x00, 0x02, 0x44, 0x55}
	}
	return nil
}

// handDerivedEmptySignatureAuthDataSizes is the arithmetic of the comment above, stated
// separately for handDerivedAuthDataSizes' reason: a derivation edited without its comment then
// fails rather than redefining what it is compared against.
var handDerivedEmptySignatureAuthDataSizes = map[ContentType]int{
	ContentTypeApplication: 1,
	ContentTypeProposal:    1,
	ContentTypeCommit:      4,
}

// emptySignatureAuthData is the value those goldens encode: the given signature, which is the
// absent one in both of its spellings, beside the confirmation tag every other sweep here uses.
// The tag is kept so the commit arm still has one to write and its encoding still differs from
// the application arm's by exactly that field.
func emptySignatureAuthData(signature []byte) *FramedContentAuthData {
	return &FramedContentAuthData{Signature: signature, ConfirmationTag: testAuthData().ConfirmationTag}
}

// TestTheAuthDataSignatureFieldIsWrittenAtEveryLengthIncludingZero states the one length no
// other sweep in this file offers either half of the codec.
//
// The signature of testAuthData is three octets, every golden above carries it, and the one
// value here holding an empty signature is only ever a receiver and never an encode input -- so
// the wire shape of this field at length zero was a claim nothing made. It is not an exotic
// input: a signature is opaque<V>, the empty one is legal, and which of "0x00" and "nothing at
// all" it encodes to is the difference between a decoder finding the confirmation tag where it
// belongs and finding it one field early.
//
// The nil and the empty slice are both offered because they are ONE statement on the wire and
// two different values in Go: a presence test written as a nil check passes for one of them and
// not for the other. The decode half then pins which of the two comes back, because that pair
// does not round trip to an equal VALUE -- only to equal bytes -- and describeOptionalOctets
// exists in this file precisely to keep the two apart, so which one a decode produces is a fact
// this file owes a reader rather than one it leaves to whoever reads syntax/decode.go.
func TestTheAuthDataSignatureFieldIsWrittenAtEveryLengthIncludingZero(t *testing.T) {
	declared := contentTypes(t)
	for _, contentType := range declared {
		want := handDerivedEmptySignatureAuthDataGolden(contentType)
		if want == nil {
			t.Fatalf("content type %d has no empty signature golden, so nothing states what this codec writes when the signature is absent",
				contentType)
		}
		size, stated := handDerivedEmptySignatureAuthDataSizes[contentType]
		if !stated {
			t.Fatalf("content type %d has no empty signature size, so its golden is compared only against itself",
				contentType)
		}
		if len(want) != size {
			t.Fatalf("content type %d: the empty signature derivation is %d octets and the arithmetic in its comment says %d",
				contentType, len(want), size)
		}
		for _, signature := range [][]byte{nil, {}} {
			encoded, err := encodeAuthData(emptySignatureAuthData(signature), contentType)
			if err != nil {
				t.Fatalf("content type %d: marshalling a signature of %s: %v",
					contentType, describeOptionalOctets(signature), err)
			}
			if !bytes.Equal(encoded, want) {
				t.Errorf("content type %d: a signature of %s encoded to\n %x\nwant\n %x\nthe signature is an opaque<V>, so a signature of length zero is a length prefix of zero and not a field left out",
					contentType, describeOptionalOctets(signature), encoded, want)
			}
		}
		decoded, err := decodeAuthData(want, contentType)
		if err != nil {
			t.Fatalf("content type %d: decoding %x: %v", contentType, want, err)
		}
		if expected := decodedFormOfAuthData(t, emptySignatureAuthData([]byte{}), contentType); !sameAuthData(decoded, expected) {
			t.Errorf("content type %d: %x decoded to\n %s\nwant\n %s",
				contentType, want, describeAuthData(decoded), describeAuthData(expected))
		}
		if decoded.Signature == nil {
			t.Errorf("content type %d: %x decoded to a nil signature; every arm carries the field, so a nil here would be the decoder saying the field was absent and no encoding of this structure can say that",
				contentType, want)
		}
		reencoded, err := encodeAuthData(decoded, contentType)
		if err != nil {
			t.Fatalf("content type %d: re-marshalling %s: %v", contentType, describeAuthData(decoded), err)
		}
		if !bytes.Equal(reencoded, want) {
			t.Errorf("content type %d: re-encode =\n %x\nwant\n %x", contentType, reencoded, want)
		}
	}
	if len(handDerivedEmptySignatureAuthDataSizes) != len(declared) {
		t.Errorf("the empty signature size table holds %d entries and the package declares %d content types",
			len(handDerivedEmptySignatureAuthDataSizes), len(declared))
	}
}

// authDataGoldens is every hand derived encoding this file holds for one content type: the
// populated one and the one whose signature is empty. Swept together where a property is about
// the LAYOUT rather than about the values, because the two families put their field boundaries
// in different places and a boundary rule stated over one of them is stated over one shape.
func authDataGoldens(t *testing.T, contentType ContentType) [][]byte {
	t.Helper()
	found := [][]byte{}
	for _, golden := range [][]byte{
		handDerivedAuthDataGolden(contentType),
		handDerivedEmptySignatureAuthDataGolden(contentType),
	} {
		if golden == nil {
			t.Fatalf("content type %d is missing one of its hand derived goldens, so a sweep meant to run over both families ran over one",
				contentType)
		}
		found = append(found, golden)
	}
	return found
}

// authDataFieldStarts derives the offsets a golden's length prefixed fields begin at, by walking
// the prefixes rather than by transcribing the layout a second time.
//
// Every field of this structure is an opaque<V> and every length in these goldens is below 64,
// so each prefix is the single octet holding its own body length -- which makes this a reading
// of the encoding rather than a second claim about it. Landing exactly on the end is checked
// rather than assumed: a golden this walk could not account for would hand its caller a set of
// boundaries that are not boundaries, and every expectation derived from them would be arbitrary
// while still looking derived.
func authDataFieldStarts(t *testing.T, golden []byte) []int {
	t.Helper()
	starts := []int{}
	for at := 0; at < len(golden); {
		if golden[at] >= 0x40 {
			t.Fatalf("the octet %#02x at offset %d of %x is not a single octet varint length prefix, so this walk cannot read that golden's layout",
				golden[at], at, golden)
		}
		starts = append(starts, at)
		next := at + 1 + int(golden[at])
		if next > len(golden) {
			t.Fatalf("the field beginning at offset %d of %x declares %d octets and runs past its end",
				at, golden, golden[at])
		}
		at = next
	}
	if len(starts) == 0 {
		t.Fatalf("no field was read out of %x, so no boundary was derived from it", golden)
	}
	return starts
}

// ---------------------------------------------------------------------------
// the refusals that name the code point they refused
// ---------------------------------------------------------------------------

// framingRegistrySwitch is one switch over a framing registry in framing.go, together with the
// refusal it reaches when none of its cases matched.
//
// The class is derived from the file rather than listed, because framing.go's own package
// comment makes the claim about ALL of them -- "the refusal paths therefore name the offending
// value numerically" -- and a list of the ones somebody remembered is how three come to be held
// and the fourth not. That is this project's most repeated failure and it is why the behavioural
// sweep below is keyed on this derivation rather than standing beside it.
type framingRegistrySwitch struct {
	method   string
	file     string
	registry string
	tag      string
	refusal  ast.Expr
}

// registryOfSwitch names the framing registry a switch discriminates on, read off its CASE
// expressions rather than off its tag.
//
// The cases are the better evidence and they are also the only evidence available. A tag is a
// parameter or a field selector, and typing either needs the function bodies the package type
// check deliberately skips; the cases are package level constants, whose types that check
// already holds. They are the code points themselves, which is the thing being claimed about.
func registryOfSwitch(t *testing.T, file string, statement *ast.SwitchStmt, registries []string) string {
	t.Helper()
	scope := typeCheckedPackage(t).Scope()
	found := ""
	for _, clause := range statement.Body.List {
		caseClause, isCase := clause.(*ast.CaseClause)
		if !isCase {
			continue
		}
		for _, expression := range caseClause.List {
			name, isName := expression.(*ast.Ident)
			if !isName {
				continue
			}
			constant, isConstant := scope.Lookup(name.Name).(*types.Const)
			if !isConstant {
				continue
			}
			named, isNamed := types.Unalias(constant.Type()).(*types.Named)
			if !isNamed || !slices.Contains(registries, named.Obj().Name()) {
				continue
			}
			if found != "" && found != named.Obj().Name() {
				t.Fatalf("one switch in %s names constants of both %s and %s, so which registry it discriminates on cannot be derived",
					file, found, named.Obj().Name())
			}
			found = named.Obj().Name()
		}
	}
	return found
}

// returnedExpression is the error a return statement returns, or nil for anything that is not
// one. A `return nil` is reported as none, so a search for the refusal a switch falls through to
// does not stop at the success path of a case clause.
//
// The LAST result rather than the only one, and the difference is measured. Every codec in this
// package returns one value and a reader written for that shape found nothing in
// ratchetTypeOf's `return 0, fmt.Errorf(...)` -- so secret_tree.go's content type refusal was
// read as a switch that falls out of the bottom of itself, which is the failure this gate
// exists to report and was here a failure of the reader. Every function this gate sweeps
// returns its error last, which is the language's own convention, and `return v, nil` still
// reports none because the last result is the nil.
func returnedExpression(statement ast.Stmt) ast.Expr {
	returned, isReturn := statement.(*ast.ReturnStmt)
	if !isReturn || len(returned.Results) == 0 {
		return nil
	}
	last := returned.Results[len(returned.Results)-1]
	if name, isName := last.(*ast.Ident); isName && name.Name == "nil" {
		return nil
	}
	return last
}

// TestTheRefusalReaderReadsTheErrorResultAndNotTheSuccessOne is that reader's control, in both
// directions for the reason every reader in this file carries one. One that read the first
// result would report a case clause's success path as the switch's refusal; one that insisted
// on a single result reads a two result refusal as no refusal at all, which is what it did.
func TestTheRefusalReaderReadsTheErrorResultAndNotTheSuccessOne(t *testing.T) {
	for _, one := range []struct {
		source  string
		refusal string
	}{
		{"return fmt.Errorf(\"%w: %d\", ErrUnknownContentType, contentType)", "fmt.Errorf(\"%w: %d\", ErrUnknownContentType, contentType)"},
		{"return 0, fmt.Errorf(\"%w: content type %d\", ErrUnknownContentType, contentType)", "fmt.Errorf(\"%w: content type %d\", ErrUnknownContentType, contentType)"},
		{"return ErrContentArmMismatch", "ErrContentArmMismatch"},
		// the success paths, which are not refusals however many results they carry
		{"return nil", ""},
		{"return RatchetApplication, nil", ""},
		// and a statement that is not a return at all
		{"self.A = 1", ""},
	} {
		parsed, err := parser.ParseFile(token.NewFileSet(), "control.go",
			"package control\nfunc f() { "+one.source+" }\n", parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %q: %v", one.source, err)
		}
		body := parsed.Decls[0].(*ast.FuncDecl).Body
		got := ""
		if expression := returnedExpression(body.List[0]); expression != nil {
			got = types.ExprString(expression)
		}
		if got != one.refusal {
			t.Errorf("%q read as the refusal %q, want %q", one.source, got, one.refusal)
		}
	}
}

// defaultClauseRefusal is the error a switch returns from its default clause, if it has one.
// Both spellings of an exhaustive refusal are read by the caller -- a default clause, and a
// return standing after the switch -- because framing.go uses one of each and the difference is
// a matter of taste rather than of what is being refused.
func defaultClauseRefusal(statement *ast.SwitchStmt) ast.Expr {
	for _, clause := range statement.Body.List {
		caseClause, isCase := clause.(*ast.CaseClause)
		if !isCase || caseClause.List != nil {
			continue
		}
		for _, inner := range caseClause.Body {
			if expression := returnedExpression(inner); expression != nil {
				return expression
			}
		}
	}
	return nil
}

// framingRegistrySwitches derives every registry switch this package's production source holds,
// keyed by the function that holds it.
//
// The scan set is framingRegistryFunctions and therefore the whole package. It used to be
// framing.go, which is what let framing_preimage.go's two wire format switches be deleted whole
// with the suite green, and which also left secret_tree.go's content type switch -- a refusal a
// peer reaches by sending an undefined content type -- outside every gate here.
func framingRegistrySwitches(t *testing.T) map[string]framingRegistrySwitch {
	t.Helper()
	registries := framingRegistries(t)
	found := map[string]framingRegistrySwitch{}
	for _, function := range framingRegistryFunctions(t) {
		method, file := function.name, function.file
		ast.Inspect(function.decl.Body, func(node ast.Node) bool {
			block, isBlock := node.(*ast.BlockStmt)
			if !isBlock {
				return true
			}
			for at, statement := range block.List {
				switched, isSwitch := statement.(*ast.SwitchStmt)
				if !isSwitch || switched.Tag == nil {
					continue
				}
				registry := registryOfSwitch(t, file, switched, registries)
				if registry == "" {
					continue
				}
				// the refusal is the default clause where there is one, and otherwise the
				// statement the switch falls through to, which is where a switch written
				// without a default puts it.
				refusal := defaultClauseRefusal(switched)
				if refusal == nil && at+1 < len(block.List) {
					refusal = returnedExpression(block.List[at+1])
				}
				if other, repeated := found[method]; repeated {
					t.Fatalf("%s holds a switch over %s and another over %s; this derivation keys one switch per method and cannot say which refusal belongs to which",
						method, other.registry, registry)
				}
				found[method] = framingRegistrySwitch{
					method:   method,
					file:     file,
					registry: registry,
					tag:      types.ExprString(switched.Tag),
					refusal:  refusal,
				}
			}
			return true
		})
	}
	if len(found) == 0 {
		t.Fatal("no switch over a framing registry was derived from this package's production source, which holds one in every framing codec method it declares, so every gate reading this would run over the empty set")
	}
	return found
}

// framingCodecMethodFiles is every MarshalMLS and UnmarshalMLS of this package that computes
// with a framing registry, with the file that declares it.
//
// The file travels with the method because it is what a failure here has to NAME. While the
// derivation root was framingFile every message below said "framing.go", and framing.go was the
// wrong answer for the one codec that was outside the gate -- the message would have been both
// false and reassuring.
func framingCodecMethodFiles(t *testing.T) map[string]string {
	t.Helper()
	found := map[string]string{}
	for _, function := range framingRegistryFunctions(t) {
		_, method, isMethod := strings.Cut(function.name, ".")
		if !isMethod || (method != "MarshalMLS" && method != "UnmarshalMLS") {
			continue
		}
		found[function.name] = function.file
	}
	if len(found) == 0 {
		t.Fatal("no framing codec method was derived from this package's production source, which declares several, so every gate reading this would run over the empty set")
	}
	return found
}

// framingCodecMethods is that class as a sorted list, which is the shape the set joins below
// take.
func framingCodecMethods(t *testing.T) []string {
	t.Helper()
	return slices.Sorted(maps.Keys(framingCodecMethodFiles(t)))
}

// expressionMentions reports whether an expression holds a sub expression written exactly as the
// given source text. Text rather than object identity because both ends come out of one file and
// one parse: the tag of the switch and the arguments of its refusal are the same source.
func expressionMentions(expression ast.Expr, text string) bool {
	found := false
	ast.Inspect(expression, func(node ast.Node) bool {
		if found {
			return false
		}
		inner, isExpression := node.(ast.Expr)
		if isExpression && types.ExprString(inner) == text {
			found = true
			return false
		}
		return true
	})
	return found
}

// TestTheRegistrySwitchReaderSeparatesARefusalThatNamesItsTagFromOneThatDoesNot is the control
// on that reader, and it is the same control the width pin reader carries. One that recognised
// everything would report every refusal as naming its code point, including the bare sentinel
// this gate exists to catch; one that recognised nothing would fail against the real file for
// the wrong reason. Both halves are stated over expressions written here.
func TestTheRegistrySwitchReaderSeparatesARefusalThatNamesItsTagFromOneThatDoesNot(t *testing.T) {
	for _, one := range []struct {
		source   string
		tag      string
		mentions bool
	}{
		{`fmt.Errorf("%w: %d", ErrUnknownContentType, contentType)`, "contentType", true},
		{`fmt.Errorf("%w: %d", ErrUnknownSenderType, self.SenderType)`, "self.SenderType", true},
		{`fmt.Errorf("%w: content type %d", ErrUnknownContentType, contentType)`, "contentType", true},
		// the survivor: a refusal that has stopped saying which code point it refused
		{`ErrUnknownContentType`, "contentType", false},
		{`fmt.Errorf("%w", ErrUnknownContentType)`, "contentType", false},
		// and a refusal naming something else, which is the shape a copied arm produces
		{`fmt.Errorf("%w: %d", ErrUnknownContentType, self.SenderType)`, "contentType", false},
	} {
		expression, err := parser.ParseExpr(one.source)
		if err != nil {
			t.Fatalf("parse %q: %v", one.source, err)
		}
		if got := expressionMentions(expression, one.tag); got != one.mentions {
			t.Errorf("%q read against the tag %s as %v, want %v", one.source, one.tag, got, one.mentions)
		}
	}
}

// TestEveryFramingRegistrySwitchRefusesByNamingTheCodePointItRefused holds framing.go's package
// comment to framing.go.
//
// That comment states the decision this file's registries turn on: none of them declares its
// reserved zero, so an unparsed header is a refusal rather than a real code point, and "the
// refusal paths therefore name the offending value numerically, which is what they have off the
// wire anyway". Nothing counted those paths. Both of the content type refusals could be reduced
// to a bare sentinel with the whole package green -- measured -- which leaves a caller holding
// an error that says only that SOMETHING in the header was unregistered, about a header they
// cannot re-read because the decode refused it.
//
// The class is the switches themselves, and the control is the other direction: every codec
// method framing.go declares must hold one, so a codec that discriminates on a registry without
// refusing the rest of it is reported here rather than being outside the sweep.
func TestEveryFramingRegistrySwitchRefusesByNamingTheCodePointItRefused(t *testing.T) {
	switches := framingRegistrySwitches(t)
	files := framingCodecMethodFiles(t)
	for _, method := range framingCodecMethods(t) {
		if _, held := switches[method]; !held {
			t.Errorf("%s declares %s and no switch over a framing registry was derived from it; every framing codec in this package discriminates on one, so either this method refuses no unregistered code point at all or the derivation has stopped seeing its switch",
				files[method], method)
		}
	}
	for _, method := range slices.Sorted(maps.Keys(switches)) {
		each := switches[method]
		if each.refusal == nil {
			t.Errorf("%s switches on %s and reaches no refusal where none of its cases match, so an unregistered code point leaves that switch by falling out of the bottom of it",
				method, each.registry)
			continue
		}
		if !expressionMentions(each.refusal, each.tag) {
			t.Errorf("%s refuses an unregistered %s with %s, which does not name %s; %s says these paths name the offending value numerically, and one that does not tells the caller only that something in the header was unregistered",
				method, each.registry, types.ExprString(each.refusal), each.tag, each.file)
		}
	}
	t.Logf("%d registry switches, each refusing by naming its own discriminant", len(switches))
}

// framingCodePointRefusals invokes each of those refusals with a code point its registry does
// not declare. It is a table, which is the shape this file distrusts, so the gate below holds
// its keys to the switches DERIVED from framing.go in both directions: a codec added to that
// file with no entry here is a refusal nothing invokes, and an entry here for a method that no
// longer switches on a registry is a sweep running over a claim the file has stopped making.
//
// Each invocation reaches the refusal and nothing else. The two decoders are handed input the
// arm would have consumed had the code point been registered -- a sender arm's octet, a whole
// commit auth data -- so a refusal that was really a truncation cannot pass for a refusal of
// the code point.
// handDerivedCommitTail is a valid AuthenticatedContent carrying an empty commit, MINUS its two
// octet wire format, written out here rather than produced by the encoder under test.
//
// The octets are the RFC's structure read off section 6: an empty group_id<V>, an eight octet
// epoch, a member sender at leaf 0, an empty authenticated_data<V>, the commit content type, an
// empty proposals<V>, an absent optional path, an empty signature<V> and a one octet
// confirmation tag. Hand derived because the decoder refusal it stands behind is being asked to
// refuse the wire format rather than to run out of input, and bytes produced by the encoder
// under test would make that a statement about the encoder.
func handDerivedCommitTail() []byte {
	return []byte{
		0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00,
		0x00,
		0x03,
		0x00,
		0x00,
		0x00,
		0x01, 0xaa,
	}
}

// handDerivedFramedContentHeader is the five fields every FramedContent opens with, ending in
// the content type the caller names, followed by two octets an arm would have consumed.
//
// The trailing octets are the point: without them a decoder that refused nothing would run out
// of input and report a truncation, which reads as a refusal of the code point and is not one.
func handDerivedFramedContentHeader(contentType ContentType) []byte {
	return []byte{
		0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00,
		0x00,
		byte(contentType),
		0x00, 0x00,
	}
}

// handDerivedTranscriptInputTail is a valid ConfirmedTranscriptHashInput carrying an empty
// commit, MINUS its two octet wire format.
//
// RFC 9420 section 8.2 writes wire_format, then the FramedContent, then opaque signature<V> --
// and NOT the confirmation tag, which is that structure's whole design. So this is
// handDerivedCommitTail's FramedContent followed by a signature vector and it stops where an
// AuthenticatedContent would have carried a tag. Hand derived for handDerivedCommitTail's
// reason: the decoder behind it is being asked to refuse a wire format rather than to run out
// of input, and bytes produced by the encoder under test would make that a statement about the
// encoder.
func handDerivedTranscriptInputTail() []byte {
	return []byte{
		0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00,
		0x00,
		0x03,
		0x00,
		0x00,
		0x01, 0xaa,
	}
}

var framingCodePointRefusals = map[string]func(codePoint uint64) error{
	"Sender.MarshalMLS": func(codePoint uint64) error {
		return (&Sender{SenderType: SenderType(codePoint)}).MarshalMLS(syntax.NewWriter())
	},
	"Sender.UnmarshalMLS": func(codePoint uint64) error {
		return (&Sender{}).UnmarshalMLS(syntax.NewReader([]byte{byte(codePoint), 0x00, 0x00, 0x00, 0x00}))
	},
	// framing.go's wire format registry, which had no raiser in production source until the
	// authenticated content codec grew one. The encoder is handed nothing but the code point,
	// because it refuses before it writes; the decoder is handed the whole of a valid commit's
	// authenticated content behind the two octets it refuses, so a refusal that was really a
	// truncation cannot pass for a refusal of the code point.
	"AuthenticatedContent.MarshalMLS": func(codePoint uint64) error {
		return (&AuthenticatedContent{WireFormat: WireFormat(codePoint)}).MarshalMLS(syntax.NewWriter())
	},
	"AuthenticatedContent.UnmarshalMLS": func(codePoint uint64) error {
		return (&AuthenticatedContent{}).UnmarshalMLS(syntax.NewReader(append(
			[]byte{byte(codePoint >> 8), byte(codePoint)}, handDerivedCommitTail()...)))
	},
	// the content type registry, at all three of the places framing.go discriminates on it.
	// checkArms is reached on its own as well as through the encoder, because the encoder
	// refuses through it and a reader arriving at either has to be told the same number.
	"FramedContent.checkArms": func(codePoint uint64) error {
		return (&FramedContent{ContentType: ContentType(codePoint)}).checkArms()
	},
	"FramedContent.MarshalMLS": func(codePoint uint64) error {
		return (&FramedContent{
			Sender:      Sender{SenderType: SenderTypeMember},
			ContentType: ContentType(codePoint),
		}).MarshalMLS(syntax.NewWriter())
	},
	"FramedContent.UnmarshalMLS": func(codePoint uint64) error {
		return (&FramedContent{}).UnmarshalMLS(syntax.NewReader(handDerivedFramedContentHeader(ContentType(codePoint))))
	},
	"FramedContentAuthData.MarshalMLS": func(codePoint uint64) error {
		return testAuthData().MarshalMLS(syntax.NewWriter(), ContentType(codePoint))
	},
	"FramedContentAuthData.UnmarshalMLS": func(codePoint uint64) error {
		return (&FramedContentAuthData{}).UnmarshalMLS(
			syntax.NewReader(handDerivedAuthDataGolden(ContentTypeCommit)), ContentType(codePoint))
	},
	// framing_preimage.go's section 8.2 structure, which reads and writes the same wire
	// format registry AuthenticatedContent does. These two rows are here because the class
	// this gate sweeps is the PACKAGE's registry switches and no longer framing.go's: while
	// it was one file wide, both of these switches could be deleted whole with the whole of
	// ./mls/... and ./message/... byte identically green, and a transcript preimage could
	// then be built over a wire format no registry declares -- which is a hash every peer
	// computes differently and a fork with no recovery path.
	"confirmedTranscriptHashInput.MarshalMLS": func(codePoint uint64) error {
		return (&confirmedTranscriptHashInput{WireFormat: WireFormat(codePoint)}).MarshalMLS(syntax.NewWriter())
	},
	"confirmedTranscriptHashInput.UnmarshalMLS": func(codePoint uint64) error {
		return (&confirmedTranscriptHashInput{}).UnmarshalMLS(syntax.NewReader(append(
			[]byte{byte(codePoint >> 8), byte(codePoint)}, handDerivedTranscriptInputTail()...)))
	},
	// secret_tree.go's content type switch. It is not a codec and it is swept here for the
	// same reason the two above are: the class is every place in this package that
	// discriminates on a framing registry, and a peer reaches this one by sending a content
	// type nobody has defined.
	"ratchetTypeOf": func(codePoint uint64) error {
		_, err := ratchetTypeOf(ContentType(codePoint))
		return err
	},
}

// undeclaredCodePointsOf is every code point of a framing registry's width that the registry
// does not declare, derived off the constants the package holds and off the type's own width
// rather than off either one alone. The reserved zero is one of them and is not special.
func undeclaredCodePointsOf(t *testing.T, registry string) []uint64 {
	t.Helper()
	bits := framingRegistryBits(t, registry)
	if bits > 16 {
		t.Fatalf("%s is %d bits wide, and sweeping its whole code point space is not what this helper is for", registry, bits)
	}
	held := map[uint64]bool{}
	for _, value := range registryConstantsOfType(t, registry) {
		held[value] = true
	}
	found := []uint64{}
	for candidate := uint64(0); candidate < uint64(1)<<bits; candidate += 1 {
		if held[candidate] {
			continue
		}
		found = append(found, candidate)
	}
	if len(found)+len(held) != 1<<bits {
		t.Fatalf("the derivation split the %d code points of %s into %d declared and %d undeclared",
			1<<bits, registry, len(held), len(found))
	}
	return found
}

// namesTheNumber reports whether a message spells value as a decimal number standing on its own
// rather than as part of a longer one.
//
// The boundary check is what makes this an assertion. A plain substring search for "1" is
// answered by a message naming 13, 21 or 100, so a refusal reporting the WRONG code point --
// which is what a loop reading the wrong index produces, and the failure extension_test.go
// already guards its own registry against -- would pass it. The format is deliberately not
// pinned: naming the value is the property, and "%d" against "content type %d" is a difference
// of prose rather than of what the caller is told.
func namesTheNumber(message string, value uint64) bool {
	want := strconv.FormatUint(value, 10)
	for at := 0; at+len(want) <= len(message); at += 1 {
		found := strings.Index(message[at:], want)
		if found < 0 {
			return false
		}
		found += at
		before := found == 0 || !isDecimalDigit(message[found-1])
		after := found+len(want) == len(message) || !isDecimalDigit(message[found+len(want)])
		if before && after {
			return true
		}
		at = found
	}
	return false
}

func isDecimalDigit(octet byte) bool {
	return octet >= '0' && octet <= '9'
}

// TestTheNumberNamingReaderReadsAWholeNumberAndNotASubstring is that reader's control, in both
// directions for the reason every reader in this file carries one.
func TestTheNumberNamingReaderReadsAWholeNumberAndNotASubstring(t *testing.T) {
	for _, one := range []struct {
		message string
		value   uint64
		names   bool
	}{
		{"mls: unknown sender type: 5", 5, true},
		{"mls: no ratchet for this content type: content type 0", 0, true},
		{"5", 5, true},
		{"mls: 5 is not a sender type", 5, true},
		// the refusal that names a neighbouring code point rather than the one it refused
		{"mls: unknown sender type: 15", 5, false},
		{"mls: unknown sender type: 51", 5, false},
		{"mls: unknown sender type: 155", 5, false},
		// and the refusal that has stopped naming any of them
		{"mls: unknown sender type", 5, false},
	} {
		if got := namesTheNumber(one.message, one.value); got != one.names {
			t.Errorf("%q read against %d as %v, want %v", one.message, one.value, got, one.names)
		}
	}
}

// TestEveryFramingCodePointRefusalNamesTheCodePointItRefused is the behavioural half of the gate
// above, swept over every code point each registry does not declare rather than over the one
// somebody thought of.
//
// The two halves are different claims and this project has been caught by the gap between them.
// The derived gate reads the SOURCE and says the refusal mentions its own discriminant; this one
// reads the MESSAGE the caller actually receives, which is where a format verb dropped from one
// of the two, or an argument naming a stale copy of the code point, shows up.
func TestEveryFramingCodePointRefusalNamesTheCodePointItRefused(t *testing.T) {
	switches := framingRegistrySwitches(t)
	derived, invoked := slices.Sorted(maps.Keys(switches)), slices.Sorted(maps.Keys(framingCodePointRefusals))
	if !slices.Equal(derived, invoked) {
		t.Fatalf("this package's production source refuses an unregistered framing code point in %v and this file invokes %v; a refusal nothing invokes is a message nobody has ever read",
			derived, invoked)
	}
	refused := 0
	for _, method := range invoked {
		registry := switches[method].registry
		for _, codePoint := range undeclaredCodePointsOf(t, registry) {
			err := framingCodePointRefusals[method](codePoint)
			if err == nil {
				t.Fatalf("%s accepted the %s code point %d, which the registry does not declare", method, registry, codePoint)
			}
			if !namesTheNumber(err.Error(), codePoint) {
				t.Fatalf("%s refused the unregistered %s %d with %q, which does not name it; the octet is what the caller has off the wire, and a refusal that will not repeat it leaves a rejected header nobody can attribute to a value",
					method, registry, codePoint, err)
			}
			refused += 1
		}
	}
	if refused == 0 {
		t.Fatal("no unregistered code point was refused, so this observed nothing")
	}
	t.Logf("%d unregistered code point refusals over %d methods, each naming the value it refused", refused, len(invoked))
}

// ---------------------------------------------------------------------------
// the compile time pins framing.go carries
// ---------------------------------------------------------------------------

// framingPin is one package level blank declaration of framing.go: the type it declares and the
// value assigned to it, as source text, and whether that type is a signature.
type framingPin struct {
	file     string
	declared string
	value    string
	isFunc   bool
}

// framingPins reads them off the file.
//
// A blank declaration with no declared TYPE is not collected, and that exclusion is the reader's
// whole point. `var _ = (*T).MarshalMLS` states nothing whatever -- it compiles for every
// signature that method could ever have -- so collecting it would let the gate below report a
// pin present where the statement inside it had been emptied out, which is the same survivor
// the width pin reader was written to close one section up.
func framingPins(t *testing.T) []framingPin {
	t.Helper()
	found := []framingPin{}
	for _, file := range slices.Compact(slices.Sorted(maps.Values(framingCodecMethodFiles(t)))) {
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		for _, declaration := range parsed.Decls {
			generic, isGeneric := declaration.(*ast.GenDecl)
			if !isGeneric || (generic.Tok != token.VAR && generic.Tok != token.CONST) {
				continue
			}
			for _, spec := range generic.Specs {
				value, isValue := spec.(*ast.ValueSpec)
				if !isValue || value.Type == nil || len(value.Values) != len(value.Names) {
					continue
				}
				_, isFunc := value.Type.(*ast.FuncType)
				for at, name := range value.Names {
					if name.Name != "_" {
						continue
					}
					found = append(found, framingPin{
						file:     file,
						declared: types.ExprString(value.Type),
						value:    types.ExprString(value.Values[at]),
						isFunc:   isFunc,
					})
				}
			}
		}
	}
	return found
}

// syntaxCodecInterface is syntax.Codec as the type checker sees it, reached through this
// package's own import of it. Read through go/types rather than through reflect because the gate
// below asks about types NAMED in framing.go, which it has as strings off the syntax tree and
// cannot turn into values.
func syntaxCodecInterface(t *testing.T) *types.Interface {
	t.Helper()
	for _, imported := range typeCheckedPackage(t).Imports() {
		if imported.Path() != "github.com/urnetwork/connect/mls/syntax" {
			continue
		}
		declared, isType := imported.Scope().Lookup("Codec").(*types.TypeName)
		if !isType {
			t.Fatal("package syntax declares no Codec, so the pin gate cannot say which codecs can satisfy it")
		}
		asInterface, isInterface := declared.Type().Underlying().(*types.Interface)
		if !isInterface {
			t.Fatal("syntax.Codec is not an interface")
		}
		return asInterface
	}
	t.Fatal("package mls does not import package syntax, so syntax.Codec cannot be read from the type check")
	return nil
}

// TestEveryFramingCodecCarriesTheCompileTimePinItsShapeAllows is the presence guard framing.go's
// own pins never had.
//
// key_schedule_deps_test.go's TestNoPinBlockShrinksWithoutFailing is this package's guard against
// a detector being deleted along with the thing it detected, and its class is TEST files: it
// skips every name that does not end in _test.go. framing.go's pins are production source, one
// file type outside that class, so the two lines standing in for the var _ syntax.Codec this
// codec cannot have were counted by nothing and could both be deleted with the package green.
// That is measured, not supposed.
//
// What is required of each codec is derived from its own SHAPE rather than from a count. A type
// whose methods fit syntax.Codec owes the one interface pin. A type whose methods cannot fit it
// -- because the content type is a PARAMETER, which is registry section 7.2's decision and the
// reason this codec exists in the form it does -- owes a signature pin per method, that being
// the only remaining form a narrowing to Codec's shape stops compiling against.
func TestEveryFramingCodecCarriesTheCompileTimePinItsShapeAllows(t *testing.T) {
	pins := framingPins(t)
	codec := syntaxCodecInterface(t)
	scope := typeCheckedPackage(t).Scope()
	files := framingCodecMethodFiles(t)
	held := 0
	for _, method := range framingCodecMethods(t) {
		receiver, name, _ := strings.Cut(method, ".")
		file := files[method]
		declared, isType := scope.Lookup(receiver).(*types.TypeName)
		if !isType {
			t.Fatalf("%s declares the method %s and package mls holds no type %s", file, method, receiver)
		}
		// the pin has to stand in the file that declares the codec and not merely somewhere
		// in the derived set. A pin pooled across files would let one file's blank
		// declaration answer for a codec declared in another, which is a build time
		// statement the reader of that file cannot see.
		if types.Implements(types.NewPointer(declared.Type()), codec) {
			want := fmt.Sprintf("(*%s)(nil)", receiver)
			if !slices.ContainsFunc(pins, func(pin framingPin) bool {
				return pin.file == file && pin.value == want && pin.declared == "syntax.Codec"
			}) {
				t.Errorf("*%s satisfies syntax.Codec and %s declares no blank syntax.Codec pin assigned %s, so the day its methods drift out of that interface nothing says so at build time",
					receiver, file, want)
				continue
			}
			held += 1
			continue
		}
		want := fmt.Sprintf("(*%s).%s", receiver, name)
		if !slices.ContainsFunc(pins, func(pin framingPin) bool {
			return pin.file == file && pin.value == want && pin.isFunc
		}) {
			t.Errorf("*%s cannot satisfy syntax.Codec -- %s takes the discriminant registry section 7.2 keeps out of the struct -- and %s declares no blank pin of a signature type assigned %s, so a later task that stores that discriminant in a field and narrows this method to one argument compiles clean",
				receiver, name, file, want)
			continue
		}
		held += 1
	}
	if held == 0 {
		t.Fatal("no codec pin was matched, so this gate states nothing")
	}
	t.Logf("%d codec methods, each pinned in the form its own shape allows", held)
}

// ---------------------------------------------------------------------------
// the receiver discipline every framing decoder that publishes whole owes
// ---------------------------------------------------------------------------

// publishesItsReceiverWhole reports whether a decoder writes its receiver ONLY as a whole --
// one or more `*self = ...` and never a `self.Field = ...`.
//
// The cut is the assignment target and not the shape of the right hand side, because the target
// is what the property is about. A decoder that only ever assigns the whole receiver has one
// moment at which the caller's value changes, so "untouched unless the decode succeeded" is a
// statement that can be true of it. FramedContent and Proposal deliberately do the other thing:
// they reset the receiver part way through and then fill an arm into it with `self.Proposal =`,
// because their arms write different fields and a fully staged copy would be a second value
// built only to be copied over the first. Those two make no such promise and are not swept.
//
// A first pass at this cut read the right hand side instead -- a NAMED local staged into the
// receiver -- and it split the class wrongly: FramedContentAuthData publishes
// `*self = FramedContentAuthData{...}` after every read has succeeded, which is the property
// exactly, and a reader looking for an identifier dropped it. What survives the mutation this
// gate is here for is unaffected either way: an `*self = decoded` inserted ahead of the reads
// leaves the method assigning only whole receivers, so it stays in the class and is caught by
// the probe rather than quietly leaving it.
func publishesItsReceiverWhole(body *ast.BlockStmt) bool {
	whole, field := false, false
	ast.Inspect(body, func(node ast.Node) bool {
		assign, isAssign := node.(*ast.AssignStmt)
		if !isAssign {
			return true
		}
		for _, target := range assign.Lhs {
			switch typed := target.(type) {
			case *ast.StarExpr:
				if name, isName := typed.X.(*ast.Ident); isName && name.Name == "self" {
					whole = true
				}
			case *ast.SelectorExpr:
				if name, isName := typed.X.(*ast.Ident); isName && name.Name == "self" {
					field = true
				}
			}
		}
		return true
	})
	return whole && !field
}

// TestTheWholeReceiverReaderSeparatesADecodeThatPublishesOnceFromOneThatFillsFields is that
// reader's control, in both directions for the reason every reader in this file carries one.
// One that recognised everything would put FramedContent in the class and report the sweep
// below as covering a decoder that never promised this; one that recognised nothing would empty
// the class out and the sweep would report green having probed nobody.
func TestTheWholeReceiverReaderSeparatesADecodeThatPublishesOnceFromOneThatFillsFields(t *testing.T) {
	for _, one := range []struct {
		source    string
		publishes bool
	}{
		{"func (self *T) UnmarshalMLS(r *syntax.Reader) error { decoded := T{}; *self = decoded; return nil }", true},
		{"func (self *T) UnmarshalMLS(r *syntax.Reader) error { *self = T{A: 1}; return nil }", true},
		{"func (self *T) UnmarshalMLS(r *syntax.Reader) error { d := T{}; d.A = 1; *self = d; return nil }", true},
		// the reset and fill, which is a different promise and is not this one
		{"func (self *T) UnmarshalMLS(r *syntax.Reader) error { *self = T{A: 1}; self.B = 2; return nil }", false},
		{"func (self *T) UnmarshalMLS(r *syntax.Reader) error { self.A = 1; return nil }", false},
		// and a decoder that fills a local and never publishes it at all
		{"func (self *T) UnmarshalMLS(r *syntax.Reader) error { d := T{}; d.A = 1; return nil }", false},
	} {
		parsed, err := parser.ParseFile(token.NewFileSet(), "control.go",
			"package control\n"+one.source+"\n", parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %q: %v", one.source, err)
		}
		function, isFunction := parsed.Decls[0].(*ast.FuncDecl)
		if !isFunction {
			t.Fatalf("%q did not parse as a function declaration", one.source)
		}
		if got := publishesItsReceiverWhole(function.Body); got != one.publishes {
			t.Errorf("%q read as publishing whole=%v, want %v", one.source, got, one.publishes)
		}
	}
}

// framingDecodersThatPublishWhole is that class over this package's framing decoders, derived
// off the assignments rather than listed.
//
// Two of the four had a behavioural test for the property and two did not, which is rule 5's
// exact shape: the property was observed where somebody had thought of it rather than wherever
// it is promised. AuthenticatedContent.UnmarshalMLS could be made to assign *self BEFORE it read
// the content -- leaving a refused decode holding a wire format out of bytes the package refused,
// over whatever the caller's value held before -- with the whole of ./mls/... and ./message/...
// green. Measured. confirmedTranscriptHashInput.UnmarshalMLS publishes whole, documents that it
// does, and had nothing at all.
func framingDecodersThatPublishWhole(t *testing.T) []string {
	t.Helper()
	found := []string{}
	for _, function := range framingRegistryFunctions(t) {
		_, method, isMethod := strings.Cut(function.name, ".")
		if !isMethod || method != "UnmarshalMLS" || !publishesItsReceiverWhole(function.decl.Body) {
			continue
		}
		found = append(found, function.name)
	}
	slices.Sort(found)
	if len(found) == 0 {
		t.Fatal("no framing decoder was read as publishing its receiver whole, and this package holds several, so the sweep below would run over the empty set")
	}
	return found
}

// framingWholeReceiverProbe hands one of those decoders input it must refuse, over a receiver
// that already holds a value, and answers what that receiver held before and what it holds
// after.
//
// The prior contents matter as much as the refusal. A receiver left holding its own zero value
// is not "untouched" -- it is a decoder that wiped a caller's value on the way to refusing --
// and a probe starting from the zero value could not tell the two apart.
type framingWholeReceiverProbe func(t *testing.T) (before any, after any, err error)

var framingWholeReceiverProbes = map[string]framingWholeReceiverProbe{
	"Sender.UnmarshalMLS": func(t *testing.T) (any, any, error) {
		refused := []byte{byte(undeclaredCodePointsOf(t, "SenderType")[0]), 0x00, 0x00, 0x00, 0x00}
		before, after := testSenderOfType(SenderTypeMember), testSenderOfType(SenderTypeMember)
		err := after.UnmarshalMLS(syntax.NewReader(refused))
		return *before, *after, err
	},
	"FramedContentAuthData.UnmarshalMLS": func(t *testing.T) (any, any, error) {
		unregistered := ContentType(undeclaredCodePointsOf(t, "ContentType")[0])
		before, after := testAuthData(), testAuthData()
		err := after.UnmarshalMLS(syntax.NewReader(handDerivedAuthDataGolden(ContentTypeCommit)), unregistered)
		return *before, *after, err
	},
	"AuthenticatedContent.UnmarshalMLS": func(t *testing.T) (any, any, error) {
		// a REGISTERED wire format over content that cannot be read: the refusal has to come
		// from BEHIND the field the receiver would be stamped with, or a decoder that stamped
		// it early would have refused before it ever reached the assignment
		before, after := testAuthenticatedCommit(), testAuthenticatedCommit()
		err := after.UnmarshalMLS(syntax.NewReader(framingRefusedContentBehind(t, WireFormatPrivateMessage)))
		return before, after, err
	},
	"confirmedTranscriptHashInput.UnmarshalMLS": func(t *testing.T) (any, any, error) {
		priorCommit, decodedInto := testAuthenticatedCommit(), testAuthenticatedCommit()
		before, after := priorCommit.transcriptHashInput(), decodedInto.transcriptHashInput()
		err := after.UnmarshalMLS(syntax.NewReader(framingRefusedContentBehind(t, WireFormatPrivateMessage)))
		return *before, *after, err
	},
}

// framingRefusedContentBehind is a registered wire format followed by a FramedContent this
// package will not read: the two octets a wire format decoder stamps its receiver with, and
// then a refusal raised strictly after them.
func framingRefusedContentBehind(t *testing.T, wireFormat WireFormat) []byte {
	t.Helper()
	unregistered := ContentType(undeclaredCodePointsOf(t, "ContentType")[0])
	return append([]byte{byte(wireFormat >> 8), byte(wireFormat)},
		handDerivedFramedContentHeader(unregistered)...)
}

// TestEveryFramingDecodeThatPublishesItsReceiverWholeLeavesItUntouchedWhenItRefuses sweeps the
// class rather than the two members of it somebody wrote a test for.
//
// What a violation costs is not a mangled struct anybody would notice. It is a well formed value
// describing a message nobody sent: a caller that reused its receiver and checked the error is
// left holding fields read out of input this package refused, in a value that decodes, prints
// and re-encodes as though a peer had sent it.
func TestEveryFramingDecodeThatPublishesItsReceiverWholeLeavesItUntouchedWhenItRefuses(t *testing.T) {
	derived := framingDecodersThatPublishWhole(t)
	probed := slices.Sorted(maps.Keys(framingWholeReceiverProbes))
	if !slices.Equal(derived, probed) {
		t.Fatalf("this package publishes its receiver whole in %v and this file probes %v; a decoder nothing probes is a promise nobody has ever held it to",
			derived, probed)
	}
	for _, method := range probed {
		before, after, err := framingWholeReceiverProbes[method](t)
		if err == nil {
			t.Errorf("%s accepted the input this probe hands it, so what it left in the receiver states nothing", method)
			continue
		}
		if !reflect.DeepEqual(before, after) {
			t.Errorf("%s refused with %v and left its receiver holding %+v rather than the %+v it held going in; a refused decode that writes the receiver hands the caller a well formed value assembled out of bytes this package would not accept",
				method, err, after, before)
		}
	}
	t.Logf("%d framing decoders publishing their receiver whole, each leaving it untouched when it refuses", len(probed))
}

// ---------------------------------------------------------------------------
// the sentinel this file's codec borrows
// ---------------------------------------------------------------------------

// filesRaising is every production file of this package whose SYNTAX TREE names a symbol, less
// the file that declares it.
//
// Read as a tree rather than as text, so a file that only discusses the name in prose is not
// counted as a raiser of it -- framing_errors.go's package comment spends nine lines on
// ErrUnknownContentType and returns it nowhere, which is exactly the false positive a grep would
// report.
func filesRaising(t *testing.T, name string) []string {
	t.Helper()
	declaredIn := packageLevelDeclarations(t, ".")[name]
	if declaredIn == "" {
		t.Fatalf("package mls declares no %s, so where it is raised cannot be derived", name)
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package directory: %v", err)
	}
	found := []string{}
	fileSet := token.NewFileSet()
	for _, entry := range entries {
		fileName := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(fileName, ".go") ||
			strings.HasSuffix(fileName, "_test.go") || fileName == declaredIn {
			continue
		}
		parsed, err := parser.ParseFile(fileSet, fileName, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", fileName, err)
		}
		raises := false
		ast.Inspect(parsed, func(node ast.Node) bool {
			if identifier, isName := node.(*ast.Ident); isName && identifier.Name == name {
				raises = true
			}
			return !raises
		})
		if raises {
			found = append(found, fileName)
		}
	}
	slices.Sort(found)
	return found
}

// docCommentOfDeclaration is the comment written above one package level declaration, taken from
// the spec where a grouped block gives each name its own comment and from the block otherwise.
func docCommentOfDeclaration(t *testing.T, file string, name string) string {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	for _, declaration := range parsed.Decls {
		generic, isGeneric := declaration.(*ast.GenDecl)
		if !isGeneric {
			continue
		}
		for _, spec := range generic.Specs {
			value, isValue := spec.(*ast.ValueSpec)
			if !isValue || !slices.ContainsFunc(value.Names, func(each *ast.Ident) bool { return each.Name == name }) {
				continue
			}
			if value.Doc != nil {
				return value.Doc.Text()
			}
			if generic.Doc != nil {
				return generic.Doc.Text()
			}
			return ""
		}
	}
	t.Fatalf("%s declares no %s", file, name)
	return ""
}

// TestTheBorrowedSentinelIsDocumentedByEveryLayerThatRaisesIt is the other half of
// TestEveryStructuralFramingErrorHasExactlyOneDeclarationSite.
//
// That gate says ErrUnknownContentType has ONE declaration site and names it, which is the
// decision this task took rather than shadowing the secret tree's sentinel. It says nothing
// about what that single site TELLS a reader. The declaration was written when the ratchet
// lookup was the only thing that raised it, and the framing codec now raises it off the wire
// where there is no ratchet in view at all -- so the comment a reader arrives at, and the
// message a caller logs, described one of the two layers and not the other.
//
// The class is derived: every production file whose syntax tree names the sentinel must be named
// by the comment on its declaration. A third layer that starts raising it fails here on the
// commit that does so, which is the only moment anybody has the reason in their head.
func TestTheBorrowedSentinelIsDocumentedByEveryLayerThatRaisesIt(t *testing.T) {
	const borrowed = "ErrUnknownContentType"
	declaredIn := packageLevelDeclarations(t, ".")[borrowed]
	raisers := filesRaising(t, borrowed)
	if len(raisers) < 2 {
		t.Fatalf("%s is declared in %s and raised from %v; this gate exists because it is raised from more than one layer, and a derivation finding fewer is reading the wrong thing",
			borrowed, declaredIn, raisers)
	}
	doc := docCommentOfDeclaration(t, declaredIn, borrowed)
	if doc == "" {
		t.Fatalf("%s is declared in %s with no comment at all", borrowed, declaredIn)
	}
	for _, file := range raisers {
		if !strings.Contains(doc, file) {
			t.Errorf("%s raises %s and the comment on its declaration in %s does not name %s, so a reader arriving at the sentinel is told about some of the layers that return it and not this one",
				file, borrowed, declaredIn, file)
		}
	}
	t.Logf("%s is declared in %s and raised from %v, each of them named by its declaration", borrowed, declaredIn, raisers)
}

// ---------------------------------------------------------------------------
// FramedContent
// ---------------------------------------------------------------------------

func TestFramedContentRoundTripApplication(t *testing.T) {
	content := FramedContent{
		GroupId:           []byte{0xaa, 0xbb},
		Epoch:             5,
		Sender:            Sender{SenderType: SenderTypeMember, LeafIndex: 1},
		AuthenticatedData: []byte{0x01, 0x02, 0x03},
		ContentType:       ContentTypeApplication,
		ApplicationData:   []byte("hello"),
	}
	encoded, err := syntax.Marshal(&content)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	decoded := FramedContent{}
	if err := syntax.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	reencoded, err := syntax.Marshal(&decoded)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !bytes.Equal(encoded, reencoded) {
		t.Fatalf("re-encoded %x, want %x", reencoded, encoded)
	}
	if !bytes.Equal(decoded.ApplicationData, []byte("hello")) {
		t.Fatalf("application data %q", decoded.ApplicationData)
	}
}

func TestFramedContentRoundTripProposal(t *testing.T) {
	content := FramedContent{
		GroupId:     []byte{0x01},
		Epoch:       0,
		Sender:      Sender{SenderType: SenderTypeMember, LeafIndex: 3},
		ContentType: ContentTypeProposal,
		Proposal: &Proposal{
			ProposalType: ProposalTypeRemove,
			Remove:       &Remove{Removed: 2},
		},
	}
	encoded, err := syntax.Marshal(&content)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	decoded := FramedContent{}
	if err := syntax.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Proposal == nil || decoded.Proposal.Remove == nil ||
		decoded.Proposal.Remove.Removed != 2 {
		t.Fatalf("decoded proposal %+v", decoded.Proposal)
	}
}

func TestFramedContentRejectsArmMismatch(t *testing.T) {
	content := FramedContent{
		GroupId:         []byte{0x01},
		Sender:          Sender{SenderType: SenderTypeMember},
		ContentType:     ContentTypeApplication,
		ApplicationData: []byte("x"),
		Commit:          &Commit{},
	}
	// the refusal must survive syntax.Marshal, which joins the semantic error from MarshalMLS
	// with the Writer's sticky error
	if _, err := syntax.Marshal(&content); !errors.Is(err, ErrContentArmMismatch) {
		t.Fatalf("got %v, want ErrContentArmMismatch", err)
	}
}

func TestFramedContentRejectsUnknownContentType(t *testing.T) {
	content := FramedContent{
		GroupId:     []byte{0x01},
		Sender:      Sender{SenderType: SenderTypeMember},
		ContentType: ContentType(9),
	}
	if _, err := syntax.Marshal(&content); !errors.Is(err, ErrUnknownContentType) {
		t.Fatalf("got %v, want ErrUnknownContentType", err)
	}
}

// The encoder refuses before it writes, which framing.go argues for at length and which nothing
// else in this file observes for FramedContent.
//
// A FramedContent is the signature preimage and the transcript hash preimage, so a half written
// one that a caller ignored the error from is a preimage shorter than the message it claims to
// describe. The Writer is handed to the codec directly rather than through syntax.Marshal,
// because syntax.Marshal builds its own Writer and hands back nothing when it refuses -- which
// is precisely the octets this test is about.
func TestFramedContentWritesNothingBeforeItRefuses(t *testing.T) {
	content := FramedContent{
		GroupId:         bytes.Repeat([]byte{0xaa}, 8),
		Epoch:           5,
		Sender:          Sender{SenderType: SenderTypeMember, LeafIndex: 1},
		ContentType:     ContentTypeApplication,
		ApplicationData: []byte("x"),
		Commit:          &Commit{},
	}
	w := syntax.NewWriter()
	if err := content.MarshalMLS(w); !errors.Is(err, ErrContentArmMismatch) {
		t.Fatalf("got %v, want ErrContentArmMismatch", err)
	}
	if w.Len() != 0 {
		t.Fatalf("the refusal left %d octets on the caller's Writer; a FramedContent is the tail of nothing, so those octets are the front of a preimage that describes no message",
			w.Len())
	}
}

// ---------------------------------------------------------------------------
// AuthenticatedContent, the transcript hash input and the proposal reference
// ---------------------------------------------------------------------------

// newTestCrypto is one crypto provider constructor for this file's framing tests.
//
// It delegates to crypto_test.go's mustProvider rather than calling NewCryptoProvider again:
// two spellings of "the provider these tests run at" is two places for the suite to be chosen,
// and the suite is what decides KDF.Nh and therefore the width of every reference below.
func newTestCrypto(t *testing.T) CryptoProvider {
	t.Helper()
	return mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
}

// testAuthenticatedCommit is a commit carrying AuthenticatedContent, built once so the tests
// below vary one thing each rather than each declaring a slightly different value.
func testAuthenticatedCommit() AuthenticatedContent {
	return AuthenticatedContent{
		WireFormat: WireFormatPublicMessage,
		Content: FramedContent{
			GroupId:     []byte{0x07},
			Epoch:       2,
			Sender:      Sender{SenderType: SenderTypeMember, LeafIndex: 1},
			ContentType: ContentTypeCommit,
			Commit:      &Commit{},
		},
		Auth: FramedContentAuthData{
			Signature:       []byte{0xde, 0xad},
			ConfirmationTag: []byte{0xbe, 0xef},
		},
	}
}

// testAuthenticatedProposal is a proposal carrying AuthenticatedContent, for the reference tests.
func testAuthenticatedProposal() AuthenticatedContent {
	return AuthenticatedContent{
		WireFormat: WireFormatPublicMessage,
		Content: FramedContent{
			GroupId:     []byte{0x07},
			Epoch:       2,
			Sender:      Sender{SenderType: SenderTypeMember, LeafIndex: 1},
			ContentType: ContentTypeProposal,
			Proposal:    &Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 2}},
		},
		Auth: FramedContentAuthData{Signature: []byte{0xde, 0xad}},
	}
}

func TestAuthenticatedContentRoundTrip(t *testing.T) {
	authContent := testAuthenticatedCommit()
	encoded, err := syntax.Marshal(&authContent)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if encoded[0] != 0x00 || encoded[1] != 0x01 {
		t.Fatalf("wire format prefix %x, want 0001", encoded[0:2])
	}

	decoded := AuthenticatedContent{}
	if err := syntax.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	reencoded, err := syntax.Marshal(&decoded)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !bytes.Equal(encoded, reencoded) {
		t.Fatalf("re-encoded %x, want %x", reencoded, encoded)
	}
}

func TestConfirmedTranscriptHashInputOmitsConfirmationTag(t *testing.T) {
	authContent := testAuthenticatedCommit()
	authContent.WireFormat = WireFormatPrivateMessage
	input, err := authContent.ConfirmedTranscriptHashInput()
	if err != nil {
		t.Fatalf("input: %v", err)
	}

	w := syntax.NewWriter()
	w.WriteUint16(uint16(WireFormatPrivateMessage))
	if err := authContent.Content.MarshalMLS(w); err != nil {
		t.Fatalf("content: %v", err)
	}
	w.WriteOpaque(authContent.Auth.Signature)
	want, err := w.Bytes()
	if err != nil {
		t.Fatalf("bytes: %v", err)
	}
	if !bytes.Equal(input, want) {
		t.Fatalf("input %x, want %x", input, want)
	}
	if bytes.Contains(input, authContent.Auth.ConfirmationTag) {
		t.Fatal("confirmation tag leaked into ConfirmedTranscriptHashInput")
	}
}

func TestConfirmedTranscriptHashInputRefusesNonCommit(t *testing.T) {
	authContent := AuthenticatedContent{
		WireFormat: WireFormatPrivateMessage,
		Content: FramedContent{
			GroupId:         []byte{0x07},
			Sender:          Sender{SenderType: SenderTypeMember},
			ContentType:     ContentTypeApplication,
			ApplicationData: []byte("x"),
		},
		Auth: FramedContentAuthData{Signature: []byte{0x01}},
	}
	if _, err := authContent.ConfirmedTranscriptHashInput(); !errors.Is(err, ErrContentArmMismatch) {
		t.Fatalf("got %v, want ErrContentArmMismatch", err)
	}
}

// TestConfirmedTranscriptHashInputPrefixesTheSignatureAsAnMlsVector separates the two length
// prefixes this package can write, over the one input where the substitution is invisible.
//
// The signature enters the section 8.2 input as opaque<V>, section 2.1.2's varint: for a two
// octet signature that is the single octet 0x02. syntax's WriteOpaqueLP is the record layer's
// fixed thirty two bit prefix and would write 0x00000002 -- four octets where one belongs, three
// of them zero. Every member of a group running that code agrees with every other, the corpus is
// the only thing that disagrees, and the disagreement arrives as a permanent fork at the first
// commit shared with anybody else.
//
// The assertion is over the OCTETS between the framed content and the signature rather than over
// a golden blob, so it says which of the two prefixes was written rather than that the answer
// changed.
func TestConfirmedTranscriptHashInputPrefixesTheSignatureAsAnMlsVector(t *testing.T) {
	authContent := testAuthenticatedCommit()
	input, err := authContent.ConfirmedTranscriptHashInput()
	if err != nil {
		t.Fatalf("input: %v", err)
	}
	w := syntax.NewWriter()
	w.WriteUint16(uint16(authContent.WireFormat))
	if err := authContent.Content.MarshalMLS(w); err != nil {
		t.Fatalf("content: %v", err)
	}
	head, err := w.Bytes()
	if err != nil {
		t.Fatalf("bytes: %v", err)
	}
	if !bytes.HasPrefix(input, head) {
		t.Fatalf("the input %x does not open with the wire format and framed content %x", input, head)
	}
	signature := authContent.Auth.Signature

	varint := syntax.NewWriter()
	varint.WriteOpaque(signature)
	wantTail, err := varint.Bytes()
	if err != nil {
		t.Fatalf("varint bytes: %v", err)
	}
	recordLayer := syntax.NewWriter()
	recordLayer.WriteOpaqueLP(signature)
	unwantedTail, err := recordLayer.Bytes()
	if err != nil {
		t.Fatalf("record layer bytes: %v", err)
	}
	if bytes.Equal(wantTail, unwantedTail) {
		t.Fatalf("both prefixes wrote %x for a %d octet signature, so this test cannot separate them",
			wantTail, len(signature))
	}
	if tail := input[len(head):]; !bytes.Equal(tail, wantTail) {
		t.Fatalf("the signature was written as %x; the MLS opaque<V> is %x and the record layer's fixed prefix is %x",
			tail, wantTail, unwantedTail)
	}
}

// TestConfirmedTranscriptHashInputIsWhatThePublishedTranscriptChainConsumes is the assertion
// nothing in this package was making: that the input THIS plan builds is the input the key
// schedule plan's ConfirmedTranscriptHash was written to consume.
//
// The two halves were written by different plans against the same section and never met. p4 read
// transcript-hashes.json by SPLITTING the published AuthenticatedContent at a byte offset --
// len(blob) - (Nh + the width of that vector's own length prefix) -- because no framing type
// existed to parse it with, and both transcript_test.go and the family 7 runner say in as many
// words that when p6 lands (*AuthenticatedContent).UnmarshalMLS the offset is replaced by the
// parse. This is that landing, and this is the test that holds the two readings to each other
// before the offset stops being computed anywhere.
//
// Four things are compared per case, and they fail differently:
//
//   - the codec's ConfirmedTranscriptHashInput is byte for byte the offset split's head. A
//     preimage one octet longer or shorter than p4's is a transcript that forks.
//   - the confirmation tag the codec recovered is the offset split's tail, verified as
//     MAC(confirmation_key, confirmed_transcript_hash_after) -- the corpus's own step, which is
//     what makes the split honest rather than assumed.
//   - p4's own ConfirmedTranscriptHash over this plan's input is the PUBLISHED confirmed hash,
//     which is the end to end statement: this input, that function, the mlswg's answer.
//   - the serialized AuthenticatedContent re-encodes to the corpus's own octets, which is what
//     says the codec is canonical over bytes it did not produce -- and which drives Commit,
//     ProposalOrRef and the whole FramedContent decode over real published input rather than
//     over values this file built.
func TestConfirmedTranscriptHashInputIsWhatThePublishedTranscriptChainConsumes(t *testing.T) {
	entries := trPublishedEntries(t)
	reached := map[CipherSuite]int{}
	compared := 0
	for index, entry := range entries {
		suite := CipherSuite(entry.CipherSuite)
		if !IsRegisteredSuite(suite) {
			continue
		}
		at := fmt.Sprintf("%s entry %d suite %#04x", transcriptHashKatFile, index, uint16(suite))
		crypto := mustProvider(t, suite)
		blob := MustHex(t, entry.AuthenticatedContent)

		authContent := AuthenticatedContent{}
		if err := syntax.Unmarshal(blob, &authContent); err != nil {
			t.Fatalf("%s: the published authenticated_content did not decode: %v", at, err)
		}
		reencoded, err := syntax.Marshal(&authContent)
		if err != nil {
			t.Fatalf("%s: re-marshal: %v", at, err)
		}
		if !bytes.Equal(reencoded, blob) {
			t.Fatalf("%s: re-encoded %x, want the corpus's own %x", at, reencoded, blob)
		}

		head, tail := trSplitPublishedCommit(t, at, crypto, blob)
		input, err := authContent.ConfirmedTranscriptHashInput()
		if err != nil {
			t.Fatalf("%s: ConfirmedTranscriptHashInput: %v", at, err)
		}
		if !bytes.Equal(input, head) {
			t.Fatalf("%s: this plan builds the section 8.2 input as %x and the key schedule plan reads it out of the same blob as %x; the two halves of one transcript disagree",
				at, input, head)
		}
		if !bytes.Equal(authContent.Auth.ConfirmationTag, tail) {
			t.Fatalf("%s: the codec recovered the confirmation tag %x and the offset split recovered %x",
				at, authContent.Auth.ConfirmationTag, tail)
		}

		confirmed := ConfirmedTranscriptHash(crypto, MustHex(t, entry.InterimTranscriptHashBefore), input)
		if want := MustHex(t, entry.ConfirmedTranscriptHashAfter); !bytes.Equal(confirmed, want) {
			t.Fatalf("%s: ConfirmedTranscriptHash over this plan's input is %x, and the corpus publishes %x",
				at, confirmed, want)
		}
		// guardrail 8: the tag comparison is the provider's MacVerify and nothing spelled out
		// here. A split taken one octet out recovers bytes this refuses.
		if !crypto.MacVerify(MustHex(t, entry.ConfirmationKey), confirmed, authContent.Auth.ConfirmationTag) {
			t.Fatalf("%s: the confirmation tag the codec recovered does not verify as MAC(confirmation_key, confirmed_transcript_hash_after)",
				at)
		}
		reached[suite] += 1
		compared += 1
	}
	if compared == 0 {
		t.Fatalf("no case of %s was at a registered suite, so this compared nothing", transcriptHashKatFile)
	}
	for _, suite := range Suites() {
		if reached[suite] == 0 {
			t.Fatalf("%s carries no case at registered suite %#04x, so nothing above ran at it",
				transcriptHashKatFile, uint16(suite))
		}
	}
	t.Logf("%d published commits parsed, re-encoded and chained through the key schedule plan's own function", compared)
}

// TestTheSectionEightTwoInputDecodesBackToTheStructureItNames is the other direction of the
// preimage, over the corpus's own bytes.
//
// A preimage that only encodes is a preimage no test can hold against bytes it did not produce:
// the encode side is compared against the offset split next door, and both could be laying the
// fields out in an order that agrees with itself. Reading the head back as the section 8.2
// structure and finding the fields the corpus published is what says the layout is the RFC's.
func TestTheSectionEightTwoInputDecodesBackToTheStructureItNames(t *testing.T) {
	entries := trPublishedEntries(t)
	read := 0
	for index, entry := range entries {
		suite := CipherSuite(entry.CipherSuite)
		if !IsRegisteredSuite(suite) {
			continue
		}
		at := fmt.Sprintf("%s entry %d suite %#04x", transcriptHashKatFile, index, uint16(suite))
		crypto := mustProvider(t, suite)
		blob := MustHex(t, entry.AuthenticatedContent)
		head, _ := trSplitPublishedCommit(t, at, crypto, blob)

		input := confirmedTranscriptHashInput{}
		if err := syntax.Unmarshal(head, &input); err != nil {
			t.Fatalf("%s: the section 8.2 input did not decode: %v", at, err)
		}
		if input.Content.ContentType != ContentTypeCommit {
			t.Fatalf("%s: the published transcript entry decoded with content type %d, and section 8.2 chains over commits",
				at, input.Content.ContentType)
		}
		authContent := AuthenticatedContent{}
		if err := syntax.Unmarshal(blob, &authContent); err != nil {
			t.Fatalf("%s: authenticated_content: %v", at, err)
		}
		if input.WireFormat != authContent.WireFormat {
			t.Fatalf("%s: the input decoded wire format %d and the authenticated content %d",
				at, input.WireFormat, authContent.WireFormat)
		}
		if !bytes.Equal(input.Signature, authContent.Auth.Signature) {
			t.Fatalf("%s: the input decoded the signature %x and the authenticated content %x",
				at, input.Signature, authContent.Auth.Signature)
		}
		reencoded, err := syntax.Marshal(&input)
		if err != nil {
			t.Fatalf("%s: re-marshal: %v", at, err)
		}
		if !bytes.Equal(reencoded, head) {
			t.Fatalf("%s: the section 8.2 input re-encoded to %x, want %x", at, reencoded, head)
		}
		read += 1
	}
	if read == 0 {
		t.Fatalf("no case of %s was read back as the section 8.2 structure", transcriptHashKatFile)
	}
}

func TestProposalRefCoversTheWholeAuthenticatedContent(t *testing.T) {
	crypto := newTestCrypto(t)
	authContent := testAuthenticatedProposal()

	ref, err := authContent.ProposalRef(crypto)
	if err != nil {
		t.Fatalf("ref: %v", err)
	}
	if len(ref) != crypto.HashSize() {
		t.Fatalf("ref length %d, want %d", len(ref), crypto.HashSize())
	}
	encoded, err := syntax.Marshal(&authContent)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Equal(ref, MakeProposalRef(crypto, encoded)) {
		t.Fatal("ProposalRef is not MakeProposalRef over the serialized AuthenticatedContent")
	}

	// the signature is inside the ref, so re-signing changes it
	resigned := authContent
	resigned.Auth.Signature = []byte{0xde, 0xae}
	other, err := resigned.ProposalRef(crypto)
	if err != nil {
		t.Fatalf("ref: %v", err)
	}
	if bytes.Equal(ref, other) {
		t.Fatal("ProposalRef does not cover the signature")
	}
}

func TestProposalRefRefusesNonProposal(t *testing.T) {
	crypto := newTestCrypto(t)
	authContent := AuthenticatedContent{
		WireFormat: WireFormatPrivateMessage,
		Content: FramedContent{
			GroupId:         []byte{0x07},
			Sender:          Sender{SenderType: SenderTypeMember},
			ContentType:     ContentTypeApplication,
			ApplicationData: []byte("x"),
		},
		Auth: FramedContentAuthData{Signature: []byte{0x01}},
	}
	if _, err := authContent.ProposalRef(crypto); !errors.Is(err, ErrContentArmMismatch) {
		t.Fatalf("got %v, want ErrContentArmMismatch", err)
	}
}

// TestProposalRefIsNotTakenOverASmallerStructureOrWithoutItsLabel is the half of "the ref is over
// the right bytes" that no round trip and no length check can see.
//
// A reference taken over the FramedContent rather than the AuthenticatedContent, over the
// Proposal alone, with the label dropped, or with the key package label instead, is a hash of
// exactly the right width, stable across runs, self consistent, and different from what every
// other implementation computes. The commit that names a proposal by one is a commit no peer can
// apply, and nothing about it looks wrong from inside.
//
// The four wrong inputs are held against the real one rather than against each other, and each
// is spelled out here as the input a plausible mistake would produce.
func TestProposalRefIsNotTakenOverASmallerStructureOrWithoutItsLabel(t *testing.T) {
	crypto := newTestCrypto(t)
	authContent := testAuthenticatedProposal()
	ref, err := authContent.ProposalRef(crypto)
	if err != nil {
		t.Fatalf("ref: %v", err)
	}
	wholeStructure, err := syntax.Marshal(&authContent)
	if err != nil {
		t.Fatalf("marshal the authenticated content: %v", err)
	}
	framedContent, err := syntax.Marshal(&authContent.Content)
	if err != nil {
		t.Fatalf("marshal the framed content: %v", err)
	}
	proposal, err := syntax.Marshal(authContent.Content.Proposal)
	if err != nil {
		t.Fatalf("marshal the proposal: %v", err)
	}
	for _, wrong := range []struct {
		why   string
		value []byte
	}{
		{"taken over the FramedContent, so it covers neither the wire format nor the signature",
			MakeProposalRef(crypto, framedContent)},
		{"taken over the Proposal alone, so two members proposing the same removal share one reference",
			MakeProposalRef(crypto, proposal)},
		{"taken with the label dropped, so a proposal reference and a key package reference over one blob collide",
			RefHash(crypto, "", wholeStructure)},
		{"taken with no RefHashInput at all, which is the digest with both length prefixes gone",
			crypto.Hash(wholeStructure)},
		{"taken with the key package label, which is the other half of section 5.2's domain separation",
			MakeKeyPackageRef(crypto, wholeStructure)},
	} {
		if bytes.Equal(ref, wrong.value) {
			t.Errorf("ProposalRef equals the reference %s", wrong.why)
		}
	}
	if !bytes.Equal(ref, RefHash(crypto, ProposalRefLabel, wholeStructure)) {
		t.Fatal("ProposalRef is not RefHash over the serialized AuthenticatedContent under the proposal label, so the comparisons above are against the wrong baseline")
	}
}

// TestProposalRefIsTheProvidersWholeHash refuses a truncated reference.
//
// A ref cut short is still a ref: it is stable, it is the same on every run, and it collides
// with every other proposal sharing its prefix. The width is read off the provider rather than
// written down here, because both registered suites fix KDF.Nh at 32 and a literal 32 is right
// for both and wrong for the first suite this package adds.
func TestProposalRefIsTheProvidersWholeHash(t *testing.T) {
	crypto := newTestCrypto(t)
	authContent := testAuthenticatedProposal()
	ref, err := authContent.ProposalRef(crypto)
	if err != nil {
		t.Fatalf("ref: %v", err)
	}
	if len(ref) != crypto.HashSize() {
		t.Fatalf("the reference is %d octets and the provider's hash is %d", len(ref), crypto.HashSize())
	}
	// and a prefix of it is a different value, so a comparison against a truncated reference is
	// a comparison that fails rather than one that happens to agree
	if bytes.Equal(ref, ref[:len(ref)-1]) {
		t.Fatal("a reference one octet shorter compares equal to the whole one")
	}
}

// proposalRefFieldPath renders one field of one structure as the path this file's rows are keyed
// by.
func proposalRefFieldPath(structure reflect.Type, field reflect.StructField) string {
	return structure.Name() + "." + field.Name
}

// proposalRefFieldsOf walks a VALUE and answers every field of it that a row has to account for.
//
// The walk is over the value rather than over the type, and that is what bounds it: it descends
// into a struct field and into a non-nil pointer to a struct, so a proposal carrying a Remove
// reaches AuthenticatedContent, FramedContent, Sender, FramedContentAuthData, Proposal and
// Remove, and stops at the arms that are nil. A type walk would follow Add into KeyPackage into
// LeafNode into Credential and answer the whole package.
//
// A field the walk descends INTO owes no row of its own -- its leaves carry it -- and every other
// field owes one. So the class is what the value is made of, and an eighth field added to any of
// those six structures arrives here without an edit.
func proposalRefFieldsOf(value reflect.Value, found *[]string) {
	structure := value.Type()
	for i := 0; i < structure.NumField(); i += 1 {
		field := structure.Field(i)
		held := value.Field(i)
		if held.Kind() == reflect.Struct {
			proposalRefFieldsOf(held, found)
			continue
		}
		if held.Kind() == reflect.Pointer && !held.IsNil() && held.Elem().Kind() == reflect.Struct {
			proposalRefFieldsOf(held.Elem(), found)
			continue
		}
		*found = append(*found, proposalRefFieldPath(structure, field))
	}
}

// What one field's mutation must do to the reference.
type proposalRefOutcome int

const (
	// the field is on the wire for this shape, so the reference must MOVE
	proposalRefMoves proposalRefOutcome = iota
	// the field is not written for this shape, so the reference must not move. Each row saying
	// this names the reason, and the reason is always a select() that did not select it.
	proposalRefUnchanged
	// the field cannot be varied and leave an encodable proposal, so the reference cannot be
	// computed at all
	proposalRefRefused
)

// One field, how to vary it, and what that must do.
type proposalRefVariation struct {
	outcome proposalRefOutcome
	why     string
	vary    func(authContent *AuthenticatedContent)
}

// proposalRefVariations is the behaviour half: one row per field the walk above finds.
//
// The CLASS is derived and this is the classification of it, which is the division this project
// settled on after fourteen hand written classes turned out to understate what they stood for. A
// field with no row fails; a row naming a field the walk does not reach fails. What each row
// asserts is a real property in both directions -- a field on the wire must move the reference,
// and a field the select() did not select must not, which is the statement that a reference
// covers the message rather than the struct.
func proposalRefVariations() map[string]proposalRefVariation {
	return map[string]proposalRefVariation{
		"AuthenticatedContent.WireFormat": {proposalRefMoves,
			"the wire format is the first field of the serialization",
			func(a *AuthenticatedContent) { a.WireFormat = WireFormatPrivateMessage }},
		"FramedContent.GroupId": {proposalRefMoves,
			"the group id is inside the framed content",
			func(a *AuthenticatedContent) { a.Content.GroupId = []byte{0x08} }},
		"FramedContent.Epoch": {proposalRefMoves,
			"the epoch is what stops a proposal being replayed into another one",
			func(a *AuthenticatedContent) { a.Content.Epoch = 3 }},
		"FramedContent.AuthenticatedData": {proposalRefMoves,
			"the authenticated data is covered by the signature and therefore by the reference",
			func(a *AuthenticatedContent) { a.Content.AuthenticatedData = []byte{0x09} }},
		"FramedContent.ContentType": {proposalRefRefused,
			"a reference is only taken over a proposal",
			func(a *AuthenticatedContent) { a.Content.ContentType = ContentTypeCommit }},
		"FramedContent.ApplicationData": {proposalRefRefused,
			"application data beside a proposal is an arm mismatch",
			func(a *AuthenticatedContent) { a.Content.ApplicationData = []byte{0x0a} }},
		"FramedContent.Commit": {proposalRefRefused,
			"a commit beside a proposal is an arm mismatch",
			func(a *AuthenticatedContent) { a.Content.Commit = &Commit{} }},
		"Sender.SenderType": {proposalRefMoves,
			"the sender type selects which arm of Sender is written",
			func(a *AuthenticatedContent) { a.Content.Sender.SenderType = SenderTypeNewMemberProposal }},
		"Sender.LeafIndex": {proposalRefMoves,
			"the leaf index is what makes two members' identical proposals different references",
			func(a *AuthenticatedContent) { a.Content.Sender.LeafIndex = 9 }},
		"Sender.SenderIndex": {proposalRefUnchanged,
			"SenderIndex is the external arm and this sender is a member, so it is not written",
			func(a *AuthenticatedContent) { a.Content.Sender.SenderIndex = 9 }},
		"FramedContentAuthData.Signature": {proposalRefMoves,
			"the signature is inside the reference, so re-signing renames the proposal",
			func(a *AuthenticatedContent) { a.Auth.Signature = []byte{0xde, 0xae} }},
		"FramedContentAuthData.ConfirmationTag": {proposalRefUnchanged,
			"the confirmation tag is the commit arm of the auth data and this is a proposal, so it is not written",
			func(a *AuthenticatedContent) { a.Auth.ConfirmationTag = []byte{0xbe, 0xef} }},
		"Proposal.ProposalType": {proposalRefRefused,
			"a proposal type naming an arm that is not populated is an arm mismatch",
			func(a *AuthenticatedContent) { a.Content.Proposal.ProposalType = ProposalTypeAdd }},
		"Proposal.Add": {proposalRefRefused,
			"a second arm is refused rather than dropped, or the two values would share a reference",
			func(a *AuthenticatedContent) { a.Content.Proposal.Add = &Add{} }},
		"Proposal.Update": {proposalRefRefused,
			"a second arm is refused rather than dropped",
			func(a *AuthenticatedContent) { a.Content.Proposal.Update = &Update{} }},
		"Proposal.PreSharedKey": {proposalRefRefused,
			"a second arm is refused rather than dropped",
			func(a *AuthenticatedContent) { a.Content.Proposal.PreSharedKey = &PreSharedKey{} }},
		"Proposal.ReInit": {proposalRefRefused,
			"a second arm is refused rather than dropped",
			func(a *AuthenticatedContent) { a.Content.Proposal.ReInit = &ReInit{} }},
		"Proposal.ExternalInit": {proposalRefRefused,
			"a second arm is refused rather than dropped",
			func(a *AuthenticatedContent) { a.Content.Proposal.ExternalInit = &ExternalInit{} }},
		"Proposal.GroupContextExtensions": {proposalRefRefused,
			"a second arm is refused rather than dropped",
			func(a *AuthenticatedContent) { a.Content.Proposal.GroupContextExtensions = &GroupContextExtensions{} }},
		"Proposal.UnknownType": {proposalRefMoves,
			"UnknownType overrides the discriminant that goes on the wire",
			func(a *AuthenticatedContent) { a.Content.Proposal.UnknownType = ProposalType(0x0a0a) }},
		"Proposal.UnknownBody": {proposalRefRefused,
			"a verbatim body beside a registered arm is a second arm",
			func(a *AuthenticatedContent) { a.Content.Proposal.UnknownBody = []byte{0x00} }},
		"Remove.Removed": {proposalRefMoves,
			"the removed leaf is the whole content of the proposal",
			func(a *AuthenticatedContent) { a.Content.Proposal.Remove.Removed = 5 }},
	}
}

// TestProposalRefsAreDistinctAcrossTheGeneratedProposalSpace is the collision property, over a
// space derived from the structures a proposal is built out of rather than from a list of the
// fields somebody thought of.
//
// Two properties, and they are separate claims:
//
//   - every field the encoding covers moves the reference, and no two of those references
//     collide with each other or with the base. A reference that did not move for one field is a
//     field the proposal carries and the reference does not, which is two distinct proposals
//     under one name.
//   - every field the encoding does NOT cover leaves the reference alone. That direction is not
//     a formality: it is the statement that the reference is over the MESSAGE and not over the
//     struct, and the two rows that assert it are the two select() arms this shape does not
//     take.
//
// The rows are held to the derived field set in both directions, so a field added to any of the
// six structures a proposal reaches fails here rather than being quietly outside the sweep.
func TestProposalRefsAreDistinctAcrossTheGeneratedProposalSpace(t *testing.T) {
	crypto := newTestCrypto(t)
	base := testAuthenticatedProposal()
	fields := []string{}
	proposalRefFieldsOf(reflect.ValueOf(base), &fields)
	slices.Sort(fields)
	fields = slices.Compact(fields)
	if len(fields) < 10 {
		t.Fatalf("the walk read %v out of a proposal carrying AuthenticatedContent, which is fewer fields than those structures have", fields)
	}

	variations := proposalRefVariations()
	for name := range variations {
		if !slices.Contains(fields, name) {
			t.Errorf("this file varies %s and no field of a proposal carrying AuthenticatedContent is reached under that name", name)
		}
	}

	baseRef, err := base.ProposalRef(crypto)
	if err != nil {
		t.Fatalf("the base reference: %v", err)
	}
	seen := map[string]string{string(baseRef): "the unvaried proposal"}
	moved, unchanged, refused := 0, 0, 0
	for _, name := range fields {
		variation, written := variations[name]
		if !written {
			t.Errorf("%s is a field of a proposal carrying AuthenticatedContent and nothing varies it, so nothing says whether the reference covers it",
				name)
			continue
		}
		varied := base
		varied.Content.Proposal = &Proposal{}
		*varied.Content.Proposal = *base.Content.Proposal
		varied.Content.Proposal.Remove = &Remove{}
		*varied.Content.Proposal.Remove = *base.Content.Proposal.Remove
		variation.vary(&varied)

		ref, err := varied.ProposalRef(crypto)
		switch variation.outcome {
		case proposalRefRefused:
			if err == nil {
				t.Errorf("%s varied and the reference came back anyway; the row says it is refused because %s", name, variation.why)
				continue
			}
			refused += 1
			continue
		case proposalRefUnchanged:
			if err != nil {
				t.Errorf("%s varied and the reference was refused with %v; the row says it is not written because %s", name, err, variation.why)
				continue
			}
			if !bytes.Equal(ref, baseRef) {
				t.Errorf("%s varied and the reference moved; the row says %s, so it is on the wire after all", name, variation.why)
				continue
			}
			unchanged += 1
			continue
		}
		if err != nil {
			t.Errorf("%s varied and the reference was refused with %v; the row says it is on the wire because %s", name, err, variation.why)
			continue
		}
		if other, collided := seen[string(ref)]; collided {
			t.Errorf("varying %s produced the same reference as %s; two distinct proposals share one name, and a commit naming that reference applies whichever of the two arrived first",
				name, other)
			continue
		}
		seen[string(ref)] = "the proposal with " + name + " varied"
		moved += 1
	}
	if moved == 0 || unchanged == 0 || refused == 0 {
		t.Fatalf("the sweep moved %d references, left %d alone and refused %d; with any of the three empty this gate holds fewer rules than it states",
			moved, unchanged, refused)
	}
	t.Logf("%d fields on the wire and pairwise distinct, %d off it and unchanged, %d refused, over %d derived fields",
		moved, unchanged, refused, len(fields))
}

// ---------------------------------------------------------------------------
// the proposal reference, against bytes this project did not produce
// ---------------------------------------------------------------------------

// TestTheProposalReferenceOfADecodedPublishedProposalIsTheOneItsCommitNames is the only
// assertion in this package that holds (*AuthenticatedContent).ProposalRef -- and the whole
// codec chain underneath it -- against bytes this project did not compute.
//
// Every other reference test above compares the method against MakeProposalRef and RefHash over
// syntax.Marshal of a value built HERE, which is the same two functions the method itself calls
// over an encoding the same encoder wrote. That is self agreement, and self agreement cannot see
// a codec and a preimage that are wrong together -- which is the entire failure mode
// framing_preimage.go's own header says it exists to prevent: not a wrong answer, a group that
// agrees with itself and with nobody else.
//
// The transcript corpus this file already reads is no help there. Every entry of it is a COMMIT
// -- TestTheSectionEightTwoInputDecodesBackToTheStructureItNames makes a non commit fatal -- so
// before this test no proposal shaped AuthenticatedContent had ever been held against published
// bytes, and no computed ProposalRef against a published one.
//
// passive-client-handling-commit.json publishes both halves and is already vendored, already
// loaded in this package and already sliced to exactly these bytes by crypto_labels_test.go's
// TestProposalRefLabelMatchesThePublishedCommits. What that test cannot say is anything about
// this package's FRAMING: it hashes the published slice directly and never decodes it. Running
// the same slice through the codec and back out anchors four things at once against mlswg's own
// bytes -- AuthenticatedContent's codec over a proposal, FramedContent's proposal arm, the whole
// Proposal codec, and the reference itself.
func TestTheProposalReferenceOfADecodedPublishedProposalIsTheOneItsCommitNames(t *testing.T) {
	vectors := []labelKatPassiveClient{}
	loadLabelKat(t, "passive-client-handling-commit.json", &vectors)
	anchored := 0
	for _, vector := range vectors {
		suite := CipherSuite(vector.CipherSuite)
		if !IsRegisteredSuite(suite) {
			continue
		}
		crypto := mustProvider(t, suite)
		// the membership tag is a mac of the suite's hash size carried as a vector, and at
		// thirty two bytes its length prefix is the one octet form
		membershipTag := 1 + crypto.HashSize()
		for epochIndex, epoch := range vector.Epochs {
			commit := mustDecodeHex(t, "the published commit", epoch.Commit)
			for _, published := range epoch.Proposals {
				at := fmt.Sprintf("suite %#04x epoch %d", uint16(suite), epochIndex)
				message := mustDecodeHex(t, "the published proposal", published)
				if len(message) <= len(mlsMessagePublicMessageHeader)+membershipTag ||
					!bytes.HasPrefix(message, mlsMessagePublicMessageHeader) {
					t.Errorf("%s: the proposal is %d bytes headed %x, want an mls10 public message",
						at, len(message), message[:min(len(message), len(mlsMessagePublicMessageHeader))])
					continue
				}
				// MLSMessage = version || AuthenticatedContent || membership_tag<V>, so the
				// content is the message without its two octet version and without the tag
				// (RFC 9420 sections 6.1 and 6.2). The slice is the one crypto_labels_test.go
				// asserts its way to and is not re-derived here.
				authenticatedContent := message[mlsMessageVersionLength : len(message)-membershipTag]
				decoded := AuthenticatedContent{}
				if err := syntax.Unmarshal(authenticatedContent, &decoded); err != nil {
					t.Errorf("%s: the published authenticated content did not decode: %v", at, err)
					continue
				}
				if decoded.Content.ContentType != ContentTypeProposal {
					t.Errorf("%s: the published proposal decoded as content type %d, so this vector is not what this test believes it is",
						at, decoded.Content.ContentType)
					continue
				}
				// the codec is held to the published bytes BEFORE the reference is taken over
				// it. A re-encoding that differed would otherwise arrive as a reference that
				// does not appear in the commit, which reads as a label or a hash defect and is
				// not one.
				reencoded, err := syntax.Marshal(&decoded)
				if err != nil {
					t.Errorf("%s: re-encoding the published authenticated content: %v", at, err)
					continue
				}
				if !bytes.Equal(reencoded, authenticatedContent) {
					t.Errorf("%s: the published authenticated content decoded and re-encoded to %x, want the %x it was decoded from",
						at, reencoded, authenticatedContent)
					continue
				}
				reference, err := decoded.ProposalRef(crypto)
				if err != nil {
					t.Errorf("%s: ProposalRef over the published proposal: %v", at, err)
					continue
				}
				if count := bytes.Count(commit, reference); count != 1 {
					t.Errorf("%s: the reference %x this package computes for the published proposal appears %d times in the published commit, want once",
						at, reference, count)
					continue
				}
				anchored += 1
			}
		}
	}
	// the count is pinned to the same constant crypto_labels_test.go pins its own sweep to, so
	// a corpus that stopped parsing, or a suite filter that stopped matching, fails here rather
	// than reporting green having anchored nothing
	if anchored != labelKatProposalRefs {
		t.Fatalf("anchored %d published proposal references through this package's codec, want %d", anchored, labelKatProposalRefs)
	}
	t.Logf("%d published proposals decoded, re-encoded byte identically and referenced as their own commits name them", anchored)
}
