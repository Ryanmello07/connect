// The mechanical half of convention C1 for this package: the byte level codec of an MLS
// structure is mls/syntax, reached through the two hooks syntax's own interfaces declare, and
// never a per type wrapper of this package's own.
//
// What this file is NOT is the whole of task 27's list, and the reason is worth writing down
// where the next person reads it. Most of what that task proposed to ban is already banned,
// by gates that DERIVE their class where the proposal enumerated one:
//
//   - hkdf.Extract and hkdf.Expand: crypto_forbidden_test.go confines every entry point
//     crypto/hkdf declares, by path, with a control fixture that calls each of them from an
//     allowed file, from a nested twin of one and from a file allowed nothing. That gate held
//     one name until this task and hkdf.Expand walked past it in ../message/writeauth.go.
//   - curve25519.ScalarMult, box.Precompute, GenerateSharedSecret, math/rand: the banned
//     primitive scan next door, plus TestTheCryptoIsBuiltFromExactlyThesePackages, which pins
//     the complete import set of mls AND message rather than banning a list of packages.
//   - bytes.Equal on a tag: TestEveryTagVerifierComparesThroughMacVerifyAndNothingElse reads
//     what a verifier ANSWERS rather than which words it contains, so a byte loop carrying no
//     comparator at all is reported too; and connect/message's G8 gate derives its comparator
//     class from the imports of the code it scans and finds eighteen, bytes.HasPrefix and
//     hmac.Equal among them.
//   - a redeclared ValSem sentinel: TestPskSentinelsBelongToTheValidationPlan.
//   - w.WriteBytes: TestConsumedSyntaxWriterShape pins syntax.Writer's method set, and a call
//     to a method that does not exist is a compile error either way.
//
// A fifth gate that duplicates a fourth reads as coverage and is not. What was left uncovered
// is the codec half, and that is what is here.
package mls

import (
	"go/ast"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The verbs that name a byte level codec entry point in this tree.
//
// A PREFIX and not a substring: ConfirmedTranscriptHash is not a parser because it has the
// letters of one in the middle of it, and a rule that fired on the substring would be
// switched off by the first person it inconvenienced.
var keyScheduleCodecVerbs = []string{"Marshal", "Unmarshal", "Parse"}

// The subpackage the codec lives in, relative to this package's directory.
const keyScheduleCodecPackageDir = "syntax"

// syntaxCodecHooks is the sanctioned half of the rule: the codec entry points a type of this
// package MAY declare, read off the interfaces mls/syntax declares rather than written down.
//
// Derived because the exemption is the half that has been understated fourteen times on this
// project. If syntax grows a third hook -- an interface method that a structure implements to
// be encoded -- the types implementing it are sanctioned by that declaration rather than by
// somebody remembering to come back here, and if syntax RENAMES one, this stops recognising
// the old spelling and the rule starts objecting to it, which is the correct direction.
func syntaxCodecHooks(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(keyScheduleCodecPackageDir)
	if err != nil {
		t.Fatalf("read %s, where the sanctioned hooks are derived from: %v", keyScheduleCodecPackageDir, err)
	}
	hooks := []string{}
	read := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		read++
		parsed := mustParseSource(t, filepath.Join(keyScheduleCodecPackageDir, name))
		ast.Inspect(parsed.file, func(node ast.Node) bool {
			declared, isInterface := node.(*ast.InterfaceType)
			if !isInterface {
				return true
			}
			for _, method := range fieldsOf(declared.Methods) {
				if _, isFunctionType := method.Type.(*ast.FuncType); !isFunctionType {
					continue
				}
				for _, named := range method.Names {
					if keyScheduleIsCodecEntryPoint(named.Name) {
						hooks = append(hooks, named.Name)
					}
				}
			}
			return true
		})
	}
	slices.Sort(hooks)
	hooks = slices.Compact(hooks)
	if read == 0 {
		t.Fatalf("no non test file of %s was read, so the sanctioned set is empty and this gate would object to the codec itself",
			keyScheduleCodecPackageDir)
	}
	// the derivation's own positive control. These two are the hooks syntax.Marshaler and
	// syntax.Unmarshaler certainly declare, and a derivation that stopped deriving would
	// report every structure of this package as carrying a codec of its own.
	for _, hook := range []string{"MarshalMLS", "UnmarshalMLS"} {
		if !slices.Contains(hooks, hook) {
			t.Fatalf("the derivation read %v out of %s and %s is not among them, so it is reading no interface at all",
				hooks, keyScheduleCodecPackageDir, hook)
		}
	}
	return hooks
}

// Whether one declared name opens with a codec verb.
func keyScheduleIsCodecEntryPoint(name string) bool {
	return slices.ContainsFunc(keyScheduleCodecVerbs, func(verb string) bool {
		return strings.HasPrefix(name, verb)
	})
}

// keyScheduleCodecWrappersIn is every declaration of one file that is a byte level codec
// entry point and is not one of the sanctioned hooks, named with its receiver so a reader is
// told which type grew one.
func keyScheduleCodecWrappersIn(parsed parsedSource, sanctioned []string) []string {
	found := []string{}
	for _, declaration := range parsed.file.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if !isFunction || !keyScheduleIsCodecEntryPoint(function.Name.Name) {
			continue
		}
		if slices.Contains(sanctioned, function.Name.Name) {
			continue
		}
		if receiver := parsed.receiverOf(function); receiver != "" {
			found = append(found, "("+receiver+")."+function.Name.Name)
			continue
		}
		found = append(found, function.Name.Name)
	}
	slices.Sort(found)
	return found
}

// keyScheduleCodecControl declares one of each shape the rule has to tell apart: the two
// sanctioned hooks, the free constructor and the per type wrapper convention C1 bans, the two
// extension vector spellings that do not exist -- the codec is WriteExtensions/ReadExtensions
// -- and one name that carries a verb in the middle rather than at the front.
//
// The last of those is the half that keeps this from being a substring match. Without it the
// prefix test can be replaced by strings.Contains and the control goes on matching exactly,
// which is measured rather than supposed; with it, that edit reports a transcript hash
// accessor as a decoder and a reader learns to ignore the gate.
const keyScheduleCodecControl = `package control

type GroupContext struct{}

type PreSharedKeyId struct{}

// the sanctioned pair, which is how every structure of this package is encoded
func (self *GroupContext) MarshalMLS(w *syntax.Writer) error { return nil }

func (self *GroupContext) UnmarshalMLS(r *syntax.Reader) error { return nil }

// the free constructor: a byte level decode that is not syntax.Unmarshal
func ParseGroupContext(b []byte) (*GroupContext, error) { return nil, nil }

func ParsePreSharedKeyId(b []byte) (*PreSharedKeyId, error) { return nil, nil }

// the per type wrapper: a byte level encode that is not syntax.Marshal
func (self *GroupContext) Marshal() []byte { return nil }

// the extension vector codec written under a name that does not exist
func MarshalExtensions(extensions []Extension) []byte { return nil }

func ParseExtensions(b []byte) ([]Extension, error) { return nil, nil }

// a verb in the middle of a name, which is not a codec entry point
func (self *GroupContext) ConfirmedTranscriptHashParsedElsewhere() []byte { return nil }
`

// What the rule must read out of the control, exactly. Exact rather than a floor in both
// directions: a rule that widened to report the accessor would be switched off, and one that
// narrowed to miss the method wrapper would issue this package the clean bill a working one
// issues.
var keyScheduleCodecControlWrappers = []string{
	"(*GroupContext).Marshal",
	"MarshalExtensions",
	"ParseExtensions",
	"ParseGroupContext",
	"ParsePreSharedKeyId",
}

// The p4-owned production files, held as a FLOOR on what the scan reads rather than as its
// scope.
//
// The plan wrote this list as the scope, and a scope written as seven file names is the
// exemption shape this project keeps rediscovering: the eighth file is outside it, and a
// wrapper written there passes. So the gate reads every non test file of the package and this
// list only asserts that the reading covered what the plan owns -- a file renamed or deleted
// fails here and says so, and a file ADDED is covered without an edit.
var keyScheduleOwnedFiles = []string{
	"errors_key_schedule.go",
	"group_context.go",
	"key_schedule.go",
	"psk.go",
	"secret_tree.go",
	"secret_zeroize.go",
	"transcript.go",
}

// TestNoTypeOfThisPackageCarriesAByteLevelCodecOfItsOwn is convention C1, enforced.
//
// The rule is one implementation of the wire format, and the reason is that a second one
// disagrees with the first eventually and never at the moment it is written. A hand rolled
// ParseGroupContext that reads the fields in the order the struct happens to declare them
// round trips its own output perfectly and disagrees with every other implementation on the
// wire; a Marshal() wrapper that forgets a vector's length prefix produces bytes this package
// decodes and no other does. Neither is visible to a round trip property, which is what makes
// this a source rule rather than a behavioural one.
//
// It is over every non test file of the package rather than over the seven the plan named,
// and the sanctioned exemption is read off mls/syntax rather than written here.
func TestNoTypeOfThisPackageCarriesAByteLevelCodecOfItsOwn(t *testing.T) {
	sanctioned := syntaxCodecHooks(t)

	// the control first, on both halves: the rule must report every banned shape and must
	// report neither hook nor the accessor.
	control := mustParseText(t, "the byte level codec control", keyScheduleCodecControl)
	if reported := keyScheduleCodecWrappersIn(control, sanctioned); !slices.Equal(reported, keyScheduleCodecControlWrappers) {
		t.Fatalf("the rule reported %v out of the control, want %v; a shape it lets through is a shape this package can be written in, and a shape it adds is one a reader will learn to ignore",
			reported, keyScheduleCodecControlWrappers)
	}

	// then this package's own source, every non test file of it
	scanned := packageLevelFunctions(t).files
	for _, owned := range keyScheduleOwnedFiles {
		if !slices.Contains(scanned, owned) {
			t.Fatalf("the scan read %v and %s is not among them, so this gate is not reading the files the key schedule lives in",
				scanned, owned)
		}
	}
	for _, path := range scanned {
		for _, wrapper := range keyScheduleCodecWrappersIn(mustParseSource(t, path), sanctioned) {
			t.Errorf("%s declares %s, and convention C1 says the byte level codec of an MLS structure is syntax.Marshal and syntax.Unmarshal reached through %v: a second encoder agrees with the first until it does not, and no round trip property can see the disagreement",
				path, wrapper, sanctioned)
		}
	}
}
