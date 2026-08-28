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
//   - a redeclared ValSem sentinel: two things, neither of them a scan. psk.go carries the
//     three refusals as UNEXPORTED values precisely so the exported names stay p8's, and a
//     second declaration of an exported one in this package is a compile error the day p8
//     lands it. Until then all seven names sit in crossPlanSymbolsNotYetLanded, and
//     TestEveryCrossPlanSymbolThatHasLandedIsPinnedHere fails on the merge that lands any of
//     them rather than on somebody remembering.
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
//
// bodies is the second sanctioned exemption, and it is DERIVED rather than written down: the
// extension body types of the same source, read off the Encode() (Extension, error) signature
// by extensionBodyTypesIn. Extension.ExtensionData is opaque, so a concrete extension body has
// to convert bytes to and from a struct somewhere, and the spelling this package sanctions for
// that is Encode answering the whole Extension paired with ParseXExtension taking the bytes.
//
// The exemption is over the PAIR and not over the Parse name, which is the difference between
// a guarantee and a naming convention. A ParseFooExtension is waved through only when Foo's own
// Encode answers an Extension -- tag and body together, so the package never hands a loose body
// to a call site that could pair it with another extension's type -- and only when the Parse
// names the type it answers and takes nothing but the bytes. An Encode answering []byte hands
// the tag choice back to the caller and exempts nothing; a Parse whose name does not name its
// own result is not the pair either. The control below declares one of each, so an exemption
// that widened to cover them fails there rather than in a review.
//
// There are TWO sanctioned read side spellings and not one, and the second is exempt on a
// stricter reading than the first. ParseLeafKeysFrom is handed the whole Extension and answers
// the body, so the tag is in its hands and it is the only entry point that can refuse a body
// arriving under the wrong one. That shape carries no byte run in its signature at all, so it
// is not a byte level codec by any reading and only the NAME rule here was ever going to
// object to it. The body it belongs to is therefore read off its RESULT rather than off its
// name -- what sanctions the shape is the types, not what somebody called it -- and the near
// miss the control declares is the same shape answering a structure that is not an extension
// body, which is a second decoder for something whose codec is syntax.Unmarshal.
func keyScheduleCodecWrappersIn(parsed parsedSource, sanctioned []string, bodies []string) []string {
	exempt := map[string]bool{}
	for _, one := range declaredIn(parsed) {
		if one.receiver != "" || !strings.HasPrefix(one.name, "Parse") {
			continue
		}
		// the bytes taking half: the name states the body it answers, and it is handed
		// nothing but that body's bytes
		if body := strings.TrimPrefix(one.name, "Parse"); slices.Contains(bodies, body) &&
			slices.Equal(one.params, []string{"[]byte"}) &&
			slices.Equal(one.results, []string{"*" + body, "error"}) {
			exempt[one.name] = true
			continue
		}
		// the tag checked half: handed the whole entry and answering one of the derived
		// body types, with no byte run anywhere in the signature
		if len(one.results) == 2 && one.results[1] == "error" &&
			slices.Equal(one.params, []string{"Extension"}) &&
			strings.HasPrefix(one.results[0], "*") &&
			slices.Contains(bodies, strings.TrimPrefix(one.results[0], "*")) {
			exempt[one.name] = true
		}
	}
	found := []string{}
	for _, declaration := range parsed.file.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if !isFunction || !keyScheduleIsCodecEntryPoint(function.Name.Name) {
			continue
		}
		if slices.Contains(sanctioned, function.Name.Name) {
			continue
		}
		if function.Recv == nil && exempt[function.Name.Name] {
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

// mlsStructuresIn is the class the shape rule below is over: the types of the scanned source
// that are MLS structures, read off the source as the types that DECLARE a sanctioned hook.
//
// This is what convention C1 is actually about. A GroupContext has a wire encoding because it
// goes on the wire, and a KeySchedule does not; the difference is not a name and not a field
// list, it is whether the type implements the codec interfaces mls/syntax declares. Derived
// this way, a structure added later is covered by the commit that gives it MarshalMLS, and a
// type that is not on the wire is left alone -- which is what keeps this from reporting every
// accessor in the package that happens to answer a byte run.
func mlsStructuresIn(files []parsedSource, sanctioned []string) []string {
	structures := []string{}
	for _, parsed := range files {
		for _, one := range declaredIn(parsed) {
			if one.receiver != "" && slices.Contains(sanctioned, one.name) {
				structures = append(structures, strings.TrimPrefix(one.receiver, "*"))
			}
		}
	}
	slices.Sort(structures)
	return slices.Compact(structures)
}

// keyScheduleStructFieldsIn is the field names of every struct type the scanned source
// declares, which is what tells a codec from an accessor below.
func keyScheduleStructFieldsIn(files []parsedSource) map[string][]string {
	fields := map[string][]string{}
	for _, parsed := range files {
		ast.Inspect(parsed.file, func(node ast.Node) bool {
			named, isNamed := node.(*ast.TypeSpec)
			if !isNamed {
				return true
			}
			structure, isStruct := named.Type.(*ast.StructType)
			if !isStruct {
				return true
			}
			for _, field := range fieldsOf(structure.Fields) {
				for _, declared := range field.Names {
					fields[named.Name.Name] = append(fields[named.Name.Name], declared.Name)
				}
			}
			return true
		})
	}
	return fields
}

// keyScheduleIsByteRun answers whether one rendered type is a run of bytes: []byte itself, or
// a type the scanned source declares as one.
func keyScheduleIsByteRun(rendered string, named []string) bool {
	return rendered == "[]byte" || slices.Contains(named, rendered)
}

// keyScheduleSecondCodecsIn is the half of this rule that reads SHAPE rather than spelling:
// every declaration that converts an MLS structure to or from a byte run under a name
// carrying no codec verb at all.
//
// The verb rule next door is a prefix match, so a hand rolled codec written as
// groupContextFromBytes and encodeToWire is invisible to it -- confirmed by adding exactly
// that pair to group_context.go and watching the gate pass. Shape is the half that does not
// depend on what somebody called it.
//
// Two shapes, and each carries the discriminator that keeps it off legitimate code, because a
// signature test alone was measured to report JoinerSecret, WelcomeSecret, GroupContextBytes
// and (*HpkeContext).nonce:
//
//   - an ENCODER answers a byte run, is reached on an MLS structure, and names MORE THAN ONE
//     of that structure's fields. The field count is the discriminator and it is the property
//     itself: what makes a second encoder dangerous is that it lays several fields out in an
//     order, and what an accessor does is hand back one. (*GroupContext).treeHash is the
//     second shape and must not be reported; a method that reads the group id AND the tree
//     hash to build bytes is the first.
//   - a DECODER takes ONE byte run and nothing else, and answers an MLS structure. The arity
//     is the discriminator: a decoder is handed one opaque run and takes it apart, where a
//     constructor is handed the fields already separated. NewGroupContext(groupId, epoch,
//     treeHash) is a constructor by that reading and is not reported.
//
// What this still cannot see is a decoder that takes a byte run AND something else -- a
// provider, a version -- under a name with no verb in it. That shape is left uncovered rather
// than bought with a rule that reports every constructor in the package, and it is written
// here rather than left for the next reader to rediscover.
func keyScheduleSecondCodecsIn(parsed parsedSource, structures []string, byteRuns []string, fields map[string][]string) []string {
	namesAnMlsStructure := func(rendered string) bool {
		return slices.ContainsFunc(structures, func(one string) bool {
			return rendered == one || rendered == "*"+one || rendered == "[]"+one || rendered == "[]*"+one
		})
	}
	found := []string{}
	for _, one := range declaredIn(parsed) {
		answers := []string{}
		for _, result := range one.results {
			if result != "error" {
				answers = append(answers, result)
			}
		}
		if len(answers) != 1 {
			continue
		}
		receiver := strings.TrimPrefix(one.receiver, "*")
		encodes := slices.Contains(structures, receiver) &&
			keyScheduleIsByteRun(answers[0], byteRuns) &&
			keyScheduleFieldsNamedIn(one.body, fields[receiver]) > 1
		decodes := len(one.params) == 1 && keyScheduleIsByteRun(one.params[0], byteRuns) &&
			namesAnMlsStructure(answers[0])
		if !encodes && !decodes {
			continue
		}
		if one.receiver != "" {
			found = append(found, "("+one.receiver+")."+one.name)
			continue
		}
		found = append(found, one.name)
	}
	return found
}

// keyScheduleFieldsNamedIn counts how many DISTINCT fields of a type one body mentions.
func keyScheduleFieldsNamedIn(body *ast.BlockStmt, fields []string) int {
	if body == nil {
		return 0
	}
	named := map[string]bool{}
	ast.Inspect(body, func(node ast.Node) bool {
		if identifier, isIdentifier := node.(*ast.Ident); isIdentifier && slices.Contains(fields, identifier.Name) {
			named[identifier.Name] = true
		}
		return true
	})
	return len(named)
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

type GroupContext struct {
	GroupId  []byte
	Epoch    uint64
	TreeHash []byte
}

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

// the same two shapes again under names carrying no verb at all, which is what the prefix
// match cannot see and the shape rule is for
func groupContextFromBytes(b []byte) (*GroupContext, error) { return nil, nil }

func (self *GroupContext) encodeToWire() []byte {
	out := append([]byte(nil), self.GroupId...)
	return append(out, self.TreeHash...)
}

// a one field accessor on the same structure, which answers a byte run and is not a codec
func (self *GroupContext) treeHash() []byte { return self.TreeHash }

// a constructor: the fields already separated, and a structure out
func NewGroupContext(groupId []byte, epoch uint64, treeHash []byte) *GroupContext {
	return &GroupContext{GroupId: groupId, Epoch: epoch, TreeHash: treeHash}
}

// the second sanctioned exception: an extension body, whose Encode answers the whole
// Extension rather than the body's bytes, paired with the two Parse spellings that read it
// back -- the one handed the body's bytes, and the one handed the whole entry so that it
// has the tag to check. None of these three may be reported.
type LeafKeysExtension struct{}

func (self *LeafKeysExtension) Encode() (Extension, error) { return Extension{}, nil }

func ParseLeafKeysExtension(data []byte) (*LeafKeysExtension, error) { return nil, nil }

func ParseLeafKeysFrom(ext Extension) (*LeafKeysExtension, error) { return nil, nil }

// the near miss the tag checked exemption must not cover: the same shape answering a
// structure that is not an extension body at all, which is a second decoder for a type
// whose codec is syntax.Unmarshal. Reported.
func ParseGroupContextFrom(ext Extension) (*GroupContext, error) { return nil, nil }

// the near miss the exemption must not cover: an Encode that answers the body's bytes
// instead of the Extension, which is the tag choice handed back to the caller and is the
// whole thing the exception is written to prevent. Its Parse is a second codec like any
// other and must be reported.
type GroupPolicyExtension struct{}

func (self *GroupPolicyExtension) Encode() ([]byte, error) { return nil, nil }

func ParseGroupPolicyExtension(data []byte) (*GroupPolicyExtension, error) { return nil, nil }

// and the pair broken on the other side: the Encode is the sanctioned one and the Parse
// takes something besides the body's bytes, so what it decodes is not one extension body
// and the exemption's shape does not describe it. Reported.
type OwnerSuccessorExtension struct{}

func (self *OwnerSuccessorExtension) Encode() (Extension, error) { return Extension{}, nil }

func ParseOwnerSuccessorExtension(data []byte, version uint16) (*OwnerSuccessorExtension, error) {
	return nil, nil
}
`

// What the rule must read out of the control, exactly. Exact rather than a floor in both
// directions: a rule that widened to report the accessor would be switched off, and one that
// narrowed to miss the method wrapper would issue this package the clean bill a working one
// issues.
var keyScheduleCodecControlWrappers = []string{
	"(*GroupContext).Marshal",
	"(*GroupContext).encodeToWire",
	"MarshalExtensions",
	"ParseExtensions",
	"ParseGroupContext",
	"ParseGroupContextFrom",
	"ParseGroupPolicyExtension",
	"ParseOwnerSuccessorExtension",
	"ParsePreSharedKeyId",
	"groupContextFromBytes",
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
//
// TWO rules, unioned, because each sees what the other cannot. The verb rule reads the NAME
// and catches a wrapper over any type at all, including the free vector codecs no structure
// owns. The shape rule reads the SIGNATURE and the BODY and catches a codec written under a
// name that carries no verb -- groupContextFromBytes and encodeToWire were added to
// group_context.go and the verb rule alone passed. Neither is a superset of the other and
// both run over every file.
func TestNoTypeOfThisPackageCarriesAByteLevelCodecOfItsOwn(t *testing.T) {
	sanctioned := syntaxCodecHooks(t)
	codecsIn := func(parsed parsedSource, files []parsedSource) []string {
		found := slices.Concat(
			keyScheduleCodecWrappersIn(parsed, sanctioned, extensionBodyTypesIn(files)),
			keyScheduleSecondCodecsIn(parsed, mlsStructuresIn(files, sanctioned),
				packageByteSliceTypeNamesIn(parsed), keyScheduleStructFieldsIn(files)),
		)
		slices.Sort(found)
		return slices.Compact(found)
	}

	// the control first, on both halves of both rules: every banned shape reported, and
	// neither the hooks, nor the one field accessor, nor the constructor, nor the name with a
	// verb in the middle of it.
	control := mustParseText(t, "the byte level codec control", keyScheduleCodecControl)
	if reported := codecsIn(control, []parsedSource{control}); !slices.Equal(reported, keyScheduleCodecControlWrappers) {
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
	files := []parsedSource{}
	for _, path := range scanned {
		files = append(files, mustParseSource(t, path))
	}
	// the shape rule's class, derived, and checked for having derived something. An empty
	// structure set makes that half of the gate demand nothing, and a gate that demands
	// nothing reports exactly what a complete one reports.
	structures := mlsStructuresIn(files, sanctioned)
	if len(structures) == 0 {
		t.Fatalf("no type of this package declares any of %v, so the shape half of this gate is over an empty class and only the name half is running",
			sanctioned)
	}
	t.Logf("the MLS structures of this package, by the hooks they declare: %v", structures)
	for at, path := range scanned {
		for _, wrapper := range codecsIn(files[at], files) {
			t.Errorf("%s declares %s, and convention C1 says the byte level codec of an MLS structure is syntax.Marshal and syntax.Unmarshal reached through %v: a second encoder agrees with the first until it does not, and no round trip property can see the disagreement",
				path, wrapper, sanctioned)
		}
	}
}
