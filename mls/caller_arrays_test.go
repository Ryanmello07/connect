// THE RETENTION HALF of "a construction and its caller do not share an array", which is the half
// TestEveryConstructionInThisPackageLeavesItsInputAlone cannot see.
//
// That gate reads what a construction ANSWERS: it records the arrays it handed in and reports a
// result cut from one of them. That is the right question for a function whose whole product is its
// answer, and it is blind to a constructor that files a caller's array away inside a value whose
// storage is unexported. (*Group).GroupId is the two line demonstration: the group context held
// cfg.GroupId itself, and GroupId() copies on the way out, so the answer aliased nothing and the
// group and its caller shared an array for the whole life of the group. ANSWERED CLONED AND
// RETAINED SHARED passes that gate exactly as a correct constructor does.
//
// So the property here is the other half, stated over storage rather than over answers:
//
//	no octet a caller can reach through its own arguments is an octet the constructed value can
//	reach, and no octet a group holds is an octet it hands back out.
//
// WHY THE ARRAYS ARE WALKED AND NOT LISTED, WHICH IS THE FIRST HALF OF THIS FILE. The row for group
// creation in crypto_test.go names four arrays -- the group id, the X-Wing public key, the
// signature key and the identity -- and its own comment says "handed a caller's array in four
// places at once". The extension bodies are the FIFTH. Nothing was wrong with the four; the row
// simply never handed a fifth in, so it ran clean over a constructor that copied the Extension
// STRUCTS out of cfg.Extensions and left every ExtensionData pointing at the caller's octets. A
// caller writing into the buffer its policy was encoded out of rewrote what GroupContext()
// answered, GroupPolicy() then refused a group founded under a perfectly good policy, and the key
// schedule went on being derived over the octets as they were -- the group's published context and
// its epoch secrets parted company with nothing in between to point at.
//
// A fifth name would leave the sixth. So the arrays are read off the ARGUMENT TYPES: the walk below
// finds every route from a type to byte storage at any depth, and a row is refused unless it
// supplied an array down every one of them. A field added to GroupConfig tomorrow fails here as
// "carries no storage at", which is this gate declining to pass over it, rather than being covered
// by nobody at all.
//
// AND WHY THE SCOPE IS WALKED TOO, WHICH IS THE SECOND HALF. A gate that derived its class and then
// enumerated the one construction it ran over would be the same defect one level out, so the
// SUBJECTS are derived as well: a construction is in this class when it is handed a caller's bytes
// -- crypto_test.go's own derivation, reused rather than restated -- and answers a type this
// package declares with no exported field at all. That second clause is exactly the blindness this
// file exists for: a value whose every field is unexported is a value the answer side gate can see
// nothing inside, so the two gates' classes are complements rather than neighbours. It is nine
// constructions today; it was one when this file was drafted, and the other eight were already
// correct, which is the point -- they are held now rather than the day one of them stops being.
//
// WHERE THE WALKS STOP, written down rather than left to be rediscovered:
//
//  1. THE ARGUMENT SIDE DOES NOT ENTER AN INTERFACE and the retained side does. An interface
//     parameter hands over an OBJECT and not a buffer -- cfg.Store is a store the group is meant to
//     keep, and a gate that called that shared storage would be reporting the group for doing its
//     job. It is also the line the type walk beside it cannot cross at all, since a static type
//     carries no dynamic value, so entering interfaces on one side only is what keeps the two walks
//     answering the same question. What it costs is a member of the control: a caller's array
//     parked in an `any` field is storage this class does not see, and the day GroupConfig grows
//     one, this paragraph is the reason.
//  2. A STRUCT IS ENTERED THROUGH ITS EXPORTED FIELDS ONLY on the argument and answer sides,
//     because those are what a holder in another package can spell -- type_reach_test.go's first
//     line, for its reason. The RETAINED side enters everything: what a value can reach is not
//     limited to what anybody else can spell, the subjects of this gate are sealed to the last
//     field, and an exported-fields walk over one would reach nothing at all and report the clean
//     run of a gate that had checked something.
//  3. STORAGE IS COMPARED BY OVERLAP AND NOT BY THE POINTER. A constructor that filed away
//     cfg.GroupId[1:] shares every octet but the first with its caller, and two runs starting at
//     different addresses are one piece of storage when their extents meet.
//  4. AN INLINE BYTE ARRAY IS STORAGE ONLY WHERE IT IS ADDRESSABLE, since a [N]byte reached through
//     a copy IS a copy. Every row hands its arguments in through pointers so nothing is silently a
//     copy, and a walk meeting an unaddressable one records it as unfollowed rather than walking
//     past it.
//  5. A RECURSIVE TYPE IS ENTERED ONCE PER BRANCH by both walks, so the type walk declares one
//     level of a self referential field and the value walk follows as many as the value really
//     has. The two therefore agree only over types that are not self referential, which the
//     arguments of these constructions are; a self referential argument type would need this
//     paragraph rewritten rather than the demand quietly dropped.
//  6. THE HAND-OUT HALF IS THE GROUP'S AND NOT THE CLASS'S. "Answers no storage of its own" is a
//     property of the product surface, not of every sealed type: (*KeySchedule).WelcomeSecret is
//     documented next door as answering the schedule's own storage, and holding it to this would be
//     holding it to not doing its job -- zeroizeSecret's exemption, one level out. So the hand-out
//     gate's class is *Group's exported method set, read off the compiled type, and every other
//     sealed type is held by the retention half alone.
package mls

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/token"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// one run of octets, and what it means for two of them to be the same storage
// ---------------------------------------------------------------------------

// byteStorage is one run of octets a walk reached, named twice: how carries the indices a reader
// needs to find it again, and path is the same route with the indices dropped, which is the
// spelling the type walk answers in.
//
// run is the slice itself, kept so the behavioural gate can read and write THROUGH what the walk
// reached rather than reconstructing an address. A walk that found storage it cannot touch has not
// really found it.
type byteStorage struct {
	how  string
	path string
	at   uintptr
	n    int
	run  reflect.Value
}

// overlaps answers whether a write through one run is visible through the other.
//
// Extents rather than the pointer, for the header's line 3: a sub-slice of a caller's array starts
// somewhere else and is the same storage.
func (self byteStorage) overlaps(other byteStorage) bool {
	return self.at < other.at+uintptr(other.n) && other.at < self.at+uintptr(self.n)
}

// octets reads the run out one byte at a time rather than through Bytes(), which refuses a value
// this walk reached through an unexported field -- and those are most of what the retained side
// reaches.
func (self byteStorage) octets() []byte {
	out := make([]byte, self.n)
	for at := range out {
		out[at] = byte(self.run.Index(at).Uint())
	}
	return out
}

// scribble writes a pattern through the run so that every octet of it changes. reflect rather than
// unsafe: every run the argument walk reached came off a value the caller still holds, so the write
// goes through the slice itself.
func (self byteStorage) scribble(mark byte) {
	for at := range self.n {
		self.run.Index(at).SetUint(uint64(mark ^ byte(at)))
	}
}

// how deep a walk goes and how many runs it will record. Both are guards against a cyclic or fanned
// out value rather than rules -- a gate that hung, or that ate the machine, is no gate -- and
// hitting either is recorded as unfollowed rather than passed over in silence.
const (
	byteStorageDepth = 24
	byteStorageMost  = 20000
)

// byteStorageWalk is which of the two questions a walk is asking; see the header's lines 1 and 2.
type byteStorageWalk struct {
	enterUnexported bool
	enterInterfaces bool
}

var (
	// what a caller owns: what it can spell, and no object it handed over
	byteStorageOutside = byteStorageWalk{}
	// what a value hands back: what a holder can spell, including whatever an interface holds
	byteStorageAnswer = byteStorageWalk{enterInterfaces: true}
	// what a value can reach: everything, because its own fields are its own business
	byteStorageInside = byteStorageWalk{enterUnexported: true, enterInterfaces: true}
)

// byteStorageFinder collects the runs one walk reached, and what it could not follow.
//
// unfollowed is not tidiness. A shape this walk cannot enter is storage nobody looked at, and a
// gate that walked past it would report the clean run of a gate that had checked it.
type byteStorageFinder struct {
	how        byteStorageWalk
	found      []byteStorage
	unfollowed []string
	entered    map[[2]uintptr]bool
}

func newByteStorageFinder(how byteStorageWalk) *byteStorageFinder {
	return &byteStorageFinder{how: how, entered: map[[2]uintptr]bool{}}
}

// paths answers the routes this walk found storage through, deduplicated, so a slice of four
// entries reads as one route rather than four.
func (self *byteStorageFinder) paths() []string {
	out := []string{}
	for _, one := range self.found {
		if !slices.Contains(out, one.path) {
			out = append(out, one.path)
		}
	}
	slices.Sort(out)
	return out
}

// contents answers what this walk reached, route by route, as hex, which is what a before and after
// comparison is made over.
func (self *byteStorageFinder) contents() map[string][]string {
	out := map[string][]string{}
	for _, one := range self.found {
		out[one.path] = append(out[one.path], fmt.Sprintf("%x", one.octets()))
	}
	for route := range out {
		slices.Sort(out[route])
	}
	return out
}

// walk reads every run of octets reachable from one value.
//
// The cycle guard is per BRANCH and not per walk: a type reached twice down two different routes is
// two different runs of storage, and a guard held across the whole walk would drop the second --
// which is a class that quietly shrank, and a gate demanding less while reporting what a complete
// one reports.
func (self *byteStorageFinder) walk(value reflect.Value, how string, path string, depth int) {
	if !value.IsValid() {
		return
	}
	if depth > byteStorageDepth {
		self.unfollowed = append(self.unfollowed, how+", which is deeper than this walk goes")
		return
	}
	if len(self.found) > byteStorageMost {
		self.unfollowed = append(self.unfollowed, how+", reached after this walk had recorded all it will")
		return
	}
	switch value.Kind() {
	case reflect.Slice:
		if value.IsNil() {
			return
		}
		// a byte slice under any name: HpkePublicKey and SignaturePrivateKey are the storage
		// they are, which is the reading packageByteSliceTypeNames takes off the source for
		// the gate next door
		if value.Type().Elem().Kind() == reflect.Uint8 {
			if value.Len() != 0 {
				self.found = append(self.found,
					byteStorage{how: how, path: path, at: value.Pointer(), n: value.Len(), run: value})
			}
			return
		}
		if !self.enter(value) {
			return
		}
		defer self.leave(value)
		for at := range value.Len() {
			self.walk(value.Index(at), fmt.Sprintf("%s[%d]", how, at), path+"[]", depth+1)
		}
	case reflect.Array:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			if value.Len() == 0 {
				return
			}
			if !value.CanAddr() {
				self.unfollowed = append(self.unfollowed,
					how+", an inline byte array reached through a copy, whose storage this walk cannot name")
				return
			}
			self.found = append(self.found, byteStorage{how: how, path: path,
				at: value.Addr().Pointer(), n: value.Len(), run: value.Slice(0, value.Len())})
			return
		}
		for at := range value.Len() {
			self.walk(value.Index(at), fmt.Sprintf("%s[%d]", how, at), path+"[]", depth+1)
		}
	case reflect.Pointer:
		if value.IsNil() {
			return
		}
		if !self.enter(value) {
			return
		}
		defer self.leave(value)
		self.walk(value.Elem(), how+"->", path+"->", depth+1)
	case reflect.Interface:
		if value.IsNil() || !self.how.enterInterfaces {
			return
		}
		self.walk(value.Elem(), how+".()", path+".()", depth+1)
	case reflect.Struct:
		for at := range value.NumField() {
			field := value.Type().Field(at)
			if !field.IsExported() && !self.how.enterUnexported {
				continue
			}
			self.walk(value.Field(at), how+"."+field.Name, path+"."+field.Name, depth+1)
		}
	case reflect.Map:
		if value.IsNil() {
			return
		}
		if !self.enter(value) {
			return
		}
		defer self.leave(value)
		for iterator := value.MapRange(); iterator.Next(); {
			self.walk(iterator.Key(), how+"{key}", path+"{key}", depth+1)
			self.walk(iterator.Value(), how+"{}", path+"{}", depth+1)
		}
	case reflect.Chan, reflect.Func, reflect.UnsafePointer:
		// a channel would have to be drained to be read and a func would have to be called,
		// and either is a side effect this gate is not entitled to have on a live value. Both
		// are recorded rather than passed over.
		if value.IsNil() {
			return
		}
		self.unfollowed = append(self.unfollowed,
			fmt.Sprintf("%s, a %s this walk will not follow", how, value.Kind()))
	}
}

// enter and leave are the per branch cycle guard. The key is the pair (type, address), so a struct
// and its first field -- one address, two types -- are not confused for each other.
func (self *byteStorageFinder) enter(value reflect.Value) bool {
	key := [2]uintptr{reflect.ValueOf(value.Type()).Pointer(), value.Pointer()}
	if self.entered[key] {
		return false
	}
	self.entered[key] = true
	return true
}

func (self *byteStorageFinder) leave(value reflect.Value) {
	delete(self.entered, [2]uintptr{reflect.ValueOf(value.Type()).Pointer(), value.Pointer()})
}

// byteStorageFoundIn is the whole of one walk, since every caller wants the runs and the refusals
// together.
func byteStorageFoundIn(value reflect.Value, how string, walk byteStorageWalk) *byteStorageFinder {
	finder := newByteStorageFinder(walk)
	finder.walk(value, how, how, 0)
	return finder
}

// ---------------------------------------------------------------------------
// and the same question asked of a TYPE, which is what makes the arrays derived
// ---------------------------------------------------------------------------

// byteStoragePathsOf answers every route from a type to byte storage.
//
// The value walk finds what a row HAPPENED to hand in; this finds what the type DECLARES, and the
// gate holds the first to cover the second. A field added to an argument type is a route here on
// the day it is declared, so a row that does not fill it fails rather than passing over it.
func byteStoragePathsOf(found reflect.Type, path string) []string {
	into := []string{}
	byteStoragePathsThrough(found, path, &into, map[reflect.Type]bool{}, 0)
	slices.Sort(into)
	return slices.Compact(into)
}

func byteStoragePathsThrough(found reflect.Type, path string, into *[]string,
	entered map[reflect.Type]bool, depth int) {
	if found == nil || depth > byteStorageDepth || entered[found] {
		return
	}
	// per branch, exactly as the value walk's guard is and for its reason: a self referential
	// type is stopped and a type reached twice down two routes is two routes
	entered[found] = true
	defer delete(entered, found)
	switch found.Kind() {
	case reflect.Slice, reflect.Array:
		if found.Elem().Kind() == reflect.Uint8 {
			*into = append(*into, path)
			return
		}
		byteStoragePathsThrough(found.Elem(), path+"[]", into, entered, depth+1)
	case reflect.Pointer:
		byteStoragePathsThrough(found.Elem(), path+"->", into, entered, depth+1)
	case reflect.Struct:
		for at := range found.NumField() {
			field := found.Field(at)
			if !field.IsExported() {
				continue
			}
			byteStoragePathsThrough(field.Type, path+"."+field.Name, into, entered, depth+1)
		}
	case reflect.Map:
		byteStoragePathsThrough(found.Key(), path+"{key}", into, entered, depth+1)
		byteStoragePathsThrough(found.Elem(), path+"{}", into, entered, depth+1)
	}
}

// ---------------------------------------------------------------------------
// the controls for the walks: one member per arm, so an arm that stopped working fails here
// ---------------------------------------------------------------------------

// callerArrayControl carries one member per constructor either walk claims to enter, and one per
// line this file's header says it draws.
//
// A control rather than a second opinion about the real types: a walk that entered nothing reports
// a clean run over every retention there is, and the only way to tell that apart from a value that
// shares nothing is to run it over one known to hold storage down every route.
type callerArrayControl struct {
	Direct    []byte
	Named     SignaturePublicKey
	Fixed     [4]byte
	Pointed   *[]byte
	Nested    callerArrayControlInner
	NestedPtr *callerArrayControlInner
	Entries   []callerArrayControlInner
	Fixture   [1]callerArrayControlInner
	Keyed     map[string][]byte
	KeyedBy   map[*callerArrayControlInner]bool
	Held      any
	hidden    []byte
}

// the deeper member. A body two structures down rather than one is what the extension bodies are --
// cfg.Extensions[].ExtensionData is reached through a slice AND a struct -- so a walk that stopped
// at the first hop would find the group id and miss the thing this file was written for.
type callerArrayControlInner struct {
	Deeper  []byte
	Deepest *callerArrayControlInner
}

func newCallerArrayControl() *callerArrayControl {
	pointed := []byte("through a pointer to a slice")
	inner := func(mark byte) callerArrayControlInner {
		return callerArrayControlInner{Deeper: bytes.Repeat([]byte{mark}, 8)}
	}
	keyed := inner(0x0a)
	return &callerArrayControl{
		Direct:    []byte("direct"),
		Named:     SignaturePublicKey("a byte slice under another name"),
		Fixed:     [4]byte{1, 2, 3, 4},
		Pointed:   &pointed,
		Nested:    inner(0x0c),
		NestedPtr: &callerArrayControlInner{Deeper: []byte("a body two structures down")},
		Entries:   []callerArrayControlInner{inner(0x01)},
		Fixture:   [1]callerArrayControlInner{inner(0x02)},
		Keyed:     map[string][]byte{"it": []byte("a map value")},
		KeyedBy:   map[*callerArrayControlInner]bool{&keyed: true},
		Held:      []byte("inside an interface"),
		hidden:    []byte("behind an unexported field"),
	}
}

// What the TYPE walk must answer over the control: every route but the interface, which no static
// type carries a value in, and every route but the unexported field, which no holder outside the
// declaring package can spell.
var callerArrayControlPaths = []string{
	"it->.Direct",
	"it->.Entries[].Deeper",
	"it->.Fixed",
	"it->.Fixture[].Deeper",
	"it->.Keyed{}",
	"it->.KeyedBy{key}->.Deeper",
	"it->.Named",
	"it->.Nested.Deeper",
	"it->.NestedPtr->.Deeper",
	"it->.Pointed->",
}

// and what the three VALUE walks must answer. They differ from the type walk, and from each other,
// by exactly one member apiece: the interface the argument side does not enter, and the unexported
// field only the retained side can spell. Held exactly rather than as floors in both directions --
// a route missing is an arm that stopped working, and a route extra is a line this file says it
// draws and does not.
var (
	callerArrayControlOutside = callerArrayControlPaths
	callerArrayControlAnswer  = append([]string{"it->.Held.()"}, callerArrayControlPaths...)
	callerArrayControlInside  = append([]string{"it->.Held.()", "it->.hidden"}, callerArrayControlPaths...)
)

// TestTheByteStorageWalksAgreeOverEveryConstructor is the control both walks are read through.
func TestTheByteStorageWalksAgreeOverEveryConstructor(t *testing.T) {
	control := newCallerArrayControl()
	if declared := byteStoragePathsOf(reflect.TypeOf(control), "it"); !slices.Equal(declared,
		sortedStorageRoutes(callerArrayControlPaths)) {
		t.Errorf("the type walk declares storage at %v, want %v",
			declared, sortedStorageRoutes(callerArrayControlPaths))
	}
	for _, arm := range []struct {
		name string
		walk byteStorageWalk
		want []string
	}{
		{name: "the argument side", walk: byteStorageOutside, want: callerArrayControlOutside},
		{name: "the answer side", walk: byteStorageAnswer, want: callerArrayControlAnswer},
		{name: "the retained side", walk: byteStorageInside, want: callerArrayControlInside},
	} {
		finder := byteStorageFoundIn(reflect.ValueOf(control), "it", arm.walk)
		if len(finder.unfollowed) != 0 {
			t.Errorf("%s could not follow %v out of its own control, so it would walk past the same shape in a real value",
				arm.name, finder.unfollowed)
		}
		if got := finder.paths(); !slices.Equal(got, sortedStorageRoutes(arm.want)) {
			t.Errorf("%s reached storage through %v, want %v",
				arm.name, got, sortedStorageRoutes(arm.want))
		}
	}
	// and the runs are readable and writable through what the walk kept, since the behavioural
	// half of this file spends both
	finder := byteStorageFoundIn(reflect.ValueOf(control), "it", byteStorageOutside)
	for _, one := range finder.found {
		if !bytes.Equal(one.octets(), one.run.Slice(0, one.n).Bytes()) {
			t.Errorf("the walk reads %s back as something other than what it holds", one.how)
		}
	}
	control.Direct = bytes.Repeat([]byte{0x11}, 6)
	before := bytes.Clone(control.Direct)
	byteStorage{n: len(control.Direct), run: reflect.ValueOf(control.Direct)}.scribble(0x5a)
	if bytes.Equal(before, control.Direct) {
		t.Error("a scribble through what the walk kept changed nothing, so the behavioural half writes nowhere")
	}
}

// TestTheByteStorageValueWalkStopsOnACycle is the per branch guard, run rather than argued: a value
// that points at itself terminates and is recorded once.
func TestTheByteStorageValueWalkStopsOnACycle(t *testing.T) {
	loop := &callerArrayControlInner{Deeper: []byte("round and round")}
	loop.Deepest = loop
	finder := byteStorageFoundIn(reflect.ValueOf(loop), "loop", byteStorageInside)
	if got := finder.paths(); !slices.Equal(got, []string{"loop->.Deeper"}) {
		t.Errorf("the value walk read %v out of a value that points at itself, want the one run it holds", got)
	}
	if len(finder.unfollowed) != 0 {
		t.Errorf("the value walk reported %v over a cycle, which the branch guard is supposed to close quietly",
			finder.unfollowed)
	}
}

// TestTheStorageOverlapRuleReadsExtentsAndNotPointers is the header's line 3.
func TestTheStorageOverlapRuleReadsExtentsAndNotPointers(t *testing.T) {
	whole := byteStorage{at: 0x1000, n: 16}
	for _, arm := range []struct {
		name    string
		other   byteStorage
		overlap bool
	}{
		{name: "the same run", other: byteStorage{at: 0x1000, n: 16}, overlap: true},
		{name: "a run one octet in", other: byteStorage{at: 0x1001, n: 15}, overlap: true},
		{name: "the last octet alone", other: byteStorage{at: 0x100f, n: 1}, overlap: true},
		{name: "a run ending where this starts", other: byteStorage{at: 0x0ff0, n: 16}, overlap: false},
		{name: "a run starting where this ends", other: byteStorage{at: 0x1010, n: 16}, overlap: false},
	} {
		if whole.overlaps(arm.other) != arm.overlap || arm.other.overlaps(whole) != arm.overlap {
			t.Errorf("%s reads as overlap %v, want %v", arm.name, !arm.overlap, arm.overlap)
		}
	}
}

func sortedStorageRoutes(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}

// ---------------------------------------------------------------------------
// the scope, read off the source: the types the answer side gate cannot see into
// ---------------------------------------------------------------------------

// packageSealedTypeNamesIn answers the exported struct types one file declares whose every field is
// unexported.
//
// A field counts under the name it is SPELLED by, which for an embedded field is the last identifier
// of its type: a struct embedding an exported type has an exported field, however it was written,
// and a walk over what a holder can spell would enter it.
func packageSealedTypeNamesIn(parsed parsedSource) []string {
	names := []string{}
	for _, declaration := range parsed.file.Decls {
		general, isGeneral := declaration.(*ast.GenDecl)
		if !isGeneral || general.Tok != token.TYPE {
			continue
		}
		for _, spec := range general.Specs {
			typeSpec, isType := spec.(*ast.TypeSpec)
			if !isType || !typeSpec.Name.IsExported() || typeSpec.Assign.IsValid() {
				continue
			}
			structType, isStruct := typeSpec.Type.(*ast.StructType)
			if !isStruct || structType.Fields == nil {
				continue
			}
			fields, exported := 0, 0
			for _, field := range structType.Fields.List {
				spelled := []string{}
				for _, name := range field.Names {
					spelled = append(spelled, name.Name)
				}
				if len(spelled) == 0 {
					spelled = append(spelled, embeddedFieldName(parsed.render(field.Type)))
				}
				for _, name := range spelled {
					fields++
					if ast.IsExported(name) {
						exported++
					}
				}
			}
			if fields != 0 && exported == 0 {
				names = append(names, typeSpec.Name.Name)
			}
		}
	}
	return names
}

// embeddedFieldName is the name an embedded field is spelled by: the last identifier of its type,
// with the pointer and the package qualifier stripped.
func embeddedFieldName(rendered string) string {
	rendered = strings.TrimPrefix(rendered, "*")
	if at := strings.LastIndex(rendered, "."); at >= 0 {
		rendered = rendered[at+1:]
	}
	return rendered
}

// packageSealedTypeNames is the same over the whole package's non test source.
//
// Absence is fatal rather than clean, for the reason every derivation in this package is: a scan
// that stopped matching leaves the gate reading it with an empty class, and an empty class reports
// exactly what a complete one reports.
func packageSealedTypeNames(t *testing.T) []string {
	t.Helper()
	names := []string{}
	for _, path := range packageSourcePaths(t) {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		names = append(names, packageSealedTypeNamesIn(mustParseSource(t, path))...)
	}
	if len(names) == 0 {
		t.Fatal("this package declares no sealed type, so the class below has no subjects")
	}
	slices.Sort(names)
	return names
}

// packageLevelFunctionResults answers, per package level function, the identifiers its result list
// names. A construction ANSWERS a type when that type's name is among them, at any depth of pointer,
// slice or tuple, which is the reading a holder takes: a *KeySchedule and a []*KeySchedule are both
// a key schedule in somebody's hands.
func packageLevelFunctionResults(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, path := range packageSourcePaths(t) {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		parsed := mustParseSource(t, path)
		for _, declaration := range parsed.file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Recv != nil || function.Type.Results == nil {
				continue
			}
			named := []string{}
			for _, field := range function.Type.Results.List {
				ast.Inspect(field.Type, func(node ast.Node) bool {
					if identifier, isIdentifier := node.(*ast.Ident); isIdentifier {
						named = append(named, identifier.Name)
					}
					return true
				})
			}
			out[function.Name.Name] = named
		}
	}
	if len(out) == 0 {
		t.Fatal("this package declares no package level function answering anything, so the class below has no subjects")
	}
	return out
}

// packageLevelFunctionArity answers how many arguments a construction takes, so a row that stopped
// passing one is a row that fails rather than one that quietly hands in less than it used to.
func packageLevelFunctionArity(t *testing.T, name string) int {
	t.Helper()
	for _, function := range packageLevelFunctions(t).functions {
		if function.name == name {
			return len(function.parameters)
		}
	}
	t.Fatalf("this package declares no package level function %s", name)
	return 0
}

// packageConstructionsOfSealedStorage is the class this gate runs over: handed a caller's bytes,
// and answering a value nothing outside can see inside.
//
// Both halves are read off the source. The first is crypto_test.go's own derivation, reused rather
// than restated, and its exemption table is honoured here too -- newKeyScheduleFromParts is excused
// there with "retaining it is the function", which is a RETENTION exemption and belongs to this
// gate more squarely than to that one.
func packageConstructionsOfSealedStorage(t *testing.T) []string {
	t.Helper()
	sealed := packageSealedTypeNames(t)
	results := packageLevelFunctionResults(t)
	names := []string{}
	for _, name := range packageLevelFunctionsTakingCallerBytes(t) {
		if _, isExcused := packageConstructionsOverBorrowedBytes[name]; isExcused {
			continue
		}
		for _, answered := range results[name] {
			if slices.Contains(sealed, answered) {
				names = append(names, name)
				break
			}
		}
	}
	if len(names) == 0 {
		t.Fatal("no construction of this package is handed bytes and answers sealed storage, so this gate demands nothing")
	}
	slices.Sort(names)
	return names
}

// TestTheSealedTypeScanReadsWhatAHolderCannotSeeInto is the control for the scope derivation.
//
// One declaration per arm, so a scan that started reading an exported field as unexported, or that
// stopped entering embedded fields, fails here rather than widening the class in silence. A class
// that GREW is as bad as one that shrank: every extra member is a construction with no row, and the
// repair somebody reaches for is deleting the demand.
func TestTheSealedTypeScanReadsWhatAHolderCannotSeeInto(t *testing.T) {
	found := packageSealedTypeNamesIn(mustParseText(t, "the sealed type control", sealedTypeControl))
	slices.Sort(found)
	if want := []string{"Sealed", "SealedByEmbedding"}; !slices.Equal(found, want) {
		t.Errorf("the sealed type scan read %v out of the control, want %v", found, want)
	}
	// and the real package's own sealed types are read the same way, with the one this file was
	// written about named rather than assumed
	if named := packageSealedTypeNames(t); !slices.Contains(named, "Group") {
		t.Errorf("the sealed type scan read %v out of this package, which declares Group with no exported field", named)
	}
}

// Six type declarations, two of which are sealed and four of which are not. Every arm of the scan
// runs on this, so one that started matching an empty struct, an alias, a non struct or a type
// whose only field is embedded and exported fails here.
const sealedTypeControl = `package control

// sealed: every field unexported
type Sealed struct {
	held  []byte
	count int
}

// sealed as well, and the reason the scan reads an embedded field by its spelled name: this one is
// embedded and unexported
type SealedByEmbedding struct {
	sealedInner
}

// not sealed: one exported field is one a holder can spell
type NotSealed struct {
	Held []byte
	held []byte
}

// not sealed: an embedded EXPORTED type is an exported field however it is written
type NotSealedByEmbedding struct {
	Sealed
	held []byte
}

// not sealed: there is nothing in it to be sealed
type NotSealedBecauseEmpty struct{}

// not a struct, so not in the class at all
type NotAStruct []byte

// an alias rather than a declaration, which names no new type to be sealed
type NotADeclaration = Sealed

// unexported, so outside the surface this gate is about
type sealedInner struct {
	held []byte
}
`

// ---------------------------------------------------------------------------
// the retention half, over every construction of that class
// ---------------------------------------------------------------------------

// callerArrayRow is one construction, with the arguments it is handed and the value it made.
//
// arguments are POINTERS to the caller's own variables, in the order the signature takes them, for
// the header's line 4 and so the arity read off the source can be compared against them. made is
// the sealed value; the gate walks the two and demands they share nothing.
type callerArrayRow struct {
	name  string
	build func(t *testing.T) (arguments []any, made any)
}

// callerArrayRows is every construction this gate runs, and it is held equal to the class derived
// from the source at the bottom of the gate.
func callerArrayRows() []callerArrayRow {
	return []callerArrayRow{
		{name: "NewGroup", build: func(t *testing.T) ([]any, any) {
			cfg, signer, cred := callerOwnedGroupArguments(t)
			group, err := NewGroup(cfg, signer, cred)
			if err != nil {
				t.Fatalf("found the group this row follows: %v", err)
			}
			t.Cleanup(func() { group.Close() })
			return []any{cfg, &signer, &cred}, group
		}},
		{name: "NewKeySchedule", build: func(t *testing.T) ([]any, any) {
			crypto, context, secrets := callerOwnedScheduleArguments(t)
			schedule, err := NewKeySchedule(crypto, secrets["init"], secrets["commit"],
				secrets["psk"], context)
			if err != nil {
				t.Fatalf("NewKeySchedule: %v", err)
			}
			return []any{&crypto, secretPointer(secrets, "init"), secretPointer(secrets, "commit"),
				secretPointer(secrets, "psk"), context}, schedule
		}},
		{name: "NewKeyScheduleFromJoiner", build: func(t *testing.T) ([]any, any) {
			crypto, context, secrets := callerOwnedScheduleArguments(t)
			schedule, err := NewKeyScheduleFromJoiner(crypto, secrets["joiner"], secrets["psk"], context)
			if err != nil {
				t.Fatalf("NewKeyScheduleFromJoiner: %v", err)
			}
			return []any{&crypto, secretPointer(secrets, "joiner"), secretPointer(secrets, "psk"),
				context}, schedule
		}},
		{name: "NewKeyScheduleFromEpochSecret", build: func(t *testing.T) ([]any, any) {
			crypto, context, secrets := callerOwnedScheduleArguments(t)
			schedule, err := NewKeyScheduleFromEpochSecret(crypto, secrets["epoch"], context)
			if err != nil {
				t.Fatalf("NewKeyScheduleFromEpochSecret: %v", err)
			}
			return []any{&crypto, secretPointer(secrets, "epoch"), context}, schedule
		}},
		{name: "NewSecretTree", build: func(t *testing.T) ([]any, any) {
			crypto, _, secrets := callerOwnedScheduleArguments(t)
			leafCount := LeafCount(8)
			tree, err := NewSecretTree(crypto, leafCount, secrets["encryption"])
			if err != nil {
				t.Fatalf("NewSecretTree: %v", err)
			}
			return []any{&crypto, &leafCount, secretPointer(secrets, "encryption")}, tree
		}},
		{name: "hpkeKeySchedule", build: func(t *testing.T) ([]any, any) {
			params := mustSuiteParams(t)
			shared := bytes.Repeat([]byte{0x31}, params.Nsecret)
			info := []byte("the info this row's context is bound to")
			context, err := hpkeKeySchedule(params, shared, info)
			if err != nil {
				t.Fatalf("hpkeKeySchedule: %v", err)
			}
			return []any{params, &shared, &info}, context
		}},
		{name: "HpkeSetupBaseS", build: func(t *testing.T) ([]any, any) {
			params := mustSuiteParams(t)
			_, pub := mustHpkeKeyPair(t, params)
			info := []byte("the info this row's context is bound to")
			random := constantReader{value: 0x77}
			_, context, err := HpkeSetupBaseS(random, params, pub, info)
			if err != nil {
				t.Fatalf("HpkeSetupBaseS: %v", err)
			}
			return []any{&random, params, &pub, &info}, context
		}},
		{name: "HpkeSetupBaseR", build: func(t *testing.T) ([]any, any) {
			params := mustSuiteParams(t)
			priv, pub := mustHpkeKeyPair(t, params)
			info := []byte("the info this row's context is bound to")
			kemOutput, _, err := HpkeSetupBaseS(constantReader{value: 0x77}, params, pub, info)
			if err != nil {
				t.Fatalf("seal the message this row opens: %v", err)
			}
			context, err := HpkeSetupBaseR(params, priv, kemOutput, info)
			if err != nil {
				t.Fatalf("HpkeSetupBaseR: %v", err)
			}
			return []any{params, &priv, &kemOutput, &info}, context
		}},
		{name: "UnmarshalRatchetTree", build: func(t *testing.T) ([]any, any) {
			encoded := callerOwnedEncodedTree(t)
			tree, err := UnmarshalRatchetTree(encoded)
			if err != nil {
				t.Fatalf("UnmarshalRatchetTree: %v", err)
			}
			return []any{&encoded}, tree
		}},
	}
}

// TestNoConstructionOfSealedStorageRetainsItsCallersArrays is the retention half, over every member
// of the derived class.
//
// Three demands per row, and the first two are what keep the third from passing vacuously: the
// arguments must cover the arity the source declares, and they must carry an array down every route
// the argument TYPES declare storage at. Only then is "these two share no octet" a statement about
// the construction rather than about what this row happened to hand it.
func TestNoConstructionOfSealedStorageRetainsItsCallersArrays(t *testing.T) {
	covered := []string{}
	for _, row := range callerArrayRows() {
		covered = append(covered, row.name)
		arguments, made := row.build(t)
		if want := packageLevelFunctionArity(t, row.name); len(arguments) != want {
			t.Errorf("%s: this row hands in %d arguments and the source declares %d, so it covers a signature that has moved on",
				row.name, len(arguments), want)
		}
		owned := newByteStorageFinder(byteStorageOutside)
		declared := []string{}
		for at, argument := range arguments {
			how := fmt.Sprintf("%s argument %d", row.name, at)
			owned.walk(reflect.ValueOf(argument), how, how, 0)
			declared = append(declared, byteStoragePathsOf(reflect.TypeOf(argument), how)...)
		}
		slices.Sort(declared)
		declared = slices.Compact(declared)
		if len(declared) == 0 {
			t.Errorf("%s: no argument type of this row declares byte storage, so this row demands nothing", row.name)
		}
		if len(owned.unfollowed) != 0 {
			t.Errorf("%s: the walk over its arguments could not follow %v", row.name, owned.unfollowed)
		}
		supplied := owned.paths()
		for _, route := range declared {
			if !slices.Contains(supplied, route) {
				t.Errorf("%s: the arguments this row hands in carry no storage at %s, which the argument types declare; a construction retaining an array there would pass over unread",
					row.name, route)
			}
		}
		for _, route := range supplied {
			if !slices.Contains(declared, route) {
				t.Errorf("%s: this row hands in storage at %s, which the argument types do not declare; the type walk and the value walk have stopped agreeing",
					row.name, route)
			}
		}
		held := byteStorageFoundIn(reflect.ValueOf(made), row.name+" made", byteStorageInside)
		if len(held.unfollowed) != 0 {
			t.Errorf("%s: the walk over what it made could not follow %v, so it would walk past a retention behind the same shape",
				row.name, held.unfollowed)
		}
		if len(held.found) == 0 {
			t.Errorf("%s: what it made reaches no storage at all, so this row compared nothing", row.name)
		}
		for _, mine := range owned.found {
			for _, theirs := range held.found {
				if mine.overlaps(theirs) {
					t.Errorf("%s retains %s, which is the caller's own %s: a write through one is a write through the other",
						row.name, theirs.how, mine.how)
				}
			}
		}
	}
	// and the rows are the class read off the source rather than the constructions somebody
	// thought of
	declared := packageConstructionsOfSealedStorage(t)
	slices.Sort(covered)
	if !slices.Equal(covered, declared) {
		t.Errorf("this gate runs over %v, and the package's constructions of sealed storage over caller bytes are %v",
			covered, declared)
	}
}

// ---------------------------------------------------------------------------
// the arguments the rows hand in
// ---------------------------------------------------------------------------

// callerOwnedGroupArguments builds the three arguments NewGroup takes, filled so that every route
// the argument TYPES declare storage down carries a distinct run of octets.
//
// Distinct rather than convenient: the gate compares extents, so two arguments cut from one buffer
// would make a finding about the wrong one.
func callerOwnedGroupArguments(t *testing.T) (*GroupConfig, SignaturePrivateKey, Credential) {
	t.Helper()
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	identity := []byte("the founder whose arrays this gate follows")
	policy := &GroupPolicyExtension{Roles: []RoleEntry{{MemberId: identity, Role: RoleOwner}}}
	if err := policy.Canonicalize(); err != nil {
		t.Fatalf("canonicalize the policy this group is founded under: %v", err)
	}
	policyExt, err := policy.Encode()
	if err != nil {
		t.Fatalf("encode the policy this group is founded under: %v", err)
	}
	cfg := &GroupConfig{
		Suite:      CipherSuiteX25519ChaCha20Sha256Ed25519,
		GroupId:    []byte("the group id this gate follows"),
		Extensions: []Extension{policyExt},
		Crypto:     crypto,
		Store:      newTestStore(),
		LeafKeys: LeafKeysExtension{
			AlgId:          AlgIdXwing,
			DeviceXwingPub: bytes.Repeat([]byte{0x62}, XwingPublicKeyLen),
		},
	}
	return cfg, SignaturePrivateKey(bytes.Repeat([]byte{0x54}, 32)),
		Credential{CredentialType: CredentialTypeBasic, Identity: bytes.Clone(identity)}
}

// callerOwnedScheduleArguments builds the provider, the group context and the six secrets the key
// schedule and secret tree rows draw from, every one of them a distinct run at KDF.Nh so no finding
// can be about the wrong array.
func callerOwnedScheduleArguments(t *testing.T) (CryptoProvider, *GroupContext, map[string][]byte) {
	t.Helper()
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	context := &GroupContext{
		Version:                 ProtocolVersionMls10,
		CipherSuite:             crypto.Suite(),
		GroupId:                 []byte("the group id these schedules are bound to"),
		Epoch:                   3,
		TreeHash:                bytes.Repeat([]byte{0x11}, crypto.HashSize()),
		ConfirmedTranscriptHash: bytes.Repeat([]byte{0x12}, crypto.HashSize()),
		Extensions: []Extension{{ExtensionType: ExtensionTypeUrmessageGroupPolicy,
			ExtensionData: []byte("the extension body these schedules are bound to")}},
	}
	secrets := map[string][]byte{}
	for at, name := range []string{"init", "commit", "psk", "joiner", "epoch", "encryption"} {
		secrets[name] = bytes.Repeat([]byte{byte(0x71 + at)}, crypto.HashSize())
	}
	return crypto, context, secrets
}

// secretPointer hands a row's secret in as a pointer to the map's own storage, so the walk reaches
// the very slice the construction was given rather than a copy of its header.
func secretPointer(secrets map[string][]byte, name string) *[]byte {
	held := secrets[name]
	return &held
}

func mustSuiteParams(t *testing.T) *SuiteParams {
	t.Helper()
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("look up the suite these rows are built over: %v", err)
	}
	return params
}

func mustHpkeKeyPair(t *testing.T, params *SuiteParams) (HpkePrivateKey, HpkePublicKey) {
	t.Helper()
	priv, pub, err := HpkeDeriveKeyPair(params, bytes.Repeat([]byte{0x32}, params.Nsk))
	if err != nil {
		t.Fatalf("derive the key pair these rows are built over: %v", err)
	}
	return priv, pub
}

// callerOwnedEncodedTree is a real one leaf tree encoded, since UnmarshalRatchetTree refuses a tree
// that holds nothing and a row that fed it one would be reporting a refusal rather than a decode.
func callerOwnedEncodedTree(t *testing.T) []byte {
	t.Helper()
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	_, encPub, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
	if err != nil {
		t.Fatalf("the encryption key of the leaf this row's tree carries: %v", err)
	}
	signer, _, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("the signature key of the leaf this row's tree carries: %v", err)
	}
	keys := LeafKeysExtension{AlgId: AlgIdXwing,
		DeviceXwingPub: bytes.Repeat([]byte{0x63}, XwingPublicKeyLen)}
	keysExt, err := keys.Encode()
	if err != nil {
		t.Fatalf("the leaf keys of the leaf this row's tree carries: %v", err)
	}
	leaf, err := NewLeafNode(crypto, signer,
		Credential{CredentialType: CredentialTypeBasic, Identity: []byte("the leaf in this row's tree")},
		encPub, v1Capabilities(), []Extension{keysExt})
	if err != nil {
		t.Fatalf("the leaf this row's tree carries: %v", err)
	}
	tree := NewRatchetTree()
	if _, err := tree.AddLeaf(leaf); err != nil {
		t.Fatalf("add the leaf this row's tree carries: %v", err)
	}
	encoded, err := marshalRatchetTree(tree)
	if err != nil {
		t.Fatalf("encode this row's tree: %v", err)
	}
	return encoded
}

// ---------------------------------------------------------------------------
// the hand-out half, over what a group ANSWERS -- see the header's line 6 for its scope
// ---------------------------------------------------------------------------

// groupAnswerRow is one exported method of *Group, called for what it answers.
//
// A row supplies the arguments a method needs and NOTHING else -- no refusal is turned into a
// t.Fatal, because both gates below call a row twice and the second call is made over a group whose
// caller has just scribbled on its own arrays. A method that starts refusing there is a finding and
// not a reason to stop reading.
type groupAnswerRow struct {
	name string
	call func(group *Group) []any
}

func groupAnswerRows() []groupAnswerRow {
	return []groupAnswerRow{
		{name: "GroupId", call: func(group *Group) []any {
			answer := group.GroupId()
			return []any{&answer}
		}},
		{name: "Epoch", call: func(group *Group) []any {
			answer := group.Epoch()
			return []any{&answer}
		}},
		{name: "OwnLeafIndex", call: func(group *Group) []any {
			answer := group.OwnLeafIndex()
			return []any{&answer}
		}},
		{name: "OwnLeafNodeCopy", call: func(group *Group) []any {
			answer := group.OwnLeafNodeCopy()
			return []any{&answer}
		}},
		{name: "Members", call: func(group *Group) []any {
			answer := group.Members()
			return []any{&answer}
		}},
		{name: "MemberAt", call: func(group *Group) []any {
			answer, found := group.MemberAt(group.OwnLeafIndex())
			return []any{&answer, &found}
		}},
		{name: "EpochAuthenticator", call: func(group *Group) []any {
			answer := group.EpochAuthenticator()
			return []any{&answer}
		}},
		{name: "Export", call: func(group *Group) []any {
			answer, err := group.Export("the exporter label this gate reads",
				[]byte("the exporter context this gate reads"), 32)
			return []any{&answer, &err}
		}},
		// both names of the closed enum, since the two arms read two different secrets and a row
		// reading one of them would pass over the other
		{name: "EpochSecret", call: func(group *Group) []any {
			senderData, senderErr := group.EpochSecret(EpochSecretSenderData)
			encryption, encryptionErr := group.EpochSecret(EpochSecretEncryption)
			return []any{&senderData, &senderErr, &encryption, &encryptionErr}
		}},
		{name: "RatchetTree", call: func(group *Group) []any {
			answer, err := group.RatchetTree()
			return []any{&answer, &err}
		}},
		{name: "GroupContext", call: func(group *Group) []any {
			answer, err := group.GroupContext()
			return []any{&answer, &err}
		}},
		{name: "GroupPolicy", call: func(group *Group) []any {
			answer, err := group.GroupPolicy()
			return []any{&answer, &err}
		}},
		// the ender gets a row like every other method, and every row gets a group of its own, so
		// there is no member of the class this gate skipped for being inconvenient
		{name: "Close", call: func(group *Group) []any {
			answer := group.Close()
			return []any{&answer}
		}},
	}
}

// answerStorageOf walks what one row answered.
func answerStorageOf(row groupAnswerRow, group *Group) *byteStorageFinder {
	finder := newByteStorageFinder(byteStorageAnswer)
	for at, answer := range row.call(group) {
		how := fmt.Sprintf("%s() result %d", row.name, at)
		finder.walk(reflect.ValueOf(answer), how, how, 0)
	}
	return finder
}

// TestNoAnswerOfAGroupSharesStorageWithIt is the hand-out half, and Members() is what it was written
// for: IdentityPub was cloned and SignatureKey, two fields of one struct three lines apart, was a
// window onto the LIVE ratchet tree. A caller writing through that window edits the tree this
// epoch's tree hash was taken over, and nothing else in this package reports it, because the tree
// goes on being self consistent with the octets it now holds.
//
// A row is refused as vacuous when its method's RESULT TYPES declare byte storage and the call
// produced none, so a method whose answer stopped carrying anything cannot read as compliant. That
// demand is derived from the signature rather than from a list of which methods answer bytes.
func TestNoAnswerOfAGroupSharesStorageWithIt(t *testing.T) {
	for _, row := range groupAnswerRows() {
		group := mustFoundedGroup(t)
		held := byteStorageFoundIn(reflect.ValueOf(group), "group", byteStorageInside)
		if len(held.unfollowed) != 0 {
			t.Errorf("%s: the walk over the group could not follow %v", row.name, held.unfollowed)
		}
		if len(held.found) == 0 {
			t.Fatalf("%s: the group reached no storage at all, so this row compared nothing", row.name)
		}
		answered := answerStorageOf(row, group)
		if len(answered.unfollowed) != 0 {
			t.Errorf("%s: the walk over its answer could not follow %v", row.name, answered.unfollowed)
		}
		if len(answered.found) == 0 && groupAnswerDeclaresStorage(t, row.name) {
			t.Errorf("%s answers types that declare byte storage and this call produced none, so this row observed nothing",
				row.name)
		}
		for _, given := range answered.found {
			for _, theirs := range held.found {
				if given.overlaps(theirs) {
					t.Errorf("%s hands out %s, which is the group's own %s: a caller writing through what it was handed writes into the group",
						row.name, given.how, theirs.how)
				}
			}
		}
	}
	// and the rows are *Group's method set rather than the methods somebody thought of
	covered := []string{}
	for _, row := range groupAnswerRows() {
		covered = append(covered, row.name)
	}
	declared := []string{}
	groupType := reflect.TypeOf((*Group)(nil))
	for at := range groupType.NumMethod() {
		declared = append(declared, groupType.Method(at).Name)
	}
	slices.Sort(declared)
	slices.Sort(covered)
	if len(declared) == 0 {
		t.Fatal("*Group exports no method, so this gate demands nothing")
	}
	if !slices.Equal(covered, declared) {
		t.Errorf("this gate calls %v, and *Group exports %v", covered, declared)
	}
}

// TestAGroupGoesOnPublishingWhatItWasFoundedOn is the same property read through what a group SAYS
// rather than through what it holds, and it is here because it is the failure a person meets.
//
// Every octet the caller owns is overwritten after the group is founded, and then the group is
// asked again. A group that copied what it was handed answers exactly what it answered before; the
// group this file was written against answered a context whose policy body was the scribble, and
// GroupPolicy() refused it with "varint prefix 0b11 is reserved" -- over a group founded under a
// policy that was perfectly good, with its epoch secrets still derived over the octets as they
// were.
//
// The class of things asked is the SAME rows the hand-out gate uses, so there is one list of what a
// group publishes rather than two that can drift apart.
func TestAGroupGoesOnPublishingWhatItWasFoundedOn(t *testing.T) {
	for _, row := range groupAnswerRows() {
		cfg, signer, cred := callerOwnedGroupArguments(t)
		owned := newByteStorageFinder(byteStorageOutside)
		owned.walk(reflect.ValueOf(cfg), "cfg", "cfg", 0)
		owned.walk(reflect.ValueOf(&signer), "signer", "signer", 0)
		owned.walk(reflect.ValueOf(&cred), "cred", "cred", 0)
		if len(owned.found) == 0 {
			t.Fatalf("%s: the walk over this group's arguments reached no storage, so this row scribbled nothing", row.name)
		}
		group, err := NewGroup(cfg, signer, cred)
		if err != nil {
			t.Fatalf("%s: found the group this row follows: %v", row.name, err)
		}
		before := answerStorageOf(row, group).contents()
		for at, mine := range owned.found {
			mine.scribble(byte(at) | 0x80)
		}
		after := answerStorageOf(row, group).contents()
		for _, route := range slices.Sorted(maps.Keys(before)) {
			if !slices.Equal(before[route], after[route]) {
				t.Errorf("%s answered %v at %s before its caller wrote into its own arrays and %v afterwards",
					row.name, before[route], route, after[route])
			}
		}
		for _, route := range slices.Sorted(maps.Keys(after)) {
			if _, answeredBefore := before[route]; !answeredBefore {
				t.Errorf("%s answered nothing at %s before its caller wrote into its own arrays and %v afterwards",
					row.name, route, after[route])
			}
		}
		group.Close()
	}
}

// mustFoundedGroup is one group over the arguments above, for the rows that do not need the
// arguments back.
func mustFoundedGroup(t *testing.T) *Group {
	t.Helper()
	cfg, signer, cred := callerOwnedGroupArguments(t)
	group, err := NewGroup(cfg, signer, cred)
	if err != nil {
		t.Fatalf("found the group this gate follows: %v", err)
	}
	t.Cleanup(func() { group.Close() })
	return group
}

// groupAnswerDeclaresStorage answers whether a method of *Group can answer byte storage at all,
// read off its signature. A method that cannot is allowed to produce none; one that can and did not
// is a row that observed nothing.
func groupAnswerDeclaresStorage(t *testing.T, name string) bool {
	t.Helper()
	method, found := reflect.TypeOf((*Group)(nil)).MethodByName(name)
	if !found {
		t.Fatalf("*Group declares no method %s, so this row names something that is not in the class", name)
	}
	for at := range method.Type.NumOut() {
		if len(byteStoragePathsOf(method.Type.Out(at), name)) != 0 {
			return true
		}
	}
	return false
}
