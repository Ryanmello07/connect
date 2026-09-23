package protocol_test

// THE GATE RULING 33 IS, AND THE MEASUREMENT IT WAS TAKEN ON.
//
// Item 244: the commit that removes a member is sealed at epoch n, is fetchable
// under read_key[n], and — under Spec B §5.4 as it was RULED — carries read_key[n+1]
// and write_key[n+1] in the clear inside a structure the server serves back verbatim.
// So a removed member ladders every future epoch forever. Reproduced against the
// message server twice: a fetch under a learned read key answered REASON_OK, and a
// forged write under a learned write key answered REASON_OK.
//
// Ruling 27 took the two keys out of the served attachment and replaced them with
// LP(H(epoch_keys)). Ruling 33 decided where they go instead, and it reversed the
// removal track's own step 3, which had said "connect/protocol: the two `Record`
// fields — use 15 and 16". The reason is a fact about this file that is checked below
// rather than recited: `Record` is the SERVER→CLIENT type in six places against two
// client→server carriers. Keys on `Record` would be six serve paths that each have to
// remember to clear them — item 244 re-opened once per path — where a request field
// is a type the response side structurally cannot carry.
//
// THIS FILE IS THE GATE THAT KEEPS THAT TRUE, AND THE PROPERTY IS ABOUT KEYS AND NOT
// ABOUT ONE TYPE NAME. It said otherwise until 2026-09-22, and the header sentence it
// said it in — "any later step that puts a key back on a served type fails here by
// name" — was false as written. Measured: `bytes write_key = 6; bytes read_key = 7;`
// added to FetchResponse, regenerated, whole package green. That is item 244's own
// defect — the epoch keys on the server→client fetch answer — re-created with every
// gate here passing, because nothing looked at a served field's NAME, and the one
// thing that looked at a served field's TYPE looked for a single simple name, reached
// only through the `oneof body` arms, and never through a map. FOUR REPAIRS:
//
//	1. the closure starts AT the envelopes, not at their oneof arms, so a non-oneof
//	   field of MessageServerResponse is inside the served set (it was in NEITHER set)
//	2. carriersOf descends into map values, so EpochKeyDelivery as a map value is a
//	   carrier and not the synthetic FooEntry the match used to compare against
//	3. every field of every served message is checked BY NAME against namesAKey
//	4. every field of every served message is checked BY TYPE, so a key one level out
//	   is caught without the carrier having to name it
//
// WHAT EACH REPAIR ACTUALLY CATCHES, MEASURED BY UNDOING IT — and it is not the tidy
// "four independent mechanisms" the list reads like, so the list does not say that.
// Two mutants: M1 is `bytes write_key = 6; bytes read_key = 7;` on FetchResponse, M2
// is `map<uint64, EpochKeyDelivery> epoch_keys = 4` on MessageServerResponse outside
// its oneof. Both regenerated with protoc 35.1 and run against the whole package.
//
//	M1 -> RED in the NAME check, and in the TYPE check through
//	      MessageServerResponse.fetch, whose type now declares a key. It is GREEN in
//	      both gates that look for the type EpochKeyDelivery, and that is the finding
//	      restated rather than a gap: a raw key is not an EpochKeyDelivery.
//	M2 -> RED in all four.
//
// Then, holding M2 and undoing one repair at a time, only repair 2 is individually
// necessary for the gate it belongs to. The other three still go red, for reasons
// worth knowing rather than worth assuming:
//
//	undo 1 -> TestNoServerToClientMessageCarriesTheEpochKeys is still red, but NOT on
//	          its ruling-33 assertion: the three envelopes fall back into `neither`,
//	          which is undispositioned, and the partition guard fires. That guard is
//	          what makes the reseeding non-revertible; the semantic assertion alone
//	          would have gone quiet.
//	undo 2 -> TestTheEpochKeysAreCarriedByExactlyTheTwoRequests goes GREEN. The IsMap
//	          branch is the whole of that catch.
//	undo 3 -> the NAME check is still red, through the COMPLEMENT and not the
//	          predicate: `epoch_keys` contains "key", the narrowed suffix no longer
//	          flags it, and an unlisted narrowing is an error. The enumeration of what
//	          a narrowing removed is load-bearing here, not commentary.
//	undo 4 -> the TYPE check is still red by ACCIDENT, and the accident is named so
//	          nobody banks on it: every synthetic map entry declares a field called
//	          `key`, which namesAKey matches, so the broken walk trips over the entry
//	          it should not have been looking at.
//
// EVERY SET BELOW IS DERIVED FROM THE COMPILED DESCRIPTOR, and the partition each
// derivation induces is PRINTED — what a narrowing removed is the thing a narrowed
// gate stops seeing, and an enumeration whose complement nobody looks at is an empty
// search that passes silently.
//
// AND THE SAME CLASS AGAIN, ONE COMMIT LATER, IN THIS FILE'S ONE UNPRINTED NARROWING.
//
// The four repairs above left keyNamedFields, keyTypedFields and carriersOf all
// iterating topLevelMessages — and declaresAKeyField is reached only through
// keyTypedFields — so a key on a NESTED type was covered by nothing but a complement
// loop in servedAndSubmitted
// — and that loop excused any simple name ending in "Entry". Reproduced, protoc 35.1,
// inside `message FetchResponse {`:
//
//	message ShimEntry   { KeyBagEntry bag = 1; }
//	message KeyBagEntry { bytes write_key = 1; bytes read_key = 2; }
//	ShimEntry shim = 20;
//
//	-> ok github.com/urnetwork/connect/protocol 0.379s
//
// Item 244's own defect for the second time in two commits, with all four key gates
// green. TWO MORE REPAIRS, and neither is a wider name match:
//
//	5. the key checks and carriersOf walk types AT ANY DEPTH — walkFrom descends by
//	   REFERENCE and by DECLARATION — instead of topLevelMessages
//	6. the exemption is md.IsMapEntry() and not a name suffix, with its complement
//	   printed and asserted against the map fields that produce it, both ways
//
// WHAT EACH REPAIR CATCHES, MEASURED AND NOT ASSUMED. Mutant M3 is the block above; M4
// is `message Extra { EpochKeyDelivery k = 1; } Extra extra = 20;` inside SubmitRequest,
// a THIRD carrier of the delivery type at depth 1 on the SUBMITTED side, where no served
// check looks at all.
//
//	M3 before repair 5  -> ok 0.379s, every gate green
//	M3 after            -> FAIL TestNoServedMessageCarriesAKeyByName (on
//	                       bringyour.FetchResponse.KeyBagEntry.write_key and .read_key)
//	                       FAIL TestNoServedMessageCarriesATypeThatDeclaresAKey
//	M4 with the descent in carriersOf undone and everything else repaired -> ok 0.404s
//	M4 after            -> FAIL TestTheEpochKeysAreCarriedByExactlyTheTwoRequests, and
//	                       that gate ALONE: the third carrier is on the submitted side
//
// So the descent in carriersOf is individually necessary for M4, measured by undoing it
// rather than by reasoning about it.
//
// WHAT NO MUTANT HERE SHOWS, said rather than left as an implication. (a) Repair 6 is
// not exercised by message.proto: the file declares no map field, so IsMapEntry and the
// old suffix agree on every type in it — which is why
// TestTheKeyCheckWalkDescendsAndSkipsOnlyMapEntries BUILDS a descriptor that has one,
// and the predicate is measured there or nowhere. (b) M3 is reached by walkFrom's
// REFERENCE descent; its DECLARATION descent is reached by no mutant, because a type
// nothing references is not on the wire and a mutant of it would be a finding about an
// unwritten line. It is kept anyway and the reason is WHEN: the only finding it can
// produce is a key-named field declared inside a served type, which ruling 33 forbids
// whether or not a field points at it yet, and catching that at the declaration is one
// commit earlier than catching it at the reference.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/urnetwork/connect/protocol"
)

// The name of the type the epoch keys travel in, and the name of the type they must
// never travel in. Simple names, because the test prints simple names.
const (
	keyDeliveryMessage = "EpochKeyDelivery"
	recordMessage      = "Record"
)

// messageFile is message.proto's compiled file descriptor, reached through a type in
// it rather than through the registry, so this walks the file this package was built
// from and not whatever else happens to be linked into the test binary.
func messageFile() protoreflect.FileDescriptor {
	return (*protocol.MessageServerRequest)(nil).ProtoReflect().Descriptor().ParentFile()
}

// topLevelMessages returns every message declared at the top level of message.proto,
// keyed by simple name.
func topLevelMessages(t *testing.T) map[string]protoreflect.MessageDescriptor {
	t.Helper()
	out := map[string]protoreflect.MessageDescriptor{}
	msgs := messageFile().Messages()
	for i := 0; i < msgs.Len(); i++ {
		md := msgs.Get(i)
		out[string(md.Name())] = md
	}
	if len(out) == 0 {
		t.Fatal("message.proto declares no top-level message; this walk is reading the wrong file descriptor")
	}
	return out
}

// envelopeDirections classifies the URmessage envelopes — the top-level messages that
// carry a `oneof body` — into the direction each one travels.
//
// DERIVED, NOT LISTED, in the same way isAuthenticatorField derives the authenticator
// class: an envelope is a top-level message with a non-synthetic `oneof body`, and it
// is client→server iff its name ends in "Request". Spec B §4.3 names exactly three —
// MessageServerRequest, MessageServerResponse and MessageServerPush — and
// TestTheEnvelopeDirectionDerivationFindsAllThree asserts the derivation finds those
// three and no others, so a fourth envelope added later cannot arrive unclassified
// and a rename cannot silently empty the server→client side.
func envelopeDirections(t *testing.T) (clientToServer, serverToClient []protoreflect.MessageDescriptor) {
	t.Helper()
	all := topLevelMessages(t)
	for _, name := range sortedKeys(all) {
		md := all[name]
		od := md.Oneofs().ByName("body")
		if od == nil || od.IsSynthetic() {
			continue
		}
		if strings.HasSuffix(name, "Request") {
			clientToServer = append(clientToServer, md)
		} else {
			serverToClient = append(serverToClient, md)
		}
	}
	return clientToServer, serverToClient
}

// closureFrom returns every message type reachable from these envelopes, THE
// ENVELOPES THEMSELVES INCLUDED. Reachability is what makes this a derived class:
// nesting a new type inside a served message pulls it in without anybody editing this
// file.
//
// IT STARTS AT THE ENVELOPE AND NOT AT `oneof body`, and that is a reproduced defect
// and not a tidy-up. Seeded with `od.Fields()` — the arms — the three envelopes' OWN
// non-oneof fields were in no closure at all: this file's own log printed
// `neither (4): [MessageServerFragment MessageServerPush MessageServerRequest
// MessageServerResponse]` and nobody read it as the hole it was. A
// `map<uint64, EpochKeyDelivery> epoch_keys = 4` added to MessageServerResponse
// OUTSIDE its oneof left every gate in this file green. An envelope is the most
// served thing here; it was the one thing the served set excluded.
func closureFrom(envelopes []protoreflect.MessageDescriptor) map[string]bool {
	out := map[string]bool{}
	var visit func(md protoreflect.MessageDescriptor)
	visit = func(md protoreflect.MessageDescriptor) {
		name := string(md.Name())
		if out[name] {
			return
		}
		out[name] = true
		fields := md.Fields()
		for i := 0; i < fields.Len(); i++ {
			f := fields.Get(i)
			if sub := f.Message(); sub != nil {
				visit(sub)
			}
			if f.IsMap() {
				if sub := f.MapValue().Message(); sub != nil {
					visit(sub)
				}
			}
		}
	}
	for _, envelope := range envelopes {
		visit(envelope)
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k, in := range m {
		if in {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// allMessageTypes returns every message message.proto declares AT ANY DEPTH, keyed by
// FULL name. topLevelMessages is the file's outermost layer; this is the file.
func allMessageTypes(t *testing.T) map[string]protoreflect.MessageDescriptor {
	t.Helper()
	out := map[string]protoreflect.MessageDescriptor{}
	var visit func(msgs protoreflect.MessageDescriptors)
	visit = func(msgs protoreflect.MessageDescriptors) {
		for i := 0; i < msgs.Len(); i++ {
			md := msgs.Get(i)
			out[string(md.FullName())] = md
			visit(md.Messages())
		}
	}
	visit(messageFile().Messages())
	if len(out) == 0 {
		t.Fatal("message.proto declares no message at all; this walk is reading the wrong file descriptor")
	}
	return out
}

// isTopLevel answers from the name rather than from pointer identity: a top-level
// message's full name has the file's package as its parent, a nested one has its
// enclosing message.
func isTopLevel(md protoreflect.MessageDescriptor) bool {
	return md.FullName().Parent() == messageFile().Package()
}

// typeWalk is what a set of root messages expands to for the key checks below: every
// message type reachable from a root BY REFERENCE and every message type DECLARED inside
// any of those, recursively — partitioned into the types the checks WALK and the
// synthetic map entries they SKIP, with the map fields that produced those entries kept
// so the skip can be asserted from both ends.
//
// KEYED BY FULL NAME, and the map entries are the reason: protoc names a synthetic entry
// after its FIELD, so two messages that each declare a map field called `foo` declare two
// different types both simply named `FooEntry`. A walk keyed on simple names would hold
// one of them and drop the other with nothing to notice.
//
// DECLARATION AS WELL AS REFERENCE, because a type declared inside a served message and
// not yet referenced by any field is one line away from being served and is invisible to
// a reachability walk.
type typeWalk struct {
	checked    map[string]protoreflect.MessageDescriptor
	mapEntries map[string]protoreflect.MessageDescriptor
	mapFields  map[string]string // map field full name -> its synthetic entry's full name
}

// walkFrom is the walk, and THE ONE NARROWING IN IT IS md.IsMapEntry().
//
// A synthetic map entry declares fields literally named `key` and `value`, so checking
// one would make every map field a finding about protoc rather than about this file. The
// predicate is the descriptor's own answer — true of synthetic entries and of nothing
// else — and NOT `strings.HasSuffix(name, "Entry")`, which is what stood here until
// 2026-09-22 and which the header records riding straight through. A skipped entry's
// VALUE type is still reached, by the IsMap branch below.
func walkFrom(roots []protoreflect.MessageDescriptor) typeWalk {
	w := typeWalk{
		checked:    map[string]protoreflect.MessageDescriptor{},
		mapEntries: map[string]protoreflect.MessageDescriptor{},
		mapFields:  map[string]string{},
	}
	seen := map[string]bool{}
	var visit func(md protoreflect.MessageDescriptor)
	visit = func(md protoreflect.MessageDescriptor) {
		full := string(md.FullName())
		if seen[full] {
			return
		}
		seen[full] = true
		if md.IsMapEntry() {
			w.mapEntries[full] = md
		} else {
			w.checked[full] = md
		}
		fields := md.Fields()
		for i := 0; i < fields.Len(); i++ {
			f := fields.Get(i)
			if sub := f.Message(); sub != nil {
				if f.IsMap() {
					w.mapFields[string(f.FullName())] = string(sub.FullName())
				}
				visit(sub)
			}
			if f.IsMap() {
				if sub := f.MapValue().Message(); sub != nil {
					visit(sub)
				}
			}
		}
		nested := md.Messages()
		for i := 0; i < nested.Len(); i++ {
			visit(nested.Get(i))
		}
	}
	for _, root := range roots {
		visit(root)
	}
	return w
}

// walkOfNames expands these TOP-LEVEL message names into the walk above.
func walkOfNames(t *testing.T, names map[string]bool) typeWalk {
	t.Helper()
	all := topLevelMessages(t)
	roots := []protoreflect.MessageDescriptor{}
	for _, name := range sortedKeys(all) {
		if names[name] {
			roots = append(roots, all[name])
		}
	}
	if len(roots) == 0 {
		t.Fatal("no root message was named, so the walk below covers nothing and every check over " +
			"it is a search across an empty set")
	}
	return walkFrom(roots)
}

// TestTheEnvelopeDirectionDerivationFindsAllThree is the floor under every set in
// this file. Without it, a rename that emptied the server→client side would make the
// ruling-33 gate below pass over nothing at all, which is the way a gate stops
// working without failing.
func TestTheEnvelopeDirectionDerivationFindsAllThree(t *testing.T) {
	clientToServer, serverToClient := envelopeDirections(t)
	got := map[string]string{}
	for _, md := range clientToServer {
		got[string(md.Name())] = "client→server"
	}
	for _, md := range serverToClient {
		got[string(md.Name())] = "server→client"
	}
	want := map[string]string{
		"MessageServerRequest":  "client→server",
		"MessageServerResponse": "server→client",
		"MessageServerPush":     "server→client",
	}
	for name, direction := range want {
		if got[name] != direction {
			t.Errorf("the derivation classifies %s as %q; Spec B §4.3 makes it %q",
				name, got[name], direction)
		}
	}
	for name, direction := range got {
		if _, known := want[name]; !known {
			t.Errorf("%s carries a `oneof body`, so this file treats it as a URmessage envelope and "+
				"classified it %q by its name alone. Spec B §4.3 names three envelopes. Decide which "+
				"direction this one travels and write it down here, because the ruling-33 gate is "+
				"only as wide as this classification.", name, direction)
		}
	}
	if len(serverToClient) == 0 {
		t.Fatal("no envelope was classified server→client, so the gate below is asserting something about an empty set")
	}
	t.Logf("envelope directions: %v", got)
}

// unreachedFromAnyEnvelope is the `neither` partition, WRITTEN DOWN WITH A
// DISPOSITION EACH, because a top-level message no envelope reaches is a message this
// file's reachability argument does not cover, and an uncovered message is exactly
// where a key would go to be missed.
//
// There is one, and it is treated as SERVED: a fragment travels back from the server
// on every response large enough to need one.
var unreachedFromAnyEnvelope = map[string]string{
	"MessageServerFragment": "the transport fragment, bound as frame type 1003 in frame.proto and not " +
		"as an arm of any envelope. It travels BOTH directions and carries an envelope's octets " +
		"opaquely in `part`, so it is SERVED and the key checks below cover it.",
}

// servedAndSubmitted partitions message.proto's top-level messages by which envelopes
// reach them, and answers with the set the key checks are about.
//
// THE SERVED SET IS "NOT SUBMITTED-ONLY" AND NOT "SERVED-ONLY". A type in `both`
// (Record) is served. A type in `neither` is not PROVEN unserved — nothing reached it,
// which is an absence of evidence — so each is dispositioned by name above and treated
// as served. Only a type reachable from the client→server envelope and from nothing
// else is a place a key may legitimately sit.
func servedAndSubmitted(t *testing.T) (served, submitted, servedSet map[string]bool) {
	t.Helper()
	clientToServer, serverToClient := envelopeDirections(t)
	served = closureFrom(serverToClient)
	submitted = closureFrom(clientToServer)

	both := map[string]bool{}
	servedOnly := map[string]bool{}
	submittedOnly := map[string]bool{}
	neither := map[string]bool{}
	for _, name := range sortedKeys(topLevelMessages(t)) {
		switch {
		case served[name] && submitted[name]:
			both[name] = true
		case served[name]:
			servedOnly[name] = true
		case submitted[name]:
			submittedOnly[name] = true
		default:
			neither[name] = true
		}
	}
	t.Logf("served only    (%2d): %v", len(servedOnly), sortedSet(servedOnly))
	t.Logf("submitted only (%2d): %v", len(submittedOnly), sortedSet(submittedOnly))
	t.Logf("both           (%2d): %v", len(both), sortedSet(both))
	t.Logf("neither        (%2d): %v", len(neither), sortedSet(neither))

	// THE `neither` PARTITION IS ASSERTED IN BOTH DIRECTIONS. An unexpected member is a
	// message whose direction nobody decided; a missing one means the disposition above
	// is dead text describing a file that has moved.
	for name := range neither {
		if _, dispositioned := unreachedFromAnyEnvelope[name]; !dispositioned {
			t.Errorf("%s is reachable from no envelope, so nothing here knows which direction it "+
				"travels and it lands in the served set by default rather than by decision. Write "+
				"its disposition into unreachedFromAnyEnvelope.", name)
		}
	}
	for name := range unreachedFromAnyEnvelope {
		if !neither[name] {
			t.Errorf("unreachedFromAnyEnvelope dispositions %s, but an envelope now reaches it or it "+
				"is gone. A dead disposition is a sentence about this file that has stopped being true.",
				name)
		}
	}

	servedSet = map[string]bool{}
	for name := range servedOnly {
		servedSet[name] = true
	}
	for name := range both {
		servedSet[name] = true
	}
	for name := range neither {
		servedSet[name] = true
	}
	if len(servedSet) == 0 {
		t.Fatal("the served set is empty, so every key check below is a search over nothing")
	}
	// the inline positive control: Record IS served, which is the fact ruling 33 was
	// taken on. If this fails, the walk is not reaching the served records and every
	// refusal below is vacuous.
	if !servedSet[recordMessage] {
		t.Fatalf("%s is not in the served set, so the walk is not reaching the served records and "+
			"the refusals below are vacuous", recordMessage)
	}
	// and the complement of "top level", WHICH IS NO LONGER AN EXEMPTION. This loop used
	// to require every member of the served closure to be a top-level message and excused
	// anything whose simple name ended in "Entry" — and since all three key checks
	// iterated topLevelMessages, that one loop was the WHOLE of the coverage of nested
	// types. It excused nothing that exists (TestTheKeyCheckWalkDescendsAndSkipsOnlyMapEntries
	// measures the file's map entries and its *Entry names at zero) while a KeyBagEntry
	// two levels down inside FetchResponse carried write_key and read_key through every
	// gate green. The checks now walk nested types directly, so what is left here is the
	// partition PRINTED: the day message.proto grows its first nested served type, the log
	// says so instead of a suffix deciding it.
	nested := []string{}
	for _, name := range sortedSet(served) {
		if _, top := topLevelMessages(t)[name]; !top {
			nested = append(nested, name)
		}
	}
	t.Logf("served closure members that are NOT top-level (%d): %v", len(nested), nested)
	return served, submitted, servedSet
}

// THE RULING 33 GATE: NO SERVER→CLIENT MESSAGE TRANSITIVELY CARRIES AN EpochKeyDelivery.
//
// The set is the transitive closure of every server→client envelope, so a key
// delivery nested three types deep inside a FetchResponse fails here exactly as one
// nested directly on it does — and one hung on the ENVELOPE itself fails too, which
// it did not until the closure was reseeded.
//
// The partition is printed in full — served only, submitted only, both, neither —
// because that is the only way to see that the closure reached anything. A gate that
// searched an empty set for EpochKeyDelivery would pass, and would go on passing for
// as long as it took somebody to put the keys back.
func TestNoServerToClientMessageCarriesTheEpochKeys(t *testing.T) {
	served, submitted, servedSet := servedAndSubmitted(t)

	if served[keyDeliveryMessage] || servedSet[keyDeliveryMessage] {
		t.Errorf("%s is reachable from a server→client envelope. Ruling 33: the epoch keys travel on "+
			"the REQUEST messages and never on anything the server hands back — a served key field is "+
			"item 244 re-opened, once for every serve path that forgets to clear it.", keyDeliveryMessage)
	}
	if !submitted[keyDeliveryMessage] {
		t.Errorf("%s is not reachable from a client→server envelope either, so it is now on no path at "+
			"all and the keys have nowhere to ride", keyDeliveryMessage)
	}
}

// namesAKey is the served-side field-name predicate: the one already applied to
// Record, NARROWED — with the narrowing printed by the test that uses it.
//
// `strings.Contains(name, "key")` is what Record is checked with, and Record carries
// nothing that would trip it falsely. Over the whole served set it does trip:
// Capabilities.read_key_window_seconds is a DURATION, named after the key whose
// retention it bounds. So the predicate is the suffix and not the substring, and
// TestNoServedMessageCarriesAKeyByName prints every served field name that contains
// "key" and that this predicate did NOT flag, asserted in both directions — because a
// narrowing whose complement nobody enumerates is how a gate quietly stops covering
// the thing it is named for.
func namesAKey(name string) bool {
	return name == "key" || strings.HasSuffix(name, "_key") || strings.HasSuffix(name, "_keys")
}

// keyNameExemptions are the fields namesAKey flags that are NOT key material, each
// with its argument, and each ASSERTED USED below.
//
// ONE LIST FOR BOTH CHECKS. The name check partitions its findings against it and is
// where "used" is measured; declaresAKeyField consults it too, so a type whose only
// key-named field is an exempt one does not make every carrier of that type a
// finding. Two lists would drift, and the drift would be silent in the direction that
// matters: an exemption taken on one check and not the other.
var keyNameExemptions = map[string]string{
	"bringyour.HelloResponse.server_keys": "repeated ServerKey — the fleet's Ed25519 PUBLIC signing " +
		"keys and their certification chain (`pub`, `sig_by_previous`, `sig_by_root`). Publishing " +
		"them is the point of the field: a client cannot verify a server signature without them.",
	"bringyour.CapabilityChange.server_keys": "the same set, re-served on rotation. Same argument.",
}

// keyNamedFields returns the fields of every message in this walk that namesAKey flags,
// and, as the complement, the ones whose name merely CONTAINS "key" and that it did not.
//
// IT TAKES THE WALK AND NOT A SET OF TOP-LEVEL NAMES. Until 2026-09-22 it iterated
// topLevelMessages, so a key on a NESTED type was outside it — reproduced, and recorded
// in the header with its protoc output.
func keyNamedFields(t *testing.T, w typeWalk) (flagged, narrowedAway map[string]string) {
	t.Helper()
	flagged = map[string]string{}
	narrowedAway = map[string]string{}
	for _, message := range sortedKeys(w.checked) {
		fields := w.checked[message].Fields()
		for i := 0; i < fields.Len(); i++ {
			f := fields.Get(i)
			name := string(f.Name())
			switch {
			case namesAKey(name):
				flagged[string(f.FullName())] = message
			case strings.Contains(name, "key"):
				narrowedAway[string(f.FullName())] = message
			}
		}
	}
	return flagged, narrowedAway
}

// NO SERVED MESSAGE CARRIES A FIELD THAT NAMES A KEY.
//
// This is the check that was missing, and item 244's own defect is what goes through
// where it is not: `bytes write_key = 6; bytes read_key = 7;` on FetchResponse is the
// served fetch answer handing out the next epoch's keys, in raw octets, naming
// itself — and every other gate in this file passed on it. A key does not have to be
// an EpochKeyDelivery to be a key.
func TestNoServedMessageCarriesAKeyByName(t *testing.T) {
	_, submitted, servedSet := servedAndSubmitted(t)

	w := walkOfNames(t, servedSet)
	t.Logf("the key checks walk %d served types (%d of them nested) and skip %d synthetic map entries",
		len(w.checked), len(w.checked)-countTopLevel(w.checked), len(w.mapEntries))
	flagged, narrowedAway := keyNamedFields(t, w)
	t.Logf("served fields whose name names a key (%d): %v", len(flagged), sortedKeys(flagged))
	t.Logf("served fields containing \"key\" that the SUFFIX predicate narrowed away (%d): %v",
		len(narrowedAway), sortedKeys(narrowedAway))

	// THE COMPLEMENT, ASSERTED IN BOTH DIRECTIONS. Every field the narrowing removed is
	// written down with its reason, so a new one has to be dispositioned rather than
	// silently skipped, and a stale one means this list describes a file that has moved.
	narrowedAwayOnPurpose := map[string]string{
		"bringyour.Capabilities.read_key_window_seconds": "a DURATION — how long this server retains " +
			"each installed read key (§5.3's ninety-day window). It names the key whose retention it " +
			"bounds and carries none.",
	}
	for full := range narrowedAway {
		if _, known := narrowedAwayOnPurpose[full]; !known {
			t.Errorf("%s contains \"key\" and namesAKey did not flag it, so this gate is not looking "+
				"at it. Either it is key material and the predicate is too narrow, or it is not and it "+
				"belongs in narrowedAwayOnPurpose with the argument.", full)
		}
	}
	for full := range narrowedAwayOnPurpose {
		if _, still := narrowedAway[full]; !still {
			t.Errorf("narrowedAwayOnPurpose excuses %s and nothing needs the excuse any more — it was "+
				"renamed, removed, or is now flagged. A dead exemption is a narrowing nobody is "+
				"measuring.", full)
		}
	}

	usedExemption := map[string]bool{}
	for _, full := range sortedKeys(flagged) {
		if _, exempt := keyNameExemptions[full]; exempt {
			usedExemption[full] = true
			continue
		}
		t.Errorf("%s is a field of %s — a type a server→client envelope reaches, or one DECLARED "+
			"inside such a type and one field reference away from being reached — and its name names "+
			"a key. Item 244 IS this shape: the served commit carrying read_key[n+1] and "+
			"write_key[n+1]. Ruling 33 is that nothing served carries one, and a key declared inside "+
			"a served type is not exempt from it for as long as no field happens to point at it. If "+
			"it is not key material, exempt it in keyNameExemptions with the argument; do not rename "+
			"it past the predicate.",
			full, flagged[full])
	}
	for full := range keyNameExemptions {
		if !usedExemption[full] {
			t.Errorf("keyNameExemptions exempts %s and nothing needed the exemption. Either the "+
				"field moved out of the served set or it is gone; either way this is a hole written "+
				"into the gate for a reason that has stopped applying.", full)
		}
	}
	t.Logf("exemptions used (%d of %d): %v", len(usedExemption), len(keyNameExemptions),
		sortedKeys(usedExemption))

	// THE FAILING DIRECTION, IN THE SAME QUERY. The identical predicate over the
	// submitted-only set must find the deliveries, or the refusal above is a predicate
	// that matches nothing rather than a file that carries nothing.
	submittedOnly := map[string]bool{}
	for name := range submitted {
		if !servedSet[name] {
			submittedOnly[name] = true
		}
	}
	control, _ := keyNamedFields(t, walkOfNames(t, submittedOnly))
	t.Logf("CONTROL — submitted-only fields that name a key (%d): %v", len(control), sortedKeys(control))
	for _, want := range []string{
		"bringyour.SubmitRequest.epoch_keys",
		"bringyour.CreateGroupRequest.epoch_keys",
		"bringyour.CreateGroupRequest.bootstrap_write_key",
	} {
		if _, found := control[want]; !found {
			t.Errorf("the control did not find %s, so namesAKey is matching nothing and the "+
				"served-side refusal above proves nothing", want)
		}
	}
}

// declaresAKeyField answers whether this message type itself declares a field that
// names a key — the TYPE-level half of the same property.
// It consults keyNameExemptions for the reason given there: HelloResponse declares
// `server_keys`, so without the exemption every envelope arm that carries a
// HelloResponse would be reported as reaching key material, and the finding would be
// the fleet's public signing keys.
func declaresAKeyField(md protoreflect.MessageDescriptor) []string {
	out := []string{}
	fields := md.Fields()
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		if _, exempt := keyNameExemptions[string(f.FullName())]; exempt {
			continue
		}
		if name := string(f.Name()); namesAKey(name) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// keyTypedFields returns the fields of every message in this walk whose MESSAGE TYPE
// declares a key, descending into map values.
//
// IT TAKES THE WALK, for the reason keyNamedFields gives.
func keyTypedFields(t *testing.T, w typeWalk) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, message := range sortedKeys(w.checked) {
		fields := w.checked[message].Fields()
		for i := 0; i < fields.Len(); i++ {
			f := fields.Get(i)
			sub := f.Message()
			// MAP VALUES ARE DESCENDED INTO, and that is a reproduced defect and not a
			// completeness flourish: `map<uint64, EpochKeyDelivery> epoch_keys = 4` is a
			// field whose f.Message() is the SYNTHETIC EpochKeysEntry, so a match that does
			// not call f.IsMap() compares against the wrong descriptor and never fires.
			if f.IsMap() {
				sub = f.MapValue().Message()
			}
			if sub == nil {
				continue
			}
			if declared := declaresAKeyField(sub); len(declared) > 0 {
				out[string(f.FullName())] = declared
			}
		}
	}
	return out
}

// NO SERVED MESSAGE CARRIES A FIELD WHOSE TYPE DECLARES A KEY.
//
// The name check above catches a key the served message names itself. This one
// catches a key ONE LEVEL OUT — a served field of some type that declares the keys,
// under a field name that says nothing — which is what an economy-minded later step
// reaches for once the name check is in the way.
func TestNoServedMessageCarriesATypeThatDeclaresAKey(t *testing.T) {
	_, submitted, servedSet := servedAndSubmitted(t)

	// the positive control, stated before the walk: the predicate flags the delivery
	// type. Without it the walk below could be running a predicate that is false of
	// everything in the file.
	delivery := topLevelMessages(t)[keyDeliveryMessage]
	if delivery == nil {
		t.Fatalf("message.proto declares no %s", keyDeliveryMessage)
	}
	declared := declaresAKeyField(delivery)
	if len(declared) == 0 {
		t.Fatalf("%s declares no field namesAKey flags, so the walk below cannot fire on the one type "+
			"it exists for. Its fields ARE the keys; if they were renamed, widen the predicate.",
			keyDeliveryMessage)
	}
	t.Logf("CONTROL — %s declares key fields %v", keyDeliveryMessage, declared)

	carried := keyTypedFields(t, walkOfNames(t, servedSet))
	t.Logf("served fields whose type declares a key (%d): %v", len(carried), sortedKeys(carried))
	for _, full := range sortedKeys(carried) {
		t.Errorf("%s has a type that declares %v. A served field does not have to NAME a key to carry "+
			"one: ruling 33 is that nothing the server hands back reaches key material at any depth, "+
			"and the walk that found this covers types DECLARED inside a served message as well as "+
			"types it references. Put the keys on a request.", full, carried[full])
	}

	// THE FAILING DIRECTION, IN THE SAME QUERY: the identical walk over the submitted
	// side must find the two carriers ruling 33 names.
	submittedOnly := map[string]bool{}
	for name := range submitted {
		if !servedSet[name] {
			submittedOnly[name] = true
		}
	}
	found := keyTypedFields(t, walkOfNames(t, submittedOnly))
	t.Logf("CONTROL — submitted-only fields whose type declares a key (%d): %v", len(found), sortedKeys(found))
	for _, want := range []string{
		"bringyour.SubmitRequest.epoch_keys",
		"bringyour.CreateGroupRequest.epoch_keys",
	} {
		if _, ok := found[want]; !ok {
			t.Errorf("the control did not find %s, so this walk finds nothing anywhere and the "+
				"served-side refusal above proves nothing", want)
		}
	}
}

// carriersOf returns every message message.proto declares — AT ANY DEPTH — with a field
// whose type is this message, keyed by the carrier's FULL name, with the field name each
// one carries it under.
//
// AT ANY DEPTH, for the reason the key checks now walk nested types. A carrier nested
// inside a request is a third place the keys can be forgotten, and a walk over top-level
// messages answers "exactly the two requests" for a file that has three. Measured, with
// the top-level walk still in place: `message Extra { EpochKeyDelivery k = 1; }` nested
// inside SubmitRequest with an `Extra extra = 20;` beside it left this gate green.
//
// MAP VALUES COUNT, for the reason keyTypedFields gives: without the IsMap branch
// this answered "no carrier" for a message that is carried as a map value, measured
// with the mutant green. SYNTHETIC MAP ENTRIES ARE NOT THEMSELVES CARRIERS: the entry of
// `map<k, EpochKeyDelivery>` has a `value` field of that type, and reporting the entry
// would name the type protoc wrote instead of the field a person did — which is the
// carrying message the IsMap branch already reports.
func carriersOf(t *testing.T, typeName string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	all := allMessageTypes(t)
	for _, name := range sortedKeys(all) {
		md := all[name]
		if md.IsMapEntry() {
			continue
		}
		fields := md.Fields()
		for i := 0; i < fields.Len(); i++ {
			f := fields.Get(i)
			sub := f.Message()
			if f.IsMap() {
				sub = f.MapValue().Message()
			}
			if sub != nil && string(sub.Name()) == typeName {
				out[name] = append(out[name], string(f.Name()))
			}
		}
	}
	return out
}

// countTopLevel is the printed half of the walk's coverage: how many of these types are
// message.proto's outermost layer, so the nested count is visible as the difference.
func countTopLevel(types map[string]protoreflect.MessageDescriptor) int {
	n := 0
	for _, md := range types {
		if isTopLevel(md) {
			n++
		}
	}
	return n
}

// The key delivery is carried by exactly the two request messages ruling 33 names,
// and the SAME QUERY prints Record's carriers as the control.
//
// Record's carriers are the control rather than a second test because they are the
// measurement the ruling rests on — six served, two submitted — and a query that
// found two carriers for one type and none for the other would be a query that had
// stopped reading the file, not a file that had changed.
func TestTheEpochKeysAreCarriedByExactlyTheTwoRequests(t *testing.T) {
	delivery := carriersOf(t, keyDeliveryMessage)
	records := carriersOf(t, recordMessage)

	t.Logf("%s carriers: %v", keyDeliveryMessage, delivery)
	t.Logf("%s carriers (the control): %v", recordMessage, records)

	if len(records) == 0 {
		t.Fatalf("the control found no carrier of %s at all, so this query is reading nothing", recordMessage)
	}

	// FULL NAMES, because carriersOf now walks every depth: a carrier nested inside one of
	// these two would be a different type with the same tail, and ruling 33 names the
	// top-level requests and not whatever is declared inside them.
	wantDelivery := map[string]string{
		"bringyour.SubmitRequest":      "epoch_keys",
		"bringyour.CreateGroupRequest": "epoch_keys",
	}
	for name, field := range wantDelivery {
		fields, carried := delivery[name]
		if !carried {
			t.Errorf("%s does not carry a %s; ruling 33 puts one on it", name, keyDeliveryMessage)
			continue
		}
		if len(fields) != 1 || fields[0] != field {
			t.Errorf("%s carries %s as %v, want exactly [%s]", name, keyDeliveryMessage, fields, field)
		}
	}
	for name := range delivery {
		if _, expected := wantDelivery[name]; !expected {
			t.Errorf("%s carries a %s and ruling 33 gives it to two messages only: SubmitRequest and "+
				"CreateGroupRequest. A third carrier is a third place the keys can be forgotten.",
				name, keyDeliveryMessage)
		}
	}

	// and the ruling's own measurement, re-derived here rather than taken from the
	// ledger: Record is the server→client type in six places against two client→server
	// carriers, which is why a key pair on it would have been six serve paths.
	//
	// SERVED-NESS IS TAKEN FROM THE WALK AND NOT FROM servedSet, because carriersOf keys
	// by full name and can now answer with a nested type. servedSet is top-level simple
	// names; a nested carrier looked up in it would miss and be counted as submitted,
	// which is the ratio silently answering the wrong question.
	_, _, servedSet := servedAndSubmitted(t)
	servedTypes := walkOfNames(t, servedSet).checked
	servedFields, submittedFields := 0, 0
	for name, fields := range records {
		if _, isServed := servedTypes[name]; isServed {
			servedFields += len(fields)
		} else {
			submittedFields += len(fields)
		}
	}
	if servedFields != 6 || submittedFields != 2 {
		t.Errorf("Record is a field of %d server→client messages and %d client→server ones; item 248 "+
			"measured six and two, and the ratio is the whole argument for ruling 33. If the file "+
			"really changed, re-argue the ruling rather than re-typing these numbers.",
			servedFields, submittedFields)
	}
	t.Logf("Record appears in %d served fields and %d submitted fields", servedFields, submittedFields)
}

// Record gains nothing, and field 14 stays out of reach.
//
// The keys half is covered transitively above; this states it directly at the type it
// is about, and adds the number. Spec B §4.3.3 declares `uint64 eph_window = 14` on
// this message and this file does not carry it — the eph window landed in the record
// CODEC at format version 0x02 and never in the protobuf projection — so 14 is
// spoken for by a field that has not arrived, not free.
func TestRecordCarriesNoKeysAndLeavesFourteenAlone(t *testing.T) {
	record := topLevelMessages(t)[recordMessage]
	if record == nil {
		t.Fatalf("message.proto declares no %s", recordMessage)
	}
	fields := record.Fields()
	numbers := map[int]string{}
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		numbers[int(f.Number())] = string(f.Name())
		if sub := f.Message(); sub != nil && string(sub.Name()) == keyDeliveryMessage {
			t.Errorf("%s.%s is an %s. Ruling 33: not on Record, ever — and the projection contract "+
				"refuses it anyway, because the server checks every field below record_bytes against "+
				"ParseRecord(record_bytes) and a key is by construction not implied by a projection "+
				"of those octets.", recordMessage, f.Name(), keyDeliveryMessage)
		}
		if name := string(f.Name()); strings.Contains(name, "key") {
			t.Errorf("%s.%s names a key. Whatever it carries, the whole of ruling 33 is that this "+
				"type carries none.", recordMessage, name)
		}
	}
	if len(numbers) == 0 {
		t.Fatalf("%s declares no field at all, so this walk read nothing", recordMessage)
	}
	if name, taken := numbers[14]; taken {
		t.Errorf("%s.%s is field 14. Spec B §4.3.3 gives 14 to eph_window on this message; taking it "+
			"for anything else puts a different field at 14 from the one every reader of that section "+
			"expects, and a projection field is compared against a parse.", recordMessage, name)
	}
	// the inline positive control: 13 IS taken, by record_id, so "14 is free" is a
	// statement about this walk having read the field numbers rather than none
	if numbers[13] != "record_id" {
		t.Errorf("%s field 13 is %q, want record_id; the number walk is not reading this message",
			recordMessage, numbers[13])
	}
	t.Logf("%s fields by number: %v", recordMessage, numbers)
}

// THE ALIGNMENT RULE, ASSERTED ON BOTH HALVES IT HAS.
//
// The shape half is the descriptor's: `epoch_keys` is repeated, of the delivery type,
// on the same message as the repeated `records` it aligns with. A singular field
// cannot be positionally aligned with a list, so the cardinality IS the rule's first
// clause.
//
// The rule half is the source's, and it is asserted over message.proto's own octets
// because that is where it lives: nothing in a descriptor can say what an entry means
// for a record that is not a commit.
//
// AND THE CLAUSE LIST NOW PINS WHAT THE RULE RESTS ON. The three clauses — the length,
// the entry-against-a-non-commit refusal and the commit-with-no-entry refusal — admit
// NO value at all for a batch mixing a commit with an ordinary record: length 0 leaves
// the commit with no entry, length n puts an entry against a non-commit, and any other
// length fails the length clause. They are satisfiable only because Spec B §4.3.3
// restricts a batch containing a commit to exactly one record. This file said the
// opposite — "the batch rule is Spec B's to relax and this alignment is not" — and
// this gate pinned that sentence. A rule that becomes unsatisfiable the moment its
// claimed independence is exercised is not general, so what the clauses below pin is
// the DEPENDENCY and its price, and the next reader relaxing §4.3.3 finds the wire
// cost written down instead of an assurance that there is none.
func TestTheEpochKeyDeliveriesAlignWithTheRecordsTheySubmit(t *testing.T) {
	submit := topLevelMessages(t)["SubmitRequest"]
	if submit == nil {
		t.Fatal("message.proto declares no SubmitRequest")
	}
	records := submit.Fields().ByName("records")
	deliveries := submit.Fields().ByName("epoch_keys")
	if records == nil || deliveries == nil {
		t.Fatalf("SubmitRequest has records=%v and epoch_keys=%v; the alignment is between those two",
			records != nil, deliveries != nil)
	}
	if records.Cardinality() != protoreflect.Repeated {
		t.Errorf("SubmitRequest.records is %v, want repeated", records.Cardinality())
	}
	if deliveries.Cardinality() != protoreflect.Repeated {
		t.Errorf("SubmitRequest.epoch_keys is %v; a singular field cannot be POSITIONALLY ALIGNED with "+
			"a repeated one, so this cardinality is the first clause of the rule and not a style choice",
			deliveries.Cardinality())
	}
	if sub := deliveries.Message(); sub == nil || string(sub.Name()) != keyDeliveryMessage {
		t.Errorf("SubmitRequest.epoch_keys has type %v, want %s", sub, keyDeliveryMessage)
	}
	// the pattern being followed, in the same test: SubmitResponse.results is the
	// repeated field this alignment is copied from, and if IT is not repeated then the
	// precedent this rule cites does not exist
	response := topLevelMessages(t)["SubmitResponse"]
	if response == nil {
		t.Fatal("message.proto declares no SubmitResponse")
	}
	if results := response.Fields().ByName("results"); results == nil || results.Cardinality() != protoreflect.Repeated {
		t.Errorf("SubmitResponse.results is %v; it is the pattern SubmitRequest.epoch_keys follows", results)
	}

	block := flatten(t, submitRequestSource(t), "and so is a commit with no entry")
	for _, clause := range []struct {
		what   string
		phrase string
	}{
		{"the alignment", "POSITIONALLY ALIGNED"},
		{"the field it aligns with", "`records`"},
		{"the length rule", "EMPTY, OR EXACTLY AS LONG AS `records`"},
		{"what an entry against a non-commit means", "is_commit = 0 IS REASON_REJECTED"},
		{"what a commit with no entry means", "and so is a commit with no entry"},
		{"the batch rule the three clauses rest on", "A batch containing a commit MUST contain exactly one record."},
		{"the empty case", "EMPTY when `records` carries no commit"},
		{"the one-entry case", "EXACTLY ONE ENTRY when `records` is a single commit"},
		{"that a mixed batch has no valid value at all", "UNSATISFIABLE"},
		{"what relaxing the batch rule would cost", "would need explicit presence"},
	} {
		if !strings.Contains(block, clause.phrase) {
			t.Errorf("SubmitRequest's declaration does not state %s. The phrase %q is gone, and this "+
				"rule lives nowhere else: no descriptor can carry it, and the server that enforces it "+
				"is in another repository reading this file.", clause.what, clause.phrase)
		}
	}
}

// THE SECOND CARRIER'S PRESENCE RULE. Symmetry, because the hazard is symmetric.
//
// CreateGroupRequest.epoch_keys had no presence rule anywhere and no gate. The hazard
// SubmitRequest documents at length — "a commit whose keys never arrived is an epoch
// the server would install without having been handed what opens it" — applies
// verbatim to the create-group commit that installs epoch 1, and was written for
// neither this carrier nor covered by any test: the alignment gate above reads
// SubmitRequest's block alone. Nothing downstream supplied it either. Measured, with
// the control inline in the same query: `GetEpochKeys` occurs in 0 non-generated Go
// files in connect, 0 in sdk and 0 in msgrepo, against `GetRecords` at 0 / 1 / 13; and
// Spec B §4.3.2 still declares this message with fields 1..3 and no delivery at all.
//
// It is NOT the same rule as SubmitRequest's, which is why writing it down mattered
// rather than citing the other one: this field is SINGULAR, so absence is
// representable and distinguishable, and the two refusals — an absent delivery and a
// present-but-zero delivery — are different refusals for different reasons.
func TestTheCreateGroupEpochKeysCarryAPresenceRule(t *testing.T) {
	create := topLevelMessages(t)["CreateGroupRequest"]
	if create == nil {
		t.Fatal("message.proto declares no CreateGroupRequest")
	}
	deliveries := create.Fields().ByName("epoch_keys")
	if deliveries == nil {
		t.Fatal("CreateGroupRequest has no epoch_keys; ruling 33 puts one on it")
	}
	// the shape the rule is written against: singular, so GetEpochKeys() can answer nil
	// and "absent" is a state the server can name. On SubmitRequest the same rule would
	// be unstatable, which is why that carrier refuses on alignment instead.
	if deliveries.Cardinality() == protoreflect.Repeated {
		t.Error("CreateGroupRequest.epoch_keys is repeated; the presence rule is written for a " +
			"SINGULAR field, whose absence a server can tell from a zero value. If this becomes a " +
			"list it needs SubmitRequest's alignment rule instead, and this one stops meaning anything.")
	}
	if sub := deliveries.Message(); sub == nil || string(sub.Name()) != keyDeliveryMessage {
		t.Errorf("CreateGroupRequest.epoch_keys has type %v, want %s", sub, keyDeliveryMessage)
	}
	// the inline control for "this request's record is always a commit": the record the
	// delivery is for is a SINGULAR Record named initial_commit. If it were a list, the
	// required-presence rule would be the wrong rule.
	commit := create.Fields().ByName("initial_commit")
	if commit == nil || commit.Cardinality() == protoreflect.Repeated {
		t.Errorf("CreateGroupRequest.initial_commit is %v; the presence rule says this request carries "+
			"exactly one record and that it is always a commit, and that is why epoch_keys is "+
			"REQUIRED here and merely aligned on SubmitRequest", commit)
	}

	block := flatten(t, createGroupRequestSource(t), "AN ABSENT epoch_keys IS REASON_REJECTED")
	for _, clause := range []struct {
		what   string
		phrase string
	}{
		{"that the delivery is required", "PRESENCE: REQUIRED."},
		{"what an absent delivery means", "AN ABSENT epoch_keys IS REASON_REJECTED"},
		{"the hazard it shares with SubmitRequest", "an epoch the server would install without having been handed what opens it"},
		{"that absence is representable here and is not on the other carrier", "AND HERE ABSENCE IS REPRESENTABLE"},
		{"that a zero delivery is not an absence", "is two EMPTY KEYS and not an absence"},
	} {
		if !strings.Contains(block, clause.phrase) {
			t.Errorf("CreateGroupRequest's epoch_keys does not state %s. The phrase %q is gone. This "+
				"carrier had NO presence rule and NO gate until 2026-09-22, and the server that "+
				"enforces it is in another repository reading this file.", clause.what, clause.phrase)
		}
	}
}

// protoSource returns message.proto's text with line endings normalised.
//
// The .proto and not the .pb.go, because protoc-gen-go does not carry every source
// comment into the compiled descriptor this package links, and because the .proto is
// the artefact a second implementation reads. The file sits beside this test.
//
// LINE ENDINGS NORMALISED BEFORE ANY MATCH. .gitattributes pins *.proto to eol=lf
// precisely because core.autocrlf=true is set at system scope on the machines that
// build this tree, and this repository has already lost 84 source anchors to a
// checkout that wrote CRLF under a gate matching LF. A gate that depends on that pin
// holding is a gate with a second failure mode; this one does not.
func protoSource(t *testing.T) string {
	t.Helper()
	path := filepath.Join(".", "message.proto")
	bs, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("message.proto is unreadable at %s: %v", path, err)
	}
	return strings.ReplaceAll(string(bs), "\r\n", "\n")
}

// messageBlock slices message.proto from a message's declaration to the brace that
// closes it, and REFUSES AN ANCHOR IT DOES NOT FIND EXACTLY ONCE — a second
// occurrence means the anchor is also matching a comment somewhere, and a clause
// search over the wrong region is an anchor that has silently stopped anchoring.
func messageBlock(t *testing.T, name string) string {
	t.Helper()
	src := protoSource(t)
	anchor := "message " + name + " {"
	if n := strings.Count(src, anchor); n != 1 {
		t.Fatalf("message.proto contains %q %d times, want exactly 1; the slice below would be "+
			"reading an arbitrary one of them", anchor, n)
	}
	open := strings.Index(src, anchor)
	end := strings.Index(src[open:], "\n}")
	if end < 0 {
		t.Fatalf("message %s is not closed by a brace at column 0 in message.proto", name)
	}
	return src[open : open+end]
}

// flatten strips message.proto's comment prefixes and collapses runs of whitespace,
// so a clause is searched for as the SENTENCE it is rather than as the line wrapping
// it happens to have today.
//
// It WIDENS the old anchors rather than narrowing them: a deleted clause is still red
// and a clause that only moved across a line break no longer is. The previous form of
// this file matched one clause as "a commit\n    // with no entry", which a reflow
// changing nothing would have failed — and a gate that fires on formatting teaches
// its readers to edit the gate.
//
// Its own control is inside it: the flattened text must have lost the comment markers
// and got shorter, or the stripping did nothing and every phrase is being matched
// against the raw block by accident.
// `probe` is the per-call positive control and is required: a phrase that the RAW
// block splits across a line break and that the flattened block must carry whole. It
// makes the flattening load-bearing rather than decorative — without it a helper that
// silently returned its input would leave every clause below matching by luck.
func flatten(t *testing.T, block string, probe string) string {
	out := strings.Join(strings.Fields(strings.ReplaceAll(block, "//", " ")), " ")
	if strings.Contains(out, "//") {
		t.Fatalf("flatten left comment markers in place, so it is not stripping what it says it "+
			"strips: %q", out[:min(200, len(out))])
	}
	if len(out) >= len(block) {
		t.Fatalf("flatten returned %d octets from a %d-octet block; it removed nothing, so the clause "+
			"matches are running against the raw source and this helper is decoration",
			len(out), len(block))
	}
	if strings.Contains(block, probe) {
		t.Fatalf("the probe %q is already contiguous in the RAW block, so it does not show that "+
			"flattening did anything. Pick a phrase this file wraps across a line.", probe)
	}
	if !strings.Contains(out, probe) {
		t.Fatalf("the probe %q is in neither the raw block nor the flattened one, so flatten is not "+
			"joining the lines it claims to join and every clause below is being searched for in "+
			"text that does not read as sentences", probe)
	}
	return out
}

// submitRequestSource returns message.proto's SubmitRequest declaration.
func submitRequestSource(t *testing.T) string {
	t.Helper()
	block := messageBlock(t, "SubmitRequest")
	// the positive control for the read itself: the declaration line the rule is about
	// has to be in what was sliced out, or the phrases are being searched for in the
	// wrong region of the file
	if !strings.Contains(block, "repeated EpochKeyDelivery epoch_keys = 3;") {
		t.Fatalf("the SubmitRequest block read from message.proto does not contain the epoch_keys "+
			"declaration; the slice is wrong. It is %d octets and begins %q",
			len(block), block[:min(120, len(block))])
	}
	return block
}

// createGroupRequestSource returns message.proto's CreateGroupRequest declaration.
func createGroupRequestSource(t *testing.T) string {
	t.Helper()
	block := messageBlock(t, "CreateGroupRequest")
	if !strings.Contains(block, "EpochKeyDelivery epoch_keys = 4;") {
		t.Fatalf("the CreateGroupRequest block read from message.proto does not contain the epoch_keys "+
			"declaration; the slice is wrong. It is %d octets and begins %q",
			len(block), block[:min(120, len(block))])
	}
	return block
}

// controlFile is the POSITIVE CONTROL FOR THE WALK, BUILT, because message.proto cannot
// supply one: it declares no nested message and no map field, so over this file the
// descent is exercised by nothing and md.IsMapEntry() is false of everything. Two
// mechanisms tested against a file that cannot make either of them fire is an empty
// search reported as a clean bill, and this file's own header is the record of what an
// unmeasured narrowing costs.
//
// It assembles, with no .proto and no codegen:
//
//	message Outer {
//	    message Inner { bytes write_key = 1; }
//	    Inner inner = 1;
//	    map<uint64, Inner> bag = 2;
//	}
//
// `Inner` is nested and is NOT a map entry; `BagEntry` is the entry protoc would
// synthesise for `bag` and IS one. The SAME walkFrom and the SAME namesAKey run over it.
func controlFile(t *testing.T) protoreflect.FileDescriptor {
	t.Helper()
	optional := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
	repeated := descriptorpb.FieldDescriptorProto_LABEL_REPEATED
	bytesKind := descriptorpb.FieldDescriptorProto_TYPE_BYTES
	uint64Kind := descriptorpb.FieldDescriptorProto_TYPE_UINT64
	messageKind := descriptorpb.FieldDescriptorProto_TYPE_MESSAGE
	const inner = ".keydeliverygatecontrol.Outer.Inner"
	const entry = ".keydeliverygatecontrol.Outer.BagEntry"
	fd := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("keydelivery_gate_control.proto"),
		Package: proto.String("keydeliverygatecontrol"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("Outer"),
			NestedType: []*descriptorpb.DescriptorProto{
				{
					Name: proto.String("Inner"),
					Field: []*descriptorpb.FieldDescriptorProto{{
						Name: proto.String("write_key"), Number: proto.Int32(1),
						Label: &optional, Type: &bytesKind, JsonName: proto.String("writeKey"),
					}},
				},
				{
					Name:    proto.String("BagEntry"),
					Options: &descriptorpb.MessageOptions{MapEntry: proto.Bool(true)},
					Field: []*descriptorpb.FieldDescriptorProto{
						{
							Name: proto.String("key"), Number: proto.Int32(1),
							Label: &optional, Type: &uint64Kind, JsonName: proto.String("key"),
						},
						{
							Name: proto.String("value"), Number: proto.Int32(2),
							Label: &optional, Type: &messageKind, TypeName: proto.String(inner),
							JsonName: proto.String("value"),
						},
					},
				},
			},
			Field: []*descriptorpb.FieldDescriptorProto{
				{
					Name: proto.String("inner"), Number: proto.Int32(1),
					Label: &optional, Type: &messageKind, TypeName: proto.String(inner),
					JsonName: proto.String("inner"),
				},
				{
					Name: proto.String("bag"), Number: proto.Int32(2),
					Label: &repeated, Type: &messageKind, TypeName: proto.String(entry),
					JsonName: proto.String("bag"),
				},
			},
		}},
	}
	file, err := protodesc.NewFile(fd, nil)
	if err != nil {
		t.Fatalf("the control descriptor does not build, so there is no control: %v", err)
	}
	return file
}

// THE SCOPE OF THE KEY CHECKS, PRINTED, AND THE ONE NARROWING IN IT ASSERTED FROM BOTH
// ENDS.
//
// Until 2026-09-22 keyNamedFields, keyTypedFields and declaresAKeyField's caller all
// iterated topLevelMessages, and the only thing standing between a NESTED type and those
// three checks was one loop in servedAndSubmitted that excused any simple name ending in
// "Entry". Reproduced, protoc 35.1, inside `message FetchResponse {`:
//
//	message ShimEntry   { KeyBagEntry bag = 1; }
//	message KeyBagEntry { bytes write_key = 1; bytes read_key = 2; }
//	ShimEntry shim = 20;
//
//	-> ok github.com/urnetwork/connect/protocol 0.379s
//
// That is item 244's own defect again — the next epoch's write and read key, under those
// exact names, on the served fetch answer — with all four key gates green. ISOLATED IN
// THE SAME QUERY: renaming the two containers to Shim/KeyBag and changing nothing else
// reddens all four, so the "Entry" suffix at depth >= 2 was the whole of the escape.
//
// AND THE EXEMPTION EXCUSED NOTHING THAT EXISTS, which is why it was invisible. The
// counts it was narrowing over are printed below rather than recited. The repair is that
// the checks walk nested types directly and the exemption is md.IsMapEntry() — the
// descriptor's own answer, true of synthetic entries and of nothing else — with its
// complement asserted against the map fields that produce it.
func TestTheKeyCheckWalkDescendsAndSkipsOnlyMapEntries(t *testing.T) {
	all := allMessageTypes(t)
	nestedInFile, entriesInFile, suffixInFile := []string{}, []string{}, []string{}
	for _, full := range sortedKeys(all) {
		md := all[full]
		if !isTopLevel(md) {
			nestedInFile = append(nestedInFile, full)
		}
		if md.IsMapEntry() {
			entriesInFile = append(entriesInFile, full)
		}
		if strings.HasSuffix(string(md.Name()), "Entry") {
			suffixInFile = append(suffixInFile, full)
		}
	}
	t.Logf("message.proto declares %d message types at all depths: %d nested, %d map entries, "+
		"%d with a simple name ending in \"Entry\" (the exemption that stood here until 2026-09-22)",
		len(all), len(nestedInFile), len(entriesInFile), len(suffixInFile))
	t.Logf("nested (%d): %v", len(nestedInFile), nestedInFile)
	t.Logf("map entries (%d): %v", len(entriesInFile), entriesInFile)
	t.Logf("simple name ends in \"Entry\" (%d): %v", len(suffixInFile), suffixInFile)
	if len(all) != len(topLevelMessages(t))+len(nestedInFile) {
		t.Fatalf("the depth walk found %d types, %d of them nested, against %d top-level; the three "+
			"do not add up, so allMessageTypes and topLevelMessages are not reading the same file",
			len(all), len(nestedInFile), len(topLevelMessages(t)))
	}

	// THE SKIP, FROM BOTH ENDS. Every type the walk skipped is the synthetic entry of a
	// map field the same walk found, and every map field the walk found has its entry in
	// the skipped set. Today both sides are EMPTY, and that is printed rather than left
	// implicit: an exemption whose complement nobody enumerates is exactly the shape the
	// "Entry" suffix had for as long as it stood.
	_, _, servedSet := servedAndSubmitted(t)
	w := walkOfNames(t, servedSet)
	t.Logf("the served walk checks %d types (%d top-level, %d nested) and skips %d synthetic map "+
		"entries, produced by %d map fields: %v",
		len(w.checked), countTopLevel(w.checked), len(w.checked)-countTopLevel(w.checked),
		len(w.mapEntries), len(w.mapFields), sortedKeys(w.mapFields))
	byEntry := map[string]string{}
	for field, produced := range w.mapFields {
		byEntry[produced] = field
	}
	for skipped := range w.mapEntries {
		if _, produced := byEntry[skipped]; !produced {
			t.Errorf("%s was skipped as a map entry and no map field in the same walk produces it, "+
				"so the skip is excusing a type nobody asked it to excuse", skipped)
		}
	}
	for produced, field := range byEntry {
		if _, skipped := w.mapEntries[produced]; !skipped {
			t.Errorf("%s is the synthetic entry of the map field %s and the walk did not skip it, so "+
				"the key checks are about to report protoc's own `key` field as key material",
				produced, field)
		}
	}

	// THE POSITIVE CONTROL, and it is the whole reason this test is not a pair of zeroes.
	// The same walkFrom and the same keyNamedFields, over a descriptor that HAS a nested
	// message and HAS a map field.
	outer := controlFile(t).Messages().Get(0)
	cw := walkFrom([]protoreflect.MessageDescriptor{outer})
	const (
		controlOuter = "keydeliverygatecontrol.Outer"
		controlInner = "keydeliverygatecontrol.Outer.Inner"
		controlEntry = "keydeliverygatecontrol.Outer.BagEntry"
		controlField = "keydeliverygatecontrol.Outer.bag"
		controlKey   = "keydeliverygatecontrol.Outer.Inner.write_key"
	)
	t.Logf("CONTROL — the built walk checks %v and skips %v",
		sortedKeys(cw.checked), sortedKeys(cw.mapEntries))
	for _, want := range []string{controlOuter, controlInner} {
		if _, ok := cw.checked[want]; !ok {
			t.Errorf("control: the walk does not check %s, so it is not descending and the served "+
				"walk above covers only what it happens to find at the top level", want)
		}
	}
	if _, ok := cw.checked[controlEntry]; ok {
		t.Errorf("control: %s is a synthetic map entry and the walk checked it; every entry declares "+
			"a field literally named `key`, so this would make every map field a finding about protoc",
			controlEntry)
	}
	if _, ok := cw.mapEntries[controlEntry]; !ok {
		t.Errorf("control: %s was not recognised as a map entry, so md.IsMapEntry() answers false for "+
			"a real one and the skip above is a predicate that fires on nothing", controlEntry)
	}
	if got := cw.mapFields[controlField]; got != controlEntry {
		t.Errorf("control: the walk records the map field %s as producing %q, want %s; the both-ends "+
			"assertion above compares against that map", controlField, got, controlEntry)
	}
	if nested := outer.Messages().ByName("Inner"); nested == nil || nested.IsMapEntry() {
		t.Error("control: the nested message Inner reports IsMapEntry() true, so the predicate does " +
			"not separate a nested message from a synthetic entry and the skip is not a narrowing " +
			"but a hole")
	}

	// AND END TO END: namesAKey, run over the built walk by the same helper the served
	// side uses, finds the key on the NESTED type. That is the escape of 2026-09-22
	// caught by the repaired mechanism, in-process and with no proto to regenerate.
	flagged, _ := keyNamedFields(t, cw)
	t.Logf("CONTROL — the key-name check over the built walk flags %v", sortedKeys(flagged))
	if _, found := flagged[controlKey]; !found {
		t.Errorf("control: keyNamedFields did not flag %s. That field is a `write_key` on a type "+
			"nested inside the message the walk was rooted at, which is exactly what rode through "+
			"this gate until 2026-09-22; if it is not found here, the repair is not in the code path "+
			"the served side uses.", controlKey)
	}
}
