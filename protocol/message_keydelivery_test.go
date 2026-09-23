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
// This file is the gate that keeps that true. Step 5 of the removal track, or any
// later step, that puts a key back on a served type fails here by name.
//
// EVERY SET BELOW IS DERIVED FROM THE COMPILED DESCRIPTOR, and the partition each
// derivation induces is PRINTED — what a narrowing removed is the thing a narrowed
// gate stops seeing, and an enumeration whose complement nobody looks at is an empty
// search that passes silently.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

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

// closureFrom returns every message type reachable from the arms of these envelopes,
// the arm types included and the envelopes themselves excluded. Reachability is what
// makes this a derived class: nesting a new type inside a served message pulls it in
// without anybody editing this file.
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
		od := envelope.Oneofs().ByName("body")
		if od == nil {
			continue
		}
		arms := od.Fields()
		for i := 0; i < arms.Len(); i++ {
			if sub := arms.Get(i).Message(); sub != nil {
				visit(sub)
			}
		}
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

// THE RULING 33 GATE: NO SERVER→CLIENT MESSAGE TRANSITIVELY CARRIES AN EpochKeyDelivery.
//
// The set is the transitive closure of the arms of every server→client envelope, so a
// key delivery nested three types deep inside a FetchResponse fails here exactly as
// one nested directly on it does.
//
// The partition is printed in full — served only, submitted only, both, neither —
// because that is the only way to see that the closure reached anything. A gate that
// searched an empty set for EpochKeyDelivery would pass, and would go on passing for
// as long as it took somebody to put the keys back.
func TestNoServerToClientMessageCarriesTheEpochKeys(t *testing.T) {
	clientToServer, serverToClient := envelopeDirections(t)
	served := closureFrom(serverToClient)
	submitted := closureFrom(clientToServer)

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

	if len(served) == 0 {
		t.Fatal("the server→client closure is empty, so this gate is a search over nothing")
	}
	// the inline positive control, in the same query: Record IS in the served closure,
	// which is the fact ruling 33 was taken on. If this fails, the closure is not
	// reaching the served records either and the assertion below means nothing.
	if !served[recordMessage] {
		t.Fatalf("%s is not in the server→client closure, so the walk is not reaching the served "+
			"records and the refusal below is vacuous", recordMessage)
	}
	if served[keyDeliveryMessage] {
		t.Errorf("%s is reachable from a server→client envelope. Ruling 33: the epoch keys travel on "+
			"the REQUEST messages and never on anything the server hands back — a served key field is "+
			"item 244 re-opened, once for every serve path that forgets to clear it.", keyDeliveryMessage)
	}
	if !submitted[keyDeliveryMessage] {
		t.Errorf("%s is not reachable from a client→server envelope either, so it is now on no path at "+
			"all and the keys have nowhere to ride", keyDeliveryMessage)
	}
	if !submittedOnly[keyDeliveryMessage] {
		t.Errorf("%s is not in the submitted-only partition; it is in %v", keyDeliveryMessage,
			map[string]bool{"served only": servedOnly[keyDeliveryMessage], "both": both[keyDeliveryMessage],
				"neither": neither[keyDeliveryMessage]})
	}
}

// carriersOf returns the top-level messages with a field whose type is this message,
// with the field name each one carries it under.
func carriersOf(t *testing.T, typeName string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	all := topLevelMessages(t)
	for _, name := range sortedKeys(all) {
		md := all[name]
		fields := md.Fields()
		for i := 0; i < fields.Len(); i++ {
			f := fields.Get(i)
			if sub := f.Message(); sub != nil && string(sub.Name()) == typeName {
				out[name] = append(out[name], string(f.Name()))
			}
		}
	}
	return out
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

	wantDelivery := map[string]string{
		"SubmitRequest":      "epoch_keys",
		"CreateGroupRequest": "epoch_keys",
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
	_, serverToClient := envelopeDirections(t)
	served := closureFrom(serverToClient)
	servedFields, submittedFields := 0, 0
	for name, fields := range records {
		if served[name] {
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
// for a record that is not a commit. SubmitResponse.results, the pattern this follows,
// states the alignment and leaves the length implicit; this one states the length too,
// because a short results list loses an answer the client can see is missing while a
// short epoch_keys list silently re-aims every later entry at the wrong record, and
// what it re-aims is a key. A change that drops either clause reddens this by name
// rather than shipping an under-specified list.
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

	block := submitRequestSource(t)
	for _, clause := range []struct {
		what   string
		phrase string
	}{
		{"the alignment", "POSITIONALLY ALIGNED"},
		{"the field it aligns with", "`records`"},
		{"the length rule", "EMPTY, OR EXACTLY AS LONG AS `records`"},
		{"what an entry against a non-commit means", "is_commit = 0 IS REASON_REJECTED"},
		{"what a commit with no entry means", "a commit\n    // with no entry"},
	} {
		if !strings.Contains(block, clause.phrase) {
			t.Errorf("SubmitRequest's declaration does not state %s. The phrase %q is gone, and this "+
				"rule lives nowhere else: no descriptor can carry it, and the server that enforces it "+
				"is in another repository reading this file.", clause.what, clause.phrase)
		}
	}
}

// submitRequestSource returns message.proto's text from the SubmitRequest declaration
// to the brace that closes it.
//
// It reads the .proto and not the .pb.go because protoc-gen-go does not carry source
// comments into the compiled descriptor this package links, and because the .proto is
// the artefact a second implementation reads. The file sits beside this test.
func submitRequestSource(t *testing.T) string {
	t.Helper()
	path := filepath.Join(".", "message.proto")
	bs, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("message.proto is unreadable at %s: %v", path, err)
	}
	// LINE ENDINGS NORMALISED BEFORE ANY MATCH. .gitattributes pins *.proto to eol=lf
	// precisely because core.autocrlf=true is set at system scope on the machines that
	// build this tree, and this repository has already lost 84 source anchors to a
	// checkout that wrote CRLF under a gate matching LF. A gate that depends on that
	// pin holding is a gate with a second failure mode; this one does not.
	src := strings.ReplaceAll(string(bs), "\r\n", "\n")
	open := strings.Index(src, "message SubmitRequest {")
	if open < 0 {
		t.Fatal("message.proto has no `message SubmitRequest {`; this test is reading the wrong file")
	}
	close := strings.Index(src[open:], "\n}")
	if close < 0 {
		t.Fatal("message SubmitRequest is not closed in message.proto")
	}
	block := src[open : open+close]
	// the positive control for the read itself: the declaration line the rule is about
	// has to be in what was sliced out, or the phrases below are being searched for in
	// the wrong region of the file
	if !strings.Contains(block, "repeated EpochKeyDelivery epoch_keys = 3;") {
		t.Fatalf("the SubmitRequest block read from message.proto does not contain the epoch_keys "+
			"declaration; the slice is wrong. It is %d octets and begins %q", len(block), block[:min(120, len(block))])
	}
	return block
}
