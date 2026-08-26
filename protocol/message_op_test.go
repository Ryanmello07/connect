package protocol_test

// The op-byte gate.
//
// Spec A §5.7 and Spec B §4.3.8 define the URmessage request authenticator as
//
//	req_auth = MAC(read_key[e], "URmessage/v1/req" ‖ LP(server_nonce)
//	                            ‖ u8(op) ‖ LP(canonical_request_bytes))
//
// with "op = the field number of the selected `oneof body` arm in
// MessageServerRequest, as a u8".
//
// That makes the protobuf field numbers of MessageServerRequest.body protocol
// constants inside a MAC rather than an implementation detail. A transposed arm
// number compiles, parses, and produces a message that looks entirely correct; it
// fails only as a MAC mismatch, which Spec B §4.5 answers with the deliberately
// non-specific REASON_REJECTED, on one operation, for one implementation. These
// tests exist to turn that into a test failure instead.
//
// Every assertion below enumerates the arms FROM THE COMPILED DESCRIPTOR, never
// from a hand-written list of arms. The hand-written part is only the mapping from
// an arm's name to the two facts the spec states about it — its op byte and whether
// it carries req_auth — and TestRequestArmSetMatchesSpecA57 asserts that mapping's
// key set EQUALS the descriptor's arm set. So a new arm added to message.proto
// fails here until somebody decides its authentication status, which is exactly the
// decision that must not be made by default.

import (
	"fmt"
	"sort"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/connect/protocol"
)

// armAuth is what Spec A §5.7 / Spec B §4.3.8 say about one oneof arm of
// MessageServerRequest.body.
type armAuth struct {
	// op is the arm's field number, which IS the op byte. Held as an int rather
	// than a uint8 so that an out-of-range value is expressible here and is caught
	// by TestRequestArmOpBytesFitInAU8 rather than by a compile error, which would
	// hide the defect instead of naming it.
	op int
	// requiresReqAuth is true for the five arms Spec A §5.7 lists under
	// "Required on", false for the ten it lists under "NOT used on".
	requiresReqAuth bool
}

// specA57 transcribes Spec A §5.7 in full: both the arms that require req_auth and
// the arms that are exempt, each with the op byte Spec B §4.3.8 gives it.
//
//	Required on, with their op bytes:  FetchRequest (13), SubscribeRequest (14),
//	                                   GroupStatusRequest (16), BlobGrantRequest (17),
//	                                   WrapFetchRequest (19).
//
//	NOT used on: HelloRequest (10), CreateGroupRequest (11), SubmitRequest (12),
//	             UnsubscribeRequest (15), RecoveryFetchRequest (18),
//	             and the five rendezvous arms (20-24), which name no group and carry
//	             their own Ed25519 authenticator instead (Spec B §4.3.11).
//
// This map is a decision table, not an inventory: its KEY SET is asserted equal to
// the descriptor's arm set, so it cannot silently fall behind message.proto.
var specA57 = map[string]armAuth{
	"hello":               {op: 10, requiresReqAuth: false},
	"create_group":        {op: 11, requiresReqAuth: false},
	"submit":              {op: 12, requiresReqAuth: false},
	"fetch":               {op: 13, requiresReqAuth: true},
	"subscribe":           {op: 14, requiresReqAuth: true},
	"unsubscribe":         {op: 15, requiresReqAuth: false},
	"group_status":        {op: 16, requiresReqAuth: true},
	"blob_grant":          {op: 17, requiresReqAuth: true},
	"recovery_fetch":      {op: 18, requiresReqAuth: false},
	"wrap_fetch":          {op: 19, requiresReqAuth: true},
	"rendezvous_register": {op: 20, requiresReqAuth: false},
	"rendezvous_open":     {op: 21, requiresReqAuth: false},
	"rendezvous_deposit":  {op: 22, requiresReqAuth: false},
	"rendezvous_collect":  {op: 23, requiresReqAuth: false},
	"rendezvous_retire":   {op: 24, requiresReqAuth: false},
}

// spec438OpBytes is a SECOND, INDEPENDENT transcription of the same numbers, taken
// from the prose of Spec B §4.3.8 rather than from the proto block of §4.3. §4.3.8
// names each op byte inline — "FetchRequest (13)", "SubscribeRequest (14)",
// "GroupStatusRequest (16)", "BlobGrantRequest (17)", "WrapFetchRequest (19)" and,
// in its exemption list, "HelloRequest (10)", "CreateGroupRequest (11)",
// "SubmitRequest (12)", "UnsubscribeRequest (15)", "RecoveryFetchRequest (18)" —
// and that redundancy is the cross-check the spec offers. Keeping it separate from
// specA57 means a coordinated edit has to get the same number wrong in three places
// (the proto, specA57, and here) before it can ship.
var spec438OpBytes = map[string]int{
	"fetch":          13,
	"subscribe":      14,
	"group_status":   16,
	"blob_grant":     17,
	"wrap_fetch":     19,
	"hello":          10,
	"create_group":   11,
	"submit":         12,
	"unsubscribe":    15,
	"recovery_fetch": 18,
}

// specA57RequiredOps is the set of op BYTES §5.7 lists under "Required on",
// transcribed as numbers rather than as names, so that renaming an arm cannot
// quietly move a number in or out of the authenticated set.
var specA57RequiredOps = []int{13, 14, 16, 17, 19}

func bodyOneof(t *testing.T, m protoreflect.ProtoMessage) protoreflect.FieldDescriptors {
	t.Helper()
	d := m.ProtoReflect().Descriptor()
	od := d.Oneofs().ByName("body")
	if od == nil {
		t.Fatalf("%s has no `oneof body`; every URmessage envelope is defined around one (Spec B §4.3)", d.FullName())
	}
	return od.Fields()
}

func armNames(fields protoreflect.FieldDescriptors) []string {
	names := make([]string, 0, fields.Len())
	for i := 0; i < fields.Len(); i++ {
		names = append(names, string(fields.Get(i).Name()))
	}
	sort.Strings(names)
	return names
}

func armNumbers(fields protoreflect.FieldDescriptors) map[string]int {
	byName := make(map[string]int, fields.Len())
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		byName[string(f.Name())] = int(f.Number())
	}
	return byName
}

// TestRequestArmSetMatchesSpecA57 is the equality that makes the rest of this file
// mean something. A test that only checked the arms it already knew about would
// pass forever, however many arms were added to message.proto afterwards.
func TestRequestArmSetMatchesSpecA57(t *testing.T) {
	fields := bodyOneof(t, (*protocol.MessageServerRequest)(nil))
	got := armNames(fields)

	want := make([]string, 0, len(specA57))
	for name := range specA57 {
		want = append(want, name)
	}
	sort.Strings(want)

	inDescriptor := make(map[string]bool, len(got))
	for _, n := range got {
		inDescriptor[n] = true
	}
	for _, n := range want {
		if !inDescriptor[n] {
			t.Errorf("specA57 names arm %q, but MessageServerRequest.body has no such arm: "+
				"the decision table has fallen out of step with message.proto", n)
		}
	}
	inSpec := make(map[string]bool, len(want))
	for _, n := range want {
		inSpec[n] = true
	}
	for _, n := range got {
		if !inSpec[n] {
			t.Errorf("MessageServerRequest.body has arm %q, which Spec A §5.7 does not classify. "+
				"Adding an arm is a decision about whether it carries req_auth (Spec B §4.3.8); "+
				"record that decision in specA57 rather than defaulting it.", n)
		}
	}
	if len(got) != len(want) {
		t.Errorf("arm count: descriptor has %d, specA57 has %d", len(got), len(want))
	}
}

// TestRequestArmNumberIsItsOpByte is the assertion the whole file exists for.
func TestRequestArmNumberIsItsOpByte(t *testing.T) {
	fields := bodyOneof(t, (*protocol.MessageServerRequest)(nil))
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		name := string(f.Name())
		spec, ok := specA57[name]
		if !ok {
			// Reported by TestRequestArmSetMatchesSpecA57; nothing to compare against.
			continue
		}
		if int(f.Number()) != spec.op {
			t.Errorf("arm %q has field number %d but Spec A §5.7 / Spec B §4.3.8 give it op byte %d. "+
				"The field number IS the op byte: it is hashed into req_auth as u8(op), so this "+
				"mismatch is a silent cross-implementation MAC failure answered with REASON_REJECTED.",
				name, f.Number(), spec.op)
		}
	}
}

// TestRequestOpBytesAgreeWithSpecSection438 checks the transcription of §4.3 against
// the independent transcription of §4.3.8, and both against the descriptor.
func TestRequestOpBytesAgreeWithSpecSection438(t *testing.T) {
	fields := bodyOneof(t, (*protocol.MessageServerRequest)(nil))
	numbers := armNumbers(fields)

	for name, op := range spec438OpBytes {
		got, ok := numbers[name]
		if !ok {
			t.Errorf("Spec B §4.3.8 names op byte %d for arm %q, which MessageServerRequest.body does not have", op, name)
			continue
		}
		if got != op {
			t.Errorf("arm %q: descriptor field number %d, Spec B §4.3.8 prose op byte %d", name, got, op)
		}
		if spec, ok := specA57[name]; ok && spec.op != op {
			t.Errorf("arm %q: specA57 op %d disagrees with the §4.3.8 prose op %d "+
				"(two transcriptions of the same protocol constant must not differ)", name, spec.op, op)
		}
	}
}

// TestRequestArmOpBytesFitInAU8 derives the u8 ceiling from the descriptor. An arm
// numbered above 255 cannot be expressed as u8(op) at all, so it is not a "large
// number" but a request that cannot be authenticated. Asserting it here means such
// an arm fails at build time rather than at the first MAC verification.
func TestRequestArmOpBytesFitInAU8(t *testing.T) {
	fields := bodyOneof(t, (*protocol.MessageServerRequest)(nil))
	if fields.Len() == 0 {
		t.Fatal("MessageServerRequest.body has no arms")
	}
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		n := int(f.Number())
		if n < 1 || n > 255 {
			t.Errorf("arm %q has field number %d, which does not fit the u8(op) of the req_auth "+
				"preimage (Spec A §5.7). An arm outside 1..255 has no representable op byte and "+
				"could never be authenticated; renumber it inside the range.", f.Name(), n)
		}
	}
	// The table must not be able to promise an op byte that the wire cannot carry
	// either, which is why armAuth.op is an int.
	for name, spec := range specA57 {
		if spec.op < 1 || spec.op > 255 {
			t.Errorf("specA57 gives arm %q op byte %d, outside the u8 range of Spec A §5.7", name, spec.op)
		}
	}
}

// TestReqAuthArmsCarryAReqAuthField derives, from each arm's own message
// descriptor, whether it actually has somewhere to put a req_auth, and checks that
// against the decision table. An arm classified as authenticated but with no
// req_auth field could never be authenticated; an arm classified as exempt but
// carrying one invites a server to verify something no client computes.
func TestReqAuthArmsCarryAReqAuthField(t *testing.T) {
	fields := bodyOneof(t, (*protocol.MessageServerRequest)(nil))
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		name := string(f.Name())
		spec, ok := specA57[name]
		if !ok {
			continue
		}
		md := f.Message()
		if md == nil {
			t.Errorf("arm %q is not a message type; every oneof arm of MessageServerRequest.body is", name)
			continue
		}
		hasReqAuth := md.Fields().ByName("req_auth") != nil
		if hasReqAuth != spec.requiresReqAuth {
			t.Errorf("arm %q: Spec A §5.7 says requiresReqAuth=%v, but %s %s a req_auth field",
				name, spec.requiresReqAuth, md.FullName(),
				map[bool]string{true: "has", false: "has no"}[hasReqAuth])
		}
		// §4.3.8: the read key is selected by read_epoch, which travels inside
		// canonical_request_bytes. An authenticated request without it would force
		// the server to trial keys, which §4.3.8 explicitly forbids.
		hasReadEpoch := md.Fields().ByName("read_epoch") != nil
		if hasReadEpoch != spec.requiresReqAuth {
			t.Errorf("arm %q: requiresReqAuth=%v, but %s %s a read_epoch field. Spec B §4.3.8 "+
				"requires the epoch to be named inside the MAC so the server never trials keys.",
				name, spec.requiresReqAuth, md.FullName(),
				map[bool]string{true: "has", false: "has no"}[hasReadEpoch])
		}
	}
}

// TestRequiredReqAuthOpsAreExactlySpecA57 checks the required set as a set of
// NUMBERS, so that renaming an arm cannot move a number in or out of the
// authenticated set unnoticed.
func TestRequiredReqAuthOpsAreExactlySpecA57(t *testing.T) {
	fields := bodyOneof(t, (*protocol.MessageServerRequest)(nil))
	var got []int
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		if spec, ok := specA57[string(f.Name())]; ok && spec.requiresReqAuth {
			got = append(got, int(f.Number()))
		}
	}
	sort.Ints(got)
	want := append([]int(nil), specA57RequiredOps...)
	sort.Ints(want)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("op bytes requiring req_auth: got %v, Spec A §5.7 requires exactly %v "+
			"(Fetch 13, Subscribe 14, GroupStatus 16, BlobGrant 17, WrapFetch 19)", got, want)
	}
}

// TestResponseArmNumbersMatchRequestArms pins the request/response symmetry, and
// pins the one deliberate asymmetry.
func TestResponseArmNumbersMatchRequestArms(t *testing.T) {
	reqNumbers := armNumbers(bodyOneof(t, (*protocol.MessageServerRequest)(nil)))
	respNumbers := armNumbers(bodyOneof(t, (*protocol.MessageServerResponse)(nil)))

	for name, respNum := range respNumbers {
		reqNum, ok := reqNumbers[name]
		if !ok {
			t.Errorf("MessageServerResponse.body has arm %q with no matching request arm; "+
				"response arms exist to answer request arms and share their numbers", name)
			continue
		}
		if reqNum != respNum {
			t.Errorf("arm %q: request number %d, response number %d. They must agree — the request "+
				"number is the op byte inside req_auth (Spec A §5.7), and a response arm that "+
				"disagrees makes the §4.3.8 cross-check unreadable.", name, reqNum, respNum)
		}
	}

	// Derive the arms that exist only on the request side, rather than listing them.
	var onlyRequest []string
	for name := range reqNumbers {
		if _, ok := respNumbers[name]; !ok {
			onlyRequest = append(onlyRequest, name)
		}
	}
	sort.Strings(onlyRequest)
	want := []string{"unsubscribe"}
	if fmt.Sprint(onlyRequest) != fmt.Sprint(want) {
		t.Errorf("request arms with no response arm: got %v, want %v. Exactly one arm is answered "+
			"by reason alone: UnsubscribeRequest, which Spec B §4.3.8 records as reading no group "+
			"state and cancelling only the caller's own subscription.", onlyRequest, want)
	}
}

// TestResponseHasNoArm15 asserts the gap at 15 is deliberate rather than tolerated.
//
// MessageServerResponse has no arm 15 because there is no UnsubscribeResponse. That
// is not an omission to tidy up. Number 15 belongs to `unsubscribe` on the request
// side, where it is also an op byte; handing it to some other response arm would
// break the invariant that a number means the same operation in both envelopes,
// and would make the §4.3.8 op-byte cross-check read differently depending on which
// envelope you looked at. The number stays reserved by staying empty.
func TestResponseHasNoArm15(t *testing.T) {
	fields := bodyOneof(t, (*protocol.MessageServerResponse)(nil))
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		if f.Number() == 15 {
			t.Errorf("MessageServerResponse.body gained arm %q at number 15. 15 is unsubscribe's "+
				"op byte on the request side and is deliberately unused here (Spec B §4.3): there "+
				"is no UnsubscribeResponse, and reusing the number for anything else breaks the "+
				"one-number-one-operation invariant across the two envelopes.", f.Name())
		}
	}
	// And the reason it is absent is that nothing answers unsubscribe with a body.
	if fields.ByName("unsubscribe") != nil {
		t.Error("MessageServerResponse.body has an `unsubscribe` arm; Spec B §4.3 defines no UnsubscribeResponse")
	}
}

// TestArmNumbersAreUniqueWithinEachEnvelope derives uniqueness from the descriptor.
// protoc already rejects a duplicate field number inside one message, so this
// cannot fail while the file compiles; it is kept as a tripwire for the day the
// descriptors stop coming from protoc (a hand-built descriptor, a dynamicpb
// schema, a merge that resolves a conflict by hand).
func TestArmNumbersAreUniqueWithinEachEnvelope(t *testing.T) {
	for _, env := range []struct {
		name string
		msg  protoreflect.ProtoMessage
	}{
		{"MessageServerRequest", (*protocol.MessageServerRequest)(nil)},
		{"MessageServerResponse", (*protocol.MessageServerResponse)(nil)},
		{"MessageServerPush", (*protocol.MessageServerPush)(nil)},
	} {
		fields := bodyOneof(t, env.msg)
		seen := make(map[int]string, fields.Len())
		for i := 0; i < fields.Len(); i++ {
			f := fields.Get(i)
			n := int(f.Number())
			if prev, dup := seen[n]; dup {
				t.Errorf("%s.body: arms %q and %q share number %d", env.name, prev, f.Name(), n)
			}
			seen[n] = string(f.Name())
		}
	}
}

// TestArmNumberMeansOneOperationAcrossEnvelopes is the falsifiable form of
// uniqueness: across MessageServerRequest and MessageServerResponse together, a
// number must name exactly one operation. A swap of two response arms' numbers, or
// a response arm reusing a request-only number, shows up here as one number
// claimed by two different arm names.
func TestArmNumberMeansOneOperationAcrossEnvelopes(t *testing.T) {
	owner := make(map[int]string)
	for _, env := range []struct {
		name string
		msg  protoreflect.ProtoMessage
	}{
		{"MessageServerRequest", (*protocol.MessageServerRequest)(nil)},
		{"MessageServerResponse", (*protocol.MessageServerResponse)(nil)},
	} {
		fields := bodyOneof(t, env.msg)
		for i := 0; i < fields.Len(); i++ {
			f := fields.Get(i)
			n := int(f.Number())
			name := string(f.Name())
			if prev, ok := owner[n]; ok && prev != name {
				t.Errorf("number %d names arm %q in one envelope and %q in the other; "+
					"a number is an operation, and Spec A §5.7 hashes it as u8(op)", n, prev, name)
			}
			owner[n] = name
		}
	}
}

// TestReqAuthAndReadEpochUseTheirReservedFieldNumbers walks every message in
// message.proto, not a list of the ones that happen to have these fields today.
// Spec B §4.3 puts read_epoch at 14 and the request authenticator at 15 in every
// message that has one, including the five rendezvous authenticators of §4.3.11,
// which sit at 15 under their own names. Because req_auth is zeroed inside
// canonical_request_bytes, its field number decides where the hole in the canonical
// bytes falls, so it is as much a protocol constant as the op byte is.
func TestReqAuthAndReadEpochUseTheirReservedFieldNumbers(t *testing.T) {
	fd := (*protocol.MessageServerRequest)(nil).ProtoReflect().Descriptor().ParentFile()
	authFieldNames := map[string]bool{
		"req_auth":      true,
		"register_auth": true,
		"open_auth":     true,
		"deposit_auth":  true,
		"collect_auth":  true,
		"retire_auth":   true,
	}
	msgs := fd.Messages()
	checked := 0
	for i := 0; i < msgs.Len(); i++ {
		md := msgs.Get(i)
		fields := md.Fields()
		for j := 0; j < fields.Len(); j++ {
			f := fields.Get(j)
			name := string(f.Name())
			if authFieldNames[name] {
				checked++
				if f.Number() != 15 {
					t.Errorf("%s.%s is field %d; Spec B §4.3 reserves 15 for the request "+
						"authenticator, and req_auth's number decides where the zeroed hole "+
						"falls inside canonical_request_bytes (Spec A §5.7)", md.FullName(), name, f.Number())
				}
			}
			if name == "read_epoch" {
				checked++
				if f.Number() != 14 {
					t.Errorf("%s.read_epoch is field %d; Spec B §4.3 reserves 14 for it", md.FullName(), f.Number())
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("walked message.proto and found no req_auth or read_epoch field at all; " +
			"the walk is looking at the wrong file descriptor")
	}
}
