package mls

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"maps"
	"math/rand"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// the file whose refusals the derived sweep at the bottom of this file reads. A CONSTANT and not
// a base name match, for the reason the hkdf confinement writes down: a base name excuses a
// group_policy.go in any subdirectory, and this one is the path the package scan collects.
const groupPolicySourceFile = "group_policy.go"

func testPolicy(t *testing.T, owner *testMember, admin *testMember, member *testMember) *GroupPolicyExtension {
	t.Helper()
	policy := &GroupPolicyExtension{
		Roles: []RoleEntry{
			{MemberId: owner.IdentityPub, Role: RoleOwner},
			{MemberId: admin.IdentityPub, Role: RoleAdmin},
			{MemberId: member.IdentityPub, Role: RoleMember},
		},
		RetentionPolicy:     RetentionPolicy{DurableMs: 0, MediaMs: 2592000000},
		DisappearingBuckets: []uint8{0},
		ServerId:            []byte("urmessage-v1-server"),
	}
	if err := policy.Canonicalize(); err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	return policy
}

func TestGroupPolicyRoundTrip(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	admin := testIdentity(t, crypto, "admin")
	member := testIdentity(t, crypto, "member")

	policy := testPolicy(t, owner, admin, member)
	encoded, err := policy.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if encoded.ExtensionType != ExtensionTypeUrmessageGroupPolicy {
		t.Fatalf("ExtensionType = %#x, want %#x", encoded.ExtensionType, ExtensionTypeUrmessageGroupPolicy)
	}
	parsed, err := ParseGroupPolicyExtension(encoded.ExtensionData)
	if err != nil {
		t.Fatalf("ParseGroupPolicyExtension: %v", err)
	}
	reencoded, err := parsed.Encode()
	if err != nil {
		t.Fatalf("re-Encode: %v", err)
	}
	if !bytes.Equal(reencoded.ExtensionData, encoded.ExtensionData) {
		t.Fatal("re-encode is not byte identical")
	}
	if role, ok := parsed.RoleOf(admin.IdentityPub); !ok || role != RoleAdmin {
		t.Fatalf("RoleOf(admin) = %v %v, want admin true", role, ok)
	}
	if parsed.AdminCount() != 1 {
		t.Fatalf("AdminCount = %d, want 1", parsed.AdminCount())
	}
	ownerId, ok := parsed.OwnerId()
	if !ok || !bytes.Equal(ownerId, owner.IdentityPub) {
		t.Fatal("OwnerId did not return the owner")
	}
}

// TestGroupPolicyRoundTripCarriesEveryFieldAndNotOnlyTheRoles is what the plan's round trip cannot
// say on its own.
//
// A codec that DROPPED the retention pair, the buckets and the server id on write and defaulted
// them on read round trips perfectly: the encode of the decode of the encode is byte identical,
// because all three encodes wrote the same nothing. So the decoded VALUE is compared field by
// field against what went in, which is the assertion a dropped field fails.
func TestGroupPolicyRoundTripCarriesEveryFieldAndNotOnlyTheRoles(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	admin := testIdentity(t, crypto, "admin")
	member := testIdentity(t, crypto, "member")

	policy := testPolicy(t, owner, admin, member)
	policy.RetentionPolicy = RetentionPolicy{DurableMs: 604800000, MediaMs: 2592000000}
	policy.DisappearingBuckets = []uint8{0, 3, 255}
	encoded, err := policy.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	parsed, err := ParseGroupPolicyExtension(encoded.ExtensionData)
	if err != nil {
		t.Fatalf("ParseGroupPolicyExtension: %v", err)
	}
	if parsed.RetentionPolicy != policy.RetentionPolicy {
		t.Errorf("RetentionPolicy = %+v, want %+v; a codec that drops this pair and defaults it round trips perfectly",
			parsed.RetentionPolicy, policy.RetentionPolicy)
	}
	if !slices.Equal(parsed.DisappearingBuckets, policy.DisappearingBuckets) {
		t.Errorf("DisappearingBuckets = %v, want %v", parsed.DisappearingBuckets, policy.DisappearingBuckets)
	}
	if !bytes.Equal(parsed.ServerId, policy.ServerId) {
		t.Errorf("ServerId = %q, want %q", parsed.ServerId, policy.ServerId)
	}
	if len(parsed.Roles) != len(policy.Roles) {
		t.Fatalf("Roles = %d entries, want %d", len(parsed.Roles), len(policy.Roles))
	}
	for i := range policy.Roles {
		if !bytes.Equal(parsed.Roles[i].MemberId, policy.Roles[i].MemberId) ||
			parsed.Roles[i].Role != policy.Roles[i].Role {
			t.Errorf("Roles[%d] = %v/%v, want %v/%v", i,
				parsed.Roles[i].MemberId, parsed.Roles[i].Role,
				policy.Roles[i].MemberId, policy.Roles[i].Role)
		}
	}
}

// TestGroupPolicyEncodesAsBytesAssembledOutsideTheEncoder holds the wire format against a run
// written out by hand rather than against the encoder's own output.
//
// This is the assertion a round trip cannot make. A codec that wrote the role byte before the
// member id, or the retention pair as little endian, or the vector prefix as an ELEMENT count
// rather than the byte count syntax.WriteVector writes, round trips its own output perfectly and
// disagrees with every other implementation on the wire -- and this body is inside the confirmed
// transcript hash, so that disagreement is a permanent fork rather than a rejected message. The
// bytes below are read off RFC 9420 section 2.1.2 and MASTER section 6 and assembled with no call
// into mls/syntax at all.
func TestGroupPolicyEncodesAsBytesAssembledOutsideTheEncoder(t *testing.T) {
	policy := &GroupPolicyExtension{
		Roles: []RoleEntry{
			{MemberId: []byte{0x01, 0x02}, Role: RoleMember},
			{MemberId: []byte{0x03}, Role: RoleOwner},
		},
		RetentionPolicy:     RetentionPolicy{DurableMs: 0x0102030405060708, MediaMs: 2592000000},
		DisappearingBuckets: []uint8{0x00, 0x07},
		ServerId:            []byte("srv"),
	}
	want := []byte{
		// roles<V>: a varint byte count of 7, then the two entries
		0x07,
		// entry 0: opaque member_id<V> of two octets, then the role byte 1 (member)
		0x02, 0x01, 0x02, 0x01,
		// entry 1: opaque member_id<V> of one octet, then the role byte 3 (owner)
		0x01, 0x03, 0x03,
		// retention_durable_ms, uint64 big endian
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		// retention_media_ms, uint64 big endian: 2592000000 == 0x9a7ec800, thirty days
		0x00, 0x00, 0x00, 0x00, 0x9a, 0x7e, 0xc8, 0x00,
		// disappearing_buckets<V>: a varint byte count of 2, then the two bucket octets
		0x02, 0x00, 0x07,
		// server_id<V>: a varint byte count of 3, then "srv"
		0x03, 0x73, 0x72, 0x76,
	}
	encoded, err := policy.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(encoded.ExtensionData, want) {
		t.Fatalf("the encoded body is\n\t%x\nand the bytes assembled by hand are\n\t%x", encoded.ExtensionData, want)
	}
	// and the same run decodes back to the same value, so the hand assembled bytes are the ones
	// this package READS as well as the ones it writes
	parsed, err := ParseGroupPolicyExtension(want)
	if err != nil {
		t.Fatalf("ParseGroupPolicyExtension over the hand assembled bytes: %v", err)
	}
	if len(parsed.Roles) != 2 || parsed.Roles[0].Role != RoleMember || parsed.Roles[1].Role != RoleOwner {
		t.Fatalf("the hand assembled bytes decode to roles %+v", parsed.Roles)
	}
	if parsed.RetentionPolicy.MediaMs != 2592000000 {
		t.Fatalf("MediaMs = %d, want 2592000000; the retention pair is not being read big endian", parsed.RetentionPolicy.MediaMs)
	}
}

// TestGroupPolicyIsStampedWithTheCodePointTheRegistryAssignsIt pins 0xF001 itself.
//
// The value is a compatibility surface and not an implementation detail: it is checked here
// against the interface registry (section 8.1) and spec A section 3.4, both of which write 0xF001,
// and it sits one digit from urmessage_leaf_keys and urmessage_owner_successor in the same const
// block. A code point off by one encodes, signs, travels, and is read at the far end as a
// different extension entirely.
func TestGroupPolicyIsStampedWithTheCodePointTheRegistryAssignsIt(t *testing.T) {
	if uint16(ExtensionTypeUrmessageGroupPolicy) != 0xF001 {
		t.Fatalf("ExtensionTypeUrmessageGroupPolicy = %#04x, want 0xF001", uint16(ExtensionTypeUrmessageGroupPolicy))
	}
	policy := &GroupPolicyExtension{Roles: []RoleEntry{{MemberId: []byte("owner"), Role: RoleOwner}}}
	encoded, err := policy.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if uint16(encoded.ExtensionType) != 0xF001 {
		t.Fatalf("Encode stamped %#04x, want 0xF001", uint16(encoded.ExtensionType))
	}
	for _, neighbour := range []ExtensionType{ExtensionTypeUrmessageLeafKeys, ExtensionTypeUrmessageOwnerSuccessor} {
		if _, err := ParseGroupPolicyFrom(Extension{ExtensionType: neighbour, ExtensionData: encoded.ExtensionData}); !errors.Is(err, ErrMalformedExtension) {
			t.Errorf("ParseGroupPolicyFrom under %#04x error = %v, want ErrMalformedExtension", uint16(neighbour), err)
		}
	}
}

func TestGroupPolicyCanonicalOrdering(t *testing.T) {
	crypto := testCrypto(t)
	a := testIdentity(t, crypto, "a")
	b := testIdentity(t, crypto, "b")
	c := testIdentity(t, crypto, "c")

	first := &GroupPolicyExtension{Roles: []RoleEntry{
		{MemberId: a.IdentityPub, Role: RoleOwner},
		{MemberId: b.IdentityPub, Role: RoleAdmin},
		{MemberId: c.IdentityPub, Role: RoleMember},
	}}
	second := &GroupPolicyExtension{Roles: []RoleEntry{
		{MemberId: c.IdentityPub, Role: RoleMember},
		{MemberId: a.IdentityPub, Role: RoleOwner},
		{MemberId: b.IdentityPub, Role: RoleAdmin},
	}}
	if err := first.Canonicalize(); err != nil {
		t.Fatalf("Canonicalize first: %v", err)
	}
	if err := second.Canonicalize(); err != nil {
		t.Fatalf("Canonicalize second: %v", err)
	}
	e1, err := first.Encode()
	if err != nil {
		t.Fatalf("Encode first: %v", err)
	}
	e2, err := second.Encode()
	if err != nil {
		t.Fatalf("Encode second: %v", err)
	}
	if !bytes.Equal(e1.ExtensionData, e2.ExtensionData) {
		t.Fatal("two insertion orders of the same role set encode differently")
	}
}

// TestGroupPolicyCanonicalOrderIsAscendingByMemberIdAndNotMerelyDeterministic is the half the
// agreement test above cannot see.
//
// Two clients that both sorted by the ROLE byte, or both reversed the member ids, agree with each
// other perfectly and disagree with every other implementation, and "the two encodings match" is
// blind to that. Interoperability is a claim about a specific order, so the order is compared
// against an independent one -- lexicographic over the member id, spelled with bytes.Compare,
// which is a comparator this package's production source may not call and a test may.
func TestGroupPolicyCanonicalOrderIsAscendingByMemberIdAndNotMerelyDeterministic(t *testing.T) {
	crypto := testCrypto(t)
	roles := []RoleEntry{}
	for _, name := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		member := testIdentity(t, crypto, name)
		role := RoleMember
		if name == "a" {
			role = RoleOwner
		}
		roles = append(roles, RoleEntry{MemberId: member.IdentityPub, Role: role})
	}
	policy := &GroupPolicyExtension{Roles: slices.Clone(roles)}
	if err := policy.Canonicalize(); err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	independent := slices.Clone(roles)
	slices.SortStableFunc(independent, func(left RoleEntry, right RoleEntry) int {
		return bytes.Compare(left.MemberId, right.MemberId)
	})
	for i := range independent {
		if !bytes.Equal(policy.Roles[i].MemberId, independent[i].MemberId) {
			t.Fatalf("Canonicalize put %x at position %d and lexicographic order puts %x there; the canonical order is a wire commitment and not merely a repeatable one",
				policy.Roles[i].MemberId, i, independent[i].MemberId)
		}
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("a canonicalized policy must satisfy the order Validate enforces: %v", err)
	}
}

// TestCompareMemberIdsAnswersWhatBytesCompareAnswers is the oracle for the one piece of this file
// that is written out by hand rather than taken from the standard library.
//
// compareMemberIds is spelled with crypto/subtle because guardrail 8's derived gate reports every
// other comparator this package's imports can reach, so the ordering the whole canonical form
// rests on is an open coded fold over four subtle primitives. A fold that got the ordering
// backwards, or that latched on the wrong octet, or that ordered a prefix AFTER what extends it,
// still produces a total order -- so Canonicalize would still be deterministic, the two insertion
// orders would still agree, and only a second implementation would ever notice. bytes.Compare is
// that second implementation, and it is reachable here because this gate's scan skips test files.
func TestCompareMemberIdsAnswersWhatBytesCompareAnswers(t *testing.T) {
	corner := [][]byte{
		nil, {}, {0x00}, {0x01}, {0xff}, {0x00, 0x00}, {0x00, 0x01}, {0x01, 0x00},
		{0x7f, 0xff}, {0x80, 0x00}, {0xff, 0xfe}, {0xff, 0xff}, {0x01, 0x02, 0x03},
		[]byte("a"), []byte("A"), []byte("ab"), []byte("aB"), []byte("b"),
	}
	for _, left := range corner {
		for _, right := range corner {
			if got, want := compareMemberIds(left, right), bytes.Compare(left, right); got != want {
				t.Fatalf("compareMemberIds(%x, %x) = %d, bytes.Compare says %d", left, right, got, want)
			}
		}
	}
	// and over random runs, because the corners are what somebody thought of
	random := rand.New(rand.NewSource(0x9420))
	for i := 0; i < 4000; i += 1 {
		left := make([]byte, random.Intn(6))
		right := make([]byte, random.Intn(6))
		random.Read(left)
		random.Read(right)
		// half the pairs share a prefix, so the fold's latch is exercised rather than decided by
		// the first octet every time
		if i%2 == 0 && len(left) > 0 && len(right) > 0 {
			right[0] = left[0]
		}
		if got, want := compareMemberIds(left, right), bytes.Compare(left, right); got != want {
			t.Fatalf("compareMemberIds(%x, %x) = %d, bytes.Compare says %d", left, right, got, want)
		}
		if sameMemberId(left, right) != bytes.Equal(left, right) {
			t.Fatalf("sameMemberId(%x, %x) = %v, bytes.Equal says %v", left, right,
				sameMemberId(left, right), bytes.Equal(left, right))
		}
	}
}

func TestGroupPolicyRejectsUnsortedOnParse(t *testing.T) {
	crypto := testCrypto(t)
	a := testIdentity(t, crypto, "a")
	b := testIdentity(t, crypto, "b")
	lo, hi := a, b
	if bytes.Compare(a.IdentityPub, b.IdentityPub) > 0 {
		lo, hi = b, a
	}
	unsorted := &GroupPolicyExtension{Roles: []RoleEntry{
		{MemberId: hi.IdentityPub, Role: RoleOwner},
		{MemberId: lo.IdentityPub, Role: RoleMember},
	}}
	encoded, err := unsorted.encodeUnchecked()
	if err != nil {
		t.Fatalf("encodeUnchecked: %v", err)
	}
	_, err = ParseGroupPolicyExtension(encoded)
	if !errors.Is(err, ErrRolesNotCanonical) {
		t.Fatalf("ParseGroupPolicyExtension error = %v, want ErrRolesNotCanonical", err)
	}
	// and the refusal is a REFUSAL rather than a silent re-sort: nothing usable comes back
	policy, err := ParseGroupPolicyExtension(encoded)
	if policy != nil {
		t.Fatalf("ParseGroupPolicyExtension answered %+v beside its refusal; a receiver that hands back a re-sorted policy accepts two spellings of one group", policy)
	}
	// the same body under its own tag is refused identically, so the tag checked entry point is
	// not a laxer path to the same bytes
	if _, err := ParseGroupPolicyFrom(Extension{
		ExtensionType: ExtensionTypeUrmessageGroupPolicy, ExtensionData: encoded,
	}); !errors.Is(err, ErrRolesNotCanonical) {
		t.Fatalf("ParseGroupPolicyFrom error = %v, want ErrRolesNotCanonical", err)
	}
}

func TestGroupPolicyRejectsDuplicateMember(t *testing.T) {
	crypto := testCrypto(t)
	a := testIdentity(t, crypto, "a")
	policy := &GroupPolicyExtension{Roles: []RoleEntry{
		{MemberId: a.IdentityPub, Role: RoleOwner},
		{MemberId: a.IdentityPub, Role: RoleMember},
	}}
	if err := policy.Canonicalize(); !errors.Is(err, ErrDuplicateRoleEntry) {
		t.Fatalf("Canonicalize error = %v, want ErrDuplicateRoleEntry", err)
	}
}

func TestGroupPolicyRequiresExactlyOneOwner(t *testing.T) {
	crypto := testCrypto(t)
	a := testIdentity(t, crypto, "a")
	b := testIdentity(t, crypto, "b")

	none := &GroupPolicyExtension{Roles: []RoleEntry{{MemberId: a.IdentityPub, Role: RoleMember}}}
	if err := none.Canonicalize(); err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if err := none.Validate(); !errors.Is(err, ErrNoOwner) {
		t.Fatalf("Validate error = %v, want ErrNoOwner", err)
	}

	two := &GroupPolicyExtension{Roles: []RoleEntry{
		{MemberId: a.IdentityPub, Role: RoleOwner},
		{MemberId: b.IdentityPub, Role: RoleOwner},
	}}
	if err := two.Canonicalize(); err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if err := two.Validate(); !errors.Is(err, ErrMultipleOwners) {
		t.Fatalf("Validate error = %v, want ErrMultipleOwners", err)
	}
}

func TestGroupPolicyRejectsUnknownRoleByte(t *testing.T) {
	crypto := testCrypto(t)
	a := testIdentity(t, crypto, "a")
	policy := &GroupPolicyExtension{Roles: []RoleEntry{{MemberId: a.IdentityPub, Role: Role(9)}}}
	if _, err := policy.Encode(); err == nil {
		t.Fatal("Encode accepted role byte 9")
	}
}

// TestGroupPolicyRefusesEveryUndefinedRoleByteOnBothSidesOfTheWire is the class the test above
// samples one member of.
//
// Four role bytes are defined and 252 are not, and the encoder and the decoder have to refuse the
// same 252: a decoder that accepted one would hand back a policy this build renders as "unknown"
// and treats, wherever a switch has a default, as an observer. The sweep runs the whole uint8
// space rather than the neighbours somebody thought of, and it runs it in BOTH directions off one
// body assembled with encodeUnchecked, which is what a hostile peer would send.
func TestGroupPolicyRefusesEveryUndefinedRoleByteOnBothSidesOfTheWire(t *testing.T) {
	defined := []Role{RoleObserver, RoleMember, RoleAdmin, RoleOwner}
	for value := 0; value <= 0xff; value += 1 {
		role := Role(value)
		policy := &GroupPolicyExtension{Roles: []RoleEntry{{MemberId: groupPolicyLowId, Role: role}}}
		_, encodeErr := policy.encodeUnchecked()
		// the smallest hostile edit there is: one well formed body with its single role octet
		// rewritten in place, so what the decoder sees differs from a legal message by one byte
		body := groupPolicyWellFormedBody(t)
		body[groupPolicyRoleByteOffset] = byte(value)
		_, decodeErr := ParseGroupPolicyExtension(body)
		if slices.Contains(defined, role) {
			if encodeErr != nil {
				t.Errorf("the encoder refused the defined role byte %d: %v", value, encodeErr)
			}
			continue
		}
		if !errors.Is(encodeErr, ErrMalformedExtension) {
			t.Errorf("the encoder answered %v for the undefined role byte %d, want ErrMalformedExtension", encodeErr, value)
		}
		if !errors.Is(decodeErr, ErrMalformedExtension) {
			t.Errorf("the decoder answered %v for the undefined role byte %d, want ErrMalformedExtension; a role this build cannot render is a policy it cannot enforce", decodeErr, value)
		}
	}
}

func TestRoleStrings(t *testing.T) {
	for _, tc := range []struct {
		role Role
		name string
	}{
		{RoleOwner, "owner"},
		{RoleAdmin, "admin"},
		{RoleMember, "member"},
		{RoleObserver, "observer"},
	} {
		if tc.role.String() != tc.name {
			t.Fatalf("Role(%d).String() = %q, want %q", tc.role, tc.role.String(), tc.name)
		}
		parsed, err := ParseRole(tc.name)
		if err != nil || parsed != tc.role {
			t.Fatalf("ParseRole(%q) = %v %v", tc.name, parsed, err)
		}
	}
	if _, err := ParseRole("superuser"); err == nil {
		t.Fatal("ParseRole accepted an unknown role name")
	}
}

// TestRoleNamesAreExactAndTheWireBytesAreTheOnesMasterAssigns is the half the table above leaves
// out, and both halves of it have bitten this project.
//
// The names are a wire surface: spec A section 7.3 exposes them through sdk, so a ParseRole that
// accepted "Owner" or "OWNER" would let one client grant an authority another client's parse of
// the same string refuses. And the four BYTES are a wire surface for the same reason the code
// point is -- they travel inside the transcript hash -- so they are pinned as numbers here rather
// than left to the order somebody happened to declare the constants in.
func TestRoleNamesAreExactAndTheWireBytesAreTheOnesMasterAssigns(t *testing.T) {
	for role, want := range map[Role]uint8{
		RoleObserver: 0, RoleMember: 1, RoleAdmin: 2, RoleOwner: 3,
	} {
		if uint8(role) != want {
			t.Errorf("%s is wire byte %d, want %d", role, uint8(role), want)
		}
	}
	for _, rejected := range []string{"Owner", "OWNER", " owner", "owner ", "", "0", "3", "unknown"} {
		if role, err := ParseRole(rejected); err == nil {
			t.Errorf("ParseRole(%q) answered %v; the role name is a wire surface and a case insensitive parse is two clients disagreeing about who is an admin",
				rejected, role)
		}
	}
	if Role(4).String() != "unknown" || Role(255).String() != "unknown" {
		t.Errorf("Role(4) renders %q and Role(255) renders %q, want unknown for both",
			Role(4).String(), Role(255).String())
	}
}

func TestGroupPolicyOfMissing(t *testing.T) {
	if _, err := GroupPolicyOf(nil); !errors.Is(err, ErrNoGroupPolicy) {
		t.Fatalf("GroupPolicyOf(nil) error = %v, want ErrNoGroupPolicy", err)
	}
}

// TestGroupPolicyOfReadsTheEntryOfItsOwnTypeAndNoOther is GroupPolicyOf's half of the argument
// LeafKeysOf's own type test makes: a lookup that answered the first entry of the vector would
// hand a role list back out of somebody else's body, and every group context in this profile
// carries required_capabilities and ratchet_tree beside the policy.
func TestGroupPolicyOfReadsTheEntryOfItsOwnTypeAndNoOther(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	leafKeys := testLeafKeys(t, owner)
	policy, err := (&GroupPolicyExtension{
		Roles:    []RoleEntry{{MemberId: owner.IdentityPub, Role: RoleOwner}},
		ServerId: []byte("urmessage-v1-server"),
	}).Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	if _, err := GroupPolicyOf([]Extension{
		{ExtensionType: ExtensionTypeRequiredCapabilities, ExtensionData: []byte{0x00, 0x00, 0x00}},
		leafKeys,
	}); !errors.Is(err, ErrNoGroupPolicy) {
		t.Fatalf("GroupPolicyOf over a list with no 0xF001 error = %v, want ErrNoGroupPolicy", err)
	}

	found, err := GroupPolicyOf([]Extension{
		{ExtensionType: ExtensionTypeRequiredCapabilities, ExtensionData: []byte{0x00, 0x00, 0x00}},
		leafKeys,
		policy,
	})
	if err != nil {
		t.Fatalf("GroupPolicyOf over a list whose 0xF001 entry is not first: %v", err)
	}
	if id, ok := found.OwnerId(); !ok || !bytes.Equal(id, owner.IdentityPub) {
		t.Fatal("GroupPolicyOf answered a policy that is not the one in the list")
	}
}

// TestGroupPolicyAccessorsAnswerTheRoleSetTheyAreGiven covers the six accessors the interface
// registry pins, each of which gains its first caller in this task.
func TestGroupPolicyAccessorsAnswerTheRoleSetTheyAreGiven(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	admin := testIdentity(t, crypto, "admin")
	member := testIdentity(t, crypto, "member")
	stranger := testIdentity(t, crypto, "stranger")
	policy := testPolicy(t, owner, admin, member)

	if role, ok := policy.RoleOf(stranger.IdentityPub); ok || role != RoleObserver {
		t.Errorf("RoleOf(a member the policy does not name) = %v %v, want observer false", role, ok)
	}
	if count := policy.AdminCount(); count != 1 {
		t.Errorf("AdminCount = %d, want 1; the owner is not an admin, and counting them would let a group with one admin meet a two admin quorum", count)
	}

	// SetRole on a member already named replaces the role and adds no entry
	before := len(policy.Roles)
	policy.SetRole(member.IdentityPub, RoleAdmin)
	if len(policy.Roles) != before {
		t.Errorf("SetRole over a named member grew the role set from %d to %d", before, len(policy.Roles))
	}
	if role, ok := policy.RoleOf(member.IdentityPub); !ok || role != RoleAdmin {
		t.Errorf("RoleOf after SetRole = %v %v, want admin true", role, ok)
	}
	if count := policy.AdminCount(); count != 2 {
		t.Errorf("AdminCount = %d, want 2", count)
	}

	// SetRole on a stranger inserts, keeps the canonical order, and COPIES the id it was handed
	handed := slices.Clone(stranger.IdentityPub)
	policy.SetRole(handed, RoleObserver)
	for i := range handed {
		handed[i] ^= 0xff
	}
	if role, ok := policy.RoleOf(stranger.IdentityPub); !ok || role != RoleObserver {
		t.Errorf("RoleOf after SetRole over a caller's buffer that was then overwritten = %v %v, want observer true; the policy is covered by a transcript hash and cannot alias a caller's slice",
			role, ok)
	}
	if err := policy.Validate(); err != nil {
		t.Errorf("SetRole left the policy in a state Validate refuses: %v", err)
	}

	policy.RemoveRole(stranger.IdentityPub)
	if _, ok := policy.RoleOf(stranger.IdentityPub); ok {
		t.Error("RemoveRole left the member in the role set")
	}
	// removing somebody the policy never named is a no op rather than a corruption
	sizeBefore := len(policy.Roles)
	policy.RemoveRole([]byte("nobody"))
	if len(policy.Roles) != sizeBefore {
		t.Errorf("RemoveRole over an absent member changed the role set from %d to %d entries", sizeBefore, len(policy.Roles))
	}
	if id, ok := policy.OwnerId(); !ok || !bytes.Equal(id, owner.IdentityPub) {
		t.Error("OwnerId no longer answers the owner")
	}
	if _, ok := (&GroupPolicyExtension{}).OwnerId(); ok {
		t.Error("OwnerId reported an owner on a policy with no roles at all")
	}
}

// TestGroupPolicyCloneSharesNothingWithWhatItWasClonedFrom is what Clone exists for: a staged
// commit mutates its copy while the live epoch is still running on the original, and a shallow
// copy would rewrite a role inside the epoch the group has not left yet.
func TestGroupPolicyCloneSharesNothingWithWhatItWasClonedFrom(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	admin := testIdentity(t, crypto, "admin")
	member := testIdentity(t, crypto, "member")
	live := testPolicy(t, owner, admin, member)
	staged := live.Clone()

	staged.SetRole(admin.IdentityPub, RoleObserver)
	staged.RemoveRole(member.IdentityPub)
	staged.RetentionPolicy.DurableMs = 1
	staged.DisappearingBuckets[0] = 9
	staged.ServerId[0] = 'X'
	// and the member id array itself, which a Clone that copied the slice header alone shares
	staged.Roles[0].MemberId[0] ^= 0xff

	if role, ok := live.RoleOf(admin.IdentityPub); !ok || role != RoleAdmin {
		t.Errorf("the live policy's admin is now %v %v after the staged copy was edited", role, ok)
	}
	if _, ok := live.RoleOf(member.IdentityPub); !ok {
		t.Error("the live policy lost a member when the staged copy removed one")
	}
	if live.RetentionPolicy.DurableMs != 0 || live.DisappearingBuckets[0] != 0 || live.ServerId[0] != 'u' {
		t.Errorf("the live policy's retention, buckets or server id followed the staged copy: %+v", live)
	}
	if err := live.Validate(); err != nil {
		t.Errorf("the live policy no longer validates after its clone was edited: %v", err)
	}
}

// ---------------------------------------------------------------------------
// every way this file refuses a role list, derived from the file
// ---------------------------------------------------------------------------

// groupPolicyRefusalSite is one place group_policy.go can answer a refusal from: the declaration
// it is written in, the sentinel it answers, an ordinal that separates two sites of one
// declaration answering the same sentinel, and the pattern the MESSAGE at that site must match.
//
// The pattern is what makes this a site and not merely a sentinel. Validate refuses an undefined
// role byte and an empty member id with the same value, so a table row that reached the wrong one
// of the two would satisfy every errors.Is assertion there is; the format string is read off the
// site's own fmt.Errorf call, so a row is held to the clause it claims rather than to the value.
type groupPolicyRefusalSite struct {
	site     string
	sentinel string
	pattern  string
}

// groupPolicyVerb matches one printf verb, so a format string can be turned into the pattern the
// message it produces has to match.
var groupPolicyVerb = regexp.MustCompile(`%[-+# 0]*[0-9]*(\.[0-9]+)?[a-zA-Z]`)

// groupPolicyMessagePattern turns a format string into a regular expression: every literal run of
// it, quoted, joined by what a verb can expand to.
func groupPolicyMessagePattern(format string) string {
	chunks := groupPolicyVerb.Split(format, -1)
	quoted := []string{}
	for _, chunk := range chunks {
		quoted = append(quoted, regexp.QuoteMeta(chunk))
	}
	return strings.Join(quoted, ".*")
}

// groupPolicyRefusalIn reads one returned expression for the sentinel it answers and the format
// it answers it under. The empty name means this expression is not a refusal.
func groupPolicyRefusalIn(parsed parsedSource, expression ast.Expr, declared []string) (string, string) {
	isSentinel := func(node ast.Expr) string {
		identifier, isIdentifier := node.(*ast.Ident)
		if !isIdentifier || !strings.HasPrefix(identifier.Name, "Err") ||
			!slices.Contains(declared, identifier.Name) {
			return ""
		}
		return identifier.Name
	}
	if name := isSentinel(expression); name != "" {
		return name, ""
	}
	call, isCall := expression.(*ast.CallExpr)
	if !isCall || parsed.render(call.Fun) != "fmt.Errorf" || len(call.Args) < 2 {
		return "", ""
	}
	literal, isLiteral := call.Args[0].(*ast.BasicLit)
	if !isLiteral {
		return "", ""
	}
	format, err := strconv.Unquote(literal.Value)
	if err != nil {
		return "", ""
	}
	for _, argument := range call.Args[1:] {
		if name := isSentinel(argument); name != "" {
			return name, format
		}
	}
	return "", ""
}

// groupPolicyRefusalSitesOf is the class the sweep below runs over: every refusal group_policy.go
// makes, read off the file's own return statements.
//
// DERIVED and not written down, which is the whole point of it. "Every way a role list is
// refused" has been written as a hand list fifteen times on this project and understated itself
// fifteen times, and the shape it understates itself in is always the same: the list holds the
// refusals somebody remembered and the file grew one more. A clause added to Validate arrives in
// this class on the commit that writes it and fails for having no input, rather than being
// covered by a table that says it is.
func groupPolicyRefusalSitesOf(t *testing.T) []groupPolicyRefusalSite {
	t.Helper()
	declared := []string{}
	for _, path := range packageLevelFunctions(t).files {
		declared = append(declared, packageLevelVarNamesIn(mustParseSource(t, path))...)
	}
	if len(declared) == 0 {
		t.Fatal("this package's non test source declares no package level variable, so every sentinel below reads as an unknown identifier and the class is empty")
	}
	parsed := mustParseSource(t, groupPolicySourceFile)
	seen := map[string]int{}
	sites := []groupPolicyRefusalSite{}
	for _, one := range declaredIn(parsed) {
		if one.body == nil {
			continue
		}
		where := one.name
		if one.receiver != "" {
			where = "(" + one.receiver + ")." + one.name
		}
		ast.Inspect(one.body, func(node ast.Node) bool {
			returned, isReturn := node.(*ast.ReturnStmt)
			if !isReturn {
				return true
			}
			for _, result := range returned.Results {
				sentinel, format := groupPolicyRefusalIn(parsed, result, declared)
				if sentinel == "" {
					continue
				}
				key := where + ":" + sentinel
				sites = append(sites, groupPolicyRefusalSite{
					site:     fmt.Sprintf("%s#%d", key, seen[key]),
					sentinel: sentinel,
					pattern:  groupPolicyMessagePattern(format),
				})
				seen[key] += 1
			}
			return true
		})
	}
	if len(sites) == 0 {
		t.Fatalf("no declaration of %s answers a sentinel, so the sweep below demands nothing", groupPolicySourceFile)
	}
	slices.SortFunc(sites, func(left groupPolicyRefusalSite, right groupPolicyRefusalSite) int {
		return strings.Compare(left.site, right.site)
	})
	return sites
}

// groupPolicyRefusalRow is one input that reaches one site.
type groupPolicyRefusalRow struct {
	call func(t *testing.T) error
}

// the two member ids the rows order against, fixed rather than minted, so the row that claims an
// ordering failure produces one every run
var (
	groupPolicyLowId  = []byte{0x01, 0x11}
	groupPolicyHighId = []byte{0x02, 0x22}
)

// groupPolicyRoleByteOffset is where the one role octet sits in the body below: past the roles
// vector's length prefix, past the member id's, and past the member id itself. Written as the sum
// of the three rather than as a number, so the rows that rewrite it move with the fixture, and
// checked against the body it indexes by groupPolicyWellFormedBody -- an edit to the wrong offset
// is a body that fails to decode for a reason nobody asked about, which is how a hostile input
// test comes to assert nothing.
var groupPolicyRoleByteOffset = 1 + 1 + len(groupPolicyLowId)

// groupPolicyWellFormedBody is one owner and nothing else, encoded past the policy gate, which is
// the run the hostile rows edit.
func groupPolicyWellFormedBody(t *testing.T) []byte {
	t.Helper()
	body, err := (&GroupPolicyExtension{
		Roles: []RoleEntry{{MemberId: groupPolicyLowId, Role: RoleOwner}},
	}).encodeUnchecked()
	if err != nil {
		t.Fatalf("the well formed body the hostile rows edit: %v", err)
	}
	if body[groupPolicyRoleByteOffset] != uint8(RoleOwner) {
		t.Fatalf("the body %x carries %d at the offset this fixture calls the role octet, want %d; every hostile row below edits that offset",
			body, body[groupPolicyRoleByteOffset], uint8(RoleOwner))
	}
	return body
}

// groupPolicyRefusalRows is the table the derived class above is held against, in both
// directions: a site with no row fails rather than going unrun, and a row for a refusal this file
// no longer makes fails rather than outliving it.
func groupPolicyRefusalRows() map[string]groupPolicyRefusalRow {
	return map[string]groupPolicyRefusalRow{
		"GroupPolicyOf:ErrNoGroupPolicy#0": {call: func(t *testing.T) error {
			_, err := GroupPolicyOf([]Extension{
				{ExtensionType: ExtensionTypeUrmessageLeafKeys, ExtensionData: []byte{0x00}},
			})
			return err
		}},
		"ParseGroupPolicyFrom:ErrMalformedExtension#0": {call: func(t *testing.T) error {
			_, err := ParseGroupPolicyFrom(Extension{
				ExtensionType: ExtensionTypeUrmessageLeafKeys,
				ExtensionData: groupPolicyWellFormedBody(t),
			})
			return err
		}},
		"ParseRole:ErrMalformedExtension#0": {call: func(t *testing.T) error {
			_, err := ParseRole("superuser")
			return err
		}},
		// the decode side's own role byte gate, reached by rewriting the one role octet of a
		// body a peer would otherwise have sent
		"readOneRoleEntry:ErrMalformedExtension#0": {call: func(t *testing.T) error {
			body := groupPolicyWellFormedBody(t)
			body[groupPolicyRoleByteOffset] = 9
			_, err := ParseGroupPolicyExtension(body)
			return err
		}},
		// the encode side's, reached through encodeUnchecked because Encode's own Validate
		// refuses the same value one clause earlier
		"writeOneRoleEntry:ErrMalformedExtension#0": {call: func(t *testing.T) error {
			_, err := (&GroupPolicyExtension{
				Roles: []RoleEntry{{MemberId: groupPolicyLowId, Role: Role(9)}},
			}).encodeUnchecked()
			return err
		}},
		"(*GroupPolicyExtension).Validate:ErrMalformedExtension#0": {call: func(t *testing.T) error {
			return (&GroupPolicyExtension{
				Roles: []RoleEntry{{MemberId: groupPolicyLowId, Role: Role(9)}},
			}).Validate()
		}},
		"(*GroupPolicyExtension).Validate:ErrMalformedExtension#1": {call: func(t *testing.T) error {
			return (&GroupPolicyExtension{
				Roles: []RoleEntry{{MemberId: nil, Role: RoleOwner}},
			}).Validate()
		}},
		"(*GroupPolicyExtension).Validate:ErrRolesNotCanonical#0": {call: func(t *testing.T) error {
			return (&GroupPolicyExtension{Roles: []RoleEntry{
				{MemberId: groupPolicyHighId, Role: RoleOwner},
				{MemberId: groupPolicyLowId, Role: RoleMember},
			}}).Validate()
		}},
		"(*GroupPolicyExtension).Validate:ErrDuplicateRoleEntry#0": {call: func(t *testing.T) error {
			return (&GroupPolicyExtension{Roles: []RoleEntry{
				{MemberId: groupPolicyLowId, Role: RoleOwner},
				{MemberId: groupPolicyLowId, Role: RoleMember},
			}}).Validate()
		}},
		"(*GroupPolicyExtension).Validate:ErrNoOwner#0": {call: func(t *testing.T) error {
			return (&GroupPolicyExtension{
				Roles: []RoleEntry{{MemberId: groupPolicyLowId, Role: RoleMember}},
			}).Validate()
		}},
		"(*GroupPolicyExtension).Validate:ErrMultipleOwners#0": {call: func(t *testing.T) error {
			return (&GroupPolicyExtension{Roles: []RoleEntry{
				{MemberId: groupPolicyLowId, Role: RoleOwner},
				{MemberId: groupPolicyHighId, Role: RoleOwner},
			}}).Validate()
		}},
		"(*GroupPolicyExtension).Canonicalize:ErrDuplicateRoleEntry#0": {call: func(t *testing.T) error {
			return (&GroupPolicyExtension{Roles: []RoleEntry{
				{MemberId: groupPolicyHighId, Role: RoleOwner},
				{MemberId: groupPolicyHighId, Role: RoleMember},
			}}).Canonicalize()
		}},
	}
}

// TestEveryRefusalTheGroupPolicyMakesHasAnInputThatProducesItAndAnswersNoOther is guardrail 5 over
// this file: the class is read off the enforcement and the table is held to it in both directions,
// so "every way a role list is refused" is a question the SOURCE answers.
//
// Three things are asserted per site and each of them has been the whole defect somewhere on this
// project. The refusal is reachable at all -- a clause no input reaches is a rule nothing enforces.
// It answers the sentinel the site names AND no other sentinel this package declares -- four
// refusals that all reduce to one comparison is the shape that passed every test on the CreateGroup
// carve-out, and errors.Is over the whole lifecycle set is what separates them. And the MESSAGE
// matches the format written at that site, which is what tells the two ErrMalformedExtension
// clauses of Validate apart: a row that reached the wrong one of the two satisfies both of the
// first two assertions.
func TestEveryRefusalTheGroupPolicyMakesHasAnInputThatProducesItAndAnswersNoOther(t *testing.T) {
	// the pattern derivation's own control, on both halves. A derivation that collapsed a format
	// to ".*" would hold every row below to nothing and report exactly what a working one reports,
	// so the pattern has to keep the format's literal text AND has to refuse a message that does
	// not carry it.
	control := groupPolicyMessagePattern("%w: entry %d is out of order")
	if !strings.Contains(control, "is out of order") || strings.TrimLeft(control, ".*") == "" {
		t.Fatalf("the message pattern derivation produced %q out of a two verb format; a pattern that keeps none of the literal text matches everything", control)
	}
	if matched, err := regexp.MatchString(control,
		"mls: group policy roles are not sorted by member id: entry 1 is out of order"); err != nil || !matched {
		t.Fatalf("the derived pattern %q does not match the message that format produces (matched=%v err=%v)", control, matched, err)
	}
	if matched, err := regexp.MatchString(control, "mls: something else entirely"); err != nil || matched {
		t.Fatalf("the derived pattern %q matched an unrelated message (matched=%v err=%v)", control, matched, err)
	}

	sites := groupPolicyRefusalSitesOf(t)
	rows := groupPolicyRefusalRows()
	named := []string{}
	for _, one := range sites {
		named = append(named, one.site)
	}
	if held := slices.Sorted(maps.Keys(rows)); !slices.Equal(named, held) {
		t.Fatalf("%s refuses at %v and this table holds %v; a refusal with no input is one nothing here runs, and a row for a refusal this file no longer makes is one that outlived it",
			groupPolicySourceFile, named, held)
	}
	t.Logf("%d refusal sites derived from %s: %v", len(sites), groupPolicySourceFile, named)

	for _, one := range sites {
		sentinel, held := lifecycleOwnedErrors[one.sentinel]
		if !held {
			t.Errorf("%s answers %s, which is not one of the lifecycle sentinels this package sweeps; nothing holds it apart from any other value",
				one.site, one.sentinel)
			continue
		}
		err := rows[one.site].call(t)
		if err == nil {
			t.Errorf("%s: the input for this refusal was accepted", one.site)
			continue
		}
		if !errors.Is(err, sentinel) {
			t.Errorf("%s answered %v, want %s", one.site, err, one.sentinel)
			continue
		}
		for _, other := range slices.Sorted(maps.Keys(lifecycleOwnedErrors)) {
			if other == one.sentinel {
				continue
			}
			if errors.Is(err, lifecycleOwnedErrors[other]) {
				t.Errorf("%s answered a value that is also %s; two refusals a caller cannot tell apart are one refusal wearing two names",
					one.site, other)
			}
		}
		pattern := one.pattern
		if pattern == "" {
			pattern = regexp.QuoteMeta(sentinel.Error())
		}
		matched, matchErr := regexp.MatchString(pattern, err.Error())
		if matchErr != nil {
			t.Errorf("%s: the pattern derived from its format is not a regular expression: %v", one.site, matchErr)
			continue
		}
		if !matched {
			t.Errorf("%s answered %q, which does not match the message written at that site (%s); this input reaches some OTHER clause answering the same sentinel",
				one.site, err.Error(), pattern)
		}
	}
}
