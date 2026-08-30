// The urmessage_group_policy group context extension, MASTER sections 6 and 11 and spec A
// section 3.4.
//
// It lives in the GROUP CONTEXT and not in a leaf, which is the whole of why it is worth
// writing down: the group context is inside the confirmed transcript hash, so the roles, the
// retention request and the disappearing buckets are covered by every confirmation tag the
// group has ever produced, and no server can alter one, add one or drop one without every
// member's transcript diverging from it.
//
// That is also what makes the CANONICAL form a security property rather than tidiness. Two
// clients that hold the same role set and encode it in two orders produce two different
// extension bodies, two different group contexts and two different transcript hashes, which is
// a permanent fork rather than a message somebody retransmits. So the order is fixed here, the
// encoder refuses what it cannot state canonically, and -- the half that a round trip cannot
// see -- the DECODER refuses a non canonical encoding instead of silently re-sorting it, since
// a receiver that re-sorts accepts two spellings of one group and agrees with each sender that
// they are the only one.
//
// ExtensionTypeUrmessageGroupPolicy (0xF001) is declared once with the other registry enums, in
// extension.go, and is checked against the interface registry and spec A there rather than
// restated here.
package mls

import (
	"crypto/subtle"
	"fmt"
	"slices"

	"github.com/urnetwork/connect/mls/syntax"
)

// Role is a member's authority in a group. MASTER section 11.
type Role uint8

const (
	RoleObserver Role = 0
	RoleMember   Role = 1
	RoleAdmin    Role = 2
	RoleOwner    Role = 3
)

// String returns the wire stable name spec A section 7.3 exposes through sdk.
//
// "unknown" for anything else rather than a number, because this is what a UI renders, and an
// undefined role byte never reaches a rendering path: the codec refuses one on the way in and
// on the way out, so a String seeing one is a bug in this package and not a peer's message.
func (self Role) String() string {
	switch self {
	case RoleObserver:
		return "observer"
	case RoleMember:
		return "member"
	case RoleAdmin:
		return "admin"
	case RoleOwner:
		return "owner"
	}
	return "unknown"
}

// valid answers whether this is one of the four defined role bytes.
//
// The comparison is against RoleOwner, the largest of the four, rather than against a list of
// them, so a fifth role added to the block above is defined the moment it is declared.
func (self Role) valid() bool {
	return self <= RoleOwner
}

// ParseRole maps the sdk role string onto the wire byte.
//
// It is DERIVED from String rather than written as a second table of the same four names, and
// that is what makes the two exact inverses of each other: a name String renders is a name this
// parses, and neither half can learn one the other does not know. The bound is the same RoleOwner
// valid() reads, so a fifth role declared in the block above is parseable by the commit that
// declares it, and "unknown" -- what String answers for everything past the bound -- is outside
// the loop and so is not a name.
//
// The comparison is crypto/subtle.ConstantTimeCompare and not ==, and the reason is the SPELLING
// rather than a claim that a role name is secret. The octet comparison gate in
// framing_guard_test.go type checks every production declaration under this tree's roots and
// reports a whole string comparison written as ordinary go equality; it has no exemption to ask
// for, and a switch over four string literals is four of them.
//
// The refusal is ErrMalformedExtension, the same value the codec answers for an undefined role
// byte, because a caller asking either question is asking whether this profile has a role by this
// name.
func ParseRole(name string) (Role, error) {
	wanted := []byte(name)
	for role := RoleObserver; role <= RoleOwner; role += 1 {
		if subtle.ConstantTimeCompare([]byte(role.String()), wanted) == 1 {
			return role, nil
		}
	}
	return RoleObserver, fmt.Errorf("%w: unknown role %q", ErrMalformedExtension, name)
}

// RoleEntry binds one member identity to one role.
//
// MemberId is the member's Ed25519 identity public key, which is the BasicCredential subject,
// so it is stable across that member's device leaves: a member with three devices holds three
// leaves in the tree and exactly one entry here.
type RoleEntry struct {
	MemberId []byte
	Role     Role
}

// RetentionPolicy is the group's requested retention, in milliseconds.
//
// A REQUEST. The server clamps and floors it and reports what it actually applied; what is
// covered by the transcript hash is what the group asked for, and it is unchanged by the
// server's answer. MASTER section 15 item 1.
type RetentionPolicy struct {
	DurableMs uint64
	MediaMs   uint64
}

// GroupPolicyExtension is the group context policy, extension type 0xF001:
//
//	struct {
//	    RoleEntry roles<V>;
//	    uint64    retention_durable_ms;
//	    uint64    retention_media_ms;
//	    uint8     disappearing_buckets<V>;
//	    opaque    server_id<V>;
//	} UrmessageGroupPolicy;
//
// ServerId is a v2 field retained in v1, where it is always the one server. It is in the
// canonical bytes from the first version rather than added later, because adding a field to a
// structure inside the transcript hash is a wire break and not a feature.
type GroupPolicyExtension struct {
	Roles               []RoleEntry
	RetentionPolicy     RetentionPolicy
	DisappearingBuckets []uint8
	ServerId            []byte
}

// the C1 pin: drift between this type and the one codec convention fails at build.
var _ syntax.Codec = (*GroupPolicyExtension)(nil)

// compareMemberIds orders two member ids the way bytes.Compare would -- lexicographically, a
// prefix ahead of what extends it -- and answers -1, 0 or 1.
//
// Spelled with crypto/subtle rather than with bytes.Compare, and that is not a claim that a
// member id is secret. It is an Ed25519 identity public key and it is public. Guardrail 8 is a
// rule about the SPELLING: the derived gate in constant_time_test.go reads the comparator class
// off this package's own imports and reports every call to any member of it, so a canonical
// sort written with bytes.Compare would be the one call site in the package needing an
// exemption -- and an exemption written for a comparison somebody judged safe is exactly the
// shape this project has been walked past before, because the next comparison inherits it.
//
// The equality half of the file is derived from THIS function rather than written beside it.
// Two members are the same member exactly when this answers zero, so the sort's idea of a
// duplicate and RoleOf's idea of a match cannot disagree -- which they can when one is spelled
// as a compare and the other as an equal, and the disagreement is a member holding two entries
// that the canonical check believes is one.
func compareMemberIds(left []byte, right []byte) int {
	shared := min(len(left), len(right))
	// decided latches at the first octet the two differ in and answer holds what that octet
	// said; every later octet is folded in and discarded, so the running time is a function of
	// the two lengths alone
	decided := 0
	answer := 0
	for i := 0; i < shared; i += 1 {
		same := subtle.ConstantTimeByteEq(left[i], right[i])
		notAfter := subtle.ConstantTimeLessOrEq(int(left[i]), int(right[i]))
		here := subtle.ConstantTimeSelect(same, 0, subtle.ConstantTimeSelect(notAfter, -1, 1))
		answer = subtle.ConstantTimeSelect(decided, answer, here)
		decided |= 1 ^ same
	}
	// two runs that agree on every shared octet are ordered by length, the shorter first
	leftNotLonger := subtle.ConstantTimeLessOrEq(len(left), len(right))
	rightNotLonger := subtle.ConstantTimeLessOrEq(len(right), len(left))
	byLength := subtle.ConstantTimeSelect(leftNotLonger&rightNotLonger, 0,
		subtle.ConstantTimeSelect(leftNotLonger, -1, 1))
	return subtle.ConstantTimeSelect(decided, answer, byLength)
}

// sameMemberId is the equality the whole file asks, derived from the ordering above so that the
// two can never answer differently about one pair.
func sameMemberId(left []byte, right []byte) bool {
	return compareMemberIds(left, right) == 0
}

// sortRolesByMemberId puts the entries in the one order this extension has, in place.
//
// STABLE, which matters only for a slice that already holds a duplicate: an unstable sort would
// order the two copies arbitrarily, so which of the two roles a duplicate carried into the
// refusal would vary run to run. Canonicalize sorts IN PLACE and then refuses, so the caller
// still holds the reordered slice after the refusal, and a caller repairing the duplicate by
// dropping the later entry keeps whichever role the sort happened to leave first.
//
// The stability is what TestSortingTheRolesKeepsTwoEntriesForOneMemberInTheOrderTheyArrived
// holds, over a fixture large enough for the difference to exist: Go's unstable sort runs an
// insertion sort below thirteen elements and is stable there by accident, so a three entry test
// of this property observes nothing.
func sortRolesByMemberId(roles []RoleEntry) {
	slices.SortStableFunc(roles, func(left RoleEntry, right RoleEntry) int {
		return compareMemberIds(left.MemberId, right.MemberId)
	})
}

// writeOneRoleEntry is WriteVector's element encoder, a named function rather than a closure for
// the reason writeOneExtension is: the codec entry pin in crypto_labels_test.go renders every
// syntax call of this package's source and holds the list whole.
//
// The undefined role byte is refused HERE rather than coerced, and the refusal is returned so
// WriteVector latches it: this extension is inside the transcript hash, so a role byte silently
// written as something else is a fork the sender cannot see and cannot be told about.
func writeOneRoleEntry(w *syntax.Writer, entry RoleEntry) error {
	if !entry.Role.valid() {
		return fmt.Errorf("%w: role byte %d is not defined", ErrMalformedExtension, uint8(entry.Role))
	}
	w.WriteOpaque(entry.MemberId)
	w.WriteUint8(uint8(entry.Role))
	return nil
}

// readOneRoleEntry applies the same role byte gate as the encoder.
//
// The same gate and not a laxer one, because the alternative is that a hostile peer introduces a
// role byte this build renders as "unknown" and treats, everywhere a switch has a default, as an
// observer. A role this profile cannot act on is a policy this profile cannot enforce, so it is
// refused at the codec where the refusal names the extension.
func readOneRoleEntry(r *syntax.Reader) (RoleEntry, error) {
	memberId, err := r.ReadOpaque()
	if err != nil {
		return RoleEntry{}, err
	}
	roleByte, err := r.ReadUint8()
	if err != nil {
		return RoleEntry{}, err
	}
	role := Role(roleByte)
	if !role.valid() {
		return RoleEntry{}, fmt.Errorf("%w: role byte %d is not defined", ErrMalformedExtension, roleByte)
	}
	return RoleEntry{MemberId: memberId, Role: role}, nil
}

// writeOneDisappearingBucket and readOneDisappearingBucket are the bucket vector's element
// halves, named for the same reason the role entry's are. A bucket is an index into the group's
// configured disappearing timers and every uint8 is a legal one, so neither half has a refusal
// to make.
func writeOneDisappearingBucket(w *syntax.Writer, bucket uint8) error {
	w.WriteUint8(bucket)
	return nil
}

func readOneDisappearingBucket(r *syntax.Reader) (uint8, error) {
	return r.ReadUint8()
}

// MarshalMLS writes roles<V>, the retention pair, disappearing_buckets<V> and server_id<V>, in
// that order and no other: the field order IS the wire format and is what two implementations
// have to agree about.
func (self *GroupPolicyExtension) MarshalMLS(w *syntax.Writer) error {
	if err := syntax.WriteVector(w, self.Roles, writeOneRoleEntry); err != nil {
		return err
	}
	w.WriteUint64(self.RetentionPolicy.DurableMs)
	w.WriteUint64(self.RetentionPolicy.MediaMs)
	if err := syntax.WriteVector(w, self.DisappearingBuckets, writeOneDisappearingBucket); err != nil {
		return err
	}
	w.WriteOpaque(self.ServerId)
	return nil
}

// UnmarshalMLS reads the wire form and VALIDATES what it read before it hands anything back.
//
// The validation belongs here rather than in ParseGroupPolicyExtension, and that is a decision
// worth two sentences because the plan put it in the parser. Convention C1 says an MLS
// structure has exactly one byte level codec, syntax.Marshal and syntax.Unmarshal reached
// through this pair, and the gate that enforces it reads every declaration taking a byte run
// and answering a structure: a ParseX that does anything besides plumb its run into the codec
// IS a second decoder by that reading, whatever it was called. So the canonical checks live at
// the one decode every path shares, which is also where they are worth the most -- a policy
// nested inside some later structure is checked by the same code as one parsed from an
// extension body, rather than by whichever entry point its caller happened to use.
//
// The whole value is replaced rather than filled field by field, so a decode that refuses part
// way leaves the receiver as it was rather than holding half of two policies. The refusal is
// made against the decoded value BEFORE the assignment for the same reason.
func (self *GroupPolicyExtension) UnmarshalMLS(r *syntax.Reader) error {
	roles, err := syntax.ReadVector(r, readOneRoleEntry)
	if err != nil {
		return err
	}
	durableMs, err := r.ReadUint64()
	if err != nil {
		return err
	}
	mediaMs, err := r.ReadUint64()
	if err != nil {
		return err
	}
	buckets, err := syntax.ReadVector(r, readOneDisappearingBucket)
	if err != nil {
		return err
	}
	serverId, err := r.ReadOpaque()
	if err != nil {
		return err
	}
	decoded := GroupPolicyExtension{
		Roles:               roles,
		RetentionPolicy:     RetentionPolicy{DurableMs: durableMs, MediaMs: mediaMs},
		DisappearingBuckets: buckets,
		ServerId:            serverId,
	}
	if err := decoded.Validate(); err != nil {
		return err
	}
	*self = decoded
	return nil
}

// Canonicalize puts the role entries in the one order this extension has and refuses a member
// id that appears twice.
//
// It is a CONSTRUCTION side helper: a caller assembling a policy out of whatever order its
// members arrived in calls this, and after it Validate has one fewer way to fail. It does not
// judge the role bytes or the owner count, which are Validate's, so a policy that came back
// clean from here is not yet a policy that may be encoded.
//
// The duplicate is refused rather than merged. Merging would decide which of two roles one
// member holds, and that decision is a governance one this codec has no standing to make.
func (self *GroupPolicyExtension) Canonicalize() error {
	sortRolesByMemberId(self.Roles)
	for i := 1; i < len(self.Roles); i += 1 {
		if sameMemberId(self.Roles[i-1].MemberId, self.Roles[i].MemberId) {
			return fmt.Errorf("%w: member id appears twice", ErrDuplicateRoleEntry)
		}
	}
	return nil
}

// Validate enforces every invariant a group policy must satisfy before it may be encoded into a
// group context or acted on out of one: a defined role byte and a non empty member id on every
// entry, strictly ascending member ids, and exactly one owner.
//
// Each refusal is its own sentinel and no two share one, which is what lets a caller -- and a
// test -- tell them apart with errors.Is. They are checked in one pass rather than four, so the
// FIRST thing wrong with a policy is what a caller is told about, and the order of the clauses
// inside the loop is the order of severity: a malformed entry is reported as malformed rather
// than as the ordering failure it would also produce.
//
// The ordering and duplicate clauses are the same walk. A strictly ascending sequence has no
// duplicates by construction, so testing the pair's comparison once and branching on the sign is
// what keeps "sorted" and "no duplicates" from being two answers that can disagree.
func (self *GroupPolicyExtension) Validate() error {
	owners := 0
	for i, entry := range self.Roles {
		if !entry.Role.valid() {
			return fmt.Errorf("%w: role byte %d is not defined", ErrMalformedExtension, uint8(entry.Role))
		}
		if len(entry.MemberId) == 0 {
			return fmt.Errorf("%w: entry %d carries an empty member id", ErrMalformedExtension, i)
		}
		if i > 0 {
			order := compareMemberIds(self.Roles[i-1].MemberId, entry.MemberId)
			if order > 0 {
				return fmt.Errorf("%w: entry %d is out of order", ErrRolesNotCanonical, i)
			}
			if order == 0 {
				return fmt.Errorf("%w: entry %d repeats entry %d", ErrDuplicateRoleEntry, i, i-1)
			}
		}
		if entry.Role == RoleOwner {
			owners += 1
		}
	}
	if owners == 0 {
		return ErrNoOwner
	}
	if owners > 1 {
		return ErrMultipleOwners
	}
	return nil
}

// encodeUnchecked serializes without the policy gate in front of it.
//
// It is unexported and it stays that way. What it exists for is the tests that have to produce
// what a HOSTILE peer would send -- an unsorted role list, two owners -- which is the input the
// decode side's refusals are about and which the exported encoder will not build.
func (self *GroupPolicyExtension) encodeUnchecked() ([]byte, error) {
	return syntax.Marshal(self)
}

// Encode serializes to a group context Extension after validating, and answers the whole
// Extension -- the 0xF001 tag and the body together -- rather than the body on its own, for the
// reason LeafKeysExtension.Encode does: a loose body is a value a caller pairs with a tag of its
// own choosing, and 0xF002 is one identifier away.
func (self *GroupPolicyExtension) Encode() (Extension, error) {
	if err := self.Validate(); err != nil {
		return Extension{}, err
	}
	data, err := self.encodeUnchecked()
	if err != nil {
		return Extension{}, err
	}
	return Extension{ExtensionType: ExtensionTypeUrmessageGroupPolicy, ExtensionData: data}, nil
}

// ParseGroupPolicyExtension decodes and validates an extension body: the bytes of one entry's
// ExtensionData, not the entry itself.
//
// The order and duplicate checks DO run on the way in, and that is the whole value of having a
// canonical encoding -- a receiver that re-sorted a non canonical body would accept two
// spellings of one policy, and since this body is inside the group context that is two
// transcript hashes each end believes is the only one. They run inside UnmarshalMLS rather than
// here, which is what leaves this declaration as the bare plumbing convention C1 asks an entry
// point to be: it hands its run to the one codec and reports what came back, exactly as
// ParseMLSMessage does, and adds no second reading of the bytes for the codec to disagree with.
//
// What that costs is the wrapping the plan wrote here: a truncated or trailing body answers
// mls/syntax's own sentinel rather than ErrMalformedExtension. That is the more precise answer
// of the two -- ErrTruncated says the sender and this package disagree about the encoding,
// ErrMalformedExtension says they agree about it and the content is refused -- and the second
// is still what every content refusal carries.
//
// syntax.Unmarshal already joins the decoder's answer with Done, so a body with a tail is
// refused there and there is no separate trailing byte check here.
//
// It is handed the body and never sees the tag those bytes arrived under, so it cannot refuse a
// wrong one; that is ParseGroupPolicyFrom's job and it is the entry point a caller holding an
// Extension should reach for.
func ParseGroupPolicyExtension(data []byte) (*GroupPolicyExtension, error) {
	policy := &GroupPolicyExtension{}
	if err := syntax.Unmarshal(data, policy); err != nil {
		return nil, err
	}
	return policy, nil
}

// ParseGroupPolicyFrom decodes one extensions<V> entry as an urmessage_group_policy body,
// refusing any entry that is not tagged ExtensionTypeUrmessageGroupPolicy.
//
// The read side counterpart to Encode. Encode never emits a body without this tag on it and this
// never accepts a body under anybody else's, and between them a caller using the package as
// documented cannot pair a policy body with 0xF002 -- which would encode, be covered by the
// confirmed transcript hash, and be refused by the first peer that tried to read an X-Wing key
// out of a role list.
func ParseGroupPolicyFrom(ext Extension) (*GroupPolicyExtension, error) {
	if ext.ExtensionType != ExtensionTypeUrmessageGroupPolicy {
		return nil, fmt.Errorf("%w: extension type %#04x is not urmessage_group_policy",
			ErrMalformedExtension, uint16(ext.ExtensionType))
	}
	return ParseGroupPolicyExtension(ext.ExtensionData)
}

// RoleOf returns a member's role and whether the policy names them at all.
//
// The false answer is RoleObserver rather than some other zero value, and the two being the same
// byte is deliberate: a caller that drops the second result treats an unknown member as an
// observer, which is the least authority this profile has.
func (self *GroupPolicyExtension) RoleOf(memberId []byte) (Role, bool) {
	for _, entry := range self.Roles {
		if sameMemberId(entry.MemberId, memberId) {
			return entry.Role, true
		}
	}
	return RoleObserver, false
}

// SetRole inserts or replaces a member's role, keeping the canonical order.
//
// The inserted member id is COPIED. The policy outlives the caller's slice, it is encoded into a
// group context and covered by a transcript hash, and a caller that reused its buffer would
// change what the group agreed to after the fact.
func (self *GroupPolicyExtension) SetRole(memberId []byte, role Role) {
	for i := range self.Roles {
		if sameMemberId(self.Roles[i].MemberId, memberId) {
			self.Roles[i].Role = role
			return
		}
	}
	self.Roles = append(self.Roles, RoleEntry{MemberId: slices.Clone(memberId), Role: role})
	sortRolesByMemberId(self.Roles)
}

// RemoveRole drops a member from the role set. Removing a member the policy does not name is not
// an error: a Remove proposal for such a member is a no op here, and is refused, if it should
// be, by the removal authority check that reads this.
func (self *GroupPolicyExtension) RemoveRole(memberId []byte) {
	kept := make([]RoleEntry, 0, len(self.Roles))
	for _, entry := range self.Roles {
		if !sameMemberId(entry.MemberId, memberId) {
			kept = append(kept, entry)
		}
	}
	self.Roles = kept
}

// AdminCount is the number of ADMIN entries, and the owner is not one of them: MASTER section
// 11's succession quorum is over the current admins, and counting the owner into it would let a
// group with one admin and an owner meet a two admin quorum.
func (self *GroupPolicyExtension) AdminCount() int {
	count := 0
	for _, entry := range self.Roles {
		if entry.Role == RoleAdmin {
			count += 1
		}
	}
	return count
}

// OwnerId returns the single owner's member id. A validated policy has exactly one; this answers
// the first, so a policy that was never validated answers the first of however many it holds
// rather than pretending the question has one answer.
func (self *GroupPolicyExtension) OwnerId() ([]byte, bool) {
	for _, entry := range self.Roles {
		if entry.Role == RoleOwner {
			return entry.MemberId, true
		}
	}
	return nil, false
}

// Clone deep copies, down to every member id, so a staged commit can mutate a policy without
// touching the live epoch's. A shallow copy would share the Roles array, and SetRole on the
// staged copy would rewrite a role inside the epoch the group is still running.
func (self *GroupPolicyExtension) Clone() *GroupPolicyExtension {
	out := &GroupPolicyExtension{
		Roles:               make([]RoleEntry, len(self.Roles)),
		RetentionPolicy:     self.RetentionPolicy,
		DisappearingBuckets: slices.Clone(self.DisappearingBuckets),
		ServerId:            slices.Clone(self.ServerId),
	}
	for i, entry := range self.Roles {
		out.Roles[i] = RoleEntry{MemberId: slices.Clone(entry.MemberId), Role: entry.Role}
	}
	return out
}

// GroupPolicyOf finds and parses the policy in a group context extension list.
//
// Absence is ErrNoGroupPolicy and not ErrMalformedExtension, because the two name different
// groups: a context with no policy at all is one this profile did not create, and a context
// whose policy will not parse is one this profile created and cannot read.
//
// A list carrying 0xF001 TWICE is refused, and it is refused HERE because no other door in this
// build refuses it. RFC 9420 forbids a repeated extension type and this package hands that
// refusal to ValSem209 in three comments; ValSem209 is not implemented. What that left was an
// accessor answering one of two policies by iteration order over a list that is inside the
// CONFIRMED TRANSCRIPT HASH -- so both role sets are covered by every confirmation tag the group
// has ever produced, both are what the group agreed to by the transcript's reckoning, and which
// one a member enforces is decided by nothing. A member reading the first and a member reading
// the second disagree about who may remove whom while agreeing on every hash. Refusing is the
// only answer that does not fork the group's governance silently, and it is also what makes the
// walk direction stop mattering: at most one entry reaches the parse.
func GroupPolicyOf(exts []Extension) (*GroupPolicyExtension, error) {
	// the whole vector before the parse, for LeafKeysOf's reason: a scan that returned at the
	// first match cannot see the second, so it cannot refuse the pair.
	found := -1
	for i := range exts {
		if exts[i].ExtensionType != ExtensionTypeUrmessageGroupPolicy {
			continue
		}
		if found >= 0 {
			return nil, fmt.Errorf("%w: the extension list carries urmessage_group_policy at entry %d and again at entry %d",
				ErrMalformedExtension, found, i)
		}
		found = i
	}
	if found < 0 {
		return nil, ErrNoGroupPolicy
	}
	return ParseGroupPolicyFrom(exts[found])
}
