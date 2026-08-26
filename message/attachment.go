// The server attachment: the one structured field of a record the server is allowed to
// read, and the one encoding both ends of that conversation share.
//
// Spec A section 5.11 is normative and spec B section 5.4 restates it character for
// character. The two agree, and the block below is theirs:
//
//	server_attachment := u16(kind) ‖ LP(body)
//
//	  kind 0x0000  NONE            body is zero length, and no conforming encoder writes it
//	  kind 0x0001  EpochAttachment carried by, and only by, a record with is_commit = 1
//	  kind 0x0002  RecoveryTag     carried by RECOVERY_PUB records and by recovery wraps
//	  kind 0x0003  WrapTag         carried by per device epoch wraps and by the snapshot
//	  kind 0x0004  EpochComplete   carried by the wrap set complete marker record
//
//	EpochAttachment := u64(epoch) ‖ u16(alg_id) ‖ LP(write_key) ‖ LP(read_key)
//	                 ‖ u32(media_ttl_seconds) ‖ u32(durable_ttl_seconds)
//	                 ‖ LP(group_context_hash) ‖ u32(expected_wrap_count)
//	RecoveryTag     := LP(recovery_handle) ‖ LP(recovery_verify_pub) ‖ u16(alg_id)
//	WrapTag         := LP(wrap_target_handle) ‖ u64(epoch)
//	EpochComplete   := u64(epoch) ‖ u32(wrap_count)
//
// codec.go states the rule that generated a layout and it holds here too: a field whose
// width is fixed by its go type encodes raw at that width, and a field whose length varies
// encodes as LP(x). That rule is what decides the go types below rather than the other way
// round. Section 5.11 writes LP on write_key, read_key, group_context_hash,
// recovery_handle, recovery_verify_pub and wrap_target_handle even though it gives each
// one an exact width in the same line, and aad_test.go's commit vector already pins those
// four octet prefixes on the wire — so each of the six is a slice here and not an array,
// and its width is checked rather than typed. An array would have made the rule and the
// spec disagree about the bytes, and the bytes are not the negotiable half.
//
// The same choice is what makes spec B section 5.1 check 3 answerable at all. That check
// is normative and it is the server's whole static defence — "server_attachment parses via
// message.ParseServerAttachment and is well formed for its record kind" — and every clause
// of it is phrased as a question about a value that could have been otherwise: write_key
// exactly 32 bytes, a 32 byte Ed25519 pub on RecoveryTag, a 16 byte target on WrapTag. A
// [32]byte field turns those into questions no caller can ask and no attacker can fail.
//
// Three decisions in here cannot be found by reading the code, and each is a place two
// implementations would otherwise diverge silently.
//
// The first is the absent attachment. An ordinary record carries a zero length
// server_attachment — the field is empty — and NOT a kind 0x0000 with an empty body. Both
// specs say so in the same words and section 5.11's test obligation says why in one line:
// a zero length attachment and an AttachmentNone attachment must encode identically "so
// H(server_attachment) cannot differ between client and server for an ordinary record".
// So EncodeServerAttachment answers no bytes at all for AttachmentNone and for a nil
// attachment alike, aad.go hashes whatever those bytes are with no carve out, and the
// ordinary record's LP(H(server_attachment)) is LP(SHA-256("")) on both sides. The
// consequence for the parser is the part neither spec writes down: the six octet encoding
// 0x0000 followed by an empty LP body is REFUSED here rather than parsed as
// AttachmentNone. It has to be. If it parsed, one attachment would have two encodings
// whose hashes differ, the write_auth mac and both aeads are over exactly one of them, and
// a record built by a client that emitted the long form is a record the server hashes
// differently and rejects as a bad mac — the intermittent, undiagnosable failure spec B
// section 12.1 A-1 exists to prevent. Refusing it is also the only reading under which
// parsing either fails or re-encodes to the identical bytes, which is the property the
// fuzz target asserts.
//
// The second is the unknown kind. It is a decode error and never a silently ignored
// attachment. Check 3 is what stands between a record and the database, and an attachment
// the server cannot parse is one it cannot check: a record carrying kind 0x0005 that
// parsed to "nothing worth looking at" would take the epoch key install path, the recovery
// index and the wrap index with it, all of them unexamined. The same rule applies on the
// encode side, so a caller cannot build one either.
//
// The third is durable_ttl_seconds, and it is the check most likely to be added by
// somebody being careful. It has TWO wire sentinels and both are legal here: 0 means the
// group set nothing and the server applies its own advertised text default, and 0xFFFFFFFF
// means the group asked for indefinite retention, which a server with a cap clamps DOWN to
// that cap. Spec B section 7.3 case 3 forbids refusing either, in all cases, and section
// 5.1 check 3 says so again in the check that calls this function. They are resolved at
// spec B section 6.1 step (6), which is the server's arithmetic over its own advertised
// policy and nothing this layer can compute. So the range check on both retention fields
// is the u32 they are typed as, and there is deliberately no comparison against either
// sentinel anywhere in this file. A refusal here would refuse a commit, and a refused
// commit is a group that cannot rekey.
//
// One clause of check 3 is not here and cannot be. "EpochAttachment iff is_commit" is a
// question about the record's header and the attachment together, and this function is
// handed the attachment alone — the server holds both, has already parsed the header
// through ParseRecord, and asks that one itself. Everything check 3 says it will rely on
// about the attachment's own contents is answered here so the server never re-derives it,
// which is spec B section 12.1 A-2: the server "parses them with
// message.ParseServerAttachment and never reimplements them".
package message

import (
	"fmt"

	"github.com/urnetwork/connect/mls/syntax"
)

// The kind discriminator, u16 on the wire.
type ServerAttachmentKind uint16

// The five kinds spec A section 5.11 defines. The codes are the spec's; nothing here may
// renumber them, because they reach the write_auth mac and both aeads by way of
// H(server_attachment) and a renumbering is a record every other implementation refuses.
const (
	AttachmentNone     ServerAttachmentKind = 0x0000
	AttachmentEpoch    ServerAttachmentKind = 0x0001
	AttachmentRecovery ServerAttachmentKind = 0x0002
	AttachmentWrap     ServerAttachmentKind = 0x0003
	AttachmentComplete ServerAttachmentKind = 0x0004
)

// The kinds this package knows, as a lookup rather than a chain of comparisons, for the
// reason record.go's classPrunable is one: a kind added later has to be given an answer
// here instead of inheriting one from whichever side of a bound it happens to fall.
var serverAttachmentKindKnown = map[ServerAttachmentKind]bool{
	AttachmentNone:     true,
	AttachmentEpoch:    true,
	AttachmentRecovery: true,
	AttachmentWrap:     true,
	AttachmentComplete: true,
}

// The exact widths spec A section 5.11 gives the six length prefixed fields. Written as
// named constants rather than as the array widths of go types, because the fields are
// slices — see the file comment — so the width is a value this file checks and not a
// property the compiler enforces.
const (
	epochWriteKeyBytes         = 32
	epochReadKeyBytes          = 32
	epochGroupContextHashBytes = 32
	recoveryHandleBytes        = 16
	recoveryVerifyPubBytes     = 32
	wrapTargetHandleBytes      = 16
)

// The algorithm identifier each kind that carries one names, from master section 7.1's
// registry: 0x0031 is HKDF-SHA-256, which is what derived write_key and read_key, and
// 0x0001 is Ed25519, which is what recovery_verify_pub verifies under. A table keyed by
// kind rather than a constant per body, so "known alg_id" is one question asked in one
// place and a kind that grows an alg_id later is given its answer here.
//
// The identifiers are pinned per kind and not to the registry as a whole. An
// EpochAttachment announcing 0x0001 would be claiming its two 32 octet keys came out of a
// signature algorithm, which is not a v1 record with an unusual field but a record built
// by something that does not know what the field is for.
var attachmentAlgIds = map[ServerAttachmentKind]uint16{
	AttachmentEpoch:    0x0031,
	AttachmentRecovery: 0x0001,
}

// The epoch attachment: everything the server needs in order to verify the epoch this
// commit opens, delivered inside the commit that opens it (spec B section 5.3).
type EpochAttachment struct {
	// The epoch this attachment OPENS, which spec B section 5.1 check 3 requires to be
	// current_epoch + 1. That comparison is the server's — it is the party that holds
	// current_epoch — and is deliberately not made here.
	Epoch uint64
	AlgId uint16
	// write_key[epoch], exactly 32 octets. The server holds it and can therefore forge
	// write_auth, which spec B section 5.3 states as an accepted consequence rather than a
	// defect: it is the party enforcing write_auth in the first place.
	WriteKey []byte
	// read_key[epoch], exactly 32 octets, and a different value in every epoch. Spec B
	// section 5.1 check 3 says in as many words that it is "never compared against a
	// previously installed one"; the server installs it against this epoch and retains it
	// for ninety days.
	ReadKey []byte
	// Both retention fields are the whole u32 range, both of durable's sentinels included.
	// The file comment says why there is no check here and why adding one refuses commits.
	MediaTtlSeconds   uint32
	DurableTtlSeconds uint32
	GroupContextHash  []byte
	// Device wraps plus recovery wraps plus the one snapshot, for the epoch this opens.
	// Greater than zero, always: the epoch it opens has at least the snapshot in it, and a
	// zero would name a wrap set the EpochComplete marker can never match, leaving the
	// group readable but not writable with nothing able to close it.
	ExpectedWrapCount uint32
}

// The recovery tag: the handle the server indexes recovery wraps by, and the public half
// the client — never the server — verifies the RECOVERY_PUB body signature under.
type RecoveryTag struct {
	RecoveryHandle []byte
	// Ed25519, exactly 32 octets. Spec B section 5.4 is exact about what authenticating
	// this proves: write_auth is group wide, so it proves a current member submitted the
	// record and not that the member owns the handle. The server keeps the first pub it
	// sees for a handle within one group and refuses a later differing one.
	RecoveryVerifyPub []byte
	AlgId             uint16
}

// The wrap tag: the target a per device wrap or the epoch snapshot is served to, which is
// what lets the server answer a WrapFetch in constant time without being able to invert
// the handle.
type WrapTag struct {
	WrapTargetHandle []byte
	// The epoch whose wrap or snapshot this record carries.
	Epoch uint64
}

// The marker that closes an epoch's fan out. Until it lands the group is readable but not
// writable and the server refuses every non wrap submit at the new epoch.
type EpochComplete struct {
	Epoch uint64
	// Required to equal that epoch's EpochAttachment.expected_wrap_count. The equality is
	// the server's, because it is the party holding the attachment this marker is about,
	// and it is not restated here as a bound of its own.
	WrapCount uint32
}

// One parsed attachment: the kind, and the one body that kind carries.
//
// Four pointers and a tag rather than an interface, because this is the shape spec A
// section 5.11 publishes and spec B section 12.1 restates, and the server switches on the
// tag. The rule that keeps the two halves from disagreeing is that exactly one body is set
// and it is the one the tag names — checkServerAttachment enforces it in both directions,
// so an attachment carrying an EpochAttachment under the WrapTag tag is refused rather
// than encoded as a wrap tag with the epoch attachment quietly dropped.
type ServerAttachment struct {
	Kind     ServerAttachmentKind
	Epoch    *EpochAttachment
	Recovery *RecoveryTag
	Wrap     *WrapTag
	Complete *EpochComplete
}

// The kind the bodies actually set say this is, and how many of them are set.
//
// It is the presence rule computed rather than asserted: a fifth kind added later with a
// fifth pointer that nobody wires in here is an attachment whose bodies say
// AttachmentNone while its tag says otherwise, which checkServerAttachment refuses. The
// alternative — a presence check written out per kind — is the one that lets a new kind
// through unchecked, which is the shape this package refuses to have.
func (self *ServerAttachment) bodyKind() (ServerAttachmentKind, int) {
	kind := AttachmentNone
	set := 0
	if self.Epoch != nil {
		kind, set = AttachmentEpoch, set+1
	}
	if self.Recovery != nil {
		kind, set = AttachmentRecovery, set+1
	}
	if self.Wrap != nil {
		kind, set = AttachmentWrap, set+1
	}
	if self.Complete != nil {
		kind, set = AttachmentComplete, set+1
	}
	return kind, set
}

// EncodeServerAttachment serialises an attachment into the layout at the top of this file.
//
// A nil attachment and an AttachmentNone attachment both answer no bytes at all. That is
// the absent/empty equivalence spec A section 5.11's test obligation names, and it is why
// this function is the one place in the package where nil is an ordinary argument rather
// than the caller bug ErrRecordNil reports: an ordinary record has no attachment, and the
// bytes it contributes to LP(H(server_attachment)) have to be the same bytes a client
// holding an explicit AttachmentNone contributes.
//
// It refuses everything its own parser refuses, through the same checkServerAttachment, so
// there is no attachment this package will write and then fail to read back.
func EncodeServerAttachment(a *ServerAttachment) ([]byte, error) {
	if a == nil {
		return nil, nil
	}
	if err := checkServerAttachment(a); err != nil {
		return nil, err
	}
	if a.Kind == AttachmentNone {
		return nil, nil
	}
	writer := syntax.NewWriter()
	writer.WriteUint16(uint16(a.Kind))
	// LP(body), through the one nesting form that frames a structure inside the record
	// layer's fixed 32 bit prefix. The region is built and then framed by its own length,
	// so the prefix cannot drift from the bytes it counts.
	if err := writer.WriteNestedLP(func(body *syntax.Writer) error {
		writeAttachmentBody(body, a)
		return nil
	}); err != nil {
		return nil, err
	}
	// the writer is sticky: the first failure latches and every later call is a no op, so
	// this is the one place the encode is asked whether it worked.
	return writer.Bytes()
}

// ParseServerAttachment deserialises the layout at the top of this file and validates
// everything spec B section 5.1 check 3 says it will rely on.
//
// Empty input is the absent attachment and answers AttachmentNone with no body, which is
// what every ordinary record carries. The six octet spelling of the same thing is refused;
// the file comment argues it.
//
// The returned attachment has exactly one body set, and it is the one Kind names.
func ParseServerAttachment(b []byte) (*ServerAttachment, error) {
	if len(b) == 0 {
		return &ServerAttachment{Kind: AttachmentNone}, nil
	}
	reader := syntax.NewReader(b)
	// the reader is sticky, so the kind's own failure latches and is reported by the
	// nesting below rather than here: a one octet input reports that it was truncated
	// instead of reporting whatever half a kind happens to be.
	kind, _ := reader.ReadUint16()
	attachment := &ServerAttachment{Kind: ServerAttachmentKind(kind)}
	// ReadNestedLP runs the body's field list against a reader bounded by the declared
	// region and then runs that reader to empty, so a body region longer than the fields
	// inside it is a refusal rather than a second encoding of one attachment.
	if err := reader.ReadNestedLP(func(body *syntax.Reader) error {
		return readAttachmentBody(body, attachment)
	}); err != nil {
		return nil, err
	}
	if err := reader.Done(); err != nil {
		return nil, err
	}
	if err := checkServerAttachment(attachment); err != nil {
		return nil, err
	}
	return attachment, nil
}

// The body of one attachment, in the field order at the top of this file. Total by
// construction: the caller has already been through checkServerAttachment, so the kind is
// known and the body it names is set, and the switch has no case left to fall out of.
func writeAttachmentBody(w *syntax.Writer, a *ServerAttachment) {
	switch a.Kind {
	case AttachmentEpoch:
		w.WriteUint64(a.Epoch.Epoch)
		w.WriteUint16(a.Epoch.AlgId)
		w.WriteOpaqueLP(a.Epoch.WriteKey)
		w.WriteOpaqueLP(a.Epoch.ReadKey)
		w.WriteUint32(a.Epoch.MediaTtlSeconds)
		w.WriteUint32(a.Epoch.DurableTtlSeconds)
		w.WriteOpaqueLP(a.Epoch.GroupContextHash)
		w.WriteUint32(a.Epoch.ExpectedWrapCount)
	case AttachmentRecovery:
		w.WriteOpaqueLP(a.Recovery.RecoveryHandle)
		w.WriteOpaqueLP(a.Recovery.RecoveryVerifyPub)
		w.WriteUint16(a.Recovery.AlgId)
	case AttachmentWrap:
		w.WriteOpaqueLP(a.Wrap.WrapTargetHandle)
		w.WriteUint64(a.Wrap.Epoch)
	case AttachmentComplete:
		w.WriteUint64(a.Complete.Epoch)
		w.WriteUint32(a.Complete.WrapCount)
	}
}

// The body of one attachment, read back.
//
// The reads are a straight run because the reader is sticky: the first failure latches,
// every later read is a no op, and the bounded region is asked whether it was well formed
// exactly once, by the Done that ReadNestedLP runs on it. Nothing here is validated as a
// value — that is checkServerAttachment's, once, for both sides of the codec — so a
// truncated body reports that it was truncated rather than reporting whichever field read
// off the end happened to land somewhere illegal.
func readAttachmentBody(r *syntax.Reader, a *ServerAttachment) error {
	switch a.Kind {
	case AttachmentNone:
		return fmt.Errorf("%w: an absent attachment is the empty field and not %d octets under kind 0x%04x",
			ErrServerAttachmentNoneEncoded, r.Remaining(), uint16(AttachmentNone))
	case AttachmentEpoch:
		epoch := &EpochAttachment{}
		epoch.Epoch, _ = r.ReadUint64()
		epoch.AlgId, _ = r.ReadUint16()
		epoch.WriteKey, _ = r.ReadOpaqueLP()
		epoch.ReadKey, _ = r.ReadOpaqueLP()
		epoch.MediaTtlSeconds, _ = r.ReadUint32()
		epoch.DurableTtlSeconds, _ = r.ReadUint32()
		epoch.GroupContextHash, _ = r.ReadOpaqueLP()
		epoch.ExpectedWrapCount, _ = r.ReadUint32()
		a.Epoch = epoch
		return nil
	case AttachmentRecovery:
		recovery := &RecoveryTag{}
		recovery.RecoveryHandle, _ = r.ReadOpaqueLP()
		recovery.RecoveryVerifyPub, _ = r.ReadOpaqueLP()
		recovery.AlgId, _ = r.ReadUint16()
		a.Recovery = recovery
		return nil
	case AttachmentWrap:
		wrap := &WrapTag{}
		wrap.WrapTargetHandle, _ = r.ReadOpaqueLP()
		wrap.Epoch, _ = r.ReadUint64()
		a.Wrap = wrap
		return nil
	case AttachmentComplete:
		complete := &EpochComplete{}
		complete.Epoch, _ = r.ReadUint64()
		complete.WrapCount, _ = r.ReadUint32()
		a.Complete = complete
		return nil
	}
	return fmt.Errorf("%w: 0x%04x, and an attachment this layer cannot parse is one the server cannot check",
		ErrServerAttachmentKindUnknown, uint16(a.Kind))
}

// The structural invariants, run by both sides of the codec so that the set of attachments
// this package will write and the set it will read are the same set.
//
// Everything spec B section 5.1 check 3 asks of an attachment's own contents is here and
// nowhere else, so the server asks rather than re-derives. What is deliberately absent is
// as load bearing as what is present: no comparison against either durable_ttl_seconds
// sentinel, no bound on media_ttl_seconds, no epoch arithmetic, and no wrap_count equality
// — each of those is either the server's own policy or a fact about state this layer never
// sees, and a refusal invented here would refuse a commit the spec calls valid.
func checkServerAttachment(a *ServerAttachment) error {
	if !serverAttachmentKindKnown[a.Kind] {
		return fmt.Errorf("%w: 0x%04x, and an attachment this layer cannot parse is one the server cannot check",
			ErrServerAttachmentKindUnknown, uint16(a.Kind))
	}
	carried, set := a.bodyKind()
	if 1 < set || carried != a.Kind {
		return fmt.Errorf("%w: kind 0x%04x carries %d bodies, the last of them kind 0x%04x",
			ErrServerAttachmentBody, uint16(a.Kind), set, uint16(carried))
	}
	switch a.Kind {
	case AttachmentEpoch:
		return checkEpochAttachment(a.Epoch)
	case AttachmentRecovery:
		return checkRecoveryTag(a.Recovery)
	case AttachmentWrap:
		return checkWrapTag(a.Wrap)
	case AttachmentComplete:
		return checkEpochComplete(a.Complete)
	}
	return nil
}

// The epoch attachment's own checks: three exact widths, the algorithm identifier its kind
// names, and a wrap set with something in it.
func checkEpochAttachment(e *EpochAttachment) error {
	if err := checkAttachmentAlgId(AttachmentEpoch, e.AlgId); err != nil {
		return err
	}
	if err := checkAttachmentWidth("write_key", e.WriteKey, epochWriteKeyBytes); err != nil {
		return err
	}
	if err := checkAttachmentWidth("read_key", e.ReadKey, epochReadKeyBytes); err != nil {
		return err
	}
	if err := checkAttachmentWidth("group_context_hash", e.GroupContextHash, epochGroupContextHashBytes); err != nil {
		return err
	}
	// spec B section 5.1 check 3 names this one outright. An epoch opens with at least its
	// own snapshot in the wrap set, so zero is not a small fan out but a marker condition
	// no EpochComplete can ever satisfy: the group would stay readable and unwritable with
	// nothing able to close it.
	if e.ExpectedWrapCount == 0 {
		return fmt.Errorf("%w: the epoch it opens expects no wraps at all, and its own snapshot is one",
			ErrExpectedWrapCountZero)
	}
	return nil
}

// The recovery tag's own checks: the handle the server indexes by, the Ed25519 public half
// the client verifies under, and the algorithm identifier that says which signature scheme
// that is.
func checkRecoveryTag(t *RecoveryTag) error {
	if err := checkAttachmentAlgId(AttachmentRecovery, t.AlgId); err != nil {
		return err
	}
	if err := checkAttachmentWidth("recovery_handle", t.RecoveryHandle, recoveryHandleBytes); err != nil {
		return err
	}
	return checkAttachmentWidth("recovery_verify_pub", t.RecoveryVerifyPub, recoveryVerifyPubBytes)
}

// The wrap tag's own check: the 16 octet target the server serves a wrap by.
func checkWrapTag(t *WrapTag) error {
	return checkAttachmentWidth("wrap_target_handle", t.WrapTargetHandle, wrapTargetHandleBytes)
}

// The marker carries a u64 and a u32 and no field with a width to get wrong. Its one rule
// — that wrap_count equals the epoch's expected_wrap_count — is an equality against an
// attachment this layer is never handed, so it belongs to the server and is not restated
// here as a bound this function could only guess at.
//
// Which leaves the nil guard as the whole body, and it reads as the odd one out beside
// checkEpochAttachment, checkRecoveryTag and checkWrapTag, all three of which dereference
// the body they are handed without one. No input reaches it: checkServerAttachment runs the
// presence rule first, and bodyKind names AttachmentComplete only when Complete is set, so
// the marker's body is never nil by the time this is called. It stays for two reasons that
// outrank the symmetry. It fails closed if the presence rule is ever loosened, which is the
// only direction that edit goes. And it is the one thing this body does with the argument it
// is handed — take it out and the function ignores its own parameter, which is the
// placeholder shape mls/crypto_test.go's TestNoStubShapesRemainInSource refuses across this
// package and that one. The three siblings read their body because they have a width to
// check against; this one reads its body because a body with nothing to check is what is
// left to read.
func checkEpochComplete(c *EpochComplete) error {
	if c == nil {
		return fmt.Errorf("%w: kind 0x%04x carries no body", ErrServerAttachmentBody, uint16(AttachmentComplete))
	}
	return nil
}

// One length prefixed field against the exact width spec A section 5.11 gives it.
//
// One sentinel across all six, wrapped with the field's name and both counts, for the
// reason ErrBlobIdPresence is one sentinel across both directions of its rule: they are one
// rule — a field of this attachment is the width the spec gives it — and a caller that told
// them apart would be acting on a distinction the wire does not carry.
func checkAttachmentWidth(name string, field []byte, want int) error {
	if len(field) != want {
		return fmt.Errorf("%w: %s is %d octets, want exactly %d", ErrServerAttachmentFieldLength, name, len(field), want)
	}
	return nil
}

// One kind's algorithm identifier against the one master section 7.1 registers for it.
func checkAttachmentAlgId(kind ServerAttachmentKind, algId uint16) error {
	want, named := attachmentAlgIds[kind]
	if !named {
		return fmt.Errorf("%w: kind 0x%04x names no algorithm identifier and was asked about 0x%04x",
			ErrServerAttachmentAlgId, uint16(kind), algId)
	}
	if algId != want {
		return fmt.Errorf("%w: kind 0x%04x carries 0x%04x, want 0x%04x", ErrServerAttachmentAlgId, uint16(kind), algId, want)
	}
	return nil
}
