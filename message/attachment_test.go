// The server attachment: the layout, the four kinds, and the properties that keep the
// server's static shape check and the client's encoder from drifting apart.
//
// Six things are observed here and they fail in different directions.
//
// The first is that the bytes are the layout spec A section 5.11 states. A round trip
// cannot see this — an encoder and a decoder that agree on a permuted field order round
// trip perfectly and agree with nobody — so the layout is written down a second time, in
// rawAttachment and its four raw bodies below, and every corpus attachment's encoding is
// compared against it. rawAttachment is also how this file reaches the encodings the
// encoder refuses to produce: a 31 octet Ed25519 pub, an expected_wrap_count of zero, the
// absent attachment spelled out as kind 0x0000, a kind nothing defines. But rawAttachment
// lives beside the encoder, so a permutation applied to both at once passes it; the
// anchors that do not move with the code are the four golden vectors, one per kind, each
// a hexadecimal string derived by hand from section 5.11's block with the arithmetic shown
// beside every line. The EpochAttachment vector is the strongest of the four and not by a
// little: it is byte for byte the attachment aad_test.go already pins, whose digest that
// file's comment records as having been derived by a separate program that imports nothing
// from this package. Agreeing with it is agreement with something that is not this
// encoder.
//
// The second is that the kind alphabet is exactly the five codes section 5.11 defines, and
// that each code means what the spec says it means. Both halves are derived: the encodable
// set by offering the encoder all 65536 kind codes crossed with every body shape this
// package has, and the parsable set by taking each kind's own valid encoding and replacing
// its leading u16 with each of the 65536 values in turn. What those derivations are
// compared against is the one place the meanings are written down, specAttachmentKindCodes,
// because a permuted table round trips perfectly and agrees with nobody — swap
// AttachmentEpoch and AttachmentRecovery in the constants and every property in this file
// but that one still holds, while every record either kind rides on carries a kind octet
// pair inside H(server_attachment), inside both aeads and inside the write_auth mac that no
// other implementation reproduces.
//
// The third is that the round trip is byte exact over a corpus that is a cross product
// rather than a list. The axes are every kind, the u64 boundaries on every 64 bit field,
// the u32 boundaries on every 32 bit field — both durable_ttl_seconds sentinels among them
// — and three content rotations across the six length prefixed fields, so that two same
// width fields never hold the same octets and a swapped encode order has somewhere to show.
//
// The fourth is that nothing is silently accepted and changed. Every single octet
// truncation of every valid encoding is refused, every trailing octet is refused, and every
// single octet corruption either is refused or re-encodes to exactly the corrupted bytes.
// That last one is what catches a field read at the wrong width, which is the one defect a
// round trip over well formed attachments cannot see: read expected_wrap_count as a u16 and
// every attachment this package writes still round trips, because the two octets it ignores
// are two octets it also never wrote.
//
// The fifth is the validation spec B section 5.1 check 3 says it will rely on, asserted as
// two claims rather than one. What must be refused: every length but the exact one on every
// length prefixed field — a class read off the go types by reflection rather than listed, so
// a seventh such field added later is covered the day it is declared — every algorithm
// identifier but the one its kind names, an expected_wrap_count of zero, an unknown kind,
// and the absent attachment spelled out. And what must NOT be refused, which is the half a
// hand written range check breaks silently: both durable_ttl_seconds sentinels, 0 and
// 4294967295, and every other value of both retention fields. Spec B section 7.3 case 3
// forbids refusing either sentinel in all cases, and a commit refused here is a group that
// cannot rekey.
//
// The sixth is the absent attachment. EncodeServerAttachment(nil) and an AttachmentNone
// attachment produce the identical zero length bytes, and therefore the identical
// H(server_attachment), which is section 5.11's test obligation stated from this side of
// aad.go's vector. It is asserted on the hash and not only on the bytes, because the hash
// is what actually reaches the mac.
//
// Beneath all six is the fuzz target and the corpus checked in beside it. Every byte string
// above was chosen by something in this file; the corpus carries the near miss framings a
// byte walk does not produce, and a plain go test replays them.
package message

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// ── the layout, written down a second time ──────────────────────────────────────────

// The framing every encoding carries whatever its kind: the u16 kind and the 32 bit length
// prefix of the body. Written as that sum so a reader can check it against section 5.11's
// server_attachment line term by term rather than against a number.
const attachmentFramingBytes = 2 + 4

// An attachment as raw values, in section 5.11's field order.
//
// This is the layout stated independently of the code under test, and it is what makes the
// encoding pinnable at all: swap two same width fields in both writeAttachmentBody and
// readAttachmentBody and every round trip in this file still passes, because the package
// would agree with itself perfectly and with no other implementation. It is also the only
// way to build the encodings EncodeServerAttachment will not — a key one octet short, a
// kind nothing defines — and those are exactly the inputs the parser's refusals are about.
type rawAttachment struct {
	kind uint16
	body []byte
}

// The bytes this raw attachment is. It writes what it is given, including a kind and a body
// the codec would refuse, which is what it is for.
func (self rawAttachment) encode(t testing.TB) []byte {
	t.Helper()
	writer := syntax.NewWriter()
	writer.WriteUint16(self.kind)
	writer.WriteOpaqueLP(self.body)
	bs, err := writer.Bytes()
	if err != nil {
		t.Fatalf("the raw attachment does not encode: %v", err)
	}
	return bs
}

// The epoch attachment's body as raw values.
type rawEpochAttachment struct {
	epoch             uint64
	algId             uint16
	writeKey          []byte
	readKey           []byte
	mediaTtlSeconds   uint32
	durableTtlSeconds uint32
	groupContextHash  []byte
	expectedWrapCount uint32
}

func (self rawEpochAttachment) encode(t testing.TB) []byte {
	t.Helper()
	writer := syntax.NewWriter()
	writer.WriteUint64(self.epoch)
	writer.WriteUint16(self.algId)
	writer.WriteOpaqueLP(self.writeKey)
	writer.WriteOpaqueLP(self.readKey)
	writer.WriteUint32(self.mediaTtlSeconds)
	writer.WriteUint32(self.durableTtlSeconds)
	writer.WriteOpaqueLP(self.groupContextHash)
	writer.WriteUint32(self.expectedWrapCount)
	bs, err := writer.Bytes()
	if err != nil {
		t.Fatalf("the raw epoch attachment does not encode: %v", err)
	}
	return bs
}

// The recovery tag's body as raw values.
type rawRecoveryTag struct {
	recoveryHandle    []byte
	recoveryVerifyPub []byte
	algId             uint16
}

func (self rawRecoveryTag) encode(t testing.TB) []byte {
	t.Helper()
	writer := syntax.NewWriter()
	writer.WriteOpaqueLP(self.recoveryHandle)
	writer.WriteOpaqueLP(self.recoveryVerifyPub)
	writer.WriteUint16(self.algId)
	bs, err := writer.Bytes()
	if err != nil {
		t.Fatalf("the raw recovery tag does not encode: %v", err)
	}
	return bs
}

// The wrap tag's body as raw values.
type rawWrapTag struct {
	wrapTargetHandle []byte
	epoch            uint64
}

func (self rawWrapTag) encode(t testing.TB) []byte {
	t.Helper()
	writer := syntax.NewWriter()
	writer.WriteOpaqueLP(self.wrapTargetHandle)
	writer.WriteUint64(self.epoch)
	bs, err := writer.Bytes()
	if err != nil {
		t.Fatalf("the raw wrap tag does not encode: %v", err)
	}
	return bs
}

// The marker's body as raw values.
type rawEpochComplete struct {
	epoch     uint64
	wrapCount uint32
}

func (self rawEpochComplete) encode(t testing.TB) []byte {
	t.Helper()
	writer := syntax.NewWriter()
	writer.WriteUint64(self.epoch)
	writer.WriteUint32(self.wrapCount)
	bs, err := writer.Bytes()
	if err != nil {
		t.Fatalf("the raw epoch complete does not encode: %v", err)
	}
	return bs
}

// One go attachment as raw values, so a test can take a valid attachment, change one field
// to something the encoder refuses, and still reach the parser with it.
//
// AttachmentNone answers the empty raw form, which encodes to the six octets that spell the
// absent attachment out — an encoding this package refuses to read and never writes, and
// therefore one only this builder can produce.
func rawAttachmentOf(t testing.TB, a *ServerAttachment) rawAttachment {
	t.Helper()
	raw := rawAttachment{kind: uint16(a.Kind)}
	switch {
	case a.Epoch != nil:
		raw.body = rawEpochAttachment{
			epoch:             a.Epoch.Epoch,
			algId:             a.Epoch.AlgId,
			writeKey:          a.Epoch.WriteKey,
			readKey:           a.Epoch.ReadKey,
			mediaTtlSeconds:   a.Epoch.MediaTtlSeconds,
			durableTtlSeconds: a.Epoch.DurableTtlSeconds,
			groupContextHash:  a.Epoch.GroupContextHash,
			expectedWrapCount: a.Epoch.ExpectedWrapCount,
		}.encode(t)
	case a.Recovery != nil:
		raw.body = rawRecoveryTag{
			recoveryHandle:    a.Recovery.RecoveryHandle,
			recoveryVerifyPub: a.Recovery.RecoveryVerifyPub,
			algId:             a.Recovery.AlgId,
		}.encode(t)
	case a.Wrap != nil:
		raw.body = rawWrapTag{
			wrapTargetHandle: a.Wrap.WrapTargetHandle,
			epoch:            a.Wrap.Epoch,
		}.encode(t)
	case a.Complete != nil:
		raw.body = rawEpochComplete{
			epoch:     a.Complete.Epoch,
			wrapCount: a.Complete.WrapCount,
		}.encode(t)
	}
	return raw
}

// ── the kind alphabet, written down once ────────────────────────────────────────────

// The five kind codes of spec A section 5.11 and what each one names. This is the one place
// in this file the MEANING of a code is written down; every set of codes below is derived
// from the package's own answers and compared against this.
//
// It has to be written down, because nothing derived can pin it. Swap AttachmentEpoch and
// AttachmentRecovery in the constants and every code still round trips, every kind is still
// distinct, the parser still refuses everything it should — the package agrees with itself
// perfectly, and the records it writes carry a kind inside H(server_attachment), inside
// aad_head and inside the write_auth preimage that no other implementation reproduces, so
// every commit and every recovery publication fails at a mac nobody can see into.
var specAttachmentKindCodes = map[ServerAttachmentKind]uint16{
	AttachmentNone:     0x0000,
	AttachmentEpoch:    0x0001,
	AttachmentRecovery: 0x0002,
	AttachmentWrap:     0x0003,
	AttachmentComplete: 0x0004,
}

// The names section 5.11's table gives the five codes, for a failure message that says
// which kind is meant rather than which number.
var specAttachmentKindNames = map[ServerAttachmentKind]string{
	AttachmentNone:     "NONE",
	AttachmentEpoch:    "EpochAttachment",
	AttachmentRecovery: "RecoveryTag",
	AttachmentWrap:     "WrapTag",
	AttachmentComplete: "EpochComplete",
}

// The written down codes, sorted, as the one alphabet every derived set is compared against.
func specAttachmentCodes() []int {
	codes := make([]int, 0, len(specAttachmentKindCodes))
	for _, code := range specAttachmentKindCodes {
		codes = append(codes, int(code))
	}
	slices.Sort(codes)
	return codes
}

// ── the corpus ──────────────────────────────────────────────────────────────────────

// The tags that make each length prefixed field's filler distinct from every other's. Two
// same width fields filled with the same octets are two fields a swapped encode order
// cannot be seen through, and write_key, read_key, group_context_hash and
// recovery_verify_pub are all 32 octets.
const (
	attachmentWriteKeyTag byte = iota + 0x40
	attachmentReadKeyTag
	attachmentGroupContextTag
	attachmentRecoveryHandleTag
	attachmentRecoveryPubTag
	attachmentWrapTargetTag
)

// How many content rotations the corpus crosses. Three rather than one, so a field written
// or read at the wrong offset lands on octets that are not the ones it should have in more
// than one arrangement.
const attachmentRotations = 3

// Deterministic filler for one field at one rotation. The rotation moves the tag rather
// than the pattern, so two fields of the same width never hold the same octets at any
// rotation.
func attachmentFiller(tag byte, rotation int, n int) []byte {
	return fillBytes(tag+byte(rotation)*0x20, n)
}

// The boundaries every 32 bit field is exercised over: zero, one, the middle of the range,
// the value below the top and the top itself. Zero and 4294967295 are also the two
// durable_ttl_seconds sentinels spec B section 5.4 defines, and both are legal values that
// this layer never refuses — which is why they are in the round trip corpus rather than in
// a refusal test.
func u32Boundaries() []uint32 {
	return []uint32{0, 1, 0x7FFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF}
}

// The same boundaries with zero dropped, for expected_wrap_count, which spec B section 5.1
// check 3 requires to be greater than zero. Derived by filtering rather than written out, so
// a boundary added above reaches this too.
func u32BoundariesAboveZero() []uint32 {
	above := []uint32{}
	for _, value := range u32Boundaries() {
		if value != 0 {
			above = append(above, value)
		}
	}
	return above
}

// One corpus attachment and the name a failure reports it by.
type attachmentCorpusEntry struct {
	name       string
	attachment *ServerAttachment
}

// A valid epoch attachment at one point of the cross product.
func validEpochAttachment(rotation int, epoch uint64, media uint32, durable uint32, count uint32) *ServerAttachment {
	return &ServerAttachment{
		Kind: AttachmentEpoch,
		Epoch: &EpochAttachment{
			Epoch:             epoch,
			AlgId:             attachmentAlgIds[AttachmentEpoch],
			WriteKey:          attachmentFiller(attachmentWriteKeyTag, rotation, epochWriteKeyBytes),
			ReadKey:           attachmentFiller(attachmentReadKeyTag, rotation, epochReadKeyBytes),
			MediaTtlSeconds:   media,
			DurableTtlSeconds: durable,
			GroupContextHash:  attachmentFiller(attachmentGroupContextTag, rotation, epochGroupContextHashBytes),
			ExpectedWrapCount: count,
		},
	}
}

// A valid recovery tag at one content rotation.
func validRecoveryTag(rotation int) *ServerAttachment {
	return &ServerAttachment{
		Kind: AttachmentRecovery,
		Recovery: &RecoveryTag{
			RecoveryHandle:    attachmentFiller(attachmentRecoveryHandleTag, rotation, recoveryHandleBytes),
			RecoveryVerifyPub: attachmentFiller(attachmentRecoveryPubTag, rotation, recoveryVerifyPubBytes),
			AlgId:             attachmentAlgIds[AttachmentRecovery],
		},
	}
}

// A valid wrap tag at one content rotation and one epoch.
func validWrapTag(rotation int, epoch uint64) *ServerAttachment {
	return &ServerAttachment{
		Kind: AttachmentWrap,
		Wrap: &WrapTag{
			WrapTargetHandle: attachmentFiller(attachmentWrapTargetTag, rotation, wrapTargetHandleBytes),
			Epoch:            epoch,
		},
	}
}

// A valid wrap set marker. Its wrap_count is unbounded here on purpose: the rule it obeys is
// equality against the epoch's own expected_wrap_count, which is an attachment this layer is
// never handed, so zero is in the corpus rather than in a refusal test.
func validEpochComplete(epoch uint64, count uint32) *ServerAttachment {
	return &ServerAttachment{
		Kind:     AttachmentComplete,
		Complete: &EpochComplete{Epoch: epoch, WrapCount: count},
	}
}

// One valid attachment of every kind, keyed by kind, including the absent one.
//
// It is the coverage the tests below index into, and it is asserted to cover every kind the
// encoder admits rather than assumed to: a kind added to the package with no valid
// attachment here would leave every property in this file holding over the four that already
// existed and saying nothing at all about the fifth.
func validAttachmentsByKind(t testing.TB) map[ServerAttachmentKind]*ServerAttachment {
	t.Helper()
	byKind := map[ServerAttachmentKind]*ServerAttachment{
		AttachmentNone:     {Kind: AttachmentNone},
		AttachmentEpoch:    validEpochAttachment(0, 42, 2592000, 0xFFFFFFFF, 1501),
		AttachmentRecovery: validRecoveryTag(0),
		AttachmentWrap:     validWrapTag(0, 0x100000000),
		AttachmentComplete: validEpochComplete(42, 1501),
	}
	for kind, attachment := range byKind {
		if _, err := EncodeServerAttachment(attachment); err != nil {
			t.Fatalf("the valid attachment for kind 0x%04x does not encode: %v", uint16(kind), err)
		}
	}
	return byKind
}

// The corpus: every kind crossed with every boundary the kind's own fields have.
//
// Computed rather than written out, and the axes are the ones section 5.11 gives each body:
// the u64 boundaries on every 64 bit field, the u32 boundaries on every 32 bit field, and
// three content rotations across the length prefixed ones. The 32 bit axis is where both
// durable_ttl_seconds sentinels live, so the round trip is asserted over them rather than
// over the ordinary values alone.
func attachmentCorpus(t testing.TB) []attachmentCorpusEntry {
	t.Helper()
	entries := []attachmentCorpusEntry{{name: "none", attachment: &ServerAttachment{Kind: AttachmentNone}}}
	for rotation := range attachmentRotations {
		for _, epoch := range u64Boundaries() {
			for _, media := range u32Boundaries() {
				for _, durable := range u32Boundaries() {
					for _, count := range u32BoundariesAboveZero() {
						name := fmt.Sprintf("epoch rot=%d epoch=%d media=%d durable=%d wraps=%d",
							rotation, epoch, media, durable, count)
						entries = append(entries, attachmentCorpusEntry{
							name:       name,
							attachment: validEpochAttachment(rotation, epoch, media, durable, count),
						})
					}
				}
			}
		}
		entries = append(entries, attachmentCorpusEntry{
			name:       fmt.Sprintf("recovery rot=%d", rotation),
			attachment: validRecoveryTag(rotation),
		})
		for _, epoch := range u64Boundaries() {
			entries = append(entries, attachmentCorpusEntry{
				name:       fmt.Sprintf("wrap rot=%d epoch=%d", rotation, epoch),
				attachment: validWrapTag(rotation, epoch),
			})
		}
	}
	for _, epoch := range u64Boundaries() {
		for _, count := range u32Boundaries() {
			entries = append(entries, attachmentCorpusEntry{
				name:       fmt.Sprintf("complete epoch=%d wraps=%d", epoch, count),
				attachment: validEpochComplete(epoch, count),
			})
		}
	}
	if len(entries) == 0 {
		t.Fatal("the corpus is empty, so every property asserted over it would hold vacuously")
	}
	kinds := map[ServerAttachmentKind]bool{}
	for _, entry := range entries {
		kinds[entry.attachment.Kind] = true
	}
	if len(kinds) != len(specAttachmentKindCodes) {
		t.Fatalf("the corpus covers %d kinds and section 5.11 defines %d", len(kinds), len(specAttachmentKindCodes))
	}
	return entries
}

// One corpus entry per kind and per 32 bit boundary, for the walks that try all 255
// alternatives at every offset and cannot afford to do it a thousand times over. Derived by
// grouping the corpus, so the subset covers every kind by construction rather than by a
// promise, and the entry chosen for each group is the first the cross product produced.
func attachmentWalkCorpus(t testing.TB) []attachmentCorpusEntry {
	t.Helper()
	seen := map[string]bool{}
	subset := []attachmentCorpusEntry{}
	for _, entry := range attachmentCorpus(t) {
		key := fmt.Sprintf("%d", entry.attachment.Kind)
		if epoch := entry.attachment.Epoch; epoch != nil {
			key = fmt.Sprintf("%s/%d", key, epoch.DurableTtlSeconds)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		subset = append(subset, entry)
	}
	if len(subset) == 0 {
		t.Fatal("the walk subset is empty, so every property asserted over it would hold vacuously")
	}
	return subset
}

// ── helpers ─────────────────────────────────────────────────────────────────────────

// One attachment's encoding, with a refusal fatal: every property below is about the bytes
// of an attachment this package says is valid, and there are none to assert over if the
// encoder refused it.
func mustEncodeAttachment(t testing.TB, what string, a *ServerAttachment) []byte {
	t.Helper()
	bs, err := EncodeServerAttachment(a)
	if err != nil {
		t.Fatalf("%s: EncodeServerAttachment refused a valid attachment: %v", what, err)
	}
	return bs
}

// What differs between two attachments, or the empty string. A field by field comparison
// rather than reflect.DeepEqual, so a failure names the field that moved.
func attachmentDifference(left *ServerAttachment, right *ServerAttachment) string {
	if left.Kind != right.Kind {
		return "Kind"
	}
	if (left.Epoch == nil) != (right.Epoch == nil) {
		return "Epoch presence"
	}
	if left.Epoch != nil {
		switch {
		case left.Epoch.Epoch != right.Epoch.Epoch:
			return "Epoch.Epoch"
		case left.Epoch.AlgId != right.Epoch.AlgId:
			return "Epoch.AlgId"
		case !bytes.Equal(left.Epoch.WriteKey, right.Epoch.WriteKey):
			return "Epoch.WriteKey"
		case !bytes.Equal(left.Epoch.ReadKey, right.Epoch.ReadKey):
			return "Epoch.ReadKey"
		case left.Epoch.MediaTtlSeconds != right.Epoch.MediaTtlSeconds:
			return "Epoch.MediaTtlSeconds"
		case left.Epoch.DurableTtlSeconds != right.Epoch.DurableTtlSeconds:
			return "Epoch.DurableTtlSeconds"
		case !bytes.Equal(left.Epoch.GroupContextHash, right.Epoch.GroupContextHash):
			return "Epoch.GroupContextHash"
		case left.Epoch.ExpectedWrapCount != right.Epoch.ExpectedWrapCount:
			return "Epoch.ExpectedWrapCount"
		}
	}
	if (left.Recovery == nil) != (right.Recovery == nil) {
		return "Recovery presence"
	}
	if left.Recovery != nil {
		switch {
		case !bytes.Equal(left.Recovery.RecoveryHandle, right.Recovery.RecoveryHandle):
			return "Recovery.RecoveryHandle"
		case !bytes.Equal(left.Recovery.RecoveryVerifyPub, right.Recovery.RecoveryVerifyPub):
			return "Recovery.RecoveryVerifyPub"
		case left.Recovery.AlgId != right.Recovery.AlgId:
			return "Recovery.AlgId"
		}
	}
	if (left.Wrap == nil) != (right.Wrap == nil) {
		return "Wrap presence"
	}
	if left.Wrap != nil {
		switch {
		case !bytes.Equal(left.Wrap.WrapTargetHandle, right.Wrap.WrapTargetHandle):
			return "Wrap.WrapTargetHandle"
		case left.Wrap.Epoch != right.Wrap.Epoch:
			return "Wrap.Epoch"
		}
	}
	if (left.Complete == nil) != (right.Complete == nil) {
		return "Complete presence"
	}
	if left.Complete != nil {
		switch {
		case left.Complete.Epoch != right.Complete.Epoch:
			return "Complete.Epoch"
		case left.Complete.WrapCount != right.Complete.WrapCount:
			return "Complete.WrapCount"
		}
	}
	return ""
}

// The body pointer of one attachment as a reflect value, for the reflection driven width
// walk below. Nil for the absent attachment, which has no body to reach into.
func attachmentBodyValue(a *ServerAttachment) reflect.Value {
	switch {
	case a.Epoch != nil:
		return reflect.ValueOf(a.Epoch).Elem()
	case a.Recovery != nil:
		return reflect.ValueOf(a.Recovery).Elem()
	case a.Wrap != nil:
		return reflect.ValueOf(a.Wrap).Elem()
	case a.Complete != nil:
		return reflect.ValueOf(a.Complete).Elem()
	}
	return reflect.Value{}
}

// One length prefixed field of one body: the kind it is on, its name, and the width the
// package's own valid attachment gives it.
type attachmentWidthField struct {
	kind  ServerAttachmentKind
	name  string
	width int
}

// Every length prefixed field of every body, read off the go types rather than listed.
//
// Section 5.11 gives six of them an exact width, and spec B section 5.1 check 3 names four
// of the six as things it will rely on this parser having checked. A test that listed them
// would be a list, and this project has been walked past a list twelve times: what is
// derived here is the class — every []byte field of every body — so a seventh such field
// added to any of the four bodies is under the walk the day it is declared, with nobody
// remembering to add it.
//
// The width each one is checked against is the width the package's own valid attachment
// carries, not a number written here, so the walk asks "every length but this one is
// refused" rather than "every length but 32 is refused" — the constant is pinned by the
// golden vectors, and this asserts the property around it.
func attachmentWidthFields(t testing.TB) []attachmentWidthField {
	t.Helper()
	fields := []attachmentWidthField{}
	byKind := validAttachmentsByKind(t)
	for _, code := range specAttachmentCodes() {
		kind := ServerAttachmentKind(code)
		body := attachmentBodyValue(byKind[kind])
		if !body.IsValid() {
			continue
		}
		for i := range body.NumField() {
			field := body.Type().Field(i)
			if field.Type.Kind() != reflect.Slice || field.Type.Elem().Kind() != reflect.Uint8 {
				continue
			}
			fields = append(fields, attachmentWidthField{kind: kind, name: field.Name, width: body.Field(i).Len()})
		}
	}
	if len(fields) == 0 {
		t.Fatal("no body carries a length prefixed field, so the width walk below would hold vacuously")
	}
	return fields
}

// ── the alphabet ────────────────────────────────────────────────────────────────────

// Every kind code the encoder will write, derived by offering it all 65536 of them crossed
// with every body shape this package has.
//
// The cross with the body shapes is what makes it a derivation of the encoder's answer
// rather than of the kind constants: a code that only encodes when it is handed the right
// body is still a code the encoder writes, and one that encodes with any body at all is a
// package that has stopped checking the two against each other.
func encodableKindCodes(t testing.TB) []int {
	t.Helper()
	bodies := []func(kind ServerAttachmentKind) *ServerAttachment{
		func(kind ServerAttachmentKind) *ServerAttachment { return &ServerAttachment{Kind: kind} },
		func(kind ServerAttachmentKind) *ServerAttachment {
			a := validEpochAttachment(0, 7, 1, 2, 3)
			a.Kind = kind
			return a
		},
		func(kind ServerAttachmentKind) *ServerAttachment {
			a := validRecoveryTag(0)
			a.Kind = kind
			return a
		},
		func(kind ServerAttachmentKind) *ServerAttachment {
			a := validWrapTag(0, 7)
			a.Kind = kind
			return a
		},
		func(kind ServerAttachmentKind) *ServerAttachment {
			a := validEpochComplete(7, 3)
			a.Kind = kind
			return a
		},
	}
	codes := []int{}
	for code := 0; code <= 0xFFFF; code++ {
		kind := ServerAttachmentKind(code)
		for _, body := range bodies {
			if _, err := EncodeServerAttachment(body(kind)); err == nil {
				codes = append(codes, code)
				break
			}
		}
	}
	if len(codes) == 0 {
		t.Fatal("the encoder wrote no kind at all, so every assertion below would hold vacuously")
	}
	return codes
}

// The alphabet, encode side: the encoder writes exactly the five codes section 5.11 defines.
func TestTheEncoderWritesExactlyTheFiveKindsSectionFiveElevenDefines(t *testing.T) {
	codes := encodableKindCodes(t)
	want := specAttachmentCodes()
	if len(want) != 5 {
		t.Fatalf("the written down table names %d codes, want the 5 of section 5.11", len(want))
	}
	if !slices.Equal(codes, want) {
		t.Errorf("the encoder writes %v, want exactly %v; every other u16 is a kind nothing defines", codes, want)
	}
}

// The alphabet, parse side: an encoding parses under its own kind code and under no other.
//
// Derived rather than listed. Each kind's valid encoding has its leading u16 replaced by
// each of the 65536 values in turn, and the set that parses has to be the one code that
// encoding was built with. A kind accepted for a body that is not its own is the defect this
// catches — a parser that read the body first and the kind afterwards, or one that fell back
// to a default kind — and so is a kind silently ignored, which spec B section 5.1 check 3
// cannot survive: an attachment the server cannot parse is one it cannot check.
func TestAnEncodingParsesUnderItsOwnKindAndNoOther(t *testing.T) {
	byKind := validAttachmentsByKind(t)
	tried := 0
	for _, kind := range specAttachmentCodes() {
		attachment := byKind[ServerAttachmentKind(kind)]
		if attachment == nil || attachment.Kind == AttachmentNone {
			continue
		}
		valid := mustEncodeAttachment(t, specAttachmentKindNames[attachment.Kind], attachment)
		accepted := []int{}
		relabelled := slices.Clone(valid)
		for code := 0; code <= 0xFFFF; code++ {
			relabelled[0] = byte(code >> 8)
			relabelled[1] = byte(code)
			if _, err := ParseServerAttachment(relabelled); err == nil {
				accepted = append(accepted, code)
			}
		}
		if !slices.Equal(accepted, []int{kind}) {
			t.Errorf("the %s encoding parses under %v, want exactly [%d]", specAttachmentKindNames[attachment.Kind], accepted, kind)
		}
		tried++
	}
	if tried == 0 {
		t.Fatal("no kind carried a body, so this walk relabelled nothing")
	}
	t.Logf("%d kinds relabelled across all 65536 codes each", tried)
}

// Each of the five codes is the number section 5.11 gives it.
//
// The one thing no derived property can see. A table permuted in both directions round trips
// perfectly and agrees with nobody, and the kind reaches the write_auth mac and both aeads
// through H(server_attachment), so a permutation is a record every other implementation
// refuses at an authenticator rather than anywhere legible.
func TestEveryKindCodeIsTheOneSectionFiveElevenGives(t *testing.T) {
	for kind, want := range specAttachmentKindCodes {
		if uint16(kind) != want {
			t.Errorf("%s is 0x%04x and section 5.11 gives it 0x%04x", specAttachmentKindNames[kind], uint16(kind), want)
		}
	}
	codes := map[uint16]bool{}
	for kind := range specAttachmentKindCodes {
		codes[uint16(kind)] = true
	}
	if len(codes) != len(specAttachmentKindCodes) {
		t.Errorf("the five kinds take %d distinct codes; two of them are the same number", len(codes))
	}
}

// ── the golden vectors ──────────────────────────────────────────────────────────────

// The epoch attachment, pinned to its exact octets.
//
// Derived by hand from section 5.11's block, one line per field:
//
//	0001                              u16(kind): 0x0001, an EpochAttachment
//	00000082                          LP(body): 130 octets, the sum of the lines below
//	000000000000002a                  u64(epoch): 42, the epoch this attachment OPENS
//	0031                              u16(alg_id): HKDF-SHA-256, master section 7.1
//	00000020 70..8f                   LP(write_key): 32 octets, a ramp from 0x70
//	00000020 90..af                   LP(read_key): 32 octets, a ramp from 0x90
//	00278d00                          u32(media_ttl_seconds): 2592000, thirty days
//	ffffffff                          u32(durable_ttl_seconds): the indefinite sentinel
//	00000020 c0..df                   LP(group_context_hash): 32 octets, a ramp from 0xc0
//	000005dd                          u32(expected_wrap_count): 1501
//
// The body adds to 8 + 2 + 36 + 36 + 4 + 4 + 36 + 4 = 130 = 0x82, and the whole attachment
// to 2 + 4 + 130 = 136.
//
// 1501 is section 5.11's own sizing at the 500 member by 2 device design target: 1000 device
// wraps, 500 recovery wraps and one snapshot. It is in the vector rather than a round number
// because it is the value the spec's own arithmetic produces.
const attachmentEpochVectorHex = "0001" +
	"00000082" +
	"000000000000002a" +
	"0031" +
	"00000020" + "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f" +
	"00000020" + "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf" +
	"00278d00" +
	"ffffffff" +
	"00000020" + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
	"000005dd"

// The recovery tag, pinned to its exact octets.
//
//	0002                              u16(kind): 0x0002, a RecoveryTag
//	0000003a                          LP(body): 58 octets, the sum of the lines below
//	00000010 a0..af                   LP(recovery_handle): 16 octets, a ramp from 0xa0
//	00000020 10..2f                   LP(recovery_verify_pub): 32 octets, a ramp from 0x10
//	0001                              u16(alg_id): Ed25519, master section 7.1
//
// The body adds to 20 + 36 + 2 = 58 = 0x3a, and the whole attachment to 2 + 4 + 58 = 64.
//
// The alg_id is last, after the two length prefixed fields. That order is section 5.11's and
// it is the one field of this body an implementation is likeliest to move to the front, where
// every other message in the system carries it.
const attachmentRecoveryVectorHex = "0002" +
	"0000003a" +
	"00000010" + "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf" +
	"00000020" + "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f" +
	"0001"

// The wrap tag, pinned to its exact octets.
//
//	0003                              u16(kind): 0x0003, a WrapTag
//	0000001c                          LP(body): 28 octets, the sum of the lines below
//	00000010 50..5f                   LP(wrap_target_handle): 16 octets, a ramp from 0x50
//	0000000100000000                  u64(epoch): 4294967296
//
// The body adds to 20 + 8 = 28 = 0x1c, and the whole attachment to 2 + 4 + 28 = 34.
//
// The epoch is the first value that does not fit in 32 bits, chosen so the vector says the
// field is 64 bits wide: read as a u32 it is zero, and read with its halves swapped it is 1.
const attachmentWrapVectorHex = "0003" +
	"0000001c" +
	"00000010" + "505152535455565758595a5b5c5d5e5f" +
	"0000000100000000"

// The wrap set marker, pinned to its exact octets.
//
//	0004                              u16(kind): 0x0004, an EpochComplete
//	0000000c                          LP(body): 12 octets, the sum of the lines below
//	000000000000002a                  u64(epoch): 42, the same epoch the vector above opens
//	000005dd                          u32(wrap_count): 1501, that epoch's expected_wrap_count
//
// The body adds to 8 + 4 = 12 = 0x0c, and the whole attachment to 2 + 4 + 12 = 18.
const attachmentCompleteVectorHex = "0004" +
	"0000000c" +
	"000000000000002a" +
	"000005dd"

// The four vectors by kind, so the coverage assertion below can be about the set rather than
// about four function names somebody remembered to write.
var attachmentGoldenVectors = map[ServerAttachmentKind]string{
	AttachmentEpoch:    attachmentEpochVectorHex,
	AttachmentRecovery: attachmentRecoveryVectorHex,
	AttachmentWrap:     attachmentWrapVectorHex,
	AttachmentComplete: attachmentCompleteVectorHex,
}

// The attachment each vector is of, built from the same values the derivation above names.
func attachmentGoldenValues() map[ServerAttachmentKind]*ServerAttachment {
	return map[ServerAttachmentKind]*ServerAttachment{
		AttachmentEpoch: {
			Kind: AttachmentEpoch,
			Epoch: &EpochAttachment{
				Epoch:             42,
				AlgId:             0x0031,
				WriteKey:          aadRamp(0x70, 32),
				ReadKey:           aadRamp(0x90, 32),
				MediaTtlSeconds:   2592000,
				DurableTtlSeconds: 0xFFFFFFFF,
				GroupContextHash:  aadRamp(0xc0, 32),
				ExpectedWrapCount: 1501,
			},
		},
		AttachmentRecovery: {
			Kind: AttachmentRecovery,
			Recovery: &RecoveryTag{
				RecoveryHandle:    aadRamp(0xa0, 16),
				RecoveryVerifyPub: aadRamp(0x10, 32),
				AlgId:             0x0001,
			},
		},
		AttachmentWrap: {
			Kind: AttachmentWrap,
			Wrap: &WrapTag{
				WrapTargetHandle: aadRamp(0x50, 16),
				Epoch:            0x100000000,
			},
		},
		AttachmentComplete: {
			Kind:     AttachmentComplete,
			Complete: &EpochComplete{Epoch: 42, WrapCount: 1501},
		},
	}
}

// Every kind is pinned to its exact octets, and back.
//
// The vectors are the anchors that do not move with the code. rawAttachment states the
// layout a second time but lives beside the encoder, so a field order permuted in the raw
// builder and in writeAttachmentBody together passes every comparison against it; a hand
// derived hexadecimal string does not move at all, and a permutation lands on it.
func TestEveryKindIsPinnedToItsExactBytes(t *testing.T) {
	values := attachmentGoldenValues()
	for _, code := range specAttachmentCodes() {
		kind := ServerAttachmentKind(code)
		want, pinned := attachmentGoldenVectors[kind]
		if !pinned {
			continue
		}
		name := specAttachmentKindNames[kind]
		attachment := values[kind]
		if attachment == nil {
			t.Fatalf("%s has a vector and no value to build it from", name)
		}
		got := mustEncodeAttachment(t, name, attachment)
		if hex.EncodeToString(got) != want {
			t.Fatalf("the %s vector encodes to\n%s\nwant\n%s", name, hex.EncodeToString(got), want)
		}
		// the declared body length is the one number in a vector a typo cannot be seen in
		// by eye, so it is read back out of the octets and checked against the ones that
		// follow it rather than trusted
		declared, err := syntax.NewReader(got[2:attachmentFramingBytes]).ReadUint32()
		if err != nil {
			t.Fatalf("the %s vector carries no body length: %v", name, err)
		}
		if len(got) != attachmentFramingBytes+int(declared) {
			t.Errorf("the %s vector is %d octets and declares a body of %d", name, len(got), declared)
		}
		parsed, err := ParseServerAttachment(got)
		if err != nil {
			t.Fatalf("the %s vector does not parse: %v", name, err)
		}
		if difference := attachmentDifference(attachment, parsed); difference != "" {
			t.Errorf("the %s vector does not round trip: %s differs", name, difference)
		}
	}
}

// Every kind that carries a body has a golden vector.
//
// The set is derived from the encoder rather than counted against four, so a fifth kind
// added to the package fails here instead of being pinned by nothing while every other
// property in this file goes on holding over the four that were already there.
func TestEveryKindThatCarriesABodyHasAGoldenVector(t *testing.T) {
	pinned := []int{}
	for kind := range attachmentGoldenVectors {
		pinned = append(pinned, int(kind))
	}
	slices.Sort(pinned)
	want := []int{}
	for _, code := range encodableKindCodes(t) {
		if ServerAttachmentKind(code) != AttachmentNone {
			want = append(want, code)
		}
	}
	if !slices.Equal(pinned, want) {
		t.Errorf("the vectors pin %v and the encoder writes bodies for %v", pinned, want)
	}
}

// The epoch attachment vector is the attachment aad_test.go already pins.
//
// This is the one assertion in the file that reaches outside the package's own agreement
// with itself. aad_test.go's commit vector carries these same 136 octets and its comment
// records that the digest over them was derived by a separate program importing nothing from
// this package, so the layout below this line was fixed before there was an encoder to agree
// with. If the two ever differ, the record's LP(H(server_attachment)) is computed over one
// attachment and this encoder writes another, and every commit fails at the mac.
func TestTheEpochVectorIsTheOneAadTestPinsIndependently(t *testing.T) {
	if attachmentEpochVectorHex != aadKatCommitAttachmentHex {
		t.Fatalf("this file's epoch vector is\n%s\nand aad_test.go's is\n%s", attachmentEpochVectorHex, aadKatCommitAttachmentHex)
	}
	attachment := attachmentGoldenValues()[AttachmentEpoch]
	got := mustEncodeAttachment(t, "the epoch vector", attachment)
	if !bytes.Equal(got, aadKatCommitAttachment(t)) {
		t.Fatalf("the encoder produced\n%s\nand aad_test.go's attachment is\n%s",
			hex.EncodeToString(got), hex.EncodeToString(aadKatCommitAttachment(t)))
	}
	// and the length aad_test.go asserts on for its own reasons, restated here so a vector
	// that changed length would fail in both files rather than in one
	if want, got := 136, len(got); got != want {
		t.Errorf("the epoch attachment is %d octets and section 5.11's block is %d", got, want)
	}
}

// ── the layout, and the round trip ──────────────────────────────────────────────────

// Every corpus attachment encodes to the layout stated independently in rawAttachment.
func TestEncodedBytesAreTheLayoutSectionFiveElevenStates(t *testing.T) {
	for _, entry := range attachmentCorpus(t) {
		got := mustEncodeAttachment(t, entry.name, entry.attachment)
		if entry.attachment.Kind == AttachmentNone {
			if len(got) != 0 {
				t.Fatalf("%s: the absent attachment encoded to %d octets", entry.name, len(got))
			}
			continue
		}
		want := rawAttachmentOf(t, entry.attachment).encode(t)
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: the encoder wrote\n%s\nand the layout is\n%s", entry.name, hex.EncodeToString(got), hex.EncodeToString(want))
		}
	}
}

// Byte exact both ways over the whole corpus: the attachment encodes, the encoding parses
// back to the same attachment, and re-encoding that attachment reproduces the same bytes.
// The second half is what catches an encoder and a decoder that disagree about a field —
// there the value survives the first hop and the bytes do not survive the second.
func TestEveryCorpusAttachmentRoundTripsByteExact(t *testing.T) {
	entries := attachmentCorpus(t)
	for _, entry := range entries {
		first := mustEncodeAttachment(t, entry.name, entry.attachment)
		parsed, err := ParseServerAttachment(first)
		if err != nil {
			t.Fatalf("%s: an attachment this package encoded does not parse: %v", entry.name, err)
		}
		if difference := attachmentDifference(entry.attachment, parsed); difference != "" {
			t.Fatalf("%s: the parsed attachment differs from the encoded one: %s", entry.name, difference)
		}
		second := mustEncodeAttachment(t, entry.name, parsed)
		if !bytes.Equal(first, second) {
			t.Fatalf("%s: re-encoding the parsed attachment produced %d octets, want the same %d", entry.name, len(second), len(first))
		}
	}
	t.Logf("%d corpus attachments round tripped", len(entries))
}

// ── the absent attachment ───────────────────────────────────────────────────────────

// A nil attachment and an AttachmentNone attachment are the same attachment, and both are no
// bytes at all.
//
// This is spec A section 5.11's test obligation asserted from the encoder's side. aad.go
// already pins the consequence — an ordinary record contributes LP(SHA-256("")) to aad_head —
// and this pins the cause, on the hash rather than only on the bytes, because the hash is
// what reaches the mac and a difference the bytes hid would surface only there.
func TestTheAbsentAttachmentAndAttachmentNoneEncodeIdentically(t *testing.T) {
	fromNil, err := EncodeServerAttachment(nil)
	if err != nil {
		t.Fatalf("a nil attachment does not encode: %v", err)
	}
	fromNone, err := EncodeServerAttachment(&ServerAttachment{Kind: AttachmentNone})
	if err != nil {
		t.Fatalf("an AttachmentNone attachment does not encode: %v", err)
	}
	if len(fromNil) != 0 {
		t.Errorf("a nil attachment encoded to %s, want no octets at all", hex.EncodeToString(fromNil))
	}
	if !bytes.Equal(fromNil, fromNone) {
		t.Fatalf("a nil attachment gives %s and an AttachmentNone one gives %s",
			hex.EncodeToString(fromNil), hex.EncodeToString(fromNone))
	}
	// the property that actually reaches the mac, so a future encoding that made the two
	// differ in length alone still fails here
	if sha256.Sum256(fromNil) != sha256.Sum256(fromNone) {
		t.Error("H(server_attachment) differs between a nil attachment and an AttachmentNone one")
	}
	if want := sha256.Sum256(nil); sha256.Sum256(fromNone) != want {
		t.Errorf("H of the absent attachment is %x, want the SHA-256 of the empty string %x", sha256.Sum256(fromNone), want)
	}
}

// The same equivalence carried the one hop that matters: through aad_head, on the encoder's
// own bytes.
//
// The test above pins the cause and aad_test.go's vector pins the consequence, but the two
// have never been joined — aad_test.go hands AADHead an attachment it wrote by hand, and
// nothing in this package yet routes EncodeServerAttachment's answer into a RecordHeader.
// The record builder that will is the place this property actually breaks, and until it
// exists this is the join: the encoder's answer for an absent attachment and for an explicit
// AttachmentNone, each carried into the header field the mac is taken over, must land on the
// identical preimage — and on the identical preimage a header holding no attachment at all
// gives, which is the vector aad_test.go pins to its exact bytes.
//
// It observes what the byte comparison above cannot: a change that made either spelling
// contribute bytes of its own reaches the aead through H(server_attachment), and a record
// built by a client with one spelling is then a record the server hashes differently and
// refuses as a bad mac — the intermittent failure spec B section 12.1 A-1 exists to prevent.
func TestBothSpellingsOfTheAbsentAttachmentGiveTheSameAadHead(t *testing.T) {
	// LP(H(server_attachment)) for the absent attachment, from spec A section 5.11 and
	// master section 0's notation line rather than from this package: the 32 bit prefix
	// 00000020 and the SHA-256 of the empty string, which is a value any second
	// implementation holds without running any of this.
	const wantTail = "00000020" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	spellings := []struct {
		name       string
		attachment *ServerAttachment
	}{
		{name: "an absent attachment", attachment: nil},
		{name: "an explicit AttachmentNone", attachment: &ServerAttachment{Kind: AttachmentNone}},
	}
	header := aadKatOrdinaryHeader()
	if header.ServerAttachment != nil {
		t.Fatal("the ordinary header already carries an attachment, so it pins no absence")
	}
	want := mustAADHead(t, "a header carrying no attachment", aadKatAlgId, &header, nil)
	if tail := hex.EncodeToString(want); !strings.HasSuffix(tail, wantTail) {
		t.Fatalf("aad_head ends %s, want LP(SHA-256(\"\")) %s", tail[len(tail)-len(wantTail):], wantTail)
	}
	for _, spelling := range spellings {
		encoded, err := EncodeServerAttachment(spelling.attachment)
		if err != nil {
			t.Fatalf("%s does not encode: %v", spelling.name, err)
		}
		// the header field and the argument both, because AADHead compares them and a
		// spelling that answered bytes would otherwise be refused rather than observed
		carried := aadKatOrdinaryHeader()
		carried.ServerAttachment = encoded
		got := mustAADHead(t, spelling.name, aadKatAlgId, &carried, encoded)
		if !bytes.Equal(got, want) {
			t.Errorf("%s encoded to %s and gives aad_head\n%s\nwant\n%s",
				spelling.name, hex.EncodeToString(encoded), hex.EncodeToString(got), hex.EncodeToString(want))
		}
	}
}

// Empty input parses back as the absent attachment with no body, which is what every ordinary
// record carries.
func TestEmptyInputParsesAsTheAbsentAttachment(t *testing.T) {
	for _, input := range [][]byte{nil, {}} {
		parsed, err := ParseServerAttachment(input)
		if err != nil {
			t.Fatalf("a %d octet input does not parse: %v", len(input), err)
		}
		if parsed.Kind != AttachmentNone {
			t.Errorf("a %d octet input parsed as kind 0x%04x, want AttachmentNone", len(input), uint16(parsed.Kind))
		}
		if carried, set := parsed.bodyKind(); set != 0 {
			t.Errorf("the absent attachment came back carrying %d bodies, the last of them kind 0x%04x", set, uint16(carried))
		}
	}
}

// The absent attachment spelled out as kind 0x0000 with an empty body is refused.
//
// Both specs say an ordinary record carries a zero length server_attachment and NOT kind
// 0x0000, and section 5.11's test obligation says why: the two must encode identically or
// H(server_attachment) differs between client and server. Accepting the long form gives one
// attachment two encodings with two different hashes, and the write_auth mac and both aeads
// are over exactly one of them. It is also the only reading under which parsing either fails
// or re-encodes to the identical bytes.
func TestTheAbsentAttachmentSpelledOutIsRefused(t *testing.T) {
	spelled := rawAttachmentOf(t, &ServerAttachment{Kind: AttachmentNone}).encode(t)
	if want := attachmentFramingBytes; len(spelled) != want {
		t.Fatalf("the spelled out absent attachment is %d octets, want %d", len(spelled), want)
	}
	_, err := ParseServerAttachment(spelled)
	if err == nil {
		t.Fatalf("%s was accepted, and an attachment with two encodings has a mac over one of them", hex.EncodeToString(spelled))
	}
	if !errors.Is(err, ErrServerAttachmentNoneEncoded) {
		t.Errorf("refused with %v, want ErrServerAttachmentNoneEncoded", err)
	}
	// and with a body, which is the same mistake with more of it
	withBody := rawAttachment{kind: uint16(AttachmentNone), body: []byte{0x00}}.encode(t)
	if _, err := ParseServerAttachment(withBody); err == nil {
		t.Errorf("%s was accepted", hex.EncodeToString(withBody))
	}
}

// ── nothing is silently accepted and changed ────────────────────────────────────────

// Every prefix of a valid encoding is refused. A parser that stopped early on any of them
// would accept a truncated attachment as a whole one, which is an attachment whose
// H(server_attachment) the mac was computed over bytes the reader never saw.
func TestEverySingleByteTruncationOfAValidAttachmentIsRejected(t *testing.T) {
	walked := 0
	for _, entry := range attachmentCorpus(t) {
		valid := mustEncodeAttachment(t, entry.name, entry.attachment)
		for length := 1; length < len(valid); length++ {
			what := fmt.Sprintf("%s truncated to %d of %d octets", entry.name, length, len(valid))
			if _, err := ParseServerAttachment(valid[:length]); err == nil {
				t.Fatalf("%s: accepted", what)
			}
			walked++
		}
	}
	if walked == 0 {
		t.Fatal("no truncation was walked, so this property holds vacuously")
	}
	t.Logf("%d truncations refused", walked)
}

// An octet after the attachment is a refusal. Without it an attachment has more than one
// encoding, and the write_auth mac is over exactly one of them.
func TestATrailingByteIsRejectedOnEveryKind(t *testing.T) {
	for _, entry := range attachmentWalkCorpus(t) {
		valid := mustEncodeAttachment(t, entry.name, entry.attachment)
		for value := 0; value <= 0xFF; value++ {
			extended := append(slices.Clone(valid), byte(value))
			if _, err := ParseServerAttachment(extended); err == nil {
				t.Fatalf("%s with a trailing 0x%02x: accepted, and an attachment with two encodings has a mac over one of them", entry.name, value)
			}
		}
	}
}

// Every single octet corruption of a valid encoding either is refused or re-encodes to
// exactly the corrupted bytes.
//
// This is the property that catches a field read at the wrong width, and it is the one thing
// a round trip over well formed attachments cannot see: read expected_wrap_count as a u16 and
// every attachment this package writes still round trips, because the two octets it ignores
// are two octets it also never wrote. Corrupt one of them and the attachment parses,
// re-encodes to different bytes, and is caught here.
func TestEverySingleByteCorruptionIsRejectedOrRoundTrips(t *testing.T) {
	walked := 0
	for _, entry := range attachmentWalkCorpus(t) {
		valid := mustEncodeAttachment(t, entry.name, entry.attachment)
		corrupted := slices.Clone(valid)
		for offset := range valid {
			original := corrupted[offset]
			for value := 0; value <= 0xFF; value++ {
				if byte(value) == original {
					continue
				}
				corrupted[offset] = byte(value)
				what := fmt.Sprintf("%s with octet %d of %d set to 0x%02x", entry.name, offset, len(valid), value)
				parsed, err := ParseServerAttachment(corrupted)
				walked++
				if err != nil {
					continue
				}
				again, err := EncodeServerAttachment(parsed)
				if err != nil {
					t.Fatalf("%s: parsed and then refused to re-encode: %v", what, err)
				}
				if !bytes.Equal(again, corrupted) {
					t.Fatalf("%s: parsed and re-encoded to different bytes, so an octet was accepted and silently changed", what)
				}
			}
			corrupted[offset] = original
		}
	}
	if walked == 0 {
		t.Fatal("no corruption was walked, so this property holds vacuously")
	}
	t.Logf("%d single octet corruptions walked", walked)
}

// ── what check 3 relies on being refused ────────────────────────────────────────────

// Every length prefixed field is its exact width and no other, on both sides of the codec.
//
// The class of fields is derived from the go types rather than listed — see
// attachmentWidthFields — so the four widths spec B section 5.1 check 3 names by hand
// (write_key 32, read_key 32, a 32 octet Ed25519 pub on RecoveryTag, a 16 octet target on
// WrapTag) are covered along with the two it does not, and a seventh field added later is
// covered without an edit here.
func TestEveryLengthPrefixedFieldIsItsExactWidthAndNoOther(t *testing.T) {
	fields := attachmentWidthFields(t)
	t.Logf("%d length prefixed fields under the walk: %v", len(fields), fields)
	byKind := validAttachmentsByKind(t)
	for _, field := range fields {
		for length := 0; length <= field.width*2+8; length++ {
			if length == field.width {
				continue
			}
			attachment := byKind[field.kind]
			fresh := validAttachmentsByKind(t)[field.kind]
			body := attachmentBodyValue(fresh)
			body.FieldByName(field.name).Set(reflect.ValueOf(fillBytes(0xFE, length)))
			what := fmt.Sprintf("%s.%s at %d octets, want %d", specAttachmentKindNames[field.kind], field.name, length, field.width)
			if _, err := EncodeServerAttachment(fresh); err == nil {
				t.Fatalf("%s: the encoder accepted it", what)
			} else if !errors.Is(err, ErrServerAttachmentFieldLength) {
				t.Errorf("%s: the encoder refused with %v, want ErrServerAttachmentFieldLength", what, err)
			}
			bs := rawAttachmentOf(t, fresh).encode(t)
			if _, err := ParseServerAttachment(bs); err == nil {
				t.Fatalf("%s: the parser accepted it", what)
			} else if !errors.Is(err, ErrServerAttachmentFieldLength) {
				t.Errorf("%s: the parser refused with %v, want ErrServerAttachmentFieldLength", what, err)
			}
			// and the width itself still passes, so the walk cannot be satisfied by a
			// package that refuses every length
			if _, err := EncodeServerAttachment(attachment); err != nil {
				t.Fatalf("%s: the valid attachment stopped encoding: %v", what, err)
			}
		}
	}
}

// Every algorithm identifier but the one its kind names is refused, on both sides.
//
// Derived over all 65536 values rather than over a handful somebody chose, so a check that
// admitted a neighbouring identifier — 0x0030, or the whole of master section 7.1's registry
// — is caught. It is per kind because the identifiers are per kind: an EpochAttachment
// announcing Ed25519 claims its two 32 octet keys came out of a signature algorithm.
func TestEveryAlgorithmIdentifierButTheKindsOwnIsRefused(t *testing.T) {
	byKind := validAttachmentsByKind(t)
	tried := 0
	for kind, want := range attachmentAlgIds {
		attachment := byKind[kind]
		if attachment == nil {
			t.Fatalf("kind 0x%04x names an algorithm identifier and has no valid attachment", uint16(kind))
		}
		body := attachmentBodyValue(attachment)
		field := body.FieldByName("AlgId")
		if !field.IsValid() {
			t.Fatalf("kind 0x%04x names an algorithm identifier and its body has no AlgId field", uint16(kind))
		}
		for value := 0; value <= 0xFFFF; value++ {
			field.Set(reflect.ValueOf(uint16(value)))
			_, encodeErr := EncodeServerAttachment(attachment)
			_, parseErr := ParseServerAttachment(rawAttachmentOf(t, attachment).encode(t))
			if uint16(value) == want {
				if encodeErr != nil || parseErr != nil {
					t.Fatalf("kind 0x%04x refused its own identifier 0x%04x: %v / %v", uint16(kind), value, encodeErr, parseErr)
				}
				continue
			}
			if encodeErr == nil || parseErr == nil {
				t.Fatalf("kind 0x%04x accepted algorithm identifier 0x%04x, and it names 0x%04x", uint16(kind), value, want)
			}
			if !errors.Is(encodeErr, ErrServerAttachmentAlgId) || !errors.Is(parseErr, ErrServerAttachmentAlgId) {
				t.Fatalf("kind 0x%04x refused 0x%04x with %v / %v, want ErrServerAttachmentAlgId", uint16(kind), value, encodeErr, parseErr)
			}
		}
		field.Set(reflect.ValueOf(want))
		tried++
	}
	if tried == 0 {
		t.Fatal("no kind names an algorithm identifier, so this walk asked nothing")
	}
	t.Logf("%d kinds walked across all 65536 identifiers each", tried)
}

// An epoch attachment that expects no wraps is refused, on both sides.
//
// Spec B section 5.1 check 3 names it outright. The epoch it opens has at least its own
// snapshot in the wrap set, so zero is not a small fan out: it names a count no EpochComplete
// marker can ever match, which leaves the group readable and not writable with nothing able
// to close it.
func TestAnEpochAttachmentExpectingNoWrapsIsRefused(t *testing.T) {
	attachment := validEpochAttachment(0, 42, 1, 1, 0)
	_, err := EncodeServerAttachment(attachment)
	if err == nil {
		t.Fatal("the encoder accepted an expected_wrap_count of zero")
	}
	if !errors.Is(err, ErrExpectedWrapCountZero) {
		t.Errorf("the encoder refused with %v, want ErrExpectedWrapCountZero", err)
	}
	bs := rawAttachmentOf(t, attachment).encode(t)
	_, err = ParseServerAttachment(bs)
	if err == nil {
		t.Fatalf("the parser accepted %s, an expected_wrap_count of zero", hex.EncodeToString(bs))
	}
	if !errors.Is(err, ErrExpectedWrapCountZero) {
		t.Errorf("the parser refused with %v, want ErrExpectedWrapCountZero", err)
	}
	// every other value of the field is accepted, so the refusal is about zero and not about
	// the field
	for _, count := range u32BoundariesAboveZero() {
		if _, err := EncodeServerAttachment(validEpochAttachment(0, 42, 1, 1, count)); err != nil {
			t.Errorf("expected_wrap_count %d was refused: %v", count, err)
		}
	}
}

// A kind nothing defines is refused, on both sides, and never silently ignored.
//
// Check 3 is what stands between a record and the database. An attachment the server cannot
// parse is one it cannot check, so a record carrying an undefined kind that parsed to
// "nothing worth looking at" would take the epoch key install, the recovery index and the
// wrap index past every question check 3 asks of them.
func TestAnUnknownKindIsADecodeError(t *testing.T) {
	defined := map[int]bool{}
	for _, code := range specAttachmentCodes() {
		defined[code] = true
	}
	body := rawEpochComplete{epoch: 42, wrapCount: 1501}.encode(t)
	refusals := 0
	for code := 0; code <= 0xFFFF; code++ {
		if defined[code] {
			continue
		}
		bs := rawAttachment{kind: uint16(code), body: body}.encode(t)
		parsed, err := ParseServerAttachment(bs)
		if err == nil {
			t.Fatalf("kind 0x%04x parsed to %+v, and an attachment this layer cannot parse is one the server cannot check", code, parsed)
		}
		if !errors.Is(err, ErrServerAttachmentKindUnknown) {
			t.Fatalf("kind 0x%04x refused with %v, want ErrServerAttachmentKindUnknown", code, err)
		}
		if _, err := EncodeServerAttachment(&ServerAttachment{Kind: ServerAttachmentKind(code)}); !errors.Is(err, ErrServerAttachmentKindUnknown) {
			t.Fatalf("the encoder refused kind 0x%04x with %v, want ErrServerAttachmentKindUnknown", code, err)
		}
		refusals++
	}
	if refusals != 0x10000-len(defined) {
		t.Fatalf("%d kinds were refused and %d are undefined", refusals, 0x10000-len(defined))
	}
	t.Logf("%d undefined kinds refused on both sides", refusals)
}

// A kind and a body that disagree are refused rather than resolved.
//
// One value carried in two places is a second thing to get wrong, and the plausible mistake
// is not a malicious one: a caller that sets Kind and forgets to set the body, or that swaps
// a body in and leaves the old Kind. Resolving it — encoding whichever half the encoder
// preferred — would put a record on the wire whose author believed it said something else,
// and the server would act on the half this package chose.
//
// This is the one body the tag does not name. The other half of the presence rule — more
// bodies than one, whatever the tag — fails in a direction this loop cannot reach and is
// asserted below over a cross product of its own.
func TestAKindAndABodyThatDisagreeAreRefused(t *testing.T) {
	byKind := validAttachmentsByKind(t)
	for _, code := range specAttachmentCodes() {
		kind := ServerAttachmentKind(code)
		for _, otherCode := range specAttachmentCodes() {
			other := ServerAttachmentKind(otherCode)
			if other == kind {
				continue
			}
			mislabelled := *byKind[kind]
			mislabelled.Kind = other
			what := fmt.Sprintf("the %s body under kind %s", specAttachmentKindNames[kind], specAttachmentKindNames[other])
			_, err := EncodeServerAttachment(&mislabelled)
			if err == nil {
				t.Fatalf("%s: accepted", what)
			}
			if !errors.Is(err, ErrServerAttachmentBody) {
				t.Errorf("%s: refused with %v, want ErrServerAttachmentBody", what, err)
			}
		}
	}
}

// One body pointer of ServerAttachment: where it sits in the struct, the name a failure
// reports it by, and the value the package's own valid attachment of that kind carries.
type attachmentBodyField struct {
	index int
	name  string
	value reflect.Value
}

// Every body ServerAttachment can carry, read off the struct rather than listed.
//
// The class the presence rule is about is "more than one body set", and this project has
// been walked past a hand written membership list twelve times: a list of the four body
// fields, or of the pairs of them, is a list that understates the class the day a fifth
// pointer is declared. So the fields are found by walking the type for its pointers — Kind
// is the only field that is not one — and each is paired with the value it holds in the
// valid attachment that sets it, which is how the walk learns what a well formed body of
// that field looks like without a table anyone has to keep in step.
//
// Both directions are asserted rather than assumed. A pointer no valid attachment sets is a
// body every cross product below would skip in silence, and a pointer two of them set is one
// the walk cannot attribute, so each is a fatal here rather than a gap there.
func attachmentBodyFields(t testing.TB) []attachmentBodyField {
	t.Helper()
	byKind := validAttachmentsByKind(t)
	fields := []attachmentBodyField{}
	structType := reflect.TypeOf(ServerAttachment{})
	for i := range structType.NumField() {
		declared := structType.Field(i)
		if declared.Type.Kind() != reflect.Pointer {
			continue
		}
		var value reflect.Value
		for _, code := range specAttachmentCodes() {
			field := reflect.ValueOf(*byKind[ServerAttachmentKind(code)]).Field(i)
			if field.IsNil() {
				continue
			}
			if value.IsValid() {
				t.Fatalf("two valid attachments set %s, so the walk cannot say which kind's body it is", declared.Name)
			}
			value = field
		}
		if !value.IsValid() {
			t.Fatalf("no valid attachment sets %s, so no cross product below ever puts a body in it", declared.Name)
		}
		fields = append(fields, attachmentBodyField{index: i, name: declared.Name, value: value})
	}
	if len(fields) < 2 {
		t.Fatalf("ServerAttachment carries %d body pointers, so no attachment can carry two and the walk below holds vacuously", len(fields))
	}
	return fields
}

// An attachment carrying more than one body is refused, whichever bodies they are and
// whatever kind it is labelled — and nothing comes out of the encoder when it is.
//
// This is the other half of the rule above and it fails in a direction the mislabelling half
// cannot see. bodyKind reports the LAST body it finds, in the order the struct declares them,
// so `carried != a.Kind` already refuses every arrangement whose EARLIER body is the one Kind
// names. The arrangements it does not refuse are the ones whose later body matches — a
// WrapTag and an EpochComplete under kind EpochComplete, say — and for those the presence
// count is the only thing standing between the caller and an encoding. Without it the encoder
// writes the one body the switch reaches and drops the other on the floor, which is verbatim
// the failure the ServerAttachment doc comment says is refused: an attachment carrying an
// EpochAttachment under the WrapTag tag encoded as a wrap tag with the epoch attachment
// quietly dropped. The record's H(server_attachment) then covers an attachment its author did
// not write, and the server indexes a wrap record as a marker with nothing anywhere refusing
// it.
//
// The space is every subset of the bodies with at least two in it, crossed with every kind
// the alphabet defines, both computed rather than written down. A pair picked by hand covers
// one of twelve orderings and — since six of the twelve are refused by the mislabelling half
// anyway — has a one in two chance of observing nothing at all.
func TestEveryAttachmentCarryingMoreThanOneBodyIsRefusedUnderEveryKind(t *testing.T) {
	fields := attachmentBodyFields(t)
	codes := specAttachmentCodes()
	refused := 0
	for subset := 1; subset < 1<<len(fields); subset++ {
		for _, code := range codes {
			attachment := &ServerAttachment{Kind: ServerAttachmentKind(code)}
			bodies := reflect.ValueOf(attachment).Elem()
			names := []string{}
			for i, field := range fields {
				if subset&(1<<i) == 0 {
					continue
				}
				bodies.Field(field.index).Set(field.value)
				names = append(names, field.name)
			}
			if len(names) < 2 {
				continue
			}
			what := fmt.Sprintf("the %s bodies at once under kind %s",
				strings.Join(names, " and "), specAttachmentKindNames[ServerAttachmentKind(code)])
			bs, err := EncodeServerAttachment(attachment)
			if err == nil {
				t.Fatalf("%s: accepted, and it encoded to %s — every body but one is dropped from the wire",
					what, hex.EncodeToString(bs))
			}
			if !errors.Is(err, ErrServerAttachmentBody) {
				t.Errorf("%s: refused with %v, want ErrServerAttachmentBody", what, err)
			}
			// a refusal that still answered bytes is a refusal a caller ignoring the error
			// puts on the wire, which is the same dropped body by another route
			if len(bs) != 0 {
				t.Errorf("%s: refused and still answered %s", what, hex.EncodeToString(bs))
			}
			refused++
		}
	}
	// the subsets of two or more, crossed with the alphabet, counted from the two derived
	// sets rather than from a number typed here
	if want := (1<<len(fields) - 1 - len(fields)) * len(codes); refused != want {
		t.Fatalf("%d multi body attachments were offered and the cross product has %d in it", refused, want)
	}
	t.Logf("%d multi body attachments refused across %d bodies and %d kinds", refused, len(fields), len(codes))
}

// ── what check 3 relies on NOT being refused ────────────────────────────────────────

// Both durable_ttl_seconds sentinels are legal, and so is every other value of both retention
// fields.
//
// This is the half a hand written range check breaks silently, and it is the reason there is
// no comparison against either sentinel anywhere in attachment.go. Spec B section 5.1 check 3
// says both are "legal values here and are resolved at section 6.1 step (6), never refused",
// and section 7.3 case 3 forbids refusing either in all cases. They mean different things — 0
// is "the group set nothing" and 4294967295 is "the group asked for indefinite" — and both
// are resolved against the server's own advertised policy, which is arithmetic this layer
// cannot do and must not pre-empt. A refusal here refuses a commit, and a refused commit is a
// group that cannot rekey.
func TestBothDurableTtlSentinelsAndEveryOtherRetentionValueAreLegal(t *testing.T) {
	sentinels := []uint32{0, 4294967295}
	for _, sentinel := range sentinels {
		attachment := validEpochAttachment(0, 42, 1, sentinel, 1)
		bs, err := EncodeServerAttachment(attachment)
		if err != nil {
			t.Fatalf("durable_ttl_seconds %d was refused by the encoder: %v", sentinel, err)
		}
		parsed, err := ParseServerAttachment(bs)
		if err != nil {
			t.Fatalf("durable_ttl_seconds %d was refused by the parser: %v", sentinel, err)
		}
		if parsed.Epoch.DurableTtlSeconds != sentinel {
			t.Errorf("durable_ttl_seconds %d came back as %d", sentinel, parsed.Epoch.DurableTtlSeconds)
		}
	}
	// and the whole range, on both retention fields, so the property is about the fields and
	// not about the two values
	for _, media := range u32Boundaries() {
		for _, durable := range u32Boundaries() {
			attachment := validEpochAttachment(0, 42, media, durable, 1)
			bs, err := EncodeServerAttachment(attachment)
			if err != nil {
				t.Fatalf("media %d durable %d was refused by the encoder: %v", media, durable, err)
			}
			parsed, err := ParseServerAttachment(bs)
			if err != nil {
				t.Fatalf("media %d durable %d was refused by the parser: %v", media, durable, err)
			}
			if parsed.Epoch.MediaTtlSeconds != media || parsed.Epoch.DurableTtlSeconds != durable {
				t.Errorf("media %d durable %d came back as %d and %d", media, durable, parsed.Epoch.MediaTtlSeconds, parsed.Epoch.DurableTtlSeconds)
			}
		}
	}
}

// The marker's wrap_count carries no bound of its own, zero included.
//
// Its one rule is equality against the epoch's expected_wrap_count, and that attachment is
// something this layer is never handed: spec B section 5.1 check 3 phrases it as "EpochComplete
// with a matching wrap_count", and matching is a question about state the server holds. A bound
// invented here would be this package guessing at the answer, and a wrong guess refuses a
// marker the server would have accepted, which leaves the group readable and not writable.
func TestTheMarkersWrapCountCarriesNoBoundOfItsOwn(t *testing.T) {
	for _, count := range u32Boundaries() {
		attachment := validEpochComplete(42, count)
		bs, err := EncodeServerAttachment(attachment)
		if err != nil {
			t.Fatalf("wrap_count %d was refused by the encoder: %v", count, err)
		}
		parsed, err := ParseServerAttachment(bs)
		if err != nil {
			t.Fatalf("wrap_count %d was refused by the parser: %v", count, err)
		}
		if parsed.Complete.WrapCount != count {
			t.Errorf("wrap_count %d came back as %d", count, parsed.Complete.WrapCount)
		}
	}
}

// ── the two halves admit the same attachments ───────────────────────────────────────

// The set of attachments EncodeServerAttachment will write and the set ParseServerAttachment
// will read are the same set.
//
// Asserted over a space computed from the package's own alphabet crossed with the edges of
// every rule the checks have: a length either side of every exact width, an algorithm
// identifier either side of the one its kind names, an expected_wrap_count of zero and one, a
// kind past the top of the alphabet. Both halves run the one checkServerAttachment, so what
// this really observes is that neither entry point has grown a check of its own — which is
// the edit that makes the server refuse a record the client considers valid.
func TestTheEncoderAndTheParserAdmitTheSameAttachments(t *testing.T) {
	byKind := validAttachmentsByKind(t)
	candidates := []struct {
		name       string
		attachment *ServerAttachment
	}{}
	add := func(name string, a *ServerAttachment) {
		candidates = append(candidates, struct {
			name       string
			attachment *ServerAttachment
		}{name: name, attachment: a})
	}
	for _, code := range specAttachmentCodes() {
		kind := ServerAttachmentKind(code)
		add(specAttachmentKindNames[kind], byKind[kind])
	}
	for _, field := range attachmentWidthFields(t) {
		for _, length := range []int{field.width - 1, field.width, field.width + 1} {
			if length < 0 {
				continue
			}
			fresh := validAttachmentsByKind(t)[field.kind]
			attachmentBodyValue(fresh).FieldByName(field.name).Set(reflect.ValueOf(fillBytes(0xFD, length)))
			add(fmt.Sprintf("%s.%s at %d", specAttachmentKindNames[field.kind], field.name, length), fresh)
		}
	}
	for kind, want := range attachmentAlgIds {
		for _, value := range []uint16{want - 1, want, want + 1} {
			fresh := validAttachmentsByKind(t)[kind]
			attachmentBodyValue(fresh).FieldByName("AlgId").Set(reflect.ValueOf(value))
			add(fmt.Sprintf("%s alg 0x%04x", specAttachmentKindNames[kind], value), fresh)
		}
	}
	for _, count := range []uint32{0, 1} {
		add(fmt.Sprintf("epoch wraps %d", count), validEpochAttachment(0, 42, 1, 1, count))
	}
	top := specAttachmentCodes()[len(specAttachmentCodes())-1]
	add("a kind past the top of the alphabet", &ServerAttachment{Kind: ServerAttachmentKind(top + 1)})

	encoded := 0
	refused := 0
	for _, candidate := range candidates {
		bs, encodeErr := EncodeServerAttachment(candidate.attachment)
		// the absent attachment has no raw form to reach the parser with — its encoding is
		// no octets at all — and its two sides are asserted by the absent/empty tests above
		if candidate.attachment.Kind == AttachmentNone && encodeErr == nil {
			encoded++
			continue
		}
		_, parseErr := ParseServerAttachment(rawAttachmentOf(t, candidate.attachment).encode(t))
		if (encodeErr == nil) != (parseErr == nil) {
			t.Errorf("%s: the encoder says %v and the parser says %v; the two halves disagree about whether this attachment exists",
				candidate.name, encodeErr, parseErr)
			continue
		}
		if encodeErr != nil {
			refused++
			continue
		}
		encoded++
		if _, err := ParseServerAttachment(bs); err != nil {
			t.Errorf("%s: the encoder wrote it and the parser refused it: %v", candidate.name, err)
		}
	}
	if encoded == 0 {
		t.Fatal("the space reached no attachment the encoder writes, so the agreement holds vacuously")
	}
	if refused == 0 {
		t.Fatal("the space reached no refusal, so the agreement says nothing about what either half refuses")
	}
	t.Logf("%d candidates, %d encoded and %d refused by both halves", len(candidates), encoded, refused)
}

// ── the fuzz target ─────────────────────────────────────────────────────────────────

const attachmentFuzzCorpusDir = "testdata/fuzz/FuzzParseServerAttachment"

// The corpus checked in beside the fuzz target is read, and it says something.
//
// A corpus directory whose name no longer matches its target is replayed by nothing and
// reported by nothing, so its contents are asserted rather than assumed: it exists, it holds
// entries, and it holds both accepted and refused ones. An input that is refused exercises
// the refusal and stops, and it is the accepted ones that have to re-encode to themselves, so
// a corpus that drifted into refusals alone would leave the whole re-encode half of the fuzz
// property unreachable from it.
//
// The property itself is asserted here as well, over exactly the bytes the fuzz target would
// see, so a corpus entry that violates it fails an ordinary go test rather than waiting for
// somebody to pass -fuzz.
func TestTheCheckedInAttachmentFuzzCorpusIsReadAndSaysSomething(t *testing.T) {
	entries, err := os.ReadDir(attachmentFuzzCorpusDir)
	if err != nil {
		t.Fatalf("the checked-in fuzz corpus is unreadable at %s: %v", attachmentFuzzCorpusDir, err)
	}
	accepted := 0
	refused := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		bs := fuzzCorpusEntry(t, filepath.Join(attachmentFuzzCorpusDir, entry.Name()))
		attachment, err := ParseServerAttachment(bs)
		if err != nil {
			refused++
			continue
		}
		accepted++
		again, err := EncodeServerAttachment(attachment)
		if err != nil {
			t.Fatalf("%s: parsed and then refused to re-encode: %v", entry.Name(), err)
		}
		if !bytes.Equal(again, bs) {
			t.Fatalf("%s: parsed and re-encoded to %d different octets, so this attachment has two encodings", entry.Name(), len(again))
		}
	}
	if accepted+refused == 0 {
		t.Fatalf("%s holds no corpus entry, so the fuzz target replays nothing but its own well formed seeds", attachmentFuzzCorpusDir)
	}
	if accepted == 0 {
		t.Fatalf("%s: all %d entries are refused, so no entry ever reaches the re-encode half of the property", attachmentFuzzCorpusDir, refused)
	}
	if refused == 0 {
		t.Fatalf("%s: all %d entries are accepted, so the malformed inputs it exists to carry are gone", attachmentFuzzCorpusDir, accepted)
	}
	t.Logf("%d corpus entries, %d accepted and %d refused", accepted+refused, accepted, refused)
}

// The one property that has to hold over bytes nobody chose: an input is refused, or it
// re-encodes to itself exactly. Anything else is a second encoding of one attachment, and
// H(server_attachment) — which reaches the write_auth mac and both aeads — is over exactly
// one of them.
//
// The seeds this function adds are well formed, because a mutator wants a valid attachment to
// work outward from. The malformed inputs live in testdata/fuzz/FuzzParseServerAttachment,
// checked in, which is what makes a plain go test replay them: the absent attachment spelled
// out, a kind nothing defines, a key one octet short, a body region longer than the fields
// inside it. Those are edits no single octet walk in this file produces, and having them on
// disk is also what gives a finding from an explicit -fuzz run somewhere to land.
func FuzzParseServerAttachment(f *testing.F) {
	for _, entry := range attachmentWalkCorpus(f) {
		bs, err := EncodeServerAttachment(entry.attachment)
		if err != nil {
			f.Fatalf("%s: EncodeServerAttachment refused a corpus attachment: %v", entry.name, err)
		}
		f.Add(bs)
	}
	for _, vector := range attachmentGoldenVectors {
		bs, err := hex.DecodeString(vector)
		if err != nil {
			f.Fatalf("a golden vector is not hexadecimal: %v", err)
		}
		f.Add(bs)
	}
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x00, 0x01})

	f.Fuzz(func(t *testing.T, bs []byte) {
		attachment, err := ParseServerAttachment(bs)
		if err != nil {
			return
		}
		if carried, set := attachment.bodyKind(); carried != attachment.Kind || 1 < set {
			t.Fatalf("accepted an attachment of kind 0x%04x carrying %d bodies, the last of them kind 0x%04x",
				uint16(attachment.Kind), set, uint16(carried))
		}
		again, err := EncodeServerAttachment(attachment)
		if err != nil {
			t.Fatalf("accepted %d octets and then refused to re-encode them: %v", len(bs), err)
		}
		if !bytes.Equal(again, bs) {
			t.Fatalf("accepted %d octets and re-encoded to %d different ones, so this attachment has two encodings", len(bs), len(again))
		}
	})
}
