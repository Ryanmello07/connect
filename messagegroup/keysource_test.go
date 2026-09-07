// CP3b's defining property, held as a STANDING test: no test-only key source anywhere on the
// record path.
//
// THE CLASS IS DERIVED AND NOT LISTED. The property's subject is every octet used as an AEAD
// key, an AEAD nonce or a MAC key by SealRecord or OpenRecord. A written down list of the
// derivations that produce those octets understates the class the moment a second key source
// is added, which is the one event this file exists to catch, so the class is closed from the
// other end instead: THE WHOLE SEALED RECORD IS REBUILT, BYTE FOR BYTE, from three values and
// nothing else. Every keyed octet of a record is inside a reproduction of that record by
// definition, so an octet drawn from anywhere this file is not given moves ct_body, ct_head,
// sender_handle or write_auth, and one of the four comparisons below goes red.
//
// THE THREE VALUES, and there are no others:
//
//	mls_secret    the REAL group's Export("URmessage/v1/storage", nil, 32), taken off the same
//	              mls.Group the session under test is holding
//	pq_secret     the value the constructor was injected with; the session takes it as a
//	              required argument and has no default to fall back to
//	server_nonce  the value the constructor was injected with; write_auth is a mac over it
//
// Neither of the last two is a KEY -- sessionfixture_test.go's header draws that distinction
// and CP3b's bar rests on it -- and the first IS the MLS key schedule's output. So a
// reproduction that succeeds from these three is the statement that every key of the record
// layer is the MLS key schedule expanded, and nothing else.
//
// NOTHING ON THE REPRODUCTION'S SIDE OF THE COMPARISON COMES FROM THE MODULE UNDER TEST, and
// that is the whole of what makes this evidence rather than a tautology. A reproduction that
// reached for the record layer's own sealer would seal under whatever key the record layer
// chose -- a key it drew from a second source included -- and would agree with it forever. What
// stands in for it is RFC 5869 written out from the RFC, chacha20poly1305.NewX, crypto/hmac and
// crypto/sha256.
//
// StorageRoot, GroupHandleKey, SenderHandle, DeriveClassKeys, RecordKeyZero, RecordKeyNext,
// RecordAeadHead, RecordAeadBody, sealRecordAead, padBody, message.AADHead, message.AADBody,
// message.WriteKey and message.ComputeWriteAuth are the fourteen names this paragraph used to
// list. THEY ARE AN ILLUSTRATION AND NOT THE CLASS. Four of them are in connect/message and
// were outside the gate that once held this claim, which is how a reviewer pointed the
// reproduction at message.WriteKey and left all three tests green. The class is now every name
// the MODULE declares, read off go.mod and the import graph, and the gate at the bottom of this
// file is where it is derived, what its scope is, and -- stated rather than implied -- what it
// still cannot see.
//
// THE REPRODUCTION CANNOT SEE THE TWO VALUES IT REPRODUCES, and that is a type rather than a
// promise. keySourceShape carries every PUBLIC field of the record: the group id, the leaf,
// the epoch, the stream index, is_commit, the retention wire byte, the size bucket, expire_at,
// the blob id, the encoded attachment and the two plaintexts. It has NO field for
// sender_handle and NO field for body_hash, which are the two header values the key schedule
// produces, so a reproduction that read the sealer's answer for either -- and therefore
// compared the sealer against itself -- does not compile.
//
// ---------------------------------------------------------------------------
// WHAT THIS FILE CANNOT SEE
// ---------------------------------------------------------------------------
//
// (1) A key source that is itself a function of these three values. What is observed is
// DEPENDENCE and EXCLUSIVITY, not the absence of a constant from the source text: a second
// derivation of the SAME material -- one rung expanded twice, one label spelled two ways that
// agree -- reproduces identically and is invisible here. What is not invisible is any value
// MIXED IN from elsewhere, which is what "a second key source" means: a constant, a second
// exporter label, an entropy draw, a per-process seed, a leftover from another epoch. Every
// one of those breaks the reproduction, and the negative control below is what proves the
// reproduction is CAPABLE of breaking: it flips each of the 256 bits of the exporter output in
// turn and requires all four outputs to move for every one of them.
//
// (2) A path this record does not take. These are three records on the DURABLE class, on the
// 256 octet rung, at the first three rungs of one sender's ladder, in EPOCH ZERO of a one
// member group, with no attachment and no blob id. A key source reached only from the
// permanent, media or eph classes is outside the observation -- and unreachable today for a
// second reason, since SealRecord refuses every class but durable until M1-6 is ruled. So is
// one reached only by the blob rung, or only by a receiver walking a skipped key window. What
// covers those is that they are the same four derivations under other arguments, which is a
// structural argument and not this file's measurement.
//
// (3) Anything at all about epoch > 0. group_handle_key is HKDF-Expand(storage_root[0],
// "gh/v1", 32) and this fixture's group is at epoch zero, so the root derived here IS the
// epoch zero root. The test ASSERTS that epoch rather than assuming it, which is what makes
// the reproduction legal rather than lucky. At any later epoch sender_handle is a function of
// a root this file is not given -- which is the whole reason group_handle_key is persisted
// state -- and TestTheGroupHandleKeyDoesNotMoveWhenTheEpochDoes is what holds that, not this.
//
// (4) Whether the MLS exporter is itself right. mls_secret arrives as whatever the real group
// answers, and connect/mls's own cross-implementation vectors are what hold RFC 9420 section
// 8.5. This file asks only what the record layer does with the answer.
//
// (5) The read key. message.ReadKey is on neither SealRecord's nor OpenRecord's path -- no
// record is macd under it -- so it is outside the derived class and outside the reproduction.
//
// (6) The OPEN side's derivations directly. What binds them is the last assertion of the first
// test: the record opens, through the session, to exactly the two plaintexts that went in. A
// second key source on the open side alone is a record that does not open; a second key source
// on BOTH sides is a record whose ciphertexts this reproduction does not match. There is no
// third case.
//
// ---------------------------------------------------------------------------
// WHY THE LABELS ARE TRANSCRIBED HERE RATHER THAN READ OFF THE PACKAGE
// ---------------------------------------------------------------------------
//
// Every label, width and code point below is transcribed from MASTER and spec A. Reaching for
// durableClassInfo, recordAeadBodyInfo or mlsSecretLabel would let a label change move both
// halves together and leave this file green over a wire format no second implementation
// computes -- the same failure the KAT sets in keyschedule_test.go, recordkey_test.go and
// handle_test.go exist to close. This is the fourth transcription of them and not the first
// sharing of one.
//
// SO IF THIS FILE DISAGREES WITH THE PACKAGE, ONE OF THE TWO IS WRONG, AND WHICH ONE IS A
// RULING QUESTION RATHER THAN A FIXTURE TO RETUNE. M1-6, M1-7 and M1-8 are all open over
// values this reproduction spells out, and a ruling that moves one of them moves this file
// too -- as an edit somebody makes deliberately, with the ruling in hand.
//
// RFC 5869 is the one thing taken from elsewhere in the test tree rather than transcribed
// again: keyScheduleReferenceExtract and keyScheduleReferenceExpand are already written out
// from the RFC in keyschedule_test.go and are already held against pinned vectors, and a
// second spelling of HKDF in this package's tests would be the second construction of one
// thing that this project bans everywhere else.
package messagegroup

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/connect/message"
	"golang.org/x/crypto/chacha20poly1305"
)

// The exporter call MASTER section 7 derives mls_secret with, transcribed.
const (
	keySourceExporterLabel = "URmessage/v1/storage"
	keySourceExporterBytes = 32
)

// Every label the chain from storage_root to a sealed record expands under, transcribed from
// MASTER section 7, MASTER section 8, MASTER section 8.1, MASTER section 9.2 and spec A
// section 5.3. They are separate constants here for the reason they are separate constants in
// the package: one construction with a word substituted into it is one edit away from making
// two keys equal.
const (
	keySourceGroupHandleInfo   = "gh/v1"
	keySourceSenderHandleInfo  = "sh/v1"
	keySourceDurableClassInfo  = "durable/v1"
	keySourceRecordKeyZeroInfo = "sender/v1"
	keySourceRecordKeyNextInfo = "ratchet/v1"
	keySourceAeadHeadInfo      = "rec/v1/head"
	keySourceAeadBodyInfo      = "rec/v1/body"
	keySourceWriteKeyInfo      = "write/v1"
)

// The three domain separation labels of the preimages, transcribed from MASTER section 7.1 and
// MASTER section 9.2.
const (
	keySourceAadHeadLabel   = "URmessage/v1/aad/head"
	keySourceAadBodyLabel   = "URmessage/v1/aad/body"
	keySourceWriteAuthLabel = "URmessage/v1/write"
)

// The widths and the two code points, transcribed.
const (
	keySourceKeyBytes       = 32
	keySourceHandleBytes    = 16
	keySourceAeadKeyBytes   = 32
	keySourceAeadNonceBytes = 24
	keySourceAeadTagBytes   = 16
	// MASTER section 7.1's registration for XChaCha20-Poly1305, carried inside both aads.
	keySourceAeadAlgId uint16 = 0x0021
	// MASTER section 8's retention table, the durable row: the CLASS tag and the wire byte it
	// joins to. BOTH are transcribed, and neither is read off the package into the shape any
	// more. Asking message.RetentionClassWire for the wire byte -- which keySourceShapeOf used
	// to do -- put one of the record layer's own derivations on the reproduction's side of the
	// comparison, and retention_wire is carried by both aads and by the write_auth preimage, so
	// it is a keyed octet by the definition this file opens with.
	keySourceDurableClassCode byte = 0x01
	keySourceDurableWire      byte = 0x01
	// MASTER's size ladder, the 256 octet rung: the bucket TAG and the octet count it names. The
	// count fixes octet_length(ct_body), so it is on the same side of the same line.
	keySourceSizeBucketCode byte = 0x00
	keySourceRungBytes           = 256
)

// keySourceShape is every PUBLIC field of one record: what a server, or anybody holding the
// record, can read without a key.
//
// THERE IS NO sender_handle FIELD AND NO body_hash FIELD, and their absence is the point. Both
// are outputs of the key schedule, both sit in RecordHeader, and both are values the
// reproduction below produces; a shape that carried either would let the reproduction read the
// sealer's own answer for the thing it is supposed to be recomputing. keyschedule.go's
// ClassKeys makes the same move for eph_root and seal.go's staging chain makes it for the
// construction order: the wrong thing is not made difficult, it is made unrepresentable.
type keySourceShape struct {
	groupId     [32]byte
	leaf        uint32
	epoch       uint64
	streamIndex uint64
	isCommit    bool
	// the JOINED wire byte of MASTER section 8's table and never the go tag, which is the value
	// both aads and the write_auth preimage carry.
	retentionWire byte
	sizeBucket    byte
	// the octet length of the rung the padded body fills, which is what fixes
	// octet_length(ct_body) at rung + 16.
	rungBytes  int
	expireAt   uint64
	blobId     []byte
	attachment []byte
	headPlain  []byte
	bodyPlain  []byte
}

// keySourceReproduction is what the three values alone produce: the record's two ciphertexts,
// the hash that binds them, the handle the server routes on and the mac the server checks.
//
// These four are every octet of a record that is not already in the shape above, which is what
// makes "the record is reproduced" the same statement as "no key came from anywhere else".
type keySourceReproduction struct {
	senderHandle [16]byte
	ctBody       []byte
	bodyHash     [32]byte
	ctHead       []byte
	writeAuth    [32]byte
}

// reproduceRecordFromTheExporterOutput rebuilds one whole sealed record from mls_secret,
// pq_secret and server_nonce, using RFC 5869, XChaCha20-Poly1305 and HMAC-SHA-256 directly.
//
// The order is spec A section 5.2's and MASTER section 8's, and it is that order for the reason
// seal.go's staging types are: hash the attachment, seal ct_body, hash it, seal ct_head, mac the
// record. Nothing here reads a value it has not already computed.
func reproduceRecordFromTheExporterOutput(t *testing.T, mlsSecret []byte, pqSecret []byte,
	serverNonce []byte, shape keySourceShape) keySourceReproduction {

	t.Helper()

	// storage_root[n] = HKDF-Extract(salt = mls_secret[n], ikm = pq_secret[n]). The salt is
	// FIRST, which is guardrail G1: crypto/hkdf writes the two the other way round, and a
	// transposition here would produce a root that is thirty two well formed octets and that
	// the package's own StorageRoot does not compute.
	storageRoot := keyScheduleReferenceExtract(mlsSecret, pqSecret)

	// group_handle_key = HKDF-Expand(storage_root[0], "gh/v1", 32). The caller asserts the group
	// is at epoch zero, which is what makes the root in hand the epoch ZERO root.
	groupHandleKey := keyScheduleReferenceExpand(storageRoot,
		[]byte(keySourceGroupHandleInfo), keySourceKeyBytes)
	// sender_handle = HKDF-Expand(group_handle_key, "sh/v1" | LP(leaf_index), 16), on the four
	// octet reading of LP(leaf_index) that open item M1-8 will rule.
	senderHandle := [16]byte(keyScheduleReferenceExpand(groupHandleKey,
		append([]byte(keySourceSenderHandleInfo), recordKeyReferenceLP(shape.leaf)...),
		keySourceHandleBytes))

	// the durable class key, then this sender's ladder walked to the record's own index. The
	// walk is what makes stream_index a key input rather than a label: a record at index k is
	// sealed under the k'th rung and under no other.
	classKey := keyScheduleReferenceExpand(storageRoot,
		[]byte(keySourceDurableClassInfo), keySourceKeyBytes)
	recordKey := keyScheduleReferenceExpand(classKey,
		append([]byte(keySourceRecordKeyZeroInfo), recordKeyReferenceLP(shape.leaf)...),
		keySourceKeyBytes)
	for walked := uint64(0); walked < shape.streamIndex; walked += 1 {
		recordKey = keyScheduleReferenceExpand(recordKey,
			[]byte(keySourceRecordKeyNextInfo), keySourceKeyBytes)
	}

	// key | nonce, the key FIRST, which is the order MASTER section 8.1 writes and a
	// transposition of which produces two values of the right widths that seal against
	// themselves and against nothing else. The fifty six is the sum of the aead's own two
	// widths rather than a written down number, for keyschedule.go's reason.
	bodyMaterial := keyScheduleReferenceExpand(recordKey, []byte(keySourceAeadBodyInfo),
		keySourceAeadKeyBytes+keySourceAeadNonceBytes)
	headMaterial := keyScheduleReferenceExpand(recordKey, []byte(keySourceAeadHeadInfo),
		keySourceAeadKeyBytes+keySourceAeadNonceBytes)
	writeKey := keyScheduleReferenceExpand(storageRoot,
		[]byte(keySourceWriteKeyInfo), keySourceKeyBytes)

	attachmentHash := sha256.Sum256(shape.attachment)

	// aad_body, which carries no body_hash at all: guardrail G4 is that the body's aad cannot
	// depend on the hash of the body it is sealing.
	aadBody := keySourceJoin(
		[]byte(keySourceAadBodyLabel),
		keySourceU16(keySourceAeadAlgId),
		keySourceLP(shape.groupId[:]),
		keySourceLP(senderHandle[:]),
		keySourceU64(shape.epoch),
		keySourceU64(shape.streamIndex),
		[]byte{shape.retentionWire},
	)

	// LP(plaintext) into a buffer exactly the rung, tail zero. Open item M1-7's scheme, whose
	// fill is pinned octet by octet in m1w1repairs_test.go rather than guessed at here.
	if shape.rungBytes < len(shape.bodyPlain)+4 {
		t.Fatalf("a %d octet body does not fit the %d octet rung this shape names",
			len(shape.bodyPlain), shape.rungBytes)
	}
	padded := make([]byte, shape.rungBytes)
	copy(padded, keySourceLP(shape.bodyPlain))

	ctBody := keySourceSeal(t, bodyMaterial, aadBody, padded)
	bodyHash := sha256.Sum256(ctBody)

	// aad_head, which covers every field of the header, body_hash included, which is what makes
	// the head's authentication cover the body it belongs to.
	aadHead := keySourceJoin(
		[]byte(keySourceAadHeadLabel),
		keySourceU16(keySourceAeadAlgId),
		keySourceLP(shape.groupId[:]),
		keySourceLP(senderHandle[:]),
		keySourceU64(shape.epoch),
		keySourceU64(shape.streamIndex),
		[]byte{keySourceIsCommitByte(shape.isCommit)},
		[]byte{shape.retentionWire},
		[]byte{shape.sizeBucket},
		keySourceU64(shape.expireAt),
		keySourceLP(bodyHash[:]),
		// unconditional, and a nil blob id writes the four zero octets.
		keySourceLP(shape.blobId),
		keySourceLP(attachmentHash[:]),
	)
	ctHead := keySourceSeal(t, headMaterial, aadHead, shape.headPlain)

	// write_auth's preimage, MASTER section 9.2. LP(H(ct_head)) is the HASH of ct_head and never
	// ct_head, which is the field a reader is most likely to write straight.
	ctHeadHash := sha256.Sum256(ctHead)
	preimage := keySourceJoin(
		[]byte(keySourceWriteAuthLabel),
		keySourceLP(serverNonce),
		keySourceLP(shape.groupId[:]),
		keySourceLP(senderHandle[:]),
		keySourceU64(shape.epoch),
		keySourceU64(shape.streamIndex),
		[]byte{keySourceIsCommitByte(shape.isCommit)},
		[]byte{shape.retentionWire},
		[]byte{shape.sizeBucket},
		keySourceU64(shape.expireAt),
		keySourceLP(ctHeadHash[:]),
		keySourceLP(bodyHash[:]),
		keySourceLP(shape.blobId),
		keySourceLP(attachmentHash[:]),
	)
	mac := hmac.New(sha256.New, writeKey)
	mac.Write(preimage)

	return keySourceReproduction{
		senderHandle: senderHandle,
		ctBody:       ctBody,
		bodyHash:     bodyHash,
		ctHead:       ctHead,
		writeAuth:    [32]byte(mac.Sum(nil)),
	}
}

// keySourceSeal runs XChaCha20-Poly1305 over one of the record's two plaintexts, splitting the
// fifty six octets of expansion the way MASTER section 8.1 does.
//
// It is chacha20poly1305.NewX and never chacha20poly1305.New: the two differ by one character
// and by twelve octets of nonce, and recordaead.go's file comment argues at length that nothing
// inside one implementation can tell them apart.
func keySourceSeal(t *testing.T, material []byte, aad []byte, plaintext []byte) []byte {
	t.Helper()
	if len(material) != keySourceAeadKeyBytes+keySourceAeadNonceBytes {
		t.Fatalf("the aead material is %d octets, want %d", len(material),
			keySourceAeadKeyBytes+keySourceAeadNonceBytes)
	}
	aead, err := chacha20poly1305.NewX(material[:keySourceAeadKeyBytes])
	if err != nil {
		t.Fatalf("build the record aead over a %d octet key: %v", keySourceAeadKeyBytes, err)
	}
	return aead.Seal(nil, material[keySourceAeadKeyBytes:], plaintext, aad)
}

// LP(x): a thirty two bit big endian length followed by x, which is the record layer's one
// length prefix. It is written out here rather than taken from mls/syntax for the reason the
// labels are transcribed: a prefix width that moved would otherwise move both halves together.
func keySourceLP(x []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(x))), x...)
}

func keySourceU16(v uint16) []byte {
	return binary.BigEndian.AppendUint16(nil, v)
}

func keySourceU64(v uint64) []byte {
	return binary.BigEndian.AppendUint64(nil, v)
}

func keySourceIsCommitByte(isCommit bool) byte {
	if isCommit {
		return 1
	}
	return 0
}

// keySourceJoin concatenates the parts of a preimage in the order they are written.
func keySourceJoin(parts ...[]byte) []byte {
	joined := []byte{}
	for _, part := range parts {
		joined = append(joined, part...)
	}
	return joined
}

// keySourceShapeOf reads the PUBLIC half of a sealed record into a shape.
//
// It takes the two plaintexts from the CALLER, which is what they are: what went in. Everything
// else comes off the header, because everything else is a value anybody holding the record can
// read without a key -- and the two fields that are NOT such values, sender_handle and
// body_hash, have nowhere in the shape to go.
func keySourceShapeOf(t *testing.T, record *message.Record, leaf uint32,
	headPlain []byte, bodyPlain []byte) keySourceShape {

	t.Helper()
	header := record.Header
	// the record is held against the TRANSCRIPTIONS, and the transcriptions are what the shape
	// then carries. This function used to call message.RetentionClassWire and
	// message.SizeBucketBytes and put their answers in the shape, which is two of the record
	// layer's own derivations producing octets the reproduction compares. What the package thinks
	// those two values are is asked on the other side of the gate, by
	// TestTheTranscribedRetentionAndSizeAgreeWithThePackage, and its answer never arrives here.
	if byte(header.RetentionClass) != keySourceDurableClassCode {
		t.Fatalf("this reproduction is written for MASTER section 8's durable class %#02x and the record carries %#02x",
			keySourceDurableClassCode, byte(header.RetentionClass))
	}
	if header.EphBucket != 0 {
		t.Fatalf("the durable row of MASTER section 8's table carries eph bucket 0 and the record carries %d",
			header.EphBucket)
	}
	if byte(header.SizeBucket) != keySourceSizeBucketCode {
		t.Fatalf("this reproduction is written for the %#02x rung of MASTER's ladder and the record carries %#02x",
			keySourceSizeBucketCode, byte(header.SizeBucket))
	}
	return keySourceShape{
		groupId:       header.GroupId,
		leaf:          leaf,
		epoch:         header.Epoch,
		streamIndex:   header.StreamIndex,
		isCommit:      header.IsCommit,
		retentionWire: keySourceDurableWire,
		sizeBucket:    keySourceSizeBucketCode,
		rungBytes:     keySourceRungBytes,
		expireAt:      header.ExpireAt,
		blobId:        header.BlobId,
		attachment:    header.ServerAttachment,
		headPlain:     headPlain,
		bodyPlain:     bodyPlain,
	}
}

// keySourceSealed is one fixture's worth of evidence: the three values the reproduction is
// allowed, the records that came out of a real session over a real group, and what those records
// opened back to.
//
// IT CARRIES NO SESSION AND NO GROUP HANDLE, and that is the boundary the gate at the bottom of
// this file rests on. keySourceSealRecords is the one function that gate excludes -- it has to
// call the record layer, because CP3b's bar is that the fixture is REAL -- and this type is what
// stops the exclusion leaking: nothing that crosses it can seal, open, export or derive. Only
// octets cross, and one subject. TestTheFixtureCanHandTheReproductionNothingItCouldSealWith
// holds that field by field, through this package's test types, so a *testSession put back here
// fails on the commit that puts it back.
type keySourceSealed struct {
	// the three values of the file header, taken here so that the reproduction's own caller
	// never has to reach the fixture for one.
	mlsSecret   []byte
	pqSecret    []byte
	serverNonce []byte
	// the sender's leaf index, which is public and is a SHAPE input rather than a key: the
	// record header carries sender_handle, which is the key schedule's function of it.
	leaf         uint32
	records      []*message.Record
	heads        [][]byte
	bodies       [][]byte
	openedHeads  [][]byte
	openedBodies [][]byte
}

// The head plaintext is EIGHTEEN octets on every record, so ct_head is thirty four, and every
// body lands on the 256 octet rung, so ct_body is two hundred and seventy two. Both widths are
// asserted rather than left implicit: a reproduction that agreed with a record of the wrong
// shape would be agreeing about the wrong thing.
const (
	keySourceHeadPlainBytes = 18
	keySourceRecordCount    = 3
)

// keySourceSealRecords founds a group, seals three records on one ladder, and collects the three
// values the reproduction is allowed to see.
//
// THREE RECORDS AND NOT ONE, because the ladder walk is a key input. The reserver hands out the
// first index above its high water, so these land on three consecutive rungs and the walk in the
// reproduction runs a different number of times for each; a single record at the ladder's head
// would leave the walk untaken and a defect in it invisible.
func keySourceSealRecords(t *testing.T, name string) *keySourceSealed {
	t.Helper()
	fixture := newTestSession(t, name)
	fixture.trackOwn(t)
	sealed := &keySourceSealed{
		pqSecret:    testPqSecret(),
		serverNonce: testServerNonce(),
		// the leaf is read HERE rather than in the reproduction's caller, because
		// GroupHandle.OwnLeafIndex is the record layer's and the caller is inside the gate.
		leaf: fixture.handle.OwnLeafIndex(),
	}
	for i := 0; i < keySourceRecordCount; i += 1 {
		head := []byte(fmt.Sprintf("record head %06d", i))
		if len(head) != keySourceHeadPlainBytes {
			t.Fatalf("the head plaintext is %d octets and this file is written for %d",
				len(head), keySourceHeadPlainBytes)
		}
		body := make([]byte, 100+i)
		for at := range body {
			body[at] = byte(at*11 + i)
		}
		record, err := fixture.session.SealRecord(message.RetentionDurable, 0, false, head, body, 0, nil)
		if err != nil {
			t.Fatalf("SealRecord %d: %v", i, err)
		}
		// the OPEN half of the class, run HERE for the same reason. See (6) in the file header
		// for what it binds: a second key source on the open side alone is a record that does
		// not open, and a second key source on both sides is a record this reproduction does not
		// match. The assertion body compares what came back; it does not run the open itself,
		// because the assertion bodies are inside the gate and the record layer's own open is
		// the subject rather than the reproduction.
		openedHead, openedBody, err := fixture.session.OpenRecord(record)
		if err != nil {
			t.Fatalf("record %d: OpenRecord: %v", i, err)
		}
		sealed.records = append(sealed.records, record)
		sealed.heads = append(sealed.heads, head)
		sealed.bodies = append(sealed.bodies, body)
		sealed.openedHeads = append(sealed.openedHeads, openedHead)
		sealed.openedBodies = append(sealed.openedBodies, openedBody)
	}
	// the group's OWN exporter, under the label MASTER section 7 names, at the width it names.
	// This is the one secret the reproduction is handed, and it comes off the real mls.Group the
	// session is holding rather than off anything this file made up.
	mlsSecret, err := fixture.handle.Export(keySourceExporterLabel, nil, keySourceExporterBytes)
	if err != nil {
		t.Fatalf("export the epoch's mls_secret: %v", err)
	}
	if len(mlsSecret) != keySourceExporterBytes {
		t.Fatalf("the exporter answered %d octets, want %d", len(mlsSecret), keySourceExporterBytes)
	}
	sealed.mlsSecret = mlsSecret
	// epoch zero is ASSERTED and not assumed: group_handle_key is expanded from storage_root[0],
	// so at any later epoch this reproduction would be deriving sender_handle from a root it was
	// never given. See (3) in the file header.
	epoch, err := fixture.session.Epoch()
	if err != nil {
		t.Fatalf("read the session's epoch: %v", err)
	}
	if epoch != 0 {
		t.Fatalf("this reproduction is only legal at epoch 0 and the session is at epoch %d", epoch)
	}
	return sealed
}

// reproduce rebuilds record i from the three values and the record's public half.
func (self *keySourceSealed) reproduce(t *testing.T, i int, mlsSecret []byte) keySourceReproduction {
	t.Helper()
	shape := keySourceShapeOf(t, self.records[i], self.leaf, self.heads[i], self.bodies[i])
	return reproduceRecordFromTheExporterOutput(t, mlsSecret, self.pqSecret, self.serverNonce, shape)
}

// CP3b's bar, standing: no test-only key source anywhere on the path.
//
// This is the only test in this package that can go red when somebody introduces a key source
// that is not the MLS key schedule. Every other case here observes that the record layer agrees
// with ITSELF -- it round trips, it refuses what it should, its ladder does not repeat -- and
// all of those stay green under a second key source, because a second key source is still well
// formed, still deterministic and still round trips.
func TestEveryKeyedOctetOfARecordIsReproducibleFromTheExporterAndTheTwoInjectedValuesAlone(t *testing.T) {
	sealed := keySourceSealRecords(t, "no-second-key-source")
	for i, record := range sealed.records {
		got := sealed.reproduce(t, i, sealed.mlsSecret)
		// the two widths, so that an agreement about a record of the wrong shape is not read as
		// an agreement about this one.
		if len(record.CtHead) != keySourceHeadPlainBytes+keySourceAeadTagBytes {
			t.Errorf("record %d: ct_head is %d octets, want %d",
				i, len(record.CtHead), keySourceHeadPlainBytes+keySourceAeadTagBytes)
		}
		if len(record.CtBody) != keySourceRungBytes+keySourceAeadTagBytes {
			t.Errorf("record %d: ct_body is %d octets, want %d",
				i, len(record.CtBody), keySourceRungBytes+keySourceAeadTagBytes)
		}
		if got.senderHandle != record.Header.SenderHandle {
			t.Errorf("record %d: sender_handle rebuilt from the exporter output is %x and the record carries %x; a handle the exporter does not produce is a handle from a second key source",
				i, got.senderHandle, record.Header.SenderHandle)
		}
		if string(got.ctBody) != string(record.CtBody) {
			t.Errorf("record %d: ct_body rebuilt from the exporter output is %x and the record carries %x",
				i, got.ctBody, record.CtBody)
		}
		if got.bodyHash != record.Header.BodyHash {
			t.Errorf("record %d: body_hash rebuilt from the exporter output is %x and the record carries %x",
				i, got.bodyHash, record.Header.BodyHash)
		}
		if string(got.ctHead) != string(record.CtHead) {
			t.Errorf("record %d: ct_head rebuilt from the exporter output is %x and the record carries %x",
				i, got.ctHead, record.CtHead)
		}
		if got.writeAuth != record.WriteAuth {
			t.Errorf("record %d: write_auth rebuilt from the exporter output is %x and the record carries %x; a mac key the exporter does not produce is a mac key from a second key source",
				i, got.writeAuth, record.WriteAuth)
		}
		// and the OPEN half of the class, bound to the same reproduction. See (6) in the file
		// header: a second key source on the open side alone is a record that does not open. The
		// open ran in the fixture, which is the one function outside the gate below; what is
		// compared here is what it answered.
		if string(sealed.openedHeads[i]) != string(sealed.heads[i]) ||
			string(sealed.openedBodies[i]) != string(sealed.bodies[i]) {
			t.Errorf("record %d: opened to %d and %d octets, want %d and %d",
				i, len(sealed.openedHeads[i]), len(sealed.openedBodies[i]),
				len(sealed.heads[i]), len(sealed.bodies[i]))
		}
	}
	t.Logf("%d records rebuilt byte for byte from Export(%q, nil, %d), pq_secret and server_nonce",
		len(sealed.records), keySourceExporterLabel, keySourceExporterBytes)
}

// The negative control, and it matters as much as the reproduction does.
//
// A reproduction that could not FAIL would certify anything, and this project has shipped nine
// consecutive tasks' worth of tests that could not. So every one of the 256 bits of the exporter
// output is flipped in turn and all four outputs are required to move: if any bit of mls_secret
// could be changed without moving ct_body, ct_head, sender_handle and write_auth, then that part
// of the record is not a function of the exporter output at all, which is the same defect stated
// from the other side.
//
// It flips the EXPORTER OUTPUT specifically, because that is the value CP3b is about. That
// pq_secret and server_nonce are also live inputs is held by
// TestTheStorageRootDependsOnTheInjectedPqSecret and by message/writeauth_test.go's nonce cases.
func TestFlippingAnyBitOfTheExporterOutputChangesEveryKeyedOctetOfARecord(t *testing.T) {
	sealed := keySourceSealRecords(t, "one-bit-of-the-exporter")
	// the control is anchored to reality first: the unflipped reproduction IS the record, so a
	// difference below is a difference from the record and not from some third thing.
	base := sealed.reproduce(t, 0, sealed.mlsSecret)
	record := sealed.records[0]
	if base.senderHandle != record.Header.SenderHandle || string(base.ctBody) != string(record.CtBody) ||
		string(base.ctHead) != string(record.CtHead) || base.writeAuth != record.WriteAuth {
		t.Fatal("the unflipped reproduction is not the record, so nothing this control observes is about the record")
	}
	flips := 0
	for octet := range sealed.mlsSecret {
		for bit := 0; bit < 8; bit += 1 {
			flipped := append([]byte(nil), sealed.mlsSecret...)
			flipped[octet] ^= 1 << bit
			got := sealed.reproduce(t, 0, flipped)
			if got.senderHandle == base.senderHandle {
				t.Errorf("bit %d of octet %d of the exporter output does not reach sender_handle", bit, octet)
			}
			if string(got.ctBody) == string(base.ctBody) {
				t.Errorf("bit %d of octet %d of the exporter output does not reach ct_body", bit, octet)
			}
			if string(got.ctHead) == string(base.ctHead) {
				t.Errorf("bit %d of octet %d of the exporter output does not reach ct_head", bit, octet)
			}
			if got.writeAuth == base.writeAuth {
				t.Errorf("bit %d of octet %d of the exporter output does not reach write_auth", bit, octet)
			}
			flips += 1
		}
	}
	if flips != len(sealed.mlsSecret)*8 {
		t.Errorf("%d bit flips were tried and the exporter output is %d octets", flips, len(sealed.mlsSecret))
	}
}

// The two table values keySourceShapeOf transcribes, held against the package that ships them.
//
// IT IS ON THE OTHER SIDE OF THE GATE ON PURPOSE. This is the one place the record layer is
// asked what it thinks the durable wire byte and the 256 octet rung are, and its answer is
// compared against a transcription and thrown away -- it reaches no shape and no preimage. Until
// this test existed the comparison happened inside keySourceShapeOf and the package's answer WAS
// the shape's, which put two derivations of the record layer on the reproduction's side.
//
// The retention class tag and the size bucket tag are pinned too, because they are what
// keySourceShapeOf holds the record against: a tag that moved without this test would make every
// record fail the shape check with no statement about which of the two was wrong.
func TestTheTranscribedRetentionAndSizeAgreeWithThePackage(t *testing.T) {
	if byte(message.RetentionDurable) != keySourceDurableClassCode {
		t.Errorf("message.RetentionDurable is %#02x and MASTER section 8's durable row is transcribed here as %#02x",
			byte(message.RetentionDurable), keySourceDurableClassCode)
	}
	wire, err := message.RetentionClassWire(message.RetentionDurable, 0)
	if err != nil {
		t.Fatalf("join the durable class and bucket 0: %v", err)
	}
	if wire != keySourceDurableWire {
		t.Errorf("the durable class joins to wire byte %#02x and MASTER section 8's table is transcribed here as %#02x",
			wire, keySourceDurableWire)
	}
	if byte(message.SizeBucket256) != keySourceSizeBucketCode {
		t.Errorf("message.SizeBucket256 is %#02x and this file transcribes the rung's tag as %#02x",
			byte(message.SizeBucket256), keySourceSizeBucketCode)
	}
	if rung := message.SizeBucketBytes(message.SizeBucket(keySourceSizeBucketCode)); rung != keySourceRungBytes {
		t.Errorf("size bucket %#02x is %d octets on the ladder and this file transcribes it as %d",
			keySourceSizeBucketCode, rung, keySourceRungBytes)
	}
}

// ---------------------------------------------------------------------------
// the gate that holds the reproduction's independence, DERIVED FROM THE PROPERTY IT NAMES
// ---------------------------------------------------------------------------

// The whole of what makes the reproduction above evidence rather than a tautology is that no
// code of the module under test produces any octet it compares. That claim was a paragraph; then
// it was a gate over the wrong class; this is the third version, and the difference between the
// second and the third is the whole subject of this comment.
//
// WHAT THE SECOND VERSION GOT WRONG, because it is the defect this project keeps repeating: its
// class was "identifiers declared in connect/messagegroup" -- the DIRECTORY the file happens to
// sit in -- and the property is "code that produces the record's keyed octets". Those are not
// the same set, and a reviewer walked through the gap three times:
//
//	(1) message.WriteKey, message.ComputeWriteAuth, message.AADHead and message.AADBody are four
//	    of the fourteen names the file header bans by name, all on SealRecord's path, all in the
//	    OTHER package of the record layer -- and all outside a class derived from this directory.
//	    A second key source planted in message.WriteKey went red on the reproduction; pointing
//	    the reproduction at message.WriteKey turned all three tests green with the gate still
//	    green.
//	(2) The matcher read *ast.CallExpr nodes and nothing else, so a production package level
//	    const or var was invisible to it. A hard coded second key source planted as a package
//	    constant, read by the reproduction, passed everything.
//	(3) The scope was the closure seeded at reproduceRecordFromTheExporterOutput, which EXCLUDES
//	    the two test bodies that carry the comparisons -- so a production derivation called from
//	    the assertion side could make a comparison tautological and stay invisible.
//
// All three are one error at three altitudes: the artefact was derived from the INSTANCE the
// property was first seen in rather than from the property. So all three are re-derived.
//
// THE CLASS IS EVERY NAME THE MODULE DECLARES. The module path is read out of go.mod, the
// package set is walked from this package and from its test source's imports through every
// module internal import transitively, and the class is every function, every method, every
// package level constant, every package level variable and every type their production source
// declares. connect/message, connect/mls and connect/mls/syntax are in it today because this
// package's production source imports them, and a package the next import adds is in it with no
// edit here. message.WriteKey is a member. So is a constant nobody has written yet.
//
// THE REACH IS CALLS AND REFERENCES. A name is reached whether it is called, read as a constant,
// taken as a value or named as a type. That is (2), and it is why the matcher walks identifiers
// rather than call expressions.
//
// THE SCOPE IS THE WHOLE COMPARISON. It is walked in BOTH directions from
// reproduceRecordFromTheExporterOutput: backwards to every test function that transitively
// reaches it -- which is what the two assertion bodies are -- and forwards from each of those
// through everything they reach. That is (3), and the gate asserts the backward walk found
// something, because a backward walk that found nothing reports the clean run a complete one
// reports.
//
// ONE FUNCTION IS OUTSIDE THE SCOPE, AND IT IS DERIVED RATHER THAN NAMED. CP3b's bar is that the
// fixture is REAL: a real mls.Group, the real sealer, the real open. So the function that founds
// the group, seals the records, opens them and takes the exporter's answer must call the record
// layer, and a gate that banned that would ban the evidence. It is found by its RESULT TYPE, as
// the one test function that answers a *keySourceSealed, and the gate fails if there is not
// exactly one -- a second one would be a second door, and writing this one's name in a list
// would be the same enumeration this section exists to undo. The gate also fails if anything
// else in the scope reaches into that function's closure other than through the function itself,
// because an exclusion that had grown to swallow an assertion body would clear it in silence.
//
// AND WHAT IT HANDS ACROSS IS A TYPE. keySourceSealed carries the three values, the leaf, the
// records and what they opened to, and no live session and no group handle -- so the excluded
// function cannot pass its reach along. TestTheFixtureCanHandTheReproductionNothingItCouldSealWith
// holds that field by field and THROUGH this package's test structs, so a *testSession put back
// on the boundary fails even though *testSession is a test type.
//
// ---------------------------------------------------------------------------
// WHAT THIS GATE STILL CANNOT SEE, stated rather than implied
// ---------------------------------------------------------------------------
//
// (a) THE SUBJECT PRODUCER ITSELF, which is the price of the exclusion above. A second key
// source MIRRORED in it -- a fixture that perturbs the exporter's answer the same way a
// perturbed production side does -- reproduces and passes. Two things stand against that and
// neither is this gate: the boundary type, which is why nothing but octets crosses, and that
// such an edit is a deliberate change to the fixture rather than to a derivation.
//
// (b) RESOLUTION IS SYNTACTIC. Names are resolved by their qualifier and not by go/types, which
// this module cannot reach: golang.org/x/tools is not a dependency and this gate is not worth
// adding one for. A selector rooted at an imported non module package, or at a local whose value
// came from one, is read as that package's -- which is what keeps aead.Seal from being read as
// connect/mls's Seal, since connect/mls really does declare a Seal. A selector the walk cannot
// root falls back to matching the selected name against the module's declarations, which OVER
// reports rather than under: a standard library method that one day shares a name with a module
// function fails here, naming the call and the file. That is the safe direction for a ban, and
// it is the direction mls/crypto_forbidden_test.go argues for its own matcher. A FIELD read off
// an unrooted value is not matched, because the record's public half is read exactly that way
// and is one of the reproduction's declared inputs rather than a derivation.
//
// (c) DYNAMIC REACH. A module function reached through a value this walk cannot follow -- a func
// typed struct field, a method value in a map -- is outside the name matching above. Nothing in
// the scope does that today and nothing here would say so if it started.
//
// (d) A SECOND DERIVATION OF THE SAME MATERIAL, unchanged from (1) in the file header. This gate
// holds that no module code produced these octets. It does not hold that the octets could not
// have been produced twice.

// The four controls, one per shape the matcher has to recognise, and nothing calls any of them.
//
// They exist so that a matcher which stopped matching fails HERE rather than reporting the
// reproduction clean having recognised nothing -- the same shape mls/crypto_forbidden_test.go's
// testdata/forbidden fixture has. Two of them are the reviewer's escapes written down as code:
// the constant read is (2), and the connect/message pair is (1). The gate asserts each is
// OUTSIDE the scope before it believes what the matcher said about it, because a control that
// had drifted into the scope would be a control reporting on itself.
func keySourceControlThatCallsThisPackagesDerivation(recordKey []byte) ([]byte, []byte) {
	return RecordAeadBody(recordKey)
}

func keySourceControlThatReadsThisPackagesConstant() uint16 {
	return RecordAeadAlgId
}

func keySourceControlThatCallsAnotherModulePackage(storageRoot []byte) []byte {
	return message.WriteKey(storageRoot)
}

func keySourceControlThatReadsAnotherModulePackage() message.RetentionClass {
	return message.RetentionDurable
}

// keySourceModulePackage is one package of the module under test, with every name its production
// source declares.
type keySourceModulePackage struct {
	importPath string
	funcs      map[string]bool
	values     map[string]bool
	types      map[string]bool
}

// keySourceTestFile is one of this package's test files, with the imports a name written in it
// resolves through. Resolution is per FILE because import names are.
type keySourceTestFile struct {
	path          string
	moduleImports map[string]string
	otherImports  map[string]bool
	dotImports    []string
}

// keySourceTestFunction is one function of this package's test source, with the file it was
// written in.
type keySourceTestFunction struct {
	name string
	decl *ast.FuncDecl
	file *keySourceTestFile
}

// keySourceTestStruct is one struct type of this package's test source, with the file it was
// written in -- which is the file its field types resolve through, and which is read off the
// declaration rather than guessed at by name.
type keySourceTestStruct struct {
	decl *ast.StructType
	file *keySourceTestFile
}

// keySourceReach is one name of the class that a scanned body reaches, with how it reached it.
type keySourceReach struct {
	from  string
	file  string
	name  string
	owner string
	kind  string
}

func (self keySourceReach) String() string {
	return fmt.Sprintf("%s (%s) %s %s, which %s declares", self.from, self.file, self.kind, self.name, self.owner)
}

// keySourceModuleRoot walks up from this package to the go.mod that declares the module, and
// answers the directory holding it and the module path it declares.
//
// Both are READ rather than written down, which is what makes "the module under test" a fact of
// the tree: a module rename carries this gate's class with it instead of emptying it.
func keySourceModuleRoot(t *testing.T) (string, string) {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("resolve this package's directory: %v", err)
	}
	for {
		source, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err == nil {
			for _, line := range strings.Split(string(source), "\n") {
				if path, isModule := strings.CutPrefix(strings.TrimSpace(line), "module "); isModule {
					return dir, strings.TrimSpace(path)
				}
			}
			t.Fatalf("%s declares no module path, so this gate has no module to derive a class from",
				filepath.Join(dir, "go.mod"))
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above this package, so this gate cannot derive the module under test")
		}
		dir = parent
	}
}

// keySourceReadModulePackage reads one package's production declarations, and answers the module
// internal imports it holds, which is how the package set below grows.
func keySourceReadModulePackage(t *testing.T, importPath string, dir string,
	modulePath string) (*keySourceModulePackage, []string) {

	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s, which %s names: %v", dir, importPath, err)
	}
	read := &keySourceModulePackage{
		importPath: importPath,
		funcs:      map[string]bool{},
		values:     map[string]bool{},
		types:      map[string]bool{},
	}
	imports := []string{}
	fileSet := token.NewFileSet()
	files := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.ToSlash(filepath.Join(dir, name))
		parsed, err := parser.ParseFile(fileSet, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		files += 1
		for _, imported := range parsed.Imports {
			held := strings.Trim(imported.Path.Value, `"`)
			if held == modulePath || strings.HasPrefix(held, modulePath+"/") {
				imports = append(imports, held)
			}
		}
		for _, declaration := range parsed.Decls {
			switch declaration := declaration.(type) {
			case *ast.FuncDecl:
				read.funcs[declaration.Name.Name] = true
			case *ast.GenDecl:
				for _, spec := range declaration.Specs {
					switch spec := spec.(type) {
					case *ast.ValueSpec:
						for _, name := range spec.Names {
							// the blank identifier names nothing. `var _ GroupHandle = ...` is an
							// interface satisfaction assertion, and reading it into the class
							// makes every `for _, x := range` in the scope a reach.
							if name.Name != "_" {
								read.values[name.Name] = true
							}
						}
					case *ast.TypeSpec:
						read.types[spec.Name.Name] = true
					}
				}
			}
		}
	}
	if files == 0 {
		t.Fatalf("%s holds no production go file, so this gate read an empty class out of %s", dir, importPath)
	}
	return read, imports
}

// keySourceModuleClass is THE CLASS: every name the production source of every module package
// this package or its test source can reach declares.
//
// The seeds are this package itself and every module package its TEST source imports, so a test
// file reaching for a package the production source does not import still hands the gate the
// class it would need to see it. Growth from there is transitive and needs no edit here.
func keySourceModuleClass(t *testing.T, root string, modulePath string,
	files []*keySourceTestFile) (map[string]*keySourceModulePackage, string) {

	t.Helper()
	here, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("resolve this package's directory: %v", err)
	}
	relative, err := filepath.Rel(root, here)
	if err != nil {
		t.Fatalf("place this package inside %s: %v", root, err)
	}
	selfImport := modulePath
	if relative != "." {
		selfImport = modulePath + "/" + filepath.ToSlash(relative)
	}
	frontier := []string{selfImport}
	for _, file := range files {
		for _, path := range file.moduleImports {
			frontier = append(frontier, path)
		}
	}
	class := map[string]*keySourceModulePackage{}
	for 0 < len(frontier) {
		importPath := frontier[len(frontier)-1]
		frontier = frontier[:len(frontier)-1]
		if _, isRead := class[importPath]; isRead {
			continue
		}
		dir := root
		if importPath != modulePath {
			dir = filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(importPath, modulePath+"/")))
		}
		read, imports := keySourceReadModulePackage(t, importPath, dir, modulePath)
		class[importPath] = read
		frontier = append(frontier, imports...)
	}
	if _, isRead := class[selfImport]; !isRead {
		t.Fatalf("%s was not read into the class, so the gate banned nothing this package declares", selfImport)
	}
	return class, selfImport
}

// keySourceTestSource reads this package's test source: every function by name, every file's
// import resolution, and every struct type, which the boundary check below walks.
func keySourceTestSource(t *testing.T, modulePath string) (map[string]*keySourceTestFunction,
	[]*keySourceTestFile, map[string]*keySourceTestStruct) {

	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read this package's directory: %v", err)
	}
	fileSet := token.NewFileSet()
	functions := map[string]*keySourceTestFunction{}
	files := []*keySourceTestFile{}
	structs := map[string]*keySourceTestStruct{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.ToSlash(filepath.Join(".", name))
		parsed, err := parser.ParseFile(fileSet, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		file := &keySourceTestFile{
			path:          path,
			moduleImports: map[string]string{},
			otherImports:  map[string]bool{},
		}
		for _, imported := range parsed.Imports {
			held := strings.Trim(imported.Path.Value, `"`)
			local := held[strings.LastIndex(held, "/")+1:]
			if imported.Name != nil {
				local = imported.Name.Name
			}
			if local == "." {
				file.dotImports = append(file.dotImports, held)
				continue
			}
			if held == modulePath || strings.HasPrefix(held, modulePath+"/") {
				file.moduleImports[local] = held
				continue
			}
			file.otherImports[local] = true
		}
		files = append(files, file)
		for _, declaration := range parsed.Decls {
			switch declaration := declaration.(type) {
			case *ast.FuncDecl:
				if declaration.Body == nil {
					continue
				}
				// a method and a function of one name collapse to one entry, which is the safe
				// direction: it pulls MORE source into the walk rather than less.
				functions[declaration.Name.Name] = &keySourceTestFunction{
					name: declaration.Name.Name, decl: declaration, file: file,
				}
			case *ast.GenDecl:
				for _, spec := range declaration.Specs {
					typed, isType := spec.(*ast.TypeSpec)
					if !isType {
						continue
					}
					if structure, isStruct := typed.Type.(*ast.StructType); isStruct {
						structs[typed.Name.Name] = &keySourceTestStruct{decl: structure, file: file}
					}
				}
			}
		}
	}
	if len(functions) == 0 {
		t.Fatal("no test function was read out of this package, so this gate scoped itself to nothing")
	}
	return functions, files, structs
}

// keySourceExprRoot is the leftmost identifier of an expression: the thing a selector chain, a
// call or a type is written on.
func keySourceExprRoot(node ast.Expr) string {
	for {
		switch typed := node.(type) {
		case nil:
			return ""
		case *ast.Ident:
			return typed.Name
		case *ast.SelectorExpr:
			node = typed.X
		case *ast.CallExpr:
			node = typed.Fun
		case *ast.IndexExpr:
			node = typed.X
		case *ast.StarExpr:
			node = typed.X
		case *ast.ParenExpr:
			node = typed.X
		case *ast.UnaryExpr:
			node = typed.X
		case *ast.SliceExpr:
			node = typed.X
		case *ast.TypeAssertExpr:
			node = typed.X
		case *ast.CompositeLit:
			node = typed.Type
		case *ast.ArrayType:
			node = typed.Elt
		case *ast.Ellipsis:
			node = typed.Elt
		default:
			return ""
		}
	}
}

// keySourceNonModuleRoots is every name inside one function that resolves to a package OUTSIDE
// this module, so a selector written on it is that package's rather than a name to match.
//
// It is what stops aead.Seal from being read as connect/mls's Seal: aead came out of
// chacha20poly1305.NewX, and t came in as a *testing.T. Without it the widened class goes red on
// the standard library, which is a gate that has to be turned off rather than one that holds.
func keySourceNonModuleRoots(function *keySourceTestFunction) map[string]bool {
	rooted := map[string]bool{}
	for _, list := range []*ast.FieldList{function.decl.Recv, function.decl.Type.Params, function.decl.Type.Results} {
		if list == nil {
			continue
		}
		for _, field := range list.List {
			if !function.file.otherImports[keySourceExprRoot(field.Type)] {
				continue
			}
			for _, name := range field.Names {
				rooted[name.Name] = true
			}
		}
	}
	note := func(targets []ast.Expr, values []ast.Expr) bool {
		grew := false
		for at, value := range values {
			root := keySourceExprRoot(value)
			if !function.file.otherImports[root] && !rooted[root] {
				continue
			}
			taking := targets
			if len(values) == len(targets) {
				taking = targets[at : at+1]
			}
			for _, target := range taking {
				name, isIdent := target.(*ast.Ident)
				if isIdent && !rooted[name.Name] {
					rooted[name.Name] = true
					grew = true
				}
			}
		}
		return grew
	}
	// to a fixpoint, because one local's package can arrive through another's.
	for pass := 0; pass < 8; pass += 1 {
		grew := false
		ast.Inspect(function.decl.Body, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.AssignStmt:
				grew = note(typed.Lhs, typed.Rhs) || grew
			case *ast.ValueSpec:
				targets := []ast.Expr{}
				for _, name := range typed.Names {
					targets = append(targets, name)
				}
				if function.file.otherImports[keySourceExprRoot(typed.Type)] {
					grew = note(targets, []ast.Expr{typed.Type}) || grew
				}
				grew = note(targets, typed.Values) || grew
			}
			return true
		})
		if !grew {
			break
		}
	}
	return rooted
}

// keySourceOwnerOf is the module package that declares a name, or the empty string. Packages are
// consulted in a fixed order, so a name two of them declare reports the same one every run.
func keySourceOwnerOf(name string, class map[string]*keySourceModulePackage, functionsOnly bool) string {
	for _, importPath := range keySourceSortedKeys(class) {
		read := class[importPath]
		if read.funcs[name] {
			return importPath
		}
		if !functionsOnly && (read.values[name] || read.types[name]) {
			return importPath
		}
	}
	return ""
}

// keySourceModuleReaches is THE MATCHER: every name of the class one function's body reaches,
// through a call, a constant read, a value or a type.
func keySourceModuleReaches(function *keySourceTestFunction, class map[string]*keySourceModulePackage,
	selfImport string) []keySourceReach {

	body := function.decl.Body
	rooted := keySourceNonModuleRoots(function)
	selected := map[*ast.Ident]bool{}
	keyed := map[*ast.Ident]bool{}
	called := map[ast.Expr]bool{}
	ast.Inspect(body, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.SelectorExpr:
			selected[typed.Sel] = true
		case *ast.KeyValueExpr:
			if name, isIdent := typed.Key.(*ast.Ident); isIdent {
				keyed[name] = true
			}
		case *ast.CallExpr:
			called[typed.Fun] = true
		}
		return true
	})
	found := []keySourceReach{}
	report := func(name string, owner string, kind string) {
		found = append(found, keySourceReach{
			from: function.name, file: function.file.path, name: name, owner: owner, kind: kind,
		})
	}
	kindOf := func(node ast.Expr) string {
		if called[node] {
			return "calls"
		}
		return "reads"
	}
	ast.Inspect(body, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.SelectorExpr:
			root := keySourceExprRoot(typed.X)
			if path, isModulePackage := function.file.moduleImports[root]; isModulePackage {
				report(root+"."+typed.Sel.Name, path, kindOf(typed))
				return true
			}
			if function.file.otherImports[root] || rooted[root] {
				return true
			}
			// a selector on a value this walk cannot root. Only a CALL is matched: a field read
			// off an unrooted value is how the record's public half is read, and that is one of
			// the reproduction's declared inputs rather than a derivation.
			if called[typed] {
				if owner := keySourceOwnerOf(typed.Sel.Name, class, true); owner != "" {
					report(typed.Sel.Name, owner, "calls")
				}
			}
		case *ast.Ident:
			if selected[typed] || keyed[typed] || typed.Name == "_" {
				return true
			}
			// unqualified, so it can only be this package's own production source: every other
			// package of the module has to be reached through an import name, and the gate
			// refuses a dot import for exactly that reason.
			own := class[selfImport]
			if own.funcs[typed.Name] || own.values[typed.Name] || own.types[typed.Name] {
				report(typed.Name, selfImport, kindOf(typed))
			}
		}
		return true
	})
	lines := []string{}
	seen := map[string]bool{}
	compacted := []keySourceReach{}
	for _, reach := range found {
		line := reach.String()
		if seen[line] {
			continue
		}
		seen[line] = true
		lines = append(lines, line)
	}
	slices.Sort(lines)
	for _, line := range lines {
		for _, reach := range found {
			if reach.String() == line {
				compacted = append(compacted, reach)
				break
			}
		}
	}
	return compacted
}

// keySourceMentionedNames is every name a body mentions: a bare identifier by its own name, a
// selector by the name it selects.
//
// The call graph below is built out of this rather than out of call expressions, because a
// function reached as a VALUE is still reached.
func keySourceMentionedNames(function *ast.FuncDecl) []string {
	names := []string{}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.Ident:
			names = append(names, typed.Name)
		case *ast.SelectorExpr:
			names = append(names, typed.Sel.Name)
		}
		return true
	})
	return names
}

// keySourceForwardClosure is every test function reachable from the seeds, the seeds included.
func keySourceForwardClosure(seeds []string, functions map[string]*keySourceTestFunction) map[string]bool {
	closure := map[string]bool{}
	frontier := []string{}
	for _, seed := range seeds {
		closure[seed] = true
		frontier = append(frontier, seed)
	}
	for 0 < len(frontier) {
		name := frontier[len(frontier)-1]
		frontier = frontier[:len(frontier)-1]
		function, isDeclared := functions[name]
		if !isDeclared {
			continue
		}
		for _, mentioned := range keySourceMentionedNames(function.decl) {
			if closure[mentioned] {
				continue
			}
			if _, isTestFunction := functions[mentioned]; !isTestFunction {
				continue
			}
			closure[mentioned] = true
			frontier = append(frontier, mentioned)
		}
	}
	return closure
}

// keySourceBackwardClosure is every test function that transitively REACHES the seed, the seed
// included. It is what puts the assertion bodies inside this gate.
func keySourceBackwardClosure(seed string, functions map[string]*keySourceTestFunction) map[string]bool {
	callers := map[string][]string{}
	for name, function := range functions {
		for _, mentioned := range keySourceMentionedNames(function.decl) {
			if _, isTestFunction := functions[mentioned]; isTestFunction {
				callers[mentioned] = append(callers[mentioned], name)
			}
		}
	}
	closure := map[string]bool{seed: true}
	frontier := []string{seed}
	for 0 < len(frontier) {
		name := frontier[len(frontier)-1]
		frontier = frontier[:len(frontier)-1]
		for _, caller := range callers[name] {
			if closure[caller] {
				continue
			}
			closure[caller] = true
			frontier = append(frontier, caller)
		}
	}
	return closure
}

// keySourceSortedKeys is the keys of a map in one order, so every list this gate prints and every
// package order it resolves through is the same on every run.
func keySourceSortedKeys[V any](held map[string]V) []string {
	keys := []string{}
	for key := range held {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

// keySourceNamesTheFixture answers whether a result list names keySourceSealed, which is how the
// subject producer is found without writing its name down.
func keySourceNamesTheFixture(results *ast.FieldList) bool {
	if results == nil {
		return false
	}
	named := false
	for _, field := range results.List {
		ast.Inspect(field.Type, func(node ast.Node) bool {
			if name, isIdent := node.(*ast.Ident); isIdent && name.Name == "keySourceSealed" {
				named = true
			}
			return true
		})
	}
	return named
}

// The reproduction's whole side of the comparison reaches nothing the module under test ships.
//
// A reproduction that reached for the record layer's own derivations would rebuild the record
// under whatever key the record layer chose -- one drawn from a second source included -- and
// would agree with it forever. So would an assertion body that recomputed an expected octet the
// same way. That is the failure the two tests above exist to be immune to, and this is what
// keeps them immune to it as the module grows.
func TestNothingOnTheReproductionsSideOfTheComparisonComesFromTheModule(t *testing.T) {
	const seed = "reproduceRecordFromTheExporterOutput"
	root, modulePath := keySourceModuleRoot(t)
	functions, files, _ := keySourceTestSource(t, modulePath)
	class, selfImport := keySourceModuleClass(t, root, modulePath, files)
	if _, isDeclared := functions[seed]; !isDeclared {
		t.Fatalf("%s was not read out of this package's test source, so this gate walked nothing", seed)
	}
	// the class has to leave this DIRECTORY, which is the whole of escape (1): message.WriteKey
	// is on SealRecord's path and is not declared here.
	beyondThisPackage := []string{}
	names := 0
	for _, importPath := range keySourceSortedKeys(class) {
		read := class[importPath]
		names += len(read.funcs) + len(read.values) + len(read.types)
		if importPath != selfImport {
			beyondThisPackage = append(beyondThisPackage, importPath)
		}
	}
	if len(beyondThisPackage) == 0 {
		t.Fatalf("the class is %s and nothing else, so it is this directory again and message.WriteKey is outside it",
			selfImport)
	}
	// a dot import would put a module name in reach unqualified, which is the one thing this
	// matcher's per file resolution cannot see.
	for _, file := range files {
		if 0 < len(file.dotImports) {
			t.Errorf("%s dot imports %v, so a name of the module can be written in it unqualified and this gate resolves by qualifier",
				file.path, file.dotImports)
		}
	}
	// THE SCOPE, walked in both directions.
	backward := keySourceBackwardClosure(seed, functions)
	if len(backward) < 2 {
		t.Fatalf("nothing in this package's test source reaches %s, so the bodies that carry the comparisons are outside this gate",
			seed)
	}
	comparison := keySourceForwardClosure(keySourceSortedKeys(backward), functions)
	// the ONE exclusion, derived by result type: the function that produces the subject.
	producers := []string{}
	for _, name := range keySourceSortedKeys(functions) {
		if keySourceNamesTheFixture(functions[name].decl.Type.Results) {
			producers = append(producers, name)
		}
	}
	if len(producers) != 1 {
		t.Fatalf("%d test function(s) answer a *keySourceSealed and this gate excludes exactly one of them: %v",
			len(producers), producers)
	}
	producer := producers[0]
	if !comparison[producer] {
		t.Fatalf("%s produces the fixture and nothing in the comparison reaches it, so the scope this gate excluded is not the one it walked",
			producer)
	}
	excluded := keySourceForwardClosure([]string{producer}, functions)
	scope := map[string]bool{}
	for name := range comparison {
		if !excluded[name] {
			scope[name] = true
		}
	}
	// the exclusion may be entered ONLY through the producer. An exclusion that had grown to
	// swallow an assertion body would clear it in silence, which is this tree's most expensive
	// failure mode.
	for _, name := range keySourceSortedKeys(scope) {
		for _, mentioned := range keySourceMentionedNames(functions[name].decl) {
			if mentioned == producer || !excluded[mentioned] {
				continue
			}
			t.Errorf("%s is inside this gate and reaches %s, which %s's closure excluded: the exclusion is swallowing scope rather than bounding the subject",
				name, mentioned, producer)
		}
	}
	// the scope holds the ASSERTION BODIES, which is escape (3).
	inScope := []string{}
	spanned := []string{}
	for _, name := range keySourceSortedKeys(scope) {
		if strings.HasPrefix(name, "Test") {
			inScope = append(inScope, name)
		}
		if path := functions[name].file.path; !slices.Contains(spanned, path) {
			spanned = append(spanned, path)
		}
	}
	slices.Sort(spanned)
	if len(inScope) < 2 {
		t.Errorf("the scope holds %v, so the bodies that carry the four comparisons are outside this gate", inScope)
	}
	// and it holds something the forward walk alone cannot reach, which is what says the backward
	// walk ran at all rather than reporting the forward one's answer over again.
	forward := keySourceForwardClosure([]string{seed}, functions)
	backwardOnly := []string{}
	for _, name := range keySourceSortedKeys(scope) {
		if !forward[name] {
			backwardOnly = append(backwardOnly, name)
		}
	}
	if len(backwardOnly) == 0 {
		t.Errorf("every function in the scope is reachable forwards from %s, so the backward walk added nothing and this is the gate that missed the assertion bodies",
			seed)
	}
	// and it leaves this file, which is the reach claim: keyschedule_test.go's RFC 5869 reference
	// is what the reproduction expands through.
	if len(spanned) < 2 {
		t.Errorf("the scope stays inside %v, so nothing outside this file is gated by it", spanned)
	}
	// the four controls, one per shape, each outside the scope and each recognised.
	controls := map[string]string{
		"keySourceControlThatCallsThisPackagesDerivation": "a call to a function this package's production source declares",
		"keySourceControlThatReadsThisPackagesConstant":   "a READ of a package level constant, which a matcher walking call expressions cannot see",
		"keySourceControlThatCallsAnotherModulePackage":   "a call into connect/message, which a class derived from this DIRECTORY does not hold",
		"keySourceControlThatReadsAnotherModulePackage":   "a read of a connect/message constant, which is both escapes at once",
	}
	for _, name := range keySourceSortedKeys(controls) {
		control, isDeclared := functions[name]
		if !isDeclared {
			t.Fatalf("the control %s was not read out of this package's test source", name)
		}
		if comparison[name] {
			t.Fatalf("%s is inside the comparison's closure, so it is no longer a control", name)
		}
		if reaches := keySourceModuleReaches(control, class, selfImport); len(reaches) == 0 {
			t.Errorf("the matcher recognised nothing in %s, which is %s, so its clean reading of the reproduction means nothing",
				name, controls[name])
		}
	}
	// and the finding.
	found := []string{}
	for _, name := range keySourceSortedKeys(scope) {
		for _, reach := range keySourceModuleReaches(functions[name], class, selfImport) {
			found = append(found, reach.String())
		}
	}
	if 0 < len(found) {
		t.Errorf("the reproduction's side of the comparison reaches the module under test, so an octet it compares was produced by the code it is evidence about: %v",
			found)
	}
	t.Logf("%d names across %d module package(s) %v banned; the scope is %d function(s) across %v, %d of them reached only backwards from %s; %s and its %d function closure are the subject",
		names, len(class), keySourceSortedKeys(class), len(scope), spanned, len(backwardOnly), seed,
		producer, len(excluded))
}

// keySourceTypeReachesTheModule answers the first module name a type expression can reach,
// following this package's own TEST structs transitively.
//
// The transitivity is the point: *testSession is a test type and looks harmless, and it holds a
// *GroupSession, which is the record layer itself. A check that stopped at the first hop would
// certify exactly the field this boundary exists to keep out.
func keySourceTypeReachesTheModule(node ast.Expr, file *keySourceTestFile,
	class map[string]*keySourceModulePackage, selfImport string,
	structs map[string]*keySourceTestStruct, seen map[string]bool) string {

	reached := ""
	ast.Inspect(node, func(inner ast.Node) bool {
		if reached != "" {
			return false
		}
		switch typed := inner.(type) {
		case *ast.SelectorExpr:
			if path, isModulePackage := file.moduleImports[keySourceExprRoot(typed.X)]; isModulePackage {
				reached = keySourceExprRoot(typed.X) + "." + typed.Sel.Name + " (" + path + ")"
				return false
			}
		case *ast.Ident:
			own := class[selfImport]
			if own.types[typed.Name] {
				reached = typed.Name + " (" + selfImport + ")"
				return false
			}
			structure, isTestStruct := structs[typed.Name]
			if !isTestStruct || seen[typed.Name] {
				return true
			}
			seen[typed.Name] = true
			// and it resolves through the file the deeper struct was written in, not this one.
			for _, field := range structure.decl.Fields.List {
				if deeper := keySourceTypeReachesTheModule(field.Type, structure.file, class,
					selfImport, structs, seen); deeper != "" {
					reached = typed.Name + " -> " + deeper
					return false
				}
			}
		}
		return true
	})
	return reached
}

// The boundary the excluded function hands across carries no door back into the record layer.
//
// keySourceSealRecords is the one function the gate above excludes from its scope, and the whole
// reason that exclusion is safe is that what it returns is octets and one subject. A *testSession
// field here -- which is what this type carried until the gate was widened -- would put a live
// GroupSession on the reproduction's side of the boundary, and everything the gate refuses to let
// the assertion bodies call would be two selectors away.
func TestTheFixtureCanHandTheReproductionNothingItCouldSealWith(t *testing.T) {
	root, modulePath := keySourceModuleRoot(t)
	_, files, structs := keySourceTestSource(t, modulePath)
	class, selfImport := keySourceModuleClass(t, root, modulePath, files)
	boundary, isDeclared := structs["keySourceSealed"]
	if !isDeclared {
		t.Fatal("keySourceSealed is not a struct of this package's test source, so this check read nothing")
	}
	carrying := []string{}
	fields := 0
	for _, field := range boundary.decl.Fields.List {
		for _, name := range field.Names {
			fields += 1
			if reached := keySourceTypeReachesTheModule(field.Type, boundary.file, class, selfImport,
				structs, map[string]bool{"keySourceSealed": true}); reached != "" {
				carrying = append(carrying, name.Name+" reaches "+reached)
			}
		}
	}
	if fields == 0 {
		t.Fatal("keySourceSealed has no fields, so this check certified an empty boundary")
	}
	slices.Sort(carrying)
	// exactly one field may reach the module, and it is the SUBJECT: the records themselves.
	// Anything else is a value the reproduction's side of the boundary could derive with.
	if len(carrying) != 1 || !strings.HasPrefix(carrying[0], "records reaches ") {
		t.Errorf("the fields of keySourceSealed that reach the module under test are %v, and the only one that may is the records themselves; everything else the fixture hands across must be octets",
			carrying)
	}
	t.Logf("%d fields on the boundary, %d of them reaching the module: %v", fields, len(carrying), carrying)
}
