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
// NOTHING HERE CALLS THIS PACKAGE'S OWN DERIVATIONS, ITS SEALER OR ITS MAC, and that is the
// whole of what makes this evidence rather than a tautology. StorageRoot, GroupHandleKey,
// SenderHandle, DeriveClassKeys, RecordKeyZero, RecordKeyNext, RecordAeadHead, RecordAeadBody,
// sealRecordAead, padBody, message.AADHead, message.AADBody, message.WriteKey and
// message.ComputeWriteAuth are absent from this file by construction. What stands in for them
// is RFC 5869 written out from the RFC, chacha20poly1305.NewX, crypto/hmac and crypto/sha256.
// A reproduction that reached for the package's own sealer would seal under whatever key the
// package chose -- a key it drew from a second source included -- and would pass.
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
	// MASTER section 8's retention table, the durable row. Held against the join below rather
	// than trusted, so a table change fails here instead of agreeing with itself.
	keySourceDurableWire byte = 0x01
	// The 256 octet rung of MASTER's size ladder, which is the rung every record here lands on.
	keySourceRungBytes = 256
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
	// the wire byte is transcribed above and held against the join every preimage in the tree
	// goes through, so a change to MASTER's table is a failure here rather than an agreement
	// between this file and itself.
	wire, err := message.RetentionClassWire(header.RetentionClass, header.EphBucket)
	if err != nil {
		t.Fatalf("join class %d and bucket %d: %v", header.RetentionClass, header.EphBucket, err)
	}
	if wire != keySourceDurableWire {
		t.Fatalf("the durable class joins to wire byte %#02x and MASTER section 8's table is transcribed here as %#02x",
			wire, keySourceDurableWire)
	}
	// the rung is transcribed and held against the ladder for the same reason.
	if rung := message.SizeBucketBytes(header.SizeBucket); rung != keySourceRungBytes {
		t.Fatalf("size bucket %d is %d octets on the ladder and this file transcribes it as %d",
			header.SizeBucket, rung, keySourceRungBytes)
	}
	return keySourceShape{
		groupId:       header.GroupId,
		leaf:          leaf,
		epoch:         header.Epoch,
		streamIndex:   header.StreamIndex,
		isCommit:      header.IsCommit,
		retentionWire: wire,
		sizeBucket:    byte(header.SizeBucket),
		rungBytes:     keySourceRungBytes,
		expireAt:      header.ExpireAt,
		blobId:        header.BlobId,
		attachment:    header.ServerAttachment,
		headPlain:     headPlain,
		bodyPlain:     bodyPlain,
	}
}

// keySourceSealed is one fixture's worth of evidence: a session over a real group, the three
// values the reproduction is allowed, and the records that came out of it.
type keySourceSealed struct {
	fixture   *testSession
	mlsSecret []byte
	records   []*message.Record
	heads     [][]byte
	bodies    [][]byte
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
	sealed := &keySourceSealed{fixture: fixture}
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
		sealed.records = append(sealed.records, record)
		sealed.heads = append(sealed.heads, head)
		sealed.bodies = append(sealed.bodies, body)
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
	shape := keySourceShapeOf(t, self.records[i], self.fixture.handle.OwnLeafIndex(),
		self.heads[i], self.bodies[i])
	return reproduceRecordFromTheExporterOutput(t, mlsSecret, testPqSecret(), testServerNonce(), shape)
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
		// header: a second key source on the open side alone is a record that does not open.
		gotHead, gotBody, err := sealed.fixture.session.OpenRecord(record)
		if err != nil {
			t.Fatalf("record %d: OpenRecord: %v", i, err)
		}
		if string(gotHead) != string(sealed.heads[i]) || string(gotBody) != string(sealed.bodies[i]) {
			t.Errorf("record %d: opened to %d and %d octets, want %d and %d",
				i, len(gotHead), len(gotBody), len(sealed.heads[i]), len(sealed.bodies[i]))
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

// ---------------------------------------------------------------------------
// the gate that holds the reproduction's independence, which was a sentence until it was this
// ---------------------------------------------------------------------------

// The whole of what makes the reproduction above evidence rather than a tautology is that it
// calls NONE of this package's own derivations. That was a paragraph in the file header and
// nothing could fail on it -- which is the exact defect this file exists to close one level up:
// a verification stated in prose is a verification nobody is holding. So it is a gate, and the
// paragraph is a summary of what the gate reads rather than the only place the claim lives.
//
// THE CLASS IS DERIVED. It is every function and method this package's PRODUCTION source
// declares, read off the syntax tree. It is deliberately not a list of the ones that look
// dangerous -- StorageRoot, RecordAeadBody, sealRecordAead -- because a list understates its
// class on the commit that adds the next declaration, and this project has been walked past by
// a hand written list fourteen times. Everything this package ships is banned from the
// reproduction, including whatever it ships next.
//
// THE SCOPE IS A CLOSURE AND NOT A FILE, which is what gives it reach past this file. It is
// every function reachable from reproduceRecordFromTheExporterOutput through this package's TEST
// source, so keyschedule_test.go's RFC 5869 reference -- which the reproduction expands through,
// and whose own header makes the same independence claim, also as a sentence -- is INSIDE this
// gate: a call to keyScheduleExpand added there fails here. That the closure leaves this file is
// ASSERTED rather than trusted, because a closure that stopped at its seed would report the same
// clean run a complete one reports.
//
// THE MATCHING IS BY NAME rather than through go/types, and it OVER reports rather than under. A
// stdlib method that one day shares a name with a production method of this package is a failure
// here, naming the call and both files. That is the safe direction for a ban list and it is the
// direction mls/crypto_forbidden_test.go argues for its own line based matcher. There is no
// collision today, and the gate logs the sizes of what it read, so the day there is one the
// failure says which name it was.

// The positive control, which nothing calls.
//
// It exists so that a matcher which stopped matching fails HERE rather than reporting the
// reproduction clean having recognised nothing -- the same shape mls/crypto_forbidden_test.go's
// testdata/forbidden fixture has, and the reason nothing below rests on a scan having run. The
// gate asserts it is OUTSIDE the closure before it believes what the matcher said about it: a
// control that had drifted into the scope would be a control reporting on itself.
func keySourceControlThatCallsAProductionDerivation(recordKey []byte) ([]byte, []byte) {
	return RecordAeadBody(recordKey)
}

// keySourceProductionCallables is the class: every function and method name this package's
// production source declares, with the file it came from.
func keySourceProductionCallables(t *testing.T) map[string]string {
	t.Helper()
	_, sources := messagegroupProductionSources(t)
	declared := map[string]string{}
	for _, source := range sources {
		for _, declaration := range source.parsed.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction {
				continue
			}
			declared[function.Name.Name] = source.path
		}
	}
	if len(declared) == 0 {
		t.Fatal("no production function was read out of this package, so this gate banned an empty class")
	}
	return declared
}

// keySourceTestFunctions indexes every function this package's TEST source declares, by name,
// with the file each came from.
//
// A method and a function of one name collapse to one entry, and that is the safe direction: it
// pulls MORE functions into the closure below, so the gate reads more source rather than less.
func keySourceTestFunctions(t *testing.T) (map[string]*ast.FuncDecl, map[string]string) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read this package's directory: %v", err)
	}
	fileSet := token.NewFileSet()
	functions := map[string]*ast.FuncDecl{}
	declaredIn := map[string]string{}
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
		for _, declaration := range parsed.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			functions[function.Name.Name] = function
			declaredIn[function.Name.Name] = path
		}
	}
	if len(functions) == 0 {
		t.Fatal("no test function was read out of this package, so this gate scoped itself to nothing")
	}
	return functions, declaredIn
}

// keySourceCalleeNames is every name called inside one body: a bare identifier by its own name,
// a selector by the name it selects.
func keySourceCalleeNames(body ast.Node) []string {
	names := []string{}
	ast.Inspect(body, func(node ast.Node) bool {
		call, isCall := node.(*ast.CallExpr)
		if !isCall {
			return true
		}
		switch callee := call.Fun.(type) {
		case *ast.Ident:
			names = append(names, callee.Name)
		case *ast.SelectorExpr:
			names = append(names, callee.Sel.Name)
		}
		return true
	})
	return names
}

// keySourceClosureFrom is every test function reachable from one seed through this package's
// test source, the seed included.
func keySourceClosureFrom(seed string, functions map[string]*ast.FuncDecl) map[string]bool {
	closure := map[string]bool{seed: true}
	frontier := []string{seed}
	for 0 < len(frontier) {
		name := frontier[len(frontier)-1]
		frontier = frontier[:len(frontier)-1]
		function, isDeclared := functions[name]
		if !isDeclared {
			continue
		}
		for _, called := range keySourceCalleeNames(function) {
			if closure[called] {
				continue
			}
			if _, isTestFunction := functions[called]; !isTestFunction {
				continue
			}
			closure[called] = true
			frontier = append(frontier, called)
		}
	}
	return closure
}

// keySourceCallsIntoProduction is the matcher: every call, from a function in the scope, to a
// name in the class.
//
// The gate and its positive control both go through this one body, so a matcher that stopped
// matching fails at the control rather than clearing the scope.
func keySourceCallsIntoProduction(functions map[string]*ast.FuncDecl, declaredIn map[string]string,
	scope map[string]bool, class map[string]string) []string {

	found := []string{}
	for name := range scope {
		function, isDeclared := functions[name]
		if !isDeclared {
			continue
		}
		for _, called := range keySourceCalleeNames(function) {
			if path, isProduction := class[called]; isProduction {
				found = append(found, fmt.Sprintf("%s (%s) calls %s, which %s declares",
					name, declaredIn[name], called, path))
			}
		}
	}
	slices.Sort(found)
	return slices.Compact(found)
}

// The reproduction reaches nothing this package ships, held off the syntax tree.
//
// A reproduction that called the package's own derivations would rebuild the record under
// whatever key the package chose -- one drawn from a second source included -- and would agree
// with it forever. That is the failure the two tests above exist to be immune to, and this is
// what keeps them immune to it as the package grows.
func TestTheReproductionCallsNothingThisPackageShips(t *testing.T) {
	class := keySourceProductionCallables(t)
	functions, declaredIn := keySourceTestFunctions(t)
	const seed = "reproduceRecordFromTheExporterOutput"
	const control = "keySourceControlThatCallsAProductionDerivation"
	if _, isDeclared := functions[seed]; !isDeclared {
		t.Fatalf("%s was not read out of this package's test source, so this gate walked nothing", seed)
	}
	closure := keySourceClosureFrom(seed, functions)
	// a closure of one is a closure that found no calls at all, which reports the clean run a
	// complete one reports.
	if len(closure) < 2 {
		t.Fatalf("the closure from %s holds %d function(s), so the walk read no calls", seed, len(closure))
	}
	// and it must LEAVE this file, which is the whole of the reach claim above: keyschedule_test.go's
	// RFC 5869 reference is what the reproduction expands through.
	spanned := []string{}
	for name := range closure {
		if !slices.Contains(spanned, declaredIn[name]) {
			spanned = append(spanned, declaredIn[name])
		}
	}
	slices.Sort(spanned)
	if len(spanned) < 2 {
		t.Errorf("the closure from %s stays inside %v, so nothing outside this file is gated by it",
			seed, spanned)
	}
	// the control is outside the scope, so what the matcher says about it is not a statement
	// about the reproduction.
	if closure[control] {
		t.Fatalf("%s is inside the reproduction's closure, so it is no longer a control", control)
	}
	if found := keySourceCallsIntoProduction(functions, declaredIn, closure, class); 0 < len(found) {
		t.Errorf("the reproduction reaches this package's own declarations, so it rebuilds a record under whatever key this package chose: %v", found)
	}
	// the positive control: the same matcher over the control function must report it. Without
	// this, a matcher that recognised nothing would clear the closure in silence.
	controlFound := keySourceCallsIntoProduction(functions, declaredIn, map[string]bool{control: true}, class)
	if len(controlFound) == 0 {
		t.Errorf("the matcher recognised nothing in %s, which calls a production derivation outright, so its clean reading of the reproduction means nothing",
			control)
	}
	t.Logf("%d production callables banned; the closure from %s is %d function(s) across %v; the control reports %v",
		len(class), seed, len(closure), spanned, controlFound)
}
