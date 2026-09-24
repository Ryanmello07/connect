// The device wrap's door, held as properties rather than as a round trip.
//
// WHY A ROUND TRIP IS NOT ENOUGH HERE, which is the sentence the whole file is arranged around. A
// sealer and an opener written by one author agree about the order of wrap_key's nine info
// elements, about which thirty two of the fifty six octets are the key, about whether the AEAD
// takes an aad, and about which octets of the eleven-octet envelope anything covers -- whatever
// those answers happen to be. Every one of those mistakes returns well formed octets and round
// trips perfectly. So the round trip is one case here and the rest are: known answers a second
// implementation can reproduce, a structural reading of what the door reaches, an inline negative
// control that fires for its own reason in the same run, and one MEASUREMENT of how much of the
// envelope is authenticated -- which is the number this door's honesty rests on and which this
// file prints on every run rather than asserting from a table.
package messagegroup

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/urnetwork/connect/mls"
)

// ---------------------------------------------------------------------------
// the two exporter labels and the two kdf labels
// ---------------------------------------------------------------------------

// Property: env_key's exporter label is MASTER's, its width is a class key's, and it does not
// collide with the only other label this package exports under.
//
// The literals are TRANSCRIBED and never referenced, which is the whole point: a case that
// compared the constant against itself passes against any drift at all. Two clients disagreeing
// here seal every device wrap of every epoch under two different outer keys and neither ever opens
// the other's.
func TestTheEnvelopeExporterLabelIsPinnedAndDoesNotCollideWithTheStorageOne(t *testing.T) {
	const fromMaster = "URmessage/v1/envelope"
	if envKeyLabel != fromMaster {
		t.Errorf("this package exports env_key under %q and MASTER section 8.2 fixes %q", envKeyLabel, fromMaster)
	}
	if EnvKeyBytes != 32 {
		t.Errorf("this package exports %d octets of env_key and MASTER section 8.2 gives 32", EnvKeyBytes)
	}
	// and the width is a CLASS KEY's, because env_key[k] stands where the class key stands at the
	// head of the device wrap's ladder. RecordKeyZero refuses anything else, so a disagreement
	// between these two numbers is a panic on the fan-out's first leaf rather than a test.
	if EnvKeyBytes != classKeyBytes {
		t.Errorf("env_key is %d octets and a class key is %d; WrapRecordKeyZero hands one to the other",
			EnvKeyBytes, classKeyBytes)
	}
	// neither label is the whole of the other, in both directions
	for _, pair := range [][2]string{{envKeyLabel, mlsSecretLabel}, {mlsSecretLabel, envKeyLabel}} {
		if strings.HasPrefix(pair[0], pair[1]) {
			t.Errorf("%q is the whole of %q; two exporter labels at one epoch are two secrets and the label is all that separates them",
				pair[0], pair[1])
		}
	}
	// and the separation is LOAD BEARING rather than a fact about two strings: the same handle at
	// the same epoch answers different octets under the two, and a neighbouring label answers
	// different octets again -- so this case could see a drifted constant.
	fixture := newTestSession(t, "envelope-label")
	envKey, err := EnvKey(fixture.handle)
	if err != nil {
		t.Fatalf("EnvKey: %v", err)
	}
	if len(envKey) != EnvKeyBytes {
		t.Fatalf("EnvKey answered %d octets, want %d", len(envKey), EnvKeyBytes)
	}
	mlsSecret, err := fixture.handle.Export(mlsSecretLabel, nil, mlsSecretBytes)
	if err != nil {
		t.Fatalf("Export under the storage label: %v", err)
	}
	if bytes.Equal(envKey, mlsSecret) {
		t.Error("env_key[k] and mls_secret[k] are the same octets, so the device wrap's outer key is the ikm of the root it exists to deliver")
	}
	drifted, err := fixture.handle.Export(fromMaster+"X", nil, EnvKeyBytes)
	if err != nil {
		t.Fatalf("Export under a drifted label: %v", err)
	}
	if bytes.Equal(envKey, drifted) {
		t.Error("two exporter labels one character apart answer the same octets, so this case could not see a drifted constant even if it were pinned")
	}
}

// The one prefix relation this package's label rule cannot avoid on the wrap's side, with the
// argument that makes it safe, held in BOTH directions.
//
// It is the same shape recordkey_test.go's rec/v1/head exemption takes and for the same reason:
// the wire is normative and the rule is connect's own stricter one. What is different is that
// only one of this pair reaches the KDF as an argument -- the salt does, and the info label is the
// first seventeen octets of a nine-element info that WrapInfo assembles -- so recordkey_test.go's
// derived class contains one of them and this case is where the pair is judged at all.
var wrapLabelPrefixDisposition = map[string]string{
	"wrapInfoLabel|wrapSaltLabel": "MASTER section 7 fixes both literals and \"URmessage/v1/wrap\" is the whole of " +
		"\"URmessage/v1/wrap-salt\". It is safe for a reason about HKDF and not about care: the salt is " +
		"Extract's SALT ARGUMENT, which is the HMAC key of HMAC(salt, ikm), and the info label is the " +
		"head of Expand's INFO, which is HMAC(prk, info | 0x01) -- two different functions with the " +
		"value in two different positions, so no truncation of one produces the other's output. And " +
		"the bare label is never a complete info: WrapInfo always continues with LP(group_id). WHAT " +
		"WOULD REMOVE IT: a spec salt that is not an extension of the info label, which is msgrepo's " +
		"to choose and is reported rather than taken here",
}

func TestTheWrapKdfLabelsArePinnedAndTheirPrefixRelationIsDispositioned(t *testing.T) {
	const saltFromMaster = "URmessage/v1/wrap-salt"
	const infoFromMaster = "URmessage/v1/wrap"
	if wrapSaltLabel != saltFromMaster {
		t.Errorf("this package extracts under %q and MASTER section 7 fixes %q", wrapSaltLabel, saltFromMaster)
	}
	if wrapInfoLabel != infoFromMaster {
		t.Errorf("this package's wrap info leads with %q and MASTER section 7 fixes %q", wrapInfoLabel, infoFromMaster)
	}
	// the CLASS: every domain separation label this package reaches a kdf or an exporter with.
	// It is four names and they are named, because the two exporter labels are not constants any
	// derived reading of "reaches keyScheduleExpand" can find -- they go to a group handle.
	labels := map[string]string{
		"mlsSecretLabel": mlsSecretLabel,
		"envKeyLabel":    envKeyLabel,
		"wrapSaltLabel":  wrapSaltLabel,
		"wrapInfoLabel":  wrapInfoLabel,
	}
	names := slices.Sorted(maps2Keys(labels))
	exercised := map[string]bool{}
	for i, left := range names {
		for _, right := range names[i+1:] {
			if labels[left] == labels[right] {
				t.Errorf("%s and %s are the same label %q", left, right, labels[left])
			}
			if !strings.HasPrefix(labels[left], labels[right]) && !strings.HasPrefix(labels[right], labels[left]) {
				continue
			}
			pair := left + "|" + right
			if _, isDispositioned := wrapLabelPrefixDisposition[pair]; isDispositioned {
				exercised[pair] = true
				continue
			}
			t.Errorf("%s (%q) is the whole of %s (%q) and no row disposes of it; a truncation of the longer one is the shorter one",
				left, labels[left], right, labels[right])
		}
	}
	// AND THE OTHER DIRECTION: a disposition that is never reached is a claim nobody measured.
	for pair := range wrapLabelPrefixDisposition {
		if !exercised[pair] {
			t.Errorf("the prefix disposition %q was never reached, so it describes a pair this package no longer has; delete it", pair)
		}
	}
	// and the property the prefix rule stands in for, over the exempted pair: the two labels
	// produce different values in the positions they are actually used in.
	material := bytes.Repeat([]byte{0x6b}, 32)
	asSalt := keyScheduleExtract([]byte(wrapSaltLabel), material)
	asTruncatedSalt := keyScheduleExtract([]byte(wrapInfoLabel), material)
	asInfo := keyScheduleExpand(material, []byte(wrapInfoLabel), 32)
	for _, pair := range [][2][]byte{{asSalt, asTruncatedSalt}, {asSalt, asInfo}, {asTruncatedSalt, asInfo}} {
		if bytes.Equal(pair[0], pair[1]) {
			t.Error("two of the three derivations the exempted prefix pair can reach answer the same thirty two octets")
		}
	}
	// and the bare label is not an info this package can ever expand under, which is the half of
	// the disposition that is a property of the code rather than of HKDF
	info := WrapInfo(WrapEnvelope{FormatVersion: WrapFormatVersion}, nil, nil, XwingAlgId, nil, nil)
	if string(info) == wrapInfoLabel {
		t.Error("WrapInfo over empty inputs IS the bare label, so a truncation of the salt is an info this package expands under")
	}
	if !bytes.HasPrefix(info, []byte(wrapInfoLabel)) {
		t.Errorf("the wrap info does not lead with %q", wrapInfoLabel)
	}
}

// maps2Keys is a local spelling of maps.Keys so this file does not add an import for one call.
func maps2Keys(m map[string]string) func(func(string) bool) {
	return func(yield func(string) bool) {
		for key := range m {
			if !yield(key) {
				return
			}
		}
	}
}

// ---------------------------------------------------------------------------
// ledger ruling 37: env_key[n+1] before the merge is env_key[n+1] after it
// ---------------------------------------------------------------------------

// Property: the committer can compute the envelope key of the epoch its staged commit OPENS,
// before the delivery service has answered, and what it computes is what every member derives
// after applying the same commit.
//
// THIS IS WHAT MAKES RULING 37 BUILDABLE AND IT IS NOT A CONVENIENCE. The fan-out used to be
// published after the merge, so the wrap rows carried record epoch n+1 -- and item 246's epoch
// ceiling serves a reader standing at epoch n only rows with epoch <= n, so read_key[n+1] needed
// pq_secret[n+1] needed the wrap needed read_key[n+1]. The ruling breaks the cycle by submitting
// the wraps at epoch n, staged, still sealed under env_key[n+1]. If this property were false the
// ruling would be unimplementable and the fallback -- exempting wrap rows from the ceiling --
// re-opens a ruled item.
//
// It is built beside enginepending_test.go's TestThePendingReadsAnswerWhatTheMergeInstalls, which
// already holds exactly this for the STORAGE exporter. The storage label's passing case is not
// evidence for this one on its own -- PendingExport takes the label as an argument and could in
// principle answer a cached value for one label and a live one for another -- so the whole chain
// is re-run here under the envelope label, with the same control.
func TestEnvKeyReadBeforeTheMergeIsWhatTheMergeInstalls(t *testing.T) {
	chain := newCommitAddChain(t, "envelope-pending")

	// with nothing staged there is no epoch to answer for, which is what keeps a fan-out from
	// being built out of the epoch the group is already in
	if key, err := PendingEnvKey(chain.founded); !errors.Is(err, mls.ErrNoPendingCommit) {
		t.Fatalf("PendingEnvKey with nothing staged answered %d octets, %v; want ErrNoPendingCommit", len(key), err)
	}

	liveBefore, err := EnvKey(chain.founded)
	if err != nil {
		t.Fatalf("EnvKey before the commit: %v", err)
	}
	third := newTestEngine(t)
	keyPackage, err := third.engine.NewKeyPackage()
	if err != nil {
		t.Fatalf("NewKeyPackage: %v", err)
	}
	commit, _, _, err := chain.founded.CommitAdd([][]byte{keyPackage})
	if err != nil {
		t.Fatalf("CommitAdd: %v", err)
	}
	staged, err := PendingEnvKey(chain.founded)
	if err != nil {
		t.Fatalf("PendingEnvKey: %v", err)
	}
	// THE CONTROL, and it fires for its own reason: the staged value is not the live one, and the
	// live handle has not moved. Without it an implementation that answered the CURRENT epoch's
	// envelope key from both doors would pass every other clause of this case.
	if bytes.Equal(staged, liveBefore) {
		t.Fatal("PendingEnvKey answered the LIVE epoch's envelope key, so the read is off the wrong schedule and every clause below is vacuous")
	}
	if stillLive, err := EnvKey(chain.founded); err != nil || !bytes.Equal(stillLive, liveBefore) {
		t.Fatalf("the live handle moved while a commit was staged: %v", err)
	}

	// the receiver applies the same commit, the committer merges, and all three agree
	processed, err := chain.joined.Process(commit)
	if err != nil {
		t.Fatalf("the joiner's Process: %v", err)
	}
	if err := chain.joined.ApplyCommit(processed); err != nil {
		t.Fatalf("the joiner's ApplyCommit: %v", err)
	}
	if err := chain.founded.MergePendingCommit(); err != nil {
		t.Fatalf("MergePendingCommit: %v", err)
	}
	merged, err := EnvKey(chain.founded)
	if err != nil {
		t.Fatalf("EnvKey after the merge: %v", err)
	}
	if !bytes.Equal(merged, staged) {
		t.Errorf("the committer sealed its fan-out under %x and entered an epoch whose envelope key is %x", staged, merged)
	}
	receiver, err := EnvKey(chain.joined)
	if err != nil {
		t.Fatalf("the receiver's EnvKey: %v", err)
	}
	if !bytes.Equal(receiver, staged) {
		t.Errorf("a receiver that applied the same commit derives %x and the committer sealed under %x; no member could open its own wrap",
			receiver, staged)
	}
	if key, err := PendingEnvKey(chain.founded); !errors.Is(err, mls.ErrNoPendingCommit) {
		t.Errorf("PendingEnvKey after the merge answered %d octets, %v; want ErrNoPendingCommit", len(key), err)
	}
}

// ---------------------------------------------------------------------------
// the door, through a real leaf keys extension
// ---------------------------------------------------------------------------

// wrapTestLeaf is one device's X-Wing half as the group publishes it: the seed the device keeps,
// the extension octets its leaf carries, and the public key parsed back out of those octets.
type wrapTestLeaf struct {
	seed      []byte
	extension []byte
	pub       *XwingPublicKey
	priv      *XwingPrivateKey
}

// newWrapTestLeaf builds one, THROUGH THE WIRE and not around it.
//
// The public key this seals to is the one that comes back out of ParseLeafKeysExtension over the
// encoded urmessage_leaf_keys body -- extension type 0xF002, alg 0x0014 -- rather than the one the
// key generator answered, because the path a fan-out actually takes is MemberAt's leafKeys octets
// and a test that sealed to the generator's own value could not see an encoder that dropped or
// reordered a byte.
//
// The private half is derived from the SEED, which is what s2-26 landed on the other side of this
// door: a device retains the thirty two octet seed behind the public half its leaf publishes, and
// derives the key through this package's XwingKeyGenFromSeed. Before that, device.go encoded only
// .Public() and no device could open a wrap addressed to its own leaf at all.
func newWrapTestLeaf(t *testing.T, fill byte) *wrapTestLeaf {
	t.Helper()
	seed := bytes.Repeat([]byte{fill}, XwingSeedSize)
	priv, err := XwingKeyGenFromSeed(seed)
	if err != nil {
		t.Fatalf("XwingKeyGenFromSeed: %v", err)
	}
	encoded, err := (&mls.LeafKeysExtension{
		AlgId:          mls.AlgIdXwing,
		DeviceXwingPub: priv.Public().Bytes(),
	}).Encode()
	if err != nil {
		t.Fatalf("encode urmessage_leaf_keys: %v", err)
	}
	if encoded.ExtensionType != mls.ExtensionTypeUrmessageLeafKeys {
		t.Fatalf("the extension is tagged %#04x, want urmessage_leaf_keys", uint16(encoded.ExtensionType))
	}
	parsed, err := mls.ParseLeafKeysExtension(encoded.ExtensionData)
	if err != nil {
		t.Fatalf("ParseLeafKeysExtension: %v", err)
	}
	pub, err := ParseXwingPublicKey(parsed.DeviceXwingPub)
	if err != nil {
		t.Fatalf("ParseXwingPublicKey over the published octets: %v", err)
	}
	// a second derivation of the same private half, so the seed really is what the device keeps
	fromSeed, err := XwingKeyGenFromSeed(seed)
	if err != nil {
		t.Fatalf("XwingKeyGenFromSeed a second time: %v", err)
	}
	if !bytes.Equal(fromSeed.Public().Bytes(), parsed.DeviceXwingPub) {
		t.Fatal("the key derived from the retained seed does not answer the public half the leaf published")
	}
	return &wrapTestLeaf{seed: seed, extension: encoded.ExtensionData, pub: pub, priv: fromSeed}
}

func wrapTestGroupId() []byte  { return bytes.Repeat([]byte{0x21}, 32) }
func wrapTestTargetId() []byte { return bytes.Repeat([]byte{0x71}, 16) }

// wrapTestAuthority stands for an opener whose OWN authority -- the epoch it is restoring and the
// record kind it asked for -- happens to be what some envelope says.
//
// IT IS A TEST HELPER AND IT IS NOT AN EXPORTED ONE, which is the whole point of OpenWrapBody's
// expectation argument: a production caller that built its expectation out of the body in front of
// it would have compared a value against itself, and this package gives it no door to do that
// through. Here the cases that use it are the ones whose subject is something else -- the KEM, the
// group binding, which octets the AEAD covers -- and every case whose subject IS the comparison
// writes its expectation out as a literal instead.
func wrapTestAuthority(envelope WrapEnvelope) WrapExpectation {
	return WrapExpectation{
		TargetType:   envelope.TargetType,
		PayloadType:  envelope.PayloadType,
		ContentEpoch: envelope.ContentEpoch,
	}
}

// wrapTestPayload is a payload of the shape MASTER section 7 puts inside aead_ct --
// secret | LP(identity_pub) | sig -- so the sizing this file asserts is the sizing MASTER
// publishes. The signature octets are fill: task 14 step 3 is blocked by open item M1-52 and
// nothing in this tree can sign a wrap.
func wrapTestPayload(secretFill byte) []byte {
	out := []byte{}
	out = append(out, bytes.Repeat([]byte{secretFill}, 32)...)
	out = append(out, 0x00, 0x00, 0x00, 0x20)
	out = append(out, bytes.Repeat([]byte{0x22}, 32)...)
	return append(out, bytes.Repeat([]byte{0x33}, 64)...)
}

// Property: a wrap sealed to a leaf's published X-Wing key opens under that leaf's own private
// half and under no other leaf's -- and the negative control fires in the same run, for its own
// reason.
//
// THE NEGATIVE CONTROL IS INLINE BECAUSE THE KEM MAKES IT NECESSARY. ML-KEM-768 rejects
// implicitly: a ciphertext not produced for this key decapsulates SUCCESSFULLY to a pseudorandom
// secret. So the second leaf's attempt reaches the KDF and the AEAD with thirty two perfectly well
// formed octets, and the only thing that separates it from the first leaf's attempt is the
// Poly1305 tag. A case that asserted only that the right leaf opens would be satisfied by a door
// that opened for everybody.
func TestAWrapOpensForItsTargetLeafAndForNoOther(t *testing.T) {
	target := newWrapTestLeaf(t, 0x01)
	other := newWrapTestLeaf(t, 0x02)
	if bytes.Equal(target.extension, other.extension) {
		t.Fatal("the two fixture leaves publish the same extension, so this case has one leaf in it")
	}
	envelope := WrapEnvelope{FormatVersion: WrapFormatVersion, TargetType: 0x01, PayloadType: 0x01, ContentEpoch: 4}
	payload := wrapTestPayload(0x11)
	body, err := SealWrapBody(rand.Reader, target.pub, envelope, wrapTestGroupId(), wrapTestTargetId(), payload)
	if err != nil {
		t.Fatalf("SealWrapBody: %v", err)
	}

	want := wrapTestAuthority(envelope)
	gotEnvelope, gotPayload, err := OpenWrapBody(target.priv, wrapTestGroupId(), wrapTestTargetId(), want, body)
	if err != nil {
		t.Fatalf("the target leaf could not open its own wrap: %v", err)
	}
	if gotEnvelope != envelope {
		t.Errorf("the envelope came back as %+v, want %+v", gotEnvelope, envelope)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("the payload came back as %d octets and went in as %d", len(gotPayload), len(payload))
	}

	// THE CONTROL: the other leaf's decapsulation SUCCEEDS and the open refuses anyway
	_, ctXwing, _, err := parseHybridCt(body[WrapEnvelopeBytes:])
	if err != nil {
		t.Fatalf("parse hybrid_ct: %v", err)
	}
	foreign, err := XwingDecapsulate(other.priv, ctXwing)
	if err != nil {
		t.Fatalf("the KEM refused a foreign ciphertext, so implicit rejection is not what this build does and this control is measuring something else: %v", err)
	}
	if len(foreign) != XwingSharedSize {
		t.Fatalf("a foreign decapsulation answered %d octets, want %d", len(foreign), XwingSharedSize)
	}
	if _, _, err := OpenWrapBody(other.priv, wrapTestGroupId(), wrapTestTargetId(), want, body); !errors.Is(err, ErrWrapOpen) {
		t.Errorf("a second leaf's private half answered %v; want ErrWrapOpen", err)
	}
	// and the group and the target are bound too, which is what stops one group's wrap opening
	// in another and one member's opening at another's handle
	if _, _, err := OpenWrapBody(target.priv, bytes.Repeat([]byte{0x99}, 32), wrapTestTargetId(), want, body); !errors.Is(err, ErrWrapOpen) {
		t.Errorf("a wrap opened under a different group_id: %v", err)
	}
	if _, _, err := OpenWrapBody(target.priv, wrapTestGroupId(), bytes.Repeat([]byte{0x99}, 16), want, body); !errors.Is(err, ErrWrapOpen) {
		t.Errorf("a wrap opened under a different target_id: %v", err)
	}
}

// Property: a wrap sealed at one epoch does not open as a wrap of another, in all three of the
// places the epoch is bound -- and the FIRST of them is the one a reader would assume and is the
// one that needed a seam built for it.
//
// THE GENUINE CASE AND THE TAMPERED CASE ARE NOT THE SAME CASE, and this case used to hold only
// the second of them. u64(content_epoch) is one of wrap_key's nine info elements, so an opener
// handed a body whose envelope was EDITED on the wire derives a key the sealer never used and the
// AEAD refuses -- that is the tampered half, and it is real. But the key is derived from the
// envelope the body CARRIES, so a genuine wrap of another epoch is self-consistent: its key
// matches its own envelope and the AEAD opens it. Measured on this door before the expectation
// argument existed: a genuine wrap of content epoch 10 opened and returned its payload byte for
// byte. The headline of m1 task 14 property 4 is about that wrap, not about the edited one, and it
// is true here only because OpenWrapBody takes the epoch its opener is honouring and refuses
// anything else -- see WrapExpectation.
//
// The THIRD is the outer seal: env_key[k] is an epoch's own exporter output, so the record ladder
// a wrap of epoch n+1 rides is not the ladder a wrap of epoch n rides, and the two are separated
// before any wrap body is reached. That half is the record layer's and not this door's.
func TestAWrapSealedAtOneEpochDoesNotOpenAtAnother(t *testing.T) {
	target := newWrapTestLeaf(t, 0x03)
	payload := wrapTestPayload(0x44)
	body, err := SealWrapBody(rand.Reader, target.pub,
		WrapEnvelope{FormatVersion: WrapFormatVersion, TargetType: 0x01, PayloadType: 0x01, ContentEpoch: 9},
		wrapTestGroupId(), wrapTestTargetId(), payload)
	if err != nil {
		t.Fatalf("SealWrapBody: %v", err)
	}
	atNine := WrapExpectation{TargetType: 0x01, PayloadType: 0x01, ContentEpoch: 9}
	atEight := WrapExpectation{TargetType: 0x01, PayloadType: 0x01, ContentEpoch: 8}
	// it opens at its own epoch, which is the control that makes the refusals below mean something
	if _, _, err := OpenWrapBody(target.priv, wrapTestGroupId(), wrapTestTargetId(), atNine, body); err != nil {
		t.Fatalf("the wrap does not open at the epoch it was sealed at: %v", err)
	}
	// THE GENUINE HALF: the body is untouched and every octet in it is the sealer's. An opener
	// honouring epoch 8 must not be handed epoch 9's secret, and nothing in the KEM or the AEAD
	// can tell it so -- the refusal here is the opener's own authority and it is asserted BY NAME,
	// because an ErrWrapOpen here would mean the key moved and the key does not move.
	genuineEnvelope, genuinePayload, err := OpenWrapBody(target.priv, wrapTestGroupId(), wrapTestTargetId(), atEight, body)
	if !errors.Is(err, ErrWrapEnvelopeMismatch) {
		t.Errorf("a GENUINE wrap of epoch 9 handed to an opener honouring epoch 8 answered %v; want ErrWrapEnvelopeMismatch", err)
	}
	if errors.Is(err, ErrWrapOpen) {
		t.Error("the genuine epoch 9 wrap was refused as a tag failure, so this case is measuring the AEAD and the AEAD cannot see this")
	}
	if genuinePayload != nil || genuineEnvelope != (WrapEnvelope{}) {
		t.Errorf("a refused wrap carried %d octets of payload and the envelope %+v out to its caller",
			len(genuinePayload), genuineEnvelope)
	}
	// and the refusal does not depend on the rest of the body: it is ahead of the KEM, so a body
	// whose hybrid_ct is destroyed is still refused as the wrong wrap rather than as bad framing.
	truncated := slices.Clone(body[:WrapEnvelopeBytes+4])
	if _, _, err := OpenWrapBody(target.priv, wrapTestGroupId(), wrapTestTargetId(), atEight, truncated); !errors.Is(err, ErrWrapEnvelopeMismatch) {
		t.Errorf("a wrap of the wrong epoch whose hybrid_ct is four octets answered %v; want ErrWrapEnvelopeMismatch, which is what puts the comparison ahead of the KEM", err)
	}
	// THE TAMPERED HALF: the same edit made on the wire moves wrap_key, and this is the one the
	// AEAD convicts. The opener still honours epoch 8, so the comparison passes and the tag is
	// what refuses -- which is how this assertion stays a measurement of the key and not of the
	// comparison above it.
	restated := slices.Clone(body)
	edited, err := ParseWrapEnvelope(restated[:WrapEnvelopeBytes])
	if err != nil {
		t.Fatalf("ParseWrapEnvelope: %v", err)
	}
	edited.ContentEpoch = 8
	copy(restated[:WrapEnvelopeBytes], edited.Encode())
	if _, _, err := OpenWrapBody(target.priv, wrapTestGroupId(), wrapTestTargetId(), atEight, restated); !errors.Is(err, ErrWrapOpen) {
		t.Errorf("a wrap whose content epoch was moved from 9 to 8 answered %v; want ErrWrapOpen", err)
	}

	// the outer half: two epochs' envelope keys start two ladders, so the record that carries a
	// wrap of epoch n+1 is not keyed under epoch n's root at any rung
	chain := newCommitAddChain(t, "envelope-epochs")
	before, err := EnvKey(chain.founded)
	if err != nil {
		t.Fatalf("EnvKey: %v", err)
	}
	third := newTestEngine(t)
	keyPackage, err := third.engine.NewKeyPackage()
	if err != nil {
		t.Fatalf("NewKeyPackage: %v", err)
	}
	if _, _, _, err := chain.founded.CommitAdd([][]byte{keyPackage}); err != nil {
		t.Fatalf("CommitAdd: %v", err)
	}
	if err := chain.founded.MergePendingCommit(); err != nil {
		t.Fatalf("MergePendingCommit: %v", err)
	}
	after, err := EnvKey(chain.founded)
	if err != nil {
		t.Fatalf("EnvKey after the commit: %v", err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("two epochs answered one envelope key, so this half is judging one epoch")
	}
	for _, leaf := range []uint32{0, 1, 0xFFFFFFFF} {
		if bytes.Equal(WrapRecordKeyZero(before, leaf), WrapRecordKeyZero(after, leaf)) {
			t.Errorf("leaf %d starts the same wrap ladder at both epochs", leaf)
		}
	}
}

// ---------------------------------------------------------------------------
// the measurement this door's honesty rests on
// ---------------------------------------------------------------------------

// Property: of the eleven octets a wrap envelope carries in the clear, exactly the ones MASTER
// section 7's info binds are refused when they are edited on the wire -- and the suite REPORTS
// which those are rather than asserting a fixed table.
//
// WHY IT IS A MEASUREMENT AND NOT AN ASSERTION. m1 task 14 property 9 states the shape: which
// octets can convict an attacker is a function of two sentences no document rules -- M1-54, what
// an opener does with an unrecognised wrap_format_version, and M1-55, whether an opener derives
// wrap_key from the envelope's CARRIED values or from its own. A fixed table here would
// presuppose one answer to each and would go red on a conforming implementation the day either is
// ruled the other way. So the set is measured, printed, and asserted only in the two directions
// that are true under every reading: every octet the info binds is REFUSED, and every octet it
// does not is REPORTED.
//
// WHAT IT MEASURES TODAY, and this is open item MG-7. This door derives wrap_key from the carried
// values, which is M1-55's first reading and the one MASTER's own rationale describes, and it
// refuses nothing on the version octet, which is M1-54 left unruled. Under that pair the killing
// set is ten of eleven: the content epoch, the target type and the payload type are in the info
// and the AEAD refuses an edit to any of them, and u8(wrap_format_version) is in NO element of
// info at all. The only construction in the corpus that ever covers it is the body signature,
// whose preimage MASTER extends by LP(wrap_envelope) for exactly this reason -- and that signature
// is task 14 step 3, blocked by M1-52. So today a wrap whose version octet was changed on the wire
// opens to the payload it carried, with no refusal anywhere, and that is printed rather than
// hidden behind a green round trip.
//
// THERE ARE TWO AUTHORITIES IN THIS DOOR AND THE CASE MEASURES THEM SEPARATELY, which is what the
// single column it used to print could not do. The AEAD convicts an octet only when the opener's
// own expectation MOVED WITH THE EDIT -- an opener that believes the edited value, which is the
// hardest case for the key and therefore the one worth measuring -- and the opener's comparison
// convicts an octet only when it did NOT. Running both columns is what separates "the key covers
// this octet" from "somebody happened to look at it", and their union's complement is the octet
// nothing in this door covers at all.
func TestTheEnvelopeOctetsTheWrapKeyBindsAreRefusedAndTheSuiteReportsTheRest(t *testing.T) {
	target := newWrapTestLeaf(t, 0x05)
	envelope := WrapEnvelope{FormatVersion: WrapFormatVersion, TargetType: 0x02, PayloadType: 0x03, ContentEpoch: 11}
	payload := wrapTestPayload(0x55)
	body, err := SealWrapBody(rand.Reader, target.pub, envelope, wrapTestGroupId(), wrapTestTargetId(), payload)
	if err != nil {
		t.Fatalf("SealWrapBody: %v", err)
	}
	sealed := wrapTestAuthority(envelope)
	if _, _, err := OpenWrapBody(target.priv, wrapTestGroupId(), wrapTestTargetId(), sealed, body); err != nil {
		t.Fatalf("the unedited wrap does not open, so every row below is measuring the wrong thing: %v", err)
	}
	refused := []int{}
	accepted := []int{}
	compared := []int{}
	for octet := 0; octet < WrapEnvelopeBytes; octet += 1 {
		edited := slices.Clone(body)
		edited[octet] ^= 0xFF
		moved, err := ParseWrapEnvelope(edited[:WrapEnvelopeBytes])
		if err != nil {
			t.Fatalf("the envelope with octet %d edited does not parse: %v", octet, err)
		}
		// COLUMN ONE, the key: the opener's own authority is moved to agree with the edit, so
		// the comparison passes and the only thing left that can refuse is the tag.
		_, gotPayload, err := OpenWrapBody(target.priv, wrapTestGroupId(), wrapTestTargetId(),
			wrapTestAuthority(moved), edited)
		switch {
		case err == nil:
			accepted = append(accepted, octet)
			// an accepted edit must at least deliver the SAME payload: an octet that
			// changed what came out while being accepted would be a third outcome this
			// reading does not have a name for
			if !bytes.Equal(gotPayload, payload) {
				t.Errorf("editing envelope octet %d was accepted AND changed the payload; that is neither of the two outcomes this reading separates", octet)
			}
		case errors.Is(err, ErrWrapOpen):
			refused = append(refused, octet)
		default:
			t.Errorf("editing envelope octet %d answered %v, which is neither the AEAD's refusal nor an acceptance; an octet that leaves the set for a third reason is a finding",
				octet, err)
		}
		// COLUMN TWO, the opener: the authority stays where the sealer put it, so an octet the
		// expectation covers is refused by name before the KEM is reached.
		switch _, _, err := OpenWrapBody(target.priv, wrapTestGroupId(), wrapTestTargetId(), sealed, edited); {
		case errors.Is(err, ErrWrapEnvelopeMismatch):
			compared = append(compared, octet)
		case err == nil || errors.Is(err, ErrWrapOpen):
		default:
			t.Errorf("editing envelope octet %d answered %v against an unmoved authority, which is neither of this column's outcomes", octet, err)
		}
	}
	uncovered := []int{}
	for octet := 0; octet < WrapEnvelopeBytes; octet += 1 {
		if !slices.Contains(refused, octet) && !slices.Contains(compared, octet) {
			uncovered = append(uncovered, octet)
		}
	}
	t.Logf("wrap envelope, %d octets: the AEAD refuses %v and accepts %v when the opener's authority moves with the edit; the opener's own comparison refuses %v when it does not; %v is covered by neither",
		WrapEnvelopeBytes, refused, accepted, compared, uncovered)
	// THE HALF THAT IS TRUE UNDER EVERY READING: the ten octets MASTER's info binds are refused
	// BY THE KEY, measured against an opener that was fooled into agreeing with the edit. Octet 0
	// is the version and is the one the info does not reach.
	for _, octet := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10} {
		if !slices.Contains(refused, octet) {
			t.Errorf("envelope octet %d is bound into wrap_key by MASTER section 7's info and editing it was not refused; the key is not being derived from the envelope's carried values",
				octet)
		}
	}
	// AND THE REPORTED HALF, held against a written-down disposition rather than against a
	// preference. It is asserted in BOTH directions: a set that grew has a new unauthenticated
	// octet nobody named, and a set that shrank means an authority arrived -- which is what the
	// signature landing looks like, and which must delete this clause rather than pass quietly.
	if !slices.Equal(accepted, []int{0}) {
		t.Errorf("the accepted set is %v and the written-down disposition is exactly {0}, u8(wrap_format_version). A LARGER set is an envelope octet nothing authenticates that no document names; a SMALLER one means this door gained an authority over the version octet -- if that is task 14 step 3's signature landing, this clause and open item MG-7 come out together",
			accepted)
	}
	// AND THE SECOND COLUMN, against its own written-down disposition. The opener's expectation
	// covers exactly the ten octets the info covers -- not by coincidence: WrapExpectation is the
	// three envelope fields MASTER's info binds and deliberately not the fourth, because ruling
	// what an opener does with an unrecognised version is M1-54's and not this package's.
	if !slices.Equal(compared, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
		t.Errorf("the opener's comparison refuses %v and the written-down disposition is exactly the ten info-bound octets. A SMALLER set is a field of WrapExpectation that stopped being compared; a LARGER one means it gained the version octet, which is M1-54 being ruled here rather than in MASTER section 7",
			compared)
	}
	// and the complement of the two columns together, which is the sentence MG-7 carries: one
	// octet of the eleven is covered by NEITHER authority in this door.
	if !slices.Equal(uncovered, []int{0}) {
		t.Errorf("the octets no authority in this door covers are %v and the disposition is exactly {0}", uncovered)
	}
}

// Property: the opener's expectation covers every field of the envelope except the one octet no
// ruling reaches, and that complement is PRINTED and held against a written-down disposition.
//
// THE COMPLEMENT IS THE MEASUREMENT AND THE TYPES ARE WHERE IT IS DECIDABLE. The behavioural case
// above measures which octets each authority refuses, and it can only measure the fields that
// exist: a twelfth envelope octet added tomorrow would be carried, compared against nothing, and
// invisible there because no row would name it. This case reads the two struct types out of the
// source and subtracts one from the other, so a field that arrives on WrapEnvelope without
// arriving on WrapExpectation fails here on the day it lands.
//
// IT FAILS IN BOTH DIRECTIONS, and the two failures mean opposite things. A complement LARGER than
// {FormatVersion} is an envelope field an opener cannot ask about -- a value on the wire that
// nothing in this door compares. A complement SMALLER than it means u8(wrap_format_version) became
// expressible, which is m1 open item M1-54 -- what an opener does with an unrecognised version --
// being decided in this package instead of in MASTER section 7, and it must arrive with the
// ruling, with the measurement above, and with MG-7's second half coming out.
func TestTheOpenerExpectationCoversEveryEnvelopeFieldButTheOneNoRulingReaches(t *testing.T) {
	_, sources := messagegroupProductionSources(t)
	envelope := messagegroupStructFields(sources, "WrapEnvelope")
	expectation := messagegroupStructFields(sources, "WrapExpectation")
	// THE POSITIVE CONTROL, in the same query and deliberately not a count of the expectation:
	// the reading sees the four fields MASTER section 7 fixes and sees SOMETHING on the other
	// side, so an empty complement below cannot be an artefact of having read nothing. How many
	// fields the expectation has is the disposition's to state and not this control's, or a
	// field added to it would fail here with "the reading is broken" instead of with what it is.
	if len(envelope) != 4 || len(expectation) == 0 {
		t.Fatalf("this reading found %d envelope fields (%v) and %d expectation fields (%v); the envelope MASTER section 7 fixes has four and this reading is not on it",
			len(envelope), envelope, len(expectation), expectation)
	}
	uncovered := []string{}
	for name, kind := range envelope {
		wanted, isCovered := expectation[name]
		if !isCovered {
			uncovered = append(uncovered, name)
			continue
		}
		if wanted != kind {
			t.Errorf("WrapEnvelope.%s is %s and WrapExpectation.%s is %s; a comparison across two widths is a comparison that can be true of two different wire values",
				name, kind, name, wanted)
		}
	}
	slices.Sort(uncovered)
	unmatched := []string{}
	for name := range expectation {
		if _, isCarried := envelope[name]; !isCarried {
			unmatched = append(unmatched, name)
		}
	}
	slices.Sort(unmatched)
	t.Logf("the envelope carries %d fields and the opener's expectation covers %d; uncovered %v, and %v of the expectation match no envelope field",
		len(envelope), len(expectation), uncovered, unmatched)
	if !slices.Equal(uncovered, []string{"FormatVersion"}) {
		t.Errorf("the envelope fields no opener can state an expectation over are %v and the written-down disposition is exactly {FormatVersion}. A LARGER set is a wire value this door compares against nothing; a SMALLER one is m1 open item M1-54 being ruled in this package rather than in MASTER section 7, and it comes with the ruling or not at all",
			uncovered)
	}
	if len(unmatched) != 0 {
		t.Errorf("%v are fields of WrapExpectation that no envelope field answers, so they are compared against nothing", unmatched)
	}
}

// messagegroupStructFields answers one named struct type's exported and unexported fields, as
// name -> type, out of this package's production source.
func messagegroupStructFields(sources []messagegroupSource, name string) map[string]string {
	fields := map[string]string{}
	for _, source := range sources {
		for _, declaration := range source.parsed.Decls {
			general, isGeneral := declaration.(*ast.GenDecl)
			if !isGeneral {
				continue
			}
			for _, spec := range general.Specs {
				typed, isTyped := spec.(*ast.TypeSpec)
				if !isTyped || typed.Name.Name != name {
					continue
				}
				structure, isStruct := typed.Type.(*ast.StructType)
				if !isStruct || structure.Fields == nil {
					continue
				}
				for _, field := range structure.Fields.List {
					for _, named := range field.Names {
						fields[named.Name] = typeExprName(field.Type)
					}
				}
			}
		}
	}
	return fields
}

// ---------------------------------------------------------------------------
// two records per target
// ---------------------------------------------------------------------------

// Property: the device wrap is TWO records at one target, and the two are separable by the one
// element of wrap_key's info that separates them.
//
// It was ONE record carrying both secrets until 2026-09-13, which is the shape every existing
// draft and the sizing arithmetic in three documents described, so it is the mistake a reader
// arrives holding. The split is what makes MASTER section 8.1's disappearing-message promise
// cryptographic: pq_secret rides a PERMANENT record and eph_root an EPH(5) one.
func TestTheDeviceWrapIsTwoBodiesAndTheirPayloadTypesMustDiffer(t *testing.T) {
	target := newWrapTestLeaf(t, 0x07)
	pqPayload := wrapTestPayload(0xAA)
	ephPayload := wrapTestPayload(0xBB)
	pqBody, ephBody, err := SealDeviceWraps(rand.Reader, target.pub, 12, 0x01,
		wrapTestGroupId(), wrapTestTargetId(), 0x01, pqPayload, 0x02, ephPayload)
	if err != nil {
		t.Fatalf("SealDeviceWraps: %v", err)
	}
	if bytes.Equal(pqBody, ephBody) {
		t.Fatal("the two device wraps of one leaf are the same octets")
	}
	for _, one := range []struct {
		name string
		body []byte
		want []byte
		kind uint8
	}{
		{name: "the pq_secret wrap", body: pqBody, want: pqPayload, kind: 0x01},
		{name: "the eph_root wrap", body: ephBody, want: ephPayload, kind: 0x02},
	} {
		envelope, payload, err := OpenWrapBody(target.priv, wrapTestGroupId(), wrapTestTargetId(),
			WrapExpectation{TargetType: 0x01, PayloadType: one.kind, ContentEpoch: 12}, one.body)
		if err != nil {
			t.Fatalf("%s did not open: %v", one.name, err)
		}
		if envelope.PayloadType != one.kind {
			t.Errorf("%s carries payload_type %#02x, want %#02x", one.name, envelope.PayloadType, one.kind)
		}
		if envelope.ContentEpoch != 12 {
			t.Errorf("%s carries content epoch %d, want 12", one.name, envelope.ContentEpoch)
		}
		// THE ASSERTION A ROUND TRIP OVER ONE RECORD CANNOT MAKE: the two secrets are not
		// interchanged
		if !bytes.Equal(payload, one.want) {
			t.Errorf("%s delivered the other record's payload", one.name)
		}
	}
	// AND THE HALF A ROUND TRIP OVER EITHER BODY CANNOT SEE: the two are not interchangeable AT
	// THE DOOR. Both bodies are genuine, both are sealed to this leaf at this epoch, and both land
	// at ONE wrap_target_handle -- so before OpenWrapBody took an expectation, each of them opened
	// under the other's arguments and the payload_type was carried out to a caller who was under
	// no obligation to look at it. An opener honouring one kind must be refused the other's.
	for _, cross := range []struct {
		name string
		body []byte
		kind uint8
	}{
		{name: "the pq_secret wrap", body: pqBody, kind: 0x02},
		{name: "the eph_root wrap", body: ephBody, kind: 0x01},
	} {
		_, payload, err := OpenWrapBody(target.priv, wrapTestGroupId(), wrapTestTargetId(),
			WrapExpectation{TargetType: 0x01, PayloadType: cross.kind, ContentEpoch: 12}, cross.body)
		if !errors.Is(err, ErrWrapEnvelopeMismatch) {
			t.Errorf("%s opened for an opener honouring payload_type %#02x and answered %v; want ErrWrapEnvelopeMismatch",
				cross.name, cross.kind, err)
		}
		if payload != nil {
			t.Errorf("%s handed %d octets of payload to an opener honouring the other kind", cross.name, len(payload))
		}
	}
	// and one payload_type used twice is refused by name, because it is the only element of
	// wrap_key's nine that separates two records landing at one wrap_target_handle
	if _, _, err := SealDeviceWraps(rand.Reader, target.pub, 12, 0x01,
		wrapTestGroupId(), wrapTestTargetId(), 0x01, pqPayload, 0x01, ephPayload); !errors.Is(err, ErrWrapPayloadTypeCollision) {
		t.Errorf("two device wraps under one payload_type answered %v; want ErrWrapPayloadTypeCollision", err)
	}
}

// Property: the wrap body's occupancy is the one MASTER section 8.2 publishes.
//
// 1,289 octets of wrap_body, 1,293 of the 4,096 rung once the record layer's LP32 body prefix is
// on it, and a 2,803-octet zero tail. Those numbers are a function of every length prefix in the
// grammar and of nothing else, so an implementation that reproduces them has agreed about all of
// them -- and one that does not has a framing disagreement no round trip against itself can see.
func TestTheWrapBodyOccupiesWhatMasterSectionEightTwoPublishes(t *testing.T) {
	target := newWrapTestLeaf(t, 0x09)
	body, err := SealWrapBody(rand.Reader, target.pub,
		WrapEnvelope{FormatVersion: WrapFormatVersion, TargetType: 0x01, PayloadType: 0x01, ContentEpoch: 1},
		wrapTestGroupId(), wrapTestTargetId(), wrapTestPayload(0x11))
	if err != nil {
		t.Fatalf("SealWrapBody: %v", err)
	}
	const fromMaster = 1289
	if len(body) != fromMaster {
		t.Errorf("a device wrap body is %d octets and MASTER section 8.2 publishes %d", len(body), fromMaster)
	}
	bucket, err := bucketForBody(len(body))
	if err != nil {
		t.Fatalf("bucketForBody: %v", err)
	}
	padded, err := padBody(bucket, body)
	if err != nil {
		t.Fatalf("padBody: %v", err)
	}
	occupancy := len(body) + lpPrefixBytes
	if occupancy != 1293 {
		t.Errorf("a device wrap occupies %d of its rung and MASTER section 8.2 publishes 1293", occupancy)
	}
	if len(padded) != 4096 {
		t.Errorf("the rung is %d octets and MASTER section 8.2's device wrap rung is 4096", len(padded))
	}
	if tail := len(padded) - occupancy; tail != 2803 {
		t.Errorf("the zero tail is %d octets and MASTER section 8.2 publishes 2803", tail)
	}
	// and the tail really is zeros, which is what the refusal task 14 property 10 owes will be
	// written over
	for i := occupancy; i < len(padded); i += 1 {
		if padded[i] != 0 {
			t.Fatalf("the pad octet at %d is %#02x and MASTER section 8.2's fill is zero", i, padded[i])
		}
	}
}

// ---------------------------------------------------------------------------
// what the door reaches, and what it erases
// ---------------------------------------------------------------------------

// Property 6's structural half: the device wrap's outer key is reached from the EXPORTER and from
// nothing that descends from a storage root.
//
// THE BEHAVIOURAL HALF CANNOT CARRY THIS ALONE and that is why the structural one exists. A wrap
// sealed under DeriveClassKeys(storage_root[k]) round trips perfectly between a sealer and an
// opener that both do it, and what it costs is not visible in any octet: storage_root[k] is the
// value the wrap exists to DELIVER, so the record would be openable only by a member that already
// had what was inside it, and a member removed by the commit that opened epoch k would keep its
// contribution to the key. That is the circularity MASTER section 8.2's ruling exists to remove,
// and an edge from this file into the key schedule's roots is exactly how it comes back.
func TestTheWrapDoorReachesTheExporterAndNoStorageRoot(t *testing.T) {
	_, sources := messagegroupProductionSources(t)
	var wrapSource *messagegroupSource
	for i := range sources {
		if strings.HasSuffix(sources[i].path, "wrap.go") {
			wrapSource = &sources[i]
		}
	}
	if wrapSource == nil {
		t.Fatal("this package has no wrap.go, so this gate read nothing")
	}
	reached := map[string]bool{}
	declared := []string{}
	for _, declaration := range wrapSource.parsed.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if !isFunction || function.Body == nil {
			continue
		}
		declared = append(declared, function.Name.Name)
		for _, callee := range keyScheduleCalleeNames(function.Body) {
			reached[callee] = true
		}
	}
	if len(declared) == 0 {
		t.Fatal("wrap.go declares no function with a body, so this gate judged an empty class")
	}
	// THE POSITIVE CONTROLS, in the same reading and for its own reason: this door certainly
	// reaches the ladder head and the exporter, so a reading that had stopped resolving callee
	// names would report the clean run a complete one reports.
	for _, wanted := range []string{"RecordKeyZero", "Export", "PendingExport", "XwingEncapsulate", "XwingDecapsulate"} {
		if !reached[wanted] {
			t.Fatalf("wrap.go's reading does not reach %s, so it is not resolving what it claims to: %v",
				wanted, slices.Sorted(maps2Keys(reachedNames(reached))))
		}
	}
	for _, forbidden := range []string{"StorageRoot", "DeriveClassKeys", "classKeyOnLoop", "classKeyOf"} {
		if reached[forbidden] {
			t.Errorf("wrap.go reaches %s; MASTER section 8.2's ruling puts env_key[k] at the head of this ladder precisely so that the device wrap is not sealed under a key descending from the root it delivers",
				forbidden)
		}
	}
}

func reachedNames(reached map[string]bool) map[string]string {
	out := map[string]string{}
	for name := range reached {
		out[name] = ""
	}
	return out
}

// Property: every value the door derives that is key material is handed to the eraser in the body
// that derived it.
//
// IT IS A SOURCE READING BECAUSE NO BEHAVIOURAL ONE EXISTS. The shared secret, the extraction's
// prk and the wrap key and nonce are locals that die with the call; nothing outside the function
// holds a header over them, so no test can look at them afterwards and no round trip changes if
// the erase is deleted. What the reading holds is the obligation: a local assigned out of the KEM
// or out of the KDF is ERASED in the body that derived it, or MOVED OUT of it.
//
// THE "MOVED OUT" HALF IS NOT A LOOPHOLE AND IT IS THE SAME ONE connect/mls's DROP SITE READING
// CARRIES. A body that hands its derivation to its caller has not dropped it; the obligation
// travels with the value, and the caller is then a member of this class in its own right.
// wrapKeyMaterial is exactly that shape -- it expands fifty six octets and returns the two halves
// of them -- and a gate that demanded an erase there would be demanding that a derivation blank
// the key it just answered, which is recordAeadMaterial's shape one file over.
//
// The CLASS is derived from the producers and not from a list of variable names, so a fifth
// derivation added to this file is judged without anybody extending this case.
func TestEveryKeyTheWrapDoorDerivesIsErasedInTheBodyThatDerivedIt(t *testing.T) {
	const controlName = "the wrap erase control"
	// the control first, over one function of each shape this reading must separate: erased,
	// dropped, half erased, and moved out to the caller. A reading that cannot separate the four
	// is a reading whose verdict on the real source means nothing.
	control := []struct {
		name     string
		source   string
		wantHeld []string
	}{
		{name: "erased", source: "func probe() {\nx, y, _ := XwingEncapsulate(r, p)\nzeroize(y)\n_ = x\n}", wantHeld: nil},
		{name: "dropped", source: "func probe() {\nx, y, _ := XwingEncapsulate(r, p)\n_ = x\n_ = y\n}", wantHeld: []string{"y"}},
		{name: "half erased", source: "func probe() {\nk, n := wrapKeyMaterial(s, i)\nzeroize(k)\n_ = n\n}", wantHeld: []string{"n"}},
		{name: "moved out", source: "func probe() []byte {\nm := keyScheduleExpand(p, i, 56)\nreturn m[:32]\n}", wantHeld: nil},
		{name: "moved out whole", source: "func probe() ([]byte, []byte) {\nk, n := wrapKeyMaterial(s, i)\nreturn k, n\n}", wantHeld: nil},
		// THE ROW THE FIRST VERSION OF THIS READING GOT WRONG, kept as a control rather than
		// only fixed: a body that hands its derivation to a CALLEE inside its own return
		// statement has not moved it out, because the callee does not own it and the local is
		// still there to erase when the call comes back.
		{name: "handed to a callee", source: "func probe() ([]byte, error) {\nc, y, _ := XwingEncapsulate(r, p)\nreturn helper(c, y), nil\n}", wantHeld: []string{"y"}},
	}
	for _, one := range control {
		held := wrapUnerasedDerivations(t, controlName, "package control\n"+one.source+"\n")
		if !slices.Equal(held, one.wantHeld) {
			t.Fatalf("the control %q reads as holding %v, want %v; the matcher is not separating an erased derivation from a dropped one, nor either from one moved out to the caller",
				one.name, held, one.wantHeld)
		}
	}
	raw, err := os.ReadFile("wrap.go")
	if err != nil {
		t.Fatalf("read wrap.go: %v", err)
	}
	if held := wrapUnerasedDerivations(t, "wrap.go", string(raw)); len(held) != 0 {
		t.Errorf("wrap.go derives %v out of the KEM or the wrap KDF and does not hand them to zeroize in the same body; the shared secret, the prk and the wrap key are the whole of what a wrap's confidentiality rests on",
			held)
	}
}

// wrapMovedOutName answers the identifier a returned expression hands to the caller, or "" when
// the expression is not one.
//
// A bare name, a slice of one and an index of one are all the same value travelling out. A CALL
// is not: its arguments belong to the body that made the call, and a body that passes its shared
// secret to a helper has not stopped owning it.
func wrapMovedOutName(expr ast.Expr) string {
	switch typed := expr.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.ParenExpr:
		return wrapMovedOutName(typed.X)
	case *ast.SliceExpr:
		return wrapMovedOutName(typed.X)
	case *ast.IndexExpr:
		return wrapMovedOutName(typed.X)
	case *ast.StarExpr:
		return wrapMovedOutName(typed.X)
	case *ast.UnaryExpr:
		return wrapMovedOutName(typed.X)
	}
	return ""
}

// mustParseMessagegroupSource parses one Go source text, for the readings that judge a control
// package and the real file through the same matcher.
func mustParseMessagegroupSource(t *testing.T, name string, source string) *ast.File {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), name, source, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return parsed
}

// wrapUnerasedDerivations answers every identifier assigned out of a key-material producer in some
// function body of the source, and neither handed to zeroize nor returned in that same body.
//
// The producers are the KEM's two doors and the wrap KDF. XwingEncapsulate's FIRST result is the
// ciphertext and is deliberately not in the class -- it is destined for the wire -- so the reading
// takes the shared secret's position rather than every result.
func wrapUnerasedDerivations(t *testing.T, name string, source string) []string {
	t.Helper()
	parsed := mustParseMessagegroupSource(t, name, source)
	held := []string{}
	for _, declaration := range parsed.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if !isFunction || function.Body == nil {
			continue
		}
		erased := map[string]bool{}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, isCall := node.(*ast.CallExpr)
			if !isCall {
				return true
			}
			callee, isName := call.Fun.(*ast.Ident)
			if !isName || callee.Name != "zeroize" || len(call.Args) != 1 {
				return true
			}
			if argument, isArgument := call.Args[0].(*ast.Ident); isArgument {
				erased[argument.Name] = true
			}
			return true
		})
		// and every name this body MOVES OUT to its caller: a slice or an index of a derivation
		// counts as moved as well as the whole of it.
		//
		// IT DOES NOT DESCEND INTO A CALL'S ARGUMENTS, and that clause is here because the first
		// version of this reading did. `return sealWrapBodyWith(..., shared, ...)` is not a body
		// moving its shared secret out to its caller -- it is a body HANDING it to a callee that
		// does not own it, and the local is still this body's to erase when the callee returns.
		// Measured: with the descent in, deleting SealWrapBody's `defer zeroize(shared)` left this
		// gate and every other case in the package green, which is the whole mutation this case
		// exists to kill.
		ast.Inspect(function.Body, func(node ast.Node) bool {
			returned, isReturn := node.(*ast.ReturnStmt)
			if !isReturn {
				return true
			}
			for _, result := range returned.Results {
				if named := wrapMovedOutName(result); named != "" {
					erased[named] = true
				}
			}
			return true
		})
		ast.Inspect(function.Body, func(node ast.Node) bool {
			assign, isAssign := node.(*ast.AssignStmt)
			if !isAssign || len(assign.Rhs) != 1 {
				return true
			}
			call, isCall := assign.Rhs[0].(*ast.CallExpr)
			if !isCall {
				return true
			}
			callee, isName := call.Fun.(*ast.Ident)
			if !isName {
				return true
			}
			secret := []int{}
			switch callee.Name {
			case "XwingEncapsulate":
				secret = []int{1}
			case "XwingDecapsulate":
				secret = []int{0}
			case "wrapKeyMaterial":
				secret = []int{0, 1}
			case "keyScheduleExtract", "keyScheduleExpand":
				secret = []int{0}
			default:
				return true
			}
			for _, position := range secret {
				if position >= len(assign.Lhs) {
					continue
				}
				target, isName := assign.Lhs[position].(*ast.Ident)
				if !isName || target.Name == "_" || erased[target.Name] {
					continue
				}
				held = append(held, target.Name)
			}
			return true
		})
	}
	slices.Sort(held)
	return slices.Compact(held)
}

// Property: the door holds no X-Wing private key in a field, which is the written excuse
// connect/mls's erase class carries for XwingPrivateKey.
//
// THE EXCUSE IS A CLAIM ABOUT THIS PACKAGE'S SOURCE AND THIS IS WHERE IT IS TRUE OR NOT.
// mls/staged_erase_test.go excuses the type with "an ANSWER. XwingGenerateKey and
// XwingKeyGenFromSeed build one per call and no production declaration holds one in a field; the
// seed inside it is the caller's to keep or to drop" -- and this door is the first production
// consumer of that type in the tree, so it is the first thing that could have made the sentence
// false. It takes the private half as an ARGUMENT for exactly that reason, and this case is what
// keeps it that way: a field here and the excuse has to change with the code, in the same commit.
func TestNoDeclarationOfThisPackageHoldsAnXwingPrivateKeyInAField(t *testing.T) {
	_, sources := messagegroupProductionSources(t)
	holders := []string{}
	structs := 0
	for _, source := range sources {
		for _, declaration := range source.parsed.Decls {
			general, isGeneral := declaration.(*ast.GenDecl)
			if !isGeneral {
				continue
			}
			for _, spec := range general.Specs {
				typed, isTyped := spec.(*ast.TypeSpec)
				if !isTyped {
					continue
				}
				structure, isStruct := typed.Type.(*ast.StructType)
				if !isStruct || structure.Fields == nil {
					continue
				}
				structs += 1
				for _, field := range structure.Fields.List {
					if !strings.Contains(typeExprName(field.Type), "XwingPrivateKey") {
						continue
					}
					for _, named := range field.Names {
						holders = append(holders, typed.Name.Name+"."+named.Name)
					}
				}
			}
		}
	}
	if structs == 0 {
		t.Fatal("this reading found no struct type in this package's production source, so it judged nothing")
	}
	// the positive control, in the same query: the reading DOES see the type where it is declared
	if !slices.Contains(theXwingPrivateKeyFieldNames(sources), "seed") {
		t.Fatal("this reading cannot see XwingPrivateKey's own fields, so its zero above is a zero over nothing")
	}
	if len(holders) != 0 {
		t.Errorf("%v hold an XwingPrivateKey in a field, and connect/mls's erase class excuses that type on the written ground that no production declaration does. The excuse is now false and must change with the code, in this commit: either the type declares a Zeroize that erases its seed and its two private halves, or it carries a row of its own",
			holders)
	}
	t.Logf("%d struct types read; no field of any of them holds an XwingPrivateKey", structs)
}

func theXwingPrivateKeyFieldNames(sources []messagegroupSource) []string {
	names := []string{}
	for _, source := range sources {
		for _, declaration := range source.parsed.Decls {
			general, isGeneral := declaration.(*ast.GenDecl)
			if !isGeneral {
				continue
			}
			for _, spec := range general.Specs {
				typed, isTyped := spec.(*ast.TypeSpec)
				if !isTyped || typed.Name.Name != "XwingPrivateKey" {
					continue
				}
				structure, isStruct := typed.Type.(*ast.StructType)
				if !isStruct || structure.Fields == nil {
					continue
				}
				for _, field := range structure.Fields.List {
					for _, named := range field.Names {
						names = append(names, named.Name)
					}
				}
			}
		}
	}
	return names
}

func typeExprName(expr ast.Expr) string {
	switch typed := expr.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.StarExpr:
		return typeExprName(typed.X)
	case *ast.SelectorExpr:
		return typed.Sel.Name
	case *ast.ArrayType:
		return typeExprName(typed.Elt)
	case *ast.MapType:
		return typeExprName(typed.Key) + "|" + typeExprName(typed.Value)
	}
	return ""
}

// ---------------------------------------------------------------------------
// the known answers
// ---------------------------------------------------------------------------

// Property: this package reproduces testdata/envelope-wrap-kat.txt, and so does RFC 5869 written
// out by hand over an info this case assembles from MASTER section 7's field list.
//
// TWO DERIVATIONS THAT SHARE NO CODE, which is what makes the rows worth more than a snapshot of
// the implementation. WrapInfo is one encoder; the reader below is a second one, written from
// MASTER's block, and the KDF halves come from keyschedule_test.go's transcription of RFC 5869
// rather than from mls's provider. A file regenerated to agree with a broken implementation still
// has to agree with both.
func TestTheWrapDoorMatchesItsKnownAnswers(t *testing.T) {
	rows := readWrapKat(t)
	envKey := wrapKatHex(t, rows, "INPUT_ENV_KEY")
	shared := wrapKatHex(t, rows, "INPUT_SS")
	groupId := wrapKatHex(t, rows, "INPUT_GROUP_ID")
	targetId := wrapKatHex(t, rows, "INPUT_TARGET_ID")
	ctXwing := wrapKatFill(t, rows, "INPUT_CT_XWING_FILL", "INPUT_CT_XWING_LEN", "INPUT_CT_XWING_SHA256")
	targetPub := wrapKatFill(t, rows, "INPUT_TARGET_PUB_FILL", "INPUT_TARGET_PUB_LEN", "INPUT_TARGET_PUB_SHA256")
	envelope := WrapEnvelope{
		FormatVersion: byte(wrapKatHex(t, rows, "INPUT_ENVELOPE_VERSION")[0]),
		TargetType:    byte(wrapKatHex(t, rows, "INPUT_ENVELOPE_TARGET_TYPE")[0]),
		PayloadType:   byte(wrapKatHex(t, rows, "INPUT_ENVELOPE_PAYLOAD_TYPE")[0]),
		ContentEpoch:  uint64(wrapKatInt(t, rows, "INPUT_ENVELOPE_CONTENT_EPOCH")),
	}
	if got := hex.EncodeToString(envelope.Encode()); got != rows["INPUT_ENVELOPE_ENCODED"] {
		t.Errorf("the envelope encodes to %s and the vector gives %s", got, rows["INPUT_ENVELOPE_ENCODED"])
	}
	if len(envelope.Encode()) != WrapEnvelopeBytes || WrapEnvelopeBytes != 11 {
		t.Errorf("the envelope is %d octets and MASTER section 7 fixes eleven", len(envelope.Encode()))
	}

	// section 2: the ladder head off a known envelope key
	ladders := 0
	for _, row := range wrapKatRows(t, rows, "LADDER") {
		fields := strings.Fields(row)
		if len(fields) != 4 {
			t.Fatalf("a LADDER row has %d fields, want 4: %q", len(fields), row)
		}
		leaf, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil {
			t.Fatalf("a LADDER row's leaf index: %v", err)
		}
		rung := WrapRecordKeyZero(envKey, uint32(leaf))
		key, nonce := RecordAeadBody(rung)
		if hex.EncodeToString(rung) != fields[1] {
			t.Errorf("record_key[0] at leaf %d is %x and the vector gives %s", leaf, rung, fields[1])
		}
		if hex.EncodeToString(key) != fields[2] || hex.EncodeToString(nonce) != fields[3] {
			t.Errorf("the body aead at leaf %d is %x/%x and the vector gives %s/%s", leaf, key, nonce, fields[2], fields[3])
		}
		// the second derivation: RFC 5869 by hand, over the ladder's own labels
		reference := keyScheduleReferenceExpand(envKey,
			append([]byte(recordKeyZeroInfo), leafIndexLP(uint32(leaf))...), recordKeyBytes)
		if !bytes.Equal(reference, rung) {
			t.Errorf("RFC 5869 written out gives %x for leaf %d and this package gives %x", reference, leaf, rung)
		}
		ladders += 1
	}
	if ladders < 3 {
		t.Fatalf("the vector carries %d LADDER rows; a reading that found fewer than three is not reading the file", ladders)
	}

	// section 3: the wrap kdf and the sealed body
	info := WrapInfo(envelope, groupId, targetId, XwingAlgId, targetPub, ctXwing)
	if got := wrapKatInt(t, rows, "INFO_LEN"); len(info) != got {
		t.Errorf("the info is %d octets and the vector gives %d", len(info), got)
	}
	if got := sha256.Sum256(info); hex.EncodeToString(got[:]) != rows["INFO_SHA256"] {
		t.Errorf("H(info) is %x and the vector gives %s", got, rows["INFO_SHA256"])
	}
	// THE SECOND ENCODER, assembled here from MASTER section 7's field list rather than by
	// calling WrapInfo, so a transposition inside WrapInfo is visible
	if !bytes.Equal(info, wrapKatReferenceInfo(rows, envelope, groupId, targetId, targetPub, ctXwing)) {
		t.Error("WrapInfo and MASTER section 7's field list written out here produce different octets")
	}
	key, nonce := wrapKeyMaterial(shared, info)
	if hex.EncodeToString(key) != rows["WRAP_KEY"] {
		t.Errorf("wrap_key is %x and the vector gives %s", key, rows["WRAP_KEY"])
	}
	if hex.EncodeToString(nonce) != rows["WRAP_NONCE"] {
		t.Errorf("wrap_nonce is %x and the vector gives %s", nonce, rows["WRAP_NONCE"])
	}
	// and the second derivation of both halves, from RFC 5869 by hand
	referencePrk := keyScheduleReferenceExtract([]byte(rows["PRK_SALT"]), shared)
	referenceMaterial := keyScheduleReferenceExpand(referencePrk, info, wrapAeadMaterialBytes)
	if !bytes.Equal(referenceMaterial[:recordAeadKeyBytes], key) ||
		!bytes.Equal(referenceMaterial[recordAeadKeyBytes:], nonce) {
		t.Error("RFC 5869 written out over MASTER's salt does not reproduce this package's wrap_key | wrap_nonce")
	}
	if rows["PRK_SALT"] != wrapSaltLabel || rows["INFO_LABEL"] != wrapInfoLabel {
		t.Errorf("the vector's labels are %q and %q and this package's are %q and %q",
			rows["PRK_SALT"], rows["INFO_LABEL"], wrapSaltLabel, wrapInfoLabel)
	}
	if rows["ALG_ID"] != fmt.Sprintf("%04x", XwingAlgId) {
		t.Errorf("the vector's alg_id is %s and this package's is %04x", rows["ALG_ID"], XwingAlgId)
	}

	payload := wrapTestPayload(0x11)
	if got := wrapKatInt(t, rows, "INPUT_PAYLOAD_LEN"); len(payload) != got {
		t.Fatalf("the fixture payload is %d octets and the vector's is %d", len(payload), got)
	}
	if got := sha256.Sum256(payload); hex.EncodeToString(got[:]) != rows["INPUT_PAYLOAD_SHA256"] {
		t.Fatalf("the fixture payload is not the vector's")
	}
	body, err := sealWrapBodyWith(envelope, groupId, targetId, targetPub, ctXwing, shared, payload)
	if err != nil {
		t.Fatalf("sealWrapBodyWith over the vector's inputs: %v", err)
	}
	if len(body) != wrapKatInt(t, rows, "WRAP_BODY_LEN") {
		t.Errorf("the wrap body is %d octets and the vector gives %d", len(body), wrapKatInt(t, rows, "WRAP_BODY_LEN"))
	}
	if got := sha256.Sum256(body); hex.EncodeToString(got[:]) != rows["WRAP_BODY_SHA256"] {
		t.Errorf("H(wrap_body) is %x and the vector gives %s", got, rows["WRAP_BODY_SHA256"])
	}
	if got := len(body) + lpPrefixBytes; got != wrapKatInt(t, rows, "WRAP_BODY_OCCUPANCY") {
		t.Errorf("the occupancy is %d and the vector gives %d", got, wrapKatInt(t, rows, "WRAP_BODY_OCCUPANCY"))
	}
	if got := wrapKatInt(t, rows, "WRAP_BODY_RUNG") - wrapKatInt(t, rows, "WRAP_BODY_OCCUPANCY"); got != wrapKatInt(t, rows, "WRAP_BODY_ZERO_TAIL") {
		t.Errorf("the vector's own rung arithmetic gives a %d octet tail and its tail row says %d", got, wrapKatInt(t, rows, "WRAP_BODY_ZERO_TAIL"))
	}
	_, vectorCt, vectorAead, err := parseHybridCt(body[WrapEnvelopeBytes:])
	if err != nil {
		t.Fatalf("the vector's own body does not parse: %v", err)
	}
	if !bytes.Equal(vectorCt, ctXwing) {
		t.Error("the body's ct_xwing is not the vector's")
	}
	if len(vectorAead) != wrapKatInt(t, rows, "AEAD_CT_LEN") {
		t.Errorf("aead_ct is %d octets and the vector gives %d", len(vectorAead), wrapKatInt(t, rows, "AEAD_CT_LEN"))
	}
	if got := sha256.Sum256(vectorAead); hex.EncodeToString(got[:]) != rows["AEAD_CT_SHA256"] {
		t.Errorf("H(aead_ct) is %x and the vector gives %s", got, rows["AEAD_CT_SHA256"])
	}

	// section 4: the failing direction, one row per envelope octet
	octets := 0
	base := sha256.Sum256(info)
	for _, row := range wrapKatRows(t, rows, "ENVELOPE_OCTET") {
		fields := strings.Fields(row)
		if len(fields) != 3 {
			t.Fatalf("an ENVELOPE_OCTET row has %d fields, want 3: %q", len(fields), row)
		}
		index, err := strconv.Atoi(fields[0])
		if err != nil {
			t.Fatalf("an ENVELOPE_OCTET row's index: %v", err)
		}
		edited := envelope.Encode()
		edited[index] ^= 0xFF
		flipped, err := ParseWrapEnvelope(edited)
		if err != nil {
			t.Fatalf("parse the flipped envelope at %d: %v", index, err)
		}
		digest := sha256.Sum256(WrapInfo(flipped, groupId, targetId, XwingAlgId, targetPub, ctXwing))
		if hex.EncodeToString(digest[:]) != fields[2] {
			t.Errorf("flipping envelope octet %d gives H(info) %x and the vector gives %s", index, digest, fields[2])
		}
		want := "bound"
		if digest == base {
			want = "unbound"
		}
		if fields[1] != want {
			t.Errorf("envelope octet %d reads as %s and the vector calls it %s", index, want, fields[1])
		}
		octets += 1
	}
	if octets != WrapEnvelopeBytes {
		t.Fatalf("the vector carries %d ENVELOPE_OCTET rows and the envelope is %d octets", octets, WrapEnvelopeBytes)
	}

	// section 5: the OTHER failing direction, where nothing was edited at all. Each row is the
	// section 1 envelope with one field moved, and what it fixes is that such a wrap has a
	// perfectly good key of its own -- a different digest, not an absent one -- so no authority
	// inside the seal can refuse it and the opener's comparison is what must.
	genuine := 0
	for _, row := range wrapKatRows(t, rows, "GENUINE_OTHER") {
		fields := strings.Fields(row)
		if len(fields) != 3 {
			t.Fatalf("a GENUINE_OTHER row has %d fields, want 3: %q", len(fields), row)
		}
		encoded, err := hex.DecodeString(fields[1])
		if err != nil {
			t.Fatalf("a GENUINE_OTHER row's envelope: %v", err)
		}
		other, err := ParseWrapEnvelope(encoded)
		if err != nil {
			t.Fatalf("parse the %s row's envelope: %v", fields[0], err)
		}
		moved := []string{}
		if other.ContentEpoch != envelope.ContentEpoch {
			moved = append(moved, "content_epoch")
		}
		if other.TargetType != envelope.TargetType {
			moved = append(moved, "target_type")
		}
		if other.PayloadType != envelope.PayloadType {
			moved = append(moved, "payload_type")
		}
		if other.FormatVersion != envelope.FormatVersion {
			moved = append(moved, "wrap_format_version")
		}
		if !slices.Equal(moved, []string{fields[0]}) {
			t.Errorf("the %s row moves %v against section 1's envelope, and a row that moves anything else is not measuring the field it names", fields[0], moved)
		}
		digest := sha256.Sum256(WrapInfo(other, groupId, targetId, XwingAlgId, targetPub, ctXwing))
		if hex.EncodeToString(digest[:]) != fields[2] {
			t.Errorf("the %s row's H(info) is %x and the vector gives %s", fields[0], digest, fields[2])
		}
		// THE CHECK THE ROW EXISTS FOR: a different key, not a broken one. An implementation
		// whose digest here equalled INFO_SHA256 would have a field that reaches no key at all,
		// which is section 4's "unbound" verdict arriving where no octet was edited.
		if digest == base {
			t.Errorf("moving %s leaves H(info) at INFO_SHA256, so that field is in no element of wrap_key's info and belongs in section 4 as unbound", fields[0])
		}
		// and this package refuses such a wrap at the door, by the opener's own authority: the
		// expectation stays where section 1 put it while the body carries the moved envelope
		if _, disagrees := wrapTestAuthority(envelope).disagreement(other); !disagrees {
			t.Errorf("an opener honouring section 1's envelope finds no disagreement with the %s row, so nothing in this door separates a genuine wrap of another %s",
				fields[0], fields[0])
		}
		genuine += 1
	}
	if genuine != 2 {
		t.Fatalf("the vector carries %d GENUINE_OTHER rows; the two MASTER section 8.2 puts at one wrap_target_handle are the epoch and the payload kind", genuine)
	}
}

// wrapKatReferenceInfo is MASTER section 7's nine elements, written out here from the block and
// not by calling WrapInfo. LP is a fixed thirty two bit big endian length, which is the record
// layer's prefix and the one the spec's notation means.
func wrapKatReferenceInfo(rows map[string]string, envelope WrapEnvelope, groupId []byte,
	targetId []byte, targetPub []byte, ctXwing []byte) []byte {

	lp := func(out []byte, value []byte) []byte {
		length := uint32(len(value))
		out = append(out, byte(length>>24), byte(length>>16), byte(length>>8), byte(length))
		return append(out, value...)
	}
	u64 := func(out []byte, value uint64) []byte {
		for shift := 56; 0 <= shift; shift -= 8 {
			out = append(out, byte(value>>uint(shift)))
		}
		return out
	}
	out := []byte(rows["INFO_LABEL"])
	out = lp(out, groupId)
	out = u64(out, envelope.ContentEpoch)
	out = append(out, envelope.TargetType)
	out = lp(out, targetId)
	out = append(out, envelope.PayloadType)
	algId, _ := hex.DecodeString(rows["ALG_ID"])
	out = append(out, algId...)
	out = lp(out, targetPub)
	return lp(out, ctXwing)
}

// The suffix under which a repeated row name is collected, so one map can carry both the single
// valued rows and the tables.
const wrapKatMultiSuffix = "[]"

// The separator a repeated table's rows are joined under, which cannot occur in a row: this file
// is ascii text and a NUL in it would already have failed the read.
const wrapKatRowSeparator = "\x00"

func readWrapKat(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("testdata/envelope-wrap-kat.txt")
	if err != nil {
		t.Fatalf("read the wrap known answers: %v", err)
	}
	// CRLF is folded before anything is read, for the reason the eph window table's gate folds
	// it: core.autocrlf is true at system scope on the boxes that build this repo, and a digest
	// or a field split that cried wolf on a clean checkout would be deleted rather than fixed.
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	rows := map[string]string{}
	multi := map[string][]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, rest, found := strings.Cut(line, " ")
		if !found {
			t.Fatalf("a row of the wrap known answers has no value: %q", line)
		}
		rest = strings.TrimSpace(rest)
		switch name {
		case "LADDER", "ENVELOPE_OCTET", "GENUINE_OTHER":
			multi[name] = append(multi[name], rest)
		default:
			if _, isRepeat := rows[name]; isRepeat {
				t.Fatalf("the wrap known answers carry %s twice", name)
			}
			rows[name] = rest
		}
	}
	if len(rows) == 0 {
		t.Fatal("the wrap known answers parsed to no rows at all")
	}
	out := map[string]string{}
	for name, value := range rows {
		out[name] = value
	}
	for name, values := range multi {
		out[name+wrapKatMultiSuffix] = strings.Join(values, wrapKatRowSeparator)
	}
	return out
}

// wrapKatRows answers the rows of one repeated table, split back out of the single value the
// reader joined them into.
func wrapKatRows(t *testing.T, rows map[string]string, name string) []string {
	t.Helper()
	joined, found := rows[name+wrapKatMultiSuffix]
	if !found {
		t.Fatalf("the wrap known answers carry no %s rows", name)
	}
	return strings.Split(joined, wrapKatRowSeparator)
}

func wrapKatHex(t *testing.T, rows map[string]string, name string) []byte {
	t.Helper()
	value, found := rows[name]
	if !found {
		t.Fatalf("the wrap known answers carry no %s row", name)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("%s is not hex: %v", name, err)
	}
	return decoded
}

func wrapKatInt(t *testing.T, rows map[string]string, name string) int {
	t.Helper()
	value, found := rows[name]
	if !found {
		t.Fatalf("the wrap known answers carry no %s row", name)
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		t.Fatalf("%s is not a decimal integer: %v", name, err)
	}
	return parsed
}

func wrapKatFill(t *testing.T, rows map[string]string, fill string, length string, digest string) []byte {
	t.Helper()
	octet := wrapKatHex(t, rows, fill)
	if len(octet) != 1 {
		t.Fatalf("%s is %d octets, want one", fill, len(octet))
	}
	built := bytes.Repeat(octet, wrapKatInt(t, rows, length))
	got := sha256.Sum256(built)
	if hex.EncodeToString(got[:]) != rows[digest] {
		t.Fatalf("the octets %s and %s describe hash to %x and %s gives %s", fill, length, got, digest, rows[digest])
	}
	return built
}
