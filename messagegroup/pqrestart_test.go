// THE RESTART pqsecret.go's FIRST DRAFT CLAIMED COULD NOT HAPPEN.
//
// That draft said, of the group-lifetime premise, that "the moment a different secret arrives the
// session is ROTATED and the fallback is gone for good", and errors.go said ErrPqSecretUnknownEpoch
// was "unreachable" while a session had not rotated. Both sentences are about ONE PROCESS and the
// thing they describe is a property of the GROUP. A device that restarts after its group has
// rotated builds a session that holds today's secret, an empty table and the premise INTACT -- it
// never witnessed the rotation and now never can -- so it answers a past epoch with today's
// secret, which is exactly the defect ledger item 251's ruling 40 exists to remove, surfacing as
// an AEAD tag failure with nothing naming the cause.
//
// FOUR CASES, AND THE FIRST ONE IS WRITTEN TO GO RED ON AN IMPROVEMENT. It pins the residual as a
// measurement rather than as a paragraph: while nothing carries rotation across a restart, this is
// what a restarted session does. The day the fact reaches a fresh session -- sdk's GroupRecord
// stops being one pq_secret scalar, which is item 243's step 4 -- that case fails and says so, and
// whoever closes it has to move this file, pqsecret.go's header and errors.go's sentinel together.
// The other three are the seam that makes closing it possible, measured in both directions.
package messagegroup

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/urnetwork/connect/message"
)

// restartOpener is a device coming back after a stop: a session built over a handle LOADED FROM
// THE STORE rather than the one the live session held, at the epoch the group has reached, handed
// the one pq_secret a durable GroupRecord carries today.
//
// The handle is loaded rather than borrowed for two reasons, and the second is the one that
// matters: a restart really does re-open its group out of storage, and a session that owns its
// own handle can be Closed in a case that measures what a closed session's doors answer. The
// price is that a loaded handle is a SNAPSHOT -- it does not move when the chain's own handle
// commits -- so a case that needs this session to advance epochs uses restartOpenerOnTheChain
// instead, and the two are separate functions rather than a flag because the difference decides
// what AdvanceEpoch does and is not a detail.
func restartOpener(t *testing.T, pair *pastEpochPair, pqSecret []byte) *GroupSession {
	t.Helper()
	handle, err := pair.chain.b.engine.LoadGroup(pair.chain.joined.GroupId(), pair.chain.joined.Epoch())
	if err != nil {
		t.Fatalf("LoadGroup at the group's current epoch %d: %v", pair.chain.joined.Epoch(), err)
	}
	session := restartOpenerOver(t, pair, handle, pqSecret)
	t.Cleanup(func() { session.Close() })
	return session
}

// restartOpenerOnTheChain is the same restart over the chain's own live handle, for the cases that
// need the session to walk forward. It is NOT closed by this helper: the handle is the chain's and
// the chain closes it, and a Close here would close the group out from under the fixture.
func restartOpenerOnTheChain(t *testing.T, pair *pastEpochPair, pqSecret []byte) *GroupSession {
	t.Helper()
	return restartOpenerOver(t, pair, pair.chain.joined, pqSecret)
}

func restartOpenerOver(t *testing.T, pair *pastEpochPair, handle GroupHandle, pqSecret []byte) *GroupSession {
	t.Helper()
	groupId := pair.chain.joined.GroupId()
	engine := pair.chain.b.engine
	session, err := NewGroupSession(handle, pqSecret, pair.chain.groupHandleKey,
		newStreamIndexMemory(), testClock(), testServerNonce())
	if err != nil {
		t.Fatalf("the restarted session: %v", err)
	}
	if err := session.InstallPastEpochLoader(func(epoch uint64) (GroupHandle, error) {
		return engine.LoadGroup(groupId, epoch)
	}); err != nil {
		t.Fatalf("InstallPastEpochLoader: %v", err)
	}
	return session
}

// epochOneCandidateKeys is the control every case below rests on: the class keys epoch one's root
// yields under its OWN pq_secret, and the ones it yields under the secret a rotated group runs on
// today. A case that compared a session's answer against one of these without knowing the two
// differ would be photographing one number twice.
func epochOneCandidateKeys(t *testing.T, pair *pastEpochPair) (own *ClassKeys, todays *ClassKeys) {
	t.Helper()
	handle, err := pair.chain.b.engine.LoadGroup(pair.chain.joined.GroupId(), 1)
	if err != nil {
		t.Fatalf("LoadGroup(epoch 1): %v", err)
	}
	defer handle.Close()
	mlsSecret, err := handle.Export(mlsSecretLabel, nil, mlsSecretBytes)
	if err != nil {
		t.Fatalf("epoch one's Export: %v", err)
	}
	defer zeroize(mlsSecret)
	ownRoot := StorageRoot(mlsSecret, pair.chain.pqSecret)
	defer zeroize(ownRoot)
	todaysRoot := StorageRoot(mlsSecret, rotatedTestPqSecret())
	defer zeroize(todaysRoot)
	own = DeriveClassKeys(ownRoot)
	todays = DeriveClassKeys(todaysRoot)
	if classKeysEqual(own, todays) {
		t.Fatalf("CONTROL FAILED: epoch one's class keys under its own pq_secret equal the ones under the rotated secret, so no case in this file can tell an answer apart from a wrong answer")
	}
	return own, todays
}

// ── 1. THE RESIDUAL, PINNED ─────────────────────────────────────────────────────────────────────
//
// This case asserts a DEFECT and it is meant to. It is the difference between a residual that a
// step-4 author will find and one they will read past: pqsecret.go's header says a restarted
// session of a rotated group answers a past epoch with today's secret, and this is that sentence
// with a measurement under it, in a form that cannot quietly stop being true.
//
// WHEN THIS CASE FAILS, THE RESIDUAL IS CLOSED. Its messages say so. Do not repair it by relaxing
// the assertion; delete it, delete the residual paragraph in pqsecret.go, rewrite errors.go's
// three-ways paragraph at ErrPqSecretUnknownEpoch, and take item 243's Consumes line with it.
func TestARestartOfARotatedGroupStillHoldsThePremiseAndAnswersAPastEpochWithTodaysSecret(t *testing.T) {
	pair := newPastEpochPair(t, "pq-restart-residual")
	record := pair.sealDurable(t, "sealed at epoch one")
	ownKeys, todaysKeys := epochOneCandidateKeys(t, pair)

	// THE GROUP ROTATES. The live session is the control for the residual: it lived through the
	// change, so it observed it, and it is the thing the restarted session below is not.
	pair.advanceOpenerWith(t, rotatedTestPqSecret())
	var livePremise bool
	if err := pair.opener.do(func() { livePremise = pair.opener.pqLifetime }); err != nil {
		t.Fatalf("do: %v", err)
	}
	if livePremise {
		t.Fatalf("the session that lived through the rotation still holds the group-lifetime premise; a second, different secret arriving at AdvanceEpoch is supposed to drop it, and if that is broken the case below measures nothing")
	}

	restarted := restartOpener(t, pair, rotatedTestPqSecret())
	var restartedPremise bool
	var held int
	if err := restarted.do(func() {
		restartedPremise = restarted.pqLifetime
		held = len(restarted.pqSecrets)
	}); err != nil {
		t.Fatalf("do: %v", err)
	}
	if !restartedPremise || held != 1 {
		t.Fatalf("THE RESIDUAL MAY BE CLOSED: a restarted session of a rotated group holds the premise: %t with %d table entry(ies), and this case was written when it was true with 1. If a constructor now carries rotation across a restart, this file, pqsecret.go's residual paragraph and errors.go's ErrPqSecretUnknownEpoch comment all have to move together",
			restartedPremise, held)
	}

	if err := restarted.TrackSenderAt(1, pair.senderLeaf, message.RetentionDurable, 0, 0, 0); err != nil {
		t.Fatalf("the restarted session's TrackSenderAt(epoch 1) answered %v; the residual is that it does NOT refuse here", err)
	}
	built := pastEpochClassKeysAt(t, restarted, 1)
	if !classKeysEqual(built, todaysKeys) || classKeysEqual(built, ownKeys) {
		t.Fatalf("THE RESIDUAL MAY BE CLOSED: the restarted session built epoch one's schedule from today's secret: %t, from epoch one's own: %t; this case was written when it was true/false. Ruling 40's line is fixed inside a session and this case is the part that is not -- if it now derives epoch one's own root, say so everywhere the residual is written down",
			classKeysEqual(built, todaysKeys), classKeysEqual(built, ownKeys))
	}
	_, _, openErr := restarted.OpenRecord(record)
	if openErr == nil {
		t.Fatalf("a restarted session of a rotated group OPENED an epoch-one record; either the residual is closed or the rotation did not happen")
	}
	if errors.Is(openErr, ErrPqSecretUnknownEpoch) {
		t.Fatalf("THE RESIDUAL IS CLOSED: the restarted session refused with ErrPqSecretUnknownEpoch, which is the answer this shape should get and did not. Delete this case and the residual with it")
	}
	// and this is the whole cost of the residual in one line: the failure a field report would
	// carry is an AEAD tag, which names nothing.
	if !errors.Is(openErr, ErrRecordAeadOpen) {
		t.Errorf("the restarted session answered %v; the residual's signature is an AEAD failure with no diagnosis in it, and an answer of another shape means the path changed under this case", openErr)
	}
}

// ── 2. THE DECLARATION ──────────────────────────────────────────────────────────────────────────
//
// DeclarePqSecretRotated is how the fact reaches a fresh session, and this case fails in both
// directions off one session: before the declaration it opens the record out of the premise, after
// it refuses by name, and after the missing secret is filed it opens it out of the RIGHT root. A
// case that only showed the refusal would be satisfied by a door that refused everything.
func TestARestartedSessionToldItsGroupRotatedRefusesUntilThePastSecretIsFiled(t *testing.T) {
	pair := newPastEpochPair(t, "pq-restart-declared")
	record := pair.sealDurable(t, "sealed at epoch one")
	ownKeys, todaysKeys := epochOneCandidateKeys(t, pair)
	pair.advanceOpenerWith(t, rotatedTestPqSecret())

	restarted := restartOpener(t, pair, rotatedTestPqSecret())

	// BEFORE, READ AT THE SECRET AND NOT THROUGH AN OPEN: this session would answer epoch one
	// with today's octets. It is read here rather than by opening a record because an open
	// CACHES the schedule it builds, and a cached pastEpoch answers ahead of the lookup this
	// case is about -- so an open before the declaration would be measuring the cache afterwards.
	var beforeSecret []byte
	if err := restarted.do(func() {
		secret, err := restarted.pqSecretForOnLoop(1)
		if err != nil {
			t.Errorf("before the declaration, epoch one's secret answered %v; the premise is supposed to answer it, and the declaration below has nothing to change if it does not", err)
			return
		}
		beforeSecret = append([]byte(nil), secret...)
	}); err != nil {
		t.Fatalf("do: %v", err)
	}
	if !bytes.Equal(beforeSecret, rotatedTestPqSecret()) {
		t.Fatalf("before the declaration the restarted session answered epoch one with something other than today's secret, so this case is not measuring the premise")
	}

	if err := restarted.DeclarePqSecretRotated(); err != nil {
		t.Fatalf("DeclarePqSecretRotated: %v", err)
	}

	if err := restarted.TrackSenderAt(1, pair.senderLeaf, message.RetentionDurable, 0, 0, 0); !errors.Is(err, ErrPqSecretUnknownEpoch) {
		t.Fatalf("a restarted session TOLD its group rotated answered %v when asked to track a sender at epoch one, want ErrPqSecretUnknownEpoch; the declaration is the only thing standing between this session and ruling 40's defect", err)
	}
	_, _, err := restarted.OpenRecord(record)
	if !errors.Is(err, ErrPqSecretUnknownEpoch) {
		t.Fatalf("the same session answered %v for an epoch-one record, want ErrPqSecretUnknownEpoch", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte(fmt.Sprintf("epoch %d", 1))) {
		t.Errorf("the refusal reads %v and does not name the epoch; the caller's only repair is to supply that epoch's secret", err)
	}

	// AFTER THE REPAIR THE REFUSAL NAMED: the past secret is filed and the same record opens, out
	// of epoch one's OWN root and not out of today's. Without this half the case above would be
	// held by a session that simply refuses everything.
	if err := restarted.InstallPqSecret(1, pair.chain.pqSecret); err != nil {
		t.Fatalf("InstallPqSecret(1, epoch one's own secret): %v", err)
	}
	if err := restarted.TrackSenderAt(1, pair.senderLeaf, message.RetentionDurable, 0, 0, 0); err != nil {
		t.Fatalf("TrackSenderAt(epoch 1) after the secret was filed: %v", err)
	}
	if _, body, err := restarted.OpenRecord(record); err != nil || string(body) != "sealed at epoch one" {
		t.Fatalf("after epoch one's own secret was filed the record answered %v / %q, want the body it was sealed with", err, body)
	}
	after := pastEpochClassKeysAt(t, restarted, 1)
	if !classKeysEqual(after, ownKeys) || classKeysEqual(after, todaysKeys) {
		t.Errorf("the repaired session built epoch one from its own secret: %t, from today's: %t; want true/false",
			classKeysEqual(after, ownKeys), classKeysEqual(after, todaysKeys))
	}
}

// ── 3. THE DOOR ─────────────────────────────────────────────────────────────────────────────────
//
// InstallPqSecret's own properties, each failing for its own reason: it FILES, it REFUTES the
// premise on the octets rather than on the call, it ERASES what it replaces, it refuses a width, a
// nothing, an epoch past the window and a closed session. The refutation is the one that earns the
// door its place -- a restorer that files a past secret has told this session its group rotates
// without a second call, so a restorer cannot half-repair itself into the residual above.
func TestInstallPqSecretFilesRefutesOnTheOctetsAndRefusesWhatItCannotServe(t *testing.T) {
	pair := newPastEpochPair(t, "pq-restart-door")
	pair.advanceOpenerWith(t, rotatedTestPqSecret())
	restarted := restartOpener(t, pair, rotatedTestPqSecret())

	// FILING TODAY'S OWN SECRET AGAIN REFUTES NOTHING. The control for the refutation: same door,
	// same epoch arithmetic, octets that match, premise intact.
	if err := restarted.InstallPqSecret(2, rotatedTestPqSecret()); err != nil {
		t.Fatalf("InstallPqSecret(2, the secret it already holds): %v", err)
	}
	var premise bool
	if err := restarted.do(func() { premise = restarted.pqLifetime }); err != nil {
		t.Fatalf("do: %v", err)
	}
	if !premise {
		t.Errorf("filing the secret this session already holds dropped the group-lifetime premise; the refutation is on the OCTETS and a door that dropped it on the call would take the compatibility path away from every group alive")
	}

	// AND FILING A DIFFERENT ONE REFUTES IT, with the entry landing at the epoch asked for.
	if err := restarted.InstallPqSecret(1, pair.chain.pqSecret); err != nil {
		t.Fatalf("InstallPqSecret(1, a different secret): %v", err)
	}
	var filed []byte
	if err := restarted.do(func() {
		premise = restarted.pqLifetime
		filed = append([]byte(nil), restarted.pqSecrets[1]...)
	}); err != nil {
		t.Fatalf("do: %v", err)
	}
	if premise {
		t.Errorf("a secret differing from the one at this session's epoch was filed and the premise survived; that filing IS the observation a restart cannot make for itself")
	}
	if !bytes.Equal(filed, pair.chain.pqSecret) {
		t.Errorf("pq_secret[1] reads %d octets and is not what was filed", len(filed))
	}

	// THE REPLACE ERASES, aliased before the replacement for the reason every erase case in this
	// package aliases: "all zero" read through the map is a photograph of whatever is there now.
	var superseded []byte
	if err := restarted.do(func() { superseded = restarted.pqSecrets[1] }); err != nil {
		t.Fatalf("do: %v", err)
	}
	if !containsNonZero(superseded) {
		t.Fatalf("the entry about to be replaced is already all zero, so the reading below would say nothing")
	}
	replacement := make([]byte, PqSecretBytes)
	for i := range replacement {
		replacement[i] = byte(0xC3 ^ i)
	}
	if err := restarted.InstallPqSecret(1, replacement); err != nil {
		t.Fatalf("InstallPqSecret(1, a replacement): %v", err)
	}
	if containsNonZero(superseded) {
		t.Errorf("the superseded pq_secret[1] is still in the heap; an entry a door replaced without erasing is a retired epoch's post quantum half with no owner")
	}

	// THE REFUSALS, each measured against the accepted call above rather than against nothing.
	if err := restarted.InstallPqSecret(1, nil); !errors.Is(err, ErrNilPqSecret) {
		t.Errorf("InstallPqSecret(1, nil) answered %v, want ErrNilPqSecret; a door that took it would file thirty two zeros as an epoch's post quantum half", err)
	}
	if err := restarted.InstallPqSecret(1, make([]byte, 4)); !errors.Is(err, ErrPqSecretLength) {
		t.Errorf("InstallPqSecret(1, four octets) answered %v, want ErrPqSecretLength; four octets extract to a storage root both clients agree on and MASTER section 7 does not specify", err)
	}

	// AND AN EPOCH ABOVE THIS SESSION'S OWN IS ACCEPTED, which is not an oversight: ruling 37 has
	// the wraps for epoch n+1 submitted AT epoch n, staged and pre-merge, so the secret of an
	// epoch this session has not yet entered is a value that legitimately arrives early.
	var at uint64
	if err := restarted.do(func() { at = restarted.epoch }); err != nil {
		t.Fatalf("do: %v", err)
	}
	if err := restarted.InstallPqSecret(at+1, replacement); err != nil {
		t.Errorf("InstallPqSecret at epoch %d, one above this session's %d, answered %v; ruling 37 has that secret arriving before the merge that opens its epoch", at+1, at, err)
	}

	// AND A CLOSED SESSION'S DOORS ARE SHUT. Both of them, because two doors onto one field with
	// one of them still open after Close is the field surviving the erase that emptied it.
	if err := restarted.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := restarted.InstallPqSecret(1, replacement); !errors.Is(err, ErrSessionClosed) {
		t.Errorf("InstallPqSecret on a closed session answered %v, want ErrSessionClosed", err)
	}
	if err := restarted.DeclarePqSecretRotated(); !errors.Is(err, ErrSessionClosed) {
		t.Errorf("DeclarePqSecretRotated on a closed session answered %v, want ErrSessionClosed", err)
	}
}

// ── 3b. THE DOOR'S WINDOW BOUND, WHICH NEEDS A SESSION FAR ENOUGH ALONG TO HAVE ONE ─────────────
//
// InstallPqSecret refuses an epoch past PastEpochWindow with pastEpochOnLoop's OWN sentinel and
// files nothing, because that function refuses the epoch before it ever asks for a secret: filing
// one would hold a retired epoch's post quantum half until the next advance erased it, for
// nothing, and would answer a restorer "recovered" about history it cannot read. The control is
// the epoch exactly AT the edge, in the same pass -- one epoch apart, opposite answers -- without
// which the refusal could be a door that refuses every past epoch.
func TestInstallPqSecretRefusesAnEpochPastTheWindowAndAcceptsTheOneAtTheEdge(t *testing.T) {
	pair := newPastEpochPair(t, "pq-restart-door-window")
	// the group walks to 1+PastEpochWindow with the SAME secret every time, so the premise is
	// intact and the only thing under test below is the bound.
	for epoch := uint64(2); epoch <= 1+PastEpochWindow; epoch += 1 {
		pair.advanceOpenerWith(t, pair.chain.pqSecret)
	}
	restarted := restartOpener(t, pair, pair.chain.pqSecret)
	var at uint64
	if err := restarted.do(func() { at = restarted.epoch }); err != nil {
		t.Fatalf("do: %v", err)
	}
	if at != 1+PastEpochWindow {
		t.Fatalf("the restarted session is at epoch %d, want %d; the bound below is arithmetic on it", at, 1+PastEpochWindow)
	}
	edge := at - PastEpochWindow
	other := make([]byte, PqSecretBytes)
	for i := range other {
		other[i] = byte(0x91 ^ (i * 3))
	}
	if err := restarted.InstallPqSecret(edge, other); err != nil {
		t.Errorf("InstallPqSecret at epoch %d, exactly PastEpochWindow behind %d, answered %v; that is the last epoch the window reaches and an open there would be admitted", edge, at, err)
	}
	if err := restarted.InstallPqSecret(edge-1, other); !errors.Is(err, ErrEpochOutOfWindow) {
		t.Errorf("InstallPqSecret at epoch %d, %d behind %d, answered %v, want ErrEpochOutOfWindow", edge-1, PastEpochWindow+1, at, err)
	}
	var heldEdge, heldBelow bool
	if err := restarted.do(func() {
		_, heldEdge = restarted.pqSecrets[edge]
		_, heldBelow = restarted.pqSecrets[edge-1]
	}); err != nil {
		t.Fatalf("do: %v", err)
	}
	if !heldEdge {
		t.Errorf("the accepted epoch %d was not filed", edge)
	}
	if heldBelow {
		t.Errorf("the refused epoch %d was filed anyway; a refusal that files is a refusal with a side effect", edge-1)
	}
}

// ── 4. WHAT THE PREMISE IS DEFINED ON, DERIVED AND ASSERTED RATHER THAN DESCRIBED ───────────────
//
// pqsecret.go claims the premise is reached "only for epochs BELOW the one this session was
// constructed at: precisely the epochs it was not present for". That is a claim about a SET, so it
// is measured as one: every epoch from zero to the session's own is asked for, each answer is
// classified by which arm produced it, and the three sets are asserted whole -- not sampled.
//
// IT FAILS BOTH WAYS. With the premise standing, the table answers exactly the epochs the session
// stood at and the premise answers exactly the rest, with NOTHING refused; with the premise
// dropped, the premise set is empty and the refused set is exactly what it used to answer. A gate
// that printed these sets without holding them against a written-down disposition would be a gate
// that passes whatever the code happens to do.
func TestThePremiseAnswersExactlyTheEpochsBelowTheOneTheSessionWasBuiltAt(t *testing.T) {
	pair := newPastEpochPair(t, "pq-restart-premise-set")
	// the group walks to epoch five with no session watching, which is what a device that was
	// offline comes back to.
	for range 4 {
		if _, _, _, err := pair.chain.joined.Commit(nil); err != nil {
			t.Fatalf("Commit(nil): %v", err)
		}
		if err := pair.chain.joined.MergePendingCommit(); err != nil {
			t.Fatalf("MergePendingCommit: %v", err)
		}
	}
	if epoch := pair.chain.joined.Epoch(); epoch != 5 {
		t.Fatalf("the group is at epoch %d after four commits, want 5", epoch)
	}
	// over the chain's LIVE handle, because this session has to walk forward and a store-loaded
	// handle is a snapshot that does not move when the chain commits.
	restarted := restartOpenerOnTheChain(t, pair, pair.chain.pqSecret)
	builtAt := uint64(5)

	// and two advances on the SAME secret, so the table holds 5, 6 and 7 and the premise is
	// still standing -- the ordinary shape of every group alive today.
	for range 2 {
		if _, _, _, err := pair.chain.joined.Commit(nil); err != nil {
			t.Fatalf("Commit(nil): %v", err)
		}
		if err := pair.chain.joined.MergePendingCommit(); err != nil {
			t.Fatalf("MergePendingCommit: %v", err)
		}
		if err := restarted.AdvanceEpoch(pair.chain.pqSecret); err != nil {
			t.Fatalf("AdvanceEpoch: %v", err)
		}
	}

	// classify is the whole measurement: which arm answered, for every epoch at or below this
	// session's own.
	//
	// THE OCTETS ARE CHECKED AND NOT ONLY THE MEMBERSHIP, which is what makes this a measurement
	// of the ORDER of the two arms rather than of the table's keys. While the premise stands both
	// arms return the same octets for every epoch in the table -- every entry is the same value --
	// so a reading that classified on the key alone would call an answer a table hit while the
	// premise produced it, and the day the entries differ that is ruling 40's defect exactly.
	// Each epoch's answer is therefore held against the entry filed AT that epoch, and a premise
	// answer against the entry at the session's own.
	classify := func() (fromTable []uint64, fromPremise []uint64, refused []uint64) {
		if err := restarted.do(func() {
			for epoch := uint64(0); epoch <= restarted.epoch; epoch += 1 {
				entry, inTable := restarted.pqSecrets[epoch]
				secret, err := restarted.pqSecretForOnLoop(epoch)
				switch {
				case err != nil:
					refused = append(refused, epoch)
				case inTable:
					if !bytes.Equal(secret, entry) {
						t.Errorf("epoch %d is in the table and the lookup answered something else; the table arm has to come FIRST or a session that has seen a rotation answers a held epoch out of the premise", epoch)
					}
					fromTable = append(fromTable, epoch)
				default:
					if !bytes.Equal(secret, restarted.pqSecrets[restarted.epoch]) {
						t.Errorf("epoch %d was answered out of neither the table nor the premise, which is a third arm this file does not know about", epoch)
					}
					fromPremise = append(fromPremise, epoch)
				}
			}
		}); err != nil {
			t.Fatalf("do: %v", err)
		}
		return fromTable, fromPremise, refused
	}
	sameSet := func(got []uint64, want []uint64) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}

	fromTable, fromPremise, refused := classify()
	// THE DISPOSITION, WRITTEN DOWN BEFORE THE READING: the table answers exactly the epochs this
	// session stood at -- the one it was built at and the two it advanced into -- and the premise
	// answers exactly the epochs below that, which is the set it has no evidence about.
	if !sameSet(fromTable, []uint64{5, 6, 7}) {
		t.Errorf("the table answered %v, want [5 6 7]: the epoch the session was built at and the two it advanced into, and nothing else", fromTable)
	}
	if !sameSet(fromPremise, []uint64{0, 1, 2, 3, 4}) {
		t.Errorf("the premise answered %v, want [0 1 2 3 4]: every epoch below the one this session was built at, and no epoch it stood at", fromPremise)
	}
	if len(refused) != 0 {
		t.Errorf("a session holding the premise refused %v; while the premise stands it answers everything, which is the behaviour every group alive today depends on", refused)
	}
	// THE COMPLEMENT, ASSERTED AND NOT MERELY PRINTED: every epoch the premise answered is
	// strictly below the epoch the session was built at. An empty premise set here would make the
	// two assertions above pass vacuously.
	if len(fromPremise) == 0 {
		t.Fatalf("no epoch reached the premise at all, so the bound below is asserted over nothing")
	}
	for _, epoch := range fromPremise {
		if epoch >= builtAt {
			t.Errorf("the premise answered epoch %d and this session was built at epoch %d; the premise is supposed to be defined exactly on what the session was not present for", epoch, builtAt)
		}
	}

	// AND THE OTHER DIRECTION, off the same session: the declaration moves the premise's whole set
	// into the refused set and leaves the table's untouched.
	if err := restarted.DeclarePqSecretRotated(); err != nil {
		t.Fatalf("DeclarePqSecretRotated: %v", err)
	}
	fromTableAfter, fromPremiseAfter, refusedAfter := classify()
	if !sameSet(fromTableAfter, []uint64{5, 6, 7}) {
		t.Errorf("after the declaration the table answered %v, want [5 6 7]: a session told its group rotates still holds the epochs it stood at", fromTableAfter)
	}
	if len(fromPremiseAfter) != 0 {
		t.Errorf("after the declaration the premise still answered %v", fromPremiseAfter)
	}
	if !sameSet(refusedAfter, []uint64{0, 1, 2, 3, 4}) {
		t.Errorf("after the declaration the refused set is %v, want [0 1 2 3 4]: exactly what the premise used to answer, refused by name instead of answered wrongly", refusedAfter)
	}

	// AND THE ORDER OF THE ARMS ONCE THE PREMISE IS GONE: epoch five's own secret is filed and
	// has to be what epoch five is answered with, rather than the entry at this session's own
	// epoch. Case 5 is where the order is measured in the state that makes it load-bearing.
	distinct := make([]byte, PqSecretBytes)
	for i := range distinct {
		distinct[i] = byte(0x6E ^ (i * 5))
	}
	if err := restarted.InstallPqSecret(5, distinct); err != nil {
		t.Fatalf("InstallPqSecret(5, a distinguishable secret): %v", err)
	}
	if err := restarted.do(func() {
		if bytes.Equal(restarted.pqSecrets[restarted.epoch], distinct) {
			t.Fatalf("the filed secret equals the one at this session's own epoch, so the order below cannot be read")
		}
		secret, err := restarted.pqSecretForOnLoop(5)
		if err != nil {
			t.Errorf("epoch five's own secret was filed and the lookup answered %v", err)
			return
		}
		if !bytes.Equal(secret, distinct) {
			t.Errorf("the lookup answered epoch five out of something other than the entry filed at epoch five; the table arm has to come first")
		}
	}); err != nil {
		t.Fatalf("do: %v", err)
	}
}

// ── 5. THE ORDER OF THE TWO ARMS, WHICH IS UNOBSERVABLE TODAY AND WILL NOT BE ───────────────────
//
// A mutant that puts the PREMISE arm first survives this package's whole suite, and after the
// query was checked that turned out to be a fact about the code rather than a hole in the reading.
// installPqSecretOnLoop is the ONLY writer of the table -- five reaches of self.pqSecrets[...] in
// the production source, one of them a store -- and it drops the premise the moment a value
// arrives that differs from the one at this session's epoch. So WHILE THE PREMISE STANDS EVERY
// ENTRY IN THE TABLE IS THE SAME OCTETS, the two arms return equal values for every epoch, and no
// reading of the live doors can tell the order apart. The mutant is equivalent, today.
//
// TODAY IS THE WHOLE OF THAT SENTENCE. The invariant is exactly what item 243's step 4 removes: a
// device wrap delivers pq_secret[k] per epoch, the table starts holding different values, and the
// order stops being a style question -- a lookup that reached the premise first would answer a
// held epoch out of the current epoch's octets, which is ruling 40's own line one arm further in.
//
// So both facts are asserted rather than either being assumed: the invariant that makes the order
// unobservable, over the real doors; and the order itself, in the state step 4 makes reachable,
// which no door can produce today and which is therefore planted on the loop. A case that planted
// the state without asserting the invariant would be testing a shape the code cannot reach; one
// that asserted the invariant without the order would leave the arm swap unmeasured until the day
// it starts mattering, which is the day nobody is looking at this file.
func TestWhileThePremiseStandsTheTableHoldsOneValueAndTheTableArmStillAnswersFirst(t *testing.T) {
	pair := newPastEpochPair(t, "pq-restart-arm-order")
	restarted := restartOpenerOnTheChain(t, pair, pair.chain.pqSecret)
	for range 2 {
		if _, _, _, err := pair.chain.joined.Commit(nil); err != nil {
			t.Fatalf("Commit(nil): %v", err)
		}
		if err := pair.chain.joined.MergePendingCommit(); err != nil {
			t.Fatalf("MergePendingCommit: %v", err)
		}
		if err := restarted.AdvanceEpoch(pair.chain.pqSecret); err != nil {
			t.Fatalf("AdvanceEpoch: %v", err)
		}
	}
	// and one more filing through the public door, with the SAME octets, because the invariant
	// is over every writer and not only over AdvanceEpoch.
	if err := restarted.InstallPqSecret(1, pair.chain.pqSecret); err != nil {
		t.Fatalf("InstallPqSecret(1, the same secret): %v", err)
	}

	// 1. THE INVARIANT. Every entry is one value, and the count of entries is checked with it so
	// that a table of one entry cannot satisfy "all entries agree" vacuously.
	var entries int
	var distinctValues int
	var premise bool
	if err := restarted.do(func() {
		premise = restarted.pqLifetime
		entries = len(restarted.pqSecrets)
		seen := [][]byte{}
		for _, secret := range restarted.pqSecrets {
			isNew := true
			for _, already := range seen {
				if bytes.Equal(already, secret) {
					isNew = false
					break
				}
			}
			if isNew {
				seen = append(seen, secret)
			}
		}
		distinctValues = len(seen)
	}); err != nil {
		t.Fatalf("do: %v", err)
	}
	if !premise {
		t.Fatalf("the premise was dropped by a run that handed in one secret throughout, so the invariant below is about some other session")
	}
	if entries < 2 {
		t.Fatalf("the table holds %d entry(ies) and the invariant is over a table of several; one entry agrees with itself", entries)
	}
	if distinctValues != 1 {
		t.Errorf("the table holds %d entries and %d distinct values while the premise stands, want 1; the premise standing IS the claim that every entry is the same octets, and it is what makes the arm order unobservable",
			entries, distinctValues)
	}

	// 2. THE ORDER, in the state step 4 makes reachable. It is planted on the loop because no
	// door can produce it: filing a differing value is what drops the premise. The control is in
	// the same pass -- the planted value differs from the one at this session's epoch -- without
	// which the assertion could be satisfied by either arm.
	var at uint64
	planted := make([]byte, PqSecretBytes)
	for i := range planted {
		planted[i] = byte(0x2D ^ (i * 11))
	}
	if err := restarted.do(func() {
		at = restarted.epoch
		if bytes.Equal(restarted.pqSecrets[at], planted) {
			t.Fatalf("the planted value equals the entry at this session's own epoch, so the two arms answer the same thing and the order cannot be read")
		}
		zeroize(restarted.pqSecrets[1])
		restarted.pqSecrets[1] = append([]byte(nil), planted...)
		// and the premise is left STANDING, which is the whole of what makes this the mutant's
		// state rather than the ordinary one.
		restarted.pqLifetime = true
		secret, err := restarted.pqSecretForOnLoop(1)
		if err != nil {
			t.Errorf("epoch one is in the table and the lookup answered %v", err)
			return
		}
		if bytes.Equal(secret, restarted.pqSecrets[at]) {
			t.Errorf("the lookup answered epoch one out of the entry at epoch %d: the PREMISE arm ran for an epoch the table holds, which is ruling 40's defect with the table already carrying the right answer", at)
		}
		if !bytes.Equal(secret, planted) {
			t.Errorf("the lookup answered epoch one out of neither the entry at epoch one nor the entry at epoch %d", at)
		}
	}); err != nil {
		t.Fatalf("do: %v", err)
	}
}
