// eph_root and K_eph[n][b][t]: the one ladder whose keys are meant to stop existing, and the
// window arithmetic that says which one a record takes.
//
// Spec A section 2.2's tree assigns "eph_root, buckets, window expiry" to this file. Two of
// those three are here. The third is not, and its absence is the first thing this file says:
// NOTHING SCHEDULES THE DESTRUCTION OF eph_root[n] OR OF K_eph[n][b][t], anywhere in the
// corpus. Ledger open item 186, filed 2026-09-13 and not ruled, and it is not this file's to
// invent -- master section 8.1 states it in its own voice, that the 2026-09-13 ruling slices
// the DERIVED key and leaves eph_root[n] one value per epoch which anyone holding it recomputes
// every window of every bucket from, and that the only deletion the corpus names anywhere is
// epoch scoped. A reader who came here expecting "window expiry" finds the reason it is missing
// instead of a schedule somebody chose.
//
// MASTER SECTION 8.1 IS THE DERIVATION AND SPEC A SECTION 5.3 IS THE SIGNATURE:
//
//	eph_root[n] = 32 B fresh CSPRNG at commit  <- NOT derived from storage_root (I4)
//	  K_eph[n][b][t] = HKDF-Expand(eph_root[n], "eph/v1" || u8(b) || u64(t), 32)
//
//	t = eph_window, the record's own plaintext field. Ruled 2026-09-13.
//	    t = floor(sent_at_ms / (eph_bucket_seconds[b] * 1000)) for b in 1..5, computed by
//	    the SENDER from the same wall clock reading it puts in sent_at; origin is the unix
//	    epoch. For b = 0, t = 0 BY DEFINITION and is never computed -- bucket 0 is never
//	    persisted, so it has one window for the life of eph_root[n] and there is no division.
//
// THE WINDOW IS AN ARGUMENT AND NEVER A CLOCK READING, and that is the property this file is
// most easily wrong about. EphKey takes t; it does not compute one, it does not take a clock,
// and it must never grow either. A window EphKey derived for itself would differ from the
// sender's on every record that crossed a bucket boundary, and the aead tag would be the only
// thing in the system that said so -- a sender and a receiver that disagree about t hold two
// different thirty two octet keys and neither can tell the other why. The sender's ONE reading
// of its own clock goes through EphWindowAt, whose argument is a reading rather than a source,
// and the answer travels in the record's eph_window field in the clear. AN OPENER TAKES THE
// WIRE VALUE AND NEVER RECOMPUTES IT (spec A section 5.3, master section 8).
//
// THE ONE THING AN OPENER DOES WITH ITS OWN CLOCK IS REFUSE, AND THE REFUSAL IS ASYMMETRIC.
// seal.go carries it, because it is OpenRecord's and not this file's, but the reason belongs
// beside the derivation it is about: an opener can derive ANY window's key from eph_root[n] --
// HKDF-Expand takes whatever t it is handed and this file is the evidence for that sentence --
// so a client that honoured a far future window would keep a record openable long past its
// timer, for every record a hostile sender or a hostile server put in front of it, with master
// section 12.4's required user facing string false and nothing anywhere reporting it. A window
// BEHIND the opener's own is not a refusal in any amount: the opener derives the key for the
// wire window and either still holds it or has destroyed it on schedule.
//
// THE ROOT HAS NO DURABLE INPUT AND THERE IS NO FUNCTION HERE THAT GIVES IT ONE. NewEphRoot
// takes an io.Reader and nothing else: no group, no epoch, no storage root, no seed. Master
// section 8.1 calls this the most easily broken property in the design -- a derivation from
// storage_root would compile, pass every test that does not specifically look for it, and
// silently make every expired message recoverable forever. The type signature is the defence
// and entropy_test.go is what holds it.
package messagegroup

import (
	"fmt"
	"io"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/mls"
	"github.com/urnetwork/connect/mls/syntax"
)

// The label of the eph ladder, raw ascii, one constant for the reason keyschedule.go's four
// ladder labels are four constants: a label built by substituting a word into a shared stem is
// one edit away from two ladders sharing a key.
const ephKeyInfo = "eph/v1"

// The width of eph_root[n] and of the key it expands to. Master section 8.1 gives the root as
// thirty two octets of fresh CSPRNG and the derived key as a thirty two octet HKDF-Expand.
const (
	EphRootBytes = 32
	ephKeyBytes  = 32
)

// The milliseconds in a second, so the one multiplication below reads as the unit conversion
// master section 8.1 writes rather than as a thousand somebody typed.
const millisecondsPerSecond = 1000

// NewEphRoot draws eph_root[n], the thirty two octets every ephemeral key of one epoch hangs
// off.
//
// IT TAKES A READER AND NOTHING ELSE, EVER. There is deliberately no function in this package
// that produces an eph_root from any durable input, and none in connect/message at all. A
// derivation from storage_root[n] would be thirty two well formed octets that every member
// agrees on, that every round trip in this package accepts, and that makes every expired
// message recoverable forever from a value nothing ever destroys -- which is the exact inverse
// of what the eph classes exist for. Master invariant I4 and spec A section 5.3 both say so;
// the signature is what enforces it, because a seed parameter is the only way to get the wrong
// thing in and there is not one.
//
// It is NewPqSecret's shape, deliberately, so the two entropy draws of this package read the
// same and entropy_test.go judges them as one class.
func NewEphRoot(random io.Reader) ([]byte, error) {
	if random == nil {
		return nil, mls.ErrNilRandomSource
	}
	root := make([]byte, EphRootBytes)
	if _, err := io.ReadFull(random, root); err != nil {
		return nil, err
	}
	return root, nil
}

// EphKey derives K_eph[n][b][t], the class key an EPH(b) record written in window t is sealed
// under.
//
//	K_eph[n][b][t] = HKDF-Expand(eph_root[n], "eph/v1" || u8(b) || u64(t), 32)
//
// THE WINDOW IS THE RECORD'S OWN eph_window FIELD AND THIS FUNCTION DOES NOT READ A CLOCK.
// Ruled 2026-09-13, m1 open item M1-27. The sender computes t once, from the same wall clock
// reading it puts in sent_at, and writes it into the record in the clear; every later holder of
// the record -- the opener, a re-sealer, a second implementation -- takes the wire value. A
// clock read inside this function is the defect and not an implementation detail: it would make
// t a function of WHEN the key is derived rather than of WHICH record it is for, and the two
// differ on every record that crossed a bucket boundary between being sealed and being read.
//
// HOW FAR THAT SENTENCE IS ACTUALLY HELD, because it is asserted by two gates and neither is
// total, and because the two earlier versions of this paragraph both said MORE than was true.
// ephkey_test.go carries seventeen known answers computed outside this module, over two eph_roots
// and every rung of the ladder. They kill a clock read whose influence on the derived octets is
// UNCONDITIONAL, or depends on the BUCKET ALONE, in the binary they run in. The bucket clause is
// the only one of the three arguments that is total: every rung message.EphBucketSeconds names is
// a row under both roots, and the complement of that coverage is asserted empty rather than
// described. Beside them the reference-graph gate walks the control flow and names, in its own
// header, every shape it is known not to see.
//
// WHAT THAT LEAVES, which is two classes and not one, both measured rather than feared:
//
//   - an influence conditional on a ROOT or a WINDOW the table does not carry. Two roots of 2^256
//     and five windows of 2^64 are a sample. A clock fired on a third root, or on one unpinned
//     window, is value changing and passes every gate in this tree. Widening the table from five
//     vectors to seventeen on 2026-09-13 killed the two plants that then existed -- one fired on
//     bucket 3, one on every root but the fixture's -- and did not close the class, which no
//     finite table can.
//   - a clock bound LATER than the test binary -- an exported setter written by a composition
//     root's init, a build-tag file, a plugin. In that binary this function really is pure, so no
//     width of table reaches it. Open item MG-3 in this directory's OPENITEMS.md carries the
//     reproduction and what a ruling would have to choose between.
//
// NOTHING IN THIS PACKAGE INSTALLS SUCH A HOOK, and nothing in it conditions this derivation on
// anything but its three arguments. The rows exist so that the absence is a measured claim
// instead of an assumption.
//
// BOTH REFUSALS ARE PANICS CARRYING A SENTINEL, because spec A section 5.3 publishes this
// signature with no error in it and RecordKeyZero already set that precedent for the same
// reason: nothing here is reachable from the network, both inputs are this member's own, and a
// key derived from a truncated root or under a bucket no wire byte names is a key no peer ever
// reproduces.
//
// THE BUCKET REFUSAL IS WHERE THE 2026-09-13 SENTINEL RULING BECOMES LOAD BEARING IN PRODUCTION
// CODE RATHER THAN IN A TEST. An off ladder bucket is refused and BUCKET 0 IS NOT: 0 is the
// transient rung, a real rung with a real key, whose window is 0 by definition. The two are
// told apart by message.EphBucketSeconds, which answers 0 for the first and a negative for the
// second -- and before the ruling it answered -1 for both, so this refusal could not have been
// written at all without either refusing the transient rung or admitting every byte from 6 to
// 255.
func EphKey(ephRoot []byte, bucket uint8, window uint64) []byte {
	refuseWrongWidthEphRoot(ephRoot)
	refuseOffLadderBucket(bucket)
	return keyScheduleExpand(ephRoot, ephLabelledInfo(bucket, window), ephKeyBytes)
}

// EphWindowAt is the SENDER's computation of t, and it takes a clock READING rather than a
// clock.
//
//	t = floor(sent_at_ms / (eph_bucket_seconds[b] * 1000))     for b in 1..5
//	t = 0                                                      for b = 0, by definition
//
// The argument is an int64 of unix milliseconds because that is what a nowMs func() int64
// answers and what sent_at carries. Taking the reading and not the source is the whole point:
// this package has no function that reads a clock, one that needs the time is handed a value,
// and that is what lets the sealer make exactly ONE reading per record and put the same instant
// in sent_at and in eph_window.
//
// IT IS THREE ANSWERS OVER message.EphBucketSeconds'S THREE, AND THAT IS WHY THE 2026-09-13
// RULING WAS NEEDED. A positive divides. A zero does not divide and answers window 0 -- master
// section 8.1 says bucket 0's window "is never computed", and it could not be: the divisor
// would be nought. A negative is a bucket that is not a bucket, and is refused. Under the
// single shared sentinel this function was unwritable: one answer would have had to mean both
// "do not divide, the window is 0" and "refuse", and whichever of the two it was written as
// would have been silently wrong for the other.
//
// A reading before the unix epoch is refused rather than wrapped into an enormous window. It is
// a clock that is wrong by decades, and floor() of a negative is not what master section 8.1's
// "count of whole buckets since that origin" means.
//
// THIS FUNCTION HAS A COPY IN ANOTHER REPOSITORY AND THE TWO HAVE ALREADY DRIFTED. The message
// server plays the sender in its own harness, and spec B section 2.2 forbids that module to link
// this package, so section 12.1 hands it the divisor and it does the division itself. Its copy
// once read "if seconds <= 0 { return 0 }", which collapses the off ladder answer and the
// transient rung into ONE -- the sentinel collision the 2026-09-13 ruling exists to eliminate,
// reintroduced one repository over, and the two answered differently on nine of thirty two probed
// pairs. No import can hold them together. WHAT CROSSES A FORBIDDEN IMPORT IS A VALUE:
// testdata/eph-window-kat.txt carries fifty seven answers computed from section 8's sentence
// outside both repositories, the other repository carries the same file byte for byte, and each
// drives its own copy over it. ephwindowkat_test.go is this side. Ledger item 193 carries the
// digest and what is still owed.
func EphWindowAt(bucket uint8, sentAtMs int64) (uint64, error) {
	seconds := message.EphBucketSeconds(bucket)
	switch {
	case seconds < 0:
		return 0, fmt.Errorf("%w: bucket %d", ErrEphBucketOffLadder, bucket)
	case seconds == 0:
		// the transient rung. One window for the life of eph_root[n], no division, and the
		// reading is not consulted at all -- which is what "by definition" means here.
		return 0, nil
	}
	if sentAtMs < 0 {
		return 0, fmt.Errorf("%w: %d milliseconds is before the unix epoch the window counts from",
			ErrEphWindowSentAt, sentAtMs)
	}
	return uint64(sentAtMs) / (uint64(seconds) * millisecondsPerSecond), nil
}

// ephLabelledInfo builds "eph/v1" || u8(b) || u64(t).
//
// Through the syntax writer and not through a hand rolled append, for the reason every other
// preimage in this tree goes through it: u64(t) is eight octets BIG ENDIAN, and a little endian
// eight octet window is a key of the right width that no other implementation ever derives.
//
// The panic is unreachable -- the writer's only error paths are a vector longer than its limit
// and there is no vector here -- and it is written rather than dropped because a silently short
// info is a silently wrong key.
func ephLabelledInfo(bucket uint8, window uint64) []byte {
	writer := syntax.NewWriter()
	writer.WriteRaw([]byte(ephKeyInfo))
	writer.WriteUint8(bucket)
	writer.WriteUint64(window)
	info, err := writer.Bytes()
	if err != nil {
		panic(fmt.Errorf("messagegroup: the info of an eph key could not be built: %w", err))
	}
	return info
}

// The eph_root width refusal, in one place so the derivation and the session's installer cannot
// disagree about what a root is.
func refuseWrongWidthEphRoot(ephRoot []byte) {
	if len(ephRoot) != EphRootBytes {
		panic(fmt.Errorf("%w: %d octets, want %d", ErrEphRootLength, len(ephRoot), EphRootBytes))
	}
}

// The bucket refusal, made off message.EphBucketSeconds's answer rather than off a comparison
// with 5.
//
// Deriving it from the ladder is what keeps this function and the wire alphabet from drifting:
// RetentionClassOf refuses every wire byte outside 0x10..0x15, so the buckets a record can
// carry are exactly the buckets the ladder has rungs for, and reading the ladder is how that
// stays true if a rung is ever added. A hard coded "bucket > 5" would be a second statement of
// the ladder's length in a file that does not own it.
func refuseOffLadderBucket(bucket uint8) {
	if message.EphBucketSeconds(bucket) < 0 {
		panic(fmt.Errorf("%w: bucket %d names no rung of the eph ladder", ErrEphBucketOffLadder, bucket))
	}
}
