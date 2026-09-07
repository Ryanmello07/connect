// The stream index reservation: the durability the record aead's nonce uniqueness rests on,
// declared here as an interface and implemented nowhere in this package.
//
// Spec A section 5.6, quoted whole because its two halves are usually collapsed into one:
//
//	stream_index is a single u64 counter per (group_id, sender_handle), write-once, assigned
//	locally. A device MUST durably record "index k consumed" BEFORE encrypting, and MUST NEVER
//	encrypt a second record at a consumed index. The server enforces monotonicity, not
//	contiguity, so a refused write, a crash between reserve and send, or a lost commit leaves a
//	legal gap.
//
//	Nonce reuse under a repeated record_key is a total break of both AEADs for that record,
//	which is why the reservation is durable rather than best-effort.
//
//	SealRecord calls Reserve and refuses to proceed on error. On startup, HighWater is read and
//	the ratchet resumes at highWater + 1, never at a recomputed value.
//
// WHY THERE IS NO IMPLEMENTATION HERE, so that a reader who finds none finds the reason instead
// of writing one. Three facts and together they are the argument.
//
// Neither half of the record layer imports an I/O package at all. Measured over the production
// files of connect/message and connect/messagegroup, the whole import set is the standard
// library's crypto, encoding/binary, errors, fmt, io, sync, mls and mls/syntax; the heaviest is
// io, for an io.Reader parameter. Adding a file format here would make the client half a storage
// engine, and it is a RECORD layer with a group attached. connect/mls's import gate holds that
// as a test rather than as a sentence: every production import of this directory is pinned in
// mls's own suite, so an os arriving here fails a test over there on the commit that adds it.
//
// Section 8.2 already assigns the persistence, to sdk. MessageStore declares
// ReserveStreamIndex(groupId []byte, index uint64) error and StreamHighWater(groupId []byte)
// (uint64, error) -- this interface, method for method and parameter for parameter, on the
// fourteen method interface the sqlite implementation already owes. A second durable
// implementation here is the second implementation of one thing, which is the shape this plan's
// first paragraph forbids.
//
// And section 5.6 injects the sink for exactly this reason -- "the constructor takes the sink to
// make it explicit" -- which is why NewSenderRatchet takes one and refuses a nil.
//
// So what ships here is the interface, the two sentinels and the CONTRACT below. The durable
// implementation is sdk's, its plan is unwritten, and every obligation stated here is one that
// plan inherits. A CP3b run over this package's test fake proves the record layer and not the
// client.
//
// THE KEYING QUESTION IS NOT ANSWERED HERE AND MUST NOT BE ANSWERED HERE. Section 5.6's first
// sentence says the counter is per (group_id, sender_handle); the interface it then declares
// takes groupId and NOT senderHandle, in both methods, and so does section 8.2's MessageStore.
// sender_handle is a function of the LEAF (MASTER section 8) and group_handle_key is fixed at
// group creation, so a device removed and re-added at a different leaf has a DIFFERENT
// sender_handle in the SAME group. A reserver keyed on group_id alone either hands the new
// handle the old leaf's high water -- burning indices, benign -- or, on any local state
// divergence, lets a fresh handle start at 1 while a stale row says otherwise. That is open item
// M1-5, it is the highest priority of the non blocking items because this is the one piece of
// durable on-disk state that cannot be migrated by recomputation, and the parameter set here is
// the one both documents declare. Implement the ruling; do not choose it in this file.
package messagegroup

// StreamIndexReserver is the durable sink a sender ratchet reserves its stream indices in.
//
// THE CONTRACT, which is the whole of what this file ships. An implementation owes all five,
// and streamindex_test.go holds a file backed fake to every one of them so that the properties
// are executable here rather than deferred to a package that does not exist yet.
//
//  1. Reserve returns only after the reservation SURVIVES A PROCESS DEATH. Not after the write
//     is issued, not after it is buffered: after it is durable. A Reserve that returns before
//     the flush is a nonce reuse machine that passes every round trip test there is, because
//     the reused value is still well formed and the record still opens against itself.
//  2. HighWater never rewinds. After a restart it is at least what it was, for every key, under
//     every interleaving. A persisted state behind an index already handed out is
//     ErrStreamIndexRewound.
//  3. A consumed index is refused and never overwritten, with ErrStreamIndexConsumed. A typed
//     fatal error per section 5.9 G7, never a bool and never a log line.
//  4. The store is TOTAL over its key space. A group never seen answers HighWater 0 with no
//     error, so highWater + 1 is a well defined start; section 5.1 makes record_id = 0 the
//     "from the beginning" cursor by the same reasoning and the two must not disagree in shape.
//  5. Reserve is not idempotent. Reserving an index a second time is condition 3 and not a
//     no-op, because "I already have that one" and "I am about to encrypt under that one" are
//     the same call from this interface's side.
//
// The cost this interface hands its implementer, filed rather than absorbed: section 5.6 makes
// EPH(bucket 0) transients consume an index locally so the counter is never rewound, which
// makes every typing indicator a synchronous flush and the transient send rate the fsync rate.
// That is open item M1-25. Nothing here forecloses a separate transient counter, and an
// implementation that wants one adds a key rather than changing a method.
type StreamIndexReserver interface {
	// Reserve records that this device is about to encrypt at index, and returns only after
	// that record is durable. The error is fatal to the seal: SealRecord refuses to proceed.
	Reserve(groupId []byte, index uint64) error
	// HighWater is the highest index this store has ever reserved for the group, or 0 for a
	// group it has never seen. The ratchet resumes at highWater + 1 and never at a
	// recomputed value.
	HighWater(groupId []byte) (uint64, error)
}
