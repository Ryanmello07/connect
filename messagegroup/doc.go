// The client half of the record layer: everything a member of a group needs and a message
// server must not be able to reach.
//
// It exists because of a capability rather than a habit. Spec B section 2.2 forbids the message
// server from linking an MLS parser at all, and section 5.3 gives the reason: the moment one is
// in that process, "just validate the commit" is a one-line change, and a client that comes to
// rely on what the server decided has made it a participant in a security argument it is not
// supposed to be in. Until the split that rule was held by nobody. connect/message imported
// connect/mls -- from xwing.go alone, for the four X25519 wrappers that keep the tree's one
// reviewed ECDH call site -- and the message server's own dependency gate,
// TestEveryDependencyOfThisModuleIsOneSpecB22Allows, was red because of it. Moving the X-Wing
// pair here takes connect/mls out of that closure without an allow-list entry and without an
// edit to spec B, which is the only repair that leaves the rule meaning what it says.
//
// The name is load bearing and is not a matter of taste. The message server's allow list carries
// connect/message as a SUBTREE, so a child package at connect/message/group would be linkable by
// the server with the gate silent -- the whole key schedule, both ratchets, the session and the
// sealer, all reachable, all uncomplained about. As a sibling, the day any package of that module
// imports this one the gate fails and a person looks. Do not tidy this package into
// connect/message/group.
//
// The layering is one way and the direction is the point. This package may import connect/mls,
// and that import is correct rather than tolerated: this is the half that holds the group.
// It may import connect/message, for the record types and the preimages the two authenticators
// run over, and since m1 wave 1's sealer it DOES: SealRecord and OpenRecord are the two callers
// of that package's aad builders and of its write_auth mac. connect/message must never import
// this package, and connect must never import either. connect/layering_test.go holds all of
// that; the compiler holds the one direction that would be a cycle, and holds nothing about the
// other two.
//
// What is here today is the X-Wing hybrid key encapsulation of draft-connolly-cfrg-xwing-kem with
// its four sentinels, and the whole of what m1 wave 1 lands: the record aead and the algorithm
// identifier MASTER section 7.1 registers for it, this package's own best effort zeroization, the
// storage root and the three retention class keys, the three handles a record is routed by, the
// record key ladder's four derivations, the stream index reserver's INTERFACE, the sender and
// receiver ratchets with the skipped key window, spec A section 6's GroupEngine and GroupHandle
// with the connect/mls adapter that satisfies them, the GroupSession every method of section 5.2
// hangs off, and SealRecord and OpenRecord.
//
// The stream index reserver has no implementation here and that is deliberate. Spec A section 8.2
// assigns the durable store to sdk's MessageStore, method for method; neither half of the record
// layer imports an I/O package, and imports_test.go holds that as a gate rather than as this
// sentence. streamindex.go's own header carries the argument and the five conditions an
// implementation owes, so a reader who finds no implementation finds the reason instead of writing
// one.
//
// WHAT IS ABSENT MATTERS MORE THAN WHAT IS PRESENT, and the honest inventory is this. This package
// can seal and open ONE client's records in memory. TWO ENGINES CAN NOW SHARE ONE GROUP: the
// adapter mints every key package under the device's own signing key, its JoinFromWelcome recovers
// the ref the Welcome addresses to this device, takes it, assembles the join material over copies
// it made and joins -- and enginejoin_test.go is the standing proof, two independent engines at one
// epoch whose exporters agree octet for octet. WHAT THAT IS NOT is the milestone: no record crosses
// between those two engines, because a session refuses an empty pq_secret and there is no delivery
// channel for one; the joiner cannot compute a sender_handle, because an epoch beyond the first
// refuses a handle that was given no group_handle_key; and the Welcome is handed over as a VALUE IN
// ONE PROCESS, which is a named, gated, test-only hand-off rather than a delivery channel. It seals
// only the DURABLE
// retention class, because MASTER section 8.1 and section 5.3 disagree about which record_key seals
// ct_head and open item M1-6 has not ruled -- so the permanent, media and eph classes are refused
// rather than guessed at. It reaches no message server: every task of wave 1 stops at a *Record in
// memory, and the submit path belongs to sdk plans that do not exist. And its stream index reserver
// is an INTERFACE with no durable implementation anywhere, so a run over this package's test fake
// proves the record layer and not the client.
//
// AND THE RECORD LAYER HAS NO SENDER AUTHENTICATION AT ALL, which belongs in this inventory
// because it is the absence a reader is least likely to guess from what is here. Every key a
// record is sealed under is derived from a GROUP wide secret: the class keys expand from the
// storage root every member holds, record_key[0] takes the leaf index as an INPUT rather than as
// a credential, sender_handle is likewise computable by every member for every leaf, and
// RecordHeader carries no signature -- write_auth is a mac under a key spec A hands to the
// server. So any member of a group can write a record attributed to any other leaf and it opens
// cleanly at every other member, and this was reproduced from exported symbols alone rather than
// argued. That may be inherent to spec A rather than a defect in this code, and it is not
// something this package can repair on its own authority; what would repair it is a signature
// over the header, which no section declares. It is recorded here so the absence is in the
// inventory, and a case in seal_test.go holds it so that the day it stops being true this
// paragraph is what fails.
//
// What lands here next is the rest of section 5: pq_secret and the provisional epoch state, the
// device wrap, the epoch fan-out and its snapshot, and the joining member. Nothing in this package
// logs a failure and carries on, and no function here takes a clock -- one that needs the time takes
// an injected nowMs func() int64, so that this package keeps the property connect/mls and
// connect/message have, of having no timing-sensitive test in it at all.
//
// Two gates of other packages judge what lands here, and both had to be told this directory
// exists. mls/crypto_forbidden_test.go's forbiddenScanRoots -- which five further mls gates
// alias rather than restate -- covers this directory, so the hkdf entry-point confinement, the
// .ECDH( confinement and the banned-primitive list all reach it, and mls's own
// TestTheCryptoIsBuiltFromExactlyThesePackages pins the union of the three roots' imports: a
// production import added here fails a test over there, on the commit that adds it.
// message/record_test.go's join gate covers it too, because the retention class and the eph
// bucket are most naturally at hand together in the sealer and the sealer is here.
package messagegroup
