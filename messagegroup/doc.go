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
// WHAT IS ABSENT MATTERS MORE THAN WHAT IS PRESENT, and the honest inventory is this.
//
// TWO ENGINES SHARE ONE GROUP AND A DURABLE RECORD CROSSES BETWEEN THEM. The adapter mints every
// key package under the device's own signing key, its JoinFromWelcome recovers the ref the Welcome
// addresses to this device, takes it, assembles the join material over copies it made and joins.
// enginejoin_test.go is the standing proof: two independent engines, two stores, two signers, at
// one epoch, whose exporters agree octet for octet -- and over that group the founder seals a
// DURABLE record which the joiner opens, head and body intact, in both directions. Every key on
// that path is derived by a production function of this package or of connect/mls out of the two
// engines' own exporters.
//
// THE PREVIOUS PARAGRAPH USED TO SAY THE OPPOSITE and the correction is recorded rather than
// quietly applied. It denied that any record could pass between the two engines, and gave as the
// reason that a session refuses an empty pq_secret with no delivery channel for one. The premise
// is true and the conclusion does not follow: NewGroupSession needs a VALUE, not a channel. A
// sentence that understates what the code does is as wrong as one that overstates it, and it is
// the more expensive kind -- it makes the next planner budget for work that is finished.
//
// The old wording is DESCRIBED here and not quoted, which is a smaller point than it looks:
// TestTheInventoryDoesNotDenyWhatThisPackageProves reads this file for the denial, and a file that
// quoted its own retracted sentence would be a file that fails its own gate forever or teaches the
// gate to ignore quotation marks. Neither is worth a verbatim.
//
// WHAT IS GENUINELY HAND-CARRIED, three values and each named with what would replace it. pq_secret,
// whose value the test draws with NewPqSecret and hands to both sides: it is a KEY on the seal and
// open path -- the ikm of every storage_root this session extracts -- it is the one such value with
// NO PRODUCTION DRIVER anywhere in this package, and its delivery channel is m1 task 14, gated on
// ledger item 152. group_handle_key, which a PRODUCTION function computes at epoch zero and which
// no channel carries to a joiner: open item M1-2. And the Welcome itself, handed over as a VALUE IN
// ONE PROCESS, which is ledger 44a's named, gated, test-only hand-off. Three hand-offs and no
// test-only key SOURCE: nothing on this path mints a key some way the product would not.
//
// NEITHER SIDE KEEPS A SESSION ACROSS AN ADD, and this is stated symmetrically because it was
// stated one-sidedly. The FOUNDER's own handle moves to epoch 1 the moment MergePendingCommit
// returns and a session built over it with no epoch zero group_handle_key hits
// ErrEpochZeroHandleKeyMissing exactly as the joiner does, in the same line of installEpochOnLoop.
// The asymmetry that IS real is narrower: the founder held that key at epoch zero and can hand it
// back, and the joiner never held it. The refusal is correct -- a group_handle_key recomputed from
// the current root would change every sender_handle at every commit -- and what is missing is the
// carrier, which is M1-2.
//
// AND THE WELCOME ANCHORS NOTHING, which belongs in this inventory because it is an absence a
// reader will assume away. A Welcome is HPKE-sealed to an init key its recipient PUBLISHED, so
// anybody holding a key package this device published can found a group, add this device and have
// it join -- reproduced from exported symbols alone, with group id, epoch, member count and
// exporter all agreeing, because the group is real and the attacker founded it. connect/mls says
// this from one layer down; GroupEngine's header now says what it leaves the CALLER of section 6
// owing, and open item MG-1 in this directory's OPENITEMS.md files the mechanism. This package
// must not invent one: which identity a joiner should expect is a design ruling.
//
// IT SEALS ONLY THE DURABLE retention class, because MASTER section 8.1 and section 5.3 disagree
// about which record_key seals ct_head and open item M1-6 has not ruled -- so the permanent, media
// and eph classes are refused rather than guessed at. It reaches no message server: every task of
// wave 1 stops at a *Record in memory, and the submit path belongs to sdk plans that do not exist.
// And its stream index reserver is an INTERFACE with no durable implementation anywhere, so a run
// over this package's test fake proves the record layer and not the client.
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
// What lands here next is the rest of section 5: the DELIVERY of pq_secret rather than the sampler,
// which is here, the device wrap, and the epoch fan-out and its snapshot. The joining member was on
// this list and is not any more. Nothing in this package logs a failure and carries on, and no
// function here takes a clock -- one that needs the time takes an injected nowMs func() int64, so
// that this package keeps the property connect/mls and connect/message have, of having no
// timing-sensitive test in it at all.
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
