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
// run over. connect/message must never import this package, and connect must never import
// either. connect/layering_test.go holds all of that, because until this package's first call
// into connect/message there is no cycle for the compiler to refuse.
//
// What is here today is the X-Wing hybrid key encapsulation of draft-connolly-cfrg-xwing-kem with
// its four sentinels, and the prefix of spec A section 5 that m1 wave 1 lands: the record aead and
// the algorithm identifier MASTER section 7.1 registers for it, this package's own best effort
// zeroization, the storage root and the three retention class keys, the three handles a record is
// routed by, the record key ladder's four derivations, the stream index reserver's INTERFACE, and
// the sender and receiver ratchets with the skipped key window.
//
// The stream index reserver has no implementation here and that is deliberate. Spec A section 8.2
// assigns the durable store to sdk's MessageStore, method for method; neither half of the record
// layer imports an I/O package, and imports_test.go holds that as a gate rather than as this
// sentence. streamindex.go's own header carries the argument and the five conditions an
// implementation owes, so a reader who finds no implementation finds the reason instead of writing
// one.
//
// What lands here next is the rest of section 5: the group engine and its connect/mls adapter, the
// session, the sealer and its reader, and the epoch fan-out. Nothing in this package logs a failure
// and carries on, and no function here takes a clock -- one that needs the time takes an injected
// nowMs func() int64, so that this package keeps the property connect/mls and connect/message have,
// of having no timing-sensitive test in it at all.
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
