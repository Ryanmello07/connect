# Open items this package's source cites and no document rules

What this file is for. `connect/messagegroup` cites open items by number — `M1-4`, `M1-6`, `M1-8`,
`M1-15`, `M1-20`, `S2-3`, `J1-1` — and every one of those numbers is assigned in the spec
repository's `SPEC-LEDGER.md`, which is where rulings are made. **This file is not that register and
does not compete with it.** It exists for the one case that register cannot serve on its own: an
obligation discovered *in this code*, whose mechanism is a design ruling, raised in a commit that
has no write access to the ledger.

An entry here is a **debt with a number so the source can cite it**, and it carries its own
migration: when the ledger assigns a number, the entry is rewritten to cite that number and this
file loses a row. Do not treat "it is written here" as "it has been decided".

Two rules, borrowed from `mls/UNOBSERVED.md` because they are the same two rules:

- **Give the obligation and the reproduction, not the worry.** An entry that says "this looks
  unauthenticated" is worth nothing. An entry that names the property, the test that reproduces the
  gap, and what a ruling would have to choose between can be acted on.
- **Close entries by deleting them.** When the mechanism is ruled and implemented, take the row out
  in the same commit and name the case that holds it.

---

## MG-1 — `GroupEngine.JoinFromWelcome` states an anchoring obligation and nothing performs it

**Status: OPEN. The obligation is stated; the mechanism is a ruling and is not this package's.**

### The property

A Welcome authenticates nobody. It is HPKE-sealed to an init key its recipient **published**, in a
key package that went to the delivery service and to every member of every group that ever added
this device. Anybody at all holding that key package can build a well-formed Welcome addressed to
it: mint a ratchet tree, sign a `GroupInfo` at a leaf of that tree with a signing key drawn for the
purpose, choose a joiner secret, seal it to the published init key.

`mls.JoinFromWelcome` says this from the layer below, at length, under *"WHAT A CALLER MUST
ESTABLISH BEFORE IT CALLS THIS"*. **`GroupEngine.JoinFromWelcome` is the surface an application
calls**, and until this item was filed it stated no obligation of its own — so the sentence that
matters was fifteen lines deep in a package section 2.2 forbids the message server to link and
section 6 exists to keep an app from naming.

### The reproduction

`TestAWelcomeFromAnAttackerJoinsAndTheOnlyThingItGetsWrongIsWhoTheGroupIs` in
`enginejoin_test.go`. An engine that has never met the victim, holding only a key package the victim
published, founds a group, adds the victim and hands over the Welcome. The victim's
`JoinFromWelcome` succeeds. Group id, epoch, member count and the `URmessage/v1/storage` exporter
all agree between attacker and victim, because the group is real — the attacker founded it. The one
thing that is false is the thing no octet on that path carries: that this is the group the user
meant to be in.

### What a ruling has to choose

Nothing below is decided and this package must not decide it.

1. **What the anchor IS.** A member identity the joiner expected (readable today through
   `GroupHandle.MemberAt`); a group id the joiner was told out of band; a signature over the
   invitation by a key the joiner already trusted; or the key-transparency log.
2. **Where the expectation comes from**, which is the half that is not a crypto question: a user
   action, a contact list, a prior group, a server-delivered invitation that is itself anchored.
3. **What a device does when the anchor is absent** — refuse the join, join but refuse to render,
   or join and surface the group as unverified. These are different products, not different
   implementations.
4. **Whose obligation it is**, and this item takes no position: the ruling may put it on `sdk`,
   on the application, or on a new method of section 6.

### Why it is not closed here

An anchoring mechanism chosen in an adapter is a security argument taken by the layer with the
least context to take it — the same argument spec B section 2.2 makes about the message server and
an MLS parser. What this package can do, and has done, is state the obligation at the surface that
owns it and make the absence visible: `GroupEngine`'s header carries it, `doc.go`'s inventory
carries it, and the reproduction above fails the day the behaviour changes.

### What is owed elsewhere

A `SPEC-LEDGER.md` number, assigned by whoever owns that register. This row is the placeholder that
lets `engine.go` cite something rather than nothing, and it is replaced by that number the moment
one exists.
