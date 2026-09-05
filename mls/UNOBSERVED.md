# Properties this package states and nothing measures

What this file is for: a property that is **correct today and observed by nothing** is a property the
next commit can delete for free. That is not hypothetical here — five rounds running, a disclosure in
this package described behaviour no test held, and each was found by a reviewer rather than by the
suite.

Each entry below is a property somebody has already **measured as unobserved**: the mutation is
written out, and it is a mutation that leaves the whole of `./mls/...` and `./message/...` passing.
An entry is a debt and not a plan. Do not treat "it is written here" as coverage.

Two rules for anything added here.

- **Give the mutation, not the worry.** An entry that says "this looks under-tested" is worth
  nothing. An entry that says "rewrite line X as Y and the suite still passes" can be checked in one
  command, and closed by writing the case that fails under it.
- **Close entries by deleting them.** When a case is written, take the entry out in the same commit
  and name the case where the property is stated. An entry that outlives the gap is the same defect
  this file exists for, pointed at the file itself.

---

## The exhausted end of the sender-ratchet round trip

`SenderRatchets` and `RestoreSenderRatchets` carry a ratchet's position as one count,
`(*ratchet).consumed`, which runs one past the counter so that a ratchet parked on `2^32-1` with
`exhausted` set reports `2^32`. That encoding exists so a restore cannot be handed the pair
`(head 5, exhausted true)`, which describes nothing this type can reach.

**Nothing in either package ever persists or restores an EXHAUSTED ratchet**, so the whole exhausted
arm of the round trip is unobserved. Three separate mutations, each of which restores a member into a
generation it has already sent under, all survive a full `./mls/... ./message/...` run — measured on
2026-09-05 at 7,489 passing, 0 failing, against a baseline of the same:

- `Consumed: r.consumed()` in `SenderRatchets` narrowed to `Consumed: uint64(r.head)`
  (7,488 pass, 0 fail, 1 skip — the skip is the timing case and not this);
- `generationsConsumed`'s `count == 1<<32` arm answering `exhausted = false` (7,489 pass, 0 fail);
- `generationsConsumed`'s `count < 1<<32` widened to `count <= 1<<32` (7,489 pass, 0 fail).

What would close it: a fixture that drives a ratchet to `2^32-1` cannot be built by stepping — it is
four billion derivations — so the case has to reach `(*ratchet)` directly, set `head` and `exhausted`
by hand, and drive `SenderRatchets` → `RestoreSenderRatchets` over that. The property to state is
that a restored exhausted ratchet refuses the next send rather than handing out generation 0 again.

## `RestoreSenderRatchets`' erased guard

`secret_tree.go`'s `RestoreSenderRatchets` opens with `if self.erased { return ErrEpochErased }`.
Deleting it leaves the suite passing — measured on 2026-09-05 over the whole of `./mls/...` and
`./message/...` at 7,489 passing, 0 failing, identical to the baseline. The per-entry
all-zero-octets check below it refuses an erased epoch's own persisted vector, and `ratchetFor`
refuses on the same field further down. The guard is benign redundancy today, and it is the frame
that reports the EPOCH — rather than the entry — as the reason, which is a different sentence for a
caller. Nothing holds it.

## What the catch-up's retention is worth at realistic occupancy

`TestTheCatchUpHoldsThisRatchetsWindowToItsOwnBound` and
`TestOneRatchetsWindowHoldsOneOverItsBoundBetweenAPeekAndTheEraseAfterIt` both run over a tree where
**one ratchet holds everything**. `MaxRetainedWindowKeys` is declared as `RatchetWindowSize` itself,
so with a single occupied ratchet the tree-wide bound and the per-ratchet bound evict down to the
same total and neither case can tell them apart.

What is unmeasured is what the catch-up's retention is worth at a realistic occupancy — several
members each holding a few skipped generations, one of them falling behind — where the two bounds do
come apart and the tree-wide one trims a walk the member that made it has not used yet. How much it
trims is a number nothing here computes. The eviction rule that would decide it (`the fullest window
pays`) is stated in `MaxRetainedWindowKeys`' own comment and exercised only in the degenerate case.

---

## Closed

- **`sealAndRecordLocked`'s own drop of the ciphertext.** All three callers write `return nil, err`
  over whatever it hands them, so rewriting its `return nil, err` as `return private, err` was
  invisible. Closed by `TestSealAndRecordDropsTheCiphertextWhoseGenerationItCouldNotRecord`, which
  calls the function rather than a door: under that rewrite the whole of `./mls/...` and
  `./message/...` comes back 7,488 passing and exactly one failing, and the one is that case.
