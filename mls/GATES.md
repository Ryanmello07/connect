# The one rule every gate in these three trees is held to, and the query that checks it

What this file is for: `mls`, `message` and `messagegroup` defend most of their properties with
**gates** — a test that derives a class of things and then asserts something over every member. A
gate is only ever as good as its class, and this project has now shipped the same class defect
**five times at five altitudes**, each one green, each one found by a reviewer a round later at full
cost. The rule those five share is written here once, with the query that finds the next one, so a
pass that is about to write or widen a gate has something to run rather than a slogan to agree with.

It is deliberately not another statement of "derive from the property, not the instance". That
sentence is already in this project's standing rules, was already in the brief for four of the five,
and did not catch any of them. What follows is the mechanical form of it.

---

## The property

> **A gate's class has two halves — the MEMBERS it admits and the SCOPE it reads them from — and
> every narrowing of either half must be stated in terms of the property being defended. A narrowing
> is derived from the INSTANCE when its justification names something that exists in the tree today:
> a symbol, a path, a count, or the construction a finding was first seen in.**

And the operational form, which is the part that is checkable:

> **Print the complement. A gate that narrows must name, at run time, every member it removed and
> the predicate it removed them by.**

That is the whole of it. An exclusion nobody prints is an exclusion nobody reads, and the two
failure modes look identical from outside a gate that does not print:

| what the complement prints | verdict |
|---|---|
| `[]` — empty | The narrowing was written for members that **do not exist**. It removes nothing today and will begin removing real ones on the commit that adds the first member of the shape it excludes. Delete it, or turn it into a **fail-closed refusal** (`t.Errorf`/`t.Fatalf`), never a `continue`. |
| exactly the identifier the narrowing's own comment names | Derived from the **instance**. Restate the exclusion from the property; if the restated sentence still needs that identifier, there is no exclusion, only a member you did not want to handle. |
| a set describable without naming any member of the tree | Derived from the **property**. Keep it, and keep printing it. |

The empty row is the one that matters most, because it is the one that reads as harmless. Four of
the five instances below had an empty or a one-name complement at the moment they were written.

---

## The five, and what each narrowed by

1. **A class dispositioned by a COUNT instead of a grep.** The number of members stood in for the
   members. A count cannot have a complement, which is why nothing could be read off it.
2. **A location query built from the NUMBERS a ruling changed** instead of from the **claims** it
   falsified. The scope half: the places to look were derived from an artefact of the ruling.
3. **A sweep for a missing AEAD nonce built from the CONSTRUCTION the defect was found in** (a KEM
   seal) rather than from the property it names (an AEAD key from a bare expand with no nonce beside
   it). It walked past a second instance in the same document.
4. **A gate whose class was a DIRECTORY** rather than "code that produces the record's keyed
   octets". Scope again. Now closed: `crypto_forbidden_test.go`'s `forbiddenScanRoots` derives its
   roots and asserts the derivation, and a fourth cryptographic sibling joins by existing.
5. **`epochSliceAnsweringAccessors`, inside the fix for the fourth.** It derived its class off the
   type and then narrowed it with `if method.Type.NumIn() != 1 { continue }`, argued in its own
   comment from the one argument-taking method that exists: *"a method that takes an argument is not
   an accessor -- InstallWraps is this type's writer."* The property is "an exported method that can
   hand back this value's live octets", and a method that takes an argument can do exactly that.
   **Its complement was EMPTY** — `InstallWraps` answers only an error, so the result reading had
   already removed it and the arity line removed nothing at all. Two planted accessors,
   `PqSecretFor(purpose string) ([]byte, error)` and `WrapAt(index int) ([]byte, error)`, each
   handing back a copy of `pq_secret`, passed the entire suite.

---

## The query

Three forms, because a class is built out of reflection, out of source, or out of prose, and the
reading differs.

### Q1 — reflection-derived classes

Find every class builder, then every narrowing inside one:

```sh
grep -rn 'NumMethod()' --include='*_test.go' mls message messagegroup
grep -rn 'NumIn()\|NumOut()\|HasPrefix(method.Name\|method.Name ==\|\.Kind() ==' \
    --include='*_test.go' mls message messagegroup
```

For each narrowing, make it append the rejected member to a slice and `t.Logf` that slice beside the
class. Then read the printed complement against the table above. Two shapes are always suspect:

- an **arity** test (`NumIn`, `NumOut`) on a class whose property is about RESULTS. Arity is a
  driver problem, not a membership problem: drive an argument-taking member with the zero value of
  each argument and let the reader fail closed, or refuse it out loud — do not `continue`.
- a **name** test (`HasPrefix`, `Name ==`) on a class the compiler can describe by shape.

### Q2 — source-scanned and scope-shaped classes

```sh
grep -rn 'ReadDir\|filepath.Walk\|ScanRoots\|\.\./' --include='*_test.go' mls message messagegroup
```

A gate that reads a set of directories, files or packages must print the ones it did **not** read,
and must derive that set from a property (`forbiddenScanRoots` derives "the cryptographic packages
this one is connected to" and asserts the derivation). A hand-written root list, a file exempted by
base name, and a `go list -f '{{range .Imports}}'` reading that only sees the runner's GOOS are all
the scope half of this defect.

### Q3 — prose classes: plans, findings, rulings

A sweep raised by a finding must be built from the **property the finding names**, never from the
**construction it was found in**. The test is a sentence: write the class with no identifier, no
path and no number in it. If you cannot, you do not have the class yet — you have one member of it.
The same applies to a table claiming to hold "every rule of X": name the derivation that produced
the rows, or the row you forgot is invisible.

---

## Measured at `81b97ca`, running Q1 over the three trees

Every arity- or name-shaped narrowing over a reflected class, and what it removed from the tree as
it stood:

| site | narrowing | complement | verdict |
|---|---|---|---|
| `messagegroup/epoch_test.go` `epochSliceAnsweringAccessors` | `NumIn() != 1` | **empty** | the fifth instance. Closed: the class reads results, an argument-taking member is driven, an unreadable shape is fatal, and the complement is printed. |
| `mls/key_schedule_test.go` `TestEveryAccessorAnsweringAPointerAnswersIntoTheSchedulesOwnStorage` | `NumIn() != 1 \|\| NumOut() != 1` | **empty** | same shape, same property (a method handing back the schedule's own storage). Closed: every pointer among a method's results is a row, an argument-taking member is refused out loud, complement printed. |
| `mls/key_schedule_test.go` `bytesTheScheduleHandsOut`, `bytesTheGroupHandsOut` | `NumIn() != 1` | driven by an argument-row table, or excused in writing and logged | already property-derived. |
| `mls/key_schedule_test.go` `bytesTheStagedCommitHandsOut` | `NumIn() != 1` | fail-closed `t.Fatalf` | already property-derived. |
| `mls/group_context_verified_test.go` | `NumIn() != 1` | fail-closed `t.Errorf` | already property-derived. |
| `mls/key_schedule_test.go` `TestAnErasedScheduleRefusesRatherThanAnsweringFromZeros` | `NumOut() == 0` | the erasers | property-derived: a method answering nothing has no refusal to observe. |
| `mls/proposal_list_test.go` `proposalListViewMethods` | `NumIn() != 1 \|\| NumOut() != 1 \|\| Out(0) != []CachedProposal` | **empty** | **OPEN.** The one name-shaped exclusion it makes (`All`) is proved non-empty, which is the right shape; the arity and out-count narrowing beside it is not, and a view answering `([]CachedProposal, error)` or taking a filter would leave the class silently. |
| `mls/extension_test.go` `capabilityPredicates` | `!strings.HasPrefix(method.Name, "Supports")` | **empty** | **OPEN.** A name-shaped narrowing over a class the shape already describes: no method that takes a registry and answers one bool is named anything else today, so the prefix removes nothing and a predicate named otherwise would be unjudged while the `len(predicates) != 1` fatal still read clean. |

Both OPEN rows are behaviour-preserving to close today, exactly because their complement is empty.
That is the point of measuring it.

---

## One hazard the scope half has here, found while closing the fifth

Several gates in `messagegroup` walk this package's **test** source by bare function name
(`keysource_test.go`'s `TestNothingOnTheReproductionsSideOfTheComparisonComesFromTheModule` is the
one that fires). A name-keyed walk cannot see a receiver, so **a test-only method sharing a name
with a production method makes a selector that used to dangle resolve into somebody else's
closure.** Measured on 2026-09-09: adding a control type with methods named `Epoch` and `Destroyed`
to `epoch_test.go` turned that gate red, reporting its exclusion as "swallowing scope" over an edge
that was a name collision and nothing else. The controls were renamed `ProbeEpoch` and
`ProbeDestroyed`, which cost them nothing -- both classes they prove are decided by results and by
behaviour, neither reads a name -- and the gate returned to its previous reading exactly.

It is recorded here rather than fixed because the fix is in the gate's resolution, not in the
control, and a gate that resolves a method selector as a package-level function is a scope defect of
its own: it will also mis-resolve two production methods of different types that share a name.

---

## Two rules for anything added here

- **Give the complement, not the worry.** An entry that says "this class looks narrow" is worth
  nothing. An entry that says "this narrowing removes these N members today, and here is the
  property that says they are out" can be checked in one command.
- **Close entries by deleting them,** and name in the same commit the gate where the narrowing now
  fails closed. A row that outlives the defect is the file describing a tree that no longer exists.
