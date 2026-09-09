# The one rule every gate in these three trees is held to, and the query that checks it

What this file is for: `mls`, `message` and `messagegroup` defend most of their properties with
**gates** — a test that derives a class of things and then asserts something over every member. A
gate is only ever as good as its class, and this project has now shipped the same class defect
**six times at six altitudes**, each one green, each one found by a reviewer a round later at full
cost.

The sixth was this file. It is worth stating plainly, because it is the reason the file no longer
looks the way it did:

> The artifact written to stop the fifth instance contained the defect. Its table opened
> *"Every arity- or name-shaped narrowing over a reflected class"* and held **eight of the
> fifty-four that exist**. Its published query — offered as *the query that finds the next one* —
> grepped the literal symbol `method.Name`, so every narrowing whose receiver was spelled
> `writer`, `reported`, `of` or `verify` was invisible to it. A universal claim written by hand is
> a list wearing a quantifier, and a query keyed to a symbol is derived from the instance.

So the table below is no longer written. It is **derived**, from the parse tree, by
`gates_index_test.go`, and the two are required to be the same set in both directions. The query
below is no longer trusted. It is **run**, and its recall against that derivation is measured on
every test run and published here as a fraction this file is held to.

---

## The property

> **A gate's class has two halves — the MEMBERS it admits and the SCOPE it reads them from — and
> every narrowing of either half must be stated in terms of the property being defended. A narrowing
> is derived from the INSTANCE when its justification names something that exists in the tree today:
> a symbol, a path, a count, or the construction a finding was first seen in.**

And the operational form, which is the part that is checkable:

> **Print the complement. A gate that narrows must name, at run time, every member it removed and
> the predicate it removed them by.**

An exclusion nobody prints is an exclusion nobody reads, and the two failure modes look identical
from outside a gate that does not print:

| what the complement prints | verdict |
|---|---|
| `[]` — empty | The narrowing was written for members that **do not exist**. It removes nothing today and will begin removing real ones on the commit that adds the first member of the shape it excludes. Delete it, or turn it into a **fail-closed refusal** (`t.Errorf`/`t.Fatalf`), never a `continue`. |
| exactly the identifier the narrowing's own comment names | Derived from the **instance**. Restate the exclusion from the property; if the restated sentence still needs that identifier, there is no exclusion, only a member you did not want to handle. |
| a set describable without naming any member of the tree | Derived from the **property**. Keep it, and keep printing it. |

The empty row is the one that matters most, because it is the one that reads as harmless. Four of
the first five instances had an empty or a one-name complement at the moment they were written, and
so did **both** of the rows this table carried as OPEN for a round.

**And the same reading applies to a QUERY and to a TABLE.** A query whose complement — the sites it
does not reach — is unprinted is the same defect as a gate whose complement is unprinted, and a
table claiming a class with no derivation behind it is a gate whose class is a list. That sentence
is the sixth instance, and the tests named at the bottom of this file are it, closed.

---

## The six, and what each narrowed by

1. **A class dispositioned by a COUNT instead of a grep.** The number of members stood in for the
   members. A count cannot have a complement, which is why nothing could be read off it.
2. **A location query built from the NUMBERS a ruling changed** instead of from the **claims** it
   falsified. The scope half: the places to look were derived from an artefact of the ruling.
3. **A sweep for a missing AEAD nonce built from the CONSTRUCTION the defect was found in** (a KEM
   seal) rather than from the property it names (an AEAD key from a bare expand with no nonce beside
   it). It walked past a second instance in the same document.
4. **A gate whose class was a DIRECTORY** rather than "code that produces the record's keyed
   octets". Scope again. Closed: `crypto_forbidden_test.go`'s `forbiddenScanRoots` derives its
   roots from the module's own import graph and asserts the derivation, and a fourth cryptographic
   sibling joins by existing.
5. **`epochSliceAnsweringAccessors`, inside the fix for the fourth.** It derived its class off the
   type and then narrowed it with `if method.Type.NumIn() != 1 { continue }`, argued in its own
   comment from the one argument-taking method that exists: *"a method that takes an argument is not
   an accessor -- InstallWraps is this type's writer."* The property is "an exported method that can
   hand back this value's live octets", and a method that takes an argument can do exactly that.
   **Its complement was EMPTY** — `InstallWraps` answers only an error, so the result reading had
   already removed it and the arity line removed nothing at all. Two planted accessors,
   `PqSecretFor(purpose string) ([]byte, error)` and `WrapAt(index int) ([]byte, error)`, each
   handing back a copy of `pq_secret`, passed the entire suite.
6. **This file, inside the fix for the fifth.** Its table was a hand-written list under a universal
   quantifier, and its published query was keyed to one spelling of the receiver. Three narrowings
   over reflected method sets — `mlsEncodingEmitters`, `TestNoVectorRunnerCanSkip` and
   `trRecordLayerCodecMethods` — were invisible to both, and the first of them removed **four**
   methods of `*syntax.Writer` (`Bytes`, `Err`, `Len`, `MaxVectorLength`) without naming one of
   them. Measured over the whole class rather than over those three, the table understated itself
   by **forty-six rows of fifty-four**, and the published query reaches **33 of the 55** narrowing
   occurrences those rows cover.

---

## The query

Three forms, because a class is built out of reflection, out of source, or out of prose, and the
reading differs.

### Q1 — reflection-derived classes

**Q1 is a test, not a grep.** `gates_index_test.go` parses every `_test.go` file under the scan
roots and derives, without naming any symbol of the tree:

> a **condition** that reads either the **NAME** of a member drawn from a reflected method set, or
> the **arity or signature shape** of that member.

The receiver can be spelled anything at all; a member reached through `Method(i)`, through
`MethodByName(n)`, through a `[]reflect.Method` a helper was handed, or through a `reflect.Value`
whose signature comes back from `Type()`, all reach the same reading. That is the half a grep
cannot do, and it is why the eight-row table was wrong for a round.

The greps below are the **first cut**, kept because a reader wants something to run:

<!-- gates-query:begin -->
```sh
grep -rnE '\.NumMethod\(\)|\.MethodByName\(|\[\]reflect\.Method' --include=*_test.go mls message messagegroup
grep -rnE '(if|for|case) .*\.Name|\.Type\.(In|Out|Kind|NumIn|NumOut|IsVariadic)\(|\.Type\(\)\.(In|Out|NumIn|NumOut)\(|\.(NumIn|NumOut)\(\)|\.(In|Out)\([0-9a-zA-Z_]+\) *(==|!=)' --include=*_test.go mls message messagegroup
```
<!-- gates-query:end -->

Their recall against the derivation is measured on every run and stated here, and the sites they do
not reach are named in the test log:

**gates-recall: 54/55**

**That fraction is a MEASUREMENT and not a claim.** These patterns were fitted against the tree as
it stands, which is instance-derived by construction — which is exactly why the number is published
rather than the completeness. When a narrowing appears that they do not reach, this fraction goes
wrong and `TestTheQueryGatesPublishesIsMeasuredAgainstTheDerivationRatherThanTrusted` turns red.
**The correct response is to update the fraction, not to chase the pattern.** The derivation is the
query; the greps are a convenience whose honesty is enforced.

It is **not** 54/54, and that is the mechanism working rather than a defect: the one site these
patterns miss is `type_reach_test.go`'s `reflectTypeReachesThrough`, which hands `found.Method(at).Type`
straight to a function and so carries none of the spellings a grep can key on. The test names it in
the log on every run. That is what printing a query's complement looks like.

For each narrowing, make it append the rejected member to a slice and `t.Logf` that slice beside the
class. Then read the printed complement against the table above. Two shapes are always suspect:

- an **arity** test (`NumIn`, `NumOut`) on a class whose property is about RESULTS. Arity is a
  driver problem, not a membership problem: drive an argument-taking member with the zero value of
  each argument and let the reader fail closed, or refuse it out loud — do not `continue`.
- a **name** test (`HasPrefix`, `Name ==`) on a class the compiler can describe by shape.

### Q2 — source-scanned and scope-shaped classes

```sh
grep -rnE 'ReadDir|filepath\.Walk|ScanRoots|\.\./' --include=*_test.go mls message messagegroup
```

A gate that reads a set of directories, files or packages must print the ones it did **not** read,
and must derive that set from a property (`forbiddenScanRoots` derives "the cryptographic packages
this one is connected to" and asserts the derivation). A hand-written root list, a file exempted by
base name, and a `go list -f '{{range .Imports}}'` reading that only sees the runner's GOOS are all
the scope half of this defect. Q1's own scope half is `forbiddenScanRoots`, **aliased and not
restated**, so a fourth package joins this file's index on the commit that joins that gate's roots.

### Q3 — prose classes: plans, findings, rulings

A sweep raised by a finding must be built from the **property the finding names**, never from the
**construction it was found in**. The test is a sentence: write the class with no identifier, no
path and no number in it. If you cannot, you do not have the class yet — you have one member of it.
The same applies to a table claiming to hold "every rule of X": name the derivation that produced
the rows, or the row you forgot is invisible. **That last sentence was in this file while its own
table was a list of eight**, which is the whole argument for deciding a claim like it in a test
rather than agreeing with it in prose.

---

## The index

Every narrowing over a reflected method set in these three trees. It is not written — it is
**derived**, and `TestTheGatesTableIsTheDerivedClassAndNotAListOfIt` holds the two equal in both
directions: a site in the tree and not here fails, and a row here whose narrowing no longer exists
fails too.

The key is the **file, the function and the rendered condition** — never the line number, because a
document keyed to line numbers rots on the first edit above it, and a gate that goes red for a
reason nobody caused is a gate that gets bypassed. Keyed this way it goes red on exactly one event:
a narrowing changed, which is the event that needs its complement read again.

The derivation is deliberately **over-broad** in one respect, stated here rather than discovered
later: it binds an identifier to a member for the whole of the function it is bound in, not for the
block Go scopes it to. Over-reporting is the safe direction; a site it reports that is not really a
narrowing gets a row saying so.

Each row carries one verdict:

| verdict | what it means |
|---|---|
| `NARROWING/complement` | A name- or arity-shaped test that removes members from the class, and the gate **names every removed member at run time**. |
| `NARROWING/refusal` | A name- or arity-shaped test that removes members and **reports each one** (`t.Errorf`/`t.Fatalf`). Nothing leaves the class silently, so there is no complement to print — the failure is the print. |
| `CLASS/results` | Membership is decided by a reading of the member's own **result or argument TYPES**. That is the property itself rather than a narrowing of it, so there is no separate exclusion predicate to hold a complement. |
| `DRIVER` | Walks a member's own arguments or results, or calls the member. It removes nobody: every member still reaches every rule. |
| `NOT-A-MEMBER` | The derivation over-reports here, and the row says why. No row uses this today; it is in the vocabulary because the over-broad reading above guarantees one eventually will. |
| `OPEN` | Unmeasured. **This verdict is RED.** Recording a narrowing as open is not closing it: the two rows this table carried as OPEN at `81b97ca` were still open when the next reviewer arrived. |

<!-- gates-index:begin -->
| site | shape | narrowing | reading |
|---|---|---|---|
| `messagegroup/epoch_test.go` `epochIsTheDestroyedFlag` | shape | `method.Type.NumIn() != 1 \|\| method.Type.NumOut() != 1 \|\| method.Type.Out(0).Kind() != reflect.Bool` | NARROWING/refusal — a member this shape does not recognise is DENIED the destroyed-flag exemption and stays under every octet rule, so failing it widens what holds rather than narrowing it. |
| `messagegroup/epoch_test.go` `epochIsTheDestroyedFlag` | name | `one.MethodByName(method.Name).Call(nil)[0].Bool()` | DRIVER — calls the member being classified, over the live set. |
| `messagegroup/epoch_test.go` `epochIsTheDestroyedFlag` | name | `!one.MethodByName(method.Name).Call(nil)[0].Bool()` | DRIVER — the same call over the destroyed set. |
| `messagegroup/epoch_test.go` `epochOctetAnsweringMethodsIn` | shape | `i < method.Type.NumOut()` | DRIVER — walks the member's own results. |
| `messagegroup/epoch_test.go` `epochOctetAnsweringMethodsIn` | shape | `method.Type.Out(i) == errorType` | DRIVER — skips one RESULT, the error, and never a member. |
| `messagegroup/epoch_test.go` `epochOctetAnsweringMethodsIn` | shape | `epochTypeCarriesOctets(method.Type.Out(i), map[reflect.Type]bool{})` | CLASS/results — membership is "some result of this member can carry an octet"; `epochSliceAnsweringAccessors` prints what it removed. The fifth instance, closed. |
| `messagegroup/epoch_test.go` `TestEveryAccessorOfAProvisionalEpochRefusesOnceItHasBeenDestroyed` | shape | `j < bound.Type().NumIn()` | DRIVER — walks the member's own arguments to build the zero row it is driven with. |
| `mls/caller_arrays_test.go` `groupAnswerDeclaresStorage` | shape | `len(byteStoragePathsOf(method.Type.Out(at), name)) != 0` | DRIVER — walks the member's own results. |
| `mls/commit_vector_join_test.go` `TestEveryExportedMethodOfAProposalCacheRefusesANilCacheRatherThanPanicking` | shape | `at < method.Type.NumIn()` | DRIVER — walks the member's own arguments. |
| `mls/commit_vector_join_test.go` `TestEveryExportedMethodOfAProposalCacheRefusesANilCacheRatherThanPanicking` | shape | `method.Type.Out(at).Kind()` | DRIVER — reads one result's kind to decide how to read it back. |
| `mls/commit_vector_join_test.go` `TestEveryExportedMethodOfAProposalCacheRefusesANilCacheRatherThanPanicking` | shape | `method.Type.Out(at) != reflect.TypeFor[error]()` | DRIVER — finds the error among the member's results. |
| `mls/epoch_advance_test.go` `TestEveryWriterOfTheProposalCacheBindingIsClassifiedHere` | shape | `at < method.Type.NumIn()` | DRIVER — walks the member's own arguments. |
| `mls/epoch_advance_test.go` `TestEveryWriterOfTheProposalCacheBindingIsClassifiedHere` | shape | `reflectTypeReaches(method.Type.In(at), []reflect.Type{reflect.TypeOf(&VerifiedGroupContext{})})` | CLASS/results — membership is what the member's argument types reach. |
| `mls/epoch_advance_test.go` `TestEveryWriterOfTheProposalCacheBindingIsClassifiedHere` | shape | `reflectTypeReaches(method.Type.In(at), reachGroupContextTargets)` | CLASS/results — the same reading against the derived target set. |
| `mls/extension_test.go` `capabilityPredicates` | shape | `method.Type.NumIn() != 2 \|\| method.Type.In(1) != registry` | NARROWING/complement — CLOSED this round. The `!strings.HasPrefix(method.Name, "Supports")` that used to open this loop is gone: measured, its complement was EMPTY, because MarshalMLS, UnmarshalMLS and Supports are all removed by these two shape clauses already. The removed members are now printed with their signatures. |
| `mls/extension_test.go` `capabilityPredicates` | shape | `method.Type.NumOut() != 1 \|\| method.Type.Out(0).Kind() != reflect.Bool` | NARROWING/complement — the other half of the same shape; complement printed. |
| `mls/extension_test.go` `capabilityPredicates` | name | `selected[method.Name]` | DRIVER — the complement printer itself, walking the method set to name what no field paired with. |
| `mls/external_provenance_test.go` `TestNoKeyScheduleAnswersAVerifiedGroupContext` | shape | `method.Type.Out(at) != verified` | DRIVER — walks results looking for the forbidden one; every member is looked at. |
| `mls/external_provenance_test.go` `TestTheOnlyExportedDoorOntoAVerifiedGroupContextIsAVerifiedGroupInfo` | shape | `door.Type.In(at) == tree` | DRIVER — walks one named door's own arguments. |
| `mls/group_context_verified_test.go` `TestNoMethodOfAVerifiedGroupContextHandsOutTheStorageItVouchesFor` | shape | `reflectTypeReaches(method.Type.Out(at), reachGroupContextTargets)` | DRIVER — walks the member's own results. |
| `mls/group_context_verified_test.go` `TestNoMethodOfAVerifiedGroupContextHandsOutTheStorageItVouchesFor` | shape | `method.Type.NumIn() != 1` | NARROWING/refusal — an argument-taking member is reported with `t.Errorf`, not skipped. |
| `mls/key_package_test.go` `mlsEncodingEmitters` | name | `strings.HasPrefix(method.Name, "Write")` | NARROWING/complement — CLOSED this round, and the first of the three the receiver-keyed query missed. Its complement is NOT empty: `Bytes`, `Err`, `Len` and `MaxVectorLength`, four members removed in silence for a round. They are now printed, and the sentence that puts them out — "they take nothing and answer the writer's accumulated state" — is read off the type as a SHAPE and required to name the same set. |
| `mls/key_package_test.go` `mlsEncodingEmitters` | shape | `method.Type.NumIn() > 1` | DRIVER — the independent shape reading that proves the row above's complement; it decides no membership on its own. |
| `mls/key_schedule_kat_test.go` `TestNoVectorRunnerCanSkip` | name | `strings.HasPrefix(name, "Skip")` | NARROWING/complement — the second site the receiver-keyed query missed. The name IS the property here: `*testing.T` offers no shape that tells `Skip` from `Log`, and the reading is anchored in both directions (`Skip`, `Skipf`, `SkipNow` must be in; `Fatal`, `Fatalf` must be out). The members it removes are now printed. |
| `mls/key_schedule_test.go` `bytesTheScheduleHandsOut` | shape | `method.Type.NumIn() == 1 && method.Type.NumOut() == 0` | NARROWING/complement — an eraser answers nothing and so hands nothing out; the removed members are printed as `notCalled`. |
| `mls/key_schedule_test.go` `bytesTheScheduleHandsOut` | shape | `method.Type.NumIn() != 1` | DRIVER — chooses the argument rows; an argument-taking member with no rows and no written excuse is fatal. |
| `mls/key_schedule_test.go` `bytesTheScheduleHandsOut` | shape | `len(row)+1 != method.Type.NumIn()` | DRIVER — checks a row's width against the member's arity before calling, so a mismatch names the method rather than panicking inside reflect. |
| `mls/key_schedule_test.go` `bytesTheScheduleHandsOut` | shape | `!value.Type().AssignableTo(want)` | DRIVER — checks one argument-row value against the member's declared argument type; it removes no member. Found only after the shape reading below stopped being a list of seven names. |
| `mls/key_schedule_test.go` `bytesTheGroupHandsOut` | shape | `method.Type.NumIn() == 1 && answersOnlyErrors(method.Type)` | NARROWING/complement — the removed members are now printed as well as counted; the non-empty check said the exclusion fired but never said what it removed. |
| `mls/key_schedule_test.go` `bytesTheGroupHandsOut` | shape | `method.Type.NumIn() != 1` | DRIVER — chooses the argument rows. |
| `mls/key_schedule_test.go` `bytesTheGroupHandsOut` | shape | `len(row)+1 != method.Type.NumIn()` | DRIVER — row width against the member's arity. |
| `mls/key_schedule_test.go` `bytesTheGroupHandsOut` | shape | `!value.Type().AssignableTo(want)` | DRIVER — the same check over *Group's rows. |
| `mls/key_schedule_test.go` `TestNoExportedMethodOfThisPackageCanReachTheEpochSecret` | shape | `!driven && method.Type.NumIn() != 1` | NARROWING/refusal — an exemption resting on a sweep that drives nothing is reported. |
| `mls/key_schedule_test.go` `bytesTheScheduleKeeps` | shape | `answer.result >= method.Type.NumOut()` | NARROWING/refusal — an excuse for a result position the method does not have is reported, because an excuse that can never fire leaves the table looking complete. |
| `mls/key_schedule_test.go` `TestEveryAccessorAnsweringAPointerAnswersIntoTheSchedulesOwnStorage` | shape | `method.Type.Out(at).Kind() == reflect.Pointer` | DRIVER — walks the member's own results collecting the pointer positions; every result is a row. |
| `mls/key_schedule_test.go` `TestEveryAccessorAnsweringAPointerAnswersIntoTheSchedulesOwnStorage` | shape | `method.Type.NumIn() != 1` | NARROWING/refusal — an argument-taking member is refused out loud rather than skipped. Closed with the fifth instance. |
| `mls/key_schedule_test.go` `scheduleMethodResults` | shape | `method.Type.NumIn() != 1` | DRIVER — chooses the argument rows; undriven is fatal. |
| `mls/key_schedule_test.go` `tagVerifierPairs` | shape | `verify.Type.NumOut() != 1 \|\| verify.Type.Out(0).Kind() != reflect.Bool` | CLASS/results — the class is "answers exactly one bool", read off the results; the members that do are logged beside the pairs. |
| `mls/key_schedule_test.go` `tagVerifierPairs` | name | `!strings.HasPrefix(verify.Name, "Verify")` | NARROWING/refusal — a bool-answering method not named `Verify<something>` is reported, not skipped, so guardrail 7 cannot be left by a rename. |
| `mls/key_schedule_test.go` `tagVerifierPairs` | shape | `verify.Type.NumIn() != 3 \|\| verify.Type.In(1) != byteSlice \|\| verify.Type.In(2) != byteSlice` | NARROWING/refusal — reported. |
| `mls/key_schedule_test.go` `tagVerifierPairs` | shape | `compute.Type.NumIn() != 2 \|\| compute.Type.In(1) != byteSlice \|\| compute.Type.NumOut() != 1 \|\| compute.Type.Out(0) != byteSlice` | NARROWING/refusal — reported. |
| `mls/key_schedule_test.go` `TestAnErasedScheduleRefusesRatherThanAnsweringFromZeros` | shape | `method.Type.NumOut() == 0` | NARROWING/complement — the erasers, which answer nothing over a live epoch and so have no refusal to observe. They are now named at run time; the gate previously counted only the class it kept. |
| `mls/key_schedule_test.go` `bytesTheStagedCommitHandsOut` | shape | `method.Type.NumIn() != 1` | NARROWING/refusal — fatal, so an accessor cannot fall outside G6 by growing a parameter. |
| `mls/proposal_list_test.go` `proposalListViewMethods` | shape | `at < signature.NumOut()` | DRIVER — walks the member's own results. |
| `mls/proposal_list_test.go` `proposalListViewMethods` | shape | `signature.Out(at) == entries` | CLASS/results — CLOSED this round. Membership is "some result of this member is a `[]CachedProposal`", in any position and whatever sits beside it. The `NumIn() != 1 \|\| NumOut() != 1` that used to open it had an EMPTY complement — every non-view is removed by this type test — and would have silently dropped a view answering `([]CachedProposal, error)` or taking a filter. |
| `mls/proposal_list_test.go` `proposalListViewMethods` | name | `method.Name == commitOrder` | NARROWING/complement — one member, `All`, removed by name because it answers the commit order rather than a view of it. Proved non-empty by a fatal if the type stops declaring it, and now named in the printed complement. |
| `mls/proposal_list_test.go` `proposalListViewAnswer` | shape | `at < bound.Type().NumIn()` | DRIVER — walks the member's own arguments to build the zero row. An argument-taking view is DRIVEN here rather than dropped, which is what closing the row above required. |
| `mls/secret_tree_test.go` `TestEveryExportedSecretTreeMethodRefusesAfterZeroize` | shape | `at < method.Type.NumIn()` | DRIVER — walks the member's own arguments. |
| `mls/secret_tree_test.go` `stMethodsAnsweringBytes` | shape | `result < method.Type.NumOut()` | DRIVER — walks the member's own results. |
| `mls/secret_tree_test.go` `stMethodsAnsweringBytes` | shape | `method.Type.Out(result) == byteSlice` | CLASS/results — membership is "some result of this member is a byte slice". |
| `mls/transcript_test.go` `trRecordLayerCodecMethods` | name | `strings.HasSuffix(name, "LP")` | NARROWING/complement — the third site the receiver-keyed query missed. The suffix is the naming rule `encode.go` states (LP is the master design's notation for a fixed 32-bit big-endian length), and the twenty-odd methods it removes are now named rather than counted. |
| `mls/treekem_test.go` `fallibleProviderMethods` | shape | `at < method.Type.NumOut()` | DRIVER — walks the member's own results. |
| `mls/treekem_test.go` `fallibleProviderMethods` | shape | `method.Type.Out(at) == failure` | CLASS/results — membership is "some result of this member is an error". |
| `mls/type_reach_test.go` `reflectTypeReachesThrough` | shape | `reflectTypeReachesThrough(found.Method(at).Type, targets, entered)` | DRIVER — the reachability walk descends into every member of an interface's method set and removes none. This row exists because the derivation stopped enumerating the readings that count as a signature test: `Method(at).Type` handed to a function matches none of the seven names the first draft listed. |
<!-- gates-index:end -->

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

## What holds this file to the tree

Four tests in `mls/gates_index_test.go`, and they are the whole reason this file is worth reading:

- `TestTheGatesTableIsTheDerivedClassAndNotAListOfIt` — the index above equals the derived class in
  both directions, every row carries a verdict from the vocabulary, and an `OPEN` row is red.
- `TestTheQueryGatesPublishesIsMeasuredAgainstTheDerivationRatherThanTrusted` — the greps published
  above are compiled and run, their recall is compared against the fraction this file states, and
  the sites they do not reach are named in the log.
- `TestAQueryKeyedToOneSpellingOfTheReceiverStillMissesTheSitesItMissed` — the query this file
  published at `81b97ca`, kept verbatim, is run against the same derivation. Measured today it
  reaches **33 of the 55** narrowing occurrences and misses 22, in eighteen functions. The claim
  that it was insufficient is a measurement anybody can re-run, and reverting the published query to
  a receiver-keyed one goes red rather than green.

  **One thing that measurement says out loud, because it is the whole argument.** Of the three sites
  the reviewer named, two — `TestNoVectorRunnerCanSkip` and `trRecordLayerCodecMethods` — are still
  missed and are asserted to be. The third, `mlsEncodingEmitters`, is now REACHED, and nothing about
  what that gate decides changed: closing it rewrote its condition from
  `if name := writer.Method(i).Name; strings.HasPrefix(name, "Write")` to
  `if strings.HasPrefix(method.Name, "Write")`, and `HasPrefix(method.Name` is exactly the literal
  the old query greps for. A query whose recall moves by a site because somebody renamed a local
  variable is measuring spelling, not the property. That is why it was replaced by a derivation, and
  why the test asserts the two rather than quietly keeping a third assertion the tree no longer
  supports.
- `TestTheGatesDerivationSeesANarrowingHoweverItsReceiverIsSpelled` — the derivation is driven over
  a control holding one narrowing of each shape it claims to read, with the receiver spelled four
  different ways, and two shapes it must NOT read (a struct field named `name`, a directory entry's
  name). A derivation that reported nothing would agree with a document that indexed nothing.

## Two rules for anything added here

- **Give the complement, not the worry.** An entry that says "this class looks narrow" is worth
  nothing. An entry that says "this narrowing removes these N members today, and here is the
  property that says they are out" can be checked in one command.
- **Close entries by deleting them,** and name in the same commit the gate where the narrowing now
  fails closed. A row that outlives its narrowing is the file describing a tree that no longer
  exists — and that direction is now decided by a test rather than by the reader's diligence.
