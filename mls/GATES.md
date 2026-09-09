# The one rule every gate in these three trees is held to, and the query that checks it

What this file is for: `mls`, `message` and `messagegroup` defend most of their properties with
**gates** — a test that derives a class of things and then asserts something over every member. A
gate is only ever as good as its class, and this project has now shipped the same class defect
**seven times at seven altitudes**, each one green, each one found by a reviewer a round later at
full cost.

The sixth and the seventh were both this file, the seventh inside the fix for the sixth. It is
worth stating plainly, because it is the reason the file no longer looks the way it did:

> The artifact written to stop the fifth instance contained the defect. Its table opened
> *"Every arity- or name-shaped narrowing over a reflected class"* and held **eight of the
> fifty-four that exist**. Its published query — offered as *the query that finds the next one* —
> grepped the literal symbol `method.Name`, so every narrowing whose receiver was spelled
> `writer`, `reported`, `of` or `verify` was invisible to it. A universal claim written by hand is
> a list wearing a quantifier, and a query keyed to a symbol is derived from the instance.
>
> And the fix for that contained the SEVENTH. The derivation it replaced the table with reads a
> **reflected method set**, under the sentence *"the two doors reflect offers onto a method set
> are `Method(i)` and `MethodByName(n)`"* — true of a method set, and the wrong class. Reflect
> opens onto a type's **fields** as well, and a name narrowing over a field set is this file's
> subject exactly as much as a name narrowing over a method set. **Seventy occurrences over
> sixty-eight keys stood one door over**, unindexed and unprinted, and a planted one passed all
> four gates below. Every one of the six findings that raised this file happened to be about a
> method, so the scope reproduced the shape of its instances.

So the table below is no longer written. It is **derived**, from the parse tree, by
`gates_index_test.go`, and the two are required to be the same set in both directions. The query
below is no longer trusted. It is **run**, and its recall against that derivation is measured on
every test run and published here as a fraction this file is held to. And the **doors** that
derivation reads a member through are no longer named either: they are derived from reflect's own
source, by the property that makes something a door, so a door Go adds in a later release joins
this reading on the day the toolchain moves.

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

## The seven, and what each narrowed by

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
7. **This file again, inside the fix for the sixth, and the SCOPE half.** The derivation that
   replaced the table was scoped to a reflected **method** set — two door names, justified by a
   sentence naming the two doors onto a method set. `Field`, `FieldByName`, `FieldByIndex`,
   `FieldByNameFunc` and `VisibleFields` are doors onto the same kind of class, and a name
   narrowing over a field set is the identical defect. The index claimed *"every narrowing over a
   reflected method set"* and the file said nowhere that a field set was outside it; the
   complement was **not empty and not printed**, and `framedContentArmFields` — one member of it
   — removed every field of `FramedContent` that appears in the cleartext header, plus one named
   by hand, without printing one of them. Closed by deriving the doors from reflect's own API
   rather than from the findings: see `gatesDeriveDoors`. The index went from 54 rows to **148**,
   and the published query's recall from **54/55** to **99/158**.

---

## The query

Three forms, because a class is built out of reflection, out of source, or out of prose, and the
reading differs.

### Q1 — reflection-derived classes

**Q1 is a test, not a grep.** `gates_index_test.go` parses every `_test.go` file under the scan
roots and derives, without naming any symbol of the tree:

> a **predicate** that reads either the **NAME** of a member drawn from a reflected **member set**,
> or the **type or signature shape** of that member.

**"MEMBER SET", and the doors onto one are derived rather than named.** A door is any exported
function or interface method of `reflect` that answers a **member descriptor** — a struct reflect
exports that names one member of a type and carries that member's type — plus, in reflect's Value
half, an exported method that answers a `Value` for the same arguments such a door takes. That
sentence names no symbol of this tree and no symbol of reflect; run against Go 1.26 it admits ten
spellings, two of which it over-reports and says so, and the whole set is printed on every run
beside the exported structs the descriptor sentence removed. Naming the two method doors instead
was the seventh instance.

The receiver can be spelled anything at all; a member reached through a door directly, through a
`[]reflect.Method` or a `[]reflect.StructField` a helper was handed, or through a `reflect.Value`
whose signature comes back from `Type()`, all reach the same reading. **And a predicate is a
predicate however it is spelled**: the condition of an `if`, `for`, `switch` or `case`; an
identifier bound to a member reading above the line that decides by it (`drop :=
strings.HasPrefix(member.Name, "Gamma")` then `if drop`); or the result of a function or literal
that answers one `bool`. That is the half a grep cannot do, and it is why the eight-row table was
wrong for a round.

The greps below are the **first cut**, kept because a reader wants something to run:

<!-- gates-query:begin -->
```sh
grep -rnE '\.NumMethod\(\)|\.MethodByName\(|\[\]reflect\.Method|\.NumField\(\)|\.FieldByName\(|\[\]reflect\.StructField' --include=*_test.go mls message messagegroup
grep -rnE '(if|for|case) .*\.Name|\.Type\.(In|Out|Kind|Elem|NumIn|NumOut|IsVariadic)\(|\.Type\(\)\.(In|Out|Elem|Kind|NumIn|NumOut)\(|\.(NumIn|NumOut)\(\)|\.(In|Out)\([0-9a-zA-Z_]+\) *(==|!=)|\.Field\([0-9a-zA-Z_]+\)|\.Kind\(\) *(==|!=)' --include=*_test.go mls message messagegroup
```
<!-- gates-query:end -->

Their recall against the derivation is measured on every run and stated here, and the sites they do
not reach are named in the test log:

**gates-recall: 99/158**

**That fraction is a MEASUREMENT and not a claim.** These patterns were fitted against the tree as
it stands, which is instance-derived by construction — which is exactly why the number is published
rather than the completeness. When a narrowing appears that they do not reach, this fraction goes
wrong and `TestTheQueryGatesPublishesIsMeasuredAgainstTheDerivationRatherThanTrusted` turns red.
**The correct response is to update the fraction, not to chase the pattern.** The derivation is the
query; the greps are a convenience whose honesty is enforced.

It is **not** 158/158, and the gap is wide rather than narrow, which is the mechanism working
rather than a defect. The **59 occurrences these patterns miss sit in 38 functions**, and they miss
them for three reasons a pattern cannot fix: a predicate that hands a member's type straight to a
function (`typeReachesByteStorageThrough(field.Type(), entered)`) carries none of the spellings a
grep can key on; a predicate bound to a name decides on a line that mentions no member at all (`if
!driven`); and a member reached through a helper's parameter is only a member because of a
declaration in another file. Every one of them is named in the test log on every run. That is what
printing a query's complement looks like, and it is also the argument for why the derivation and
not the grep is the query.

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
the scope half of this defect.

**Q1 has TWO scope halves and both are derived, which is the seventh instance stated as a rule.**
The first is the set of files read: `forbiddenScanRoots`, **aliased and not restated**, so a fourth
package joins this file's index on the commit that joins that gate's roots. The second is the set
of **doors** a member is read through, and naming that one was the seventh instance: a derivation
can be perfect over the class it reads and still be scoped to a third of it. When a gate derives a
class, ask what it derives it *through*, and derive that too.

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

Every narrowing over a reflected **member** set in these three trees — through every door reflect
offers onto one, methods and fields alike, and whichever of the three ways a predicate is spelled.
It is not written — it is **derived**, and `TestTheGatesTableIsTheDerivedClassAndNotAListOfIt`
holds the two equal in both directions: a site in the tree and not here fails, and a row here whose
narrowing no longer exists fails too.

The key is the **file, the function and the rendered condition** — never the line number, because a
document keyed to line numbers rots on the first edit above it, and a gate that goes red for a
reason nobody caused is a gate that gets bypassed. Keyed this way it goes red on exactly one event:
a narrowing changed, which is the event that needs its complement read again.

The derivation is deliberately **over-broad** in three respects, stated here and DRIVEN through
the control rather than discovered later: it binds an identifier to a member for the whole of the
function it is bound in, not for the block Go scopes it to; it treats anything reached from a
member's signature as a reading of that signature; and in reflect's Value half it admits two
element readings that take the same arguments a field door takes. Over-reporting is the safe
direction; a site it reports that is not really a narrowing gets a row saying so, and three rows
below say exactly that. **It under-reaches in exactly three places, and all three want the same
thing: a TYPE.** A member reached through a parameter declared `reflect.Value`; a member held in a
struct FIELD whose type is declared in another declaration; and a predicate answering a DEFINED
type whose underlying type is `bool`. Closing any of them needs `go/types` and a full type-check,
which is the one rebuild this file has not had. Those boundaries are not sentences here: each is
driven through the control and asserted NOT found, so none can quietly stop being true.

Each row carries one verdict:

| verdict | what it means |
|---|---|
| `NARROWING/complement` | A name- or arity-shaped test that removes members from the class, and the gate **names every removed member at run time**. |
| `NARROWING/refusal` | A name- or arity-shaped test that removes members and **reports each one** (`t.Errorf`/`t.Fatalf`). Nothing leaves the class silently, so there is no complement to print — the failure is the print. |
| `CLASS/results` | Membership is decided by a reading of the member's own **result, argument or field TYPES**. That is the property itself rather than a narrowing of it, so there is no separate exclusion predicate to hold a complement. (The word was "result or argument" while the class was method-shaped; a field's own type is the same reading one door over.) |
| `DRIVER` | Walks a member's own arguments, results or fields, calls the member, recurses through it, or IS the assertion. It removes nobody: every member still reaches every rule. |
| `NOT-A-MEMBER` | The derivation over-reports here, and the row says why. No row carries this verdict today, and that is not the same as no over-report: the three sites where the derivation over-reports share a (file, function, condition) key with an occurrence that IS a member, so they carry `DRIVER` and say so in the reading. A key whose every occurrence is a non-member would carry this. |
| `OPEN` | Unmeasured. **This verdict is RED.** Recording a narrowing as open is not closing it: the two rows this table carried as OPEN at `81b97ca` were still open when the next reviewer arrived. |

<!-- gates-index:begin -->
| site | shape | narrowing | reading |
|---|---|---|---|
| `message/aad_test.go` `TestBodyBindingIsAStrictProjectionOfTheHeader` | shape | `headerField.Type != field.Type` | DRIVER — the assertion itself. Every field of BodyBinding is looked up on RecordHeader and one whose type differs is reported; it removes no field. |
| `message/attachment_test.go` `attachmentBodyFields` | shape | `declared.Type.Kind() != reflect.Pointer` | CLASS/results — membership is "the arms of a ServerAttachment", read off the field's own type: an arm is a pointer. An empty class is fatal below. |
| `message/attachment_test.go` `attachmentWidthFields` | shape | `field.Type.Kind() != reflect.Slice \|\| field.Type.Elem().Kind() != reflect.Uint8` | CLASS/results — membership is "a field of the attachment body that carries octets", read off the field's own type. That is the property rather than a narrowing of it. |
| `message/codec_agreement_test.go` `lpFieldValue` | name | `field.Name == name` | DRIVER — a lookup of the one field the caller named, over the whole structure. It decides no class. |
| `message/codec_agreement_test.go` `lpFieldValue` | shape | `field.Type.Kind() == reflect.Struct` | DRIVER — the recursion, so a field nested inside a struct is reached rather than dropped. It widens the walk. |
| `message/writeauth_test.go` `writeAuthCoveredNames` | shape | `field.Type == headerType` | DRIVER — decides whether a field contributes its own name or the twelve the header expands to; every field contributes. |
| `messagegroup/epoch_test.go` `TestAProvisionalEpochDeclaresNoFieldAbleToHoldACachedEnvKey` | name | `!slices.Contains(declared, name)` | NARROWING/refusal — the other direction: a row naming a field the type no longer declares is reported. |
| `messagegroup/epoch_test.go` `TestAProvisionalEpochDeclaresNoFieldAbleToHoldACachedEnvKey` | name | `isRowed where isRowed = epochProvisionalFields[name]` | NARROWING/refusal — a field with no row is reported on the else arm; nothing leaves silently. |
| `messagegroup/epoch_test.go` `TestEveryAccessorOfAProvisionalEpochAnswersTheValueItWasBuiltFrom` | name | `!isRowed where isRowed = epochAccessorAnswers[method.Name]` | NARROWING/refusal — an accessor with no row saying which of section 5.12 step 1's values it answers is reported. |
| `messagegroup/epoch_test.go` `TestEveryAccessorOfAProvisionalEpochRefusesOnceItHasBeenDestroyed` | shape | `!answersError where answersError = epochMethodResults(method.Type)` | CLASS/results — membership is "answers an error", read off the member's results. The members it does not admit are exactly the ones TestNoExportedAccessorOfAProvisionalEpochAnswersStateWithoutARefusal reports, so the complement is judged elsewhere rather than dropped. |
| `messagegroup/epoch_test.go` `TestEveryAccessorOfAProvisionalEpochRefusesOnceItHasBeenDestroyed` | shape | `j < bound.Type().NumIn()` | DRIVER — walks the member's own arguments to build the zero row it is driven with. |
| `messagegroup/epoch_test.go` `TestNoExportedAccessorOfAProvisionalEpochAnswersStateWithoutARefusal` | shape | `answersState && !answersError where answersError = epochMethodResults(method.Type) where answersState = epochMethodResults(method.Type)` | NARROWING/refusal — the complement of the row above, and it is reported rather than skipped: a member answering state with no error has no way to refuse once the destructor has run. |
| `messagegroup/epoch_test.go` `epochIsTheDestroyedFlag` | name | `!one.MethodByName(method.Name).Call(nil)[0].Bool()` | DRIVER — the same call over the destroyed set. |
| `messagegroup/epoch_test.go` `epochIsTheDestroyedFlag` | shape | `method.Type.NumIn() != 1 \|\| method.Type.NumOut() != 1 \|\| method.Type.Out(0).Kind() != reflect.Bool` | CLASS/results — RE-READ THIS ROUND, and the row was wrong before it: membership in the destroyed-flag exemption is decided by the member’s own signature, taking nothing and answering one bool, which is the property rather than a narrowing of it. It carried NARROWING/refusal, and it reports nothing at all — it answers false, and a member denied the exemption stays under every octet rule, so failing it widens what holds. `TestEveryRowClaimingAPrintedComplementHasOne` is what found that: the verdict claimed a refusal and the function calls no reporter. |
| `messagegroup/epoch_test.go` `epochIsTheDestroyedFlag` | name | `one.MethodByName(method.Name).Call(nil)[0].Bool()` | DRIVER — calls the member being classified, over the live set. |
| `messagegroup/epoch_test.go` `epochOctetAnsweringMethodsIn` | shape | `epochTypeCarriesOctets(method.Type.Out(i), map[reflect.Type]bool{})` | CLASS/results — membership is "some result of this member can carry an octet"; `epochSliceAnsweringAccessors` prints what it removed. The fifth instance, closed. |
| `messagegroup/epoch_test.go` `epochOctetAnsweringMethodsIn` | shape | `i < method.Type.NumOut()` | DRIVER — walks the member's own results. |
| `messagegroup/epoch_test.go` `epochOctetAnsweringMethodsIn` | shape | `method.Type.Out(i) == errorType` | DRIVER — skips one RESULT, the error, and never a member. |
| `messagegroup/epoch_test.go` `epochTypeCarriesOctets` | shape | `epochTypeCarriesOctets(carrier.Field(i).Type, seen)` | DRIVER — the reachability walk descends into every field and removes none. |
| `messagegroup/ratchet_test.go` `TestNoFieldOfAStreamKeyIsSomethingACallerCanWriteThrough` | shape | `field.Type.Kind()` | NARROWING/refusal — every field's kind is judged and the default arm reports, so a shape nobody wrote a case for fails rather than passing. |
| `messagegroup/seal_test.go` `TestBodyHashIsTheHashOfTheSealedBodyAndIsNotInTheBodyAad` | name | `strings.Contains(strings.ToLower(field.Name), "hash")` | NARROWING/refusal — a name-shaped predicate that REPORTS the members it selects. Nothing is removed from any rule by it. |
| `mls/caller_arrays_test.go` `groupAnswerDeclaresStorage` | shape | `len(byteStoragePathsOf(method.Type.Out(at), name)) != 0` | DRIVER — walks the member's own results. |
| `mls/caller_arrays_test.go` `groupInjectedObjects` | shape | `field.IsExported() && field.Type.Kind() == reflect.Interface` | CLASS/results — membership is "a field a caller supplies an object through", read off the field's own type and its exportedness; an empty class is fatal. |
| `mls/caller_arrays_test.go` `typeReachesByteStorageThrough` | shape | `typeReachesByteStorageThrough(field.Type(), entered)` | DRIVER — the reachability walk into every exported field. |
| `mls/commit_vector_join_test.go` `TestEveryExportedMethodOfAProposalCacheRefusesANilCacheRatherThanPanicking` | shape | `!known where known = arguments[parameter]` | NARROWING/refusal — an argument type this sweep has no value for is fatal, rather than driven with a zero value that a nil receiver would survive for the wrong reason. |
| `mls/commit_vector_join_test.go` `TestEveryExportedMethodOfAProposalCacheRefusesANilCacheRatherThanPanicking` | shape | `at < method.Type.NumIn()` | DRIVER — walks the member's own arguments. |
| `mls/commit_vector_join_test.go` `TestEveryExportedMethodOfAProposalCacheRefusesANilCacheRatherThanPanicking` | shape | `method.Type.Out(at) != reflect.TypeFor[error]()` | DRIVER — finds the error among the member's results. |
| `mls/commit_vector_join_test.go` `TestEveryExportedMethodOfAProposalCacheRefusesANilCacheRatherThanPanicking` | shape | `method.Type.Out(at).Kind()` | DRIVER — reads one result's kind to decide how to read it back. |
| `mls/crypto_labels_test.go` `TestEveryPublishedFieldOfTheKeyScheduleCorpusIsDecodedAndRead` | name | `!slices.Contains(readings, name)` | NARROWING/refusal — a published field nothing reads off a corpus epoch is reported. |
| `mls/crypto_labels_test.go` `theEpochsFieldOf` | shape | `field.Type.Kind() == reflect.Slice && field.Type.Elem() == epoch` | CLASS/results — the field is found by its own type, and a type declaring no such field is fatal. |
| `mls/crypto_test.go` `providerStructByteFields` | shape | `(field.Kind() == reflect.Slice \|\| field.Kind() == reflect.Array) && field.Type().Elem().Kind() == reflect.Uint8` | CLASS/results — membership is "this field carries octets", read off the field's own type. The array arm is in the same case as the slice because reading only the slice made a fixed width field render as no bytes at all. |
| `mls/crypto_test.go` `providerStructByteFields` | shape | `field.Kind() == reflect.Map && field.Type().Elem().Kind() == reflect.Slice && field.Type().Elem().Elem().Kind() == reflect.Uint8` | CLASS/results — the map arm of the same "carries octets" reading. |
| `mls/crypto_test.go` `providerStructByteFields` | shape | `field.Kind() == reflect.Slice && field.Type().Elem().Kind() == reflect.Struct` | DRIVER — descends into every entry of a vector, in order; it removes nobody. |
| `mls/epoch_advance_test.go` `TestEveryWriterOfTheProposalCacheBindingIsClassifiedHere` | shape | `at < method.Type.NumIn()` | DRIVER — walks the member's own arguments. |
| `mls/epoch_advance_test.go` `TestEveryWriterOfTheProposalCacheBindingIsClassifiedHere` | shape | `reflectTypeReaches(method.Type.In(at), []reflect.Type{reflect.TypeOf(&VerifiedGroupContext{})})` | CLASS/results — membership is what the member's argument types reach. |
| `mls/epoch_advance_test.go` `TestEveryWriterOfTheProposalCacheBindingIsClassifiedHere` | shape | `reflectTypeReaches(method.Type.In(at), reachGroupContextTargets)` | CLASS/results — the same reading against the derived target set. |
| `mls/epoch_advance_test.go` `epochCachesHeldBy` | shape | `extensionTypeSelectionNamedAs(field.Type(), cacheType)` | CLASS/results — membership is read off the field's own type. |
| `mls/extension_test.go` `TestSupportsEnforcesEveryEntryOfEveryRequirementVector` | shape | `mandatoryToImplement[carveOutKey(registry, code)]` | DRIVER — `registry` is a string read off a field's element type, and the derivation carries "anything reached from a member's signature" forward — its stated over-report. The condition chooses which of two assertions a dropped code point gets and removes no field. |
| `mls/extension_test.go` `capabilityPredicates` | shape | `method.Type.NumIn() != 2 \|\| method.Type.In(1) != registry` | NARROWING/complement — CLOSED this round. The `!strings.HasPrefix(method.Name, "Supports")` that used to open this loop is gone: measured, its complement was EMPTY, because MarshalMLS, UnmarshalMLS and Supports are all removed by these two shape clauses already. The removed members are now printed with their signatures. |
| `mls/extension_test.go` `capabilityPredicates` | shape | `method.Type.NumOut() != 1 \|\| method.Type.Out(0).Kind() != reflect.Bool` | NARROWING/complement — the other half of the same shape; complement printed. |
| `mls/extension_test.go` `capabilityPredicates` | name | `selected[method.Name]` | DRIVER — the complement printer itself, walking the method set to name what no field paired with. |
| `mls/extension_test.go` `generatedRegistryStructs` | shape | `got != typeName` | NARROWING/refusal — a field whose element type is not the name given is fatal. |
| `mls/extension_test.go` `requiredCapabilityFields` | shape | `capabilities.Field(j).Type == field.Type` | CLASS/results — the pairing is decided by the two members' own types, and a pairing that is not exactly one is fatal. |
| `mls/external_provenance_test.go` `TestNoKeyScheduleAnswersAVerifiedGroupContext` | shape | `method.Type.Out(at) != verified` | DRIVER — walks results looking for the forbidden one; every member is looked at. |
| `mls/external_provenance_test.go` `TestTheOnlyExportedDoorOntoAVerifiedGroupContextIsAVerifiedGroupInfo` | shape | `door.Type.In(at) == tree` | DRIVER — walks one named door's own arguments. |
| `mls/external_provenance_test.go` `externalDoorsOntoAVerifiedGroupContext` | shape | `!isSignature where isSignature = method.Type().(*types.Signature)` | DRIVER — three occurrences share this key. Two read a *types.Object out of a package scope and are not members at all — the derivation binds an identifier for the whole function rather than the block it is scoped to, which is its stated over-report and why the predicate text here is carried from the third. The third guards a type assertion over a go/types method set whose complement is empty by construction, a *types.Func's type being always a signature, so it removes nobody. |
| `mls/external_provenance_test.go` `externalShadowHasThisTypesShape` | name+shape | `mine.Name() != theirs.Name() \|\| mine.Embedded() != theirs.Embedded() \|\| shadowStruct.Tag(at) != realStruct.Tag(at) \|\| !types.Identical(mine.Type(), theirs.Type())` | DRIVER — the assertion itself, walking both structs position by position; a difference is reported and no field is removed. |
| `mls/framing_guard_test.go` `comparesOctets` | shape | `comparesOctets(spelled.Field(index).Type(), seen)` | DRIVER — the walk descends into every field of a struct. |
| `mls/framing_protect_test.go` `TestEveryRegisteredContentTypeEncodesToThePrivateMessageContentLayoutSection631Writes` | name | `name == "ContentType" \|\| slices.Contains(arms, name)` | NARROWING/complement — CLOSED THIS ROUND: the removed set is the derived arm class plus the selector, and it is now printed beside the complement it builds. The arm class is itself asserted equal to the layout table three lines above, and an empty complement is fatal. |
| `mls/framing_protect_test.go` `TestTheSenderDataAadCoversExactlyTheHeaderFieldsItsParameterListNames` | name | `slices.Contains(covered, strings.ToLower(name[:1])+name[1:])` | DRIVER — every field of PrivateMessage is rewritten and observed above; this decides only which side of an equality the field lands on, and the two sides are compared, so a field left out of `want` fails here if it turns out to be covered. |
| `mls/framing_protect_test.go` `framedContentArmFields` | name | `!elsewhere[name]` | NARROWING/complement — CLOSED THIS ROUND, and it is the live member the SEVENTH instance was found by: a name narrowing over a reflected FIELD set, invisible to this file for six rounds because the derivation read method sets only. The removed members are now printed beside the class. One seed is an identifier of the tree — `"Sender"` is put out by hand because section 6.3.2 carries the sender in the ENCRYPTED SENDER DATA rather than in the content, and no type in this package holds that placement as a field the join could read; the rest of the removed set is derived from PrivateMessage's own fields. |
| `mls/framing_protect_test.go` `framingPreimageStructTypes` | shape | `field.Kind() == reflect.Struct` | DRIVER — queues a nested structure so the sweep reaches it; every field is still emitted. |
| `mls/framing_protect_test.go` `perturbFramedContentField` | shape | `field.Type() == reflect.TypeOf(Sender{})` | NARROWING/refusal — the other arm of the same switch. |
| `mls/framing_protect_test.go` `perturbFramedContentField` | shape | `field.Type() == reflect.TypeOf([]byte(nil))` | NARROWING/refusal — one arm of a switch whose default is fatal, so a field shape nobody wrote a move for fails rather than going unmoved. |
| `mls/framing_test.go` `TestTheAuthDataCodecWritesEveryFieldItsContentTypeCarriesAndNoOther` | name | `!carried && changed where carried = slices.Contains(authDataVariantPaths[contentType], name)` | NARROWING/refusal — the other direction of the same assertion. |
| `mls/framing_test.go` `TestTheAuthDataCodecWritesEveryFieldItsContentTypeCarriesAndNoOther` | name | `!observed[name]` | NARROWING/refusal — a field no declared content type's encoding depends on is reported. |
| `mls/framing_test.go` `TestTheAuthDataCodecWritesEveryFieldItsContentTypeCarriesAndNoOther` | name | `carried && !changed where carried = slices.Contains(authDataVariantPaths[contentType], name)` | NARROWING/refusal — an assertion, reported. |
| `mls/framing_test.go` `TestTheSenderCodecWritesEveryFieldItsArmCarriesAndNoOther` | name | `!carried && changed where carried = slices.Contains(senderVariantPaths[senderType], name)` | NARROWING/refusal — the other direction of the same assertion. |
| `mls/framing_test.go` `TestTheSenderCodecWritesEveryFieldItsArmCarriesAndNoOther` | name | `!observed[name]` | NARROWING/refusal — a field no declared sender type's encoding depends on is reported. |
| `mls/framing_test.go` `TestTheSenderCodecWritesEveryFieldItsArmCarriesAndNoOther` | name | `carried && !changed where carried = slices.Contains(senderVariantPaths[senderType], name)` | NARROWING/refusal — an assertion, reported. |
| `mls/framing_test.go` `TestTheSenderCodecWritesEveryFieldItsArmCarriesAndNoOther` | name | `name == senderDiscriminantField` | NARROWING/complement — CLOSED THIS ROUND: the removed member is now printed beside the swept class. It is one member, named by a constant of this file, and the discriminant is covered by the golden assertion at the end of this test rather than by the sweep — which the test states and then checks rather than assuming. |
| `mls/framing_test.go` `TestTheSenderVariantTableCoversTheTypeAndTheRegistry` | name | `claimed[name]` | NARROWING/refusal — every field is judged by how many arms carry it, and both 0 and more than 1 are reported. |
| `mls/framing_test.go` `TestTheSenderVariantTableCoversTheTypeAndTheRegistry` | name | `claimed[name] != 0` | NARROWING/refusal — reported. |
| `mls/framing_test.go` `TestTheSenderVariantTableCoversTheTypeAndTheRegistry` | name | `name == senderDiscriminantField` | NARROWING/refusal — the discriminant is not skipped here: it is asserted to be carried by no arm and then deleted from the table, so the member is judged rather than removed. |
| `mls/framing_test.go` `decodedFormOfAuthData` | name | `slices.Contains(carried, name)` | DRIVER — decides whether a field is zeroed or kept while building the decoded form; every field is written one way or the other. |
| `mls/framing_test.go` `mlsMessageArmFields` | shape | `structure.Field(at).Type.Kind() == reflect.Pointer` | CLASS/results — an arm is a pointer field, read off the type; an empty class is fatal. |
| `mls/group_context_test.go` `TestGroupContextCloneIsDeepAtEveryWritableLocation` | name | `strings.HasPrefix(path, "GroupContext."+name)` | NARROWING/refusal — a field no exercised writable location sits under is reported. |
| `mls/group_context_verified_test.go` `TestEveryConstructionOfAVerifiedGroupContextIsClassifiedHere` | name | `field.Name != verifiedGroupContextFieldName` | NARROWING/refusal — fatal, because the derivation downstream reads that spelling and a rename would empty its class. |
| `mls/group_context_verified_test.go` `TestEveryConstructionOfAVerifiedGroupContextIsClassifiedHere` | shape | `field.Type != reflect.TypeOf((*GroupContext)(nil))` | NARROWING/refusal — fatal: a value there rather than a pointer would make the zero value read as the empty group at epoch 0. |
| `mls/group_context_verified_test.go` `TestNoMethodOfAVerifiedGroupContextHandsOutTheStorageItVouchesFor` | shape | `method.Type.NumIn() != 1` | NARROWING/refusal — an argument-taking member is reported with `t.Errorf`, not skipped. |
| `mls/group_context_verified_test.go` `TestNoMethodOfAVerifiedGroupContextHandsOutTheStorageItVouchesFor` | shape | `reflectTypeReaches(method.Type.Out(at), reachGroupContextTargets)` | DRIVER — walks the member's own results. |
| `mls/group_test.go` `framedContentCarrier` | shape | `structure.Field(i).Type == declared` | CLASS/results — the carrier is found by the field's own type, and a second field of that type answers the empty string, which the reading's own gate refuses. |
| `mls/key_package_test.go` `mlsEncodingEmitters` | shape | `method.Type.NumIn() > 1` | DRIVER — the independent shape reading that proves the row above's complement; it decides no membership on its own. |
| `mls/key_package_test.go` `mlsEncodingEmitters` | name | `strings.HasPrefix(method.Name, "Write")` | NARROWING/complement — CLOSED this round, and the first of the three the receiver-keyed query missed. Its complement is NOT empty: `Bytes`, `Err`, `Len` and `MaxVectorLength`, four members removed in silence for a round. They are now printed, and the sentence that puts them out — "they take nothing and answer the writer's accumulated state" — is read off the type as a SHAPE and required to name the same set. |
| `mls/key_schedule_kat_test.go` `TestNoVectorRunnerCanSkip` | name | `strings.HasPrefix(name, "Skip")` | NARROWING/complement — the second site the receiver-keyed query missed. The name IS the property here: `*testing.T` offers no shape that tells `Skip` from `Log`, and the reading is anchored in both directions (`Skip`, `Skipf`, `SkipNow` must be in; `Fatal`, `Fatalf` must be out). The members it removes are now printed. |
| `mls/key_schedule_roundtrip_test.go` `seedMoveFieldAt` | name | `seedMoveFieldAt(value.Field(index), at+"."+field.Name, want)` | DRIVER — the recursive search over every exported field. |
| `mls/key_schedule_roundtrip_test.go` `seedValuesAgree` | name | `!seedValuesAgree(t, path+"."+field.Name, left.Field(index), right.Field(index))` | DRIVER — the recursive comparison over every exported field. |
| `mls/key_schedule_test.go` `TestAnErasedScheduleRefusesRatherThanAnsweringFromZeros` | shape | `method.Type.NumOut() == 0` | NARROWING/complement — the erasers, which answer nothing over a live epoch and so have no refusal to observe. They are now named at run time; the gate previously counted only the class it kept. |
| `mls/key_schedule_test.go` `TestEveryAccessorAnsweringAPointerAnswersIntoTheSchedulesOwnStorage` | shape | `method.Type.NumIn() != 1` | NARROWING/refusal — an argument-taking member is refused out loud rather than skipped. Closed with the fifth instance. |
| `mls/key_schedule_test.go` `TestEveryAccessorAnsweringAPointerAnswersIntoTheSchedulesOwnStorage` | shape | `method.Type.Out(at).Kind() == reflect.Pointer` | DRIVER — walks the member's own results collecting the pointer positions; every result is a row. |
| `mls/key_schedule_test.go` `TestNoExportedMethodOfThisPackageCanReachTheEpochSecret` | shape | `!driven && method.Type.NumIn() != 1` | NARROWING/refusal — an exemption resting on a sweep that drives nothing is reported. |
| `mls/key_schedule_test.go` `bytesTheGroupHandsOut` | name | `!driven where driven = groupMethodArgumentRows[method.Name]` | NARROWING/refusal — an argument-taking method with no rows is fatal unless an excuse is written down for it. |
| `mls/key_schedule_test.go` `bytesTheGroupHandsOut` | name | `!excused where excused = groupMethodsTakingArguments[method.Name]` | NARROWING/refusal — the excuse itself; without one the method is fatal. |
| `mls/key_schedule_test.go` `bytesTheGroupHandsOut` | shape | `!value.Type().AssignableTo(want)` | DRIVER — the same check over *Group's rows. |
| `mls/key_schedule_test.go` `bytesTheGroupHandsOut` | name | `driven where driven = groupMethodArgumentRows[method.Name]` | NARROWING/refusal — the other direction: rows for a method that takes no arguments are reported. |
| `mls/key_schedule_test.go` `bytesTheGroupHandsOut` | shape | `len(row)+1 != method.Type.NumIn()` | DRIVER — row width against the member's arity. |
| `mls/key_schedule_test.go` `bytesTheGroupHandsOut` | shape | `method.Type.NumIn() != 1` | DRIVER — chooses the argument rows. |
| `mls/key_schedule_test.go` `bytesTheGroupHandsOut` | shape | `method.Type.NumIn() == 1 && answersOnlyErrors(method.Type)` | NARROWING/complement — the removed members are now printed as well as counted; the non-empty check said the exclusion fired but never said what it removed. |
| `mls/key_schedule_test.go` `bytesTheScheduleHandsOut` | name | `!driven where driven = keyScheduleMethodArgumentRows[method.Name]` | NARROWING/refusal — an argument-taking method with no rows is fatal unless an excuse is written down for it. |
| `mls/key_schedule_test.go` `bytesTheScheduleHandsOut` | name | `!excused where excused = keyScheduleMethodsTakingArguments[method.Name]` | NARROWING/refusal — the excuse itself; without one the method is fatal. |
| `mls/key_schedule_test.go` `bytesTheScheduleHandsOut` | shape | `!value.Type().AssignableTo(want)` | DRIVER — checks one argument-row value against the member's declared argument type; it removes no member. Found only after the shape reading below stopped being a list of seven names. |
| `mls/key_schedule_test.go` `bytesTheScheduleHandsOut` | name | `driven where driven = keyScheduleMethodArgumentRows[method.Name]` | NARROWING/refusal — the other direction: rows for a method that takes no arguments are reported. |
| `mls/key_schedule_test.go` `bytesTheScheduleHandsOut` | shape | `len(row)+1 != method.Type.NumIn()` | DRIVER — checks a row's width against the member's arity before calling, so a mismatch names the method rather than panicking inside reflect. |
| `mls/key_schedule_test.go` `bytesTheScheduleHandsOut` | shape | `method.Type.NumIn() != 1` | DRIVER — chooses the argument rows; an argument-taking member with no rows and no written excuse is fatal. |
| `mls/key_schedule_test.go` `bytesTheScheduleHandsOut` | shape | `method.Type.NumIn() == 1 && method.Type.NumOut() == 0` | NARROWING/complement — an eraser answers nothing and so hands nothing out; the removed members are printed as `notCalled`. |
| `mls/key_schedule_test.go` `bytesTheScheduleKeeps` | name | `!read where read = scheduleStorageReaders[name]` | NARROWING/refusal — fatal: a kept []byte field with no reader falls outside every comparison this gate makes. |
| `mls/key_schedule_test.go` `bytesTheScheduleKeeps` | name | `!slices.Contains(fields, name)` | NARROWING/refusal — the other direction: a reader for a field the type does not declare is reported. |
| `mls/key_schedule_test.go` `bytesTheScheduleKeeps` | shape | `answer.result >= method.Type.NumOut()` | NARROWING/refusal — an excuse for a result position the method does not have is reported, because an excuse that can never fire leaves the table looking complete. |
| `mls/key_schedule_test.go` `bytesTheScheduleKeeps` | shape | `valueType.Field(i).Type != byteSlice` | CLASS/results — membership is "a []byte field of the schedule", read off the field's own type; a member of it with no reader is fatal on the next line. |
| `mls/key_schedule_test.go` `bytesTheStagedCommitHandsOut` | shape | `method.Type.NumIn() != 1` | NARROWING/refusal — fatal, so an accessor cannot fall outside G6 by growing a parameter. |
| `mls/key_schedule_test.go` `epochSecretsByField` | shape | `field.Type() != byteSlice` | NARROWING/refusal — fatal: a secret held in anything but a []byte would fall outside every sweep over the derived secrets, so it is reported rather than skipped. |
| `mls/key_schedule_test.go` `mutatedGroupContexts` | shape | `target.Kind() == reflect.Slice && target.Type().Elem() == extensionType` | NARROWING/refusal — the other arm of the same switch. |
| `mls/key_schedule_test.go` `mutatedGroupContexts` | shape | `target.Kind() == reflect.Slice && target.Type().Elem().Kind() == reflect.Uint8` | NARROWING/refusal — one arm of a switch whose default is fatal, so a field this gate cannot move fails rather than going unjudged. |
| `mls/key_schedule_test.go` `scheduleMethodResults` | shape | `method.Type.NumIn() != 1` | DRIVER — chooses the argument rows; undriven is fatal. |
| `mls/key_schedule_test.go` `tagVerifierPairs` | name | `!strings.HasPrefix(verify.Name, "Verify")` | NARROWING/refusal — a bool-answering method not named `Verify<something>` is reported, not skipped, so guardrail 7 cannot be left by a rename. |
| `mls/key_schedule_test.go` `tagVerifierPairs` | shape | `compute.Type.NumIn() != 2 \|\| compute.Type.In(1) != byteSlice \|\| compute.Type.NumOut() != 1 \|\| compute.Type.Out(0) != byteSlice` | NARROWING/refusal — reported. |
| `mls/key_schedule_test.go` `tagVerifierPairs` | shape | `verify.Type.NumIn() != 3 \|\| verify.Type.In(1) != byteSlice \|\| verify.Type.In(2) != byteSlice` | NARROWING/refusal — reported. |
| `mls/key_schedule_test.go` `tagVerifierPairs` | shape | `verify.Type.NumOut() != 1 \|\| verify.Type.Out(0).Kind() != reflect.Bool` | CLASS/results — the class is "answers exactly one bool", read off the results; the members that do are logged beside the pairs. |
| `mls/leaf_node_test.go` `TestLeafNodeValidateEnforcesEveryRequiredCapabilitiesVector` | name | `!written where written = byField[name]` | NARROWING/refusal — a field of RequiredCapabilities with no row is reported. |
| `mls/leaf_node_test.go` `leafNodeFieldPathsOf` | shape | `field.Type.Kind() == reflect.Struct && !leafNodeFieldIsDelegated(field.Type)` | DRIVER — decides whether a field is descended into or emitted as a leaf path; every field yields at least one path. |
| `mls/message_protection_kat_test.go` `theGroupContextParameters` | shape | `isSignature where isSignature = method.Type().(*types.Signature)` | DRIVER — the same shape as externalDoorsOntoAVerifiedGroupContext's row: two occurrences, one over a scope object that is not a member and one over a go/types method set whose complement is empty by construction. The predicate text is carried across blocks by the derivation's stated function-wide binding. |
| `mls/proposal_ceiling_test.go` `TestTheCachesAccountingIsAlwaysAViewOfTheEntriesItHolds` | name | `exempt \|\| compared[name] where exempt = entries[name]` | NARROWING/refusal — a field of the cache that neither table accounts for is reported, and the loop below reports a table key with no field, so both directions are judged. |
| `mls/proposal_ceiling_test.go` `testArmNamesALeaf` | shape | `arm.Field(i).Type() == names` | CLASS/results — "the arm names a leaf" is read off the field's own type. |
| `mls/proposal_ceiling_test.go` `testArmReplacesItsSendersLeaf` | shape | `arm.Field(i).Type() == replaces` | CLASS/results — "the arm replaces its sender's leaf" is read off the field's own type. |
| `mls/proposal_list_derivation_test.go` `TestAProposalListKeepsItsProposalsInExactlyOnePlace` | shape | `held.Type != want` | NARROWING/refusal — reported: anything but a []CachedProposal has lost the commit order. |
| `mls/proposal_list_derivation_test.go` `TestAProposalListKeepsItsProposalsInExactlyOnePlace` | name | `unicode.IsUpper([]rune(held.Name)[0])` | NARROWING/refusal — an exported storage field is reported. |
| `mls/proposal_list_derivation_test.go` `TestEveryPerTypeViewOfAProposalListIsItsCommitOrderFiltered` | name | `!joined where joined = carriedBy[method.Name]` | NARROWING/refusal — a view nothing names the filtered type of is reported. |
| `mls/proposal_list_derivation_test.go` `proposalListStorageFields` | shape | `carries(held.Field(i).Type, entered)` | DRIVER — the reachability walk into every field. |
| `mls/proposal_list_derivation_test.go` `proposalListStorageFields` | shape | `carries(structure.Field(i).Type, map[reflect.Type]bool{})` | CLASS/results — membership is "this field can carry a cached proposal", read off the field's own type. |
| `mls/proposal_list_test.go` `proposalListViewAnswer` | shape | `at < bound.Type().NumIn()` | DRIVER — walks the member's own arguments to build the zero row. An argument-taking view is DRIVEN here rather than dropped, which is what closing the row above required. |
| `mls/proposal_list_test.go` `proposalListViewMethods` | shape | `at < signature.NumOut()` | DRIVER — walks the member's own results. |
| `mls/proposal_list_test.go` `proposalListViewMethods` | name | `method.Name == commitOrder` | NARROWING/complement — one member, `All`, removed by name because it answers the commit order rather than a view of it. Proved non-empty by a fatal if the type stops declaring it, and now named in the printed complement. |
| `mls/proposal_list_test.go` `proposalListViewMethods` | shape | `signature.Out(at) == entries` | CLASS/results — CLOSED this round. Membership is "some result of this member is a `[]CachedProposal`", in any position and whatever sits beside it. The `NumIn() != 1 \|\| NumOut() != 1` that used to open it had an EMPTY complement — every non-view is removed by this type test — and would have silently dropped a view answering `([]CachedProposal, error)` or taking a filter. |
| `mls/proposal_wire_test.go` `proposalArmFields` | shape | `field.Type.Kind()` | CLASS/results — an arm is a pointer or a slice, read off the field's own type. The discriminant falls out by that same reading rather than by name, so a discriminant renamed does not fall in and an eighth arm added does; fewer than two arms is fatal. |
| `mls/proposal_wire_test.go` `proposalOrRefArmFields` | shape | `field.Type.Kind()` | CLASS/results — the same reading over ProposalOrRef. |
| `mls/provider_methods_test.go` `reachesByteSliceType` | shape | `reachesByteSliceType(under.Field(i).Type(), visiting)` | DRIVER — the reachability walk into every field. |
| `mls/psk_test.go` `providerPskInputBytePaths` | shape | `field.Type.Kind() == reflect.Slice && field.Type.Elem().Kind() == reflect.Uint8` | CLASS/results — membership is "a field carrying octets", read off the field's own type. |
| `mls/psk_test.go` `providerPskInputBytePaths` | shape | `field.Type.Kind() == reflect.Struct` | DRIVER — descends into a nested structure so its octet fields join the same class. |
| `mls/secret_tree_test.go` `TestEveryExportedSecretTreeMethodRefusesAfterZeroize` | shape | `at < method.Type.NumIn()` | DRIVER — walks the member's own arguments. |
| `mls/secret_tree_test.go` `TestSecretTreeCachedGeometryIsDerivedFromTheLeafCount` | name | `!onTheType[name]` | NARROWING/refusal — a table naming a field the type does not declare is reported. |
| `mls/secret_tree_test.go` `stMethodsAnsweringBytes` | shape | `method.Type.Out(result) == byteSlice` | CLASS/results — membership is "some result of this member is a byte slice". |
| `mls/secret_tree_test.go` `stMethodsAnsweringBytes` | shape | `result < method.Type.NumOut()` | DRIVER — walks the member's own results. |
| `mls/transcript_test.go` `trRecordLayerCodecMethods` | name | `strings.HasSuffix(name, "LP")` | NARROWING/complement — the third site the receiver-keyed query missed. The suffix is the naming rule `encode.go` states (LP is the master design's notation for a fixed 32-bit big-endian length), and the twenty-odd methods it removes are now named rather than counted. |
| `mls/tree_sync_test.go` `TestEveryFactBothContextsCarryIsReconciled` | shape | `carried[pinned.Field(i).Type]` | CLASS/results — the class is "a group context field whose type the tree context also carries", read off both types. It is logged at run time and an empty class is fatal. |
| `mls/treekem_test.go` `fallibleProviderMethods` | shape | `at < method.Type.NumOut()` | DRIVER — walks the member's own results. |
| `mls/treekem_test.go` `fallibleProviderMethods` | shape | `method.Type.Out(at) == failure` | CLASS/results — membership is "some result of this member is an error". |
| `mls/type_reach_test.go` `TestTheCompiledTypeReachWalkEntersEveryConstructorItClaims` | shape | `reflectTypeReaches(field.Type, targets)` | CLASS/results — membership is what the field's own type reaches, and the answer is compared against the control's declared set in both directions. |
| `mls/type_reach_test.go` `reflectTypeReachesThrough` | shape | `reflectTypeReachesThrough(field.Type, targets, entered)` | DRIVER — the reflect half of the same walk, into every exported field. |
| `mls/type_reach_test.go` `reflectTypeReachesThrough` | shape | `reflectTypeReachesThrough(found.Method(at).Type, targets, entered)` | DRIVER — the reachability walk descends into every member of an interface's method set and removes none. This row exists because the derivation stopped enumerating the readings that count as a signature test: `Method(at).Type` handed to a function matches none of the seven names the first draft listed. |
| `mls/type_reach_test.go` `typeReachesNamedThrough` | shape | `!isSignature where isSignature = shape.Method(at).Type().(*types.Signature)` | DRIVER — a type assertion guard over a go/types method set; a *types.Func's type is always a signature, so its complement is empty by construction and it removes nobody. |
| `mls/type_reach_test.go` `typeReachesNamedThrough` | shape | `typeReachesNamedThrough(field.Type(), name, entered)` | DRIVER — the walk into every exported field. |
| `mls/validate_commit_test.go` `TestTheSectionTwelveTwoInputThisFileBuildsIsThisCommitsOwnFields` | name | `!written where written = expected[name]` | NARROWING/refusal — a field of the section 12.2 input nothing says the provenance of is reported. |
| `mls/validate_commit_test.go` `TestValidateCommitRefusesAListThatIsNotTheCommitsOwnProposalVector` | name | `!driven[name]` | NARROWING/refusal — a field of ProposalOrRef no row makes the list and the vector disagree over is reported. |
| `mls/validate_commit_test.go` `TestValidateCommitRefusesAListThatIsNotTheCommitsOwnProposalVector` | name | `!onTheType[name]` | NARROWING/refusal — the other direction: a row naming a field the type does not carry is reported. |
| `mls/welcome_test.go` `TestTheGroupInfoSignatureCoversEveryFieldOfItsToBeSigned` | name | `name == "Signature"` | NARROWING/complement — CLOSED THIS ROUND: the removed member is now printed beside the class it is removed from. It is one member, named by a literal of this test, and the sentence that puts it out is that a signature does not cover itself. |
| `mls/welcome_test.go` `changeGroupInfoField` | shape | `value.Type().Elem().Kind() == reflect.Uint8` | DRIVER — chooses how to move a value of this kind; the switch's default is fatal, so a kind with no move fails rather than being reported covered. |
| `mls/welcome_test.go` `groupInfoTbsFieldPaths` | shape | `field.Type.Kind() == reflect.Struct` | DRIVER — descends into a nested structure; every field yields a path. |
| `mls/welcome_test.go` `providerGroupInfoPerturbations` | name | `!written where written = edits[name]` | NARROWING/refusal — fatal: a field of GroupInfo no perturbation moves would answer identically under every move this gate makes. |
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

Five tests in `mls/gates_index_test.go`, and they are the whole reason this file is worth reading:

- `TestTheGatesTableIsTheDerivedClassAndNotAListOfIt` — the index above equals the derived class in
  both directions, every row carries a verdict from the vocabulary, and an `OPEN` row is red.
- `TestTheQueryGatesPublishesIsMeasuredAgainstTheDerivationRatherThanTrusted` — the greps published
  above are compiled and run, their recall is compared against the fraction this file states, and
  the sites they do not reach are named in the log.
- `TestAQueryKeyedToOneSpellingOfTheReceiverStillMissesTheSitesItMissed` — the query this file
  published at `81b97ca`, kept verbatim, is run against the same derivation. Measured today it
  reaches **48 of the 158** narrowing occurrences and misses 110, in seventy-one functions. The
  claim that it was insufficient is a measurement anybody can re-run, and reverting the published
  query to a receiver-keyed one goes red rather than green.

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
- `TestEveryRowClaimingAPrintedComplementHasOne` — the two verdicts that make a claim about RUN
  TIME are held to the source that has to carry it. `NARROWING/complement` is separated from `OPEN`
  by one thing, whether the removed members are named at run time, and until this test existed that
  separation was prose: deleting the `t.Logf` out of `framedContentArmFields` left every other gate
  here green. It is a PROXY and says so — it decides that the narrowing's own function calls a
  reporter, not that what it prints IS the removed set — and it fails closed toward the row: a
  complement printed by the caller reads as absent, so move the print or change the verdict. It
  found one wrong row on the commit that added it: `epochIsTheDestroyedFlag`'s signature clause was
  indexed as a refusal and reports nothing at all.

- `TestTheGatesDerivationSeesANarrowingHoweverItsReceiverIsSpelled` — the derivation is driven over
  a control holding one narrowing of each shape it claims to read, with the receiver spelled four
  different ways, and four shapes it must NOT read. A derivation that reported nothing would agree
  with a document that indexed nothing.

  **It is also what holds this file's stated BOUNDARY to something.** Seven shapes it must see: a
  name narrowing over a method set, an arity narrowing in another function, a shape narrowing
  through a bound signature, **a name narrowing over a FIELD set**, **a shape narrowing through a
  bound field descriptor**, **a predicate bound to a name and used as a condition**, and **a
  predicate spelled as a function literal's result**. Four it must not: a struct field spelled
  `name`, a directory entry's name, an accumulator of member names consumed by `len()`, and **the
  one under-reach this file states** — a signature read off a parameter declared `reflect.Value`.
  The last of those is the difference between a boundary and a paragraph. The boundary list at the
  top of `gates_index_test.go` was defended by nothing for a round, and it was incomplete while it
  read as complete: a predicate bound to a name was on neither of the two lines that claimed to say
  what could not be seen, and it was invisible to the derivation, to both published greps and to all
  four gates here. It is now read rather than listed.

## Two rules for anything added here

- **Give the complement, not the worry.** An entry that says "this class looks narrow" is worth
  nothing. An entry that says "this narrowing removes these N members today, and here is the
  property that says they are out" can be checked in one command.
- **Close entries by deleting them,** and name in the same commit the gate where the narrowing now
  fails closed. A row that outlives its narrowing is the file describing a tree that no longer
  exists — and that direction is now decided by a test rather than by the reader's diligence.
