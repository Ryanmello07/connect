// The derived gate over the class the messagegroup join rests on: a field this package ERASES must
// not be filled with an array its CALLER owns.
//
// WHY THIS EXISTS BESIDE A BEHAVIOURAL PIN. connect/messagegroup holds the same property from the
// outside -- TestTheJoinLeavesThisDeviceAndItsNewHandleAbleToWork joins, then asks whether the
// device can still sign, whether its new handle can still sign, and whether that handle can still
// open a path addressed to its own leaf. That pin catches the symptom wherever it comes from and it
// cannot go stale when this package refactors, which is exactly what a pin is for. What it cannot
// do is see a FOURTH site: it observes only the fields the join path it drives happens to use, it
// fails three packages away from the mistake, and the day somebody adds a retained field that no
// join exercises the pin is green over it. This gate is the other half. It fails at the statement.
//
// THE CLASS IS DERIVED AND NOT ENUMERATED, in three steps, each of which refuses rather than
// reporting clean if it finds nothing:
//
//  1. THE ERASE HELPERS, found by what they DO. A function of this package whose body writes a
//     zero through every index of its byte-slice parameter is an erase helper. The name
//     zeroizeSecret appears nowhere in this derivation; rename it and the set is unchanged.
//  2. THE ERASED FIELDS, found by where those helpers are CALLED on a receiver's own field.
//     Every (type, field) an erase reaches is a field whose backing array this package destroys.
//  3. THE FILL SITES, found by field name over every composite literal and every assignment in
//     this package's production source. By NAME rather than by resolved type, deliberately: that
//     over-reports at the class boundary, which is the safe direction, and the sites it admits in
//     excess are printed.
//
// THE DECISION AT EACH SITE IS AN ALIAS QUESTION AND NOT A SPELLING ONE, which is the whole reason
// this gate is worth having. The three sites the coupling actually rests on are written TWO
// DIFFERENT WAYS -- cloneBytes(x) twice and append(T(nil), x...) once -- and a gate that grepped
// for either spelling would be blind to the other. So nothing here matches a spelling. The RHS of
// every fill site is resolved down to the ORIGIN of its backing array, through parentheses, slice
// expressions, dereferences, address-of, type conversions this package declares, append's
// destination, single-assignment locals, and one hop into the return of any function this package
// declares. A site is CALLER-ROOTED when that origin is a parameter of the enclosing function. A
// new spelling of a copy passes without being taught; a new spelling of an alias is caught without
// being taught.
//
// AND THEN THE PART THAT IS NOT DERIVABLE, WHICH WAS MEASURED RATHER THAN GUESSED AT. Twenty fill
// sites exist. Fifteen are not caller-rooted. FIVE ARE, AND NONE OF THE FIVE IS A DEFECT: this
// package HANDS OWNERSHIP OVER on purpose in four places and the fifth is erased by its own caller.
// (*SecretTree).newRatchet's header says so in its own words -- "taking ownership of the root
// secret: it is erased in place by the first step, so the caller must not keep it" -- while
// JoinFromWelcome must never take ownership of a device's signing key. Both are a field an erase
// reaches, filled from a parameter. NOTHING IN THE SOURCE TELLS THEM APART; it takes escape
// analysis or a stated contract.
//
// So the split is: THE CLASS IS DERIVED AND THE DISPOSITION IS ENUMERATED, in
// eraseOwnershipHandovers below, keyed by file:function.field with the evidence for each. Anything
// caller-rooted and undisposed is RED, and any disposition matching no site is RED. That is
// GATES.md's own remedy rather than a retreat from it -- "a derived class whose literal is
// invisible and silent is worth less than an enumerated one that refuses and prints" -- and the
// alternative, widening the decision rule until those five passed, is how a gate stops refusing
// anything.
//
// JUDGED BY GATES.md's TWO QUESTIONS, because "it is derived" is not the criterion this package
// stopped on:
//
//   - IS THE LITERAL AT A LEVEL WHERE BEING WRONG IS VISIBLE? The literals are the erase body
//     shape (step 1), the syntactic forms the resolver peels, and the five dispositions. Being
//     wrong about step 1 empties the class and this gate FATALS rather than passing. Being wrong
//     about a peel form lands the site in the printed "undecided" list, which is an error and
//     not a silent admit. Being wrong about a disposition is visible because every disposition
//     is PRINTED WITH ITS REASON on every passing run, next to the site it excuses.
//   - DOES IT FAIL CLOSED AND PRINT ITS COMPLEMENT? Empty helper set, empty field set and empty
//     site set each fatal. An origin the resolver cannot reach is an error, never an admit. An
//     empty reason on a disposition is an error. And three complements are printed on every run:
//     what "a field an erase reaches" removed (43 sibling fields), what "the origin is a
//     parameter" removed (15 fill sites, each with where its array came from), and every callee
//     this gate admitted WITHOUT opening -- the three names every one of those admissions rests
//     on. Each of the two "complement is empty" clauses was driven red by forcing it empty.
package mls

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"slices"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// what the resolver answers
// ---------------------------------------------------------------------------

// eraseOriginKind is where a fill site's backing array came from.
type eraseOriginKind int

const (
	// the enclosing function's own parameter, or something reached from one without ever
	// leaving its backing array. THIS IS THE DEFECT.
	eraseOriginParameter eraseOriginKind = iota
	// a fresh array: make, new, a composite literal, a constant, nil, or an append onto one.
	eraseOriginFresh
	// the receiver's own state, which is this type's array and not the caller's.
	eraseOriginReceiver
	// a call this gate could not open: a method, a qualified call, or a function of another
	// package. Admitted, and NAMED on every run.
	eraseOriginOpaque
	// the resolver ran out of forms it understands. Refused, and named.
	eraseOriginUndecided
)

func (self eraseOriginKind) String() string {
	switch self {
	case eraseOriginParameter:
		return "a parameter of the enclosing function"
	case eraseOriginFresh:
		return "a fresh array"
	case eraseOriginReceiver:
		return "the receiver's own state"
	case eraseOriginOpaque:
		return "a call this gate did not open"
	}
	return "UNDECIDED"
}

type eraseOrigin struct {
	kind eraseOriginKind
	// the parameter name, the callee name, or the expression the resolver gave up on.
	what string
}

// eraseFillSite is one place this package's production source writes into a field an erase reaches.
type eraseFillSite struct {
	at     string
	inside string
	field  string
	rhs    string
	origin eraseOrigin
}

// ---------------------------------------------------------------------------
// the gate
// ---------------------------------------------------------------------------

// TestEveryFieldThisPackageErasesIsFilledFromAnArrayItOwns is the gate.
//
// It is the class connect/messagegroup's join body rests on, stated from this side. That body
// assembles mls.JoinKeyMaterial over four copies and defers (*JoinKeyMaterial).Zeroize over the
// result, and its own header calls the fourth copy "a fourth instance of a discipline this path
// already spells three times". The three it names are fill sites in THIS package, and nothing here
// held them. This does.
//
// The symptom of a violation is silent in every case, which is why a gate and not a review: an
// all-zero ed25519 seed derives a perfectly valid public key, so a device whose signing key was
// erased through an alias goes on publishing leaves and founding groups under a key anybody can
// derive, with its credential still naming the real identity.
func TestEveryFieldThisPackageErasesIsFilledFromAnArrayItOwns(t *testing.T) {
	fileSet, sources := eraseSources(t)

	// ---- step 1: the erase helpers, by what they do ----
	helpers := eraseHelpersIn(sources)
	if len(helpers) == 0 {
		t.Fatal("no function of this package writes a zero through every index of a byte-slice parameter, so the erase helper derivation found nothing and every step below would report clean having read nothing")
	}
	t.Logf("step 1 -- %d erase helper(s), derived by body shape and not by name: %v",
		len(helpers), helpers)

	// ---- step 2: the fields those helpers erase ----
	erased, owners := eraseFieldsIn(fileSet, sources, helpers)
	if len(erased) == 0 {
		t.Fatal("no erase helper of this package is called on a receiver's own field, so the erased-field class is empty and this gate would admit every fill site in the tree")
	}
	fields := slices.Sorted(maps_Keys(erased))
	t.Logf("step 2 -- %d erased field name(s), derived from %d call site(s): %v",
		len(fields), len(erased), fields)

	// COMPLEMENT 1: what "a field an erase reaches" removed.
	notErased := eraseSiblingFields(sources, erased)
	t.Logf("complement 1 -- the %d field(s) of the %d type(s) that own an erased field which NO erase of this package reaches, and which this gate therefore says nothing about: %v",
		len(notErased), len(owners), notErased)
	if len(notErased) == 0 {
		t.Error("complement 1 is EMPTY: every field of every type that owns an erased field is itself erased, so 'a field an erase reaches' narrows nothing today and would begin removing real members the day one appears")
	}

	// ---- step 3: the fill sites ----
	sites, refusals, removedForms := eraseFillSitesIn(fileSet, sources, erased)
	if len(sites) == 0 {
		t.Fatal("no composite literal and no assignment in this package's production source fills a field an erase reaches, so this gate read nothing")
	}

	// COMPLEMENT 4: what the FORM class removed, and it is here because its absence is the defect
	// this gate shipped with. The first version read two sub-forms of two of the four binding
	// positions Go has; the rest were not refused and not counted, they were INVISIBLE, and a
	// passing run over a tree holding a positional alias was byte for byte a passing run over a
	// tree holding none. A form nothing counts is a form nothing can miss.
	reasons := slices.Sorted(maps_Keys(removedForms))
	decided := 0
	lines := []string{}
	for _, reason := range reasons {
		decided += removedForms[reason]
		lines = append(lines, fmt.Sprintf("%4d  %s", removedForms[reason], reason))
	}
	t.Logf("complement 4 -- the %d binding position(s) this walk DECIDED were not members, under the reading that decided each:\n\t%s",
		decided, strings.Join(lines, "\n\t"))
	if decided == 0 {
		t.Error("complement 4 is EMPTY: every binding position in this package's production source is a fill site of an erased field, so the form walk removes nothing today and a form this gate CANNOT read would be indistinguishable from one it read and dismissed")
	}
	for _, refusal := range refusals {
		t.Errorf("%s: `%s` is %s. A BINDING POSITION this gate has no reading for is REFUSED and never skipped: the two forms this gate shipped blind to -- a positional composite literal and `x.Field, err = f()` -- produced no site, no complement entry and no undecided count between them",
			refusal.at, refusal.src, refusal.form)
	}

	byOrigin := map[eraseOriginKind][]eraseFillSite{}
	for _, site := range sites {
		byOrigin[site.origin.kind] = append(byOrigin[site.origin.kind], site)
	}
	t.Logf("step 3 -- %d fill site(s): %d from a parameter, %d fresh, %d from the receiver, %d through a call this gate did not open, %d undecided",
		len(sites), len(byOrigin[eraseOriginParameter]), len(byOrigin[eraseOriginFresh]),
		len(byOrigin[eraseOriginReceiver]), len(byOrigin[eraseOriginOpaque]),
		len(byOrigin[eraseOriginUndecided]))

	// COMPLEMENT 2: what "the origin is a parameter" removed.
	removed := []string{}
	for _, kind := range []eraseOriginKind{eraseOriginFresh, eraseOriginReceiver, eraseOriginOpaque} {
		for _, site := range byOrigin[kind] {
			removed = append(removed, fmt.Sprintf("%s %s.%s = %s <- %s",
				site.at, site.inside, site.field, site.rhs, site.origin.kind))
		}
	}
	slices.Sort(removed)
	t.Logf("complement 2 -- the %d fill site(s) this gate ADMITTED because the array they write did not come from the caller:\n\t%s",
		len(removed), strings.Join(removed, "\n\t"))
	if len(removed) == 0 {
		t.Error("complement 2 is EMPTY: every fill site in this package is caller-rooted, so 'the origin is a parameter' removes nothing today and the clause is doing no work")
	}

	// COMPLEMENT 3: what the admission RESTS ON. A call this gate could not open is admitted on
	// the strength of that callee copying, and this gate did not check that it does. It is named
	// on every run so that a new name appearing here is visible in the diff of a test log rather
	// than invisible inside a pass.
	opaque := map[string][]string{}
	for _, site := range byOrigin[eraseOriginOpaque] {
		opaque[site.origin.what] = append(opaque[site.origin.what], site.at)
	}
	names := slices.Sorted(maps_Keys(opaque))
	t.Logf("complement 3 -- %d callee(s) this gate admitted WITHOUT opening, and every admission above rests on each of them copying: %v",
		len(names), names)

	// ---- the refusals ----
	for _, site := range byOrigin[eraseOriginUndecided] {
		t.Errorf("%s: %s fills %s with %s and this gate cannot tell where that array came from (%s). A fill site whose origin is unknown is REFUSED rather than admitted: an erase over a caller's array is silent, so the unknown case must be the failing one",
			site.at, site.inside, site.field, site.rhs, site.origin.what)
	}
	// ---- the caller-rooted sites, against their dispositions ----
	//
	// EVERY ONE OF THEM IS NAMED, on every run, whether it is dispositioned or not -- so the set
	// is readable out of a passing log and a reader never has to run the gate to see what it
	// admitted.
	held := map[string][]eraseFillSite{}
	for _, site := range byOrigin[eraseOriginParameter] {
		key := eraseSiteKey(site)
		reason, isHandedOver := eraseOwnershipHandovers[key]
		held[key] = append(held[key], site)
		if !isHandedOver {
			t.Errorf("%s: %s fills %s with %s, whose backing array is the caller's own parameter %q. This package ERASES that field, so this statement hands a caller's array to an erase the caller does not know about -- which is silent: an all-zero seed derives a perfectly valid public key and an all-zero HPKE key opens nothing while looking like a key. Either COPY it, in whatever spelling this file already uses, or record %q in eraseOwnershipHandovers with the call site that proves the caller hands the array over",
				site.at, site.inside, site.field, site.rhs, site.origin.what, key)
			continue
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("%s is dispositioned with an EMPTY reason, which is an allow-list entry wearing a justification", key)
			continue
		}
		t.Logf("caller-rooted and dispositioned -- %s (%s): %s", key, site.at, reason)
	}
	// AND THE TABLE IS HELD TO THE TREE IN BOTH DIRECTIONS. An entry that matches no site is a
	// disposition for a statement that no longer exists, and the next caller-rooted fill site to
	// land in that function would inherit it silently.
	for key := range eraseOwnershipHandovers {
		if len(held[key]) == 0 {
			t.Errorf("eraseOwnershipHandovers disposes of %q and no fill site of this package answers to it. A stale disposition is an exemption waiting for a statement it was never written about",
				key)
		}
	}
	// AND ONE REASON MAY NOT BE EVIDENCE ABOUT TWO STATEMENTS. Even with the array in the key, two
	// statements can spell the same array the same way in the same function, and the reason below
	// was read and written about ONE of them. The second would inherit a judgement nobody made
	// about it, which is the narrower form of the defect the key itself closes.
	for key, matching := range held {
		if len(matching) < 2 {
			continue
		}
		if _, isHandedOver := eraseOwnershipHandovers[key]; !isHandedOver {
			continue
		}
		places := []string{}
		for _, site := range matching {
			places = append(places, site.at)
		}
		slices.Sort(places)
		t.Errorf("eraseOwnershipHandovers disposes of %q and %d statements answer to it (%v). The reason was read and written about one of them; a second statement inheriting it is an exemption nobody granted it",
			key, len(matching), places)
	}
}

// eraseOwnershipHandovers is the DISPOSITION of the caller-rooted fill sites, and it is
// deliberately a list while the class above is deliberately not one.
//
// WHY THE SPLIT IS HERE AND NOT ONE LEVEL UP. The class -- "a field an erase reaches, filled from
// the caller's array" -- is derivable and is derived. What is NOT derivable from source is whether
// the caller goes on OWNING that array or HANDS IT OVER, and this package does both on purpose:
// (*SecretTree).newRatchet's own header says "taking ownership of the root secret ... so the caller
// must not keep it", while mls.JoinFromWelcome must never take ownership of a device's signing key.
// Telling those two apart needs escape analysis or a stated contract, and a gate that guessed would
// be widened at the first false refusal until it refused nothing.
//
// So the gate derives the class and REFUSES anything undisposed, and the judgement that a
// particular handover is safe is written down where a reader can check it -- which is GATES.md's
// own remedy, quoted: "A derived class whose literal is invisible and silent is worth less than an
// enumerated one that refuses and prints." A sixth caller-rooted fill site cannot land green. A
// fifth that stops existing cannot leave its exemption behind.
//
// THE KEY IS file:function.field AND NOT A LINE. A line-keyed exemption goes stale on the next
// edit above it and gets "refreshed" without being re-read, which is how an allow-list stops being
// read at all.
//
// Each reason names the EVIDENCE, and every one of them was read before it was written here.
var eraseOwnershipHandovers = map[string]string{
	"key_schedule.go:newKeyScheduleFromParts.joinerSecret = joinerSecret":   "the two exported constructors are the only callers and both hand over arrays they made: NewKeySchedule passes bytes.Clone(joinerSecret) at key_schedule.go:269 and NewKeyScheduleFromEpochSecret passes nil. The copy is at the CALL site rather than at the fill site, which is a choice about where the clone lives and not an alias.",
	"key_schedule.go:newKeyScheduleFromParts.welcomeSecret = welcomeSecret": "the same two callers, and welcomeSecret is derived inside NewKeySchedule one statement earlier (crypto.DeriveSecret(memberSecret, \"welcome\")) and never read again by it.",
	"key_schedule.go:newKeyScheduleFromParts.epochSecret = epochSecret":     "the same two callers, and epochSecret is derived inside NewKeySchedule one statement earlier (crypto.ExpandWithLabel) and never read again by it.",
	"secret_tree.go:newRatchet.secret = rootSecret":                         "an ownership transfer the function's own header STATES: \"taking ownership of the root secret: it is erased in place by the first step, so the caller must not keep it or pass a slice it still reads.\" The erase is (*ratchet).step's forward secrecy and the handover is the contract that makes it safe.",
	"welcome.go:BuildWelcome.PathSecret = joiner.PathSecret":                "the GroupSecrets this loop builds are marshalled and sealed and then dropped; BuildWelcome erases nothing. The array belongs to the caller's WelcomeJoiner entries and the caller is the one that erases it -- group.go:2409 calls joiners[i].Zeroize() after the seal. The erase that put PathSecret in this class is on the JOIN side, over a GroupSecrets this package decoded itself (group.go:3196).",
}

// eraseSiteKey names a fill site by file, enclosing function, field AND THE ARRAY IT WRITES --
// never by line.
//
// WHY THE ARRAY IS IN THE KEY, which it was not. The key was file:function.field, and each reason
// below was read and written about ONE statement -- a particular array, reached from a particular
// parameter. A key that stops at the field name is satisfied by any statement in that function
// binding that field, so a NEW caller-rooted fill landing beside a dispositioned one inherited its
// exemption in silence and printed, on every passing run, a reason about a different array. It was
// demonstrated by planting `secrets.PathSecret = &PathSecret{PathSecret: joinerSecret}` one line
// under BuildWelcome's own fill: green, and excused by a sentence about joiner.PathSecret.
//
// STILL NEVER A LINE. A line-keyed exemption goes stale on the next edit above it and gets
// "refreshed" without being re-read, which is how an allow-list stops being read at all. The
// rendered right-hand side is not a line: it survives every edit that does not change what the
// statement writes, and changes exactly when the array does.
func eraseSiteKey(site eraseFillSite) string {
	file := site.at
	if at := strings.LastIndex(file, ":"); at >= 0 {
		file = file[:at]
	}
	return fmt.Sprintf("%s:%s.%s = %s", file, site.inside, site.field, site.rhs)
}

// TestTheErasedFieldGateSeesAnAliasHoweverItIsSpelled is the acceptance test for the gate above,
// and it is the clause that says the gate is about aliasing rather than about spelling.
//
// It is here because the three sites the coupling rests on are written two different ways today,
// and this project has shipped a class defect keyed to ONE spelling nine times. So the resolver is
// driven over a control corpus: thirteen spellings of a COPY that must all be admitted, and thirteen
// spellings of an ALIAS that must all be refused -- including the ones that carry a call, a
// conversion, a slice expression or a local in front of the parameter, which is where a
// spelling-keyed gate goes blind.
//
// AND IT IS THE ACCEPTANCE TEST FOR THE FORM CLASS, which is the half it did not have. Spellings 9
// to 13 are not new spellings of the same statement: they are different BINDING POSITIONS, and the
// first version of this gate could not see four of them. A form dropped from eraseFillSitesIn turns
// this control red at "the gate did not see the site at all" rather than being argued about in a
// comment, which is the only way a boundary stays true after the round that wrote it down.
//
//	 9  a POSITIONAL composite literal            &Held{x}
//	10  the multi-value assignment                h.Secret, err = f(x)
//	11  a method call declared in this package    b.Raw()
//	12  a positional literal with an ELIDED type  []Held{{x}}
//	13  a forwarded multi-value return            return two(x)
//
// It parses a source file of its own rather than reading the tree, because a control has to be able
// to contain the defect.
func TestTheErasedFieldGateSeesAnAliasHoweverItIsSpelled(t *testing.T) {
	const control = `package mls

type Held struct{ Secret []byte }

//go:noinline
func wipe(secret []byte) {
	for i := range secret {
		secret[i] = 0
	}
}

func (self *Held) Zeroize() { wipe(self.Secret) }

func copyOf(bs []byte) []byte {
	out := make([]byte, len(bs))
	copy(out, bs)
	return out
}

func passThrough(bs []byte) []byte { return bs }

type Named []byte

func copy1(x []byte) *Held  { return &Held{Secret: copyOf(x)} }
func copy2(x []byte) *Held  { return &Held{Secret: append([]byte(nil), x...)} }
func copy3(x []byte) *Held  { return &Held{Secret: Named(copyOf(x))} }
func copy4(x []byte) *Held  { return &Held{Secret: make([]byte, len(x))} }
func copy5(x []byte) *Held  { h := &Held{}; h.Secret = copyOf(x); return h }
func copy6(x []byte) *Held  { out := copyOf(x); return &Held{Secret: out} }
func copy7(x []byte) *Held  { return &Held{Secret: append(copyOf(x), 0)} }
func copy8(x []byte) *Held  { return &Held{Secret: nil} }

func alias1(x []byte) *Held { return &Held{Secret: x} }
func alias2(x []byte) *Held { return &Held{Secret: Named(x)} }
func alias3(x []byte) *Held { return &Held{Secret: x[:]} }
func alias4(x []byte) *Held { return &Held{Secret: x[1:4]} }
func alias5(x []byte) *Held { h := &Held{}; h.Secret = x; return h }
func alias6(x []byte) *Held { out := x; return &Held{Secret: out} }
func alias7(x []byte) *Held { return &Held{Secret: passThrough(x)} }
func alias8(x []byte) *Held { return &Held{Secret: append(x, 0)} }

// 9 -- the POSITIONAL composite literal. The field name is not written anywhere in the statement,
// so a gate reading only *ast.KeyValueExpr elements does not see the site AT ALL.
func copy9(x []byte) *Held  { return &Held{copyOf(x)} }
func alias9(x []byte) *Held { return &Held{x} }

// 10 -- the MULTI-VALUE assignment, which is how every decode in the real package binds the octets
// it just read. The array is result 0 and the error is result 1.
func two(x []byte) ([]byte, error)     { return x, nil }
func twoCopies(x []byte) ([]byte, error) { return copyOf(x), nil }

func copy10(x []byte) *Held {
	h := &Held{}
	var err error
	h.Secret, err = twoCopies(x)
	_ = err
	return h
}

func alias10(x []byte) *Held {
	h := &Held{}
	var err error
	h.Secret, err = two(x)
	_ = err
	return h
}

// 11 -- a METHOD-CALL spelling, declared in this package on a type this package declares. The body
// is already parsed here, so admitting it as "a call this gate did not open" was a false statement
// about this gate's own reach.
type Box struct{ inner []byte }

func (self *Box) Raw() []byte    { return self.inner }
func (self *Box) Copied() []byte { return copyOf(self.inner) }

func copy11(b *Box) *Held  { return &Held{Secret: b.Copied()} }
func alias11(b *Box) *Held { return &Held{Secret: b.Raw()} }

// 12 -- the positional literal with its type ELIDED, which is the form that has to be given a type
// by the literal containing it before its fields can be named at all.
func copy12(x []byte) []Held  { return []Held{{copyOf(x)}} }
func alias12(x []byte) []Held { return []Held{{x}} }

// 13 -- a forwarded multi-value return, which answered "fresh" having read no return statement at
// all while the single-result restriction stood.
func forwardsAnAlias(x []byte) ([]byte, error) { return two(x) }
func forwardsACopy(x []byte) ([]byte, error)   { return twoCopies(x) }

func copy13(x []byte) *Held {
	h := &Held{}
	var err error
	h.Secret, err = forwardsACopy(x)
	_ = err
	return h
}

func alias13(x []byte) *Held {
	h := &Held{}
	var err error
	h.Secret, err = forwardsAnAlias(x)
	_ = err
	return h
}
`
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, "erased_field_alias_control.go", control,
		parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse the control corpus: %v", err)
	}
	sources := []eraseSource{{path: "erased_field_alias_control.go", parsed: parsed}}

	helpers := eraseHelpersIn(sources)
	if !slices.Contains(helpers, "wipe") {
		t.Fatalf("the erase helper derivation did not find the control's own erase, which is spelled `wipe`: it found %v. The derivation is keyed to a NAME and this whole gate is void",
			helpers)
	}
	erased, _ := eraseFieldsIn(fileSet, sources, helpers)
	if !erased["Secret"] {
		t.Fatalf("the erased-field derivation did not find Held.Secret: it found %v",
			slices.Sorted(maps_Keys(erased)))
	}
	sites, refusals, removedForms := eraseFillSitesIn(fileSet, sources, erased)
	for _, refusal := range refusals {
		t.Errorf("the control corpus holds `%s` at %s, which this gate refused as %s. Every form in the control is one this gate is supposed to READ",
			refusal.src, refusal.at, refusal.form)
	}
	if len(removedForms) == 0 {
		t.Error("the form walk removed nothing at all over the control corpus, so complement 4 is empty here and the walk is admitting every binding position it sees")
	}

	verdict := map[string]eraseOrigin{}
	for _, site := range sites {
		verdict[site.inside] = site.origin
	}
	for at := 1; at <= 13; at += 1 {
		copyName := fmt.Sprintf("copy%d", at)
		origin, seen := verdict[copyName]
		if !seen {
			t.Errorf("%s fills an erased field and the gate did not see the site at all", copyName)
		} else if origin.kind == eraseOriginParameter {
			t.Errorf("%s COPIES and the gate calls it an alias of %q; a gate that refuses a copy will be widened until it refuses nothing",
				copyName, origin.what)
		} else if origin.kind == eraseOriginUndecided {
			t.Errorf("%s COPIES and the gate cannot decide it (%s); it would be refused as unknown",
				copyName, origin.what)
		}

		aliasName := fmt.Sprintf("alias%d", at)
		origin, seen = verdict[aliasName]
		if !seen {
			t.Errorf("%s hands a caller's array to an erased field and the gate did not see the site at all", aliasName)
		} else if origin.kind != eraseOriginParameter {
			t.Errorf("%s hands the caller's array straight to an erased field and the gate calls its origin %s. This is the nine-times shape: the gate is keyed to how a copy is SPELLED rather than to whether the array is the caller's",
				aliasName, origin.kind)
		}
	}
	t.Logf("the resolver admitted 13 spellings of a copy and refused 13 spellings of an alias, across all five binding positions; the form walk decided %d non-member position(s) over this corpus",
		len(removedForms))
}

// ---------------------------------------------------------------------------
// step 1 -- the erase helpers, by body shape
// ---------------------------------------------------------------------------

// eraseHelpersIn answers every function of these sources whose body writes a zero through every
// index of one of its byte-slice parameters.
//
// THE NAME IS NOT READ. `zeroizeSecret` does not appear in this function, and the control corpus
// above spells its erase `wipe` for exactly that reason: a derivation that matched the name would
// be the same defect this file exists to prevent, one level up.
func eraseHelpersIn(sources []eraseSource) []string {
	found := []string{}
	for _, source := range sources {
		for _, declaration := range source.parsed.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil || function.Recv != nil {
				continue
			}
			parameters := eraseParameterNames(function)
			erases := false
			ast.Inspect(function.Body, func(node ast.Node) bool {
				loop, isRange := node.(*ast.RangeStmt)
				if !isRange || loop.Key == nil || loop.Body == nil {
					return true
				}
				over, isIdentifier := loop.X.(*ast.Ident)
				if !isIdentifier || !parameters[over.Name] {
					return true
				}
				index, isIndexIdentifier := loop.Key.(*ast.Ident)
				if !isIndexIdentifier {
					return true
				}
				for _, statement := range loop.Body.List {
					assign, isAssign := statement.(*ast.AssignStmt)
					if !isAssign || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
						continue
					}
					target, isIndexed := assign.Lhs[0].(*ast.IndexExpr)
					if !isIndexed {
						continue
					}
					into, isInto := target.X.(*ast.Ident)
					at, isAt := target.Index.(*ast.Ident)
					if !isInto || !isAt || into.Name != over.Name || at.Name != index.Name {
						continue
					}
					if literal, isLiteral := assign.Rhs[0].(*ast.BasicLit); isLiteral && literal.Value == "0" {
						erases = true
					}
				}
				return true
			})
			if erases {
				found = append(found, function.Name.Name)
			}
		}
	}
	slices.Sort(found)
	return slices.Compact(found)
}

// ---------------------------------------------------------------------------
// step 2 -- the fields those helpers erase
// ---------------------------------------------------------------------------

// eraseFieldsIn answers every field name an erase helper is called on through a receiver, and the
// receiver type names that own one.
func eraseFieldsIn(fileSet *token.FileSet, sources []eraseSource,
	helpers []string) (map[string]bool, map[string]bool) {

	isHelper := map[string]bool{}
	for _, name := range helpers {
		isHelper[name] = true
	}
	fields := map[string]bool{}
	owners := map[string]bool{}
	for _, source := range sources {
		for _, declaration := range source.parsed.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil || function.Recv == nil ||
				len(function.Recv.List) != 1 {
				continue
			}
			receiver := ""
			if len(function.Recv.List[0].Names) == 1 {
				receiver = function.Recv.List[0].Names[0].Name
			}
			if receiver == "" {
				continue
			}
			owner := eraseTypeNameOf(function.Recv.List[0].Type)
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, isCall := node.(*ast.CallExpr)
				if !isCall || len(call.Args) != 1 {
					return true
				}
				callee, isIdentifier := call.Fun.(*ast.Ident)
				if !isIdentifier || !isHelper[callee.Name] {
					return true
				}
				selector, isSelector := eraseUnparen(call.Args[0]).(*ast.SelectorExpr)
				if !isSelector {
					return true
				}
				base, isBase := eraseUnparen(selector.X).(*ast.Ident)
				if !isBase || base.Name != receiver {
					return true
				}
				fields[selector.Sel.Name] = true
				if owner != "" {
					owners[owner] = true
				}
				return true
			})
		}
	}
	return fields, owners
}

// eraseSiblingFields is complement 1: every field of every struct type that owns an erased field,
// minus the erased ones.
func eraseSiblingFields(sources []eraseSource, erased map[string]bool) []string {
	found := []string{}
	for _, source := range sources {
		for _, declaration := range source.parsed.Decls {
			general, isGeneral := declaration.(*ast.GenDecl)
			if !isGeneral || general.Tok != token.TYPE {
				continue
			}
			for _, spec := range general.Specs {
				typeSpec, isType := spec.(*ast.TypeSpec)
				if !isType {
					continue
				}
				structure, isStruct := typeSpec.Type.(*ast.StructType)
				if !isStruct || structure.Fields == nil {
					continue
				}
				owns := false
				for _, field := range structure.Fields.List {
					for _, name := range field.Names {
						if erased[name.Name] {
							owns = true
						}
					}
				}
				if !owns {
					continue
				}
				for _, field := range structure.Fields.List {
					for _, name := range field.Names {
						if !erased[name.Name] {
							found = append(found, typeSpec.Name.Name+"."+name.Name)
						}
					}
				}
			}
		}
	}
	slices.Sort(found)
	return slices.Compact(found)
}

// ---------------------------------------------------------------------------
// step 3 -- the fill sites and the origin of what they write
// ---------------------------------------------------------------------------

// eraseFormRefusal is a BINDING POSITION this walk found and has no reading for.
//
// It is an error and never a skip, which is the whole of what was wrong with the first version:
// the two forms it could not read produced no site, no complement entry and no undecided count, so
// a tree containing one looked exactly like a tree containing none.
type eraseFormRefusal struct {
	at   string
	form string
	src  string
}

// eraseFillSitesIn answers every place this package's production source BINDS a field an erase
// reaches, where the backing array of what it binds came from, the binding positions it decided
// were NOT members, and the forms it REFUSES.
//
// THE FORM CLASS IS THE LITERAL OF THIS STEP, and the first version of this gate got it wrong in
// the shape GATES.md records nine times. It read *ast.KeyValueExpr elements of a composite literal
// and assignments whose two sides have equal length, and nothing else -- so &PathSecret{p} was
// invisible, and so was x.Field, err = f(), of which this package's production source holds
// twenty-two instances today because it is how every decode binds the octets it just read.
//
// THE BOUNDARY IS STATED AND THE WALK FAILS CLOSED, which is the remedy gatesDeriveDoors took for
// the same defect one gate over. Go REBINDS a struct field in exactly four syntactic positions:
//
//	*ast.CompositeLit  an element, keyed or POSITIONAL, at any depth of elision
//	*ast.AssignStmt    the one-to-one form, the MULTI-VALUE form, and the operator form
//	*ast.RangeStmt     for k, x.Field = range v, when the range binds with = rather than :=
//	*ast.IncDecStmt    x.Field++
//
// and each of the four is decided here in every one of its sub-forms, with a refusal where a
// sub-form has no reading. WHAT IS OUTSIDE THE BOUNDARY IS STATED RATHER THAN IMPLIED, because a
// boundary nobody wrote down is the same thing as no boundary:
//
//   - a write THROUGH the field's existing array, copy(x.Field, p), and a write through a pointer
//     taken at &x.Field. Neither rebinds the field; this gate does not see them and does not claim
//     to. Twenty-seven &field expressions and one copy-into are in this package's source today.
//   - a binding at PACKAGE LEVEL, outside any function body. The walk below is over function
//     bodies, and that is sound rather than lucky: this class is "filled from an array the CALLER
//     owns", a package-level initialiser has no caller and no parameters, so no member of the class
//     can live in one.
//
// AND THE NARROWING PRINTS WHAT IT REMOVED. Every binding position decided NOT to be a member is
// counted under the reading that decided it, and the gate errors if that complement is empty --
// because a form nothing counts is a form nothing can miss.
func eraseFillSitesIn(fileSet *token.FileSet, sources []eraseSource,
	erased map[string]bool) ([]eraseFillSite, []eraseFormRefusal, map[string]int) {

	resolver := newEraseResolver(sources)
	sites := []eraseFillSite{}
	refusals := []eraseFormRefusal{}
	removed := map[string]int{}
	for _, source := range sources {
		shapes := eraseCompositeShapes(source.parsed, resolver)
		for _, declaration := range source.parsed.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			inside := function.Name.Name
			where := func(node ast.Node) string {
				return fmt.Sprintf("%s:%d", source.path, fileSet.Position(node.Pos()).Line)
			}
			// result is the POSITION in the value the binding takes its array from: 0 for every
			// form but the multi-value assignment, where x.Field is the nth thing one call
			// answers and the nth result is the only one whose origin is the field's.
			record := func(field string, value ast.Expr, result int) {
				sites = append(sites, eraseFillSite{
					at:     where(value),
					inside: inside,
					field:  field,
					rhs:    eraseRender(fileSet, value),
					origin: resolver.originOfResult(value, result, function, 0, map[string]bool{}),
				})
			}
			refuse := func(node ast.Node, form string) {
				refusals = append(refusals, eraseFormRefusal{
					at: where(node), form: form, src: eraseRender(fileSet, node),
				})
			}
			// fieldOf answers the field name an assignment target binds, and whether an erase of
			// this package reaches it.
			fieldOf := func(target ast.Expr) (string, bool) {
				selector, isSelector := eraseUnparen(target).(*ast.SelectorExpr)
				if !isSelector {
					return "", false
				}
				return selector.Sel.Name, erased[selector.Sel.Name]
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				switch shaped := node.(type) {
				case *ast.CompositeLit:
					keyed := false
					for _, element := range shaped.Elts {
						if _, isPair := element.(*ast.KeyValueExpr); isPair {
							keyed = true
						}
					}
					if keyed {
						for _, element := range shaped.Elts {
							pair, isPair := element.(*ast.KeyValueExpr)
							if !isPair {
								refuse(element, "an element with no key in a composite literal whose other elements have one, which Go does not permit and this gate cannot place")
								continue
							}
							key, isKey := pair.Key.(*ast.Ident)
							if !isKey {
								removed["a keyed element whose key is not an identifier, so it keys a map or an array and binds no field"] += 1
								continue
							}
							if !erased[key.Name] {
								removed["a keyed element binding a field no erase of this package reaches"] += 1
								continue
							}
							record(key.Name, pair.Value, 0)
						}
						return true
					}
					if len(shaped.Elts) == 0 {
						removed["a composite literal with no elements, which binds nothing"] += 1
						return true
					}
					// POSITIONAL. Nothing in the literal names the fields, so they are read off
					// the TYPE -- which is why this arm needs a type reading and the keyed arm
					// does not, and why a gate with no type reading could not see the form.
					shape, isNamed := shapes[shaped]
					if !isNamed {
						refuse(shaped, "a POSITIONAL composite literal whose type this gate could not name, so it cannot say which field each element binds")
						return true
					}
					if !shape.isStruct {
						removed["a positional literal of a slice, array or map type, whose elements bind no field"] += 1
						return true
					}
					for index, element := range shaped.Elts {
						if index >= len(shape.fields) {
							refuse(element, "a positional element past the end of the field list this gate read for its type")
							continue
						}
						if !erased[shape.fields[index]] {
							removed["a positional element binding a field no erase of this package reaches"] += 1
							continue
						}
						record(shape.fields[index], element, 0)
					}
				case *ast.AssignStmt:
					if shaped.Tok != token.ASSIGN && shaped.Tok != token.DEFINE {
						// AN OPERATOR ASSIGNMENT. No operator Go has rebinds a slice, so this
						// cannot be a member -- but it IS a binding position, so it is decided
						// here rather than walked past, and an erased field on its left is
						// refused rather than assumed harmless.
						for _, target := range shaped.Lhs {
							if field, isErased := fieldOf(target); isErased {
								refuse(shaped, fmt.Sprintf("an operator assignment onto %s, a field an erase reaches", field))
							}
						}
						removed["an operator assignment, which writes through a field's array and cannot rebind it"] += 1
						return true
					}
					if len(shaped.Lhs) == len(shaped.Rhs) {
						for index, target := range shaped.Lhs {
							field, isErased := fieldOf(target)
							if field == "" {
								removed["a one-to-one assignment onto something that is not a field"] += 1
								continue
							}
							if !isErased {
								removed["a one-to-one assignment onto a field no erase of this package reaches"] += 1
								continue
							}
							record(field, shaped.Rhs[index], 0)
						}
						return true
					}
					if len(shaped.Rhs) == 1 {
						// THE MULTI-VALUE FORM. The first version returned at this shape, so
						// every one of these was invisible. The array reaching a field comes out
						// of RESULT POSITION index of the one expression on the right, and that
						// is what its origin is resolved through -- not the call as a whole,
						// which would read result 0 for a field bound at result 1.
						for index, target := range shaped.Lhs {
							field, isErased := fieldOf(target)
							if field == "" {
								removed["a multi-value assignment onto something that is not a field"] += 1
								continue
							}
							if !isErased {
								removed["a multi-value assignment onto a field no erase of this package reaches"] += 1
								continue
							}
							record(field, shaped.Rhs[0], index)
						}
						return true
					}
					refuse(shaped, "an assignment whose two sides have different lengths and whose right side is not a single expression")
				case *ast.RangeStmt:
					if shaped.Tok == token.DEFINE || shaped.Tok == token.ILLEGAL {
						removed["a range that declares its own variables or binds none, which binds no field"] += 1
						return true
					}
					bound := false
					for _, target := range []ast.Expr{shaped.Key, shaped.Value} {
						if target == nil {
							continue
						}
						if field, isErased := fieldOf(target); isErased {
							bound = true
							refuse(shaped, fmt.Sprintf("a range binding %s, a field an erase reaches, once per iteration", field))
						}
					}
					if !bound {
						removed["a range binding with =, onto targets no erase of this package reaches"] += 1
					}
				case *ast.IncDecStmt:
					if field, isErased := fieldOf(shaped.X); isErased {
						refuse(shaped, fmt.Sprintf("an increment or decrement of %s, a field an erase reaches", field))
						return true
					}
					removed["an increment or decrement, which cannot rebind a slice field"] += 1
				}
				return true
			})
		}
	}
	slices.SortFunc(sites, func(a, b eraseFillSite) int { return strings.Compare(a.at, b.at) })
	slices.SortFunc(refusals, func(a, b eraseFormRefusal) int { return strings.Compare(a.at, b.at) })
	return sites, refusals, removed
}

// eraseShape is what one type NAME is, as far as a composite literal is concerned: whether it is a
// struct, and if it is, the fields it declares IN ORDER together with their written types.
//
// The ORDER is the point. A keyed element says which field it binds; a POSITIONAL one does not, and
// nothing but the declaration order can say. The first version of this gate had no type reading at
// all, which is why it could not see a positional element and had no way to know that it could not.
type eraseShape struct {
	isStruct bool
	fields   []string
	types    []ast.Expr
	byName   map[string]ast.Expr
}

// eraseResolver answers where the backing array an expression evaluates to came from.
type eraseResolver struct {
	// every type name this package declares, so a one-argument call can be told from a
	// conversion without a type checker.
	types map[string]bool
	// every package-level function this package declares, so the resolver can take one hop into
	// a callee's return.
	functions map[string]*ast.FuncDecl
	// what each declared type name is UNDERNEATH, so a composite literal's type can be told apart
	// as a struct, a slice, a map or an interface -- and so the element type of a named slice can
	// be reached, which is what gives an ELIDED literal a type at all.
	underlying map[string]ast.Expr
	// the shape of every struct this package declares, by name.
	structs map[string]*eraseShape
	// every METHOD this package declares, by the type it is on and then by its own name. A call
	// spelled x.M() whose receiver is a concrete type of this package is a callee whose body is
	// already parsed here, so admitting it unopened was a false statement about this gate's reach.
	methods map[string]map[string]*ast.FuncDecl
}

const eraseResolverDepth = 8

func newEraseResolver(sources []eraseSource) *eraseResolver {
	self := &eraseResolver{
		types:      map[string]bool{},
		functions:  map[string]*ast.FuncDecl{},
		underlying: map[string]ast.Expr{},
		structs:    map[string]*eraseShape{},
		methods:    map[string]map[string]*ast.FuncDecl{},
	}
	for _, source := range sources {
		for _, declaration := range source.parsed.Decls {
			switch shaped := declaration.(type) {
			case *ast.GenDecl:
				if shaped.Tok != token.TYPE {
					continue
				}
				for _, spec := range shaped.Specs {
					typeSpec, isType := spec.(*ast.TypeSpec)
					if !isType {
						continue
					}
					self.types[typeSpec.Name.Name] = true
					self.underlying[typeSpec.Name.Name] = typeSpec.Type
					if structure, isStructure := typeSpec.Type.(*ast.StructType); isStructure {
						self.structs[typeSpec.Name.Name] = eraseShapeOf(structure)
					}
				}
			case *ast.FuncDecl:
				if shaped.Recv == nil {
					self.functions[shaped.Name.Name] = shaped
					continue
				}
				if len(shaped.Recv.List) != 1 {
					continue
				}
				owner := eraseTypeNameOf(shaped.Recv.List[0].Type)
				if owner == "" {
					continue
				}
				if self.methods[owner] == nil {
					self.methods[owner] = map[string]*ast.FuncDecl{}
				}
				self.methods[owner][shaped.Name.Name] = shaped
			}
		}
	}
	return self
}

// eraseShapeOf reads one struct declaration into the ordered field list a positional element is
// resolved through. An EMBEDDED field is named by its own type, which is how Go names it.
func eraseShapeOf(structure *ast.StructType) *eraseShape {
	shape := &eraseShape{isStruct: true, byName: map[string]ast.Expr{}}
	if structure.Fields == nil {
		return shape
	}
	for _, field := range structure.Fields.List {
		if len(field.Names) == 0 {
			name := eraseTypeNameOf(field.Type)
			shape.fields = append(shape.fields, name)
			shape.types = append(shape.types, field.Type)
			if name != "" {
				shape.byName[name] = field.Type
			}
			continue
		}
		for _, declared := range field.Names {
			shape.fields = append(shape.fields, declared.Name)
			shape.types = append(shape.types, field.Type)
			shape.byName[declared.Name] = field.Type
		}
	}
	return shape
}

// shapeOf answers what a written type IS, following the names this package declares. nil means this
// reading cannot say, and nil keeps a positional literal REFUSED rather than guessed at.
func (self *eraseResolver) shapeOf(written ast.Expr, depth int) *eraseShape {
	if written == nil || depth > eraseResolverDepth {
		return nil
	}
	switch shaped := written.(type) {
	case *ast.ParenExpr:
		return self.shapeOf(shaped.X, depth+1)
	case *ast.StarExpr:
		return self.shapeOf(shaped.X, depth+1)
	case *ast.StructType:
		return eraseShapeOf(shaped)
	case *ast.ArrayType, *ast.MapType, *ast.ChanType, *ast.InterfaceType, *ast.FuncType:
		return &eraseShape{}
	case *ast.IndexExpr:
		return self.shapeOf(shaped.X, depth+1)
	case *ast.IndexListExpr:
		return self.shapeOf(shaped.X, depth+1)
	case *ast.Ident:
		if shape, isStruct := self.structs[shaped.Name]; isStruct {
			return shape
		}
		if under, isDeclared := self.underlying[shaped.Name]; isDeclared {
			return self.shapeOf(under, depth+1)
		}
	}
	return nil
}

// elementTypesOf answers the element and key types of a written container type, which is what gives
// an ELIDED composite literal -- {left, right} inside a [2][2]NodeIndex -- a type at all.
func (self *eraseResolver) elementTypesOf(written ast.Expr, depth int) (ast.Expr, ast.Expr) {
	if written == nil || depth > eraseResolverDepth {
		return nil, nil
	}
	switch shaped := written.(type) {
	case *ast.ParenExpr:
		return self.elementTypesOf(shaped.X, depth+1)
	case *ast.StarExpr:
		return self.elementTypesOf(shaped.X, depth+1)
	case *ast.ArrayType:
		return shaped.Elt, nil
	case *ast.MapType:
		return shaped.Value, shaped.Key
	case *ast.IndexExpr:
		return self.elementTypesOf(shaped.X, depth+1)
	case *ast.Ident:
		if under, isDeclared := self.underlying[shaped.Name]; isDeclared {
			return self.elementTypesOf(under, depth+1)
		}
	}
	return nil, nil
}

// eraseCompositeShapes answers the shape of EVERY composite literal in one file, including the ones
// whose type is written only on a literal that contains them.
//
// A literal missing from this map is one this reading could not name, and the walk refuses it rather
// than skipping it -- but only when it is POSITIONAL, because a keyed element names its own field
// and needs no type at all.
func eraseCompositeShapes(file *ast.File, resolver *eraseResolver) map[*ast.CompositeLit]*eraseShape {
	shapes := map[*ast.CompositeLit]*eraseShape{}
	var walk func(literal *ast.CompositeLit, expected ast.Expr)
	walk = func(literal *ast.CompositeLit, expected ast.Expr) {
		written := literal.Type
		if written == nil {
			written = expected
		}
		shape := resolver.shapeOf(written, 0)
		if shape != nil {
			shapes[literal] = shape
		}
		element, key := resolver.elementTypesOf(written, 0)
		for index, entry := range literal.Elts {
			value := entry
			expectation := element
			if pair, isPair := entry.(*ast.KeyValueExpr); isPair {
				value = pair.Value
				if shape != nil && shape.isStruct {
					if name, isName := pair.Key.(*ast.Ident); isName {
						expectation = shape.byName[name.Name]
					}
				}
				if inner, isInner := pair.Key.(*ast.CompositeLit); isInner {
					walk(inner, key)
				}
			} else if shape != nil && shape.isStruct && index < len(shape.types) {
				expectation = shape.types[index]
			}
			if inner, isInner := value.(*ast.CompositeLit); isInner {
				walk(inner, expectation)
			}
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		literal, isLiteral := node.(*ast.CompositeLit)
		if !isLiteral || literal.Type == nil {
			return true
		}
		if _, alreadyWalked := shapes[literal]; alreadyWalked {
			return true
		}
		walk(literal, nil)
		return true
	})
	return shapes
}

// declaredTypeNameOf answers the name of the type an expression HAS, read off the declaration that
// introduced it: a parameter, the receiver, a local with a written type, a local assigned a
// composite literal, a field of a struct this package declares, or the first result of a function
// it declares.
//
// "" means this gate cannot say, and "" keeps a method call OPAQUE. That is exactly the line between
// the hole closed here and the open edge this gate discloses: h.Bytes() where h is declared
// *probeHolder is a body already parsed here, while crypto.DeriveSecret(...) where crypto is
// declared CryptoProvider is an INTERFACE, and picking the one implementation that happens to live
// in this package would be a guess wearing a derivation.
func (self *eraseResolver) declaredTypeNameOf(value ast.Expr, inside *ast.FuncDecl, depth int) string {
	if inside == nil || depth > eraseResolverDepth {
		return ""
	}
	switch shaped := eraseUnparen(value).(type) {
	case *ast.StarExpr:
		return self.declaredTypeNameOf(shaped.X, inside, depth+1)
	case *ast.CompositeLit:
		return eraseTypeNameOf(shaped.Type)
	case *ast.UnaryExpr:
		if shaped.Op == token.AND {
			return self.declaredTypeNameOf(shaped.X, inside, depth+1)
		}
	case *ast.Ident:
		if written := eraseDeclaredTypeOfName(inside, shaped.Name); written != nil {
			return eraseTypeNameOf(written)
		}
		for _, assigned := range eraseAssignmentsTo(inside, shaped.Name) {
			if name := self.declaredTypeNameOf(assigned, inside, depth+1); name != "" {
				return name
			}
		}
	case *ast.SelectorExpr:
		owner := self.declaredTypeNameOf(shaped.X, inside, depth+1)
		if shape, isStruct := self.structs[owner]; isStruct {
			if written, isField := shape.byName[shaped.Sel.Name]; isField {
				return eraseTypeNameOf(written)
			}
		}
	case *ast.CallExpr:
		callee, isIdentifier := eraseUnparen(shaped.Fun).(*ast.Ident)
		if !isIdentifier {
			return ""
		}
		declared, isDeclared := self.functions[callee.Name]
		if isDeclared && declared.Type != nil && declared.Type.Results != nil &&
			len(declared.Type.Results.List) >= 1 {
			return eraseTypeNameOf(declared.Type.Results.List[0].Type)
		}
	}
	return ""
}

// eraseDeclaredTypeOfName answers the WRITTEN type of one name inside one function: its receiver,
// its parameters, its results, or a var declaration in its body.
func eraseDeclaredTypeOfName(function *ast.FuncDecl, name string) ast.Expr {
	if function == nil {
		return nil
	}
	lists := []*ast.FieldList{function.Recv}
	if function.Type != nil {
		lists = append(lists, function.Type.Params, function.Type.Results)
	}
	for _, list := range lists {
		if list == nil {
			continue
		}
		for _, field := range list.List {
			for _, declared := range field.Names {
				if declared.Name == name {
					return field.Type
				}
			}
		}
	}
	var found ast.Expr
	if function.Body != nil {
		ast.Inspect(function.Body, func(node ast.Node) bool {
			spec, isSpec := node.(*ast.ValueSpec)
			if !isSpec || spec.Type == nil {
				return true
			}
			for _, declared := range spec.Names {
				if declared.Name == name {
					found = spec.Type
				}
			}
			return true
		})
	}
	return found
}

// originOf is the whole decision. It peels every form that PRESERVES a backing array and stops at
// the first thing that makes a new one.
func (self *eraseResolver) originOf(value ast.Expr, inside *ast.FuncDecl, depth int,
	seen map[string]bool) eraseOrigin {

	if depth > eraseResolverDepth {
		return eraseOrigin{kind: eraseOriginUndecided, what: "the resolver ran out of depth"}
	}
	switch shaped := value.(type) {
	case *ast.ParenExpr:
		return self.originOf(shaped.X, inside, depth+1, seen)
	case *ast.StarExpr:
		return self.originOf(shaped.X, inside, depth+1, seen)
	case *ast.TypeAssertExpr:
		return self.originOf(shaped.X, inside, depth+1, seen)
	case *ast.SliceExpr:
		// a reslice is the SAME array. This is one of the four forms a spelling-keyed gate
		// walks straight past.
		return self.originOf(shaped.X, inside, depth+1, seen)
	case *ast.IndexExpr:
		return self.originOf(shaped.X, inside, depth+1, seen)
	case *ast.UnaryExpr:
		if shaped.Op == token.AND {
			return self.originOf(shaped.X, inside, depth+1, seen)
		}
		return eraseOrigin{kind: eraseOriginFresh, what: "a computed value"}
	case *ast.BasicLit, *ast.CompositeLit, *ast.FuncLit, *ast.BinaryExpr:
		return eraseOrigin{kind: eraseOriginFresh, what: "a literal"}
	case *ast.SelectorExpr:
		if base, isIdentifier := eraseUnparen(shaped.X).(*ast.Ident); isIdentifier {
			if eraseParameterNames(inside)[base.Name] {
				return eraseOrigin{kind: eraseOriginParameter, what: base.Name + "." + shaped.Sel.Name}
			}
			if eraseReceiverName(inside) == base.Name {
				return eraseOrigin{kind: eraseOriginReceiver, what: base.Name + "." + shaped.Sel.Name}
			}
		}
		return self.originOf(shaped.X, inside, depth+1, seen)
	case *ast.Ident:
		return self.originOfIdent(shaped, inside, depth, seen)
	case *ast.CallExpr:
		return self.originOfCall(shaped, 0, inside, depth, seen)
	}
	return eraseOrigin{kind: eraseOriginUndecided, what: fmt.Sprintf("%T", value)}
}

// originOfResult is originOf at a RESULT POSITION, which is what the multi-value assignment form
// needs and what the first version of this gate had no way to ask for.
//
// x.Field, err = f() binds the field from result 0 and err from result 1. Resolving the call as a
// whole would answer result 0 for every target, so a field bound at position 1 would be decided by
// the origin of a value it never receives.
func (self *eraseResolver) originOfResult(value ast.Expr, result int, inside *ast.FuncDecl,
	depth int, seen map[string]bool) eraseOrigin {

	if result == 0 {
		return self.originOf(value, inside, depth, seen)
	}
	switch shaped := eraseUnparen(value).(type) {
	case *ast.CallExpr:
		return self.originOfCall(shaped, result, inside, depth, seen)
	case *ast.IndexExpr, *ast.TypeAssertExpr:
		// the comma-ok forms, v, ok := m[k] and v, ok := x.(T). Result 1 is a bool and carries
		// no array at all.
		return eraseOrigin{kind: eraseOriginFresh, what: "the ok of a comma-ok form"}
	case *ast.UnaryExpr:
		if shaped.Op == token.ARROW {
			return eraseOrigin{kind: eraseOriginFresh, what: "the ok of a channel receive"}
		}
	}
	return eraseOrigin{kind: eraseOriginUndecided,
		what: fmt.Sprintf("result %d of a %T, a form this gate has no reading for", result, value)}
}

func (self *eraseResolver) originOfIdent(name *ast.Ident, inside *ast.FuncDecl, depth int,
	seen map[string]bool) eraseOrigin {

	if name.Name == "nil" {
		return eraseOrigin{kind: eraseOriginFresh, what: "nil"}
	}
	if eraseParameterNames(inside)[name.Name] {
		return eraseOrigin{kind: eraseOriginParameter, what: name.Name}
	}
	if eraseReceiverName(inside) == name.Name {
		return eraseOrigin{kind: eraseOriginReceiver, what: name.Name}
	}
	// KEYED BY THE RECEIVER TYPE AND NOT BY THE FUNCTION NAME ALONE. Two methods of the same name
	// on two types are two bodies, and now that a method call is opened they can both be on one
	// resolution chain; a key that named only the method would call the second a cycle and answer
	// "fresh" having read nothing.
	key := eraseFunctionKey(inside) + "." + name.Name
	if seen[key] {
		return eraseOrigin{kind: eraseOriginFresh, what: "a cycle, already resolved"}
	}
	seen[key] = true
	// a LOCAL: every value it is ever assigned. The most alias-y answer wins, because a local
	// that holds the caller's array on ONE path holds it.
	assigned := eraseAssignmentsTo(inside, name.Name)
	if len(assigned) == 0 {
		return eraseOrigin{kind: eraseOriginUndecided,
			what: fmt.Sprintf("%q is neither a parameter, the receiver, nor a local this gate found an assignment for", name.Name)}
	}
	worst := eraseOrigin{kind: eraseOriginFresh, what: "a fresh array"}
	for _, value := range assigned {
		origin := self.originOf(value, inside, depth+1, seen)
		if origin.kind == eraseOriginParameter {
			return origin
		}
		if origin.kind == eraseOriginUndecided || origin.kind == eraseOriginOpaque {
			worst = origin
		}
	}
	return worst
}

func (self *eraseResolver) originOfCall(call *ast.CallExpr, result int, inside *ast.FuncDecl,
	depth int, seen map[string]bool) eraseOrigin {

	if result == 0 {
		switch eraseUnparen(call.Fun).(type) {
		case *ast.ArrayType, *ast.MapType, *ast.ChanType, *ast.InterfaceType, *ast.StructType:
			// a conversion written as a TYPE LITERAL, which is how `[]byte(nil)` is spelled --
			// the destination of one of the two copy spellings this coupling actually uses. It
			// is a conversion like any other: peel it.
			if len(call.Args) == 1 {
				return self.originOf(call.Args[0], inside, depth+1, seen)
			}
		}
	}
	callee, isIdentifier := eraseUnparen(call.Fun).(*ast.Ident)
	if !isIdentifier {
		if selector, isSelector := eraseUnparen(call.Fun).(*ast.SelectorExpr); isSelector {
			if origin, decided := self.originOfMethodCall(call, selector, result, inside, depth, seen); decided {
				return origin
			}
		}
		// a qualified call, or a method reached through an INTERFACE or a foreign type. This is
		// the open edge this gate discloses: admitted, and named in complement 3.
		return eraseOrigin{kind: eraseOriginOpaque, what: eraseRender(token.NewFileSet(), call.Fun)}
	}
	if result == 0 {
		switch callee.Name {
		case "append":
			// append writes into its DESTINATION's array whenever that array has room, so the
			// origin of an append is the origin of its first argument. append(T(nil), x...) is
			// fresh; append(callersSlice, x...) is the caller's.
			if len(call.Args) == 0 {
				return eraseOrigin{kind: eraseOriginFresh, what: "append of nothing"}
			}
			return self.originOf(call.Args[0], inside, depth+1, seen)
		case "make", "new":
			return eraseOrigin{kind: eraseOriginFresh, what: callee.Name}
		case "len", "cap", "copy", "int", "uint", "byte", "string", "uint16", "uint32", "uint64":
			return eraseOrigin{kind: eraseOriginFresh, what: callee.Name}
		}
		if self.types[callee.Name] && len(call.Args) == 1 {
			// a conversion this package declares. It renames the type and keeps the array,
			// which is the second of the four forms a spelling-keyed gate walks past.
			return self.originOf(call.Args[0], inside, depth+1, seen)
		}
	}
	declared, isDeclared := self.functions[callee.Name]
	if !isDeclared || declared.Body == nil {
		return eraseOrigin{kind: eraseOriginOpaque, what: callee.Name}
	}
	// ONE HOP INTO THE CALLEE. Whatever it returns at this result position is resolved against
	// ITS parameters, and a return rooted at one of them is mapped back onto the matching
	// argument here. cloneBytes is decided by this arm and not by its name: it returns `out`, a
	// local assigned from make, so the array it answers is fresh.
	return self.originOfBody(declared, callee.Name, result, call.Args, nil, inside, depth, seen)
}

// originOfMethodCall opens a call spelled x.M(...) when M is a method THIS PACKAGE DECLARES on a
// CONCRETE type this package declares, and x's own declaration says which one.
//
// THIS IS NOT THE OPEN EDGE THIS GATE DISCLOSES, which is why it is closed here rather than added
// to complement 3. That edge is about callees whose body this gate does not have -- a function of
// another package, or a method reached through an interface, where the source says nothing about
// which implementation runs. A method on a struct of this package is neither: its body is in the
// files this gate already parsed, so admitting it as "a call this gate did not open" was a false
// statement about this gate's own reach, and it admitted h.Bytes() -- a plain alias -- in silence.
//
// AN INTERFACE RECEIVER STAYS OPAQUE and stays named in complement 3. crypto.DeriveSecret could be
// any implementation of CryptoProvider, and reading the one that happens to live in this package
// would be a guess wearing a derivation.
//
// The second bool says whether this reading DECIDED. False hands the call back to the opaque arm.
func (self *eraseResolver) originOfMethodCall(call *ast.CallExpr, selector *ast.SelectorExpr,
	result int, inside *ast.FuncDecl, depth int, seen map[string]bool) (eraseOrigin, bool) {

	owner := self.declaredTypeNameOf(selector.X, inside, 0)
	if owner == "" {
		return eraseOrigin{}, false
	}
	shape, isStruct := self.structs[owner]
	if !isStruct || !shape.isStruct {
		return eraseOrigin{}, false
	}
	declared, isDeclared := self.methods[owner][selector.Sel.Name]
	if !isDeclared || declared.Body == nil {
		return eraseOrigin{}, false
	}
	name := fmt.Sprintf("(%s).%s", owner, selector.Sel.Name)
	return self.originOfBody(declared, name, result, call.Args, selector.X, inside, depth, seen), true
}

// originOfBody is the one hop, shared by the function arm and the method arm.
//
// receiver is the expression the method was called ON, or nil for a plain function. A body that
// answers its RECEIVER's own state is answering an array that belongs to whatever the receiver
// expression is rooted at in the CALLER's frame -- which is how h.Bytes(), where h is a parameter,
// is the caller's array spelled as a method call.
func (self *eraseResolver) originOfBody(declared *ast.FuncDecl, name string, result int,
	arguments []ast.Expr, receiver ast.Expr, inside *ast.FuncDecl, depth int,
	seen map[string]bool) eraseOrigin {

	key := fmt.Sprintf("call:%s:%d", name, result)
	if seen[key] {
		return eraseOrigin{kind: eraseOriginFresh, what: "a recursive callee, already resolved"}
	}
	seen[key] = true
	worst := eraseOrigin{kind: eraseOriginFresh, what: name + " answers a fresh array"}
	returned, forwarded := eraseReturnExpressionsAt(declared, result)
	for _, value := range returned {
		origin := self.originOf(value, declared, depth+1, seen)
		switch origin.kind {
		case eraseOriginReceiver:
			if receiver == nil {
				// a plain function has no receiver, so a receiver-rooted return out of one
				// is a reading this gate cannot map back onto anything here.
				return eraseOrigin{kind: eraseOriginUndecided,
					what: fmt.Sprintf("%s answers receiver state and this gate called it as a function", name)}
			}
			return self.originOf(receiver, inside, depth+1, seen)
		case eraseOriginParameter:
			at := eraseParameterIndex(declared, strings.Split(origin.what, ".")[0])
			if at < 0 || at >= len(arguments) {
				return eraseOrigin{kind: eraseOriginUndecided,
					what: fmt.Sprintf("%s answers its own parameter %q and this gate could not map it back onto an argument",
						name, origin.what)}
			}
			return self.originOf(arguments[at], inside, depth+1, seen)
		case eraseOriginUndecided, eraseOriginOpaque:
			worst = eraseOrigin{kind: origin.kind, what: name + ": " + origin.what}
		}
	}
	// A FORWARDED MULTI-VALUE RETURN, `return g()` out of a function with several results. The
	// results cannot be split apart syntactically, so the same result position is asked of g.
	// Without this arm a forwarding body answered "fresh" having read nothing, which is the
	// silent admit this gate exists to refuse.
	for _, value := range forwarded {
		origin := self.originOfResult(value, result, declared, depth+1, seen)
		switch origin.kind {
		case eraseOriginParameter:
			at := eraseParameterIndex(declared, strings.Split(origin.what, ".")[0])
			if at < 0 || at >= len(arguments) {
				return eraseOrigin{kind: eraseOriginUndecided,
					what: fmt.Sprintf("%s forwards its own parameter %q and this gate could not map it back onto an argument",
						name, origin.what)}
			}
			return self.originOf(arguments[at], inside, depth+1, seen)
		case eraseOriginReceiver:
			if receiver == nil {
				return eraseOrigin{kind: eraseOriginUndecided,
					what: fmt.Sprintf("%s forwards receiver state and this gate called it as a function", name)}
			}
			return self.originOf(receiver, inside, depth+1, seen)
		case eraseOriginUndecided, eraseOriginOpaque:
			worst = eraseOrigin{kind: origin.kind, what: name + " forwards: " + origin.what}
		}
	}
	return worst
}

// ---------------------------------------------------------------------------
// the small readings
// ---------------------------------------------------------------------------

type eraseSource struct {
	path   string
	parsed *ast.File
}

func eraseSources(t *testing.T) (*token.FileSet, []eraseSource) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read this package's directory: %v", err)
	}
	fileSet := token.NewFileSet()
	sources := []eraseSource{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fileSet, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		sources = append(sources, eraseSource{path: name, parsed: parsed})
	}
	if len(sources) == 0 {
		t.Fatal("no production go file was read out of this package, so this gate scanned nothing")
	}
	return fileSet, sources
}

func eraseParameterNames(function *ast.FuncDecl) map[string]bool {
	names := map[string]bool{}
	if function == nil || function.Type == nil || function.Type.Params == nil {
		return names
	}
	for _, field := range function.Type.Params.List {
		for _, name := range field.Names {
			names[name.Name] = true
		}
	}
	return names
}

func eraseParameterIndex(function *ast.FuncDecl, name string) int {
	at := 0
	if function.Type == nil || function.Type.Params == nil {
		return -1
	}
	for _, field := range function.Type.Params.List {
		for _, declared := range field.Names {
			if declared.Name == name {
				return at
			}
			at += 1
		}
	}
	return -1
}

// eraseFunctionKey names one declaration uniquely across this package: (Type).Method for a method,
// and the bare name for a function.
func eraseFunctionKey(function *ast.FuncDecl) string {
	if function == nil {
		return ""
	}
	if function.Recv != nil && len(function.Recv.List) == 1 {
		if owner := eraseTypeNameOf(function.Recv.List[0].Type); owner != "" {
			return "(" + owner + ")." + function.Name.Name
		}
	}
	return function.Name.Name
}

func eraseReceiverName(function *ast.FuncDecl) string {
	if function == nil || function.Recv == nil || len(function.Recv.List) != 1 ||
		len(function.Recv.List[0].Names) != 1 {
		return ""
	}
	return function.Recv.List[0].Names[0].Name
}

func eraseTypeNameOf(value ast.Expr) string {
	switch shaped := value.(type) {
	case *ast.StarExpr:
		return eraseTypeNameOf(shaped.X)
	case *ast.ParenExpr:
		return eraseTypeNameOf(shaped.X)
	case *ast.Ident:
		return shaped.Name
	case *ast.IndexExpr:
		return eraseTypeNameOf(shaped.X)
	case *ast.IndexListExpr:
		return eraseTypeNameOf(shaped.X)
	}
	return ""
}

// eraseAssignmentsTo answers every value a local is ever assigned inside one function, including
// the range and the type-switch forms, so that a local standing in front of a parameter is not a
// hole in the derivation.
func eraseAssignmentsTo(function *ast.FuncDecl, name string) []ast.Expr {
	values := []ast.Expr{}
	if function == nil || function.Body == nil {
		return values
	}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		switch shaped := node.(type) {
		case *ast.AssignStmt:
			// the one-to-one form.
			if len(shaped.Lhs) == len(shaped.Rhs) {
				for at, target := range shaped.Lhs {
					if identifier, isIdentifier := target.(*ast.Ident); isIdentifier && identifier.Name == name {
						values = append(values, shaped.Rhs[at])
					}
				}
				return true
			}
			// AND THE MULTI-VALUE FORM, `a, err := f()`, which is not a corner: it is how
			// every decode in this package binds the bytes it just read, and a resolver that
			// did not know it reported those locals UNDECIDED. The array comes out of the one
			// call on the right, so that call is what the local's origin is resolved through.
			if len(shaped.Rhs) != 1 {
				return true
			}
			for _, target := range shaped.Lhs {
				if identifier, isIdentifier := target.(*ast.Ident); isIdentifier && identifier.Name == name {
					values = append(values, shaped.Rhs[0])
				}
			}
		case *ast.ValueSpec:
			if len(shaped.Values) != len(shaped.Names) {
				return true
			}
			for at, declared := range shaped.Names {
				if declared.Name == name {
					values = append(values, shaped.Values[at])
				}
			}
		case *ast.RangeStmt:
			if identifier, isIdentifier := shaped.Value.(*ast.Ident); isIdentifier && identifier.Name == name {
				values = append(values, shaped.X)
			}
		}
		return true
	})
	return values
}

// eraseReturnExpressionsAt answers every value one function can return AT ONE RESULT POSITION, and
// separately the calls it FORWARDS whole.
//
// The single-result restriction the first version carried was not a corner either: a function
// answering (T, error) -- which is most of this package -- was opened, matched nothing, and
// answered "fresh" having read no return at all. A body this gate cannot read must not look like a
// body that makes its own array.
func eraseReturnExpressionsAt(function *ast.FuncDecl, at int) ([]ast.Expr, []ast.Expr) {
	values := []ast.Expr{}
	forwarded := []ast.Expr{}
	if function == nil || function.Body == nil || function.Type == nil ||
		function.Type.Results == nil {
		return values, forwarded
	}
	names := []string{}
	for _, field := range function.Type.Results.List {
		if len(field.Names) == 0 {
			names = append(names, "")
			continue
		}
		for _, declared := range field.Names {
			names = append(names, declared.Name)
		}
	}
	if at < 0 || at >= len(names) {
		return values, forwarded
	}
	// a NAMED result is resolved through its name, so a body that assigns it and returns bare is
	// not a hole.
	if names[at] != "" {
		values = append(values, eraseAssignmentsTo(function, names[at])...)
	}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		statement, isReturn := node.(*ast.ReturnStmt)
		if !isReturn {
			return true
		}
		if len(statement.Results) == len(names) {
			values = append(values, statement.Results[at])
			return true
		}
		if len(statement.Results) == 1 && len(names) > 1 {
			forwarded = append(forwarded, statement.Results[0])
		}
		return true
	})
	return values, forwarded
}

func eraseUnparen(value ast.Expr) ast.Expr {
	for {
		parenthesised, isParen := value.(*ast.ParenExpr)
		if !isParen {
			return value
		}
		value = parenthesised.X
	}
}

func eraseRender(fileSet *token.FileSet, value ast.Node) string {
	buffer := &bytes.Buffer{}
	if err := printer.Fprint(buffer, fileSet, value); err != nil {
		return fmt.Sprintf("%T", value)
	}
	return strings.Join(strings.Fields(buffer.String()), " ")
}

// maps_Keys is maps.Keys, spelled locally so this file adds no import its neighbours do not carry.
func maps_Keys[V any](of map[string]V) func(func(string) bool) {
	return func(yield func(string) bool) {
		for key := range of {
			if !yield(key) {
				return
			}
		}
	}
}
