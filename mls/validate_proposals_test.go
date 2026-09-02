package mls

import (
	"errors"
	"go/ast"
	"maps"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect/mls/syntax"
)

// ---------------------------------------------------------------------------
// the fixtures
// ---------------------------------------------------------------------------

// testTreeWith builds a pre-commit tree of len(names) leaves and returns it with the members that
// own them.
func testTreeWith(t *testing.T, crypto CryptoProvider, names ...string) (*RatchetTree, []*testMember) {
	t.Helper()
	tree := NewRatchetTree()
	members := make([]*testMember, 0, len(names))
	for _, name := range names {
		member := testIdentity(t, crypto, name)
		leaf, _ := testLeafNode(t, crypto, member)
		if _, err := tree.AddLeaf(leaf); err != nil {
			t.Fatalf("AddLeaf %s: %v", name, err)
		}
		members = append(members, member)
	}
	return tree, members
}

// testProposalList buckets entries the way (*ProposalCache).Resolve does, so a fixture cannot
// accidentally test the bucket rules while meaning to test something else.
//
// The switch is Resolve's and is written out rather than called, because Resolve buckets while
// resolving a ProposalOrRef vector against a cache and these fixtures have neither. A type with no
// bucket is fatal here rather than dropped: a fixture whose proposal went nowhere would be judged
// by nothing and would report the clean bill a correct one reports.
func testProposalList(t *testing.T, entries ...CachedProposal) *ProposalList {
	t.Helper()
	list := &ProposalList{}
	for _, entry := range entries {
		list.All = append(list.All, entry)
		switch entry.Proposal.ProposalType {
		case ProposalTypeAdd:
			list.Adds = append(list.Adds, entry)
		case ProposalTypeUpdate:
			list.Updates = append(list.Updates, entry)
		case ProposalTypeRemove:
			list.Removes = append(list.Removes, entry)
		case ProposalTypeGroupContextExtensions:
			list.GCE = append(list.GCE, entry)
		default:
			t.Fatalf("testProposalList has no bucket for %s", proposalTypeName(entry.Proposal.ProposalType))
		}
	}
	return list
}

func testAddOf(kp *KeyPackage) CachedProposal {
	return CachedProposal{
		Proposal: Proposal{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: *kp}},
		ByValue:  true,
	}
}

func testRemoveOf(leaf LeafIndex) CachedProposal {
	return CachedProposal{
		Proposal: Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: leaf}},
		ByValue:  true,
	}
}

func testUpdateOf(sender LeafIndex, leaf *LeafNode) CachedProposal {
	return CachedProposal{
		Proposal: Proposal{ProposalType: ProposalTypeUpdate, Update: &Update{LeafNode: *leaf}},
		Sender:   sender,
		ByValue:  true,
	}
}

func testGceOf(exts ...Extension) CachedProposal {
	return CachedProposal{
		Proposal: Proposal{ProposalType: ProposalTypeGroupContextExtensions,
			GroupContextExtensions: &GroupContextExtensions{Extensions: exts}},
		ByValue: true,
	}
}

// testRequiredCapabilitiesExtension is a required_capabilities naming one extension type no
// fixture leaf of this package lists, so a capability rule that fires is firing on the
// requirement rather than on something testCapabilities happens to leave out.
func testRequiredCapabilitiesExtension(t *testing.T) Extension {
	t.Helper()
	body, err := syntax.Marshal(&RequiredCapabilities{
		ExtensionTypes: []ExtensionType{ExtensionType(0xF00A)}})
	if err != nil {
		t.Fatalf("marshal required_capabilities: %v", err)
	}
	return Extension{ExtensionType: ExtensionTypeRequiredCapabilities, ExtensionData: body}
}

func testValidationInput(t *testing.T, crypto CryptoProvider, tree *RatchetTree,
	committer LeafIndex, list *ProposalList) *ProposalValidationInput {
	t.Helper()
	return &ProposalValidationInput{
		Crypto: crypto,
		Tree:   tree,
		Context: &GroupContext{Version: ProtocolVersionMls10,
			CipherSuite: CipherSuiteX25519ChaCha20Sha256Ed25519,
			GroupId:     []byte("group"), Epoch: 1},
		Committer: committer,
		List:      list,
		Now:       time.Now(),
	}
}

// ---------------------------------------------------------------------------
// the error class, derived from the file that declares it
// ---------------------------------------------------------------------------

const proposalValidationErrorsFile = "errors_proposal_validation.go"

// proposalValidationOwnedErrors is every value errors_proposal_validation.go declares, keyed by
// its name.
//
// Written out rather than derived at run time, for the reason every other class of this package
// gives: a class computed from the file it is judging agrees with that file whatever the file
// says. TestProposalValidationOwnedErrorsIsEveryErrorItsFileDeclares is what joins the two, in
// both directions, and mlsErrorClasses is what puts all of them inside the package wide
// exclusivity sweep.
var proposalValidationOwnedErrors = map[string]error{
	"ErrAddDuplicateSignatureKey":        ErrAddDuplicateSignatureKey,
	"ErrDuplicateInitKey":                ErrDuplicateInitKey,
	"ErrAddDuplicateEncryptionKey":       ErrAddDuplicateEncryptionKey,
	"ErrInitEqualsEncryptionKey":         ErrInitEqualsEncryptionKey,
	"ErrSuiteMismatch":                   ErrSuiteMismatch,
	"ErrAddMissingRequiredCapability":    ErrAddMissingRequiredCapability,
	"ErrDuplicateRemove":                 ErrDuplicateRemove,
	"ErrRemoveNonMember":                 ErrRemoveNonMember,
	"ErrUpdateMissingRequiredCapability": ErrUpdateMissingRequiredCapability,
	"ErrUpdateDuplicateEncryptionKey":    ErrUpdateDuplicateEncryptionKey,
	"ErrSelfUpdateInCommit":              ErrSelfUpdateInCommit,
	"ErrUpdateSenderNotMember":           ErrUpdateSenderNotMember,
	"ErrRemoveCommitter":                 ErrRemoveCommitter,
	"ErrUpdateOrRemoveSameLeaf":          ErrUpdateOrRemoveSameLeaf,
	"ErrProposalListMisbucketed":         ErrProposalListMisbucketed,
	"ErrProposalListBucketsDisagree":     ErrProposalListBucketsDisagree,
	"errNilProposalValidationInput":      errNilProposalValidationInput,
	"errNilProposalList":                 errNilProposalList,
	"errNilRatchetTree":                  errNilRatchetTree,
}

// TestProposalValidationOwnedErrorsIsEveryErrorItsFileDeclares holds the class to the file in both
// directions, so a seventeenth refusal added by a later task is swept the moment it is declared
// and a name deleted from the file fails here rather than shrinking every sweep in silence.
func TestProposalValidationOwnedErrorsIsEveryErrorItsFileDeclares(t *testing.T) {
	declared := packageLevelDeclarations(t, ".")
	fromFile := []string{}
	for name, file := range declared {
		if file == proposalValidationErrorsFile {
			fromFile = append(fromFile, name)
		}
	}
	slices.Sort(fromFile)
	// the positive control: a scan reading the wrong file reports exactly the clean bill a
	// complete one reports
	if !slices.Contains(fromFile, "ErrRemoveNonMember") {
		t.Fatalf("the scan read %v out of %s, which certainly declares ErrRemoveNonMember, so it is reading something other than that file",
			fromFile, proposalValidationErrorsFile)
	}
	if want := slices.Sorted(maps.Keys(proposalValidationOwnedErrors)); !slices.Equal(fromFile, want) {
		t.Fatalf("%s declares %v and proposalValidationOwnedErrors holds %v; every sweep of this package runs over the second",
			proposalValidationErrorsFile, fromFile, want)
	}
	if _, held := mlsErrorClasses[proposalValidationErrorsFile]; !held {
		t.Fatalf("mlsErrorClasses holds no class for %s, so the package wide exclusivity sweep runs past every one of these",
			proposalValidationErrorsFile)
	}
}

// TestEveryProposalListRefusalIsDistinctFromEveryOther is the one-value-per-rule property, swept
// over the derived class rather than over a slice literal of its own.
//
// Thirteen ValSem codes is thirteen rules, and the plan this task comes from puts five of them on
// three values. errors.Is cannot tell two rules apart when they answer one value, so a sweep over
// every ordered pair is the only statement of the property that survives somebody later deciding
// two of them are "the same thing really".
func TestEveryProposalListRefusalIsDistinctFromEveryOther(t *testing.T) {
	names := slices.Sorted(maps.Keys(proposalValidationOwnedErrors))
	if len(names) != 19 {
		t.Fatalf("the proposal list refusal set holds %d values, this task declares 19", len(names))
	}
	for _, name := range names {
		one := proposalValidationOwnedErrors[name]
		if one == nil {
			t.Fatalf("%s is nil", name)
		}
		if !strings.HasPrefix(one.Error(), "mls: ") {
			t.Errorf("%s reads %q; every refusal this package hands a caller names the package it came from",
				name, one.Error())
		}
		for _, other := range names {
			if name != other && errors.Is(one, proposalValidationOwnedErrors[other]) {
				t.Fatalf("%s and %s are the same value: %v", name, other, one)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// the rule table: one row per rule, derived against the rules the aggregate runs
// ---------------------------------------------------------------------------

// proposalListRuleRow is one rule of the list, the input that breaks it, and the value it must
// answer.
type proposalListRuleRow struct {
	sentinel error
	build    func(t *testing.T, crypto CryptoProvider) *ProposalValidationInput
}

// proposalListRuleName is the declared name of one of the rule functions, read off the value
// rather than written beside it, so a row cannot claim to cover a rule it does not hold.
func proposalListRuleName(rule func(*ProposalValidationInput) error) string {
	full := runtime.FuncForPC(reflect.ValueOf(rule).Pointer()).Name()
	return full[strings.LastIndex(full, ".")+1:]
}

// proposalListRules is every rule ValidateProposalList runs, in the order it runs them, read off
// the three groups the production source declares rather than listed here.
func proposalListRules() []string {
	names := []string{}
	for _, group := range [][]func(*ProposalValidationInput) error{
		proposalListStructuralChecks, proposalListChecks, proposalListCrossChecks} {
		for _, rule := range group {
			names = append(names, proposalListRuleName(rule))
		}
	}
	return names
}

// proposalListRuleRows is the input that breaks each rule and the value that rule must answer.
//
// Every row is built so that every rule the aggregate runs BEFORE it passes, which is what lets
// the sweep assert the same value out of the named function and out of ValidateProposalList. A row
// whose fixture tripped an earlier rule would still pass a test that only called the named
// function, and the aggregate half is what catches it.
func proposalListRuleRows() map[string]proposalListRuleRow {
	return map[string]proposalListRuleRow{
		// a psk proposal, which is registered and outside the v1 profile. It is carried in the
		// commit order and in no bucket, which is what a list assembled around a type this
		// build does not implement looks like.
		"ValSem113ProposalTypeSupported": {sentinel: errProfilePsk,
			build: func(t *testing.T, crypto CryptoProvider) *ProposalValidationInput {
				tree, _ := testTreeWith(t, crypto, "alice")
				psk := CachedProposal{Proposal: Proposal{
					ProposalType: ProposalTypePreSharedKey, PreSharedKey: &PreSharedKey{}}}
				return testValidationInput(t, crypto, tree, LeafIndex(0),
					&ProposalList{All: []CachedProposal{psk}})
			}},
		// a remove sitting in the adds bucket, which is a nil dereference in ValSem101 under
		// any order that runs the duplicate rules first
		"validateProposalBucketsHoldTheirOwnType": {sentinel: ErrProposalListMisbucketed,
			build: func(t *testing.T, crypto CryptoProvider) *ProposalValidationInput {
				tree, _ := testTreeWith(t, crypto, "alice", "bob")
				remove := testRemoveOf(1)
				return testValidationInput(t, crypto, tree, LeafIndex(0), &ProposalList{
					Adds: []CachedProposal{remove}, All: []CachedProposal{remove}})
			}},
		// an add every rule of this file judges and the application walks straight past
		"validateBucketsAgreeWithTheCommitOrder": {sentinel: ErrProposalListBucketsDisagree,
			build: func(t *testing.T, crypto CryptoProvider) *ProposalValidationInput {
				tree, _ := testTreeWith(t, crypto, "alice")
				kp, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "carol"))
				return testValidationInput(t, crypto, tree, LeafIndex(0), &ProposalList{
					Adds: []CachedProposal{testAddOf(kp)}})
			}},
		"validateOneGroupContextExtensions": {sentinel: errMultipleGroupContextExtensions,
			build: func(t *testing.T, crypto CryptoProvider) *ProposalValidationInput {
				tree, _ := testTreeWith(t, crypto, "alice")
				one := testGceOf(Extension{ExtensionType: ExtensionType(0x00FF), ExtensionData: []byte{1}})
				two := testGceOf(Extension{ExtensionType: ExtensionType(0x00FF), ExtensionData: []byte{2}})
				return testValidationInput(t, crypto, tree, LeafIndex(0), testProposalList(t, one, two))
			}},
		// two entries of one commit naming one cached proposal. They remove DIFFERENT leaves,
		// so no content rule of this file could answer instead.
		"validateNoRepeatedProposalReference": {sentinel: errDuplicateProposalReference,
			build: func(t *testing.T, crypto CryptoProvider) *ProposalValidationInput {
				tree, _ := testTreeWith(t, crypto, "alice", "bob", "carol")
				first := testRemoveOf(1)
				first.ByValue, first.Ref = false, ProposalRef([]byte("one-name"))
				second := testRemoveOf(2)
				second.ByValue, second.Ref = false, ProposalRef([]byte("one-name"))
				return testValidationInput(t, crypto, tree, LeafIndex(0), testProposalList(t, first, second))
			}},
		"ValSem101UniqueSignatureKey": {sentinel: ErrAddDuplicateSignatureKey,
			build: func(t *testing.T, crypto CryptoProvider) *ProposalValidationInput {
				tree, _ := testTreeWith(t, crypto, "alice")
				carol := testIdentity(t, crypto, "carol")
				first, _, _ := testKeyPackage(t, crypto, carol)
				second, _, _ := testKeyPackage(t, crypto, carol)
				return testValidationInput(t, crypto, tree, LeafIndex(0),
					testProposalList(t, testAddOf(first), testAddOf(second)))
			}},
		"ValSem102UniqueInitKey": {sentinel: ErrDuplicateInitKey,
			build: func(t *testing.T, crypto CryptoProvider) *ProposalValidationInput {
				tree, _ := testTreeWith(t, crypto, "alice")
				dave, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "dave"))
				erin, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "erin"))
				erin.InitKey = dave.InitKey
				return testValidationInput(t, crypto, tree, LeafIndex(0),
					testProposalList(t, testAddOf(dave), testAddOf(erin)))
			}},
		"ValSem103UniqueEncryptionKey": {sentinel: ErrAddDuplicateEncryptionKey,
			build: func(t *testing.T, crypto CryptoProvider) *ProposalValidationInput {
				tree, _ := testTreeWith(t, crypto, "alice")
				dave, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "dave"))
				erin, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "erin"))
				erin.LeafNode.EncryptionKey = dave.LeafNode.EncryptionKey
				return testValidationInput(t, crypto, tree, LeafIndex(0),
					testProposalList(t, testAddOf(dave), testAddOf(erin)))
			}},
		"ValSem104InitNotEqualEncryptionKey": {sentinel: ErrInitEqualsEncryptionKey,
			build: func(t *testing.T, crypto CryptoProvider) *ProposalValidationInput {
				tree, _ := testTreeWith(t, crypto, "alice")
				dave, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "dave"))
				dave.InitKey = HpkePublicKey(dave.LeafNode.EncryptionKey)
				return testValidationInput(t, crypto, tree, LeafIndex(0),
					testProposalList(t, testAddOf(dave)))
			}},
		"ValSem105SuiteAndVersionMatch": {sentinel: ErrSuiteMismatch,
			build: func(t *testing.T, crypto CryptoProvider) *ProposalValidationInput {
				tree, _ := testTreeWith(t, crypto, "alice")
				dave, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "dave"))
				dave.Version = ProtocolVersion(0x0002)
				return testValidationInput(t, crypto, tree, LeafIndex(0),
					testProposalList(t, testAddOf(dave)))
			}},
		"ValSem106RequiredCapabilitiesSatisfied": {sentinel: ErrAddMissingRequiredCapability,
			build: func(t *testing.T, crypto CryptoProvider) *ProposalValidationInput {
				tree, _ := testTreeWith(t, crypto, "alice")
				dave, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "dave"))
				in := testValidationInput(t, crypto, tree, LeafIndex(0),
					testProposalList(t, testAddOf(dave)))
				in.Context.Extensions = []Extension{testRequiredCapabilitiesExtension(t)}
				return in
			}},
		"ValSem107UniqueRemove": {sentinel: ErrDuplicateRemove,
			build: func(t *testing.T, crypto CryptoProvider) *ProposalValidationInput {
				tree, _ := testTreeWith(t, crypto, "alice", "bob")
				return testValidationInput(t, crypto, tree, LeafIndex(0),
					testProposalList(t, testRemoveOf(1), testRemoveOf(1)))
			}},
		"ValSem108RemoveExists": {sentinel: ErrRemoveNonMember,
			build: func(t *testing.T, crypto CryptoProvider) *ProposalValidationInput {
				tree, _ := testTreeWith(t, crypto, "alice", "bob")
				return testValidationInput(t, crypto, tree, LeafIndex(0),
					testProposalList(t, testRemoveOf(9)))
			}},
		"ValSem109UpdateRequiredCapabilities": {sentinel: ErrUpdateMissingRequiredCapability,
			build: func(t *testing.T, crypto CryptoProvider) *ProposalValidationInput {
				tree, members := testTreeWith(t, crypto, "alice", "bob")
				leaf, _ := testLeafNode(t, crypto, members[1])
				in := testValidationInput(t, crypto, tree, LeafIndex(0),
					testProposalList(t, testUpdateOf(1, leaf)))
				in.Context.Extensions = []Extension{testRequiredCapabilitiesExtension(t)}
				return in
			}},
		// bob's update republishes carol's encryption key, which no member may hold twice
		"ValSem110UpdateUniqueEncryptionKey": {sentinel: ErrUpdateDuplicateEncryptionKey,
			build: func(t *testing.T, crypto CryptoProvider) *ProposalValidationInput {
				tree, members := testTreeWith(t, crypto, "alice", "bob", "carol")
				leaf, _ := testLeafNode(t, crypto, members[1])
				leaf.EncryptionKey = tree.Leaf(2).EncryptionKey
				return testValidationInput(t, crypto, tree, LeafIndex(0),
					testProposalList(t, testUpdateOf(1, leaf)))
			}},
		"ValSem111NoCommitterUpdate": {sentinel: ErrSelfUpdateInCommit,
			build: func(t *testing.T, crypto CryptoProvider) *ProposalValidationInput {
				tree, members := testTreeWith(t, crypto, "alice", "bob")
				leaf, _ := testLeafNode(t, crypto, members[0])
				return testValidationInput(t, crypto, tree, LeafIndex(0),
					testProposalList(t, testUpdateOf(0, leaf)))
			}},
		"ValSem112UpdateSenderIsMember": {sentinel: ErrUpdateSenderNotMember,
			build: func(t *testing.T, crypto CryptoProvider) *ProposalValidationInput {
				tree, members := testTreeWith(t, crypto, "alice", "bob")
				leaf, _ := testLeafNode(t, crypto, members[1])
				return testValidationInput(t, crypto, tree, LeafIndex(0),
					testProposalList(t, testUpdateOf(9, leaf)))
			}},
		// an update and a remove landing on one leaf. Two removes would be ValSem107's, which
		// is why this pair is mixed.
		"validateSingleUpdateOrRemovePerLeaf": {sentinel: ErrUpdateOrRemoveSameLeaf,
			build: func(t *testing.T, crypto CryptoProvider) *ProposalValidationInput {
				tree, members := testTreeWith(t, crypto, "alice", "bob")
				leaf, _ := testLeafNode(t, crypto, members[1])
				return testValidationInput(t, crypto, tree, LeafIndex(0),
					testProposalList(t, testUpdateOf(1, leaf), testRemoveOf(1)))
			}},
		"validateCommitterIsNotRemoved": {sentinel: ErrRemoveCommitter,
			build: func(t *testing.T, crypto CryptoProvider) *ProposalValidationInput {
				tree, _ := testTreeWith(t, crypto, "alice", "bob")
				return testValidationInput(t, crypto, tree, LeafIndex(0),
					testProposalList(t, testRemoveOf(0)))
			}},
	}
}

// TestEachProposalListRuleAnswersOnlyItsOwnSentinel is the property the whole of this task turns
// on, and it is the reason the sentinels are not shared.
//
// Three claims per row, and they are different claims. The named function must answer its own
// value, which is ledger 17's rule that a refusal owes a test naming its sentinel. NO OTHER ROW'S
// value may answer, which is what "thirteen rules" means and is invisible to a test that only
// asserts the positive half: five of these rules answered three values in the plan as written, and
// every positive assertion over them passed. And ValidateProposalList must answer the SAME value,
// which says the aggregate reaches this rule with this input rather than tripping over an earlier
// one -- a fixture that failed two rules would satisfy the first two claims and hide the second
// rule entirely.
func TestEachProposalListRuleAnswersOnlyItsOwnSentinel(t *testing.T) {
	crypto := testCrypto(t)
	rows := proposalListRuleRows()
	for _, name := range slices.Sorted(maps.Keys(rows)) {
		row := rows[name]
		t.Run(name, func(t *testing.T) {
			in := row.build(t, crypto)
			ruled := proposalListRuleFor(t, name)(in)
			if !errors.Is(ruled, row.sentinel) {
				t.Fatalf("%s answered %v, want %v", name, ruled, row.sentinel)
			}
			for _, other := range slices.Sorted(maps.Keys(rows)) {
				if other == name {
					continue
				}
				if errors.Is(ruled, rows[other].sentinel) {
					t.Errorf("%s answers %s's value as well, so errors.Is cannot tell the two rules apart",
						name, other)
				}
			}
			aggregated := ValidateProposalList(in)
			if !errors.Is(aggregated, row.sentinel) {
				t.Fatalf("ValidateProposalList over the %s fixture answered %v, want %v; the aggregate is reaching a different rule with this input",
					name, aggregated, row.sentinel)
			}
		})
	}
}

// proposalListRuleFor answers the rule function of that name out of the groups the production
// source declares, so a row is joined to a rule the aggregate actually runs.
func proposalListRuleFor(t *testing.T, name string) func(*ProposalValidationInput) error {
	t.Helper()
	for _, group := range [][]func(*ProposalValidationInput) error{
		proposalListStructuralChecks, proposalListChecks, proposalListCrossChecks} {
		for _, rule := range group {
			if proposalListRuleName(rule) == name {
				return rule
			}
		}
	}
	t.Fatalf("no rule of ValidateProposalList is named %s", name)
	return nil
}

// TestEveryRuleTheAggregateRunsHasARowAndEveryRowIsARuleItRuns holds the table above to the
// production groups in both directions.
//
// Without it the table is a list, and a list is what rule 5 exists about: a fourteenth ValSem code
// added to proposalListChecks with no row would be run by the aggregate and asserted by nothing,
// and a row naming a rule that had been deleted would go on reporting a clean bill over a rule
// that no longer exists.
func TestEveryRuleTheAggregateRunsHasARowAndEveryRowIsARuleItRuns(t *testing.T) {
	rules := proposalListRules()
	rows := proposalListRuleRows()
	if !slices.Contains(rules, "ValSem108RemoveExists") {
		t.Fatalf("the rule groups read as %v, and ValidateProposalList certainly runs ValSem108RemoveExists, so the names are being read off something else",
			rules)
	}
	for _, name := range rules {
		if _, written := rows[name]; !written {
			t.Errorf("ValidateProposalList runs %s and no row builds an input that breaks it, so nothing here says what that rule refuses",
				name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(rows)) {
		if !slices.Contains(rules, name) {
			t.Errorf("a row names %s and ValidateProposalList runs no rule under that name", name)
		}
	}
	// and every rule is named once: a function repeated across two groups would be run twice
	// and would make the group ordering above unreadable
	seen := map[string]bool{}
	for _, name := range rules {
		if seen[name] {
			t.Errorf("%s appears in more than one of the rule groups", name)
		}
		seen[name] = true
	}
}

// proposalListRulesDeclared is every rule validate_proposals.go declares, read off the SIGNATURE
// rather than off a name.
//
// The shape is the class: a package level function taking one *ProposalValidationInput and
// answering one error is a rule of this file and there is nothing else it could be. Deriving on
// the ValSem prefix instead would cover the thirteen codes and leave the six rules that carry no
// code outside the coverage gate entirely -- the two structural ones, the bucket count, the
// single GCE, the same-leaf rule and the remove-the-committer rule. That is rule 5s shortfall
// exactly: a class stated over the members somebody remembered rather than over the ones that
// exist.
func proposalListRulesDeclared(t *testing.T) []string {
	t.Helper()
	parsed := mustParseSource(t, "validate_proposals.go")
	found := []string{}
	for _, declaration := range parsed.file.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if !isFunction || function.Recv != nil || function.Type.Params == nil {
			continue
		}
		if len(function.Type.Params.List) != 1 ||
			parsed.render(function.Type.Params.List[0].Type) != "*ProposalValidationInput" {
			continue
		}
		if function.Type.Results == nil || len(function.Type.Results.List) != 1 ||
			parsed.render(function.Type.Results.List[0].Type) != "error" {
			continue
		}
		// the aggregate is not one of its own rules
		if function.Name.Name == "ValidateProposalList" {
			continue
		}
		found = append(found, function.Name.Name)
	}
	slices.Sort(found)
	return found
}

// TestValidateProposalListRunsEveryRuleThisFileDeclares derives the rule set from the source
// rather than counting it here.
//
// The aggregate holds its rules in three slice literals. A slice literal is a transcription, and
// the failure it has on this project is the quiet one: a rule declared, documented and never run.
// So the class is every rule-shaped function validate_proposals.go declares, held in both
// directions, and the thirteen ValSem codes are counted inside it -- because "thirteen" is a claim
// about RFC 9420 section 12.2 rather than about this file.
func TestValidateProposalListRunsEveryRuleThisFileDeclares(t *testing.T) {
	declared := proposalListRulesDeclared(t)
	if !slices.Contains(declared, "ValSem108RemoveExists") {
		t.Fatalf("the signature scan read %v out of validate_proposals.go, which certainly declares ValSem108RemoveExists, so it is reading something else",
			declared)
	}
	codes := []string{}
	for _, name := range declared {
		if strings.HasPrefix(name, "ValSem") {
			codes = append(codes, name)
		}
	}
	if len(codes) != 13 {
		t.Fatalf("validate_proposals.go declares %d ValSem functions (%v), RFC 9420 section 12.2 as this plan states it is thirteen",
			len(codes), codes)
	}
	run := proposalListRules()
	for _, name := range declared {
		if !slices.Contains(run, name) {
			t.Errorf("%s is declared and ValidateProposalList runs %v, so that rule is documented and reached by nothing",
				name, run)
		}
	}
	for _, name := range run {
		if !slices.Contains(declared, name) {
			t.Errorf("ValidateProposalList runs %s and validate_proposals.go declares no rule of that name", name)
		}
	}
}

// TestEveryBucketOfAProposalListIsNamedByTheBucketRule derives the bucket set from the struct.
//
// proposalBucketsOf is four rows written by hand, and four rows written by hand is the shape that
// understates its class the moment a fifth bucket is added -- a psk bucket, when the profile
// widens. So the class is read off ProposalList itself: every []CachedProposal field must be
// named, except the one field that is the commit order rather than a bucket, which is excluded by
// name and with its reason.
func TestEveryBucketOfAProposalListIsNamedByTheBucketRule(t *testing.T) {
	const commitOrderField = "All"
	named := []string{}
	for _, bucket := range proposalBucketsOf(&ProposalList{}) {
		named = append(named, bucket.field)
	}
	slices.Sort(named)
	fields := []string{}
	structure := reflect.TypeOf(ProposalList{})
	for i := 0; i < structure.NumField(); i += 1 {
		field := structure.Field(i)
		if field.Type != reflect.TypeOf([]CachedProposal{}) || field.Name == commitOrderField {
			continue
		}
		fields = append(fields, field.Name)
	}
	slices.Sort(fields)
	if len(fields) == 0 {
		t.Fatal("ProposalList declares no []CachedProposal bucket at all, so this gate read something other than the struct")
	}
	if !slices.Equal(named, fields) {
		t.Fatalf("ProposalList's buckets are %v and proposalBucketsOf names %v; a bucket nothing names is judged by no rule of validate_proposals.go and applied by nothing",
			fields, named)
	}
	// and the exclusion is real rather than a name nobody declares
	if _, found := structure.FieldByName(commitOrderField); !found {
		t.Fatalf("ProposalList declares no %s field, so the one exclusion this gate makes is excluding nothing",
			commitOrderField)
	}
}

// TestEveryProposalValidationEntryPointRefusesANilInput drives every door of this file with
// nothing.
//
// A panic out of a library is not a refusal: it takes the caller's process rather than its call
// and says nothing about which argument was wrong. The class is the rules the production source
// declares rather than a list, and the four shapes are the four ways an input can be missing the
// thing a rule reads -- the input itself, the list, the tree, the context -- because a guard that
// only covered the outermost of them would leave the other three as dereferences.
func TestEveryProposalValidationEntryPointRefusesANilInput(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice")
	shapes := map[string]struct {
		in       *ProposalValidationInput
		sentinel error
	}{
		"a nil input":    {nil, errNilProposalValidationInput},
		"no list":        {&ProposalValidationInput{Tree: tree, Context: &GroupContext{}}, errNilProposalList},
		"no tree":        {&ProposalValidationInput{List: &ProposalList{}, Context: &GroupContext{}}, errNilRatchetTree},
		"no context":     {&ProposalValidationInput{List: &ProposalList{}, Tree: tree}, ErrNilGroupContext},
		"nothing at all": {&ProposalValidationInput{}, errNilProposalList},
	}
	doors := map[string]func(*ProposalValidationInput) error{"ValidateProposalList": ValidateProposalList}
	for _, name := range proposalListRules() {
		doors[name] = proposalListRuleFor(t, name)
	}
	if len(doors) < 14 {
		t.Fatalf("the sweep found %d doors, and this file declares thirteen ValSem codes plus the aggregate at least", len(doors))
	}
	for _, name := range slices.Sorted(maps.Keys(doors)) {
		for _, shape := range slices.Sorted(maps.Keys(shapes)) {
			answered := proposalValidationRefusalOf(t, name+" with "+shape, doors[name], shapes[shape].in)
			if !errors.Is(answered, shapes[shape].sentinel) {
				t.Errorf("%s with %s answered %v, want %v", name, shape, answered, shapes[shape].sentinel)
			}
		}
	}
}

// proposalValidationRefusalOf runs one door and turns a panic into the error it should have been,
// so one door dereferencing its input is a failure of its own case rather than the end of the
// sweep.
func proposalValidationRefusalOf(t *testing.T, what string,
	door func(*ProposalValidationInput) error, in *ProposalValidationInput) (answered error) {
	t.Helper()
	defer func() {
		if panicked := recover(); panicked != nil {
			t.Errorf("%s panicked with %v; a panic out of a library takes the caller's process rather than its call",
				what, panicked)
			answered = nil
		}
	}()
	return door(in)
}

// ---------------------------------------------------------------------------
// the positive half, and the rules whose fixtures are worth reading on their own
// ---------------------------------------------------------------------------

// TestValidateProposalListAcceptsAValidList is the control every negative row above is measured
// against: with none of the nineteen rules broken, the aggregate accepts.
func TestValidateProposalListAcceptsAValidList(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "alice", "bob", "carol")
	kp, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "dave"))
	leaf, _ := testLeafNode(t, crypto, members[1])
	list := testProposalList(t, testUpdateOf(1, leaf), testRemoveOf(2), testAddOf(kp))
	if err := ValidateProposalList(testValidationInput(t, crypto, tree, LeafIndex(0), list)); err != nil {
		t.Fatalf("ValidateProposalList: %v", err)
	}
}

// TestValSem101AcceptsAnAddOfAMemberTheSameListRemoves is RFC 9420 section 12.2's "unless there is
// a Remove proposal in the list removing the matching client from the group".
//
// It is the clause that makes a device replacing itself in one commit legal, and it is invisible
// to the duplicate test next to it: a ValSem101 written without the exemption refuses this list,
// and every OTHER test of ValSem101 passes over that version.
func TestValSem101AcceptsAnAddOfAMemberTheSameListRemoves(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "alice", "bob")
	// bob's own signature key, arriving again in a key package, beside a remove of bob's leaf
	kp, _, _ := testKeyPackage(t, crypto, members[1])
	list := testProposalList(t, testRemoveOf(1), testAddOf(kp))
	in := testValidationInput(t, crypto, tree, LeafIndex(0), list)
	if err := ValSem101UniqueSignatureKey(in); err != nil {
		t.Fatalf("ValSem101 over a rejoin refused it: %v", err)
	}
	// and the same list without the remove is the refusal, which is what says the exemption is
	// doing the work rather than the fixture being toothless
	without := testProposalList(t, testAddOf(kp))
	if err := ValSem101UniqueSignatureKey(testValidationInput(t, crypto, tree, LeafIndex(0), without)); !errors.Is(err, ErrAddDuplicateSignatureKey) {
		t.Fatalf("ValSem101 over the same add with no remove answered %v, want %v", err, ErrAddDuplicateSignatureKey)
	}
}

// TestValSem110ExcludesAnUpdatingLeafsOwnOutgoingKey is the other half of ValSem110's members'
// loop.
//
// A leaf's outgoing encryption key is exactly the key its own update replaces, so a members' loop
// that did not exclude the leaves this list updates would refuse every update that republished
// anything -- and the duplicate row above passes over that version, because a key collision is a
// key collision whichever leaf it came from.
func TestValSem110ExcludesAnUpdatingLeafsOwnOutgoingKey(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "alice", "bob")
	leaf, _ := testLeafNode(t, crypto, members[1])
	// bob republishing the key bob's leaf already holds: legal, because that leaf is being
	// replaced by this very proposal
	leaf.EncryptionKey = tree.Leaf(1).EncryptionKey
	in := testValidationInput(t, crypto, tree, LeafIndex(0), testProposalList(t, testUpdateOf(1, leaf)))
	if err := ValSem110UpdateUniqueEncryptionKey(in); err != nil {
		t.Fatalf("ValSem110 refused a leaf republishing its own outgoing key: %v", err)
	}
}

// TestValSem106ReadsTheExtensionsAGroupContextExtensionsProposalInTheSameListAdds is RFC 9420
// section 12.3's "The new extensions MUST be used when evaluating other proposals in this list".
//
// The group context here requires nothing, so a ValSem106 reading only the context accepts; the
// list's own GCE proposal is what makes the add illegal, and that is the whole rule.
func TestValSem106ReadsTheExtensionsAGroupContextExtensionsProposalInTheSameListAdds(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice")
	kp, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "dave"))
	list := testProposalList(t, testGceOf(testRequiredCapabilitiesExtension(t)), testAddOf(kp))
	in := testValidationInput(t, crypto, tree, LeafIndex(0), list)
	if err := ValSem106RequiredCapabilitiesSatisfied(in); !errors.Is(err, ErrAddMissingRequiredCapability) {
		t.Fatalf("ValSem106 answered %v, want %v; the requirement this commit adds is not being read",
			err, ErrAddMissingRequiredCapability)
	}
	// the control: the same add with no GCE beside it is accepted, so the refusal above is the
	// proposal's doing rather than the fixture's
	if err := ValSem106RequiredCapabilitiesSatisfied(testValidationInput(t, crypto, tree,
		LeafIndex(0), testProposalList(t, testAddOf(kp)))); err != nil {
		t.Fatalf("ValSem106 refused an add under a group requiring nothing: %v", err)
	}
}

// TestRequiredCapabilitiesThatCannotBeReadIsARefusalRatherThanNoRequirement is the one place this
// file departs from the plan's sketch, and it is a security departure rather than a taste one.
//
// The sketch answers "(nil, false)" for a required_capabilities whose body does not decode and for
// a vector carrying the extension twice, which reads as "the group requires nothing" -- so a
// malformed extension would admit a member who supports none of it, and would be strictly better
// for an attacker than a well formed one.
func TestRequiredCapabilitiesThatCannotBeReadIsARefusalRatherThanNoRequirement(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice")
	kp, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "dave"))
	list := testProposalList(t, testAddOf(kp))
	for name, exts := range map[string][]Extension{
		"a body that does not decode": {{ExtensionType: ExtensionTypeRequiredCapabilities,
			ExtensionData: []byte{0xff, 0xff, 0xff}}},
		"the extension twice": {testRequiredCapabilitiesExtension(t), testRequiredCapabilitiesExtension(t)},
	} {
		in := testValidationInput(t, crypto, tree, LeafIndex(0), list)
		in.Context.Extensions = exts
		for rule, run := range map[string]func(*ProposalValidationInput) error{
			"ValSem106": ValSem106RequiredCapabilitiesSatisfied,
			"ValSem109": ValSem109UpdateRequiredCapabilities,
		} {
			if err := run(in); !errors.Is(err, ErrMalformedExtension) {
				t.Errorf("%s over %s answered %v, want %v", rule, name, err, ErrMalformedExtension)
			}
		}
	}
}

// TestValSem113AnswersTheProfileGatesOwnValueForEveryTypeItRefuses says the delegation is complete
// rather than covering the one type a single fixture happens to use.
//
// The class is READ OFF proposalTypeProfile rather than listed, which matters because the point of
// ValSem113 is that there is exactly one table of what the v1 profile accepts: a fixture list of
// three or four types would be a second, shorter statement of that table, and the first code point
// whose disposition changed would leave the two disagreeing with nothing to say so. The profile
// table is itself held to the registry in both directions by
// TestTheV1ProfileClassifiesEveryRegisteredProposalType, so this is derived from a derived class.
//
// No arm is built for any row, and that is not laziness: checkProposalProfile judges the TYPE
// before it looks at the arm, so a refused type is refused whatever it carries -- and a row that
// supplied the matching arm would be asserting the same thing through more fixture. The
// unregistered code point is the one row the table cannot supply, because a table of the registry
// has no member outside it.
func TestValSem113AnswersTheProfileGatesOwnValueForEveryTypeItRefuses(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice")
	answered := func(proposal Proposal) error {
		return ValSem113ProposalTypeSupported(testValidationInput(t, crypto, tree, LeafIndex(0),
			&ProposalList{All: []CachedProposal{{Proposal: proposal}}}))
	}
	refused := 0
	for _, code := range slices.Sorted(maps.Keys(proposalTypeProfile)) {
		want := proposalTypeProfile[code]
		if want == nil {
			// a type this profile accepts. It is refused here anyway, by the arm check,
			// which is a different rule and is why nothing is asserted about its value.
			continue
		}
		refused += 1
		if err := answered(Proposal{ProposalType: code}); !errors.Is(err, want) {
			t.Errorf("ValSem113 over a %s proposal answered %v, and the v1 profile refuses that code point with %v",
				proposalTypeName(code), err, want)
		}
	}
	if refused == 0 {
		t.Fatal("the v1 profile table refuses no registered proposal type at all, so this sweep asserted nothing")
	}
	// and a code point outside the registry, which is the one member of the class the table
	// cannot hold
	if err := answered(Proposal{ProposalType: ProposalType(0x1A1A), UnknownBody: []byte{1}}); !errors.Is(err, errUnregisteredProposalType) {
		t.Errorf("ValSem113 over an unregistered code point answered %v, want %v", err, errUnregisteredProposalType)
	}
	t.Logf("%d registered proposal types the v1 profile refuses, each answered through ValSem113", refused)
}

// TestValSem113ReadsTheBucketsAndNotOnlyTheCommitOrder is what makes the twelve rules below it
// safe to write.
//
// A proposal reachable through a bucket and absent from All would otherwise be judged by no arm
// check at all, and the rules that read that bucket dereference the arm. The fixture is an Add
// whose Add arm is nil, in the Adds bucket, which is a nil dereference in ValSem101 under any
// version that swept the commit order alone.
func TestValSem113ReadsTheBucketsAndNotOnlyTheCommitOrder(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice")
	armless := CachedProposal{Proposal: Proposal{ProposalType: ProposalTypeAdd}}
	in := testValidationInput(t, crypto, tree, LeafIndex(0),
		&ProposalList{Adds: []CachedProposal{armless}})
	if err := ValSem113ProposalTypeSupported(in); err == nil {
		t.Fatal("ValSem113 accepted an add with no add arm sitting in the adds bucket")
	}
	// and the aggregate refuses it rather than dereferencing it
	if err := proposalValidationRefusalOf(t, "ValidateProposalList over an armless bucketed add",
		ValidateProposalList, in); err == nil {
		t.Fatal("ValidateProposalList accepted an add with no add arm")
	}
}
