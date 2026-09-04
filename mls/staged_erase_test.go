// The erase obligation, stated over the CLASS of types this package holds key material inside
// rather than over the two calls that were missing from it.
//
// What was missing, and what it cost. (*Group).Close zeroized self.schedule and self.secretTree
// and never touched self.pending, and (*Group).ClearPendingCommit was literally self.pending =
// nil. A StagedCommit is a complete second epoch -- its own key schedule, holding the init
// secret, the confirmation key, the encryption secret, the epoch authenticator, the exporter and
// the resumption PSK; its own secret tree, holding every message key derived from that encryption
// secret; and the leaf private key the committer drew for the epoch its commit would open -- and
// nothing in this package called Zeroize on any of it. Measured before the repair: snapshot the
// staged epoch's init secret, its confirmation key and its leaf private key, call Close, and all
// three read back byte for byte.
//
// AND CLEARING ONE IS THE ORDINARY PATH. ClearPendingCommit exists for MASTER section 9.3's
// lost-commit race: the delivery service accepts at most one commit per (group, epoch), so a
// client whose commit lost that race drops a fully derived epoch nobody ever entered. That is not
// an edge case, it is what happens whenever two members commit at once.
//
// So the fix is not two calls. Every type here that holds key material owes an erase, and every
// path that drops such a value has to take it, and both halves are read off the source below:
//
//   - the CLASS is derived. Its seed is the types that declare an erase -- read off the erase
//     helper class this package already derives, so a type joins by erasing rather than by being
//     listed -- and it is closed upward over holders: a type with a field whose type names a
//     member is a member, which is exactly how a StagedCommit holding a *KeySchedule and
//     declaring no erase becomes a failure rather than an omission.
//   - the FIELDS are derived: every field of a member whose type reaches byte storage, with the
//     ones that are not key material carrying a row that says why, checked in both directions so
//     a field cannot fall out of the class by being forgotten and a row cannot outlive its field.
//   - and the DROP SITES are derived: every assignment a member's own method makes to one of
//     those fields, which must erase the value it drops, install it, or refuse to overwrite a
//     live one.
//
// What this cannot see, said out loud. The assignment reading is rooted in the positions a
// CALLER fills -- the receiver and the parameters -- so a body that constructs a member itself
// and writes over a field of it is outside this, deliberately: nothing was handed to it and
// nothing of anybody else's is dropped. A value handed OUT of this package and dropped by its
// new holder is that holder's obligation and not this one's, which is what PathDecryptResult's
// row says. And the erase of a SUB-field of a value being moved out is read by the callee's bare
// name, so a namesake of an erase would certify one -- the install half beside it is resolved
// exactly, and it is the half that says a merge moved rather than dropped.
package mls

import (
	"errors"
	"fmt"
	"go/ast"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// ---------------------------------------------------------------------------
// what a staged epoch is holding, and what happens to it
// ---------------------------------------------------------------------------

// stagedEpochStorage is every secret the staged epoch is holding, as the slices the epoch itself
// is using rather than copies of them.
//
// The slices and not their contents, because that is the only reading that can observe an erase
// at all: zeroizeSecret writes through the backing array, so a test holding a copy would see the
// copy afterwards and report a clean erase over a schedule that never ran one.
//
// Every entry is checked to be non-zero before it is answered, which is the live control. "All
// zero afterwards" is satisfied by storage that was already zero, and a fixture that had stopped
// deriving an epoch would pass every assertion below while observing nothing.
func stagedEpochStorage(t *testing.T, staged *StagedCommit) map[string][]byte {
	t.Helper()
	if staged == nil {
		t.Fatal("no commit is staged, so the erase below is over nothing")
	}
	held := map[string][]byte{
		"schedule.init_secret":         staged.schedule.Secrets().InitSecret,
		"schedule.confirmation_key":    staged.schedule.Secrets().Confirmation,
		"schedule.encryption_secret":   staged.schedule.Secrets().Encryption,
		"schedule.epoch_authenticator": staged.schedule.Secrets().EpochAuthenticator,
		"schedule.resumption_psk":      staged.schedule.Secrets().ResumptionPsk,
		"ownPriv.encryption_priv":      staged.ownPriv.EncryptionPriv,
	}
	for x, secret := range staged.secretTree.nodes {
		held[fmt.Sprintf("secretTree.node[%d]", x)] = secret
	}
	for x, secret := range staged.ownPriv.PathSecrets {
		held[fmt.Sprintf("ownPriv.path_secret[%d]", x)] = secret
	}
	if staged.plan != nil {
		held["plan.commit_secret"] = staged.plan.CommitSecret
		for i, secret := range staged.plan.PathSecrets {
			held[fmt.Sprintf("plan.path_secret[%d]", i)] = secret
		}
	}
	for name, secret := range held {
		if len(secret) == 0 {
			t.Fatalf("%s is empty in the staged epoch, so an all zero reading afterwards would say nothing", name)
		}
		if !slices.ContainsFunc(secret, func(b byte) bool { return b != 0 }) {
			t.Fatalf("%s is already all zero before the erase, so an all zero reading afterwards would say nothing", name)
		}
	}
	return held
}

// requireErased fails on the first byte of any entry that survived.
func requireErased(t *testing.T, at string, held map[string][]byte) {
	t.Helper()
	for _, name := range slices.Sorted(maps.Keys(held)) {
		for i, b := range held[name] {
			if b != 0 {
				t.Errorf("%s: byte %d of %s is %#02x, want 0; the staged epoch was dropped with its key material still in it",
					at, i, name, b)
				break
			}
		}
	}
}

// TestClosingAGroupErasesTheEpochItStagedAndNeverEntered is the first half of the measurement
// this file exists for, run the other way round.
func TestClosingAGroupErasesTheEpochItStagedAndNeverEntered(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	if _, err := group.CreateCommit(nil, nil, nil); err != nil {
		t.Fatalf("CreateCommit: %v", err)
	}
	staged := group.stagedForTest()
	held := stagedEpochStorage(t, staged)

	if err := group.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	requireErased(t, "Close", held)
	// and the staged secret tree refuses rather than answering out of zeros, which is the half
	// (*SecretTree).Zeroize's own comment calls load bearing.
	if !staged.secretTree.erased {
		t.Error("the staged secret tree is not marked erased, so every method of it still answers -- out of Nh zero bytes, with no error, which is a key every party in the world can compute")
	}
	if !staged.ownPriv.erased {
		t.Error("the staged private tree state is not marked erased, so its leaf arm still answers a key")
	}
}

// TestClearPendingCommitErasesTheStagedEpoch is the same erase on the path it is actually taken
// on: not a close, but the lost-commit race of MASTER section 9.3.
func TestClearPendingCommitErasesTheStagedEpoch(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	if _, err := group.CreateCommit(nil, nil, nil); err != nil {
		t.Fatalf("CreateCommit: %v", err)
	}
	staged := group.stagedForTest()
	held := stagedEpochStorage(t, staged)

	group.ClearPendingCommit()
	requireErased(t, "ClearPendingCommit", held)
	if group.stagedForTest() != nil {
		t.Fatal("ClearPendingCommit left a commit staged")
	}
	// and the group is still usable in the epoch it never left, which is the whole point of the
	// method: a clear that took the live epoch with it would turn a lost race into a dead client.
	if len(group.EpochAuthenticator()) == 0 {
		t.Error("the group answers no epoch authenticator after clearing a staged commit")
	}
	if _, err := group.CreateCommit(nil, nil, nil); err != nil {
		t.Errorf("CreateCommit after ClearPendingCommit: %v; the group cannot build another commit against the epoch it is still in", err)
	}
}

// TestClearingAnAddOnlyCommitLeavesTheLiveEpochsLeafKeyIntact is the control on the erase above,
// and it is the input that separates the two programs.
//
// An add-only commit needs no update path (RFC 9420 section 12.4), so the staged epoch carries
// this client's leaf private state FORWARD rather than replacing it. Before CreateCommit cloned
// it, the staged commit and the live group held ONE *TreeKEMPrivate -- so an erase of the staged
// epoch on this path erased the key the group is still decrypting update paths with, on the
// ordinary lost-commit race, and every commit this client received afterwards failed to open
// with a message about a ciphertext that was perfectly well formed.
func TestClearingAnAddOnlyCommitLeavesTheLiveEpochsLeafKeyIntact(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	joiner := testIdentity(t, crypto, "bob")
	kp, _, _ := testKeyPackage(t, crypto, joiner)
	encoded, err := syntax.Marshal(kp)
	if err != nil {
		t.Fatalf("marshal the joiner's key package: %v", err)
	}
	if _, err := group.ProposeAdd(encoded); err != nil {
		t.Fatalf("ProposeAdd: %v", err)
	}
	if _, err := group.CreateCommit(nil, nil, nil); err != nil {
		t.Fatalf("CreateCommit: %v", err)
	}
	staged := group.stagedForTest()
	if staged.plan != nil {
		t.Fatal("the add-only commit carries an update path, so it is not the shape this control is about")
	}
	if staged.ownPriv == group.ownPriv {
		t.Fatal("the staged commit and the live group hold the same *TreeKEMPrivate; erasing the staged epoch erases the epoch the group is still in")
	}
	live := append([]byte(nil), group.ownPriv.EncryptionPriv...)
	if !slices.ContainsFunc(live, func(b byte) bool { return b != 0 }) {
		t.Fatal("the live leaf private key is already all zero, so this control observes nothing")
	}

	group.ClearPendingCommit()

	if !slices.Equal(group.ownPriv.EncryptionPriv, live) {
		t.Errorf("clearing the staged commit changed the LIVE epoch's leaf private key; the staged epoch was sharing storage with the group it was staged against")
	}
	if group.ownPriv.erased {
		t.Error("clearing the staged commit marked the live epoch's private tree state erased")
	}
	if _, _, err := group.ownPriv.NodePrivateKey(crypto, group.ownLeaf.NodeIndex()); err != nil {
		t.Errorf("the live epoch's own leaf answers %v after a staged commit was cleared", err)
	}
}

// TestMergePendingCommitErasesTheEpochItClosed is the third drop site, and the one nothing was
// asking about: a merge REPLACES the schedule, the secret tree and the leaf private state, and
// there is no past-epoch window in this build to hand the outgoing ones to.
func TestMergePendingCommitErasesTheEpochItClosed(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	closing := map[string][]byte{
		"schedule.init_secret":       group.schedule.Secrets().InitSecret,
		"schedule.confirmation_key":  group.schedule.Secrets().Confirmation,
		"schedule.encryption_secret": group.schedule.Secrets().Encryption,
		"ownPriv.encryption_priv":    append([]byte(nil), group.ownPriv.EncryptionPriv...),
	}
	closingPriv := group.ownPriv
	for name, secret := range closing {
		if !slices.ContainsFunc(secret, func(b byte) bool { return b != 0 }) {
			t.Fatalf("%s is already all zero before the merge, so an all zero reading afterwards would say nothing", name)
		}
	}
	// read the live slice back for the leaf key: the copy above is what the erase must NOT reach,
	// and the slice itself is what it must.
	closing["ownPriv.encryption_priv"] = closingPriv.EncryptionPriv

	if _, err := group.CreateCommit(nil, nil, nil); err != nil {
		t.Fatalf("CreateCommit: %v", err)
	}
	staged := group.stagedForTest()
	plan := staged.plan
	if plan == nil {
		t.Fatal("the commit carries no update path, so the plan this merge has to erase does not exist")
	}
	planSecret := plan.CommitSecret
	if err := group.MergePendingCommit(); err != nil {
		t.Fatalf("MergePendingCommit: %v", err)
	}

	requireErased(t, "MergePendingCommit", closing)
	for i, b := range planSecret {
		if b != 0 {
			t.Errorf("byte %d of the update path plan's commit secret is %#02x after the merge, want 0; the plan is the one piece of the staged commit no field of the group receives",
				i, b)
			break
		}
	}
	// and the epoch the merge ENTERED is intact, which is what says the erase reached the right
	// side of the swap. A merge that erased what it installed would pass every assertion above.
	if len(group.EpochAuthenticator()) == 0 {
		t.Fatal("the group answers no epoch authenticator after a merge")
	}
	if group.ownPriv.erased {
		t.Fatal("the merge erased the private tree state it installed")
	}
	if _, _, err := group.ownPriv.NodePrivateKey(crypto, group.ownLeaf.NodeIndex()); err != nil {
		t.Errorf("the merged epoch's own leaf answers %v", err)
	}
	if _, err := group.CreateCommit(nil, nil, nil); err != nil {
		t.Errorf("CreateCommit in the merged epoch: %v", err)
	}
}

// TestAnErasedPrivateTreeStateRefusesRatherThanAnsweringZeros holds the half of
// (*TreeKEMPrivate).Zeroize that is not the write.
//
// (*SecretTree).Zeroize states the rule this follows: erasing and refusing are one operation,
// because a state that answered out of erased storage would hand its caller a zero-length leaf
// private key with a nil error, and every failure downstream of that names a message rather than
// the key that opened it.
func TestAnErasedPrivateTreeStateRefusesRatherThanAnsweringZeros(t *testing.T) {
	crypto := testCrypto(t)
	priv, pub, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
	if err != nil {
		t.Fatalf("DeriveKeyPair: %v", err)
	}
	_ = pub
	state := NewTreeKEMPrivate(0, priv)
	state.PathSecrets[NodeIndex(1)] = crypto.Random(crypto.HashSize())
	leafKey := state.EncryptionPriv
	pathSecret := state.PathSecrets[NodeIndex(1)]
	if !slices.ContainsFunc(leafKey, func(b byte) bool { return b != 0 }) {
		t.Fatal("the leaf private key is already all zero, so this reads nothing")
	}

	state.Zeroize()

	for i, b := range leafKey {
		if b != 0 {
			t.Errorf("byte %d of the leaf private key is %#02x after Zeroize, want 0", i, b)
			break
		}
	}
	for i, b := range pathSecret {
		if b != 0 {
			t.Errorf("byte %d of the path secret is %#02x after Zeroize, want 0", i, b)
			break
		}
	}
	if len(state.PathSecrets) != 0 {
		t.Errorf("the erased state still reports %d path secret(s); a map of zeroed entries says this member can derive a key for every node of its direct path",
			len(state.PathSecrets))
	}
	if _, _, err := state.NodePrivateKey(crypto, LeafIndex(0).NodeIndex()); !errors.Is(err, errTreeKEMPrivateErased) {
		t.Errorf("an erased state answers %v for its own leaf, want errTreeKEMPrivateErased; without the refusal it hands back a zero length private key with no error",
			err)
	}
	// a second erase is a no-op rather than a fault, for (*KeySchedule).Zeroize's reason: a value
	// may be dropped by one path and released by another.
	state.Zeroize()
	// and a clone of an erased state is erased, or the copy answers what the original refuses.
	if !state.Clone().erased {
		t.Error("a clone of an erased private tree state is not erased, so the copy answers out of storage the original refuses to answer out of")
	}
}

// ---------------------------------------------------------------------------
// the class: read off the source, because two calls are not the property
// ---------------------------------------------------------------------------

// eraseSourceReading is one parse of the production source the erase obligation is stated over,
// with everything derived from it that both gates below need.
type eraseSourceReading struct {
	files   []parsedSource
	structs map[string]*ast.StructType
	// the named byte slice types, so storage held under HpkePrivateKey is the same storage as
	// storage held under []byte, which is what the compiler thinks too.
	named []string
	// this package's erase helpers, derived by eraseHelperClass and not named here.
	helpers []string
	// per type, the method names of it that erase storage the type itself declares.
	erasers map[string]map[string]bool
	// the class, and the types the closure reaches that owe no erase.
	members []string
}

// eraseReadingOf parses the production half of the roots the guardrails walk.
//
// BOTH ROOTS, for the seam gate's reason: a type declared in connect/message holding one of this
// package's erasable values is a holder, and scoping the class to the directory its first members
// happen to sit in is the defect this project has paid for more than once.
func eraseReadingOf(t *testing.T) eraseSourceReading {
	t.Helper()
	reading := eraseSourceReading{structs: map[string]*ast.StructType{}}
	scan := mustScanSources(t, forbiddenScanRoots)
	candidates := []eraseHelperCandidate{}
	paths := slices.Sorted(maps.Keys(productionSources(scan.sourceTexts)))
	for _, path := range paths {
		parsed := mustParseSource(t, path)
		reading.files = append(reading.files, parsed)
		structTypesIn(parsed, reading.structs)
		reading.named = append(reading.named, packageByteSliceTypeNamesIn(parsed)...)
	}
	slices.Sort(reading.named)
	reading.named = slices.Compact(reading.named)
	for _, path := range paths {
		candidates = append(candidates,
			eraseHelperCandidatesIn(mustReadCommented(t, path), path, reading.named)...)
	}
	reading.helpers, _ = eraseHelperClass(candidates)
	if len(reading.helpers) == 0 {
		t.Fatal("this source declares no erase helper, so every reading below finds no erase however an erase is written")
	}
	reading.erasers = eraseMethodsIn(reading)
	reading.members = eraseClassOf(reading)
	return reading
}

// eraseTypeReachesStorage answers whether a field of this type can hold octets: the type is the
// language's own byte slice, or one of this source's named byte slice types, or a struct declared
// here that reaches one through a field of its own.
//
// It is the reading that says which fields an erase has to account for. A LeafIndex cannot hold a
// secret and an interface is somebody else's storage; a *KeySchedule, a map[NodeIndex][]byte and
// a [][]byte all can.
func eraseTypeReachesStorage(structs map[string]*ast.StructType, named []string, expr ast.Expr,
	seen map[string]bool) bool {

	for _, mentioned := range identifiersNamedIn(expr) {
		if mentioned == "byte" || slices.Contains(named, mentioned) {
			return true
		}
		structure, isStruct := structs[mentioned]
		if !isStruct || seen[mentioned] {
			continue
		}
		seen[mentioned] = true
		for _, field := range structure.Fields.List {
			if eraseTypeReachesStorage(structs, named, field.Type, seen) {
				return true
			}
		}
	}
	return false
}

// eraseField is one field an erase has to account for: its name, and the types this source
// declares that its type mentions, which is where an erase of its own would be declared.
type eraseField struct {
	name  string
	types []string
}

// theFieldsReachingStorageOf is every field of one type that reaches octets, in declaration
// order. Embedded fields are read too -- an embedded struct's storage is this type's storage.
func theFieldsReachingStorageOf(structs map[string]*ast.StructType, named []string,
	typeName string) []eraseField {

	structure, isDeclared := structs[typeName]
	if !isDeclared {
		return nil
	}
	fields := []eraseField{}
	for _, field := range structure.Fields.List {
		if !eraseTypeReachesStorage(structs, named, field.Type, map[string]bool{}) {
			continue
		}
		held := []string{}
		for _, mentioned := range identifiersNamedIn(field.Type) {
			if _, isStruct := structs[mentioned]; isStruct {
				held = append(held, mentioned)
			}
		}
		names := field.Names
		if len(names) == 0 {
			// an embedded field: its name is its type's, which is how a body spells it.
			for _, mentioned := range identifiersNamedIn(field.Type) {
				fields = append(fields, eraseField{name: mentioned, types: held})
				break
			}
			continue
		}
		for _, declared := range names {
			fields = append(fields, eraseField{name: declared.Name, types: held})
		}
	}
	return fields
}

// eraseFieldNameOf resolves an expression to the receiver's own field it reads: self.x, x[i],
// *x, self.x.y, and any local bound from one of those.
//
// The ROOT field is the answer, because that is the storage: self.secrets.SenderData is storage
// of the field secrets, and a body erasing it has accounted for that field.
func eraseFieldNameOf(expr ast.Expr, receiver string, alias map[string]string) string {
	switch typed := expr.(type) {
	case *ast.ParenExpr:
		return eraseFieldNameOf(typed.X, receiver, alias)
	case *ast.StarExpr:
		return eraseFieldNameOf(typed.X, receiver, alias)
	case *ast.IndexExpr:
		return eraseFieldNameOf(typed.X, receiver, alias)
	case *ast.SliceExpr:
		return eraseFieldNameOf(typed.X, receiver, alias)
	case *ast.SelectorExpr:
		if base, isBare := typed.X.(*ast.Ident); isBare && base.Name == receiver {
			return typed.Sel.Name
		}
		return eraseFieldNameOf(typed.X, receiver, alias)
	case *ast.Ident:
		return alias[typed.Name]
	}
	return ""
}

// eraseAliasesIn binds the local names of one body to the receiver's field they read, to a fixed
// point.
//
// Without it every erase written as a loop reads as erasing nothing: `for _, secret := range
// self.nodes { zeroizeSecret(secret) }` hands a helper a local, and the local is the field.
func eraseAliasesIn(function *ast.FuncDecl, receiver string) map[string]string {
	alias := map[string]string{}
	for grew := true; grew; {
		grew = false
		bind := func(target ast.Expr, source ast.Expr) {
			field := eraseFieldNameOf(source, receiver, alias)
			if field == "" {
				return
			}
			name, isBare := target.(*ast.Ident)
			if !isBare || name.Name == "_" || alias[name.Name] != "" {
				return
			}
			alias[name.Name] = field
			grew = true
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.AssignStmt:
				if len(typed.Lhs) == len(typed.Rhs) {
					for i := range typed.Rhs {
						bind(typed.Lhs[i], typed.Rhs[i])
					}
					return true
				}
				if len(typed.Rhs) == 1 && len(typed.Lhs) != 0 {
					bind(typed.Lhs[0], typed.Rhs[0])
				}
			case *ast.RangeStmt:
				// the VALUE of a range names the storage; the key is an index or a map key.
				if typed.Value != nil {
					bind(typed.Value, typed.X)
				}
			}
			return true
		})
	}
	return alias
}

// eraseMethod is one method of one type, as both readings below ask about it.
type eraseMethod struct {
	receiver string
	name     string
	// the receiver's own name in the body, which every field reading is rooted in.
	self   string
	parsed parsedSource
	decl   *ast.FuncDecl
}

// methodsWithNoParametersIn is every method of the source that takes nothing.
//
// AN ERASE TAKES NO ARGUMENTS, and that is a property rather than a convention: an erase is a
// total operation on storage the receiver already holds, so a method that has to be TOLD what to
// erase is erasing part of something rather than all of it. Without this line
// (*SecretTree).takeLeafSecret -- which hands one node's secret to a helper and answers it --
// certifies a caller that names it as having erased the whole tree.
func methodsWithNoParametersIn(files []parsedSource) []eraseMethod {
	methods := []eraseMethod{}
	for _, parsed := range files {
		for _, declaration := range parsed.file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			if function.Recv == nil || len(function.Recv.List) != 1 {
				continue
			}
			if function.Type.Params != nil && len(function.Type.Params.List) != 0 {
				continue
			}
			self := ""
			if names := function.Recv.List[0].Names; len(names) == 1 {
				self = names[0].Name
			}
			if self == "" || self == "_" {
				continue
			}
			methods = append(methods, eraseMethod{
				receiver: receiverTypeName(function.Recv.List[0].Type),
				name:     function.Name.Name,
				self:     self,
				parsed:   parsed,
				decl:     function,
			})
		}
	}
	return methods
}

// theFieldsErasedBy is which of a method's own fields it hands to an erase.
//
// Two shapes and both are this package's: storage handed to an erase HELPER as an argument
// (zeroizeSecret(self.epochSecret)), and an erase METHOD called on the field
// (self.schedule.Zeroize()). The second is the one a holder uses and the one the erase helper
// class cannot see, because the storage arrives as a receiver rather than as an argument.
//
// A MENTION IS NOT AN ERASE. The call is read and its argument or its receiver is resolved to a
// field, so a body that named every secret -- a length check over each, a log line -- accounts
// for none of them, which is precisely the shape "make Zeroize a no-op" takes once the calls are
// gone.
func theFieldsErasedBy(method eraseMethod, fields []eraseField, helpers []string,
	erasers map[string]map[string]bool) map[string]bool {

	alias := eraseAliasesIn(method.decl, method.self)
	byName := map[string]eraseField{}
	for _, field := range fields {
		byName[field.name] = field
	}
	erased := map[string]bool{}
	ast.Inspect(method.decl.Body, func(node ast.Node) bool {
		call, isCall := node.(*ast.CallExpr)
		if !isCall {
			return true
		}
		switch callee := call.Fun.(type) {
		case *ast.Ident:
			if !slices.Contains(helpers, callee.Name) {
				return true
			}
			for _, argument := range call.Args {
				if field := eraseFieldNameOf(argument, method.self, alias); field != "" {
					erased[field] = true
				}
			}
		case *ast.SelectorExpr:
			// an erase run ON the field. The method has to be an erase OF THE FIELD'S OWN TYPE,
			// so a namesake declared by some other type certifies nothing.
			field := eraseFieldNameOf(callee.X, method.self, alias)
			if field == "" {
				return true
			}
			held, isField := byName[field]
			if !isField {
				return true
			}
			for _, typeName := range held.types {
				if erasers[typeName][callee.Sel.Name] {
					erased[field] = true
				}
			}
			// and an erase helper reached through a package qualifier or through storage of the
			// field, which is how a helper of another package would be spelled.
			if slices.Contains(helpers, callee.Sel.Name) {
				for _, argument := range call.Args {
					if named := eraseFieldNameOf(argument, method.self, alias); named != "" {
						erased[named] = true
					}
				}
			}
		}
		return true
	})
	return erased
}

// eraseMethodsIn derives, per type, which of its no-argument methods erase storage it declares.
//
// A fixed point, because a holder's erase is an erase only once the erase it calls on its field
// is one: (*Group).Close erases through (*StagedCommit).Zeroize, which erases through
// (*KeySchedule).Zeroize, which erases through the helper this package derives.
func eraseMethodsIn(reading eraseSourceReading) map[string]map[string]bool {
	methods := methodsWithNoParametersIn(reading.files)
	erasers := map[string]map[string]bool{}
	for grew := true; grew; {
		grew = false
		for _, method := range methods {
			if erasers[method.receiver][method.name] {
				continue
			}
			fields := theFieldsReachingStorageOf(reading.structs, reading.named, method.receiver)
			if len(theFieldsErasedBy(method, fields, reading.helpers, erasers)) == 0 {
				continue
			}
			if erasers[method.receiver] == nil {
				erasers[method.receiver] = map[string]bool{}
			}
			erasers[method.receiver][method.name] = true
			grew = true
		}
	}
	return erasers
}

// eraseClassOf is the class: the types that declare an erase, and every type holding one of those
// in a field of its own, to a fixed point.
//
// THE SEED IS DERIVED AND NOT LISTED. A type joins it by erasing its own storage, so the day a
// fifth erasable type is written it is in this class without anybody remembering to add it -- and
// the closure is what turns "StagedCommit holds a *KeySchedule and declares no erase" from a thing
// somebody has to notice into a failing test.
func eraseClassOf(reading eraseSourceReading) []string {
	member := map[string]bool{}
	for typeName, methods := range reading.erasers {
		if len(methods) != 0 {
			member[typeName] = true
		}
	}
	for grew := true; grew; {
		grew = false
		for typeName, structure := range reading.structs {
			if member[typeName] {
				continue
			}
			for _, field := range structure.Fields.List {
				for _, mentioned := range identifiersNamedIn(field.Type) {
					if member[mentioned] {
						member[typeName] = true
						grew = true
					}
				}
			}
		}
	}
	return slices.Sorted(maps.Keys(member))
}

// typesTheEraseClassReachesThatOweNoErase is every member of the closure above that owes no erase
// of its own, with the reason written out for each.
//
// The class is derived and this table is checked against it in both directions, so a type cannot
// escape the obligation by being forgotten and a row cannot outlive the type it excuses.
var typesTheEraseClassReachesThatOweNoErase = map[string]string{
	"PathDecryptResult": "it is an ANSWER and not storage. DecryptUpdatePath builds one per call and hands " +
		"it to a caller that installs both halves into the epoch it is entering, and no production " +
		"declaration holds one in a field, so there is no drop site an erase could be reachable from. " +
		"The obligation lands on the types that RETAIN this material: the key schedule the commit " +
		"secret is derived into, and the private tree state the group installs -- both of which are " +
		"members of this class in their own right",
}

// theFieldsOfTheEraseClassThatAreNotKeyMaterial is every field of a member that reaches octets and
// is not a secret, with the reason written out for each.
//
// Checked in both directions against the derived field set, which is the shape standing rule 5
// asks for: derive the members, and make every exception carry a sentence somebody had to write.
var theFieldsOfTheEraseClassThatAreNotKeyMaterial = map[string]string{
	"Group.cred": "the credential is this member's identity and it is published in its own leaf node, " +
		"which every member of the group holds and every joiner is handed in its Welcome",
	"Group.tree": "the ratchet tree is public. It carries encryption PUBLIC keys, signature public keys " +
		"and hashes, it travels beside every Welcome, and (*Group).RatchetTree hands it out on request",
	"Group.context": "the group context is what framing signs and MACs over and what a Welcome carries; " +
		"scheduleByteSlicesThatAreNotSecrets excuses the schedule's serialized copy of it for the same reason",
	"Group.verified": "the same context with its authority established. It holds no storage the context " +
		"does not, and a Clone of it is what the type hands out",
	"Group.transcript": "the confirmed and interim transcript hashes are hashes over messages every member " +
		"received, and every member of the group computes both",
	"Group.proposals": "the cache holds proposals this member received and their references, which travelled " +
		"to every member of the group as messages the delivery service also saw",
	"StagedCommit.context":    "the group context of the epoch this commit opens; see Group.context",
	"StagedCommit.verified":   "see Group.verified",
	"StagedCommit.tree":       "the post-commit ratchet tree, which the committer PUBLISHES: CommitResult carries it",
	"StagedCommit.transcript": "see Group.transcript",
	"StagedCommit.list": "the resolved proposal list, which is the proposals this commit names -- every one " +
		"of them already on the wire",
	"StagedCommit.commit": "the Commit structure as it was signed and sealed, which is what went to every " +
		"member of the group",
	"StagedCommit.confirmTag": "the confirmation tag travels in the commit's own auth data and every receiver " +
		"recomputes it; the confirmation KEY it is taken under is the secret, and the schedule erases that",
	"WelcomeJoiner.KeyPackage": "the joiner's PUBLISHED key package. It arrived in an Add proposal that went to " +
		"every member of the group and to the delivery service, every field of its encoding is public, and the " +
		"one field of the Go struct that is not encoded -- signPriv -- is written only by NewKeyPackage and " +
		"cleared by UnmarshalMLS, so a committer's copy of somebody else's key package holds no private half. " +
		"Erasing it would remove nothing an attacker lacks and would destroy a value the caller still owns; " +
		"the path secret beside it is the key material, and (*WelcomeJoiner).Zeroize erases that",
	"UpdatePathPlan.PublicKeys": "the public half of the path this commit publishes, which is exactly what the " +
		"UpdatePath on the wire carries",
	"UpdatePathPlan.LeafNode": "the re-signed leaf node this commit installs in the tree, which is public the " +
		"moment the commit is sent",
	"UpdatePathPlan.Private": "the leaf private state a MERGE INSTALLS as the group's own. A plan that erased " +
		"it would erase the key the epoch it opened runs on, so the holder that DROPS the plan erases it " +
		"instead: (*StagedCommit).Zeroize hands ownPriv -- the same pointer -- to (*TreeKEMPrivate).Zeroize, " +
		"and (*Group).MergePendingCommit erases the leaf state it REPLACED rather than the one it installed",
}

// TestEveryTypeHoldingErasableKeyMaterialErasesAllOfIt is the completeness half, read off the
// source because no behavioural test can reach every field of every holder.
func TestEveryTypeHoldingErasableKeyMaterialErasesAllOfIt(t *testing.T) {
	reading := eraseReadingOf(t)
	// the control first, over a package holding one of each shape this reading must separate.
	eraseControlReading(t)

	// the type whose OWN storage is held elsewhere, derived rather than named: the declarer of
	// the epoch secret is what TestZeroizeErasesEveryByteSliceThisTypeDeclares is written over,
	// field by field and with its own table of what is not a secret. This gate covers the rest
	// of the class rather than restating that one.
	declaring := theTypesDeclaringTheEpochSecret(reading.structs)
	if len(declaring) != 1 {
		t.Fatalf("%v declare the epoch secret storage and this gate defers to a single declarer; a second one is a type nothing holds to the field-by-field reading",
			declaring)
	}
	if len(reading.members) < 4 {
		t.Fatalf("the erase class read %v; this package holds a key schedule, a secret tree, a private tree state and the staged epoch that carries all three, so a class this small is not reading what it claims to",
			reading.members)
	}
	t.Logf("erase class: %v", reading.members)

	excused := map[string]bool{}
	for _, member := range reading.members {
		if reason, isExcused := typesTheEraseClassReachesThatOweNoErase[member]; isExcused {
			excused[member] = true
			if len(reading.erasers[member]) != 0 {
				t.Errorf("%s declares an erase and typesTheEraseClassReachesThatOweNoErase excuses it as %q; one of the two is wrong and which one holds cannot be read off either",
					member, reason)
			}
			continue
		}
		if member == declaring[0] {
			continue
		}
		fields := theFieldsReachingStorageOf(reading.structs, reading.named, member)
		wanted := []string{}
		for _, field := range fields {
			if _, isExcused := theFieldsOfTheEraseClassThatAreNotKeyMaterial[member+"."+field.name]; isExcused {
				continue
			}
			wanted = append(wanted, field.name)
		}
		if len(wanted) == 0 {
			t.Errorf("%s is in the erase class and every field of it that reaches octets is excused; a member with nothing to erase is a closure that swept in a type holding no key material",
				member)
			continue
		}
		best, covered := "", map[string]bool{}
		for _, method := range methodsWithNoParametersIn(reading.files) {
			if method.receiver != member || !reading.erasers[member][method.name] {
				continue
			}
			erased := theFieldsErasedBy(method, fields, reading.helpers, reading.erasers)
			if best == "" || len(erased) > len(covered) {
				best, covered = method.name, erased
			}
		}
		if best == "" {
			t.Errorf("%s holds %v and declares no erase; every type here that holds key material owes one, and a value dropped by any path is dropped with all of that still in it",
				member, wanted)
			continue
		}
		missing := []string{}
		for _, field := range wanted {
			if !covered[field] {
				missing = append(missing, field)
			}
		}
		if len(missing) != 0 {
			t.Errorf("(*%s).%s erases %v and leaves %v; a field this erase does not reach is key material the drop sites below cannot erase however carefully they call it",
				member, best, slices.Sorted(maps.Keys(covered)), missing)
		}
	}

	// and the tables in the other direction, so no row outlives what it excuses.
	for typeName := range typesTheEraseClassReachesThatOweNoErase {
		if !slices.Contains(reading.members, typeName) {
			t.Errorf("typesTheEraseClassReachesThatOweNoErase excuses %s, which the erase class does not reach; a row that outlived its type excuses nothing and hides that it does",
				typeName)
		}
	}
	for row := range theFieldsOfTheEraseClassThatAreNotKeyMaterial {
		typeName, fieldName, split := strings.Cut(row, ".")
		if !split {
			t.Errorf("theFieldsOfTheEraseClassThatAreNotKeyMaterial names %q, which is not a Type.field row", row)
			continue
		}
		if !slices.Contains(reading.members, typeName) || excused[typeName] {
			t.Errorf("theFieldsOfTheEraseClassThatAreNotKeyMaterial excuses %s, and %s is not a member of the erase class this gate reads fields of",
				row, typeName)
			continue
		}
		found := false
		for _, field := range theFieldsReachingStorageOf(reading.structs, reading.named, typeName) {
			if field.name == fieldName {
				found = true
			}
		}
		if !found {
			t.Errorf("theFieldsOfTheEraseClassThatAreNotKeyMaterial excuses %s, which is not a field of %s that reaches octets; a row that outlived its field excuses nothing",
				row, typeName)
		}
	}
}

// ---------------------------------------------------------------------------
// the drop sites
// ---------------------------------------------------------------------------

// eraseDropSite is one assignment a member's own method makes to a field of itself that holds key
// material, and what the body does about the value it is dropping.
type eraseDropSite struct {
	method  eraseMethod
	field   eraseField
	at      int
	erased  bool
	refused bool
	// the sub-fields of the dropped value this body reads out into storage of its own, and the
	// ones it erases: between them, a value that is being MOVED rather than dropped.
	installed map[string]bool
	movedOut  map[string]bool
}

// theDropSitesIn reads every assignment to a key-material field of the receiver's own type.
//
// The three ways a body may drop such a value, and every one of them is read off the body rather
// than off a list of method names:
//
//   - it ERASES the value first. The order is read, because an erase written after the assignment
//     erases whatever was just installed and leaves what it replaced in the heap;
//   - it REFUSES to overwrite a live one, which is (*Group).CreateCommit: a body comparing the
//     field against nil and returning is a body whose assignment can only ever land on nothing;
//   - or it MOVES the value, which is (*Group).MergePendingCommit: every field of the dropped
//     value is either read out into the holder's own storage or erased, and what is left is a
//     shell. A merge that erased what it had just installed would be the same defect pointing the
//     other way.
func theDropSitesIn(reading eraseSourceReading, member string) []eraseDropSite {
	fields := theFieldsReachingStorageOf(reading.structs, reading.named, member)
	byName := map[string]eraseField{}
	for _, field := range fields {
		byName[field.name] = field
	}
	// every name this source erases through, so an erase of a sub-field is told from any other
	// method call on it. Derived from the helper class and from the types' own erases rather
	// than written down.
	eraseNames := map[string]bool{}
	for _, helper := range reading.helpers {
		eraseNames[helper] = true
	}
	for _, methods := range reading.erasers {
		for name := range methods {
			eraseNames[name] = true
		}
	}
	sites := []eraseDropSite{}
	for _, method := range declarationsHolding(reading.files, member) {
		alias := eraseAliasesIn(method.decl, method.self)
		erased := theFieldsErasedBy(method, fields, reading.helpers, reading.erasers)
		erasedAt := map[string]int{}
		refused := map[string]bool{}
		installed := map[string]map[string]bool{}
		movedOut := map[string]map[string]bool{}
		ast.Inspect(method.decl.Body, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.CallExpr:
				// where the erase of a field stands, so the order can be read.
				for _, argument := range typed.Args {
					if field := eraseFieldNameOf(argument, method.self, alias); field != "" && erased[field] {
						if at, seen := erasedAt[field]; !seen || int(typed.Pos()) < at {
							erasedAt[field] = int(typed.Pos())
						}
					}
				}
				if selector, isSelector := typed.Fun.(*ast.SelectorExpr); isSelector {
					if field := eraseFieldNameOf(selector.X, method.self, alias); field != "" && erased[field] {
						if at, seen := erasedAt[field]; !seen || int(typed.Pos()) < at {
							erasedAt[field] = int(typed.Pos())
						}
					}
					// an erase run on one SUB-field of a value this body is moving out, which is
					// the other half of a move: what the holder does not take, it erases.
					if eraseNames[selector.Sel.Name] {
						for held := range byName {
							if sub := eraseSubFieldOn(selector.X, method.self, alias, held); sub != "" {
								if movedOut[held] == nil {
									movedOut[held] = map[string]bool{}
								}
								movedOut[held][sub] = true
							}
						}
					}
				}
			case *ast.BinaryExpr:
				if field := eraseFieldNameOf(typed.X, method.self, alias); field != "" {
					if name, isBare := typed.Y.(*ast.Ident); isBare && name.Name == "nil" {
						refused[field] = true
					}
				}
			case *ast.AssignStmt:
				// a sub-field read out INTO STORAGE OF THE HOLDER, which is what an install is.
				// A read into a local is not one: the value would go out of scope with the frame.
				if len(typed.Lhs) == len(typed.Rhs) {
					for i, right := range typed.Rhs {
						left, isSelector := typed.Lhs[i].(*ast.SelectorExpr)
						if !isSelector {
							continue
						}
						if base, isBare := left.X.(*ast.Ident); !isBare || base.Name != method.self {
							continue
						}
						for held := range byName {
							if sub := eraseSubFieldOn(right, method.self, alias, held); sub != "" {
								if installed[held] == nil {
									installed[held] = map[string]bool{}
								}
								installed[held][sub] = true
							}
						}
					}
				}
			}
			return true
		})
		ast.Inspect(method.decl.Body, func(node ast.Node) bool {
			assign, isAssign := node.(*ast.AssignStmt)
			if !isAssign {
				return true
			}
			for _, left := range assign.Lhs {
				selector, isSelector := left.(*ast.SelectorExpr)
				if !isSelector {
					continue
				}
				base, isBare := selector.X.(*ast.Ident)
				if !isBare || base.Name != method.self {
					continue
				}
				field, isHeld := byName[selector.Sel.Name]
				if !isHeld {
					continue
				}
				at, wasErased := erasedAt[field.name]
				sites = append(sites, eraseDropSite{
					method:    method,
					field:     field,
					at:        int(assign.Pos()),
					erased:    wasErased && at < int(assign.Pos()),
					refused:   refused[field.name],
					installed: installed[field.name],
					movedOut:  movedOut[field.name],
				})
			}
			return true
		})
	}
	return sites
}

// eraseSubFieldOn answers which sub-field of `field` an expression reads: staged.schedule, where
// a local named staged was bound from self.pending, answers "schedule".
func eraseSubFieldOn(expr ast.Expr, receiver string, alias map[string]string, field string) string {
	selector, isSelector := expr.(*ast.SelectorExpr)
	if !isSelector {
		return ""
	}
	if eraseFieldNameOf(selector.X, receiver, alias) != field {
		return ""
	}
	// self.field itself resolves to the field; a sub-field of it is one selector further in.
	if base, isBare := selector.X.(*ast.Ident); isBare && base.Name == receiver {
		return ""
	}
	return selector.Sel.Name
}

// declarationsHolding is every declaration of the source that is HANDED one of these values --
// in the receiver, or in a parameter -- with the name it holds it under, one entry per position.
//
// THE POSITION IS DERIVED AND NOT NAMED, which is the defect the seam gate next door records
// having fixed and the generator rule beside it records having reintroduced. A reading rooted in
// the receiver alone asks the erase obligation of methods and of nothing else, and a free
// function in this package handed a *Group -- or a declaration in connect/message handed an
// *UpdatePathPlan, whose secret fields are exported -- drops exactly what a method drops.
//
// LOCALS ARE NOT POSITIONS, and that boundary is the seam gate's own: a value a body CONSTRUCTED
// is not a value anybody handed it, so an assignment to a field of one drops storage that never
// left this frame. CreateUpdatePathSecrets writes private.EncryptionPriv over the nil a
// constructor two statements up put there, and a reading that swept in locals would report that
// as a leaked leaf key.
func declarationsHolding(files []parsedSource, typeName string) []eraseMethod {
	held := []eraseMethod{}
	for _, parsed := range files {
		for _, declaration := range parsed.file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			positions := []*ast.Field{}
			if function.Recv != nil && len(function.Recv.List) == 1 &&
				receiverTypeName(function.Recv.List[0].Type) == typeName {

				positions = append(positions, function.Recv.List[0])
			}
			if function.Type.Params != nil {
				for _, parameter := range function.Type.Params.List {
					if slices.Contains(identifiersNamedIn(parameter.Type), typeName) {
						positions = append(positions, parameter)
					}
				}
			}
			for _, position := range positions {
				for _, name := range position.Names {
					if name.Name == "_" {
						continue
					}
					held = append(held, eraseMethod{
						receiver: typeName, name: function.Name.Name, self: name.Name,
						parsed: parsed, decl: function,
					})
				}
			}
		}
	}
	return held
}

// TestEveryPathThatDropsHeldKeyMaterialErasesItFirst is the half a completeness reading cannot
// see: an erase that exists and is not called at the site that drops the value.
//
// That is exactly what this package had. (*KeySchedule).Zeroize and (*SecretTree).Zeroize were
// both written, both complete, both held by their own gates -- and the staged epoch carrying one
// of each was dropped by two paths that called neither.
func TestEveryPathThatDropsHeldKeyMaterialErasesItFirst(t *testing.T) {
	reading := eraseReadingOf(t)
	sites := 0
	for _, member := range reading.members {
		if _, isExcused := typesTheEraseClassReachesThatOweNoErase[member]; isExcused {
			continue
		}
		for _, site := range theDropSitesIn(reading, member) {
			if _, isExcused := theFieldsOfTheEraseClassThatAreNotKeyMaterial[member+"."+site.field.name]; isExcused {
				continue
			}
			sites += 1
			if site.erased || site.refused {
				continue
			}
			held := []string{}
			for _, typeName := range site.field.types {
				for _, sub := range theFieldsReachingStorageOf(reading.structs, reading.named, typeName) {
					if _, isExcused := theFieldsOfTheEraseClassThatAreNotKeyMaterial[typeName+"."+sub.name]; isExcused {
						continue
					}
					held = append(held, sub.name)
				}
			}
			moved := []string{}
			for _, sub := range held {
				if site.installed[sub] || site.movedOut[sub] {
					continue
				}
				moved = append(moved, sub)
			}
			if len(held) != 0 && len(moved) == 0 {
				continue
			}
			t.Errorf("(*%s).%s writes to %s and neither erases what it drops, refuses to overwrite a live one, nor moves it: %v is dropped with the value. A staged epoch dropped this way is a complete second epoch left in the heap for the collector to move around",
				member, site.method.name, site.field.name, moved)
		}
	}
	if sites < 4 {
		t.Fatalf("this reading found %d drop site(s); (*Group) alone closes, clears and merges a staged commit and swaps its own schedule, so a reading this thin is not finding the assignments it is stated over",
			sites)
	}
	t.Logf("%d drop site(s) of held key material, every one of them erased, refused or moved", sites)
}

// ---------------------------------------------------------------------------
// the control
// ---------------------------------------------------------------------------

// A package holding one of each shape the two readings must separate.
//
// Holder DECLARES an erase that misses one field; Mover moves a value out rather than erasing it;
// Dropper does neither. The reading has to report the second field of Holder and Dropper's
// assignment, and has to leave Mover alone -- a gate that demanded an erase there would be
// demanding that a merge erase the epoch it just entered.
const eraseObligationControl = `package control

type Held struct {
	secret []byte
	label  []byte
}

func (self *Held) Zeroize() {
	wipe(self.secret)
}

type Holder struct {
	held      *Held
	forgotten *Held
}

func (self *Holder) Zeroize() {
	self.held.Zeroize()
}

type Mover struct {
	pending *Holder
	held    *Held
}

func (self *Mover) merge() {
	staged := self.pending
	self.held = staged.held
	staged.forgotten.Zeroize()
	self.pending = nil
}

type Dropper struct {
	pending *Holder
}

func (self *Dropper) drop() {
	self.pending = nil
}

// the same drop through a position a receiver-rooted reading has no name for.
func abandon(dropper *Dropper) {
	dropper.pending = nil
}

type Refuser struct {
	pending *Holder
}

func (self *Refuser) stage(next *Holder) error {
	if self.pending != nil {
		return errPending
	}
	self.pending = next
	return nil
}

func wipe(secret []byte) {
	for i := range secret {
		secret[i] = 0
	}
}
`

// eraseControlReading runs both readings over the control, so a reading narrowed or widened by an
// edit fails here rather than reporting the real source clean.
func eraseControlReading(t *testing.T) {
	t.Helper()
	control := mustParseText(t, "erase_obligation_control.go", eraseObligationControl)
	reading := eraseSourceReading{
		files:   []parsedSource{control},
		structs: map[string]*ast.StructType{},
	}
	structTypesIn(control, reading.structs)
	reading.named = packageByteSliceTypeNamesIn(control)
	reading.helpers = []string{"wipe"}
	reading.erasers = eraseMethodsIn(reading)
	reading.members = eraseClassOf(reading)

	for _, want := range []string{"Held", "Holder", "Mover", "Dropper", "Refuser"} {
		if !slices.Contains(reading.members, want) {
			t.Errorf("the erase class read %v out of the control and %s is not in it; a type that declares an erase, or that holds one that does, is a member by doing so",
				reading.members, want)
		}
	}
	if !reading.erasers["Holder"]["Zeroize"] {
		t.Error("(*Holder).Zeroize is not read as an erase, and it hands a field to an erase of that field's own type; the holder half of the reading is doing nothing")
	}
	if reading.erasers["Dropper"]["drop"] {
		t.Error("(*Dropper).drop is read as an erase and it erases nothing")
	}

	// the completeness half: Holder erases held and not forgotten.
	fields := theFieldsReachingStorageOf(reading.structs, reading.named, "Holder")
	if len(fields) != 2 {
		t.Fatalf("the field reading found %d field(s) of Holder reaching octets, want 2; it is not following the struct the type holds",
			len(fields))
	}
	holder := []eraseMethod{}
	for _, method := range methodsWithNoParametersIn(reading.files) {
		if method.receiver == "Holder" {
			holder = append(holder, method)
		}
	}
	if len(holder) != 1 {
		t.Fatalf("the control declares %d no-argument method(s) on Holder, want 1", len(holder))
	}
	erased := theFieldsErasedBy(holder[0], fields, reading.helpers, reading.erasers)
	if !erased["held"] || erased["forgotten"] {
		t.Errorf("(*Holder).Zeroize is read as erasing %v, want held alone; the erase reading is not telling a call from a field it never names",
			slices.Sorted(maps.Keys(erased)))
	}

	// and the drop sites: Dropper is reported, Mover and Refuser are not.
	verdicts := map[string]eraseDropSite{}
	for _, member := range []string{"Mover", "Dropper", "Refuser"} {
		for _, site := range theDropSitesIn(reading, member) {
			verdicts[member+"."+site.method.name] = site
		}
	}
	if _, found := verdicts["Dropper.abandon"]; !found {
		t.Errorf("the drop reading found no assignment in abandon, which is handed a Dropper in a parameter and drops its held value; a reading rooted in the receiver asks this obligation of methods and of nothing else")
	}
	drop, found := verdicts["Dropper.drop"]
	if !found {
		t.Fatal("the drop reading found no assignment in (*Dropper).drop, so the rule below is over nothing")
	}
	if drop.erased || drop.refused || len(drop.installed) != 0 || len(drop.movedOut) != 0 {
		t.Errorf("(*Dropper).drop is read as erasing, refusing or moving what it drops: erased=%v refused=%v installed=%v moved=%v",
			drop.erased, drop.refused, slices.Sorted(maps.Keys(drop.installed)), slices.Sorted(maps.Keys(drop.movedOut)))
	}
	move, found := verdicts["Mover.merge"]
	if !found {
		t.Fatal("the drop reading found no assignment to pending in (*Mover).merge")
	}
	if !move.installed["held"] || !move.movedOut["forgotten"] {
		t.Errorf("(*Mover).merge is read as installing %v and erasing %v out of the value it drops, want held installed and forgotten erased; a merge whose move goes unread is a merge this gate would demand erase the epoch it just entered",
			slices.Sorted(maps.Keys(move.installed)), slices.Sorted(maps.Keys(move.movedOut)))
	}
	refuse, found := verdicts["Refuser.stage"]
	if !found {
		t.Fatal("the drop reading found no assignment to pending in (*Refuser).stage")
	}
	if !refuse.refused {
		t.Error("(*Refuser).stage is not read as refusing to overwrite a live value, and it returns on exactly that comparison; without it every constructor of a staged value is a drop site")
	}
}
