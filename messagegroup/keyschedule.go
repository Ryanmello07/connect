// The record layer's key schedule: the storage root every group key of an epoch hangs off, and
// the three retention class keys derived from it.
//
// Spec A section 5.3 is normative and its block is this file's contract:
//
//	storage_root[n] = HKDF-Extract(salt = mls_secret[n], ikm = pq_secret[n])   MASTER section 7
//
//	mls_secret[n] = MLS-Exporter("URmessage/v1/storage", "", 32)   RFC 9420 section 8.5
//
//	NOTE the argument order. crypto/hkdf's Extract takes (secret, salt) -- ikm FIRST.
//	This wrapper takes (salt, ikm), matching the spec text. Never call
//	crypto/hkdf's Extract directly anywhere in this package. See section 5.9.
//
// Guardrail G1 is that note, and it is the reason this file has a helper where a one line body
// would do. crypto/hkdf's Extract takes the input keying material first and the salt second,
// which is the reverse of the HKDF-Extract(salt, ikm) MASTER, RFC 9420 and RFC 9180 all write.
// Transposing them compiles, returns thirty two bytes, and passes every test that does not
// compare against an implementation written by somebody else -- both ends of this project would
// agree with themselves forever, and only a second client would ever find out.
//
// So the extraction is done in ONE unexported helper and that helper delegates to
// mls.CryptoProvider.Extract, which already takes the arguments in the spec's order, is already
// the tree's one reviewed swap, and is already held against RFC 5869's own table. That is open
// item M1-16's recommended shape and it is the cheaper of the two: the alternative was to call
// crypto/hkdf here and take an allow list entry in mls's forbidden gate, which is keyed by
// needle and would have excused Extract, Expand AND Key in this file -- and Key is the worst of
// the three to transpose, because the whole schedule it produces is internally consistent and
// wrong. Taking the delegation leaves the tree with exactly one direct extraction in the whole
// crypto surface and needs no widening of anything. If M1-16 is ever ruled the other way, the
// change is inside keyScheduleExtract and nowhere else.
//
// The expansion is one helper for the same reason at lower stakes: Expand has no salt argument
// and so carries no transposition, but a second spelling of it is a second place for a length or
// an info conversion to drift. Every derivation in this package that expands goes through it.
//
// ClassKeys carries three keys and its SHAPE is the second defence. Spec A section 5.3:
// "Eph is NOT here. eph_root is 32 B fresh CSPRNG at commit, never derived from storage_root.
// MASTER I4. Putting it in this struct would make the wrong thing the easy thing." An eph key
// derived from the storage root would be recoverable from it forever, which is the whole
// property the eph classes exist to not have, and the struct that has no field for it is what
// makes the correct thing the only thing in reach.
//
// The three labels are three constants and are never built by substituting a word into a shared
// stem. writeauth.go already sets that precedent for write/v1 and read/v1 and gives the
// argument: one construction is a single edit away from making two keys equal, and two
// retention classes sharing a key is a permanent record openable with a media key.
package messagegroup

import (
	"fmt"

	"github.com/urnetwork/connect/mls"
)

// The three retention class labels, raw ascii, expanded from the storage root at thirty two
// octets each.
//
// They are deliberately not the same length, and the separation does not rest on that. It rests
// on the bytes: all three disagree at index zero, which is inside the shortest of them, so no
// choice of anything that follows one label can turn it into another.
const (
	permClassInfo    = "perm/v1"
	durableClassInfo = "durable/v1"
	mediaClassInfo   = "media/v1"
)

// The width of a class key and of the storage root, in octets. MASTER section 7 gives both as
// thirty two, and the exporter that produces mls_secret is called for thirty two.
const classKeyBytes = 32

// The provider every derivation in this package runs on.
//
// It is one value for the process because it is stateless: mls's own comment on
// NewCryptoProvider says so in as many words -- it holds the suite parameters and an entropy
// source, and both are safe to share -- and nothing here draws entropy through it at all.
//
// The suite it is built for does not enter any derivation below. Extract and Expand are written
// against sha256 directly in mls's provider rather than selected from the suite parameters, and
// both registered suites name HKDF-SHA256; the guard for a third suite that did not is mls's
// own TestEverySuiteNamesTheHashTheProviderComputes, which reads the registry rather than this
// file. The suite is named here only because the constructor takes one.
//
// A failure here is an unregistered code point, which is a compile time constant of this file
// being wrong, so it stops the process at initialisation rather than handing every later
// derivation a nil provider.
var keyScheduleCrypto = mustKeyScheduleCrypto()

// The provider, or a stopped process. Split out so the var above has no function literal in it
// and reads as what it is.
func mustKeyScheduleCrypto() mls.CryptoProvider {
	crypto, err := mls.NewCryptoProvider(mls.CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		panic(fmt.Errorf("messagegroup: the key schedule's crypto provider names an unregistered suite: %w", err))
	}
	return crypto
}

// The ONE extraction of this package, and guardrail G1's single reviewed call site.
//
// The argument names are the spec's and the delegation preserves them: mls's Extract is declared
// Extract(salt, ikm) precisely so that a call reading the way the spec reads is the correct
// call. Nothing else in this package may extract, and keyschedule_test.go derives that class off
// the syntax tree rather than trusting this sentence.
func keyScheduleExtract(salt []byte, ikm []byte) []byte {
	return keyScheduleCrypto.Extract(salt, ikm)
}

// The ONE expansion of this package.
//
// It exists so that a length, an info conversion or a provider is never spelled twice, and so
// that every derivation this package publishes can be read as one line naming its own label.
// mls's Expand panics on a length outside the KDF's range rather than returning a short key,
// which is the answer this layer wants too: every length below is a compile time constant of
// this file.
func keyScheduleExpand(prk []byte, info []byte, length int) []byte {
	return keyScheduleCrypto.Expand(prk, info, length)
}

// StorageRoot derives storage_root[n], the root every other key of an epoch is expanded from.
//
// The first argument is the SALT and the second is the input keying material, in that order,
// because that is the order MASTER section 7 and spec A section 5.3 write and because the whole
// of guardrail G1 is that the library writes them the other way round. mls_secret comes from
// the group's MLS exporter and pq_secret from the epoch's post quantum contribution; a
// transposition here produces a root that is thirty two well formed octets, that both ends of
// one implementation agree on, and that no second implementation ever reproduces.
//
// There is no refusal and no error: it is a pure function of two secrets its caller has already
// obtained, and the one thing that could go wrong -- an aged out epoch that cannot export -- is
// reported by mls's exporter one level above this signature.
func StorageRoot(mlsSecret []byte, pqSecret []byte) []byte {
	return keyScheduleExtract(mlsSecret, pqSecret)
}

// ClassKeys holds one key per retention class that a record can be written under.
//
// There are three and there is no fourth. The eph classes are absent on purpose and the absence
// is the point -- MASTER I4 and spec A section 5.3 -- because eph_root is fresh entropy at each
// commit and is never a function of the storage root. A field here for it would make deriving
// the wrong thing the shortest path to a compiling program.
type ClassKeys struct {
	// Permanent records: kept until the group deletes them.
	Perm []byte
	// Durable records: the class an ordinary message is written under, and the class CP3b's
	// one message travels in.
	Durable []byte
	// Media records: the class a blob's inline metadata is written under.
	Media []byte
}

// Zeroize erases all three keys in place.
//
// It is owed because this type is storage rather than an answer: a session holds one for the
// epoch it is in and drops it at the next commit, and the octets it drops are what forward
// secrecy is about. Every field is erased by name rather than by a loop over a slice of them,
// so a fourth field added without an erase beside it leaves this method visibly short.
func (self *ClassKeys) Zeroize() {
	if self == nil {
		return
	}
	zeroize(self.Perm)
	zeroize(self.Durable)
	zeroize(self.Media)
}

// DeriveClassKeys expands the three retention class keys from a storage root.
//
// Each is HKDF-Expand(storage_root, label, 32) under its own label, and the three labels are
// three separate constants for the reason the file comment gives.
func DeriveClassKeys(storageRoot []byte) *ClassKeys {
	return &ClassKeys{
		Perm:    keyScheduleExpand(storageRoot, []byte(permClassInfo), classKeyBytes),
		Durable: keyScheduleExpand(storageRoot, []byte(durableClassInfo), classKeyBytes),
		Media:   keyScheduleExpand(storageRoot, []byte(mediaClassInfo), classKeyBytes),
	}
}
