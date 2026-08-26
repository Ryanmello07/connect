// The storage layer of the messaging work: the X-Wing hybrid key encapsulation of
// draft-connolly-cfrg-xwing-kem, and the message store built on it.
//
// The layering is one way, and both directions matter. This package must never import
// connect, and connect must never import it: a package that imports its own subpackage
// inverts the dependency, so the child's API is frozen by its own parent and cycles
// become easy to create. It reaches into connect/mls for the one x25519 helper, which
// is what keeps a single reviewed call site in the whole tree, and connect/mls must not
// reach back — connect/mls imports only the standard library, golang.org/x/crypto, and
// its own child mls/syntax.
//
// What is here so far is the record and its two ladders, in record.go: the go form of
// the record master section 8 defines, the size ladder a body is padded to, the eph
// ladder a transient record expires on, the one pair of functions that crosses between
// the retention class as go carries it and the single byte the wire carries it in, and
// the class predicate spec B section 7.2 sweeps on. The key schedule, the codec, the
// authenticators and the server attachment land beside them and read these types.
// Nothing in this package logs a failure and carries on: every error here is one of the
// sentinels in errors.go, and the only bare bools are the three constant time verifiers
// of spec A section 5.7 and that class predicate, none of which reports a failure.
//
// Two rules in this package are enforced by a test rather than by the compiler, and
// both walk the directory tree rather than reading a list of files. The forbidden
// primitive gate in mls/crypto_forbidden_test.go covers this package as well as its own,
// which is why the directory existed before there was anything in it: a gate whose root
// is missing either fails outright or, worse, reports clean having read nothing. The
// join gate in record_test.go covers this package, connect/mls and the sdk repository
// beside connect, and holds both halves of the class-and-bucket crossing — the join and
// the split alike — to record.go alone. It reads the syntax tree rather than the text,
// because the shapes it bans have more spellings than anybody can list.
package message
