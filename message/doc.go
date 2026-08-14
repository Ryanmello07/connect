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
// The package is a doc stub for now: the X-Wing implementation lands with the tasks
// that need it. It exists this early because the forbidden primitive gate in
// mls/crypto_forbidden_test.go walks this directory, and a gate whose root is missing
// either fails outright or, worse, reports clean having read nothing.
package message
