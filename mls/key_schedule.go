// The RFC 9420 section 8 epoch key schedule.
//
// Every secret an epoch holds is a function of that epoch's GroupContext, so nothing in
// this file may take a shortcut around it. Two members that expand over different context
// bytes derive different secrets and stop being able to talk, and that failure arrives as
// an undecryptable message rather than as the mistake it was.
//
// The one thing this file has to get right that no downstream check can see is the order
// of the two arguments to Extract. RFC 9420 writes KDF.Extract(salt, ikm); crypto/hkdf
// takes the input keying material first and the salt second. The swap is confined to
// crypto.go and hpke.go, and CryptoProvider.Extract — which takes (salt, ikm), the spec's
// order — is the only spelling this file may use. Transposing the two here compiles,
// returns KDF.Nh bytes, and satisfies every round trip and every self consistency check
// this package could write, because the wrong secret is exactly as well formed as the
// right one. The only thing that separates them is a known answer somebody else published,
// which is what key_schedule_test.go holds this to.
package mls

import (
	"fmt"

	"github.com/urnetwork/connect/mls/syntax"
)

// PastEpochWindow bounds how many past epochs of state, and therefore how many past
// resumption_psk values and eph_root values, a client retains. RFC 9420 ValSem400 makes
// bounding this a SHOULD and OpenMLS does not implement it at all (openmls#1122); here it
// is a hard bound. Thirty-two rather than eight because the window is a product promise
// about how long a laptop may stay closed, and an active group can burn eight epochs in a
// day.
const PastEpochWindow uint64 = 32

// ZeroSecret returns the KDF.Nh all-zero secret RFC 9420 writes as 0. It is the
// commit_secret of a commit with no UpdatePath and the psk_secret of an epoch with no
// PSKs.
//
// A fresh slice per call, and not a package level constant handed out repeatedly, because
// the key schedule zeroizes what it is finished with: a caller that erased a shared
// constant would leave every later call returning the same bytes and no way to tell.
// Callers cannot be asked to remember which secrets are safe to erase.
//
// What a test can honestly observe about this is its length, that every byte is zero, and
// that two calls do not share storage. That the value is the RIGHT zero — the one RFC 9420
// substitutes for a missing commit secret — is not a property of the returned bytes at
// all, since one run of Nh zero bytes is indistinguishable from another. What holds the
// spelling is the published key schedule and psk_secret corpora that expand over it, and
// the tasks that consume this function are where those comparisons live. A test here that
// claimed more would be reassuring rather than checking.
func ZeroSecret(crypto CryptoProvider) []byte {
	return make([]byte, crypto.HashSize())
}

// DeriveJoinerSecret computes joiner_secret for the epoch being entered:
//
//	joiner_secret = ExpandWithLabel(
//	    KDF.Extract(init_secret_[n-1], commit_secret),
//	    "joiner", GroupContext_[n], KDF.Nh)
//
// The GroupContext is the one for the epoch being ENTERED, not the one being left. A
// caller that passes the outgoing context derives a joiner secret every peer disagrees
// with, and there is nothing about the value that says so.
//
// init_secret_[n-1] is the salt and commit_secret is the input keying material, in that
// order, through CryptoProvider.Extract. See the file comment: the transposition is
// invisible to everything except a published answer.
//
// Both secrets must be exactly KDF.Nh bytes and a short one is refused rather than
// stretched. HKDF-Extract accepts any length of either argument and would hand back a
// perfectly well formed pseudorandom key, so a truncated init secret becomes an epoch that
// looks valid on this side and matches nobody — the length mistake would surface epochs
// later as an undecryptable message.
//
// The pseudorandom key is erased before returning. It is not the joiner secret and nothing
// downstream needs it, and it is one HKDF-Expand away from every key of the epoch.
//
// A nil context is refused rather than serialized. syntax.Marshal is handed a non nil
// interface holding a nil pointer, so MarshalMLS dereferences it and the caller gets a
// runtime panic raised inside the syntax package, naming neither this function nor the
// argument that was missing. Every caller of this takes its context off a struct field,
// which is exactly where an unset one comes from.
func DeriveJoinerSecret(
	crypto CryptoProvider,
	initSecretPrev []byte,
	commitSecret []byte,
	groupContext *GroupContext,
) ([]byte, error) {
	if groupContext == nil {
		return nil, ErrNilGroupContext
	}
	nh := crypto.HashSize()
	if len(initSecretPrev) != nh {
		return nil, fmt.Errorf("%w: init secret is %d bytes, want %d", ErrSecretLength, len(initSecretPrev), nh)
	}
	if len(commitSecret) != nh {
		return nil, fmt.Errorf("%w: commit secret is %d bytes, want %d", ErrSecretLength, len(commitSecret), nh)
	}
	encodedGroupContext, err := syntax.Marshal(groupContext)
	if err != nil {
		return nil, err
	}
	// Extract takes (salt, ikm), the order the spec writes. init_secret is the salt.
	prk := crypto.Extract(initSecretPrev, commitSecret)
	joinerSecret := crypto.ExpandWithLabel(prk, "joiner", encodedGroupContext, nh)
	zeroizeSecret(prk)
	return joinerSecret, nil
}
