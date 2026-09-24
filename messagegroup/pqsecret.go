// pq_secret PER EPOCH, ledger item 251's ruling 40.
//
// WHAT WAS WRONG, AND IT IS ONE LINE. Every storage root in this system is
// StorageRoot(mls_secret[n], pq_secret) -- the MLS exporter of epoch n mixed with the only post
// quantum material the design has. The mls_secret half was already per epoch and had to be:
// pastepoch.go rebuilds a prior epoch's whole group to export it. The pq_secret half was a SCALAR
// on the session, so pastepoch.go's `root := StorageRoot(mlsSecret, self.pqSecret)` re-derived a
// PAST epoch's root out of TODAY's secret. While every group is handed the same octets forever
// that is invisible; the day a commit rotates the secret, every epoch below it becomes unopenable
// at the AEAD tag, with nothing anywhere saying why. Reproduced before it was fixed, with the
// unrotated session as the control: pqepoch_test.go's first case.
//
// WHY THE SCALAR WAS THERE AT ALL is item 243: pq_secret was RULED a group lifetime value in
// 2026-09-18, on the explicit condition that rotating it is a prerequisite of shipping REMOVAL --
// because a lifetime value leaves a removed member a permanent contribution to every future
// epoch's storage root. Ruling 40 is that condition coming due. This file is the table; the
// carrier that delivers a rotated secret to the other members is the device wrap, and it is NOT
// here.
//
// WHAT IS HELD, FOR HOW LONG, AND WHAT ERASES IT, because that is the sentence the erase
// discipline asks of every holder in this package.
//
//   - ONE ENTRY PER EPOCH THIS SESSION HAS STOOD AT, keyed by epoch, each of them thirty two
//     octets this session copied out of what its caller handed AdvanceEpoch or the constructor.
//   - BOUNDED BY PastEpochWindow, which is the same bound pastepoch.go refuses below and the same
//     bound connect/mls deletes state below. An entry more than PastEpochWindow behind the
//     session's epoch can serve no open that pastEpochOnLoop would admit, so it is dropped AND
//     ERASED as the window moves past it -- not merely dropped, because these are the post
//     quantum half of a retired epoch's storage root and a map entry nobody deleted is a live
//     secret with no owner.
//   - AND THE WHOLE TABLE GOES AT Close, erased entry by entry.
//
// It is NOT dropped at an epoch install, which is the one place this table's discipline differs
// from every other field installEpochOnLoop touches. The ratchets, the class keys and the prior
// epochs' schedules are re-derived or rebuilt on demand from the epoch the session moved to; a
// past epoch's pq_secret is neither derivable nor rebuildable from anything -- it is a value that
// ARRIVED -- so dropping it at the install would destroy the only copy of the thing that makes a
// past epoch's root computable, which is precisely what this file exists to keep.
//
// THE COMPATIBILITY PATH, AND IT IS NARROW ON PURPOSE. Every group that exists today was handed
// one pq_secret at its creation and the same octets at every AdvanceEpoch since, and a device that
// restarts constructs its session AT WHATEVER EPOCH THE GROUP HAS REACHED -- so its table holds
// exactly one epoch, and every prior epoch inside the window would be a miss. Before this file
// the scalar answered all of them. So: WHILE A SESSION HAS NEVER BEEN HANDED A SECOND, DIFFERENT
// SECRET, the one it holds answers every epoch, which is the old behaviour exactly. The moment a
// different secret arrives the session is ROTATED and the fallback is gone for good, because from
// that moment "the secret I have" and "the secret that epoch had" are different values and
// answering with the first is the defect above wearing another hat. A rotated session with no
// entry for an epoch refuses with ErrPqSecretUnknownEpoch and names the epoch, because the
// caller's only repair is to supply that epoch's secret.
//
// THE FLAG IS SET ON THE OCTETS AND NOT ON A COUNT. "Has this session been rotated" is decided by
// comparing what arrives against what is already held, in constant time, so a caller that hands
// the same secret in a hundred times is not rotated, and one that hands in a different secret
// once is rotated forever. A count of AdvanceEpoch calls would have made every group in the world
// rotated at its second commit and taken the fallback away from all of them.
package messagegroup

import (
	"crypto/subtle"
	"fmt"
)

// installPqSecretOnLoop records pq_secret[epoch] and decides whether this session has rotated.
//
// The value is COPIED. The caller's array is the caller's: AdvanceEpoch's own parameter is passed
// straight through from sdk, which holds it for its own reasons, and a table aliasing it would
// erase a caller's buffer when the window moved.
//
// An entry already standing at that epoch is ERASED before it is replaced. It happens when a
// caller advances into an epoch twice -- a retried install, a CAS race resolved the other way --
// and the octets underneath are a storage root's post quantum half however briefly they were
// wrong.
//
// The caller is the loop goroutine, or the constructor before the loop exists.
//
// The noinline directive is this package's erase helper class: the store above erases an entry of
// the receiver's own table, and that store outlives this call.
//
//go:noinline
func (self *GroupSession) installPqSecretOnLoop(epoch uint64, pqSecret []byte) {
	// the rotation decision is taken BEFORE the table is touched, against the secret of the
	// epoch this session is standing at -- which, while the session is unrotated, is the same
	// value as every other entry. subtle.ConstantTimeCompare and not bytes.Equal: guardrail G8
	// sends every comparison of secret octets in this tree through it.
	if !self.pqRotated {
		if standing, isHeld := self.pqSecrets[self.epoch]; isHeld {
			if subtle.ConstantTimeCompare(standing, pqSecret) != 1 {
				self.pqRotated = true
			}
		}
	}
	if held, isHeld := self.pqSecrets[epoch]; isHeld {
		zeroize(held)
	}
	self.pqSecrets[epoch] = append([]byte(nil), pqSecret...)
}

// pqSecretForOnLoop answers pq_secret[epoch], or refuses.
//
// THE ORDER OF THE TWO ARMS IS THE WHOLE OF THE RULE. The table first, always, so that a rotated
// session never reaches the fallback for an epoch it actually holds; then the compatibility path,
// which answers only while this session has never been handed a second secret. A session with
// nothing at all in its table falls through both and refuses, which is the closed session's shape
// and is what Close leaves behind.
//
// The refusal names THE SHAPE OF THE TABLE and never its octets -- a table of secrets is not a
// thing to print into an error string that travels to a log -- because what a caller debugging a
// miss needs is whether the epoch is one this device ever stood at and whether the fallback was
// available to answer it.
//
// The caller is the loop goroutine.
func (self *GroupSession) pqSecretForOnLoop(epoch uint64) ([]byte, error) {
	if secret, isHeld := self.pqSecrets[epoch]; isHeld {
		return secret, nil
	}
	if !self.pqRotated {
		if secret, isHeld := self.pqSecrets[self.epoch]; isHeld {
			return secret, nil
		}
	}
	oldest := self.epoch
	for held := range self.pqSecrets {
		if held < oldest {
			oldest = held
		}
	}
	return nil, fmt.Errorf("%w: epoch %d; this session stands at epoch %d, holds %d pq_secret(s) from epoch %d up, and has been rotated: %t",
		ErrPqSecretUnknownEpoch, epoch, self.epoch, len(self.pqSecrets), oldest, self.pqRotated)
}

// dropPqSecretsBelowWindowOnLoop erases and drops every entry the window has moved past.
//
// THE BOUND IS pastEpochOnLoop's OWN, spelled the same way round: that function refuses an epoch
// when `self.epoch-epoch > PastEpochWindow`, so an entry satisfying the same comparison can serve
// no open this session would admit, and holding it is holding a retired epoch's post quantum
// secret for nothing. The subtraction is guarded by `epoch < self.epoch` because these are
// uint64s: an entry at or above the session's epoch underflows the comparison into a number that
// is always past the window, and the entry that would drop is the CURRENT epoch's.
//
// The caller is the loop goroutine.
//
// The noinline directive is this package's erase helper class: the erase below lands in the
// receiver's own table and outlives this call.
//
//go:noinline
func (self *GroupSession) dropPqSecretsBelowWindowOnLoop() {
	for epoch, secret := range self.pqSecrets {
		if epoch < self.epoch && self.epoch-epoch > PastEpochWindow {
			zeroize(secret)
			delete(self.pqSecrets, epoch)
		}
	}
}
