//go:build ignore

// The positive control for the join gate in message/record_test.go: one file that
// commits every shape spec A section 5.1 bans, so the matchers can be shown to catch
// them rather than assumed to. A matcher that finds nothing because it is broken and one
// that finds nothing because the tree is clean report the same result, and all four
// matchers found nothing on the day they were written. This file is what tells the two
// apart.
//
// It cannot reach the gate and the gate cannot reach it. The walk skips any directory
// named testdata unless a root names one outright, which only the controls do; the go
// tool never builds a testdata directory at all; and the build constraint above says so
// a second time for a reader who has only this file open.
//
// None of this is real code and none of it is how a record is written. The class and the
// bucket are joined in exactly one place, message/record.go, and every shape below is a
// second implementation of that join — which is a second place the two can be conflated,
// silently, in a comparison that then covers half the eph records it reads as covering.
// The sibling file documented.go carries the other half of the control: the same four
// shapes in prose, and the legal call beside them, so that "not reported" means "allowed
// or absent" rather than "the matchers are asleep".
package forbidden

// The shift, which is how the wire byte is usually rebuilt by hand.
func joinByShift(retentionClass uint8) uint8 { return retentionClass << 4 }

// The or, in the operand order a contributor reaches for first.
func joinByOr(retentionClass uint8, ephBucket uint8) uint8 { return retentionClass | ephBucket }

// The addition, with the eph base written as a decimal literal.
func joinByAdd(ephBucket uint8) uint8 { return 16 + ephBucket }

// The multiplication, which is the shift written for a reader who dislikes shifts.
func joinByMultiply(retentionClass uint8) uint8 { return retentionClass * 16 }
