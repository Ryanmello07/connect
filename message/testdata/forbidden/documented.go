//go:build ignore

// The negative half of the control: a file that names every banned shape in prose and
// commits none of them. It stands in for message/record.go and for record_test.go, both
// of which write all four shapes out in comments — record.go because the wire table is
// restated there in full, and the test file because it has to quote what it matches. A
// gate that fires on those comments bans the sentence that teaches the rule, so the
// matchers strip comments first and this file is what proves they do.
//
// The four banned shapes, in a line comment: class<<4, class|bucket, 16+bucket and
// class*16.
//
// Under testdata and build constrained out, like every file in this directory.
package forbidden

/*
And again in a block comment, because a block comment is no more executable than a line
comment: class<<4, class|bucket, 16+bucket, class*16.

Written out at length too, in the arithmetic a reader would recognise: shifting the
retention class left by four and adding the eph bucket to it, or multiplying the class by
16 and or-ing the bucket in.
*/

import "github.com/urnetwork/connect/message"

// The legal way to do it, which is to call the one function allowed to join, so that the
// controls are comparing "allowed" against "reported" rather than "absent" against
// "reported".
func joinTheOnlyWay(retentionClass message.RetentionClass, ephBucket uint8) (byte, error) {
	return message.RetentionClassWire(retentionClass, ephBucket)
}

// And the split, the other half of the pair, for the same reason.
func splitTheOnlyWay(wire byte) (message.RetentionClass, uint8, error) {
	return message.RetentionClassOf(wire)
}
