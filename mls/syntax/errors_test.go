// The sentinels are the package's whole error contract, so they are asserted to be
// distinct from each other and to survive the joins the package uses to add context.
package syntax

import (
	"errors"
	"testing"
)

// TestErrorSentinelsAreDistinct asserts no two sentinels are errors.Is-equal to each other.
func TestErrorSentinelsAreDistinct(t *testing.T) {
	sentinels := []error{
		ErrTruncated,
		ErrTrailingBytes,
		ErrVarintReserved,
		ErrVarintNotMinimal,
		ErrVarintOverflow,
		ErrLengthExceedsInput,
		ErrLengthExceedsMax,
		ErrOptionalPresence,
		ErrZeroLengthElement,
		ErrNegativeLength,
		ErrRoundTripNotByteExact,
		ErrRoundTripNotStable,
	}
	for i, a := range sentinels {
		if a == nil {
			t.Fatalf("sentinel %d is nil", i)
		}
		for j, b := range sentinels {
			if i == j {
				continue
			}
			if errors.Is(a, b) {
				t.Errorf("sentinel %d and sentinel %d are not distinct: %v", i, j, a)
			}
		}
	}
}

// TestErrorSentinelsSurviveAJoin asserts sentinels survive errors.Join without losing their identity.
func TestErrorSentinelsSurviveAJoin(t *testing.T) {
	joined := errors.Join(ErrLengthExceedsMax, ErrTruncated)
	if !errors.Is(joined, ErrLengthExceedsMax) {
		t.Errorf("join lost ErrLengthExceedsMax")
	}
	if !errors.Is(joined, ErrTruncated) {
		t.Errorf("join lost ErrTruncated")
	}
	if errors.Is(joined, ErrTrailingBytes) {
		t.Errorf("join matched an unrelated sentinel")
	}
}

// TestLengthLimits asserts the three length constants match RFC 9420 and spec A section 5.8.
func TestLengthLimits(t *testing.T) {
	if MaxVarint != 1073741823 {
		t.Errorf("MaxVarint is %d, want 1073741823 per rfc 9420 section 2.1.2", MaxVarint)
	}
	if MaxVectorLength != 1<<20 {
		t.Errorf("MaxVectorLength is %d, want 1 MiB per spec A section 5.8", MaxVectorLength)
	}
	if MaxRatchetTreeLength != 1<<24 {
		t.Errorf("MaxRatchetTreeLength is %d, want 16 MiB per spec A section 5.8", MaxRatchetTreeLength)
	}
}
