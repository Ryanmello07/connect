package connect

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A message behind a run of lost predecessors waits its turn in order. While
// the receiver's head keeps advancing, the sequence is alive and recovering, so
// the wait must not end it. A head that has stopped still expires on time.
func TestAckLifetimeFollowsCumulativeProgress(t *testing.T) {
	const ackTimeout = 30 * time.Second
	origin := time.Unix(1700000000, 0)
	cases := []struct {
		name         string
		headAdvanced time.Duration
		expired      bool
		deadline     time.Duration
	}{
		{name: "head still advancing", headAdvanced: 29 * time.Second, deadline: 59 * time.Second},
		{name: "head stopped before the message was sent", headAdvanced: -time.Second, expired: true},
		{name: "head stopped when the message was sent", headAdvanced: 0, expired: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sequence := &SendSequence{resendQueue: newResendQueue(nil, 0)}
			sequence.lastHeadAckTime = origin.Add(c.headAdvanced)
			item := &sendItem{
				transferItem: transferItem{messageId: NewId(), sequenceNumber: 72669},
				sendTime:     origin,
				ackTimeout:   ackTimeout,
				resendTime:   origin.Add(time.Minute),
				expectsAck:   true,
			}
			sequence.addResendItem(item)
			defer sequence.ackLifetimes.clear()
			defer sequence.resendQueue.Clear()

			deadline, err := sequence.nextAckLifetime(origin.Add(ackTimeout))
			if c.expired {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("stalled sequence must expire, got deadline=%v err=%v", deadline, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("progressing sequence must not expire: %v", err)
			}
			if want := origin.Add(c.deadline); !deadline.Equal(want) {
				t.Fatalf("deadline = %v, want %v", deadline, want)
			}
		})
	}
}

// The zero time means no head has ever advanced, which must not renew anything.
func TestAckLifetimeWithoutHeadProgressKeepsItemDeadline(t *testing.T) {
	sequence := &SendSequence{}
	item := &sendItem{ackTimeout: time.Second}
	if deadline := sequence.ackProgressDeadline(item); !deadline.IsZero() {
		t.Fatalf("deadline = %v, want zero", deadline)
	}
}

// A message that has outlived its send-time lifetime on head progress must
// still back off. A resend clamped to the old deadline is always already due,
// which writes the same message in a tight loop.
func TestAckLifetimeResendDeadlineFollowsProgress(t *testing.T) {
	origin := time.Unix(1700000000, 0)
	sequence := &SendSequence{}
	sequence.lastHeadAckTime = origin.Add(40 * time.Second)
	item := &sendItem{sendTime: origin, ackTimeout: 30 * time.Second}
	if deadline, want := sequence.ackLifetimeDeadline(item), origin.Add(70*time.Second); !deadline.Equal(want) {
		t.Fatalf("deadline = %v, want %v", deadline, want)
	}
	sequence.lastHeadAckTime = origin.Add(-time.Second)
	if deadline, want := sequence.ackLifetimeDeadline(item), origin.Add(30*time.Second); !deadline.Equal(want) {
		t.Fatalf("deadline without progress = %v, want %v", deadline, want)
	}
}

// A repeated head ACK, or a late ACK at or below the head, still counts as an
// ACK window update, but it is not progress. A head stuck on a lost message
// keeps receiving such ACKs, and they must not renew the sequence forever.
func TestAckLifetimeIgnoresRepeatedHeadAck(t *testing.T) {
	const ackTimeout = 30 * time.Second
	origin := time.Unix(1700000000, 0)
	window := newSequenceAckWindow()
	sequence := &SendSequence{resendQueue: newResendQueue(nil, 0)}
	apply := func(at time.Time) {
		snapshot := window.Snapshot(true)
		if snapshot.ackUpdateCount == 0 {
			t.Fatalf("ACK at %v was not counted as a window update", at.Sub(origin))
		}
		sequence.noteHeadAck(snapshot.headAck.sequenceNumber, at)
	}

	window.Update(sequenceAck{sequenceNumber: 5, messageId: NewId()})
	apply(origin.Add(10 * time.Second))

	item := &sendItem{
		transferItem: transferItem{messageId: NewId(), sequenceNumber: 6},
		sendTime:     origin,
		ackTimeout:   ackTimeout,
		resendTime:   origin.Add(time.Minute),
		expectsAck:   true,
	}
	sequence.addResendItem(item)
	defer sequence.ackLifetimes.clear()
	defer sequence.resendQueue.Clear()

	// The same head again, then a late selective ACK below it.
	window.Update(sequenceAck{sequenceNumber: 5, messageId: NewId()})
	apply(origin.Add(25 * time.Second))
	window.Update(sequenceAck{sequenceNumber: 3, messageId: NewId(), selective: true})
	apply(origin.Add(35 * time.Second))
	if want := origin.Add(10 * time.Second); !sequence.lastHeadAckTime.Equal(want) {
		t.Fatalf("lastHeadAckTime = %v, want the last advance at %v", sequence.lastHeadAckTime, want)
	}
	if deadline, err := sequence.nextAckLifetime(origin.Add(40 * time.Second)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stuck head must expire at the last advance plus the lifetime, got deadline=%v err=%v", deadline, err)
	}

	// A head that moves forward still renews.
	window.Update(sequenceAck{sequenceNumber: 6, messageId: NewId()})
	apply(origin.Add(45 * time.Second))
	if want := origin.Add(45 * time.Second); !sequence.lastHeadAckTime.Equal(want) {
		t.Fatalf("lastHeadAckTime = %v, want the advance at %v", sequence.lastHeadAckTime, want)
	}
}
