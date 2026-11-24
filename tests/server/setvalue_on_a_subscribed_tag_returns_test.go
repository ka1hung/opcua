//go:build conformance

// Server.SetValue on a point a client is subscribed to returns, and the
// subscriber is notified of the value that was written.
//
// This is how an application feeds field data into the server while
// clients hold subscriptions, so it is the common case, not an exotic
// one. Writing the value and notifying subscribers must not wait on a
// lock the caller already holds: sync.RWMutex forbids recursive read
// locking ("Note that this prohibits recursive read-locking",
// go/src/sync/rwmutex.go). The specification's nearest clause is
// OPC 10000-3 §5.6.2, "In general Atomicity is expected of OPC UA read
// and write operations" - descriptive rather than a shall; the authority
// the row scores is the Go one.
//
// Neighbouring row: client_keeps_working_across_token_renewals_test.go
// scores the client and server pair across key renewals; this row scores
// one write inside a single token's life.
//
// The row runs against the in-tree server holding one tag namespace, and
// a real client connected over the wire - the shared fixture in
// harness.go, which registers the monitored item through the real
// CreateSubscription and CreateMonitoredItems services. See harness.go.
//
// The row asserts that the write returns within respond, and that a
// notification carrying the written literal reaches the subscription: a
// change that makes SetValue return by not notifying has not fixed
// anything, and the notification check is what catches that. The
// notification only has to arrive within respond; how late inside that
// window it arrives is not scored. It deliberately asserts nothing
// about the wire the value
// crossed - the server encoded it and the client decoded it, both
// gopcua, so the check scores delivery and not bytes. No row anywhere
// holds the literal bytes for an Int32 inside a Variant that this one
// could name; an encoding row in tests/encoding holding those bytes would
// change that. It also asserts nothing about concurrent readers.
//
// It guards against a deadlock measured in upstream gopcua (2026-11-06):
// adding a read lock to the namespace read path made SetValue on a
// subscribed tag block, because the notification path re-enters that read
// while the caller holds the lock. This server passes it.
//
// No reference stack has been read for this behaviour; one would be
// another server.s source. The instrument
// the verdict rests on is a wall clock on the write's return - SetValue
// returns nothing, so the return is scored by outliving the deadline,
// with the write on a goroutine the row spawns and the clock on the
// goroutine that waits - not wire bytes.

package server

import (
	"testing"
	"time"
)

func TestSetValueOnASubscribedTagReturns(t *testing.T) {
	h, teardown, why := startServerAndClient()
	defer teardown()
	if why != "" {
		t.Fatalf("could not set the test up: %s", why)
	}

	subTeardown, why := h.subscribeTo(tag)
	if why != "" {
		t.Fatalf("could not set the test up: %s", why)
	}
	defer subTeardown()

	// The literal comes from outside gopcua; the header says what the
	// notification check scores.
	const written = int32(-4242)

	// The deadline needs the write off the test goroutine: a wedged
	// SetValue called directly would hang the test before it ever reached
	// the deadline. The channel is unbuffered on purpose - the only
	// signal is the close after the call returns.
	returned := make(chan struct{})
	start := time.Now()
	go func() {
		h.ns.SetValue(tag, written)
		close(returned)
	}()

	var elapsed time.Duration
	select {
	case <-returned:
		elapsed = time.Since(start)
	case <-time.After(respond):
		// The verdict the row exists for. Not a decline: the run was
		// scored and the library failed it. Errorf followed by return,
		// because there is nothing left to score after a write that did
		// not return - expectNotification would only add a second failure
		// line five seconds later.
		t.Errorf("SetValue on a subscribed tag did not return within %v", respond)
		return
	}

	if why := h.expectNotification(written); why != "" {
		t.Errorf("%s", why)
	} else {
		t.Logf("SetValue returned after %s and the subscription was notified of %d", elapsed, written)
	}
}
