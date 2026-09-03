package node

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Zaltapar/iran-germany-split-tunnel/pkg/session"
)

// Pure unit tests for the aggregate session-buffer budget primitive
// (Issue #6). These exercise the accounting mechanics directly — no
// carriers, no relays, no network — with only the bounded parking
// waits that are part of the refusal policy.

// freshKey builds a DISTINCT bufKey (the zero value collides: two zero
// keys are the same map key). In production the key is bufKey{sess,dir}
// with a non-nil session pointer, so keys are unique; these tests
// mirror that with distinct *session.Session values.
func freshKey(i *session.Session) bufKey { return bufKey{sess: i, dir: session.DirUp} }

func TestBudgetDisabledByDefault(t *testing.T) {
	b := newSessionBufferBudget(0) // 0 = disabled sentinel
	k1, k2 := freshKey(&session.Session{}), freshKey(&session.Session{})
	if k1 == k2 {
		t.Fatal("test keys must be distinct")
	}
	b.begin(k1)
	b.begin(k2)
	ctx := context.Background()
	// Disabled: every charge is admitted, nothing is accounted.
	for i := 0; i < 100; i++ {
		if !b.chargeWait(k1, 1<<20, ctx) {
			t.Fatalf("disabled budget must admit charge #%d", i)
		}
	}
	if got := b.AccountedBytes(); got != 0 {
		t.Fatalf("disabled budget must account 0, got %d", got)
	}
	// Refund/end are no-ops on the aggregate but still deregister.
	if r := b.refund(k1, 1<<20); r != 0 {
		t.Fatalf("disabled refund must reclaim 0, got %d", r)
	}
	if r := b.end(k1); r != 0 {
		t.Fatalf("disabled end must reclaim 0, got %d", r)
	}
	if b.ActiveRelays() != 1 {
		t.Fatalf("ActiveRelays = %d, want 1 (k2 still registered)", b.ActiveRelays())
	}
	if r := b.Close(); r != 0 {
		t.Fatalf("disabled Close must reclaim 0, got %d", r)
	}
	if b.ActiveRelays() != 0 || b.AccountedBytes() != 0 {
		t.Fatalf("after Close: active=%d accounted=%d, want 0/0",
			b.ActiveRelays(), b.AccountedBytes())
	}
}

func TestBudgetChargeRefusalParkingAndFree(t *testing.T) {
	const limit = 1000
	b := newSessionBufferBudget(limit)
	k1, k2 := freshKey(&session.Session{}), freshKey(&session.Session{})
	if k1 == k2 {
		t.Fatal("test keys must be distinct")
	}
	b.begin(k1)
	b.begin(k2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// k1 fills the whole budget.
	if !b.chargeWait(k1, 1000, ctx) {
		t.Fatal("charge 1000 (exactly the cap) must be admitted")
	}
	if got := b.AccountedBytes(); got != limit {
		t.Fatalf("accounted = %d, want %d", got, limit)
	}
	// k2 is REFUSED (saturated): it must park, not over-admit.
	parked := make(chan bool, 1)
	go func() { parked <- b.chargeWait(k2, 100, ctx) }()
	select {
	case ok := <-parked:
		t.Fatalf("charge at the cap must have parked, returned %v", ok)
	case <-time.After(50 * time.Millisecond): // observation, not sync
	}
	if got := b.AccountedBytes(); got != limit {
		t.Fatalf("parked charge must not account; accounted = %d, want %d", got, limit)
	}
	// k1 frees 500: the parker must wake and be admitted (it wanted
	// 100 <= 500 headroom).
	if r := b.refund(k1, 500); r != 500 {
		t.Fatalf("refund reclaimed %d, want 500", r)
	}
	select {
	case ok := <-parked:
		if !ok {
			t.Fatal("woken parker must be admitted after space frees")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("parker was not woken by the refund")
	}
	if got := b.AccountedBytes(); got != 600 {
		t.Fatalf("accounted = %d, want 600 (500 + 100)", got)
	}
	// k2 top-up to exactly the cap (600 + 400 = 1000): admitted.
	if !b.chargeWait(k2, 400, ctx) {
		t.Fatal("charge 400 to reach the cap must be admitted (600+400=1000)")
	}
	// Now k2 cannot exceed the cap.
	parked2 := make(chan bool, 1)
	go func() { parked2 <- b.chargeWait(k2, 100, ctx) }()
	select {
	case ok := <-parked2:
		t.Fatalf("charge over the cap must park, returned %v", ok)
	case <-time.After(50 * time.Millisecond):
	}
	// ctx done: the parker exits refused, even with no refund.
	cancel()
	select {
	case ok := <-parked2:
		if ok {
			t.Fatal("parker after ctx cancel must be refused")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("parker was not released by ctx cancel")
	}
	if got := b.AccountedBytes(); got != 1000 {
		t.Fatalf("refused parker must not account; accounted = %d, want 1000", got)
	}
	// end reclaims the rest; a second end is 0 (idempotent).
	if r := b.end(k1); r != 500 {
		t.Fatalf("end(k1) reclaimed %d, want 500", r)
	}
	if r := b.end(k2); r != 500 {
		t.Fatalf("end(k2) reclaimed %d, want 500 (100+400)", r)
	}
	if r := b.end(k2); r != 0 {
		t.Fatalf("second end must reclaim 0, got %d", r)
	}
	if got := b.AccountedBytes(); got != 0 {
		t.Fatalf("after end accounted = %d, want 0", got)
	}
}

func TestBudgetNeverDrivesNegative(t *testing.T) {
	b := newSessionBufferBudget(1000)
	k := freshKey(&session.Session{})
	b.begin(k)
	ctx := context.Background()
	if !b.chargeWait(k, 100, ctx) {
		t.Fatal("charge 100 must be admitted")
	}
	// Over-refund must be clamped to the outstanding amount — never
	// negative (the Phase 3 invariant the issue calls out).
	if r := b.refund(k, 10_000); r != 100 {
		t.Fatalf("clamped refund reclaimed %d, want 100", r)
	}
	if got := b.AccountedBytes(); got != 0 {
		t.Fatalf("accounted = %d, want 0 (no negative drift)", got)
	}
	if r := b.refund(k, 5); r != 0 {
		t.Fatalf("refund after full reclaim must be 0, got %d", r)
	}
	// Charge on an unknown key is refused (no park, no hang).
	other := freshKey(&session.Session{})
	if b.chargeWait(other, 1, ctx) {
		t.Fatal("charge for an unregistered relay must be refused")
	}
	if got := b.AccountedBytes(); got != 0 {
		t.Fatalf("accounted = %d, want 0", got)
	}
}

func TestBudgetConcurrentChargersNoOverAdmit(t *testing.T) {
	// The check-then-add under one mutex must never admit more than the
	// limit, no matter how many relays race. 64 relays each charge 100
	// bytes against a 1000-byte budget: at most 10 may be admitted.
	const limit = 1000
	b := newSessionBufferBudget(limit)
	const n = 64
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		k := freshKey(&session.Session{})
		b.begin(k)
		wg.Add(1)
		go func(k bufKey) {
			defer wg.Done()
			if b.chargeWait(k, 100, ctx) {
				// Admitted: hold it until the test drains.
			}
		}(k)
	}
	// Admissions happen as the scheduler permits; wait (bounded) for the
	// settle point: 64 x 100 = 6400 >> 1000, so exactly 10 chargers fit
	// and the budget is full; the other 54 park on ctx=Background.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if b.AccountedBytes() == limit {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if got := b.AccountedBytes(); got > limit {
		t.Fatalf("concurrent chargers over-admitted: accounted %d > limit %d", got, limit)
	}
	if got := b.AccountedBytes(); got != limit {
		t.Fatalf("settle point: accounted %d, want %d (exactly 10 x 100 admitted)", got, limit)
	}
	// Close force-reclaims the 10 admitted charges (1000) and wakes the
	// parked chargers (they return false), so nothing leaks.
	if r := b.Close(); r != limit {
		t.Fatalf("Close reclaimed %d, want %d", r, limit)
	}
	wg.Wait() // parked chargers exit now (woken by Close)
	if b.AccountedBytes() != 0 || b.ActiveRelays() != 0 {
		t.Fatalf("after Close: accounted=%d active=%d, want 0/0",
			b.AccountedBytes(), b.ActiveRelays())
	}
}

func TestBudgetCloseReclaimsAndWakes(t *testing.T) {
	const limit = 1000
	b := newSessionBufferBudget(limit)
	ks := make([]bufKey, 3)
	for i := range ks {
		ks[i] = freshKey(&session.Session{})
		b.begin(ks[i])
	}
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if !b.chargeWait(ks[i], 400, ctx) {
			t.Fatalf("charge %d must be admitted", i)
		}
	}
	// ks[2] parks (800 + 300 > 1000).
	parked := make(chan bool, 1)
	go func() { parked <- b.chargeWait(ks[2], 300, ctx) }()
	select {
	case ok := <-parked:
		t.Fatalf("charge at 800/1000 wanting 300 must park, returned %v", ok)
	case <-time.After(50 * time.Millisecond):
	}
	// Close force-reclaims 800 and wakes the parker (which is refused).
	if r := b.Close(); r != 800 {
		t.Fatalf("Close reclaimed %d, want 800", r)
	}
	select {
	case ok := <-parked:
		if ok {
			t.Fatal("parker after Close must be refused")
		}
	case <-time.After(time.Second):
		t.Fatal("parker was not woken by Close")
	}
	if r := b.Close(); r != 0 {
		t.Fatalf("second Close must reclaim 0, got %d", r)
	}
	if b.AccountedBytes() != 0 || b.ActiveRelays() != 0 {
		t.Fatalf("after Close: accounted=%d active=%d, want 0/0",
			b.AccountedBytes(), b.ActiveRelays())
	}
	// Post-close: charge is refused, end is a no-op.
	if b.chargeWait(ks[0], 1, ctx) {
		t.Fatal("charge after Close must be refused")
	}
	if r := b.end(ks[0]); r != 0 {
		t.Fatalf("end after Close must reclaim 0, got %d", r)
	}
}
