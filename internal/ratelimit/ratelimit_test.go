package ratelimit

import (
	"testing"
	"time"
)

func TestBurstThenRefill(t *testing.T) {
	l := New(60, 2) // 1 token/s, burst 2
	base := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	now := base
	l.SetClock(func() time.Time { return now })

	if !l.Allow("k") || !l.Allow("k") {
		t.Fatal("burst of 2 must pass")
	}
	if l.Allow("k") {
		t.Fatal("third immediate call must be limited")
	}
	now = base.Add(1 * time.Second)
	if !l.Allow("k") {
		t.Fatal("one token must refill after 1s at 60/min")
	}
	if l.Allow("k") {
		t.Fatal("refill must not exceed elapsed time")
	}
	// Refill never exceeds burst.
	now = base.Add(time.Hour)
	if !l.Allow("k") || !l.Allow("k") {
		t.Fatal("burst must be available after long idle")
	}
	if l.Allow("k") {
		t.Fatal("bucket must cap at burst")
	}
}

func TestKeysIsolated(t *testing.T) {
	l := New(60, 1)
	if !l.Allow("a") {
		t.Fatal("a's first call")
	}
	if !l.Allow("b") {
		t.Fatal("b must have its own bucket")
	}
	if l.Allow("a") {
		t.Fatal("a must be limited")
	}
}

func TestByteBudgetRollover(t *testing.T) {
	b := NewByteBudget()
	day1 := time.Date(2026, 12, 31, 23, 0, 0, 0, time.UTC)
	now := day1
	b.SetClock(func() time.Time { return now })

	if !b.Spend("k", 100, 100) {
		t.Fatal("within cap")
	}
	if b.Spend("k", 1, 100) {
		t.Fatal("over cap same day")
	}
	// Year boundary: Dec 31 -> Jan 1 must reset.
	now = time.Date(2027, 1, 1, 0, 30, 0, 0, time.UTC)
	if !b.Spend("k", 100, 100) {
		t.Fatal("budget must reset on new UTC day across year boundary")
	}
	if !b.Spend("k", 5, 0) {
		t.Fatal("limit 0 means unlimited")
	}
}
