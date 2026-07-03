package lease

import (
	"testing"
	"time"
)

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

func TestRenewOutcomes(t *testing.T) {
	s := NewStore()
	base := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	s.SetClock(fixedClock(base))

	renewable := s.Create("a/b", "scope", "static-disclosure", 10*time.Minute, true)
	fixed := s.Create("a/b", "scope", "static-disclosure", 10*time.Minute, false)

	if _, outcome := s.Renew("lease_nope", time.Minute); outcome != "notfound" {
		t.Fatalf("notfound: %q", outcome)
	}
	if _, outcome := s.Renew(fixed.ID, time.Minute); outcome != "nonrenewable" {
		t.Fatalf("nonrenewable: %q", outcome)
	}
	if l, outcome := s.Renew(renewable.ID, 30*time.Minute); outcome != "" || !l.ExpiresAt.Equal(base.Add(30*time.Minute)) {
		t.Fatalf("renew: %q %v", outcome, l)
	}
	if _, outcome := s.Surrender(renewable.ID); outcome != "" {
		t.Fatalf("surrender: %q", outcome)
	}
	if _, outcome := s.Renew(renewable.ID, time.Minute); outcome != "surrendered" {
		t.Fatalf("renew after surrender: %q", outcome)
	}

	// Past expiry.
	s.SetClock(fixedClock(base.Add(time.Hour)))
	if _, outcome := s.Renew(fixed.ID, time.Minute); outcome != "expired" {
		t.Fatalf("expired: %q", outcome)
	}
}

func TestSurrenderIdempotent(t *testing.T) {
	s := NewStore()
	l := s.Create("a/b", "scope", "static-disclosure", time.Minute, false)
	if _, outcome := s.Surrender(l.ID); outcome != "" {
		t.Fatalf("first surrender: %q", outcome)
	}
	if _, outcome := s.Surrender(l.ID); outcome != "already" {
		t.Fatalf("second surrender must report already, got %q", outcome)
	}
}

func TestSweepEmitsOnceAndPrunes(t *testing.T) {
	s := NewStore()
	base := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	s.SetClock(fixedClock(base))
	l := s.Create("a/b", "scope", "static-disclosure", time.Minute, false)

	if got := s.SweepExpired(time.Hour); len(got) != 0 {
		t.Fatalf("nothing expired yet: %v", got)
	}
	s.SetClock(fixedClock(base.Add(2 * time.Minute)))
	if got := s.SweepExpired(time.Hour); len(got) != 1 || got[0].ID != l.ID {
		t.Fatalf("first sweep: %v", got)
	}
	if got := s.SweepExpired(time.Hour); len(got) != 0 {
		t.Fatalf("second sweep must not re-emit: %v", got)
	}
	// Past retain window the entry is pruned entirely.
	s.SetClock(fixedClock(base.Add(2 * time.Hour)))
	s.SweepExpired(time.Hour)
	if s.Get(l.ID) != nil {
		t.Fatal("lease should be pruned after retain window")
	}
}

func TestSurrenderedLeaseNotSweptAsExpired(t *testing.T) {
	s := NewStore()
	base := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	s.SetClock(fixedClock(base))
	l := s.Create("a/b", "scope", "static-disclosure", time.Minute, false)
	s.Surrender(l.ID)
	s.SetClock(fixedClock(base.Add(2 * time.Minute)))
	if got := s.SweepExpired(time.Hour); len(got) != 0 {
		t.Fatalf("surrendered lease must not emit lease.expired: %v", got)
	}
}
