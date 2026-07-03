// Package ratelimit implements per-key token buckets. These exist to keep a
// compromised agent from flooding the audit stream to bury its own records
// (threat model §4) — static limits, not anomaly response.
package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter is a token-bucket limiter keyed by string (subject, source IP).
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   float64
	now     func() time.Time
}

// New creates a limiter allowing ratePerMinute sustained, burst peak.
func New(ratePerMinute float64, burst int) *Limiter {
	return &Limiter{
		buckets: make(map[string]*bucket),
		rate:    ratePerMinute / 60.0,
		burst:   float64(burst),
		now:     time.Now,
	}
}

// SetClock overrides time (tests only).
func (l *Limiter) SetClock(now func() time.Time) { l.now = now }

// Allow consumes one token for key if available.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// ByteBudget tracks per-key daily byte budgets (claim-bytes cap).
type ByteBudget struct {
	mu   sync.Mutex
	used map[string]int64
	day  int
	now  func() time.Time
}

func NewByteBudget() *ByteBudget {
	return &ByteBudget{used: make(map[string]int64), now: time.Now}
}

// Spend records n bytes for key and reports whether the total stays within
// limit. limit <= 0 means unlimited.
func (b *ByteBudget) Spend(key string, n, limit int64) bool {
	if limit <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	day := b.now().UTC().YearDay()
	if day != b.day {
		b.day = day
		b.used = make(map[string]int64)
	}
	if b.used[key]+n > limit {
		return false
	}
	b.used[key] += n
	return true
}
