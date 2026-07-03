// Package lease tracks issued leases in memory. Leases are audit constructs:
// losing them on restart loses renewal/surrender continuity, not security —
// the signed event stream in Loki remains the durable record.
package lease

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Lease is one issuance of a scope's secret material to a subject.
type Lease struct {
	ID         string
	SubjectKey string
	Scope      string
	Semantics  string
	IssuedAt   time.Time
	ExpiresAt  time.Time
	Renewable  bool

	Surrendered bool
	expiredEmit bool
}

// Store is the in-memory lease table.
type Store struct {
	mu     sync.Mutex
	leases map[string]*Lease
	now    func() time.Time
}

// NewStore creates an empty lease store.
func NewStore() *Store {
	return &Store{leases: make(map[string]*Lease), now: time.Now}
}

// SetClock overrides time (tests only).
func (s *Store) SetClock(now func() time.Time) { s.now = now }

// NewID returns a random identifier with the given prefix; used for lease
// and claim IDs (104 bits of crypto/rand entropy).
func NewID(prefix string) string {
	b := make([]byte, 13)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failure is not a recoverable state
	}
	return prefix + "_" + hex.EncodeToString(b)
}

func (s *Store) Create(subjectKey, scope, semantics string, ttl time.Duration, renewable bool) *Lease {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	l := &Lease{
		ID:         NewID("lease"),
		SubjectKey: subjectKey,
		Scope:      scope,
		Semantics:  semantics,
		IssuedAt:   now,
		ExpiresAt:  now.Add(ttl),
		Renewable:  renewable,
	}
	s.leases[l.ID] = l
	return l
}

// Get returns a copy of the lease, or nil.
func (s *Store) Get(id string) *Lease {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.leases[id]
	if l == nil {
		return nil
	}
	cp := *l
	return &cp
}

// Renew extends a lease. Returns the updated copy, or an outcome string:
// "notfound", "expired", "nonrenewable", "surrendered".
func (s *Store) Renew(id string, ttl time.Duration) (*Lease, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.leases[id]
	switch {
	case l == nil:
		return nil, "notfound"
	case l.Surrendered:
		return nil, "surrendered"
	case s.now().After(l.ExpiresAt):
		return nil, "expired"
	case !l.Renewable:
		return nil, "nonrenewable"
	}
	l.ExpiresAt = s.now().Add(ttl)
	cp := *l
	return &cp, ""
}

// Surrender marks a lease done. Purely an audit marker for static secrets.
// Surrendering an already-surrendered lease returns outcome "already" so the
// handler can stay idempotent without emitting another event.
func (s *Store) Surrender(id string) (*Lease, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.leases[id]
	if l == nil {
		return nil, "notfound"
	}
	if l.Surrendered {
		cp := *l
		return &cp, "already"
	}
	l.Surrendered = true
	cp := *l
	return &cp, ""
}

// Remove deletes a lease outright. Used to roll back an issuance whose
// audit event failed to write — the secret was never disclosed.
func (s *Store) Remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.leases, id)
}

// SweepExpired returns leases newly past expiry (each at most once) and
// prunes long-dead entries. Callers emit best-effort lease.expired events.
func (s *Store) SweepExpired(retain time.Duration) []Lease {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var out []Lease
	for id, l := range s.leases {
		if now.After(l.ExpiresAt) && !l.expiredEmit && !l.Surrendered {
			l.expiredEmit = true
			out = append(out, *l)
		}
		if now.After(l.ExpiresAt.Add(retain)) {
			delete(s.leases, id)
		}
	}
	return out
}
