package policy

import (
	"context"
	"crypto/sha256"
	"os"
	"sync"
	"time"
)

// Store holds the active policy and hot-reloads it when the backing file
// changes. A failed reload keeps the previous policy. Reload outcomes are
// reported through the callbacks so the caller can emit policy.reloaded /
// policy.reload_failed audit events — a grant added out-of-band (live
// ConfigMap edit) must itself become a signed, queryable event.
type Store struct {
	mu      sync.RWMutex
	current *Policy

	path     string
	lastSum  [32]byte
	interval time.Duration

	OnReload func(old, new *Policy)
	OnError  func(oldPolicy *Policy, err error)
}

// NewStore loads the initial policy (fatal on error, by design: a broker with
// no valid policy issues nothing).
func NewStore(path string, interval time.Duration) (*Store, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	return &Store{current: p, path: path, lastSum: sha256.Sum256(raw), interval: interval}, nil
}

// Current returns the active policy.
func (s *Store) Current() *Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// Watch polls the file until ctx is done. Kubernetes updates ConfigMap
// volumes atomically via symlink swap; content polling catches every case.
func (s *Store) Watch(ctx context.Context) {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.reloadIfChanged()
		}
	}
}

func (s *Store) reloadIfChanged() {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if s.OnError != nil {
			s.OnError(s.Current(), err)
		}
		return
	}
	sum := sha256.Sum256(raw)
	if sum == s.lastSum {
		return
	}
	next, err := Parse(raw)
	if err != nil {
		s.lastSum = sum // don't re-report the same broken content every tick
		if s.OnError != nil {
			s.OnError(s.Current(), err)
		}
		return
	}
	s.mu.Lock()
	old := s.current
	s.current = next
	s.lastSum = sum
	s.mu.Unlock()
	if s.OnReload != nil {
		s.OnReload(old, next)
	}
}
