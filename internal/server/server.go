// Package server implements the /v1 HTTP API from docs/api.md.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/amorabito/agent-cred-broker/internal/audit"
	"github.com/amorabito/agent-cred-broker/internal/lease"
	"github.com/amorabito/agent-cred-broker/internal/policy"
	"github.com/amorabito/agent-cred-broker/internal/provider"
	"github.com/amorabito/agent-cred-broker/internal/ratelimit"
)

// AuthnFunc validates a presented bearer token and returns the subject.
type AuthnFunc func(ctx context.Context, token string) (*audit.Subject, error)

// Config holds tunables with safe defaults.
type Config struct {
	LeaseRatePerMinute float64 // default 10
	LeaseBurst         int     // default 10
	ClaimRatePerMinute float64 // default 60
	ClaimBurst         int     // default 60
	MaxBodyBytes       int64   // default 16 KiB
	MaxContextBytes    int     // default 4 KiB
	MaxClaimBytes      int     // default 2 KiB
	MaxClaimsPerReq    int     // default 50
}

func (c *Config) applyDefaults() {
	if c.LeaseRatePerMinute == 0 {
		c.LeaseRatePerMinute = 10
	}
	if c.LeaseBurst == 0 {
		c.LeaseBurst = 10
	}
	if c.ClaimRatePerMinute == 0 {
		c.ClaimRatePerMinute = 60
	}
	if c.ClaimBurst == 0 {
		c.ClaimBurst = 60
	}
	if c.MaxBodyBytes == 0 {
		// Must accommodate a spec-valid claims batch: MaxClaimsPerReq ×
		// MaxClaimBytes plus JSON envelope overhead.
		c.MaxBodyBytes = 128 << 10
	}
	if c.MaxContextBytes == 0 {
		c.MaxContextBytes = 4 << 10
	}
	if c.MaxClaimBytes == 0 {
		c.MaxClaimBytes = 2 << 10
	}
	if c.MaxClaimsPerReq == 0 {
		c.MaxClaimsPerReq = 50
	}
}

// Server implements the /v1 API handlers and their middleware.
type Server struct {
	cfg       Config
	policies  *policy.Store
	authn     AuthnFunc
	providers map[string]provider.Provider
	leases    *lease.Store
	emitter   *audit.Emitter
	signer    *audit.Signer
	metrics   *Metrics

	leaseLimiter    *ratelimit.Limiter
	claimLimiter    *ratelimit.Limiter
	authFailLimiter *ratelimit.Limiter
	rlAudit         *ratelimit.Limiter // aggregates rate-limit lease.denied so the throttle path isn't itself a flood
	claimBudget     *ratelimit.ByteBudget

	now func() time.Time
}

// New wires a Server from its collaborators; cfg zero-values get defaults.
func New(cfg Config, policies *policy.Store, authn AuthnFunc, providers map[string]provider.Provider,
	leases *lease.Store, emitter *audit.Emitter, signer *audit.Signer, metrics *Metrics) *Server {
	cfg.applyDefaults()
	return &Server{
		cfg:             cfg,
		policies:        policies,
		authn:           authn,
		providers:       providers,
		leases:          leases,
		emitter:         emitter,
		signer:          signer,
		metrics:         metrics,
		leaseLimiter:    ratelimit.New(cfg.LeaseRatePerMinute, cfg.LeaseBurst),
		claimLimiter:    ratelimit.New(cfg.ClaimRatePerMinute, cfg.ClaimBurst),
		authFailLimiter: ratelimit.New(1, 1), // ≤1 auth.failed event/min/source
		rlAudit:         ratelimit.New(1, 1), // ≤1 rate-limited lease.denied/min/subject
		claimBudget:     ratelimit.NewByteBudget(),
		now:             time.Now,
	}
}

// SetClock overrides time (tests only).
func (s *Server) SetClock(now func() time.Time) { s.now = now }

type ctxKey int

const (
	ctxSubject ctxKey = iota
	ctxRequestID
	ctxSource
)

func subjectFrom(ctx context.Context) *audit.Subject {
	s, _ := ctx.Value(ctxSubject).(*audit.Subject)
	return s
}
func requestIDFrom(ctx context.Context) string { id, _ := ctx.Value(ctxRequestID).(string); return id }
func sourceFrom(ctx context.Context) *audit.Source {
	s, _ := ctx.Value(ctxSource).(*audit.Source)
	return s
}

// Handler returns the authenticated API mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/leases", s.handleLeaseCreate)
	mux.HandleFunc("POST /v1/leases/{id}/renew", s.handleLeaseRenew)
	mux.HandleFunc("DELETE /v1/leases/{id}", s.handleLeaseSurrender)
	mux.HandleFunc("GET /v1/leases/{id}", s.handleLeaseGet)
	mux.HandleFunc("POST /v1/claims", s.handleClaims)
	mux.HandleFunc("GET /v1/whoami", s.handleWhoami)
	return s.withRequestID(s.withAuth(mux))
}

// HealthHandler returns the unauthenticated mux (separate listener: health,
// readiness, metrics, verify-key). Kept off the main port so the chart's
// NetworkPolicy can expose it to scrapers only.
func (s *Server) HealthHandler(ready func() bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if ready() {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	mux.Handle("GET /metrics", s.metrics)
	mux.HandleFunc("GET /v1/audit/verify-key", s.handleVerifyKey)
	return mux
}

func (s *Server) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		id := "req_" + hex.EncodeToString(b)
		w.Header().Set("X-Request-Id", id)

		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr // no port (some test transports)
		}
		// RemoteAddr only: X-Forwarded-For is caller-controlled and the
		// broker is called pod-to-pod, not through a proxy.
		src := &audit.Source{IP: ip, UserAgent: r.UserAgent()}

		ctx := context.WithValue(r.Context(), ctxRequestID, id)
		ctx = context.WithValue(ctx, ctxSource, src)
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := requestIDFrom(r.Context())
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || token == "" {
			s.recordAuthFailure(r, "missing-bearer")
			writeProblem(w, http.StatusUnauthorized, ProblemUnauthenticated,
				"missing or malformed Authorization header", "", reqID)
			return
		}
		sub, err := s.authn(r.Context(), token)
		if err != nil {
			s.recordAuthFailure(r, "token-rejected")
			writeProblem(w, http.StatusUnauthorized, ProblemUnauthenticated,
				"token rejected", "", reqID)
			return
		}
		ctx := context.WithValue(r.Context(), ctxSubject, sub)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// recordAuthFailure counts every failure in metrics and emits an aggregated,
// per-source-rate-limited auth.failed event — reconnaissance should be
// visible in the stream without becoming a flooding vector itself. The token
// is never recorded.
func (s *Server) recordAuthFailure(r *http.Request, reason string) {
	s.metrics.Inc("acb_auth_failures_total", nil)
	src := sourceFrom(r.Context())
	key := ""
	if src != nil {
		key = src.IP
	}
	if !s.authFailLimiter.Allow(key) {
		return
	}
	_ = s.emitter.Emit(audit.Event{
		Type:      audit.TypeAuthFailed,
		RequestID: requestIDFrom(r.Context()),
		Source:    src,
		Attested:  map[string]any{"reason": reason, "aggregated": true},
	})
}

// rateLimited counts every throttled request in metrics and writes the 429, then
// emits an aggregated (≤1/subject/min) signed lease.denied so a flooding agent —
// the exact signal the limiter exists to catch — leaves a footprint in the audit
// stream without the throttle path itself becoming a flood vector. endpoint marks
// which limiter fired (leases | claims). Returns false so callers can `return`.
func (s *Server) rateLimited(w http.ResponseWriter, sub *audit.Subject, src *audit.Source, reqID, endpoint, title string) bool {
	s.metrics.Inc("acb_rate_limited_total", map[string]string{"subject": sub.Key()})
	if s.rlAudit.Allow(sub.Key()) {
		_ = s.emitter.Emit(audit.Event{
			Type: audit.TypeLeaseDenied, RequestID: reqID, Subject: sub, Source: src,
			Attested: map[string]any{
				"reason": "rate-limited", "decision": "denied", "aggregated": true,
				"endpoint": endpoint, "policy_hash": s.policies.Current().Hash,
			},
		})
	}
	writeProblem(w, http.StatusTooManyRequests, ProblemRateLimited, title, "", reqID)
	return false
}
