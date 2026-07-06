package notify

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/amorabito/agent-cred-broker/internal/audit"
	"github.com/amorabito/agent-cred-broker/internal/ratelimit"
)

// Audit event types the proxy emits (signed under the proxy's own key).
const (
	TypeNotifyForwarded = "notify.forwarded"
	TypeNotifyDenied    = "notify.denied"
	TypeProxyStarted    = "proxy.started"
	TypeAuthFailed      = "auth.failed"
)

// allowedPushDataKeys is the hand-maintained allowlist of push `data` keys.
// HA actionable-notification data can trigger service calls, so "just a push"
// is not fully inert — any key outside this set is rejected (ADR-0006). This is
// enforcement only because the list is real and small.
var allowedPushDataKeys = map[string]bool{"group": true, "tag": true, "url": true}

// AuthnFunc validates a presented bearer token (the broker's authn.Reviewer).
type AuthnFunc func(ctx context.Context, token string) (*audit.Subject, error)

// Metrics is the subset of the shared counter registry the proxy needs, plus
// its /metrics handler. server.Metrics satisfies this structurally.
type Metrics interface {
	Inc(name string, labels map[string]string)
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}

// Config holds tunables with safe defaults.
type Config struct {
	RatePerMinute float64 // per-caller notify rate; default 12
	Burst         int     // default 6
	MaxBodyBytes  int64   // default 16 KiB
}

func (c *Config) applyDefaults() {
	if c.RatePerMinute == 0 {
		c.RatePerMinute = 12
	}
	if c.Burst == 0 {
		c.Burst = 6
	}
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = 16 << 10
	}
}

// Server is the ha-notify-proxy HTTP API.
type Server struct {
	cfg     Config
	policy  *Policy
	authn   AuthnFunc
	ha      *HAClient
	lease   *LeaseClient
	emitter *audit.Emitter
	signer  *audit.Signer
	metrics Metrics

	limiter  *ratelimit.Limiter
	authFail *ratelimit.Limiter
	rlAudit  *ratelimit.Limiter // aggregates rate-limit notify.denied so the throttle path isn't itself a flood
}

func New(cfg Config, policy *Policy, authn AuthnFunc, ha *HAClient, lease *LeaseClient,
	emitter *audit.Emitter, signer *audit.Signer, metrics Metrics) *Server {
	cfg.applyDefaults()
	return &Server{
		cfg: cfg, policy: policy, authn: authn, ha: ha, lease: lease,
		emitter: emitter, signer: signer, metrics: metrics,
		limiter:  ratelimit.New(cfg.RatePerMinute, cfg.Burst),
		authFail: ratelimit.New(1, 1), // <=1 auth.failed event/min/source
		rlAudit:  ratelimit.New(1, 1), // <=1 rate-limit notify.denied/min/subject
	}
}

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

// Handler returns the authenticated API mux. The more specific
// /persistent/dismiss route wins over /persistent for its POSTs (Go 1.22 mux).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/notify/push", s.handlePush)
	mux.HandleFunc("POST /v1/notify/persistent", s.handlePersistentCreate)
	mux.HandleFunc("POST /v1/notify/persistent/dismiss", s.handlePersistentDismiss)
	return s.withRequestID(s.withAuth(mux))
}

// HealthHandler returns the unauthenticated mux (health, readiness, metrics,
// verify-key), served on a separate port.
func (s *Server) HealthHandler(ready func() bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if ready() {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	mux.Handle("GET /metrics", s.metrics)
	mux.HandleFunc("GET /v1/audit/verify-key", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"keys": []map[string]string{{"kid": s.signer.KID(), "alg": "Ed25519", "public_key": s.signer.PublicBase64()}},
		})
	})
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
			ip = r.RemoteAddr
		}
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
			writeProblem(w, http.StatusUnauthorized, ProblemUnauthenticated, "missing or malformed Authorization header", "", reqID)
			return
		}
		sub, err := s.authn(r.Context(), token)
		if err != nil {
			s.recordAuthFailure(r, "token-rejected")
			writeProblem(w, http.StatusUnauthorized, ProblemUnauthenticated, "token rejected", "", reqID)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxSubject, sub)))
	})
}

func (s *Server) recordAuthFailure(r *http.Request, reason string) {
	s.metrics.Inc("acb_auth_failures_total", nil)
	src := sourceFrom(r.Context())
	key := ""
	if src != nil {
		key = src.IP
	}
	if !s.authFail.Allow(key) {
		return
	}
	_ = s.emitter.Emit(audit.Event{
		Type: TypeAuthFailed, RequestID: requestIDFrom(r.Context()), Source: src,
		Attested: map[string]any{"reason": reason, "aggregated": true},
	})
}

// --- handlers ---

type pushReq struct {
	Title   string            `json:"title"`
	Message string            `json:"message"`
	Data    map[string]string `json:"data"`
}

func (s *Server) handlePush(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sub, reqID, src := subjectFrom(ctx), requestIDFrom(ctx), sourceFrom(ctx)
	if !s.rateOK(w, sub, src, reqID) {
		return
	}
	var req pushReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// An authenticated caller's malformed/oversized body is still an
		// attributable refusal — audit it (a bad body must not be a quieter
		// probe than a well-formed unauthorized one). rateOK already bounded it.
		s.deny(w, reqID, sub, src, KindPush, "bad-body", http.StatusBadRequest, ProblemBadRequest, "invalid request body", nil)
		return
	}
	target := s.policy.PushTarget(sub.Key()) // "" if no push grant
	if target == "" {
		s.deny(w, reqID, sub, src, KindPush, "no-grant", http.StatusForbidden, ProblemGrantDenied, "not permitted", nil)
		return
	}
	for k := range req.Data {
		if !allowedPushDataKeys[k] {
			s.deny(w, reqID, sub, src, KindPush, "bad-data-key", http.StatusBadRequest, ProblemBadRequest, "unsupported data key", map[string]string{"data_key": k})
			return
		}
	}
	haBody := map[string]any{"title": req.Title, "message": req.Message}
	if len(req.Data) > 0 {
		haBody["data"] = req.Data
	}
	s.forward(ctx, w, sub, src, reqID, KindPush, "notify", target, haBody)
}

type persistReq struct {
	NotificationID string `json:"notification_id"`
	Title          string `json:"title"`
	Message        string `json:"message"`
}

func (s *Server) handlePersistentCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sub, reqID, src := subjectFrom(ctx), requestIDFrom(ctx), sourceFrom(ctx)
	if !s.rateOK(w, sub, src, reqID) {
		return
	}
	var req persistReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.deny(w, reqID, sub, src, KindPersistentCreate, "bad-body", http.StatusBadRequest, ProblemBadRequest, "invalid request body", nil)
		return
	}
	if !s.idAllowed(sub, KindPersistentCreate, req.NotificationID) {
		s.deny(w, reqID, sub, src, KindPersistentCreate, "no-grant-or-prefix", http.StatusForbidden, ProblemGrantDenied, "not permitted", map[string]string{"requested_notification_id": req.NotificationID})
		return
	}
	haBody := map[string]any{"notification_id": req.NotificationID, "title": req.Title, "message": req.Message}
	s.forward(ctx, w, sub, src, reqID, KindPersistentCreate, "persistent_notification", "create", haBody)
}

type dismissReq struct {
	NotificationID string `json:"notification_id"`
}

func (s *Server) handlePersistentDismiss(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sub, reqID, src := subjectFrom(ctx), requestIDFrom(ctx), sourceFrom(ctx)
	if !s.rateOK(w, sub, src, reqID) {
		return
	}
	var req dismissReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.deny(w, reqID, sub, src, KindPersistentDismiss, "bad-body", http.StatusBadRequest, ProblemBadRequest, "invalid request body", nil)
		return
	}
	if !s.idAllowed(sub, KindPersistentDismiss, req.NotificationID) {
		s.deny(w, reqID, sub, src, KindPersistentDismiss, "no-grant-or-prefix", http.StatusForbidden, ProblemGrantDenied, "not permitted", map[string]string{"requested_notification_id": req.NotificationID})
		return
	}
	haBody := map[string]any{"notification_id": req.NotificationID}
	s.forward(ctx, w, sub, src, reqID, KindPersistentDismiss, "persistent_notification", "dismiss", haBody)
}

// idAllowed reports whether the subject may act on a persistent notification_id:
// it must hold the grant AND the id must carry the grant's required prefix.
func (s *Server) idAllowed(sub *audit.Subject, kind, id string) bool {
	g := s.policy.Grant(sub.Key(), kind)
	return g != nil && id != "" && strings.HasPrefix(id, g.IDPrefix)
}

func (s *Server) rateOK(w http.ResponseWriter, sub *audit.Subject, src *audit.Source, reqID string) bool {
	if s.limiter.Allow(sub.Key()) {
		return true
	}
	s.metrics.Inc("acb_notify_rate_limited_total", map[string]string{"subject": sub.Key()})
	// A throttled request is the exact attack signal the limiter exists to catch
	// (a flooding agent), so it must leave a signed footprint — but aggregated
	// (>=1/subject/min) so the throttle path can't itself become the flood vector
	// (ADR-0006). The metric counts every attempt; the signed record samples.
	if s.rlAudit.Allow(sub.Key()) {
		_ = s.emitter.Emit(audit.Event{
			Type: TypeNotifyDenied, RequestID: reqID, Subject: sub, Source: src,
			Attested: map[string]any{"reason": "rate-limited", "decision": "denied", "aggregated": true, "policy_hash": s.policy.Hash},
		})
	}
	writeProblem(w, http.StatusTooManyRequests, ProblemRateLimited, "notify rate limit exceeded", "", reqID)
	return false
}

// forward leases the HA token, makes the one HA call, drops the token, and
// emits a best-effort signed notify.forwarded. The notification is the point;
// audit is observation, not a disclosure gate — so a failed emit does not undo
// a sent push (ADR-0006, best-effort audit).
func (s *Server) forward(ctx context.Context, w http.ResponseWriter, sub *audit.Subject, src *audit.Source, reqID, kind, domain, service string, haBody map[string]any) {
	lctx := map[string]string{"originating_agent": sub.Key(), "action": kind, "ha_service": domain + "/" + service}
	if sub.Pod != "" {
		lctx["originating_pod"] = sub.Pod
	}
	lease, err := s.lease.Lease(ctx, lctx)
	if err != nil {
		s.metrics.Inc("acb_notify_lease_errors_total", nil)
		s.emitForwarded(reqID, sub, src, kind, domain, service, 0, false, "", "lease-failed")
		writeProblem(w, http.StatusBadGateway, ProblemUpstreamFailure, "could not obtain notify credential", "", reqID)
		return
	}
	status, callErr := s.ha.Call(ctx, lease.Token, domain, service, haBody)
	delivered := callErr == nil && status >= 200 && status < 300
	errClass := ""
	switch {
	case callErr != nil:
		errClass = "ha-unreachable"
	case !delivered:
		errClass = "ha-status"
	}
	s.emitForwarded(reqID, sub, src, kind, domain, service, status, delivered, lease.LeaseID, errClass)
	if !delivered {
		s.metrics.Inc("acb_notify_ha_errors_total", map[string]string{"kind": kind})
		writeProblem(w, http.StatusBadGateway, ProblemUpstreamFailure, "notification not delivered", "", reqID)
		return
	}
	s.metrics.Inc("acb_notify_forwarded_total", map[string]string{"kind": kind})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{"delivered": true, "request_id": reqID})
}

func (s *Server) emitForwarded(reqID string, sub *audit.Subject, src *audit.Source, kind, domain, service string, status int, delivered bool, leaseID, errClass string) {
	att := map[string]any{
		"kind": kind, "ha_domain": domain, "ha_service": service,
		"ha_status": status, "delivered": delivered, "policy_hash": s.policy.Hash,
	}
	if leaseID != "" {
		att["lease_id"] = leaseID
	}
	if errClass != "" {
		att["error"] = errClass
	}
	_ = s.emitter.Emit(audit.Event{Type: TypeNotifyForwarded, RequestID: reqID, Subject: sub, Source: src, Attested: att})
}

func (s *Server) deny(w http.ResponseWriter, reqID string, sub *audit.Subject, src *audit.Source, kind, reason string, status int, ptype, title string, asserted map[string]string) {
	s.metrics.Inc("acb_notify_denied_total", map[string]string{"kind": kind, "reason": reason})
	_ = s.emitter.Emit(audit.Event{
		Type: TypeNotifyDenied, RequestID: reqID, Subject: sub, Source: src,
		Attested: map[string]any{"kind": kind, "reason": reason, "decision": "denied", "policy_hash": s.policy.Hash},
		Asserted: asserted, // caller-supplied (a requested id): treat with suspicion
	})
	writeProblem(w, status, ptype, title, "", reqID)
}

// EmitStarted emits the signed proxy.started event (called once by main).
func (s *Server) EmitStarted() {
	_ = s.emitter.Emit(audit.Event{
		Type: TypeProxyStarted,
		Attested: map[string]any{
			"policy_hash": s.policy.Hash, "kid": s.signer.KID(), "public_key": s.signer.PublicBase64(),
		},
	})
}
