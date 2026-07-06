package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/amorabito/agent-cred-broker/internal/audit"
	"github.com/amorabito/agent-cred-broker/internal/lease"
	"github.com/amorabito/agent-cred-broker/internal/policy"
	"github.com/amorabito/agent-cred-broker/internal/provider"
)

type leaseRequest struct {
	Scope      string            `json:"scope"`
	TTLSeconds int64             `json:"ttl_seconds"`
	Context    map[string]string `json:"context"`
}

type leaseResponse struct {
	LeaseID   string            `json:"lease_id"`
	Scope     string            `json:"scope"`
	IssuedAt  string            `json:"issued_at"`
	ExpiresAt string            `json:"expires_at"`
	Renewable bool              `json:"renewable"`
	Semantics string            `json:"semantics"`
	Secret    map[string]string `json:"secret,omitempty"`
}

func leaseMeta(l *lease.Lease) leaseResponse {
	return leaseResponse{
		LeaseID:   l.ID,
		Scope:     l.Scope,
		IssuedAt:  l.IssuedAt.UTC().Format(time.RFC3339),
		ExpiresAt: l.ExpiresAt.UTC().Format(time.RFC3339),
		Renewable: l.Renewable,
		Semantics: l.Semantics,
	}
}

// clampTTL resolves the effective TTL from a request against a grant. The
// clamp works in integer seconds BEFORE converting to time.Duration —
// time.Duration(math.MaxInt64) * time.Second overflows negative and would
// otherwise slip past a duration-typed comparison.
func clampTTL(requested int64, g *policy.Grant) (time.Duration, bool) {
	if requested < 0 {
		return 0, false
	}
	if requested == 0 {
		return g.TTLDefault.D(), true
	}
	maxSeconds := int64(g.TTLMax.D() / time.Second)
	if requested > maxSeconds {
		requested = maxSeconds
	}
	return time.Duration(requested) * time.Second, true
}

// auditFailClosed handles an Emit error on a path where the event is the
// point (disclosure, claim receipt): count it and fail the request. No
// credential leaves the broker unrecorded.
func (s *Server) auditFailClosed(w http.ResponseWriter, reqID string, err error) {
	s.metrics.Inc("acb_audit_write_errors_total", nil)
	writeProblem(w, http.StatusInternalServerError, ProblemAuditUnavailable,
		"audit event could not be written; request failed closed", "", reqID)
	_ = err // error detail stays out of responses; it may describe broker internals
}

func (s *Server) handleLeaseCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sub, reqID, src := subjectFrom(ctx), requestIDFrom(ctx), sourceFrom(ctx)
	pol := s.policies.Current()

	if !s.leaseLimiter.Allow(sub.Key()) {
		s.metrics.Inc("acb_rate_limited_total", map[string]string{"subject": sub.Key()})
		writeProblem(w, http.StatusTooManyRequests, ProblemRateLimited, "lease rate limit exceeded", "", reqID)
		return
	}

	var req leaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Scope == "" {
		writeProblem(w, http.StatusBadRequest, ProblemBadRequest, "invalid request body", "", reqID)
		return
	}
	if ctxBytes, _ := json.Marshal(req.Context); len(ctxBytes) > s.cfg.MaxContextBytes {
		writeProblem(w, http.StatusBadRequest, ProblemBadRequest, "context exceeds size limit", "", reqID)
		return
	}

	scope := pol.Scope(req.Scope) // nil for unknown names
	deny := func(status int, problemType, title, auditReason string) {
		// Metrics label: the validated scope name or a fixed sentinel.
		// req.Scope is caller-controlled text; using it as a label value
		// would let a caller mint unbounded metric series.
		scopeLabel := "<unknown>"
		attested := map[string]any{
			"requested_scope": req.Scope, // caller-supplied, unvalidated
			"decision":        "denied",
			"reason":          auditReason,
			"policy_hash":     pol.Hash,
		}
		if scope != nil {
			scopeLabel = scope.Name
			attested["scope"] = scope.Name // broker-validated
		}
		s.metrics.Inc("acb_leases_denied_total", map[string]string{
			"subject": sub.Key(), "scope": scopeLabel, "reason": auditReason,
		})
		_ = s.emitter.Emit(audit.Event{ // best-effort: denials disclose nothing
			Type: audit.TypeLeaseDenied, RequestID: reqID, Subject: sub, Source: src,
			Attested: attested,
			Asserted: req.Context,
		})
		// The uniform response carries no more than the caller may learn;
		// the audit event above carries the real reason.
		writeProblem(w, status, problemType, title, "", reqID)
	}

	grant := pol.Grant(sub.Key(), req.Scope)
	if grant == nil {
		reason := "no-grant"
		if scope == nil {
			reason = "unknown-scope" // audit-only distinction
		}
		deny(http.StatusForbidden, ProblemGrantDenied, "no grant for scope", reason)
		return
	}
	if !grant.WindowOpen(s.now()) {
		deny(http.StatusForbidden, ProblemOutsideWindow, "outside issuance window", "outside-window")
		return
	}

	ttl, ok := clampTTL(req.TTLSeconds, grant)
	if !ok {
		writeProblem(w, http.StatusBadRequest, ProblemBadRequest, "ttl_seconds must be non-negative", "", reqID)
		return
	}

	prov, ok := s.providers[scope.Provider]
	if !ok {
		deny(http.StatusBadGateway, ProblemProviderFailure, "secret provider unavailable", "provider-unconfigured")
		return
	}
	fetchStart := time.Now()
	result, err := prov.Fetch(ctx, provider.Request{
		Ref: scope.Ref, Fields: scope.Fields, Params: scope.Params, TTL: ttl,
	})
	s.metrics.Add("acb_provider_duration_seconds_sum", map[string]string{"provider": scope.Provider}, time.Since(fetchStart).Seconds())
	s.metrics.Inc("acb_provider_duration_seconds_count", map[string]string{"provider": scope.Provider})
	if err != nil {
		s.metrics.Inc("acb_provider_errors_total", map[string]string{"provider": scope.Provider})
		// Fail closed, no partial secrets; the error string never reaches
		// the caller (it could describe upstream internals).
		deny(http.StatusBadGateway, ProblemProviderFailure, "secret provider failure", "provider-error")
		return
	}

	// A revocable provider mints a credential with its own hard expiry
	// (GitHub ~1h). Clamp the lease so it never claims to outlive the
	// credential it represents — the signed lease.issued event must be
	// truthful about when the secret actually dies.
	var upstreamExpiry string
	if !result.ExpiresAt.IsZero() {
		upstreamExpiry = result.ExpiresAt.UTC().Format(time.RFC3339)
		if capped := result.ExpiresAt.Sub(s.now()); capped > 0 && capped < ttl {
			ttl = capped
		}
	}

	l := s.leases.Create(sub.Key(), req.Scope, prov.Semantics(), ttl, grant.Renewable)
	attested := map[string]any{
		"scope": l.Scope, "lease_id": l.ID, "ttl_seconds": int64(ttl.Seconds()),
		"expires_at": l.ExpiresAt.UTC().Format(time.RFC3339),
		"decision":   "issued", "semantics": l.Semantics, "policy_hash": pol.Hash,
	}
	if upstreamExpiry != "" {
		attested["upstream_expires_at"] = upstreamExpiry
	}
	if err := s.emitter.Emit(audit.Event{
		Type: audit.TypeLeaseIssued, RequestID: reqID, Subject: sub, Source: src,
		Attested: attested,
		Asserted: req.Context,
	}); err != nil {
		// The secret was never disclosed; remove the ghost lease and fail
		// closed — disclosure without a signed record must not happen.
		s.leases.Remove(l.ID)
		s.auditFailClosed(w, reqID, err)
		return
	}
	s.metrics.Inc("acb_leases_issued_total", map[string]string{"subject": sub.Key(), "scope": l.Scope})

	resp := leaseMeta(l)
	resp.Secret = result.Secret // returned exactly once; no endpoint re-discloses it
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleLeaseRenew(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sub, reqID, src := subjectFrom(ctx), requestIDFrom(ctx), sourceFrom(ctx)
	id := r.PathValue("id")

	// Renew emits an audit event per call, so it shares the lease limiter —
	// otherwise one valid lease is an unbounded signed-event firehose.
	if !s.leaseLimiter.Allow(sub.Key()) {
		s.metrics.Inc("acb_rate_limited_total", map[string]string{"subject": sub.Key()})
		writeProblem(w, http.StatusTooManyRequests, ProblemRateLimited, "lease rate limit exceeded", "", reqID)
		return
	}

	existing := s.leases.Get(id)
	if existing == nil {
		writeProblem(w, http.StatusNotFound, ProblemLeaseNotFound, "no such lease", "", reqID)
		return
	}
	if existing.SubjectKey != sub.Key() {
		writeProblem(w, http.StatusForbidden, ProblemLeaseForbidden, "not your lease", "", reqID)
		return
	}
	// Re-check the grant against the *current* policy: a revoked grant also
	// revokes renewal.
	pol := s.policies.Current()
	grant := pol.Grant(sub.Key(), existing.Scope)
	if grant == nil || !grant.Renewable {
		writeProblem(w, http.StatusConflict, ProblemLeaseConflict, "lease not renewable", "", reqID)
		return
	}

	var req struct {
		TTLSeconds int64 `json:"ttl_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		// Empty body means defaults; malformed body is an error, not a
		// silent fallback to defaults.
		writeProblem(w, http.StatusBadRequest, ProblemBadRequest, "invalid request body", "", reqID)
		return
	}
	ttl, ok := clampTTL(req.TTLSeconds, grant)
	if !ok {
		writeProblem(w, http.StatusBadRequest, ProblemBadRequest, "ttl_seconds must be non-negative", "", reqID)
		return
	}

	l, outcome := s.leases.Renew(id, ttl)
	if outcome != "" {
		writeProblem(w, http.StatusConflict, ProblemLeaseConflict, "lease "+outcome, "", reqID)
		return
	}
	if err := s.emitter.Emit(audit.Event{
		Type: audit.TypeLeaseRenewed, RequestID: reqID, Subject: sub, Source: src,
		Attested: map[string]any{
			"scope": l.Scope, "lease_id": l.ID,
			"expires_at":  l.ExpiresAt.UTC().Format(time.RFC3339),
			"policy_hash": pol.Hash,
		},
	}); err != nil {
		// The extension already applied and cannot be unwound; kill the
		// lease instead so no unaudited extension survives, and fail the
		// request.
		_, _ = s.leases.Surrender(id)
		s.auditFailClosed(w, reqID, err)
		return
	}
	writeJSON(w, http.StatusOK, leaseMeta(l))
}

func (s *Server) handleLeaseSurrender(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sub, reqID, src := subjectFrom(ctx), requestIDFrom(ctx), sourceFrom(ctx)
	id := r.PathValue("id")

	// Shares the lease limiter: every successful surrender emits an event.
	if !s.leaseLimiter.Allow(sub.Key()) {
		s.metrics.Inc("acb_rate_limited_total", map[string]string{"subject": sub.Key()})
		writeProblem(w, http.StatusTooManyRequests, ProblemRateLimited, "lease rate limit exceeded", "", reqID)
		return
	}

	existing := s.leases.Get(id)
	if existing == nil {
		writeProblem(w, http.StatusNotFound, ProblemLeaseNotFound, "no such lease", "", reqID)
		return
	}
	if existing.SubjectKey != sub.Key() {
		writeProblem(w, http.StatusForbidden, ProblemLeaseForbidden, "not your lease", "", reqID)
		return
	}
	if existing.Surrendered {
		// Idempotent: re-surrendering emits nothing (flooding guard).
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// Emit before marking so a failed write stays retryable — the audit
	// marker is the entire point of surrender.
	if err := s.emitter.Emit(audit.Event{
		Type: audit.TypeLeaseSurrendered, RequestID: reqID, Subject: sub, Source: src,
		Attested: map[string]any{
			"scope": existing.Scope, "lease_id": existing.ID,
			"policy_hash": s.policies.Current().Hash,
		},
	}); err != nil {
		s.auditFailClosed(w, reqID, err)
		return
	}
	_, _ = s.leases.Surrender(id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleLeaseGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sub, reqID := subjectFrom(ctx), requestIDFrom(ctx)
	id := r.PathValue("id")

	l := s.leases.Get(id)
	if l == nil {
		writeProblem(w, http.StatusNotFound, ProblemLeaseNotFound, "no such lease", "", reqID)
		return
	}
	if l.SubjectKey != sub.Key() {
		writeProblem(w, http.StatusForbidden, ProblemLeaseForbidden, "not your lease", "", reqID)
		return
	}
	writeJSON(w, http.StatusOK, leaseMeta(l)) // metadata only, never the secret
}

type claimsRequest struct {
	LeaseID string              `json:"lease_id"`
	Claims  []map[string]string `json:"claims"`
}

func (s *Server) handleClaims(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sub, reqID, src := subjectFrom(ctx), requestIDFrom(ctx), sourceFrom(ctx)

	if !s.claimLimiter.Allow(sub.Key()) {
		s.metrics.Inc("acb_rate_limited_total", map[string]string{"subject": sub.Key()})
		writeProblem(w, http.StatusTooManyRequests, ProblemRateLimited, "claim rate limit exceeded", "", reqID)
		return
	}

	var req claimsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, ProblemBadRequest, "invalid request body", "", reqID)
		return
	}
	if len(req.Claims) == 0 || len(req.Claims) > s.cfg.MaxClaimsPerReq {
		writeProblem(w, http.StatusBadRequest, ProblemBadRequest,
			fmt.Sprintf("claims must contain 1-%d entries", s.cfg.MaxClaimsPerReq), "", reqID)
		return
	}
	var totalBytes int64
	for _, c := range req.Claims {
		b, _ := json.Marshal(c)
		if len(b) > s.cfg.MaxClaimBytes {
			writeProblem(w, http.StatusBadRequest, ProblemBadRequest, "claim entry exceeds size limit", "", reqID)
			return
		}
		totalBytes += int64(len(b))
	}
	if req.LeaseID != "" {
		l := s.leases.Get(req.LeaseID)
		if l == nil || l.SubjectKey != sub.Key() {
			writeProblem(w, http.StatusForbidden, ProblemLeaseForbidden, "lease not held by caller", "", reqID)
			return
		}
	}
	budgetCap := s.policies.Current().ClaimBytesCap(sub.Key())
	if !s.claimBudget.Spend(sub.Key(), totalBytes, budgetCap) {
		s.metrics.Inc("acb_rate_limited_total", map[string]string{"subject": sub.Key()})
		writeProblem(w, http.StatusTooManyRequests, ProblemRateLimited, "daily claim-bytes cap exceeded", "", reqID)
		return
	}

	ids := make([]string, 0, len(req.Claims))
	for _, c := range req.Claims {
		id := lease.NewID("claim")
		attested := map[string]any{"claim_id": id}
		if req.LeaseID != "" {
			attested["lease_id"] = req.LeaseID
		}
		if err := s.emitter.Emit(audit.Event{
			Type: audit.TypeClaimRecorded, RequestID: reqID, Subject: sub, Source: src,
			Attested: attested,
			Asserted: c, // stored opaquely; the broker signs receipt, not truth
		}); err != nil {
			// 202 promises the claim is in the stream; if it isn't, say so.
			// Claims already emitted stand (at-least-once).
			s.auditFailClosed(w, reqID, err)
			return
		}
		ids = append(ids, id)
	}
	s.metrics.Inc("acb_claims_recorded_total", map[string]string{"subject": sub.Key()})
	writeJSON(w, http.StatusAccepted, map[string]any{"claim_ids": ids})
}

func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sub := subjectFrom(ctx)
	pol := s.policies.Current()

	type windowOut struct {
		Cron     string `json:"cron"`
		Duration string `json:"duration"`
	}
	type grantOut struct {
		Scope             string      `json:"scope"`
		TTLDefaultSeconds int64       `json:"ttl_default_seconds"`
		TTLMaxSeconds     int64       `json:"ttl_max_seconds"`
		Renewable         bool        `json:"renewable"`
		IssueWindows      []windowOut `json:"issue_windows,omitempty"`
	}
	grants := []grantOut{}
	for _, g := range pol.GrantsFor(sub.Key()) {
		out := grantOut{
			Scope:             g.Scope,
			TTLDefaultSeconds: int64(g.TTLDefault.D().Seconds()),
			TTLMaxSeconds:     int64(g.TTLMax.D().Seconds()),
			Renewable:         g.Renewable,
		}
		for _, iw := range g.IssueWindows {
			out.IssueWindows = append(out.IssueWindows, windowOut{Cron: iw.Cron, Duration: iw.Duration.D().String()})
		}
		grants = append(grants, out)
	}
	writeJSON(w, http.StatusOK, map[string]any{"subject": sub, "grants": grants})
}

func (s *Server) handleVerifyKey(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]string{
			{"kid": s.signer.KID(), "alg": "Ed25519", "public_key": s.signer.PublicBase64()},
		},
	})
}

// SweepExpiredLeases emits best-effort lease.expired events; main runs it on
// a ticker.
func (s *Server) SweepExpiredLeases(retain time.Duration) {
	polHash := s.policies.Current().Hash
	for _, l := range s.leases.SweepExpired(retain) {
		ns, sa, _ := strings.Cut(l.SubjectKey, "/")
		_ = s.emitter.Emit(audit.Event{
			Type:    audit.TypeLeaseExpired,
			Subject: &audit.Subject{Namespace: ns, ServiceAccount: sa},
			Attested: map[string]any{
				"scope": l.Scope, "lease_id": l.ID,
				"expired_at":  l.ExpiresAt.UTC().Format(time.RFC3339),
				"policy_hash": polHash, // hash at sweep time, not issuance
			},
		})
	}
}
