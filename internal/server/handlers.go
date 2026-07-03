package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/amorabito/agent-cred-broker/internal/audit"
	"github.com/amorabito/agent-cred-broker/internal/lease"
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

	deny := func(status int, problemType, title, auditReason string) {
		s.metrics.Inc("acb_leases_denied_total", map[string]string{
			"subject": sub.Key(), "scope": req.Scope, "reason": auditReason,
		})
		_ = s.emitter.Emit(audit.Event{
			Type: audit.TypeLeaseDenied, RequestID: reqID, Subject: sub, Source: src,
			Attested: map[string]any{
				"scope": req.Scope, "decision": "denied", "reason": auditReason,
				"policy_hash": pol.Hash,
			},
			Asserted: req.Context,
		})
		// The uniform response carries no more than the caller may learn;
		// the audit event above carries the real reason.
		writeProblem(w, status, problemType, title, "", reqID)
	}

	grant := pol.Grant(sub.Key(), req.Scope)
	if grant == nil {
		reason := "no-grant"
		if pol.Scope(req.Scope) == nil {
			reason = "unknown-scope" // audit-only distinction
		}
		deny(http.StatusForbidden, ProblemGrantDenied, "no grant for scope", reason)
		return
	}
	if !grant.WindowOpen(s.now()) {
		deny(http.StatusForbidden, ProblemOutsideWindow, "outside issuance window", "outside-window")
		return
	}

	ttl := grant.TTLDefault.D()
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	if ttl > grant.TTLMax.D() {
		ttl = grant.TTLMax.D()
	}

	scope := pol.Scope(req.Scope)
	prov, ok := s.providers[scope.Provider]
	if !ok {
		deny(http.StatusBadGateway, ProblemProviderFailure, "secret provider unavailable", "provider-unconfigured")
		return
	}
	secret, err := prov.Fetch(ctx, scope.Ref, scope.Fields)
	if err != nil {
		s.metrics.Inc("acb_provider_errors_total", map[string]string{"provider": scope.Provider})
		// Fail closed, no partial secrets; the error string never reaches
		// the caller (it could describe upstream internals).
		deny(http.StatusBadGateway, ProblemProviderFailure, "secret provider failure", "provider-error")
		return
	}

	l := s.leases.Create(sub.Key(), req.Scope, prov.Semantics(), ttl, grant.Renewable)
	_ = s.emitter.Emit(audit.Event{
		Type: audit.TypeLeaseIssued, RequestID: reqID, Subject: sub, Source: src,
		Attested: map[string]any{
			"scope": l.Scope, "lease_id": l.ID, "ttl_seconds": int64(ttl.Seconds()),
			"expires_at": l.ExpiresAt.UTC().Format(time.RFC3339),
			"decision":   "issued", "semantics": l.Semantics, "policy_hash": pol.Hash,
		},
		Asserted: req.Context,
	})
	s.metrics.Inc("acb_leases_issued_total", map[string]string{"subject": sub.Key(), "scope": l.Scope})

	resp := leaseMeta(l)
	resp.Secret = secret // returned exactly once; no endpoint re-discloses it
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleLeaseRenew(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sub, reqID, src := subjectFrom(ctx), requestIDFrom(ctx), sourceFrom(ctx)
	id := r.PathValue("id")

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
	_ = json.NewDecoder(r.Body).Decode(&req) // empty body = defaults
	ttl := grant.TTLDefault.D()
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	if ttl > grant.TTLMax.D() {
		ttl = grant.TTLMax.D()
	}

	l, outcome := s.leases.Renew(id, ttl)
	if outcome != "" {
		writeProblem(w, http.StatusConflict, ProblemLeaseConflict, "lease "+outcome, "", reqID)
		return
	}
	_ = s.emitter.Emit(audit.Event{
		Type: audit.TypeLeaseRenewed, RequestID: reqID, Subject: sub, Source: src,
		Attested: map[string]any{
			"scope": l.Scope, "lease_id": l.ID,
			"expires_at":  l.ExpiresAt.UTC().Format(time.RFC3339),
			"policy_hash": pol.Hash,
		},
	})
	writeJSON(w, http.StatusOK, leaseMeta(l))
}

func (s *Server) handleLeaseSurrender(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sub, reqID, src := subjectFrom(ctx), requestIDFrom(ctx), sourceFrom(ctx)
	id := r.PathValue("id")

	existing := s.leases.Get(id)
	if existing == nil {
		writeProblem(w, http.StatusNotFound, ProblemLeaseNotFound, "no such lease", "", reqID)
		return
	}
	if existing.SubjectKey != sub.Key() {
		writeProblem(w, http.StatusForbidden, ProblemLeaseForbidden, "not your lease", "", reqID)
		return
	}
	l, _ := s.leases.Surrender(id)
	_ = s.emitter.Emit(audit.Event{
		Type: audit.TypeLeaseSurrendered, RequestID: reqID, Subject: sub, Source: src,
		Attested: map[string]any{"scope": l.Scope, "lease_id": l.ID},
	})
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
		writeProblem(w, http.StatusBadRequest, ProblemBadRequest, "claims must contain 1-50 entries", "", reqID)
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
	cap := s.policies.Current().ClaimBytesCap(sub.Key())
	if !s.claimBudget.Spend(sub.Key(), totalBytes, cap) {
		s.metrics.Inc("acb_rate_limited_total", map[string]string{"subject": sub.Key()})
		writeProblem(w, http.StatusTooManyRequests, ProblemRateLimited, "daily claim-bytes cap exceeded", "", reqID)
		return
	}

	ids := make([]string, 0, len(req.Claims))
	for _, c := range req.Claims {
		id := lease.NewID("claim")
		ids = append(ids, id)
		attested := map[string]any{"claim_id": id}
		if req.LeaseID != "" {
			attested["lease_id"] = req.LeaseID
		}
		_ = s.emitter.Emit(audit.Event{
			Type: audit.TypeClaimRecorded, RequestID: reqID, Subject: sub, Source: src,
			Attested: attested,
			Asserted: c, // stored opaquely; the broker signs receipt, not truth
		})
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
	for _, l := range s.leases.SweepExpired(retain) {
		ns, sa, _ := cutSubjectKey(l.SubjectKey)
		_ = s.emitter.Emit(audit.Event{
			Type:    audit.TypeLeaseExpired,
			Subject: &audit.Subject{Namespace: ns, ServiceAccount: sa},
			Attested: map[string]any{
				"scope": l.Scope, "lease_id": l.ID,
				"expired_at": l.ExpiresAt.UTC().Format(time.RFC3339),
			},
		})
	}
}

func cutSubjectKey(key string) (ns, sa string, ok bool) {
	for i := 0; i < len(key); i++ {
		if key[i] == '/' {
			return key[:i], key[i+1:], true
		}
	}
	return key, "", false
}
