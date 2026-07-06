package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/amorabito/agent-cred-broker/internal/audit"
	"github.com/amorabito/agent-cred-broker/internal/lease"
	"github.com/amorabito/agent-cred-broker/internal/policy"
	"github.com/amorabito/agent-cred-broker/internal/provider"
)

const testPolicy = `
scopes:
  - name: github-bot-pat
    provider: onepassword-connect
    ref: "vaults/abcdefghijklmnopqrstuvwxyz/items/zyxwvutsrqponmlkjihgfedcba"
    fields:
      token: credential
  - name: windowed-scope
    provider: onepassword-connect
    ref: "vaults/abcdefghijklmnopqrstuvwxyz/items/zyxwvutsrqponmlkjihgfedcba"
    fields:
      token: credential
subjects:
  - serviceAccount: agents/pr-reviewer
    claimBytesPerDay: 4096
    grants:
      - scope: github-bot-pat
        ttlDefault: 15m
        ttlMax: 1h
        renewable: true
      - scope: windowed-scope
        ttlDefault: 5m
        ttlMax: 10m
        issueWindows:
          - cron: "55 11 * * *"
            duration: 45m
`

type fakeProvider struct {
	secret    map[string]string
	err       error
	semantics string    // defaults to static-disclosure
	expiresAt time.Time // non-zero => revocable-style upstream expiry
}

func (f *fakeProvider) Name() string { return "onepassword-connect" }
func (f *fakeProvider) Semantics() string {
	if f.semantics != "" {
		return f.semantics
	}
	return provider.SemanticsStaticDisclosure
}
func (f *fakeProvider) Fetch(context.Context, provider.Request) (*provider.Result, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &provider.Result{Secret: f.secret, ExpiresAt: f.expiresAt}, nil
}

// failableBuffer lets tests simulate a broken audit pipe.
type failableBuffer struct {
	bytes.Buffer
	Failing bool
}

func (f *failableBuffer) Write(p []byte) (int, error) {
	if f.Failing {
		return 0, fmt.Errorf("simulated audit write failure")
	}
	return f.Buffer.Write(p)
}

type fixture struct {
	srv     *Server
	events  *failableBuffer
	handler http.Handler
	signer  *audit.Signer
}

func newFixture(t *testing.T, cfg Config, prov provider.Provider) *fixture {
	t.Helper()
	dir := t.TempDir()
	polPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(polPath, []byte(testPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	policies, err := policy.NewStore(polPath, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := audit.NewSigner(priv)
	events := &failableBuffer{}
	emitter := audit.NewEmitter(events, signer, "test")

	authn := func(_ context.Context, token string) (*audit.Subject, error) {
		switch token {
		case "good-token":
			return &audit.Subject{Namespace: "agents", ServiceAccount: "pr-reviewer", Pod: "pr-reviewer-1"}, nil
		case "other-token":
			return &audit.Subject{Namespace: "agents", ServiceAccount: "someone-else"}, nil
		}
		return nil, fmt.Errorf("unauthenticated")
	}
	srv := New(cfg, policies, authn, map[string]provider.Provider{"onepassword-connect": prov},
		lease.NewStore(), emitter, signer, NewMetrics())
	// Fixed mid-year date, far from the 11:55 UTC window.
	srv.SetClock(func() time.Time { return time.Date(2026, 7, 3, 3, 0, 0, 0, time.UTC) })
	return &fixture{srv: srv, events: events, handler: srv.Handler(), signer: signer}
}

func (f *fixture) do(t *testing.T, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	return w
}

func (f *fixture) eventTypes(t *testing.T) []string {
	t.Helper()
	var types []string
	for _, line := range bytes.Split(bytes.TrimSpace(f.events.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		ev, err := audit.Verify(line, f.signer.Public())
		if err != nil {
			t.Fatalf("emitted event does not verify: %v", err)
		}
		types = append(types, ev.Type)
	}
	return types
}

func TestLeaseIssueHappyPath(t *testing.T) {
	f := newFixture(t, Config{}, &fakeProvider{secret: map[string]string{"token": "s3cr3t-value"}})
	w := f.do(t, "POST", "/v1/leases", "good-token",
		map[string]any{"scope": "github-bot-pat", "context": map[string]string{"reason": "nightly run"}})
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control: %q", cc)
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["semantics"] != "static-disclosure" {
		t.Fatalf("semantics: %v", resp["semantics"])
	}
	if resp["secret"].(map[string]any)["token"] != "s3cr3t-value" {
		t.Fatal("secret missing from create response")
	}
	// The secret must never appear in the audit stream.
	if bytes.Contains(f.events.Bytes(), []byte("s3cr3t-value")) {
		t.Fatal("secret leaked into audit events")
	}
	types := f.eventTypes(t)
	if len(types) != 1 || types[0] != audit.TypeLeaseIssued {
		t.Fatalf("events: %v", types)
	}
	// Lease metadata must be readable, without the secret.
	id := resp["lease_id"].(string)
	w2 := f.do(t, "GET", "/v1/leases/"+id, "good-token", nil)
	if w2.Code != http.StatusOK || strings.Contains(w2.Body.String(), "s3cr3t-value") {
		t.Fatalf("lease get: %d %s", w2.Code, w2.Body)
	}
}

// A revocable provider (GitHub App) mints a credential with an upstream hard
// expiry. The lease must be clamped to it so a signed lease.issued never
// claims to outlive the token, and the upstream expiry must be recorded.
func TestRevocableLeaseCappedToUpstreamExpiry(t *testing.T) {
	// Fixture clock is 2026-07-03 03:00 UTC; the token dies at 03:10 (10m),
	// shorter than github-bot-pat's 15m default — so the lease clamps to 10m.
	upstream := time.Date(2026, 7, 3, 3, 10, 0, 0, time.UTC)
	f := newFixture(t, Config{}, &fakeProvider{
		secret:    map[string]string{"token": "ghs_x"},
		semantics: provider.SemanticsRevocable,
		expiresAt: upstream,
	})
	// Pin the lease store's clock to the fixture clock so response TTL is
	// measured against the same "now" the cap uses.
	f.srv.leases.SetClock(func() time.Time { return time.Date(2026, 7, 3, 3, 0, 0, 0, time.UTC) })

	w := f.do(t, "POST", "/v1/leases", "good-token", map[string]any{"scope": "github-bot-pat"})
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["semantics"] != "revocable" {
		t.Fatalf("semantics: %v", resp["semantics"])
	}
	issued, _ := time.Parse(time.RFC3339, resp["issued_at"].(string))
	expires, _ := time.Parse(time.RFC3339, resp["expires_at"].(string))
	if got := expires.Sub(issued); got != 10*time.Minute {
		t.Fatalf("lease must clamp to upstream expiry (10m), got %v", got)
	}
	if !strings.Contains(f.events.String(), `"upstream_expires_at":"2026-07-03T03:10:00Z"`) {
		t.Fatalf("lease.issued must record upstream_expires_at; events: %s", f.events.String())
	}
}

// Unknown scope and ungranted scope must be indistinguishable to the caller
// (no enumeration oracle) while the audit trail records the real reason.
func TestUniformDenial(t *testing.T) {
	f := newFixture(t, Config{}, &fakeProvider{secret: map[string]string{"token": "x"}})
	wUnknown := f.do(t, "POST", "/v1/leases", "good-token", map[string]any{"scope": "does-not-exist"})
	wUngranted := f.do(t, "POST", "/v1/leases", "other-token", map[string]any{"scope": "github-bot-pat"})

	if wUnknown.Code != http.StatusForbidden || wUngranted.Code != http.StatusForbidden {
		t.Fatalf("codes: %d %d", wUnknown.Code, wUngranted.Code)
	}
	var p1, p2 problem
	_ = json.Unmarshal(wUnknown.Body.Bytes(), &p1)
	_ = json.Unmarshal(wUngranted.Body.Bytes(), &p2)
	if p1.Type != p2.Type || p1.Title != p2.Title || p1.Detail != p2.Detail {
		t.Fatalf("denials distinguishable: %+v vs %+v", p1, p2)
	}
	// Audit events carry the real reasons.
	joined := f.events.String()
	if !strings.Contains(joined, `"unknown-scope"`) || !strings.Contains(joined, `"no-grant"`) {
		t.Fatal("audit events missing real denial reasons")
	}
}

func TestIssueWindowDenied(t *testing.T) {
	f := newFixture(t, Config{}, &fakeProvider{secret: map[string]string{"token": "x"}})
	w := f.do(t, "POST", "/v1/leases", "good-token", map[string]any{"scope": "windowed-scope"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d", w.Code)
	}
	var p problem
	_ = json.Unmarshal(w.Body.Bytes(), &p)
	if p.Type != ProblemOutsideWindow {
		t.Fatalf("problem type: %s", p.Type)
	}
	// Inside the window it issues.
	f.srv.SetClock(func() time.Time { return time.Date(2026, 7, 3, 12, 10, 0, 0, time.UTC) })
	w2 := f.do(t, "POST", "/v1/leases", "good-token", map[string]any{"scope": "windowed-scope"})
	if w2.Code != http.StatusCreated {
		t.Fatalf("in-window status %d: %s", w2.Code, w2.Body)
	}
}

func TestProviderFailureFailsClosed(t *testing.T) {
	f := newFixture(t, Config{}, &fakeProvider{err: fmt.Errorf("upstream detail that must not leak")})
	w := f.do(t, "POST", "/v1/leases", "good-token", map[string]any{"scope": "github-bot-pat"})
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "upstream detail") {
		t.Fatal("provider error detail leaked to caller")
	}
}

func TestRenewAndSurrender(t *testing.T) {
	f := newFixture(t, Config{}, &fakeProvider{secret: map[string]string{"token": "x"}})
	w := f.do(t, "POST", "/v1/leases", "good-token", map[string]any{"scope": "github-bot-pat"})
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	id := resp["lease_id"].(string)

	if w := f.do(t, "POST", "/v1/leases/"+id+"/renew", "other-token", nil); w.Code != http.StatusForbidden {
		t.Fatalf("foreign renew: %d", w.Code)
	}
	if w := f.do(t, "POST", "/v1/leases/"+id+"/renew", "good-token", nil); w.Code != http.StatusOK {
		t.Fatalf("renew: %d %s", w.Code, w.Body)
	}
	if w := f.do(t, "DELETE", "/v1/leases/"+id, "good-token", nil); w.Code != http.StatusNoContent {
		t.Fatalf("surrender: %d", w.Code)
	}
	if w := f.do(t, "POST", "/v1/leases/"+id+"/renew", "good-token", nil); w.Code != http.StatusConflict {
		t.Fatalf("renew after surrender: %d", w.Code)
	}
	want := []string{audit.TypeLeaseIssued, audit.TypeLeaseRenewed, audit.TypeLeaseSurrendered}
	types := f.eventTypes(t)
	if len(types) != len(want) {
		t.Fatalf("events: %v", types)
	}
	for i := range want {
		if types[i] != want[i] {
			t.Fatalf("events: %v", types)
		}
	}
}

func TestClaims(t *testing.T) {
	f := newFixture(t, Config{}, &fakeProvider{secret: map[string]string{"token": "x"}})
	w := f.do(t, "POST", "/v1/claims", "good-token", map[string]any{
		"claims": []map[string]string{
			{"action": "gh.pr.merge", "target": "org/repo#1", "reason": "risk=LOW"},
			{"action": "gh.pr.comment", "target": "org/repo#2"},
		},
	})
	if w.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var resp map[string][]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp["claim_ids"]) != 2 {
		t.Fatalf("claim ids: %v", resp)
	}
	// Claim against someone else's lease is forbidden.
	wl := f.do(t, "POST", "/v1/leases", "good-token", map[string]any{"scope": "github-bot-pat"})
	var lr map[string]any
	_ = json.Unmarshal(wl.Body.Bytes(), &lr)
	w2 := f.do(t, "POST", "/v1/claims", "other-token", map[string]any{
		"lease_id": lr["lease_id"], "claims": []map[string]string{{"action": "x"}},
	})
	if w2.Code != http.StatusForbidden {
		t.Fatalf("foreign lease claim: %d", w2.Code)
	}
}

func TestClaimBytesCap(t *testing.T) {
	f := newFixture(t, Config{}, &fakeProvider{secret: map[string]string{"token": "x"}})
	big := strings.Repeat("a", 1500)
	// Cap is 4096 bytes/day; each claim ~1520 bytes → third request over cap.
	for i := 0; i < 2; i++ {
		w := f.do(t, "POST", "/v1/claims", "good-token", map[string]any{
			"claims": []map[string]string{{"reason": big}},
		})
		if w.Code != http.StatusAccepted {
			t.Fatalf("claim %d: %d", i, w.Code)
		}
	}
	w := f.do(t, "POST", "/v1/claims", "good-token", map[string]any{
		"claims": []map[string]string{{"reason": big}},
	})
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("over-cap claim: %d", w.Code)
	}
}

func TestLeaseRateLimit(t *testing.T) {
	f := newFixture(t, Config{LeaseRatePerMinute: 1, LeaseBurst: 2},
		&fakeProvider{secret: map[string]string{"token": "x"}})
	for i := 0; i < 2; i++ {
		if w := f.do(t, "POST", "/v1/leases", "good-token", map[string]any{"scope": "github-bot-pat"}); w.Code != http.StatusCreated {
			t.Fatalf("lease %d: %d", i, w.Code)
		}
	}
	if w := f.do(t, "POST", "/v1/leases", "good-token", map[string]any{"scope": "github-bot-pat"}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
}

func TestAuthFailuresAggregated(t *testing.T) {
	f := newFixture(t, Config{}, &fakeProvider{secret: map[string]string{"token": "x"}})
	for i := 0; i < 5; i++ {
		if w := f.do(t, "GET", "/v1/whoami", "bad-token", nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("status %d", w.Code)
		}
	}
	types := f.eventTypes(t)
	authFails := 0
	for _, ty := range types {
		if ty == audit.TypeAuthFailed {
			authFails++
		}
	}
	if authFails != 1 {
		t.Fatalf("auth.failed events = %d, want 1 (aggregated)", authFails)
	}
}

// ttl_seconds is attacker-influenced input: a huge value must clamp to
// ttlMax (not overflow time.Duration into the past) and negatives are 400.
func TestTTLClampAndOverflow(t *testing.T) {
	f := newFixture(t, Config{}, &fakeProvider{secret: map[string]string{"token": "x"}})

	w := f.do(t, "POST", "/v1/leases", "good-token",
		map[string]any{"scope": "github-bot-pat", "ttl_seconds": int64(9223372036854775807)})
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	issued, _ := time.Parse(time.RFC3339, resp["issued_at"].(string))
	expires, _ := time.Parse(time.RFC3339, resp["expires_at"].(string))
	if got := expires.Sub(issued); got != time.Hour { // ttlMax in test policy
		t.Fatalf("huge ttl must clamp to ttlMax, got %v", got)
	}

	w2 := f.do(t, "POST", "/v1/leases", "good-token",
		map[string]any{"scope": "github-bot-pat", "ttl_seconds": -5})
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("negative ttl: %d", w2.Code)
	}
}

// If the signed lease.issued event cannot be written, the secret must not
// be disclosed — the flight recorder is the point.
func TestAuditWriteFailureFailsClosed(t *testing.T) {
	f := newFixture(t, Config{}, &fakeProvider{secret: map[string]string{"token": "s3cr3t-value"}})
	f.events.Failing = true
	w := f.do(t, "POST", "/v1/leases", "good-token", map[string]any{"scope": "github-bot-pat"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "s3cr3t-value") {
		t.Fatal("secret disclosed despite audit write failure")
	}
	// And the failed issuance must not leave a usable ghost lease.
	f.events.Failing = false
	w2 := f.do(t, "POST", "/v1/claims", "good-token", map[string]any{
		"lease_id": "lease_ghost", "claims": []map[string]string{{"a": "b"}},
	})
	if w2.Code != http.StatusForbidden {
		t.Fatalf("ghost lease reference: %d", w2.Code)
	}
}

// Surrender is idempotent and renew/surrender share the lease rate limit —
// one lease must not be an unbounded signed-event firehose.
func TestSurrenderIdempotentNoEventFlood(t *testing.T) {
	f := newFixture(t, Config{}, &fakeProvider{secret: map[string]string{"token": "x"}})
	w := f.do(t, "POST", "/v1/leases", "good-token", map[string]any{"scope": "github-bot-pat"})
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	id := resp["lease_id"].(string)

	for i := 0; i < 3; i++ {
		if w := f.do(t, "DELETE", "/v1/leases/"+id, "good-token", nil); w.Code != http.StatusNoContent {
			t.Fatalf("surrender %d: %d", i, w.Code)
		}
	}
	surrendered := 0
	for _, ty := range f.eventTypes(t) {
		if ty == audit.TypeLeaseSurrendered {
			surrendered++
		}
	}
	if surrendered != 1 {
		t.Fatalf("lease.surrendered events = %d, want 1", surrendered)
	}
}

func TestRenewMalformedBodyRejected(t *testing.T) {
	f := newFixture(t, Config{}, &fakeProvider{secret: map[string]string{"token": "x"}})
	w := f.do(t, "POST", "/v1/leases", "good-token", map[string]any{"scope": "github-bot-pat"})
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	id := resp["lease_id"].(string)

	req := httptest.NewRequest("POST", "/v1/leases/"+id+"/renew", strings.NewReader(`{"ttl_seconds": "not-a-number"`))
	req.Header.Set("Authorization", "Bearer good-token")
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed renew body: %d", rec.Code)
	}
}

func TestWhoami(t *testing.T) {
	f := newFixture(t, Config{}, &fakeProvider{secret: map[string]string{"token": "x"}})
	w := f.do(t, "GET", "/v1/whoami", "good-token", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "github-bot-pat") || !strings.Contains(body, "pr-reviewer") {
		t.Fatalf("whoami: %s", body)
	}
	if strings.Contains(body, "vaults/") {
		t.Fatal("whoami leaked provider refs")
	}
}
