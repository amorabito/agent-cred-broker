package notify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/amorabito/agent-cred-broker/internal/audit"
	"github.com/amorabito/agent-cred-broker/internal/ratelimit"
	"github.com/amorabito/agent-cred-broker/internal/server"
)

type haCall struct {
	path  string
	token string
	body  map[string]any
}

type fakeHA struct {
	mu     sync.Mutex
	calls  []haCall
	status int
}

type fixture struct {
	srv        *Server
	events     *bytes.Buffer
	signer     *audit.Signer
	handler    http.Handler
	ha         *fakeHA
	brokerFail bool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{ha: &fakeHA{status: http.StatusOK}}

	haTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.ha.mu.Lock()
		f.ha.calls = append(f.ha.calls, haCall{path: r.URL.Path, token: r.Header.Get("Authorization"), body: body})
		st := f.ha.status
		f.ha.mu.Unlock()
		w.WriteHeader(st)
	}))
	t.Cleanup(haTS.Close)

	brokerTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if f.brokerFail {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"lease_id": "lease_test", "secret": map[string]string{"token": "leased-ha-token"},
		})
	}))
	t.Cleanup(brokerTS.Close)

	pol, err := Parse([]byte(validNotifyPolicy))
	if err != nil {
		t.Fatal(err)
	}
	lease, err := NewLeaseClient(brokerTS.URL, "", "ha-notify-token", tokenFileWith(t, "proxy-tok"))
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := audit.NewSigner(priv)
	f.events = &bytes.Buffer{}
	emitter := audit.NewEmitter(f.events, signer, "test-proxy")

	authn := func(_ context.Context, token string) (*audit.Subject, error) {
		switch token {
		case "alert-triage-token":
			return &audit.Subject{Namespace: "agents", ServiceAccount: "alert-triage", Pod: "alert-triage-1"}, nil
		case "digest-token":
			return &audit.Subject{Namespace: "agents", ServiceAccount: "house-hunt-digest"}, nil
		}
		return nil, fmt.Errorf("unauthenticated")
	}
	f.signer = signer
	f.srv = New(Config{}, pol, authn, NewHAClient(haTS.URL), lease, emitter, signer, server.NewMetrics())
	f.handler = f.srv.Handler()
	return f
}

func (f *fixture) do(t *testing.T, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest("POST", path, &buf)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	return w
}

func (f *fixture) verifiedEvents(t *testing.T) []*audit.Event {
	t.Helper()
	var out []*audit.Event
	for _, line := range bytes.Split(bytes.TrimSpace(f.events.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		ev, err := audit.Verify(line, f.signer.Public())
		if err != nil {
			t.Fatalf("emitted event does not verify: %v", err)
		}
		out = append(out, ev)
	}
	return out
}

func TestPushHappyPath(t *testing.T) {
	f := newFixture(t)
	w := f.do(t, "/v1/notify/push", "alert-triage-token", map[string]any{
		"title": "🔴 2 alerts", "message": "body", "data": map[string]string{"group": "alert-triage", "tag": "alert-triage", "url": "/home-hub"},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	// The proxy pinned the target and passed the LEASED token to HA.
	f.ha.mu.Lock()
	defer f.ha.mu.Unlock()
	if len(f.ha.calls) != 1 {
		t.Fatalf("ha calls: %d", len(f.ha.calls))
	}
	c := f.ha.calls[0]
	if c.path != "/api/services/notify/mobile_app_test_phone" {
		t.Fatalf("ha path: %s", c.path)
	}
	if c.token != "Bearer leased-ha-token" {
		t.Fatalf("ha did not receive the leased token: %q", c.token)
	}
	// notify.forwarded emitted, verifies, records caller identity + lease_id.
	evs := f.verifiedEvents(t)
	last := evs[len(evs)-1]
	if last.Type != TypeNotifyForwarded {
		t.Fatalf("last event: %s", last.Type)
	}
	if last.Subject == nil || last.Subject.Key() != "agents/alert-triage" {
		t.Fatalf("caller identity not attested: %+v", last.Subject)
	}
	if last.Attested["lease_id"] != "lease_test" || last.Attested["delivered"] != true {
		t.Fatalf("attested: %v", last.Attested)
	}
}

func TestPushDeniedNoGrant(t *testing.T) {
	f := newFixture(t)
	// digest holds push, but let's deny a kind it lacks by using persistent.
	w := f.do(t, "/v1/notify/persistent", "digest-token", map[string]any{"notification_id": "digest-x", "title": "t", "message": "m"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d", w.Code)
	}
	f.ha.mu.Lock()
	defer f.ha.mu.Unlock()
	if len(f.ha.calls) != 0 {
		t.Fatal("denied request must never reach HA")
	}
	evs := f.verifiedEvents(t)
	if evs[len(evs)-1].Type != TypeNotifyDenied {
		t.Fatalf("expected notify.denied, got %s", evs[len(evs)-1].Type)
	}
}

func TestPushBadDataKeyRejected(t *testing.T) {
	f := newFixture(t)
	w := f.do(t, "/v1/notify/push", "alert-triage-token", map[string]any{
		"title": "t", "message": "m", "data": map[string]string{"actions": "unlock_door"}, // not allowlisted
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d", w.Code)
	}
	f.ha.mu.Lock()
	defer f.ha.mu.Unlock()
	if len(f.ha.calls) != 0 {
		t.Fatal("a rejected data key must not reach HA (actionable-notification guard)")
	}
}

func TestPersistentPrefixEnforced(t *testing.T) {
	f := newFixture(t)
	// good prefix
	if w := f.do(t, "/v1/notify/persistent", "alert-triage-token", map[string]any{"notification_id": "alert-triage-latest", "title": "t", "message": "m"}); w.Code != http.StatusCreated {
		t.Fatalf("good prefix: %d %s", w.Code, w.Body)
	}
	// wrong prefix -> denied, no HA call
	before := len(f.ha.calls)
	if w := f.do(t, "/v1/notify/persistent", "alert-triage-token", map[string]any{"notification_id": "someone-elses-note", "title": "t", "message": "m"}); w.Code != http.StatusForbidden {
		t.Fatalf("wrong prefix must be 403, got %d", w.Code)
	}
	if len(f.ha.calls) != before {
		t.Fatal("wrong-prefix create must not reach HA")
	}
}

func TestDismissHappyPath(t *testing.T) {
	f := newFixture(t)
	w := f.do(t, "/v1/notify/persistent/dismiss", "alert-triage-token", map[string]any{"notification_id": "alert-triage-latest"})
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	f.ha.mu.Lock()
	defer f.ha.mu.Unlock()
	if f.ha.calls[0].path != "/api/services/persistent_notification/dismiss" {
		t.Fatalf("path: %s", f.ha.calls[0].path)
	}
}

func TestUnauthenticated(t *testing.T) {
	f := newFixture(t)
	if w := f.do(t, "/v1/notify/push", "bad-token", map[string]any{"title": "t"}); w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
	if w := f.do(t, "/v1/notify/push", "", map[string]any{"title": "t"}); w.Code != http.StatusUnauthorized {
		t.Fatalf("missing bearer: %d", w.Code)
	}
}

func TestHAFailureIsAttestedAnd502(t *testing.T) {
	f := newFixture(t)
	f.ha.status = http.StatusInternalServerError
	w := f.do(t, "/v1/notify/push", "alert-triage-token", map[string]any{"title": "t", "message": "m"})
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "leaked") {
		t.Fatal("HA body must not leak")
	}
	last := f.verifiedEvents(t)
	ev := last[len(last)-1]
	if ev.Type != TypeNotifyForwarded || ev.Attested["delivered"] != false {
		t.Fatalf("a failed delivery must still emit notify.forwarded delivered=false: %v", ev.Attested)
	}
}

func TestLeaseFailureIs502(t *testing.T) {
	f := newFixture(t)
	f.brokerFail = true
	w := f.do(t, "/v1/notify/push", "alert-triage-token", map[string]any{"title": "t", "message": "m"})
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status %d", w.Code)
	}
	f.ha.mu.Lock()
	defer f.ha.mu.Unlock()
	if len(f.ha.calls) != 0 {
		t.Fatal("no lease -> no HA call")
	}
}

func TestRateLimited(t *testing.T) {
	f := newFixture(t)
	f.srv.limiter = ratelimit.New(1, 2) // burst 2, then 429
	codes := map[int]int{}
	for i := 0; i < 4; i++ {
		w := f.do(t, "/v1/notify/push", "alert-triage-token", map[string]any{"title": "t", "message": "m"})
		codes[w.Code]++
	}
	if codes[http.StatusTooManyRequests] == 0 {
		t.Fatalf("expected some 429s, got %v", codes)
	}
	// A throttled request — the attack signal the limiter exists to catch — must
	// leave a signed footprint (aggregated), not just a metric.
	denied := 0
	for _, e := range f.verifiedEvents(t) {
		if e.Type == TypeNotifyDenied && e.Attested["reason"] == "rate-limited" {
			denied++
		}
	}
	if denied < 1 {
		t.Fatal("a throttled request must emit at least one signed notify.denied (rate-limited)")
	}
}

func TestMalformedBodyAudited(t *testing.T) {
	f := newFixture(t)
	req := httptest.NewRequest("POST", "/v1/notify/push", strings.NewReader(`{"title":`)) // truncated JSON
	req.Header.Set("Authorization", "Bearer alert-triage-token")
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d", w.Code)
	}
	// An authenticated caller's bad body must not be a quieter probe than a
	// well-formed unauthorized one — it emits a signed, attributed notify.denied.
	evs := f.verifiedEvents(t)
	last := evs[len(evs)-1]
	if last.Type != TypeNotifyDenied || last.Attested["reason"] != "bad-body" {
		t.Fatalf("malformed body must emit signed notify.denied(bad-body): %v", last.Attested)
	}
	if last.Subject == nil || last.Subject.Key() != "agents/alert-triage" {
		t.Fatalf("bad-body denial must attribute the caller: %+v", last.Subject)
	}
}
