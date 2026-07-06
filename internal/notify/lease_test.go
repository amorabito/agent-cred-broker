package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func tokenFileWith(t *testing.T, val string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(val), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLeaseHappyPath(t *testing.T) {
	var gotBody map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/leases" || r.Method != http.MethodPost {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer proxy-broker-token" {
			t.Errorf("auth: %q", r.Header.Get("Authorization"))
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"lease_id": "lease_abc", "secret": map[string]string{"token": "ha-god-token"},
		})
	}))
	defer ts.Close()

	lc, err := NewLeaseClient(ts.URL, "", "ha-notify-token", tokenFileWith(t, "proxy-broker-token"))
	if err != nil {
		t.Fatal(err)
	}
	lease, err := lc.Lease(context.Background(), map[string]string{"originating_agent": "agents/alert-triage", "action": "push"})
	if err != nil {
		t.Fatal(err)
	}
	if lease.Token != "ha-god-token" || lease.LeaseID != "lease_abc" {
		t.Fatalf("lease: %+v", lease)
	}
	if gotBody["scope"] != "ha-notify-token" {
		t.Fatalf("scope not sent: %v", gotBody)
	}
	ctxOut, _ := gotBody["context"].(map[string]any)
	if ctxOut["originating_agent"] != "agents/alert-triage" {
		t.Fatalf("lease context (the audit join) not forwarded: %v", gotBody["context"])
	}
}

func TestLeaseErrorNotEchoed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"detail":"policy names a vault"}`, http.StatusForbidden)
	}))
	defer ts.Close()
	lc, _ := NewLeaseClient(ts.URL, "", "ha-notify-token", tokenFileWith(t, "t"))
	_, err := lc.Lease(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if got := err.Error(); got != "broker lease failed: status 403" {
		t.Fatalf("broker body leaked: %q", got)
	}
}

func TestLeaseIncompleteResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"lease_id": "lease_x", "secret": map[string]string{}})
	}))
	defer ts.Close()
	lc, _ := NewLeaseClient(ts.URL, "", "ha-notify-token", tokenFileWith(t, "t"))
	if _, err := lc.Lease(context.Background(), nil); err == nil {
		t.Fatal("missing token in lease response must fail closed")
	}
}
