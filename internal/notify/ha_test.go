package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHAAllowed(t *testing.T) {
	ok := [][2]string{
		{"notify", "mobile_app_test_phone_2"},
		{"persistent_notification", "create"},
		{"persistent_notification", "dismiss"},
	}
	bad := [][2]string{
		{"lock", "unlock"},
		{"persistent_notification", "delete"}, // not create/dismiss
		{"notify", "mobile_app/../lock"},      // bad charset
		{"switch", "turn_on"},
		{"homeassistant", "restart"},
	}
	for _, p := range ok {
		if !haAllowed(p[0], p[1]) {
			t.Errorf("expected allowed: %s/%s", p[0], p[1])
		}
	}
	for _, p := range bad {
		if haAllowed(p[0], p[1]) {
			t.Errorf("expected DENIED: %s/%s", p[0], p[1])
		}
	}
}

func TestHACallHappyPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/services/notify/mobile_app_test_phone" {
			t.Errorf("path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer ha-tok" {
			t.Errorf("auth: %q", r.Header.Get("Authorization"))
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["title"] != "hi" {
			t.Errorf("body: %v", body)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"context":{"id":"leaks-entity-data"}}`)) // must never be echoed
	}))
	defer ts.Close()

	status, err := NewHAClient(ts.URL).Call(context.Background(), "ha-tok", "notify", "mobile_app_test_phone",
		map[string]any{"title": "hi", "message": "there"})
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK {
		t.Fatalf("status: %d", status)
	}
}

func TestHACallDeniedPairMakesNoRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("disallowed pair must not reach HA")
	}))
	defer ts.Close()
	if _, err := NewHAClient(ts.URL).Call(context.Background(), "ha-tok", "lock", "unlock", nil); err == nil {
		t.Fatal("disallowed pair must error before any request")
	}
}

func TestHACallReturnsNon2xxStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"unknown service"}`, http.StatusBadRequest)
	}))
	defer ts.Close()
	status, err := NewHAClient(ts.URL).Call(context.Background(), "ha-tok", "persistent_notification", "create", map[string]any{"notification_id": "x"})
	if err != nil {
		t.Fatalf("a completed request must not be a transport error: %v", err)
	}
	if status != http.StatusBadRequest {
		t.Fatalf("status: %d", status)
	}
}
