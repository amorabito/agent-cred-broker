package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

const testRef = "vaults/abcdefghijklmnopqrstuvwxyz/items/zyxwvutsrqponmlkjihgfedcba"

func newConnect(t *testing.T, handler http.HandlerFunc) *OnePassword {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return NewOnePassword(ts.URL, func() (string, error) { return "connect-token", nil })
}

func TestFetchHappyPath(t *testing.T) {
	p := newConnect(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/vaults/abcdefghijklmnopqrstuvwxyz/items/zyxwvutsrqponmlkjihgfedcba" {
			t.Errorf("path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer connect-token" {
			t.Errorf("auth: %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"fields": []map[string]string{
				{"id": "f1", "label": "credential", "value": "the-secret"},
				{"id": "f2", "label": "notes", "value": "irrelevant"},
			},
		})
	})
	out, err := p.Fetch(context.Background(), testRef, map[string]string{"token": "credential"})
	if err != nil {
		t.Fatal(err)
	}
	if out["token"] != "the-secret" {
		t.Fatalf("out: %v", out)
	}
	if _, ok := out["notes"]; ok {
		t.Fatal("unmapped fields must not be returned")
	}
}

func TestFetchMissingFieldFailsClosed(t *testing.T) {
	p := newConnect(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"fields": []map[string]string{{"id": "f1", "label": "other", "value": "x"}},
		})
	})
	if _, err := p.Fetch(context.Background(), testRef, map[string]string{"token": "credential"}); err == nil {
		t.Fatal("missing field must fail closed")
	}
}

func TestFetchUpstreamErrorNotEchoed(t *testing.T) {
	p := newConnect(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"vault details that must not propagate"}`, http.StatusForbidden)
	})
	_, err := p.Fetch(context.Background(), testRef, map[string]string{"token": "credential"})
	if err == nil {
		t.Fatal("expected error")
	}
	if got := err.Error(); got != "connect returned status 403" {
		t.Fatalf("error leaks upstream body: %q", got)
	}
}

func TestFetchRejectsBadRef(t *testing.T) {
	p := NewOnePassword("http://unused", func() (string, error) { return "t", nil })
	if _, err := p.Fetch(context.Background(), "../health", nil); err == nil {
		t.Fatal("bad ref must be rejected before any request")
	}
}
