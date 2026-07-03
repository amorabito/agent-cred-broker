package authn

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func fakeAPIServer(t *testing.T, status func(presented string) map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/authentication.k8s.io/v1/tokenreviews" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer broker-own-token" {
			t.Errorf("broker did not authenticate itself: %q", got)
		}
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		spec := req["spec"].(map[string]any)
		auds, _ := spec["audiences"].([]any)
		if len(auds) != 1 || auds[0] != "agent-cred-broker" {
			t.Errorf("broker must request its audience, got %v", auds)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": status(spec["token"].(string)),
		})
	}))
}

func newReviewer(t *testing.T, apiURL string) *Reviewer {
	t.Helper()
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("broker-own-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := New(Config{APIBase: apiURL, TokenFile: tokenFile, Audience: "agent-cred-broker"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestReviewHappyPath(t *testing.T) {
	ts := fakeAPIServer(t, func(string) map[string]any {
		return map[string]any{
			"authenticated": true,
			"audiences":     []string{"agent-cred-broker"},
			"user": map[string]any{
				"username": "system:serviceaccount:agents:pr-reviewer",
				"extra": map[string][]string{
					"authentication.kubernetes.io/pod-name": {"pr-reviewer-x7k2m"},
				},
			},
		}
	})
	defer ts.Close()
	sub, err := newReviewer(t, ts.URL).Review(context.Background(), "presented-token")
	if err != nil {
		t.Fatal(err)
	}
	if sub.Namespace != "agents" || sub.ServiceAccount != "pr-reviewer" || sub.Pod != "pr-reviewer-x7k2m" {
		t.Fatalf("subject: %+v", sub)
	}
}

func TestReviewRejections(t *testing.T) {
	cases := map[string]map[string]any{
		"unauthenticated": {"authenticated": false, "error": "token expired"},
		"audience mismatch": {
			"authenticated": true,
			"audiences":     []string{"https://kubernetes.default.svc"},
			"user":          map[string]any{"username": "system:serviceaccount:agents:pr-reviewer"},
		},
		"not a serviceaccount": {
			"authenticated": true,
			"audiences":     []string{"agent-cred-broker"},
			"user":          map[string]any{"username": "kubernetes-admin"},
		},
	}
	for name, status := range cases {
		ts := fakeAPIServer(t, func(string) map[string]any { return status })
		_, err := newReviewer(t, ts.URL).Review(context.Background(), "presented-token")
		ts.Close()
		if err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
