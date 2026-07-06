package provider

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// verifyAppJWT checks the RS256 signature and required claims exactly as GitHub
// would, so a happy-path test proves the broker's hand-rolled signing is valid.
func verifyAppJWT(t *testing.T, tok, wantIss string, pub *rsa.PublicKey) {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt not three parts: %q", tok)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("app jwt signature invalid: %v", err)
	}
	var claims struct {
		Iss string `json:"iss"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(cb, &claims)
	if claims.Iss != wantIss {
		t.Fatalf("iss = %q, want %q", claims.Iss, wantIss)
	}
	if claims.Exp-claims.Iat > 600 {
		t.Fatalf("jwt lifetime %ds exceeds GitHub's 10-minute max", claims.Exp-claims.Iat)
	}
}

func TestGitHubMintHappyPath(t *testing.T) {
	key := testKey(t)
	expiry := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)

	var gotBody map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app/installations/12345678/access_tokens" {
			t.Errorf("path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method: %s", r.Method)
		}
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		verifyAppJWT(t, bearer, "998877", &key.PublicKey)
		if r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Errorf("accept: %q", r.Header.Get("Accept"))
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      "ghs_installationtoken",
			"expires_at": expiry.Format(time.RFC3339),
		})
	}))
	defer ts.Close()

	p := NewGitHubApp(ts.URL, "998877", key)
	res, err := p.Fetch(context.Background(), Request{
		Ref:    "installations/12345678",
		Fields: map[string]string{"GITHUB_TOKEN": "token"},
		Params: map[string]string{
			"permissions":  "contents=read,pull_requests=write",
			"repositories": "example-infra-repo",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Secret["GITHUB_TOKEN"] != "ghs_installationtoken" {
		t.Fatalf("token: %v", res.Secret)
	}
	if !res.ExpiresAt.Equal(expiry) {
		t.Fatalf("expiry: %v want %v", res.ExpiresAt, expiry)
	}
	// The request the broker sent must carry exactly the policy-pinned scope.
	perms, _ := gotBody["permissions"].(map[string]any)
	if perms["contents"] != "read" || perms["pull_requests"] != "write" {
		t.Fatalf("permissions not pinned to policy: %v", gotBody["permissions"])
	}
	repos, _ := gotBody["repositories"].([]any)
	if len(repos) != 1 || repos[0] != "example-infra-repo" {
		t.Fatalf("repositories not pinned to policy: %v", gotBody["repositories"])
	}
}

func TestGitHubMintNoPermissionsFailsClosed(t *testing.T) {
	// No upstream should even be contacted; a permission-less scope is denied
	// before the exchange because the token would inherit the whole install.
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("must not contact GitHub without pinned permissions")
	}))
	defer ts.Close()
	p := NewGitHubApp(ts.URL, "1", testKey(t))
	_, err := p.Fetch(context.Background(), Request{
		Ref:    "installations/1",
		Fields: map[string]string{"token": "token"},
		Params: map[string]string{"repositories": "x"},
	})
	if err == nil {
		t.Fatal("missing permissions must fail closed")
	}
}

func TestGitHubMintUpstreamErrorNotEchoed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"contents permission not granted to installation"}`, http.StatusUnprocessableEntity)
	}))
	defer ts.Close()
	p := NewGitHubApp(ts.URL, "1", testKey(t))
	_, err := p.Fetch(context.Background(), Request{
		Ref:    "installations/1",
		Fields: map[string]string{"token": "token"},
		Params: map[string]string{"permissions": "contents=write"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if got := err.Error(); got != "github token exchange: status 422" {
		t.Fatalf("error leaks upstream body: %q", got)
	}
}

func TestGitHubMintUnknownFieldFailsClosed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token": "ghs_x", "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		})
	}))
	defer ts.Close()
	p := NewGitHubApp(ts.URL, "1", testKey(t))
	_, err := p.Fetch(context.Background(), Request{
		Ref:    "installations/1",
		Fields: map[string]string{"token": "not-token"}, // maps an unknown output key
		Params: map[string]string{"permissions": "contents=read"},
	})
	if err == nil {
		t.Fatal("field mapping an unknown output key must fail closed")
	}
}

func TestGitHubMintBadRef(t *testing.T) {
	p := NewGitHubApp("http://unused", "1", testKey(t))
	if _, err := p.Fetch(context.Background(), Request{Ref: "installations/abc"}); err == nil {
		t.Fatal("non-numeric installation ref must be rejected before any request")
	}
}

func TestParseKeyPKCS1AndPKCS8(t *testing.T) {
	key := testKey(t)
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if _, err := ParseKey(pkcs1); err != nil {
		t.Fatalf("PKCS#1: %v", err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	pkcs8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := ParseKey(pkcs8); err != nil {
		t.Fatalf("PKCS#8: %v", err)
	}
	if _, err := ParseKey([]byte("not a pem")); err == nil {
		t.Fatal("garbage must be rejected")
	}
}
