package provider

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// GitHubApp mints GitHub App *installation access tokens*: short-lived
// (~1 hour, upstream-enforced) credentials scoped to exactly the repositories
// and permissions the policy pins. This is the revocable counterpart to the
// static 1Password provider — the credential the agent receives dies on its
// own within the hour and can be actively revoked, so a leak is contained by
// the credential's own lifetime rather than by a rotation runbook.
//
// The App's private key is the broker's second long-lived root secret; it is
// mounted from a file (never in policy, which is a non-secret ConfigMap) and
// used only to sign the short JWT that authenticates the token exchange.
type GitHubApp struct {
	base   string // e.g. https://api.github.com (or a GHES base)
	appID  string
	key    *rsa.PrivateKey
	client *http.Client
	now    func() time.Time // overridable in tests
}

// ghInstallationRef matches "installations/<numeric-id>".
var ghInstallationRef = regexp.MustCompile(`^installations/([0-9]+)$`)

// NewGitHubApp constructs a provider for one GitHub App. baseURL defaults to
// the public API when empty.
func NewGitHubApp(baseURL, appID string, key *rsa.PrivateKey) *GitHubApp {
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	return &GitHubApp{
		base:   strings.TrimRight(baseURL, "/"),
		appID:  appID,
		key:    key,
		client: &http.Client{Timeout: 10 * time.Second},
		now:    time.Now,
	}
}

func (g *GitHubApp) Name() string      { return "github-app" }
func (g *GitHubApp) Semantics() string { return SemanticsRevocable }

// ParseKey loads an RSA private key from a GitHub App PEM. GitHub issues
// PKCS#1 ("RSA PRIVATE KEY") keys; PKCS#8 ("PRIVATE KEY") is accepted too so a
// converted key still works.
func ParseKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("github app key: no PEM block")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("github app key: not PKCS#1 or PKCS#8 RSA")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("github app key: not an RSA key")
	}
	return key, nil
}

// appJWT builds the short-lived RS256 JWT that authenticates the broker AS the
// App to the token-exchange endpoint. iat is back-dated 30s to tolerate clock
// skew; exp is 9 minutes out (GitHub rejects JWTs with lifetime > 10 min).
func (g *GitHubApp) appJWT() (string, error) {
	now := g.now()
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"iat": now.Add(-30 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": g.appID,
	}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(hb) + "." + enc.EncodeToString(cb)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, g.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign app jwt: %w", err)
	}
	return signingInput + "." + enc.EncodeToString(sig), nil
}

type ghTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Fetch mints an installation token for the scope. The repositories and
// permissions are read from Params (policy-pinned) — the caller cannot widen
// them. req.TTL is ignored: GitHub fixes the token lifetime (~1h) and the
// broker clamps the lease to the returned ExpiresAt.
func (g *GitHubApp) Fetch(ctx context.Context, req Request) (*Result, error) {
	m := ghInstallationRef.FindStringSubmatch(req.Ref)
	if m == nil {
		// Policy validation already enforces this; re-checked so a bad ref
		// can never reach URL construction.
		return nil, fmt.Errorf("invalid github installation ref")
	}
	installationID := m[1]

	body := map[string]any{}
	if perms := parsePermissions(req.Params["permissions"]); len(perms) > 0 {
		body["permissions"] = perms
	} else {
		// A permission-less installation token would carry the installation's
		// full granted scope — the opposite of least privilege. Fail closed.
		return nil, fmt.Errorf("github scope has no permissions")
	}
	if repos := parseList(req.Params["repositories"]); len(repos) > 0 {
		body["repositories"] = repos
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	jwt, err := g.appJWT()
	if err != nil {
		return nil, err
	}
	// installationID is \d+ from a validated ref; safe to interpolate.
	url := g.base + "/app/installations/" + installationID + "/access_tokens"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+jwt)
	httpReq.Header.Set("Accept", "application/vnd.github+json")
	httpReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := g.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("github token exchange: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		// Never echo the body: GitHub's error can name repos/permissions and
		// the caller may learn only that the mint failed, not why.
		return nil, fmt.Errorf("github token exchange: status %d", resp.StatusCode)
	}
	var tok ghTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, fmt.Errorf("decode github token: %w", err)
	}
	if tok.Token == "" || tok.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("github token response incomplete")
	}

	// The provider's only output key is "token"; Fields renames it to the
	// lease field the caller expects (e.g. {GITHUB_TOKEN: token}). Any field
	// mapping to an unknown key fails closed, mirroring the 1Password path.
	out := make(map[string]string, len(req.Fields))
	for leaseField, key := range req.Fields {
		if key != "token" {
			return nil, fmt.Errorf("github scope maps unknown field %q", key)
		}
		out[leaseField] = tok.Token
	}
	return &Result{Secret: out, ExpiresAt: tok.ExpiresAt.UTC()}, nil
}

// parsePermissions turns "contents=read,pull_requests=write" into a GitHub
// permissions object. Malformed entries are dropped; policy validation is the
// authoritative gate, this is defensive.
func parsePermissions(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || k == "" || v == "" {
			continue
		}
		out[k] = v
	}
	return out
}

// parseList splits a comma-separated list, trimming blanks.
func parseList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
