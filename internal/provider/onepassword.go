package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

var opRef = regexp.MustCompile(`^vaults/([a-z0-9]{26})/items/([a-z0-9]{26})$`)

// OnePassword fetches items from a 1Password Connect server. The Connect
// token is the one long-lived credential in the whole system; it is read
// lazily per request from tokenFn so file-based rotation takes effect
// without a restart.
type OnePassword struct {
	base    string
	tokenFn func() (string, error)
	client  *http.Client

	healthMu  sync.Mutex
	healthAt  time.Time
	healthErr error
}

func NewOnePassword(baseURL string, tokenFn func() (string, error)) *OnePassword {
	return &OnePassword{
		base:    strings.TrimRight(baseURL, "/"),
		tokenFn: tokenFn,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (o *OnePassword) Name() string      { return "onepassword-connect" }
func (o *OnePassword) Semantics() string { return SemanticsStaticDisclosure }

// healthTTL caches the (authenticated, thus not-free) probe so Kubernetes
// readiness checks don't hammer Connect. A newly-bad token reflects in readiness
// within this window.
const healthTTL = 60 * time.Second

// Healthy validates that the broker can actually mint credentials right now:
// Connect is reachable AND the Connect token authenticates. It hits the
// AUTHENTICATED /v1/vaults endpoint (not the unauthenticated /health), so an
// expired or revoked token — the silent-failure mode /health cannot see — makes
// /readyz go unready instead of the broker running dark. Cached to keep readiness
// probes off Connect's back.
func (o *OnePassword) Healthy(ctx context.Context) error {
	o.healthMu.Lock()
	defer o.healthMu.Unlock()
	if time.Since(o.healthAt) < healthTTL {
		return o.healthErr
	}
	err := o.probeAuthenticated(ctx)
	o.healthAt, o.healthErr = time.Now(), err
	return err
}

// probeAuthenticated does a token-authenticated GET /v1/vaults: 200 = reachable
// and token valid; 401/403 = token expired or revoked; transport error =
// unreachable. The response body (a vault list) is never read — only the status
// matters, and it can carry no secret the broker didn't already trust.
func (o *OnePassword) probeAuthenticated(ctx context.Context) error {
	token, err := o.tokenFn()
	if err != nil {
		return fmt.Errorf("read connect token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.base+"/v1/vaults", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("connect unreachable: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("connect token check: status %d", resp.StatusCode)
	}
	return nil
}

type opItem struct {
	Fields []struct {
		ID    string `json:"id"`
		Label string `json:"label"`
		Value string `json:"value"`
	} `json:"fields"`
}

func (o *OnePassword) Fetch(ctx context.Context, req Request) (*Result, error) {
	m := opRef.FindStringSubmatch(req.Ref)
	if m == nil {
		// Policy validation already enforces this; double-checked here so a
		// bad ref can never reach URL construction.
		return nil, fmt.Errorf("invalid onepassword ref")
	}
	// URL built from parsed, pattern-constrained components only.
	u := fmt.Sprintf("%s/v1/vaults/%s/items/%s", o.base, url.PathEscape(m[1]), url.PathEscape(m[2]))

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	token, err := o.tokenFn()
	if err != nil {
		return nil, fmt.Errorf("read connect token: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("connect request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Never include response body: upstream errors may echo item data.
		return nil, fmt.Errorf("connect returned status %d", resp.StatusCode)
	}
	var item opItem
	if err := json.NewDecoder(resp.Body).Decode(&item); err != nil {
		return nil, fmt.Errorf("decode connect item: %w", err)
	}

	byLabel := make(map[string]string, len(item.Fields))
	for _, f := range item.Fields {
		byLabel[f.Label] = f.Value
	}
	out := make(map[string]string, len(req.Fields))
	for leaseField, label := range req.Fields {
		v, ok := byLabel[label]
		if !ok || v == "" {
			return nil, fmt.Errorf("item field %q missing or empty", label)
		}
		out[leaseField] = v
	}
	// ExpiresAt stays zero: a 1Password item is static-disclosure. The lease
	// TTL is the only bound, and it bounds the contract, not the secret.
	return &Result{Secret: out}, nil
}
