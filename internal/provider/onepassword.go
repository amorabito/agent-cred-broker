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

// Healthy probes the Connect server's unauthenticated /health endpoint so
// /readyz can reflect provider reachability. Results are cached for 5s to
// keep readiness probes off the Connect server's back.
func (o *OnePassword) Healthy(ctx context.Context) error {
	o.healthMu.Lock()
	defer o.healthMu.Unlock()
	if time.Since(o.healthAt) < 5*time.Second {
		return o.healthErr
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.base+"/health", nil)
	if err != nil {
		return err
	}
	resp, err := o.client.Do(req)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("connect health status %d", resp.StatusCode)
		}
	}
	o.healthAt, o.healthErr = time.Now(), err
	return err
}

type opItem struct {
	Fields []struct {
		ID    string `json:"id"`
		Label string `json:"label"`
		Value string `json:"value"`
	} `json:"fields"`
}

func (o *OnePassword) Fetch(ctx context.Context, ref string, fields map[string]string) (map[string]string, error) {
	m := opRef.FindStringSubmatch(ref)
	if m == nil {
		// Policy validation already enforces this; double-checked here so a
		// bad ref can never reach URL construction.
		return nil, fmt.Errorf("invalid onepassword ref")
	}
	// URL built from parsed, pattern-constrained components only.
	u := fmt.Sprintf("%s/v1/vaults/%s/items/%s", o.base, url.PathEscape(m[1]), url.PathEscape(m[2]))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	token, err := o.tokenFn()
	if err != nil {
		return nil, fmt.Errorf("read connect token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := o.client.Do(req)
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
	out := make(map[string]string, len(fields))
	for leaseField, label := range fields {
		v, ok := byLabel[label]
		if !ok || v == "" {
			return nil, fmt.Errorf("item field %q missing or empty", label)
		}
		out[leaseField] = v
	}
	return out, nil
}
