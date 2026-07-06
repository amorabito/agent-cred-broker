package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// haServiceNameRe bounds any service-name segment the proxy will place in a HA
// URL. Belt to the policy's suspenders (haTargetPattern) and to haAllowed.
var haServiceNameRe = regexp.MustCompile(`^[a-z0-9_]+$`)

// haAllowed is the compiled binary ceiling on what the proxy can EVER call:
// exactly two HA domains, and for persistent_notification exactly create or
// dismiss. This is enforced in the binary, so a config typo or a widened
// ConfigMap can never make the proxy call lock.unlock — the domain isn't here.
// (Grafted from the broker's github provider discipline: URLs are built from
// validated components, never caller strings.)
func haAllowed(domain, service string) bool {
	switch domain {
	case "notify":
		// The specific target (which mobile_app) is constrained by policy;
		// here we only bound the charset of the service segment.
		return haServiceNameRe.MatchString(service)
	case "persistent_notification":
		return service == "create" || service == "dismiss"
	}
	return false
}

// HAClient calls Home Assistant. It holds NO token — the token is passed per
// call (leased fresh from the broker and dropped after), so nothing HA-powerful
// is resident in this struct.
type HAClient struct {
	base   string
	client *http.Client
}

func NewHAClient(baseURL string) *HAClient {
	return &HAClient{
		base:   strings.TrimRight(baseURL, "/"),
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Call performs one HA service call with the given per-call token. It returns
// the HA HTTP status (0 if the request never completed) and an error only for
// a disallowed pair or a transport failure. HA's response body is NEVER read or
// echoed — it can carry entity data, and the status is all the proxy needs.
func (h *HAClient) Call(ctx context.Context, token, domain, service string, body map[string]any) (int, error) {
	if !haAllowed(domain, service) {
		// Defense in depth: policy should already have constrained this.
		return 0, fmt.Errorf("ha service %s/%s not permitted", domain, service)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	// URL from validated components only (url.PathEscape on each), never by
	// concatenating a caller-supplied string.
	u := h.base + "/api/services/" + url.PathEscape(domain) + "/" + url.PathEscape(service)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("home assistant unreachable: %w", err)
	}
	// Drain-free close: we never read the body on purpose.
	resp.Body.Close()
	return resp.StatusCode, nil
}
