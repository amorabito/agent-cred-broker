package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// LeaseClient leases the HA token from the broker per request, using the
// proxy's OWN bound ServiceAccount token (audience agent-cred-broker). The HA
// token never rests here — it is returned to the caller, used for one HA call,
// and dropped. This is what keeps the broker the sole holder-at-rest of the
// god-token (ADR-0006).
type LeaseClient struct {
	brokerURL string
	scope     string
	client    *http.Client
	tokenFn   func() (string, error) // the proxy's own bound broker-audience token
}

// NewLeaseClient builds a client that pins the broker's CA. caFile empty means
// system roots (dev only).
func NewLeaseClient(brokerURL, caFile, scope, tokenFile string) (*LeaseClient, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		ca, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read broker CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("no certs parsed from %s", caFile)
		}
		tlsCfg.RootCAs = pool
	}
	return &LeaseClient{
		brokerURL: strings.TrimRight(brokerURL, "/"),
		scope:     scope,
		client:    &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}},
		tokenFn: func() (string, error) {
			b, err := os.ReadFile(tokenFile)
			return strings.TrimSpace(string(b)), err
		},
	}, nil
}

// Lease is the HA token plus the broker lease id that authorized it. The lease
// id joins the broker's signed lease.issued to the proxy's notify.forwarded.
type Lease struct {
	Token   string
	LeaseID string
}

type leaseReq struct {
	Scope   string            `json:"scope"`
	Context map[string]string `json:"context,omitempty"`
}
type leaseResp struct {
	LeaseID string            `json:"lease_id"`
	Secret  map[string]string `json:"secret"`
}

// Lease requests the HA token from the broker. context is copied verbatim into
// the broker's lease.issued asserted block (originating agent, action) so the
// two audit streams correlate. The broker's error text is never echoed.
func (l *LeaseClient) Lease(ctx context.Context, leaseContext map[string]string) (*Lease, error) {
	body, err := json.Marshal(leaseReq{Scope: l.scope, Context: leaseContext})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.brokerURL+"/v1/leases", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	tok, err := l.tokenFn()
	if err != nil {
		return nil, fmt.Errorf("read broker token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")

	resp, err := l.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("broker unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		// Never propagate the broker's body: it may name scopes/policy.
		return nil, fmt.Errorf("broker lease failed: status %d", resp.StatusCode)
	}
	var lr leaseResp
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return nil, fmt.Errorf("decode lease: %w", err)
	}
	tokenVal := lr.Secret["token"]
	if tokenVal == "" || lr.LeaseID == "" {
		return nil, fmt.Errorf("broker lease response incomplete")
	}
	return &Lease{Token: tokenVal, LeaseID: lr.LeaseID}, nil
}
