// Package authn validates bound ServiceAccount tokens with the Kubernetes
// TokenReview API. The broker holds no verification key material of its own:
// it sends the presented token plus its required audience and trusts the API
// server's verdict. Results are deliberately not cached — the API server
// rejects a bound token once its pod dies, and a cache would trade that
// liveness check away (ADR-0002).
package authn

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/amorabito/agent-cred-broker/internal/audit"
)

const (
	saPrefix     = "system:serviceaccount:"
	podNameExtra = "authentication.kubernetes.io/pod-name"
	podUIDExtra  = "authentication.kubernetes.io/pod-uid"
)

// ErrUnauthenticated is returned for any token the API server rejects or that
// fails the audience check. Callers must not distinguish causes to clients.
var ErrUnauthenticated = fmt.Errorf("unauthenticated")

// Reviewer validates tokens via TokenReview.
type Reviewer struct {
	client   *http.Client
	apiBase  string
	audience string
	token    func() (string, error)
}

// Config for constructing a Reviewer outside the cluster (tests) or in it.
type Config struct {
	// APIBase is the API server URL, e.g. https://kubernetes.default.svc.
	APIBase string
	// TokenFile is the broker's own ServiceAccount token used to call TokenReview.
	TokenFile string
	// CAFile is the cluster CA bundle; empty means system roots.
	CAFile string
	// Audience the broker requires in presented tokens.
	Audience string
}

// InClusterConfig builds a Config from the standard in-cluster paths.
func InClusterConfig(audience string) (Config, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return Config{}, fmt.Errorf("not running in-cluster: KUBERNETES_SERVICE_HOST/PORT unset")
	}
	return Config{
		APIBase:   "https://" + host + ":" + port,
		TokenFile: "/var/run/secrets/kubernetes.io/serviceaccount/token",
		CAFile:    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
		Audience:  audience,
	}, nil
}

func New(cfg Config) (*Reviewer, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		ca, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("no certs parsed from %s", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	return &Reviewer{
		client:   &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}},
		apiBase:  strings.TrimRight(cfg.APIBase, "/"),
		audience: cfg.Audience,
		token: func() (string, error) {
			b, err := os.ReadFile(cfg.TokenFile)
			if err != nil {
				return "", err
			}
			return strings.TrimSpace(string(b)), nil
		},
	}, nil
}

type tokenReview struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Spec       tokenReviewSpec `json:"spec"`
	Status     struct {
		Authenticated bool     `json:"authenticated"`
		Audiences     []string `json:"audiences"`
		Error         string   `json:"error"`
		User          struct {
			Username string              `json:"username"`
			Extra    map[string][]string `json:"extra"`
		} `json:"user"`
	} `json:"status"`
}

type tokenReviewSpec struct {
	Token     string   `json:"token"`
	Audiences []string `json:"audiences"`
}

// Review validates a presented token and returns the subject. Any failure —
// API rejection, wrong audience, malformed username — returns
// ErrUnauthenticated (wrapped), never a distinguishing error for the client.
func (r *Reviewer) Review(ctx context.Context, presented string) (*audit.Subject, error) {
	body, err := json.Marshal(tokenReview{
		APIVersion: "authentication.k8s.io/v1",
		Kind:       "TokenReview",
		Spec:       tokenReviewSpec{Token: presented, Audiences: []string{r.audience}},
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		r.apiBase+"/apis/authentication.k8s.io/v1/tokenreviews", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	own, err := r.token()
	if err != nil {
		return nil, fmt.Errorf("read own token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+own)
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tokenreview request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tokenreview status %d", resp.StatusCode)
	}
	var tr tokenReview
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, fmt.Errorf("decode tokenreview: %w", err)
	}
	if !tr.Status.Authenticated {
		return nil, fmt.Errorf("%w: token rejected", ErrUnauthenticated)
	}
	if !slices.Contains(tr.Status.Audiences, r.audience) {
		return nil, fmt.Errorf("%w: audience mismatch", ErrUnauthenticated)
	}
	ns, sa, ok := strings.Cut(strings.TrimPrefix(tr.Status.User.Username, saPrefix), ":")
	if !strings.HasPrefix(tr.Status.User.Username, saPrefix) || !ok || ns == "" || sa == "" {
		return nil, fmt.Errorf("%w: not a serviceaccount: %q", ErrUnauthenticated, tr.Status.User.Username)
	}
	sub := &audit.Subject{Namespace: ns, ServiceAccount: sa}
	if pods := tr.Status.User.Extra[podNameExtra]; len(pods) > 0 {
		sub.Pod = pods[0]
	}
	if uids := tr.Status.User.Extra[podUIDExtra]; len(uids) > 0 {
		sub.PodUID = uids[0]
	}
	return sub, nil
}
