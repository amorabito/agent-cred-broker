// Command ha-notify-proxy narrows Home Assistant's all-or-nothing access token
// down to three notify actions, gated by the caller's bound k8s ServiceAccount
// identity. Agents hold no HA credential; the proxy leases the HA token from
// the broker per request, makes one HA call, and drops it (ADR-0006).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/amorabito/agent-cred-broker/internal/audit"
	"github.com/amorabito/agent-cred-broker/internal/authn"
	"github.com/amorabito/agent-cred-broker/internal/notify"
	"github.com/amorabito/agent-cred-broker/internal/server"
	"github.com/amorabito/agent-cred-broker/internal/tlsx"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("ha-notify-proxy: %v", err)
	}
}

func run() error {
	var (
		listenAddr  = env("HANP_LISTEN_ADDR", ":8444")
		healthAddr  = env("HANP_HEALTH_ADDR", ":8082")
		policyFile  = env("HANP_POLICY_FILE", "/etc/ha-notify-proxy/policy/policy.yaml")
		signingKey  = env("HANP_SIGNING_KEY_FILE", "/etc/ha-notify-proxy/keys/signing.pem")
		tlsCert     = os.Getenv("HANP_TLS_CERT_FILE")
		tlsKey      = os.Getenv("HANP_TLS_KEY_FILE")
		audience    = env("HANP_AUDIENCE", "ha-notify-proxy")
		haURL       = os.Getenv("HANP_HA_URL")
		brokerURL   = os.Getenv("HANP_BROKER_URL")
		brokerCA    = env("HANP_BROKER_CA_FILE", "/etc/ha-notify-proxy/broker-ca/ca.crt")
		brokerTok   = env("HANP_BROKER_TOKEN_FILE", "/var/run/secrets/broker/token")
		leaseScope  = env("HANP_LEASE_SCOPE", "ha-notify-token")
		devInsecure = os.Getenv("HANP_DEV_INSECURE") == "1"
	)
	if haURL == "" {
		return fmt.Errorf("HANP_HA_URL is required")
	}
	if brokerURL == "" {
		return fmt.Errorf("HANP_BROKER_URL is required")
	}

	signer, err := loadSigner(signingKey, devInsecure)
	if err != nil {
		return err
	}
	instance, err := os.Hostname()
	if err != nil || instance == "" {
		instance = "unknown-instance"
	}
	emitter := audit.NewEmitter(os.Stdout, signer, instance)

	raw, err := os.ReadFile(policyFile)
	if err != nil {
		return fmt.Errorf("read notify policy: %w", err)
	}
	pol, err := notify.Parse(raw)
	if err != nil {
		return fmt.Errorf("notify policy is fatal at startup by design: %w", err)
	}

	reviewerCfg, err := authn.InClusterConfig(audience)
	if kubeAPI := os.Getenv("HANP_KUBE_API"); kubeAPI != "" { // test/dev override
		reviewerCfg, err = authn.Config{
			APIBase:   kubeAPI,
			TokenFile: env("HANP_KUBE_TOKEN_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
			CAFile:    os.Getenv("HANP_KUBE_CA_FILE"),
			Audience:  audience,
		}, nil
	}
	if err != nil {
		return err
	}
	reviewer, err := authn.New(reviewerCfg)
	if err != nil {
		return err
	}

	leaseClient, err := notify.NewLeaseClient(brokerURL, brokerCA, leaseScope, brokerTok)
	if err != nil {
		return err
	}

	metrics := server.NewMetrics()
	emitter.SetCounter(func(t string) { metrics.Inc("acb_audit_events_total", map[string]string{"type": t}) })
	srv := notify.New(notify.Config{}, pol, reviewer.Review, notify.NewHAClient(haURL), leaseClient, emitter, signer, metrics)

	srv.EmitStarted()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Readiness = policy loaded AND Home Assistant reachable. No token-expiry
	// gauge exists for HA's ~10-year LLAT, so reachability is the honest alarm
	// signal (ADR-0006). Probes /manifest.json — served without auth — because an
	// unauthenticated GET /api/ registers as a failed login attempt in HA's
	// http.ban component on every cycle. Cached so the probe doesn't hammer HA.
	haReady := newCachedProbe(haURL+"/manifest.json", 30*time.Second)
	ready := func() bool { return pol != nil && haReady() }

	health := &http.Server{Addr: healthAddr, Handler: srv.HealthHandler(ready), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := health.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("health listener: %v", err)
		}
	}()

	api := &http.Server{
		Addr:              listenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = api.Shutdown(shutdownCtx)
		_ = health.Shutdown(shutdownCtx)
	}()

	switch {
	case tlsCert != "" && tlsKey != "":
		// GetCertificate re-reads the keypair from disk so a cert-manager
		// rotation is served without a pod restart (the cert-manager Certificate
		// renews ~15 days before a 90-day expiry).
		reloader := &tlsx.Reloader{CertFile: tlsCert, KeyFile: tlsKey}
		tlsCfg, cfgErr := reloader.Config()
		if cfgErr != nil {
			return fmt.Errorf("load tls keypair: %w", cfgErr)
		}
		api.TLSConfig = tlsCfg
		log.Printf("ha-notify-proxy listening (TLS) on %s, health on %s", listenAddr, healthAddr)
		err = api.ListenAndServeTLS("", "")
	case devInsecure:
		log.Printf("ha-notify-proxy listening (PLAINTEXT, HANP_DEV_INSECURE) on %s — never in production", listenAddr)
		err = api.ListenAndServe()
	default:
		return fmt.Errorf("TLS is required: set HANP_TLS_CERT_FILE/HANP_TLS_KEY_FILE (or HANP_DEV_INSECURE=1 for local dev)")
	}
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// newCachedProbe returns a function that reports whether url answers any HTTP
// status within a short timeout, caching the result for ttl.
func newCachedProbe(url string, ttl time.Duration) func() bool {
	var (
		mu   sync.Mutex
		at   time.Time
		ok   bool
		seen bool
	)
	client := &http.Client{Timeout: 3 * time.Second}
	return func() bool {
		mu.Lock()
		defer mu.Unlock()
		if seen && time.Since(at) < ttl {
			return ok
		}
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			at, ok, seen = time.Now(), false, true
			return false
		}
		// Distinct UA so upstream logs attribute the probe instantly.
		req.Header.Set("User-Agent", "ha-notify-proxy-readyz/1.0")
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		at, ok, seen = time.Now(), err == nil, true
		return ok
	}
}

// loadSigner reads a PKCS#8 Ed25519 private key PEM. In dev mode a missing key
// is generated ephemerally (events won't verify across restarts — dev only).
func loadSigner(path string, devInsecure bool) (*audit.Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if devInsecure && os.IsNotExist(err) {
			_, priv, genErr := ed25519.GenerateKey(rand.Reader)
			if genErr != nil {
				return nil, genErr
			}
			log.Printf("WARNING: ephemeral signing key (dev only): %s missing", path)
			return audit.NewSigner(priv), nil
		}
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	return audit.ParseSignerPEM(raw)
}
