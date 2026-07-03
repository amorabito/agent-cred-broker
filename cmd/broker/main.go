// Command broker runs the agent-cred-broker: TokenReview authn, YAML policy
// authz, 1Password Connect as the secret source, signed act-claims on stdout.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/amorabito/agent-cred-broker/internal/audit"
	"github.com/amorabito/agent-cred-broker/internal/authn"
	"github.com/amorabito/agent-cred-broker/internal/lease"
	"github.com/amorabito/agent-cred-broker/internal/policy"
	"github.com/amorabito/agent-cred-broker/internal/provider"
	"github.com/amorabito/agent-cred-broker/internal/server"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("broker: %v", err)
	}
}

func run() error {
	var (
		listenAddr  = env("ACB_LISTEN_ADDR", ":8443")
		healthAddr  = env("ACB_HEALTH_ADDR", ":8081")
		policyFile  = env("ACB_POLICY_FILE", "/etc/agent-cred-broker/policy.yaml")
		signingKey  = env("ACB_SIGNING_KEY_FILE", "/etc/agent-cred-broker/keys/signing.pem")
		tlsCert     = os.Getenv("ACB_TLS_CERT_FILE")
		tlsKey      = os.Getenv("ACB_TLS_KEY_FILE")
		connectURL  = os.Getenv("ACB_CONNECT_URL")
		connectTok  = env("ACB_CONNECT_TOKEN_FILE", "/etc/agent-cred-broker/connect/token")
		audience    = env("ACB_AUDIENCE", "agent-cred-broker")
		devInsecure = os.Getenv("ACB_DEV_INSECURE") == "1"
	)

	signer, err := loadSigner(signingKey, devInsecure)
	if err != nil {
		return err
	}
	instance, _ := os.Hostname()
	emitter := audit.NewEmitter(os.Stdout, signer, instance)

	policies, err := policy.NewStore(policyFile, 10*time.Second)
	if err != nil {
		return fmt.Errorf("policy is fatal at startup by design: %w", err)
	}
	policies.OnReload = func(old, new_ *policy.Policy) {
		_ = emitter.Emit(audit.Event{
			Type: audit.TypePolicyReloaded,
			Attested: map[string]any{
				"old_policy_hash": old.Hash, "new_policy_hash": new_.Hash,
				"subjects": new_.SubjectKeys(), "scopes": new_.ScopeNames(),
			},
		})
	}
	policies.OnError = func(old *policy.Policy, err error) {
		_ = emitter.Emit(audit.Event{
			Type: audit.TypePolicyReloadFailed,
			Attested: map[string]any{
				"retained_policy_hash": old.Hash, "error": err.Error(),
			},
		})
	}

	if connectURL == "" {
		return fmt.Errorf("ACB_CONNECT_URL is required")
	}
	providers := map[string]provider.Provider{
		"onepassword-connect": provider.NewOnePassword(connectURL, func() (string, error) {
			b, err := os.ReadFile(connectTok)
			return strings.TrimSpace(string(b)), err
		}),
	}

	reviewerCfg, err := authn.InClusterConfig(audience)
	if kubeAPI := os.Getenv("ACB_KUBE_API"); kubeAPI != "" { // test/dev override
		reviewerCfg, err = authn.Config{
			APIBase:   kubeAPI,
			TokenFile: env("ACB_KUBE_TOKEN_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
			CAFile:    os.Getenv("ACB_KUBE_CA_FILE"),
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

	metrics := server.NewMetrics()
	emitter.SetCounter(func(t string) {
		metrics.Inc("acb_audit_events_total", map[string]string{"type": t})
	})
	leases := lease.NewStore()
	srv := server.New(server.Config{}, policies, reviewer.Review, providers, leases, emitter, signer, metrics)

	_ = emitter.Emit(audit.Event{
		Type: audit.TypeBrokerStarted,
		Attested: map[string]any{
			"policy_hash": policies.Current().Hash,
			"kid":         signer.KID(),
			"public_key":  signer.PublicBase64(),
		},
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go policies.Watch(ctx)
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				srv.SweepExpiredLeases(time.Hour)
			}
		}
	}()

	health := &http.Server{
		Addr:              healthAddr,
		Handler:           srv.HealthHandler(func() bool { return policies.Current() != nil }),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = health.ListenAndServe() }()

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
		log.Printf("broker listening (TLS) on %s, health on %s", listenAddr, healthAddr)
		err = api.ListenAndServeTLS(tlsCert, tlsKey)
	case devInsecure:
		log.Printf("broker listening (PLAINTEXT, ACB_DEV_INSECURE) on %s — never in production", listenAddr)
		err = api.ListenAndServe()
	default:
		return fmt.Errorf("TLS is required: set ACB_TLS_CERT_FILE/ACB_TLS_KEY_FILE (or ACB_DEV_INSECURE=1 for local dev)")
	}
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// loadSigner reads a PKCS#8 Ed25519 private key PEM. In dev mode a missing
// key is generated ephemerally (events won't verify across restarts — dev
// only, and loudly logged).
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
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("signing key %s: no PEM block", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key %s: not Ed25519", path)
	}
	return audit.NewSigner(priv), nil
}
