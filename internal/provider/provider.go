// Package provider defines the secret-source interface and its
// implementations. Two shapes of provider share one interface:
//
//   - static-disclosure (1Password Connect): returns a pre-existing long-lived
//     secret. The lease TTL is a contract and an audit construct — nothing
//     un-discloses a static secret once it has left the broker.
//   - revocable (GitHub App installation tokens): mints a fresh credential
//     with an upstream-enforced hard expiry, scoped to exactly the repos and
//     permissions the policy pins. This is the "eliminate, not just contain"
//     path — a leaked token dies on its own within the hour.
package provider

import (
	"context"
	"time"
)

// Semantics of the secret material a provider returns (ADR-0004, ADR-0005).
const (
	// SemanticsStaticDisclosure: the TTL is a contract and an audit
	// construct, not revocation. Nothing un-discloses a static secret.
	SemanticsStaticDisclosure = "static-disclosure"
	// SemanticsRevocable: the material is freshly minted with an
	// upstream-enforced expiry (and, where the upstream supports it, active
	// revocation). A leak is bounded by the credential's own lifetime.
	SemanticsRevocable = "revocable"
)

// Request is the fully-resolved scope configuration handed to a provider. All
// fields come from the policy (a deny-by-default ConfigMap) except TTL, which
// is the caller's already-clamped lease lifetime. Nothing here is
// caller-controlled beyond the requested TTL — a subject can never widen its
// own repos or permissions.
type Request struct {
	// Ref is the provider-specific locator (a 1Password item ref, a GitHub
	// installation ref). Validated by policy before it reaches here.
	Ref string
	// Fields maps lease field name -> provider output key. A missing key is
	// an error: fail closed, no partial secrets.
	Fields map[string]string
	// Params carries provider-specific static configuration from the scope
	// (e.g. GitHub repositories and permissions). Empty for static providers.
	Params map[string]string
	// TTL is the lease lifetime the broker intends. A provider that mints a
	// credential with its own fixed lifetime (GitHub ~1h) ignores this; the
	// broker caps the lease to the returned Result.ExpiresAt so the lease
	// never claims to outlive the credential.
	TTL time.Duration
}

// Result is the material a provider returns for one issuance.
type Result struct {
	// Secret maps lease field name -> value, per Request.Fields.
	Secret map[string]string
	// ExpiresAt is the upstream-enforced hard expiry of the credential. Zero
	// for static-disclosure providers (the secret has no self-expiry). For
	// revocable providers it is the moment the credential stops working no
	// matter what the lease says — the broker clamps the lease to it.
	ExpiresAt time.Time
}

// Provider fetches or mints secret material for a scope.
type Provider interface {
	// Name matches the policy `provider` field.
	Name() string
	// Semantics of the returned material.
	Semantics() string
	// Fetch resolves a Request into secret material. Fail closed: any
	// missing field or upstream error returns an error and no partial secret.
	Fetch(ctx context.Context, req Request) (*Result, error)
}
