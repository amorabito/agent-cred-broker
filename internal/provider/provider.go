// Package provider defines the secret-source interface and its
// implementations. The MVP ships one static provider (1Password Connect);
// the interface admits dynamic providers (GitHub App installation tokens,
// Kubernetes TokenRequest) that mint genuinely revocable credentials later.
package provider

import "context"

// Semantics of the secret material a provider returns (ADR-0004).
const (
	// SemanticsStaticDisclosure: the TTL is a contract and an audit
	// construct, not revocation. Nothing un-discloses a static secret.
	SemanticsStaticDisclosure = "static-disclosure"
	// SemanticsRevocable is reserved for dynamic providers. Nothing in the
	// MVP issues it.
	SemanticsRevocable = "revocable"
)

// Provider fetches secret material for a scope.
type Provider interface {
	// Name matches the policy `provider` field.
	Name() string
	// Semantics of the returned material.
	Semantics() string
	// Fetch resolves ref and returns lease-field -> value. fields maps
	// lease field name -> provider field label. A missing field is an
	// error: fail closed, no partial secrets.
	Fetch(ctx context.Context, ref string, fields map[string]string) (map[string]string, error)
}
