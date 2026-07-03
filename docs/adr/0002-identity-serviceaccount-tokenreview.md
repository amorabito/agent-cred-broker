# ADR-0002: Agent identity = ServiceAccount, verified by TokenReview

Status: accepted · 2026-07-03

## Context

Per-agent identity is the foundation: scoping and attribution are meaningless if the
broker can't tell agents apart. Candidates: Kubernetes ServiceAccounts with bound
tokens; SPIFFE/SPIRE; mTLS with a broker-run CA; static per-agent API keys.

## Decision

Kubernetes ServiceAccounts, one per agent workload, presented as **bound projected
tokens** (`audience: agent-cred-broker`, `expirationSeconds: 600`) and verified with
the **TokenReview** API.

Because the platform already solves workload identity: the kubelet issues, rotates,
and binds these tokens to living pods, and the operator never provisions or stores
any secret on the agent's behalf. The projected token is still a bearer credential
sitting on the pod filesystem — but a leak is bounded to minutes of broker-only
access (audience-bound, short `expirationSeconds`) instead of a permanent vault-wide
token. Audience binding means a token captured from an agent is useless against the
API server or anything else; TokenReview gives the broker the ServiceAccount and pod
identity without the broker holding any verification key material of its own.

## Alternatives considered

- **Static per-agent API keys** — recreates the exact problem the broker exists to
  kill (long-lived bearer secrets in agent pods). Rejected on principle.
- **SPIFFE/SPIRE** — the right answer at organizational scale; a full identity-plane
  deployment to identify three agents on one cluster fails the project's
  no-product-scope rule.
- **mTLS with broker-run CA** — cert issuance/rotation machinery lands back on the
  broker; TokenReview gets equivalent assurance from machinery the cluster already
  runs.

## Consequences

- Identity granularity is the ServiceAccount: agents sharing a pod share identity.
  Converting an agent to the broker starts with giving it its own workload and SA
  (threat model §6).
- The broker needs a dedicated ClusterRole with `create` on
  `tokenreviews.authentication.k8s.io` — its entire RBAC.
- One TokenReview round-trip per request, uncached: the API server rejects bound
  tokens once their pod dies, and caching results would trade that liveness check
  away. If latency ever forces a cache, its TTL must sit far below the token
  lifetime and the trade-off gets documented here.

Single-cluster only, by design. Out-of-cluster callers are out of scope (would need
OIDC federation; not planned).
