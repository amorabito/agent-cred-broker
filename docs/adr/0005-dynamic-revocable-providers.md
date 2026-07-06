# ADR-0005: Revocable dynamic providers, starting with GitHub App installation tokens

Status: accepted · 2026-07-05

## Context

[ADR-0004](0004-static-secret-lease-semantics.md) drew the honest line: a lease over a
1Password item is a *disclosure record*, not revocation. It also reserved a slot —
`"semantics": "revocable"` — for providers that mint credentials the broker can
actually bound in time. This ADR fills that slot.

The motivating workload is the nightly PR-review agent. Its GitHub credential was a
long-lived fine-grained PAT: leaked, it works until someone notices and rotates it by
hand. GitHub Apps solve exactly this — an **installation access token** is minted on
demand, scoped to chosen repositories and permissions, and **hard-expires in ~1 hour**
no matter what. That is the difference between "we wrote down when the secret left the
building" and "the secret dies on its own before you finish reading the alert."

The design question was how to add a fundamentally different *kind* of provider (one
that mints, expires, and could revoke) without splitting the broker into two code paths
or letting a caller widen its own scope.

## Decision

**One provider interface, evolved to carry an upstream expiry.** `Provider.Fetch` now
takes a `Request{Ref, Fields, Params, TTL}` and returns a `Result{Secret, ExpiresAt}`.
Static providers leave `ExpiresAt` zero; revocable providers set it to the
upstream-enforced hard expiry. Nothing else in the request/lease/audit machinery
forks — the handler treats both uniformly.

**The lease is clamped to the credential's real expiry.** When a provider returns a
non-zero `ExpiresAt`, the broker caps the lease so it can never claim to outlive the
token it represents, and records `upstream_expires_at` in the signed `lease.issued`
event. A `revocable` act-claim is therefore *truthful about when the secret dies*, not
just about when it was disclosed.

**Scope is policy-pinned, never caller-supplied.** The GitHub repositories and
permissions live in the scope's `params` (a field in the deny-by-default policy
ConfigMap). A subject names a scope; it cannot ask for `contents=write` on a repo the
policy didn't grant. A permission-less scope is rejected at policy-load time, because a
GitHub token minted with no `permissions` inherits the installation's entire granted
scope — the precise opposite of least privilege.

**The App private key is a second root secret, treated like the first.** It is mounted
from a file (`ACB_GITHUB_APP_KEY_FILE`), never placed in the policy ConfigMap, and used
only to sign the short (≤10-minute) RS256 JWT that authenticates the token exchange. It
joins the Connect token as one of the broker's few long-lived credentials, resident
only in the one hardened pod.

**The provider is optional and fails safe when absent.** It is constructed only if
`ACB_GITHUB_APP_ID` is set. A policy that references `github-app` on a broker without an
App configured denies issuance with `provider-unconfigured` — a visible config gap,
never a silent fallback to a broader credential.

## Alternatives considered

- **A separate `Mint` method / a second handler path.** Rejected: it would duplicate the
  rate-limit, audit-fail-closed, and lease-lifecycle logic and invite the two paths to
  drift. The upstream expiry is the only genuinely new datum; a return field carries it.
- **Let the caller pass repositories/permissions in the lease `context`.** Rejected
  outright — it would let a compromised agent widen its own credential. Scope is
  policy's job; `context` stays purely asserted, forensic content.
- **Pull in a JWT library.** Rejected per [ADR-0001](0001-go-minimal-deps.md): the RS256
  App JWT is a header, a claims set, and one `rsa.SignPKCS1v15` — ~20 lines of stdlib,
  no dependency, and a test verifies the signature the way GitHub would.
- **Active revocation on surrender now.** Deferred (see below), not rejected.

## Consequences

- The PR-review agent's GitHub credential can become genuinely short-lived: minted for
  its run, scoped to the repos it reviews, dead within the hour. That is the first
  "eliminate, not just contain" credential in the system.
- `DELETE /v1/leases/{id}` (surrender) is still only an audit marker. **Active
  revocation** — calling GitHub's `DELETE /installation/token` when a revocable lease is
  surrendered — is the natural next increment, but it requires the broker to hold the
  minted token in memory keyed by lease so it can present it to the revoke endpoint.
  That reintroduces a live-secret-at-rest tradeoff (small, in the one hardened pod, but
  real) and is left as a deliberate, separately-decided step rather than folded in
  silently. Until then, the ~1h hard expiry is the revocation mechanism.
- GitHub reachability is **not** wired into readiness. The provider deliberately
  implements no `Healthy` probe: a GitHub outage must fail an individual mint with
  `502`, not flip the whole broker (including 1Password-backed leases) to unready.
- The interface now admits the next dynamic providers (Kubernetes TokenRequest, cloud
  STS) with no further shape change — they set `ExpiresAt` and return `revocable`.
