# ADR-0004: Leases over static secrets are disclosure records, and the API says so

Status: accepted · 2026-07-03

## Context

The MVP fronts 1Password Connect, which stores **static** secrets — PATs, API keys,
passwords. A "lease with a TTL" over a static secret cannot revoke anything: once
disclosed, the value works until rotated at the source. Vault-style systems solve
this with dynamic secrets engines; several commercial products solve it with
marketing.

The tempting move is to present leases as if expiry were enforcement. The failure
mode is an operator believing containment exists where only bookkeeping does.

## Decision

Name the semantics in the API itself. Every lease response carries:

```json
"semantics": "static-disclosure"
```

meaning: *the secret was disclosed at `issued_at`; `expires_at` is the window the
subject is contracted to use it within; nothing revokes it.* The reserved value
`revocable` exists for future dynamic providers and is issued by nothing in the MVP.

What TTLs and issuance windows on static secrets *do* buy — and why leases exist
anyway:

1. **Issuance-time enforcement is real.** Outside a grant's `issueWindows`, or beyond
   `ttlMax`, disclosure simply doesn't happen. For a nightly agent, "this PAT is
   only obtainable for 45 minutes a day" is a true statement about the system.
2. **Anomaly detection gets a baseline.** Provider-side audit logs (e.g. GitHub's)
   can be compared against lease windows; use outside any lease window is a
   high-signal alert instead of noise.
3. **Attribution.** Which agent held which credential when becomes a single query.

## Alternatives considered

- **Only broker dynamic secrets** ("if it can't revoke, don't ship it") — would mean
  shipping nothing, since the real workloads' credentials are static PATs and OAuth
  tokens today. The perfect revocation story would kill the actual risk reduction
  available now (getting the vault-wide token out of agent pods).
- **Present TTLs without qualification** — the industry default; rejected as the
  exact dishonesty this project is positioned against.

## Consequences

- The `semantics` field costs a few bytes and makes the limitation machine-readable
  instead of buried in documentation.
- Dynamic providers (GitHub App installation tokens first — they make the PR
  reviewer's Git credential *actually* short-lived) have a designed slot: implement
  the provider interface, return `revocable`, change no API shape.
