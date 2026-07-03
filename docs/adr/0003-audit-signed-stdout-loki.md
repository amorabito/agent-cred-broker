# ADR-0003: Audit events are Ed25519-signed JSON lines on stdout

Status: accepted · 2026-07-03

## Context

Act-claims are the system's second half: every issuance decision and agent claim
must become a durable, attributable, tamper-evident record that ends up somewhere
queryable (Loki + Grafana). Options: write to stdout and let the cluster's existing
log pipeline (log agent → Loki) carry them; push directly to Loki's HTTP API; or keep
an authoritative local store (SQLite/PVC) and ship copies.

## Decision

**One signed JSON object per line on stdout**, collected by the pipeline the cluster
already runs. Signature: Ed25519 over the RFC 8785 (JCS) canonical form of the event
minus the `sig` field, keyed by `kid`, verifiable offline via `GET /v1/audit/verify-key`
and the in-repo `acb-verify` tool.

Reasons:

- **Zero new infrastructure and zero new write paths.** The pipeline that ships every
  other pod's logs ships these; there is no second delivery mechanism to secure,
  monitor, or explain.
- **Crash-honest ordering.** The broker writes the event before returning the
  secret, so the broker itself never holds an unflushed internal buffer. Durability
  past the process boundary belongs to the pipeline and is lossy (see Consequences).
- **Signature carries the trust, not the transport.** Loki is treated as an untrusted
  store: anyone can *read* events usefully, but only holders of the broker key can
  *mint* them. Verification doesn't depend on how the bytes traveled.

Ed25519 over JWS/JWT because events need exactly one signer, no negotiation, no
header games; a fixed algorithm removes the entire `alg`-confusion class. JCS because
signed JSON needs *some* canonical form and RFC 8785 is small enough to re-implement
in the verifier if the library ever bit-rots. Audit writes are serialized in-process,
one atomic line per event, so concurrent leases cannot interleave bytes into
unverifiable JSON.

## Alternatives considered

- **Direct Loki push** — gains delivery confirmation, costs a second network
  dependency in the issuance path and a Loki outage becoming a secrets outage (or
  silent audit loss, choose one). Rejected for the MVP.
- **Authoritative SQLite + shipped copies** — real durability win (survives Loki
  retention), real cost (state, backup, compaction). Deferred; the envelope's `seq`
  field and off-cluster archival are the designated path when this matters.

## Consequences

- Durability inherits Loki's retention (days–weeks in the target deployment) —
  accepted and documented in threat model §5.6.
- Delivery is at-least-once-ish with no confirmation: a dead log agent drops events
  silently. Mitigation: `broker.seq` gap detection in the Grafana dashboard.
- The private key is generated at install and persisted in a Kubernetes Secret in
  the broker's namespace — a pod-local key would not survive restarts — which places
  Secret-readers in that namespace inside the audit trust boundary (threat model,
  asset 4).
- `GET /v1/audit/verify-key` is a distribution convenience, not the trust anchor:
  the active public key's fingerprint is pinned in the chart values (Git), and
  `broker.started` announces the active `kid` and public key, so an
  attacker-introduced key shows up as a mismatch against deploy history. Rotation
  publishes new keys alongside old ones so history stays verifiable.
