# API specification — v1

Status: **draft, pre-implementation**. This spec is written before the code on
purpose; the implementation will conform to it or the spec will be amended in the
same commit that diverges.

## Concepts

| Term | Meaning |
|------|---------|
| **subject** | An authenticated caller identity: a Kubernetes ServiceAccount, expressed as `<namespace>/<serviceaccount>`. |
| **scope** | A named, brokerable credential (e.g. `github-bot-pat`). Maps to a provider reference in policy. Scopes are the unit of granting. |
| **grant** | A policy entry allowing a subject to lease a scope, with TTL caps and optional issuance windows. |
| **lease** | One issuance of a scope's secret material to a subject: an ID, a validity window, and an audit trail. For static secrets the window is a contract, not revocation — see [threat model §5.1](threat-model.md). |
| **act-claim** | A signed audit event. Broker-attested events (`lease.*`, `policy.*`, `auth.*`, `broker.*`) record what the broker did and observed; agent-asserted claims (`claim.recorded`) record what an agent *says* it is doing. The signature proves origin and time of recording, never the truth of asserted content. |
| **provider** | A backend that produces secret material for a scope. MVP: `onepassword-connect` (static secrets). The interface admits dynamic providers (GitHub App installation tokens, Kubernetes TokenRequest) later. |

## Authentication

Every request (except health/metrics) carries a **bound ServiceAccount token**:

```
Authorization: Bearer <projected SA token, audience=agent-cred-broker>
```

Agents obtain it from a projected volume:

```yaml
volumes:
  - name: broker-token
    projected:
      sources:
        - serviceAccountToken:
            audience: agent-cred-broker
            expirationSeconds: 600
            path: token
```

The broker validates tokens with the Kubernetes `TokenReview` API: it sends
`spec.audiences: ["agent-cred-broker"]` and accepts only responses whose
`status.audiences` includes that audience. The subject is derived from the
TokenReview response — `status.user.username`
(`system:serviceaccount:<namespace>:<name>`) plus
`status.user.extra["authentication.kubernetes.io/pod-name"]` / `pod-uid` when
present. Audience binding makes a stolen token useless against the API server or any
other service; the short expiry bounds replay against the broker itself. TokenReview
results are not cached: the API server rejects a bound token once its pod dies, and a
cache would trade that liveness check away.

The broker's own RBAC: a dedicated ClusterRole granting only `create` on
`tokenreviews.authentication.k8s.io`. It cannot read Secrets, pods, or anything else
in the cluster.

Transport is HTTPS only. The server certificate is chart-provisioned (or
cert-manager-issued); clients pin the CA bundle the chart publishes in a ConfigMap.

## Common behavior

- Content type: `application/json` both ways.
- Errors: RFC 7807 `application/problem+json`, e.g.

```json
{
  "type": "https://agent-cred-broker.dev/errors/grant-denied",
  "title": "no grant for scope",
  "status": 403,
  "detail": "subject agents/pr-reviewer holds no grant for scope 'prod-db-password'",
  "request_id": "req_01HZXW..."
}
```

- Every response carries `X-Request-Id`; the same ID appears in emitted audit events.
- Denials are not silent: authorization failures emit signed `lease.denied` events,
  and authentication failures emit aggregated `auth.failed` events.
- Per-subject rate limits (token bucket) apply to `/v1/leases` and `/v1/claims`;
  policy may set a per-subject daily claim-bytes cap. Exceeding either returns `429`.
  This exists to keep a compromised agent from flooding the audit stream to bury its
  own records (see threat model §4).
- Responses containing `secret` are sent with `Cache-Control: no-store`. The broker
  never logs request or response bodies, and the chart must not place a body-logging
  proxy in front of `/v1/leases`.

## Endpoints

### POST /v1/leases

Request issuance of a scope's secret.

Request:

```json
{
  "scope": "github-bot-pat",
  "ttl_seconds": 900,
  "context": {
    "run_id": "nightly-2026-07-03",
    "reason": "review dependency-update PRs"
  }
}
```

- `scope` (required) — must exist in policy and be granted to the caller.
- `ttl_seconds` (optional) — clamped to the grant's `ttlMax`; defaults to `ttlDefault`.
- `context` (optional, ≤ 4 KiB) — free-form strings copied verbatim into the audit
  event as **asserted** content.

Response `201`:

```json
{
  "lease_id": "lease_01HZXW9K...",
  "scope": "github-bot-pat",
  "issued_at": "2026-07-03T12:00:02Z",
  "expires_at": "2026-07-03T12:15:02Z",
  "renewable": true,
  "secret": {
    "token": "<value>"
  },
  "semantics": "static-disclosure"
}
```

- `secret` — field names come from the scope's provider mapping. **Returned exactly
  once**; no endpoint re-discloses it. Lose it, lease again (audited).
- `semantics` — `static-disclosure` (TTL is contractual) or `revocable` (reserved for
  dynamic providers).

Errors: `403` for unknown scope, ungranted scope, or outside issuance window.
Unknown and ungranted are deliberately indistinguishable to the caller — a `404`
would hand authenticated callers a scope-name enumeration oracle; the signed
`lease.denied` event carries the real reason. Window denials use a distinct
`problem.type` (the caller already holds the grant, so nothing is disclosed). `502`
provider failure (fail closed, no partial secrets).

Emits: `lease.issued` or `lease.denied`.

### POST /v1/leases/{lease_id}/renew

Extend a renewable lease before expiry. Does **not** re-disclose the secret; it
extends the contractual window and the audit trail.

Request: `{"ttl_seconds": 900}` (optional, same clamping).
Response `200`: lease metadata (as above, minus `secret`).
Errors: `403` not caller's lease, `409` expired or non-renewable.
Emits: `lease.renewed`.

### DELETE /v1/leases/{lease_id}

Surrender a lease early. For static secrets this is purely an audit marker ("agent
declares it is done with the credential") — it revokes nothing.

Response `204`. Emits: `lease.surrendered`.

### GET /v1/leases/{lease_id}

Lease metadata (never the secret). Callers can read only their own leases.

### POST /v1/claims

Attach agent-asserted act-claims to the audit stream — the "what I am doing and why"
record accompanying credential use.

Request:

```json
{
  "lease_id": "lease_01HZXW9K...",
  "claims": [
    {
      "action": "gh.pr.merge",
      "target": "example-org/example-repo#4123",
      "reason": "risk=LOW per review rubric",
      "ts": "2026-07-03T12:07:41Z"
    }
  ]
}
```

- `lease_id` (optional) — if present, must belong to the caller; links the claim to a
  disclosure.
- `claims[]` — 1–50 entries, each ≤ 2 KiB. `action`/`target`/`reason` are
  conventions, not enforced vocabulary; the broker stores them opaquely.

Response `202` with `claim_ids`. Emits one `claim.recorded` event per claim, marked
**asserted** — the broker signs that the claim was received, not that it is true
([threat model §5.4](threat-model.md)).

### GET /v1/whoami

Echo the authenticated subject and its grants (names + TTL caps, no provider refs).
Exists for debugging agent wiring; also the smallest end-to-end auth test.

### GET /v1/audit/verify-key

Public verification material: `{"keys": [{"kid": "2026-07-a", "alg": "Ed25519", "public_key": "<base64>"}]}`.
Old keys remain listed after rotation so historical events stay verifiable.

This endpoint is a distribution convenience, **not the trust anchor**: the active
public key's fingerprint is pinned in the chart values (i.e. in Git), and
`broker.started` events announce the active `kid` and public key. A key that appears
here without a matching change in deploy history is itself an anomaly.

### Unauthenticated

`GET /healthz`, `GET /readyz` (readiness = policy loaded + provider reachable),
`GET /metrics` (Prometheus; lease/denial/claim counters by subject and scope, provider
latency — never secret material). Served on a separate port, kept unexposed by the
chart's NetworkPolicy except to scrapers.

## Audit event schema

One JSON object per line on stdout; the cluster log pipeline ships them to Loki.
Common envelope:

```json
{
  "v": 1,
  "kind": "act-claim",
  "type": "lease.issued",
  "ts": "2026-07-03T12:00:02Z",
  "request_id": "req_01HZXW...",
  "broker": { "instance": "agent-cred-broker-6f9b...", "kid": "2026-07-a", "seq": 4127 },
  "subject": { "namespace": "agents", "serviceaccount": "pr-reviewer", "pod": "pr-reviewer-29184760-x7k2m" },
  "source": { "ip": "10.42.0.99", "user_agent": "acb-client/0.1" },
  "attested": { "scope": "github-bot-pat", "lease_id": "lease_01HZXW9K...", "ttl_seconds": 900, "expires_at": "2026-07-03T12:15:02Z", "decision": "issued", "policy_hash": "sha256:9f2c..." },
  "asserted": { "run_id": "nightly-2026-07-03", "reason": "review dependency-update PRs" },
  "sig": "<base64 Ed25519 signature>"
}
```

Rules:

- `attested` holds only broker-observed facts; `asserted` holds only caller-supplied
  content. The split is structural so queries and readers can't confuse the two.
  Every `lease.*` event's `attested` includes the `policy_hash` in effect at decision
  time, pinning each issuance to the exact policy that authorized it.
- Events are serialized with full JSON string escaping and are exactly one line each;
  no caller-supplied byte can introduce a line break or unescaped control character
  (enforced by test). Audit writes are serialized in-process — one atomic line per
  event — so concurrent requests cannot interleave bytes into unverifiable JSON.
- Consumers must match parsed JSON fields (LogQL: `| json | type="lease.denied"`),
  never raw line substrings: `asserted` content is attacker-controlled and can
  contain event-lookalike text.
- `sig` is Ed25519 over the RFC 8785 (JCS) canonicalization of the event with `sig`
  removed. Verification: fetch key by `kid`, canonicalize, verify. A reference
  verifier ships in-repo (`cmd/acb-verify`) and doubles as the audit-integrity check
  in CI.
- `broker.seq` is a per-instance monotonic counter: deleted events leave visible gaps
  within an instance's run. (Not a hash chain; see threat model §6.)
- Event types: `lease.issued`, `lease.denied`, `lease.renewed`, `lease.surrendered`,
  `lease.expired` (emitted by a sweep, best-effort), `claim.recorded`,
  `policy.reloaded` (old hash, new hash, summary of changed subjects/scopes),
  `policy.reload_failed` (previous policy retained), `auth.failed` (aggregated and
  rate-limited; records source and failure reason, never the token), and
  `broker.started` (policy hash + active signing `kid` and public key, so both
  policy state and key introductions are visible in the stream and cross-checkable
  against deploy history).
- Secret values never appear in events, metrics, or error text.

## Policy file

Mounted from a ConfigMap (GitOps-managed), reloaded on change. Deny by default: no
grant, no lease.

```yaml
scopes:
  - name: github-bot-pat
    provider: onepassword-connect
    ref: "vaults/<vault-uuid>/items/<item-uuid>"
    fields:
      token: credential          # lease field -> provider field label
  - name: model-api-token
    provider: onepassword-connect
    ref: "vaults/<vault-uuid>/items/<item-uuid>"
    fields:
      token: password

subjects:
  - serviceAccount: agents/pr-reviewer
    grants:
      - scope: github-bot-pat
        ttlDefault: 15m
        ttlMax: 1h
        renewable: true
        issueWindows:              # optional; absent = any time
          - cron: "55 11 * * *"    # nightly agent: issuable 11:55–12:40 UTC only
            duration: 45m
      - scope: model-api-token
        ttlDefault: 15m
        ttlMax: 1h
```

Issuance windows are one of the few *genuinely enforceable* controls over static
secrets (enforcement happens at issuance, before disclosure), which is why they are
in the MVP while revocation is not.

A scope's `ref` must match the provider's reference format exactly (for
`onepassword-connect`: `^vaults/[a-z0-9]{26}/items/[a-z0-9]{26}$`); anything else
fails validation. Upstream request URLs are built from the parsed components, never
by string concatenation, so a malformed ref cannot redirect the broker's
authenticated request.

Policy validation failures at startup are fatal; a failed reload keeps the previous
policy and emits `policy.reload_failed`. Every successful reload emits
`policy.reloaded` with the old and new hashes — a grant added out-of-band (a live
ConfigMap edit racing GitOps self-heal) is itself a signed, queryable event. A broker
with no valid policy issues nothing.

## Versioning

`/v1` is stable once the MVP tags `v0.1.0`; breaking changes bump the path. The
audit envelope carries its own `v` independent of the API version, since stored
events outlive API revisions.
