# ADR-0006: ha-notify-proxy — a workload-identity-gated capability narrower

Status: accepted · 2026-07-06

## Context

Two agents (alert-triage, house-hunt-digest) need to send phone notifications through
Home Assistant. Today they lease `ha-notify-token` — HA's real long-lived access token
— from the broker as a `static-disclosure` scope, then call HA directly. That token is
**all-or-nothing**: HA has no token scoping. Verified against current (2026) sources —
HA's permission model is *entity-only* ("limited to just entities"; read/control/edit on
entity_ids/domains/areas), it does **not** gate service calls at all, tokens inherit the
full permissions of their user, and there is no admin lever, add-on, or integration that
mints a "notify-only" token. (The HA community's own workaround for this exact wall is a
proxy, e.g. Varco.) So the token that lets you send a push also unlocks the front door
lock, reads all state/history, and calls any service.

The whole capability the two agents actually use is **three REST calls**:

1. `POST /api/services/notify/{mobile_app_service}` — phone push (both).
2. `POST /api/services/persistent_notification/create` — (alert-triage).
3. `POST /api/services/persistent_notification/dismiss` — (alert-triage).

Handing a general-purpose LLM agent — one that runs `claude -p` over attacker-influenceable
content (alert text, house listings) — the ability to obtain HA's god-token to make three
notify calls is the worst credential exposure in the system.

## Decision

Build **ha-notify-proxy**: a small, single-purpose service in the `ha` namespace that
exposes exactly those three notify actions and nothing else. Agents authenticate to it
with their **own bound k8s ServiceAccount token** (audience `ha-notify-proxy`, verified
via TokenReview — the broker's `authn.Reviewer` reused verbatim). The agent holds **no
HA credential at all** — only its own short-lived, cluster-only workload identity, which
it uses to *ask* the proxy to notify. This is the capability-not-credential model: a
capability gated by workload identity, holding no exportable secret.

The proxy does **not** hold the HA token at rest. On each request it **leases
`ha-notify-token` from the existing broker** using its own bound SA identity, makes the
one HA call, and drops the token. So:

- The broker stays the **sole holder-at-rest** of the HA token (its read-only Agent Broker
  vault, unchanged). No second resident copy anywhere. The token exists outside the vault
  only in the proxy's process memory for the milliseconds of one lease→call→drop — never
  on disk, never logged, never an env var.
- The broker keeps its cleanest invariant: it still only **leases and signs**, and never
  makes outbound application calls. The acting-verb lives in a separate pod with a separate
  SA, ClusterRole (TokenReview-create only), and signing key.

Authorization is a deny-by-default policy ConfigMap mapping each caller SA to the
notification **kinds** and **targets** it may use (`push` → allowed mobile_app service
names; `persistent_create`/`persistent_dismiss` → an allowed `notification_id` prefix).
On top of policy, the proxy **binary** hard-codes a compiled allowlist of the only two HA
domains it can address (`notify`, `persistent_notification`) and, for persistent, the only
two services (`create`, `dismiss`); the upstream URL is built from these validated
components, never from caller strings. So the three-verb ceiling is enforced by the binary,
not just by a mutable ConfigMap — a config typo or a widened ConfigMap can never make the
proxy call `lock.unlock`. Push `data` keys are allowlisted to `{group, tag, url}` and any
other key is rejected, so an injected model can't smuggle an HA *actionable*-notification
payload (which can trigger service calls).

Every request emits a proxy-signed act-claim to stdout → Loki: `notify.forwarded`
(attested: the TokenReview-established caller identity, HA domain/service, HA status,
delivered bool, and the broker `lease_id`) or `notify.denied` (policy/rate-limit refusals).
The broker separately emits its usual `lease.issued` for `ha-notify-token` with subject
`ha/ha-notify-proxy` and the originating agent + action in context. The two signed streams
join on `lease_id`.

## Alternatives considered

- **A — proxy holds the HA token at rest** (mounted from a new OnePasswordItem). Nearly
  identical and equally strong on "agent holds zero HA credential," but it plants a
  *second* at-rest copy of the god-token in a second always-on pod, and forks a second
  policy engine + signing key + secret to custody. D keeps the token solely in the broker
  and only touches it in per-request memory — strictly better custody at no extra reuse
  cost. A is the deliberate runner-up.
- **B — a broker action-endpoint** (`POST /v1/actions`, a third `proxied-capability`
  semantics). Lowest new surface and a single clean signed stream — genuinely tempting.
  Rejected because it destroys the broker's most legible property: today `Provider.Fetch`
  *returns* a secret and the broker never *acts*. B would make the broker hold+use a third
  god-credential and issue outbound calls into `ha`, adding an SSRF/confused-deputy surface
  and a new egress edge to the single highest-value pod (the one holding the Connect token
  + GitHub App key), plus a scope-creep precedent toward "authenticated egress gateway."
  For a portfolio whose thesis is a minimal, single-purpose broker, keeping it pure is
  worth more than saving one service. (B's compiled-allowlist discipline is grafted into D.)
- **C — HA-side integration / webhook.** This cluster runs bare-container HA with no
  Supervisor, so add-ons are impossible; the buildable form is a custom integration exposing
  a webhook. Rejected: the agent would hold a `webhook_id` — a long-lived, non-expiring,
  non-revocable URL-secret (worse than a static token on the revocation axis, and
  possession-of-URL is not identity), and HA is not in the act-claim fleet so the action
  loses signed attestation.

## Consequences

- **The agent holds zero HA credential.** After migration, `grep HA_TOKEN` in either agent
  returns nothing; the agent presents only its own audience-bound SA token.
- **Blast radius under agent compromise collapses** from "full HA control incl. the front
  door lock" to "send one push / the three notify actions on allowlisted targets." Enforced
  by the *absence* of any other code path in the proxy — the agent's identity can no longer
  even lease the HA token (that grant moves to `ha/ha-notify-proxy`).
- **Notifications become attested for the first time** — a signed, offline-verifiable record
  of which agent caused which push and whether HA accepted it, replacing today's self-reported
  claim.

Honest limits, named (this is the brand — a blast-radius **move**, not elimination):

- **Contains who, not what.** The HA token is still the all-or-nothing god-token. A
  code-exec compromise of the *proxy* (or the broker) still yields full HA. HA offers no
  scoped token, so no design eliminates that. D's win is moving the token out of two
  LLM-driven, free-text-ingesting agent pods into one no-LLM, structured-JSON-only,
  distroless-nonroot, read-only-rootfs, default-deny pod, and shrinking its at-rest window
  to per-request memory.
- **Two-stream audit seam.** Provenance is two signed streams under two keys (broker
  `lease.issued` + proxy `notify.forwarded`), correlated by `lease_id` — verifiable, but
  not a single signature. B's single stream is cleaner on this one axis; D accepts the seam
  to keep the broker pure.
- **Best-effort audit, not fail-closed — for the *forwarded* event only.** Every *refusal*
  (auth failure, rate-limit, policy denial, malformed body) is a signed event emitted
  *before* any HA call — so an authenticated-but-rejected request is never a quieter probe
  than an authorized one, and a throttled flood (the exact signal the rate limiter exists to
  catch) still leaves a signed footprint (aggregated, so the throttle path is not itself a
  flood vector). Only the post-call `notify.forwarded` is best-effort: unlike the broker's
  `lease.issued` (which gates a secret disclosure and so fails closed), the proxy sends the
  notification and emits `notify.forwarded` *after* the HA call — a crash in that tail window
  sends the push without a record. A notification is not a secret; refusing to alert because
  the audit pipe is down is the wrong failure. Disclosed, not hidden.
- **The `data`-key allowlist is enforcement only if maintained.** HA actionable-notification
  `data` can trigger service calls, so "just a push" is not fully inert; the `{group,tag,url}`
  allowlist is a small hand-maintained list, and widening it wrongly re-opens a control path.
- **A new fail-closed dependency.** Every push now needs proxy-up + its TokenReview +
  broker-up + lease-succeeds. Correct for batch agents (fail-closed), but two single-replica
  services must both be healthy for a full agent run. Readiness (not a token-expiry gauge —
  HA LLATs have no `exp`) is the alarm signal.

Neither the proxy nor the broker will accept further proxied capabilities without an explicit
re-evaluation. The proxy is HA-notify-shaped **on purpose**; it is not a general egress gateway.
