# Threat model

This document describes what `agent-cred-broker` defends against, what it does not,
and why the residual risk is acceptable for its intended deployment: a
single-operator Kubernetes cluster running a handful of autonomous AI agents.

The "Explicit non-goals" section is the most important part of this document.

## 1. System overview

```
 ┌───────────────────────────────────────────────────────────────────────┐
 │ Kubernetes cluster                                                     │
 │                                                                        │
 │  ┌─────────────┐  bound SA token:      ┌───────────────────┐          │
 │  │  agent pod  │  POST /v1/leases      │ agent-cred-broker │  bearer: │
 │  │ (per-agent  │ ────────────────────▶ │                   │  GET item│
 │  │  SvcAcct)   │ ◀──────────────────── │   policy.yaml     │ ────────────▶ 1Password
 │  │             │  scoped secret,       │   Ed25519 signer  │          │    Connect API
 │  │             │  TTL lease            │                   │          │
 │  │             │ ────────────────────▶ │                   │          │
 │  └─────────────┘  POST /v1/claims      └─────────┬─────────┘          │
 │                                                  │ signed act-claims  │
 │                                                  │ (JSON lines,       │
 │                                                  ▼  stdout)           │
 │                                        log shipper ─▶ Loki ─▶ Grafana │
 └───────────────────────────────────────────────────────────────────────┘
```

The broker is the only workload holding a 1Password Connect token. Agents hold nothing
long-lived: they authenticate to the broker with their Kubernetes ServiceAccount
identity (a short-lived, audience-bound projected token) and receive secrets scoped and
TTL-boxed by a static policy file. Every issuance decision and every agent-submitted
claim is emitted as a signed, structured audit event ("act-claim").

### Trust boundaries

| # | Boundary | Crossing mechanism |
|---|----------|--------------------|
| B1 | Agent pod → broker | HTTPS + bound ServiceAccount token (audience `agent-cred-broker`), validated via TokenReview |
| B2 | Broker → 1Password Connect | HTTP(S) + Connect bearer token (the one long-lived credential in the system) |
| B3 | Broker → audit pipeline | JSON lines on stdout, collected by the cluster log shipper into Loki |
| B4 | Operator → broker | Helm values + policy ConfigMap (GitOps), no runtime admin API |

## 2. Assets

Ranked by impact if compromised:

1. **The broker's 1Password Connect token** — grants read access to every item the
   Connect token's vault grant allows. Compromise ≈ compromise of all brokered secrets.
2. **Brokered secret values in flight and at the agent** — individual credentials
   (API tokens, PATs) after disclosure to an agent.
3. **Audit log integrity** — the act-claim stream in Loki. Worthless if forgeable;
   this is what the signing key protects.
4. **The audit signing key** — Ed25519 private key, generated at install, persisted
   in a Kubernetes Secret in the broker's namespace, mounted only by the broker.
   Secret-readers in that namespace are inside the audit trust boundary.
5. **Policy** — the subject→grant mapping. An attacker who can edit policy can grant
   themselves any scope (but policy lives in Git and syncs via GitOps, so this reduces
   to "attacker with write access to the cluster or the Git repo").

## 3. Actors

- **A1 — Legitimate agent**: an autonomous LLM-driven workload (e.g. a nightly PR
  reviewer) doing what it was deployed to do.
- **A2 — Prompt-injected agent**: the same workload, steered by adversarial content it
  ingested (a malicious PR description, issue body, or web page). Same credentials,
  same identity, attacker-chosen behavior.
- **A3 — Compromised co-tenant workload**: some other pod in the cluster (no grant in
  policy) attempting to obtain secrets.
- **A4 — Compromised agent pod**: full code execution inside a pod that *does* have
  grants — the attacker inherits the agent's identity.
- **A5 — Network attacker**: on-path within the cluster network (implies node or CNI
  compromise).
- **A6 — Cluster administrator / node root / etcd access**: effectively the platform
  itself.

## 4. Threats and mitigations

| Threat | Actor | Mitigation | Class |
|--------|-------|------------|-------|
| Steal a long-lived vault-wide token from an agent pod's env or filesystem | A3, A4 | **Structural fix — the core point of the project.** Agents no longer hold any 1Password token. The only 1P token lives in the broker pod. | prevented |
| Ungranted workload requests a secret | A3 | TokenReview-verified identity checked against policy; default deny. Denials emit signed `lease.denied` events. | prevented + detected |
| Workload replays a captured broker token elsewhere | A3 | ServiceAccount tokens are audience-bound to the broker (`aud: agent-cred-broker`); useless against the Kubernetes API or any other service. | prevented |
| Exfiltrated bound token replayed *to the broker* within its lifetime | A3, A4 | Bounded, not prevented: the projected token is a bearer credential on the pod filesystem. Audience binding limits it to the broker; `expirationSeconds` (≈10 min) caps the window; every lease taken in that window is attributed and logged, and an unexpected source pod/IP in the events is the detection hook. | bounded + detected |
| Agent requests a scope it holds no grant for (confused deputy, prompt-injected "try everything") | A2 | Policy is per-subject allowlist; the blast radius of an injected agent is exactly its granted scopes, no more. | bounded |
| Agent uses its *legitimate* grants for attacker-chosen ends | A2 | **Not prevented** (see non-goals). Bounded by scope TTLs and issuance windows (e.g. a nightly agent's scope is only issuable in a window around its schedule); made *investigable* by signed lease + claim trail. | detected |
| Secret disclosure outside expected hours / volume | A2, A4 | Issuance windows and TTL caps in policy; lease events in Loki make "credential issued at 3am" a dashboard query. | detected |
| Forged or backdated audit events | A3, A4 | Events are Ed25519-signed by the broker at write time; forging one requires the signing key, i.e. Secret access in the broker's namespace (asset 4). | prevented |
| Event-lookalike content injected via asserted strings (log forging, query spoofing) | A2, A4 | Events are single-line, fully JSON-escaped (enforced by test), so no caller byte can start a new event. Residual: `asserted` content can still contain lookalike *text*, so consumers must match parsed JSON fields, never raw substrings. | bounded |
| Audit flooding: junk claims/leases bury real events or accelerate Loki retention washout | A2, A4 | Per-subject rate limits on `/v1/leases` and `/v1/claims`, per-subject daily claim-bytes cap in policy, dashboard alert on claim-rate anomalies. Residual: a patient attacker inside the limits still adds noise. | bounded + detected |
| Grant added by editing the live policy ConfigMap (bypassing Git, racing GitOps self-heal) | A6 | Detection, not prevention: every reload emits a signed `policy.reloaded` event with old/new hashes, and every lease event pins the `policy_hash` that authorized it. | detected |
| Tampering with stored audit events | A5, A6 | Signatures make *modification* detectable on verification. **Deletion is silent** — see non-goals. | partial |
| Sniff secrets in transit agent↔broker | A5 | TLS on the broker listener (chart-generated or cert-manager issued). | prevented |
| Broker impersonation (rogue pod claims to be the broker) | A3 | TLS server cert + agents pin the chart-provisioned CA. | prevented |
| DoS the broker so agents can't get credentials | A3 | Fail-closed by design: agents without credentials stop acting. Availability is explicitly sacrificed for containment. | accepted |

## 5. Explicit non-goals

Things this system does **not** defend against. Each is a deliberate scoping decision,
not an oversight.

1. **Post-disclosure exfiltration of static secrets.** The MVP brokers *static*
   secrets (PATs, API keys) held in 1Password. Once a value is disclosed, the lease
   TTL is a contract and an audit construct — **not revocation**. An agent (or its
   attacker) can copy the value and use it after expiry. What the TTL buys: a defined
   window to compare against upstream provider audit logs (use outside the lease
   window is a detectable anomaly rather than background noise). True short-lived
   credentials require providers that mint them (GitHub App installation tokens,
   Kubernetes TokenRequest, cloud STS); the provider interface is designed for that,
   and the MVP does not implement it.
2. **A compromised broker.** The broker concentrates risk by design: one Connect
   token in one hardened pod (distroless image, no shell, default-deny NetworkPolicy,
   RBAC limited to TokenReview creation) instead of N copies in N agent-reachable
   pods. If the broker itself is compromised, all brokered secrets are exposed. The
   claim is *reduced attack surface*, not invulnerability.
3. **Prompt injection as such.** The broker cannot tell a legitimate request from an
   injected one made by the same identity within the same grants. It bounds what an
   injected agent can *obtain* and records what it *did*; it does not judge intent.
   Defenses against injection itself (input sanitization, tool allowlists, human
   gates) live in the agent harness, not here.
4. **Lying agents.** Act-claims submitted by agents (`POST /v1/claims`) are
   **self-reported**. The broker's signature attests "identity X submitted this claim
   at time T" — it does not verify the claim is true. An agent that says it is
   reviewing a PR while doing something else produces a signed record of its lie,
   which has forensic value, but nothing prevents the lie. Verifying claims against
   observed side effects (provider audit logs, k8s audit events) is future work and
   will be labeled as such.
5. **The platform.** A cluster admin, node root, or anyone with etcd access can read
   any Kubernetes Secret, snapshot the broker's memory, or take the Connect token
   directly. A single-operator homelab cannot meaningfully defend against its own
   operator, and does not try. (Corollary: this design assumes the GitOps repo is
   trusted — policy comes from it.)
6. **Audit log deletion and retention.** Loki retention here is short (days–weeks)
   and cluster-local. Signatures make tampering *detectable*, but an attacker with
   write access to Loki storage can delete events silently, and events age out on
   their own. Off-cluster export/archival of act-claims is future work.
7. **Secrets that bypass the broker.** Kubernetes Secrets materialized by other means
   (e.g. a secrets operator syncing items directly into namespaces) are an
   independent, unchanged path. The broker covers *agent-fetched* credentials only.
   An inventory of which secrets moved behind the broker and which did not belongs in
   the deployment's own documentation.
8. **High availability.** Single replica, fail-closed. If the broker is down, agents
   don't get credentials and their runs fail. For nightly batch agents that is an
   acceptable and even desirable failure mode; for anything latency- or
   uptime-critical it would not be.

## 6. Known weaknesses accepted in the MVP

Sharper-edged than non-goals: these are gaps I expect to close, listed so nobody
mistakes them for solved.

- **Identity granularity is the pod, not the process.** If two processes share a pod
  (or a pod runs a whole dev environment), they share a ServiceAccount and are
  indistinguishable to the broker. Converting an agent to the broker properly means
  giving it its own workload (Job/CronJob) and ServiceAccount first.
- **No anomaly response in the broker.** Rate limits are static per-subject token
  buckets; nothing adapts to abnormal-but-within-limits behavior. Detection beyond
  the static limits is delegated to dashboards over the audit stream.
- **Connect token rotation is manual.** The broker's own credential is rotated by the
  operator; the broker does not (cannot) rotate it itself.
- **No hash chaining between events.** Each event is independently signed and
  carries a per-instance sequence number (`broker.seq`), so deleting events from the
  middle of an instance's run leaves a visible gap. Deleting the tail of a run, or
  whole runs across restarts, leaves no gap evidence; full hash chaining across
  restarts is not in the MVP.

## 7. Why this is still worth building

Before: several autonomous agents, each holding (a) a vault-wide secrets-manager
token resident in pod env, (b) long-lived provider tokens (Git PATs, model-provider
OAuth tokens), with no per-agent attribution — every agent's secret reads look
identical in the vault's audit log, and nothing records *why* a credential was in use
at a given moment.

After: agents hold only their platform identity. Secret access is per-agent,
allowlisted, TTL-boxed, time-windowed, and every issuance and claim is a signed,
queryable event. The count of long-lived credentials *resident in agent-reachable
pods* drops to zero; one Connect token remains, in a pod that runs no agent code.
The brokered secrets themselves stay long-lived at their providers until rotated
(§5.1) — what changed is where they live and what gets recorded.

None of that stops a determined attacker with platform access. All of it turns
"an agent did something with some credential at some point" into an answerable
question — which, for autonomous agents acting on production infrastructure, is the
difference between operating blind and operating with a flight recorder.
