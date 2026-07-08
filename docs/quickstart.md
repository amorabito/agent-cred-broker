# Quickstart — ten minutes, no cluster

You'll run the broker on your laptop against fake upstreams, lease a secret with
nothing but an identity, get told no, file an act-claim, and then verify the
signed audit trail offline — including catching a tampered event.

Everything in the broker's real request path runs for real here: the policy
engine, deny-by-default authz, TTL clamps, the lease store, Ed25519-signed audit
events, the offline verifier. What's faked (and how) is spelled out
[at the end](#what-was-real-and-what-was-fake).

Prereqs: Go 1.23+, `curl`. `jq` strongly recommended.

## 1. Build

```sh
git clone https://github.com/amorabito/agent-cred-broker
cd agent-cred-broker
make build
```

## 2. Terminal A — fake upstreams

```sh
./bin/acb-playground
```

This serves a fake Kubernetes TokenReview API and a fake 1Password Connect on
`:8181`. The fake's one rule: a "bound token" is just the string
`<namespace>/<serviceaccount>`, so you can play any identity from your keyboard.
(That's the toy part — in production the API server cryptographically verifies
real bound ServiceAccount tokens and the broker trusts nothing else.)

## 3. Terminal B — the broker

```sh
mkdir -p /tmp/acb && echo playground > /tmp/acb/token

ACB_DEV_INSECURE=1 \
  ACB_POLICY_FILE=examples/quickstart-policy.yaml \
  ACB_CONNECT_URL=http://127.0.0.1:8181 \
  ACB_CONNECT_TOKEN_FILE=/tmp/acb/token \
  ACB_KUBE_API=http://127.0.0.1:8181 \
  ACB_KUBE_TOKEN_FILE=/tmp/acb/token \
  ./bin/broker | tee events.jsonl
```

The broker's stdout **is** its audit stream — one signed JSON event per line
(in production a log shipper sends it to Loki). `tee` keeps a copy you'll
verify in step 7. Two startup notes are expected in dev: a WARNING about an
ephemeral signing key, and "PLAINTEXT … never in production". Those notes go
to stderr, so they stay out of `events.jsonl` — don't merge the streams with
`2>&1`, or log lines will corrupt the audit file for step 7.

The [policy it loaded](../examples/quickstart-policy.yaml) is deny-by-default
and grants exactly one identity (`agents/demo-agent`) exactly one scope
(`demo-secret`).

> Ports `8443`/`8081` busy? Add `ACB_LISTEN_ADDR=:9443 ACB_HEALTH_ADDR=:9081`
> and use `:9443` in the curls below. If `:8181` is busy, start the playground
> with `PLAYGROUND_ADDR=:9181` and point both `ACB_CONNECT_URL` and
> `ACB_KUBE_API` at `http://127.0.0.1:9181`.

## 4. Terminal C — lease a secret with an identity, not a key

```sh
curl -s -H "Authorization: Bearer agents/demo-agent" \
     -H "Content-Type: application/json" \
     -d '{"scope":"demo-secret","ttl_seconds":300,
          "context":{"run_id":"quickstart","reason":"first lease"}}' \
     http://127.0.0.1:8443/v1/leases | jq .
```

```json
{
  "lease_id": "lease_32befc5b0d4f5c746d4c2d87d9",
  "scope": "demo-secret",
  "issued_at": "2026-07-08T15:00:40Z",
  "expires_at": "2026-07-08T15:05:40Z",
  "renewable": true,
  "semantics": "static-disclosure",
  "secret": {
    "token": "playground-secret-demode"
  }
}
```

The caller presented no API key — only an identity. Note
`"semantics": "static-disclosure"`: the broker is telling you, in the response,
that this lease over a static secret is a disclosure record with a TTL
contract, **not** revocation ([ADR-0004](adr/0004-static-secret-lease-semantics.md)).
Where the upstream can mint real short-lived credentials (GitHub App
installation tokens), the semantics become `revocable` — see the README demo.

## 5. Get told no

```sh
curl -s -w '\nHTTP %{http_code}\n' \
     -H "Authorization: Bearer agents/intruder" \
     -H "Content-Type: application/json" \
     -d '{"scope":"demo-secret","ttl_seconds":300}' \
     http://127.0.0.1:8443/v1/leases
```

```
{"type":"https://agent-cred-broker.dev/errors/grant-denied","title":"no grant for scope","status":403,"request_id":"req_13d072695558a661"}
HTTP 403
```

A valid identity with no grant gets a uniform 403 — and, in Terminal B, a
signed `lease.denied` event with the real reason. Refusals are evidence too.

## 6. Say what you did

Agents attach self-reported act-claims to their leases — the "what I'm doing
and why" record alongside the disclosure (use your `lease_id` from step 4):

```sh
curl -s -w '\nHTTP %{http_code}\n' \
     -H "Authorization: Bearer agents/demo-agent" \
     -H "Content-Type: application/json" \
     -d '{"lease_id":"lease_32befc5b0d4f5c746d4c2d87d9",
          "claims":[{"action":"demo.step","target":"quickstart",
                     "reason":"proving the audit loop"}]}' \
     http://127.0.0.1:8443/v1/claims
```

```
{"claim_ids":["claim_4696b961070458add347d4b86f"]}
HTTP 202
```

The broker's signature on the resulting event attests *who said it and when* —
not that it's true. Broker-observed facts and agent-asserted context live in
separate fields, because one of them can lie.

## 7. Verify the flight recorder — offline

Your `events.jsonl` now holds the whole story:

```sh
jq -r .type events.jsonl
```

```
broker.started
lease.issued
lease.denied
claim.recorded
```

The broker published its verify key in its own first event. Extract it and
check every signature and sequence number, no broker required:

```sh
PUB=$(jq -r 'select(.type=="broker.started") | .attested.public_key' events.jsonl)
./bin/acb-verify -pubkey "$PUB" events.jsonl
```

```
events=4 valid=4 invalid=0 seq_gaps=0 duplicate_seqs=0 instances=1
```

Now tamper with history — change one word of the lease's recorded reason:

```sh
sed 's/first lease/totally legit/' events.jsonl > tampered.jsonl
./bin/acb-verify -pubkey "$PUB" tampered.jsonl
```

```
INVALID line 2: signature verification failed
SEQ GAP instance=<your-hostname>: 1 -> 3 (1 missing)
events=4 valid=3 invalid=1 seq_gaps=1 duplicate_seqs=0 instances=1
```

Exit code 1. The signature catches the edit, and because the forged event no
longer counts, the per-instance sequence chain shows a hole where it used to
be. Deleting the line instead of editing it leaves the same gap.

## 8. Change the rules live (optional)

With the broker still running, append a grant for the intruder to
`examples/quickstart-policy.yaml`:

```yaml
  - serviceAccount: agents/intruder
    grants:
      - scope: demo-secret
        ttlDefault: 5m
        ttlMax: 15m
```

Within ~10 seconds Terminal B emits a signed `policy.reloaded` event naming
`subjects_added: ["agents/intruder"]` — and the step-5 curl now returns 201
with a lease of its own.
Policy is data; in production it's a GitOps-managed ConfigMap, and every change
is itself an audit event pinned by hash to the leases it authorized.

## What was real and what was fake

**Real** — the exact code paths production runs: TokenReview-based authn (the
broker holds no verification keys of its own), deny-by-default policy with TTL
clamps and hot reload, the lease store, signed act-claims with fail-closed
disclosure paths, `acb-verify`.

**Fake** — the two upstreams. The playground authenticates the literal string
`<ns>/<sa>` (production sends the presented token to the Kubernetes API server
and trusts only its verdict on real, kubelet-rotated, audience-bound tokens)
and hands out obviously fake secrets (production fronts 1Password Connect and
mints GitHub App installation tokens). TLS is off via a dev flag that refuses
to stay quiet about it.

**Not shown here**: issuance windows (cron-scoped mintability), per-subject
rate limits, `revocable` leases clamped to the upstream token's hard expiry,
the Grafana dashboard over the Loki stream, and the ha-notify-proxy
(capability-not-credential for APIs that can't scope tokens). Those are in the
[README](../README.md), [threat model](threat-model.md), [API spec](api.md),
and [ADRs](adr/).
