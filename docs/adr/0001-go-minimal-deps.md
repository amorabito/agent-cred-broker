# ADR-0001: Go, standard library first

Status: accepted · 2026-07-03

## Context

The broker is a small, security-sensitive HTTP service for Kubernetes: validate a
token, check a policy file, call one upstream REST API, sign and print JSON. Its
dependency tree is part of its attack surface.

## Decision

Go, with a small dependency set:

- `net/http` + stdlib for the server; no web framework.
- `crypto/ed25519` (stdlib) for signing.
- Kubernetes TokenReview via a plain authenticated REST call to the API server
  (`POST /apis/authentication.k8s.io/v1/tokenreviews`) using the in-cluster
  ServiceAccount token and CA — importing all of `client-go` to make one POST is not
  worth its dependency graph.
- 1Password Connect via its REST API with `net/http`; no vendor SDK.
- One YAML parser for policy (`gopkg.in/yaml.v3`), one JCS (RFC 8785)
  canonicalization library for audit signatures (`github.com/gowebpki/jcs`), one
  cron-expression parser for issuance windows (`github.com/robfig/cron/v3`). All
  three are small, pinned, dependency-free, and reviewed before adoption.

Single static binary in a distroless image, no shell.

## Alternatives considered

- **TypeScript/Node** — the author's most-used stack, but a broker that ships a
  `node_modules` tree undermines its own story, and cold-start/footprint matter for
  a security chokepoint.
- **Go + client-go / controller-runtime** — right choice the moment this grows CRDs
  or watches; wrong default for two REST calls.

## Consequences

Some things are written by hand that a framework would give away (routing,
middleware, problem+json). That is acceptable and, for this repo's purpose, the
point: the whole service should be readable in one sitting.
