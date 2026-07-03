package server

import (
	"encoding/json"
	"net/http"
)

// errBase is the namespace for problem types (RFC 7807).
const errBase = "https://agent-cred-broker.dev/errors/"

// Problem types. grant-denied deliberately covers both unknown-scope and
// ungranted-scope: a distinct not-found response would hand authenticated
// callers a scope-name enumeration oracle. The signed lease.denied event
// carries the real reason.
const (
	ProblemUnauthenticated = errBase + "unauthenticated"
	ProblemGrantDenied     = errBase + "grant-denied"
	ProblemOutsideWindow   = errBase + "outside-issue-window"
	ProblemLeaseNotFound   = errBase + "lease-not-found"
	ProblemLeaseForbidden  = errBase + "lease-forbidden"
	ProblemLeaseConflict   = errBase + "lease-conflict"
	ProblemBadRequest      = errBase + "bad-request"
	ProblemRateLimited     = errBase + "rate-limited"
	ProblemProviderFailure = errBase + "provider-failure"
)

type problem struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Detail    string `json:"detail,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

func writeProblem(w http.ResponseWriter, status int, typ, title, detail, requestID string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problem{
		Type: typ, Title: title, Status: status, Detail: detail, RequestID: requestID,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
