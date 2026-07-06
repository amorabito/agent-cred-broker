package notify

import (
	"encoding/json"
	"net/http"
)

// errBase is shared with the broker's problem namespace on purpose: a client
// (an agent) sees one consistent error vocabulary across both services.
const errBase = "https://agent-cred-broker.dev/errors/"

const (
	ProblemUnauthenticated = errBase + "unauthenticated"
	// ProblemGrantDenied covers every policy refusal — no grant, wrong target,
	// wrong notification_id prefix — uniformly, so an authenticated caller
	// can't probe the policy. The signed notify.denied event carries the real
	// reason.
	ProblemGrantDenied = errBase + "grant-denied"
	ProblemBadRequest  = errBase + "bad-request"
	ProblemRateLimited = errBase + "rate-limited"
	// ProblemUpstreamFailure: the request was authorized but the proxy could
	// not complete it (broker lease failed, or HA rejected/was unreachable).
	// HA's own error text is never propagated.
	ProblemUpstreamFailure = errBase + "upstream-failure"
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
	_ = json.NewEncoder(w).Encode(problem{Type: typ, Title: title, Status: status, Detail: detail, RequestID: requestID})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
