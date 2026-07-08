// Command acb-playground fakes the broker's two upstreams — the Kubernetes
// TokenReview API and 1Password Connect — so the quickstart
// (docs/quickstart.md) runs on a laptop with no cluster and no vault.
//
// It is deliberately a TOY. The real broker trusts the API server's
// cryptographic verdict on bound ServiceAccount tokens; the playground
// trusts the presented string outright ("<namespace>/<serviceaccount>") so
// you can play both sides of the identity boundary from one terminal. The
// fake Connect hands out an obviously fake secret for any vault/item ref.
// Neither fake is reachable from any production code path.
package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	addr := env("PLAYGROUND_ADDR", ":8181")
	mux := http.NewServeMux()
	mux.HandleFunc("POST /apis/authentication.k8s.io/v1/tokenreviews", tokenReview)
	mux.HandleFunc("GET /v1/vaults", listVaults)
	mux.HandleFunc("GET /v1/vaults/{vault}/items/{item}", getItem)

	// Bind BEFORE announcing: a bind failure after a "listening" banner reads
	// as success to anyone skimming a second terminal.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("bind %s: %v (port busy? set PLAYGROUND_ADDR to a free port and point ACB_CONNECT_URL/ACB_KUBE_API at it)", addr, err)
	}
	log.Printf("acb-playground listening on %s", addr)
	log.Printf("  fake TokenReview:  POST http://127.0.0.1%s/apis/authentication.k8s.io/v1/tokenreviews", addr)
	log.Printf("  fake 1P Connect:   GET  http://127.0.0.1%s/v1/vaults/{vault}/items/{item}", addr)
	log.Printf(`  playground "bound tokens" are just <namespace>/<serviceaccount>, e.g. agents/demo-agent`)

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.Serve(ln))
}

// tokenReview authenticates any token of the form <namespace>/<serviceaccount>
// and echoes the requested audiences back as satisfied. This is the toy part:
// a real API server verifies the token's signature, binding, expiry, and
// audience; here the string IS the identity so you can impersonate anyone.
func tokenReview(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Spec struct {
			Token     string   `json:"token"`
			Audiences []string `json:"audiences"`
		} `json:"spec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad tokenreview body", http.StatusBadRequest)
		return
	}
	ns, sa, ok := strings.Cut(strings.TrimSpace(req.Spec.Token), "/")
	status := map[string]any{"authenticated": false, "error": "playground tokens look like <namespace>/<serviceaccount>"}
	if ok && ns != "" && sa != "" && !strings.Contains(sa, "/") {
		status = map[string]any{
			"authenticated": true,
			"audiences":     req.Spec.Audiences,
			"user": map[string]any{
				"username": "system:serviceaccount:" + ns + ":" + sa,
				"extra": map[string][]string{
					"authentication.kubernetes.io/pod-name": {sa + "-playground-0"},
					"authentication.kubernetes.io/pod-uid":  {"00000000-feed-face-0000-000000000000"},
				},
			},
		}
		log.Printf("tokenreview: %q -> system:serviceaccount:%s:%s", req.Spec.Token, ns, sa)
	} else {
		log.Printf("tokenreview: %q -> REJECTED (not <ns>/<sa>)", req.Spec.Token)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenReview",
		"status":     status,
	})
}

// listVaults satisfies the broker's authenticated readiness probe.
func listVaults(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte("[]"))
}

// getItem returns the same shape a real Connect item has, with a value that
// could never be mistaken for a real secret.
func getItem(w http.ResponseWriter, r *http.Request) {
	item := r.PathValue("item")
	suffix := item
	if len(suffix) > 6 {
		suffix = suffix[:6]
	}
	log.Printf("connect: item %s/%s fetched", r.PathValue("vault"), item)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"fields": []map[string]string{
			{"id": "f1", "label": "credential", "value": "playground-secret-" + suffix},
			{"id": "f2", "label": "password", "value": "playground-password-" + suffix},
		},
	})
}
