package server

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// Metrics is a minimal hand-rolled Prometheus text-exposition registry:
// counters only, no external dependency (ADR-0001). Secret material never
// appears here — labels are subject keys, scope names and event types.
type Metrics struct {
	mu       sync.Mutex
	counters map[string]map[string]float64 // metric name -> rendered labels -> value
	help     map[string]string
}

func NewMetrics() *Metrics {
	return &Metrics{
		counters: make(map[string]map[string]float64),
		help: map[string]string{
			"acb_leases_issued_total":   "Leases issued, by subject and scope.",
			"acb_leases_denied_total":   "Lease denials, by subject, scope and reason.",
			"acb_claims_recorded_total": "Agent-asserted claims recorded, by subject.",
			"acb_auth_failures_total":   "Authentication failures (aggregate).",
			"acb_rate_limited_total":    "Requests rejected by rate limiting, by subject.",
			"acb_audit_events_total":    "Audit events emitted, by type.",
			"acb_provider_errors_total": "Secret provider failures, by provider.",
		},
	}
}

func labelString(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		v := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(labels[k])
		parts[i] = fmt.Sprintf("%s=%q", k, v)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// Inc increments a counter.
func (m *Metrics) Inc(name string, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	set, ok := m.counters[name]
	if !ok {
		set = make(map[string]float64)
		m.counters[name] = set
	}
	set[labelString(labels)]++
}

// ServeHTTP renders Prometheus text exposition format.
func (m *Metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	names := make([]string, 0, len(m.counters))
	for n := range m.counters {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if h := m.help[n]; h != "" {
			fmt.Fprintf(w, "# HELP %s %s\n", n, h)
		}
		fmt.Fprintf(w, "# TYPE %s counter\n", n)
		series := make([]string, 0, len(m.counters[n]))
		for ls := range m.counters[n] {
			series = append(series, ls)
		}
		sort.Strings(series)
		for _, ls := range series {
			fmt.Fprintf(w, "%s%s %g\n", n, ls, m.counters[n][ls])
		}
	}
}
