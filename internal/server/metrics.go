package server

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// Metrics is a minimal hand-rolled Prometheus text-exposition registry:
// counters only, no external dependency (ADR-0001). Secret material never
// appears here, and caller-supplied strings are never used as label values
// (unbounded label cardinality is a memory-exhaustion vector) — labels are
// policy-defined subject keys and scope names, event types, and fixed
// sentinels.
type Metrics struct {
	mu       sync.Mutex
	counters map[string]map[string]float64 // metric name -> rendered labels -> value
	help     map[string]string
}

// NewMetrics creates the registry with help text for the known series.
func NewMetrics() *Metrics {
	return &Metrics{
		counters: make(map[string]map[string]float64),
		help: map[string]string{
			"acb_leases_issued_total":             "Leases issued, by subject and scope.",
			"acb_leases_denied_total":             "Lease denials, by subject, scope and reason.",
			"acb_claims_recorded_total":           "Agent-asserted claims recorded, by subject.",
			"acb_auth_failures_total":             "Authentication failures (aggregate).",
			"acb_rate_limited_total":              "Requests rejected by rate limiting, by subject.",
			"acb_audit_events_total":              "Audit events emitted, by type.",
			"acb_audit_write_errors_total":        "Audit events that failed to write (requests failed closed).",
			"acb_provider_errors_total":           "Secret provider failures, by provider.",
			"acb_provider_duration_seconds_sum":   "Cumulative provider fetch latency.",
			"acb_provider_duration_seconds_count": "Provider fetch count.",
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

// Inc increments a counter by one.
func (m *Metrics) Inc(name string, labels map[string]string) {
	m.Add(name, labels, 1)
}

// Add increments a counter by v (used for latency sum/count pairs).
func (m *Metrics) Add(name string, labels map[string]string, v float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	set, ok := m.counters[name]
	if !ok {
		set = make(map[string]float64)
		m.counters[name] = set
	}
	set[labelString(labels)] += v
}

// ServeHTTP renders Prometheus text exposition format. The exposition is
// built into a buffer under the lock and written after release — a slow
// scraper must not block Inc, which sits on the audit-emit path.
func (m *Metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	var buf strings.Builder
	m.mu.Lock()
	names := make([]string, 0, len(m.counters))
	for n := range m.counters {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if h := m.help[n]; h != "" {
			fmt.Fprintf(&buf, "# HELP %s %s\n", n, h)
		}
		fmt.Fprintf(&buf, "# TYPE %s counter\n", n)
		series := make([]string, 0, len(m.counters[n]))
		for ls := range m.counters[n] {
			series = append(series, ls)
		}
		sort.Strings(series)
		for _, ls := range series {
			fmt.Fprintf(&buf, "%s%s %g\n", n, ls, m.counters[n][ls])
		}
	}
	m.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = io.WriteString(w, buf.String())
}
