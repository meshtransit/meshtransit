package meshgw

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
)

// groupStatus is a group as /status shows it: never a token.
type groupStatus struct {
	Name          string    `json:"name"`
	Enabled       bool      `json:"enabled"`
	Impersonation bool      `json:"impersonation,omitempty"`
	Reason        string    `json:"reason,omitempty"`
	Detail        string    `json:"detail,omitempty"`
	CheckedAt     time.Time `json:"checked_at,omitzero"`
}

// kubeStatus is the proxy's part of /status.
type kubeStatus struct {
	Mode      string            `json:"mode"`
	Listening bool              `json:"listening"`
	Closed    string            `json:"closed_reason,omitempty"`
	Groups    []groupStatus     `json:"groups"`
	Sessions  map[string]int    `json:"sessions"`
	Cut       map[string]uint64 `json:"sessions_cut"`
}

func (runtime *kubeRuntime) groups() []groupStatus {
	groups := make([]groupStatus, 0, len(runtime.groupNames))
	for _, name := range runtime.groupNames {
		verdict := runtime.checker.Verdict(name)
		groups = append(groups, groupStatus{Name: name, Enabled: verdict.Enabled,
			Impersonation: verdict.Impersonation, Reason: verdict.Reason, Detail: verdict.Detail,
			CheckedAt: verdict.CheckedAt})
	}
	return groups
}

func (runtime *kubeRuntime) status() any {
	sessions := runtime.proxy.Sessions()
	return kubeStatus{Mode: KubeModeProxy, Listening: runtime.listener.Listening(),
		Closed: runtime.listener.ClosedReason(), Groups: runtime.groups(), Sessions: sessions.Open,
		Cut: sessions.Cut}
}

// writeMetrics writes the proxy's metrics (K1b design §11): sessions, cuts
// and their latency, groups turned off, the listener.
func (runtime *kubeRuntime) writeMetrics(w io.Writer) {
	sessions := runtime.proxy.Sessions()
	writeLabelled(w, "meshgw_kube_sessions", "gauge", "Open kubectl sessions by kind.", "kind", sessions.Open)
	writeLabelled(w, "meshgw_kube_sessions_cut_total", "counter", "Sessions cut because their access ended, by reason.",
		"reason", sessions.Cut)
	histogram := sessions.CutSeconds
	_, _ = fmt.Fprintf(w, "# HELP meshgw_kube_session_cut_seconds Seconds a cut session took to end.\n"+
		"# TYPE meshgw_kube_session_cut_seconds histogram\n")
	for index, bound := range histogram.Bounds {
		_, _ = fmt.Fprintf(w, "meshgw_kube_session_cut_seconds_bucket{le=\"%s\"} %d\n",
			strconv.FormatFloat(bound, 'g', -1, 64), histogram.Cumulative[index])
	}
	total := histogram.Cumulative[len(histogram.Cumulative)-1]
	_, _ = fmt.Fprintf(w, "meshgw_kube_session_cut_seconds_bucket{le=\"+Inf\"} %d\n"+
		"meshgw_kube_session_cut_seconds_sum %g\nmeshgw_kube_session_cut_seconds_count %d\n",
		total, histogram.Sum, total)
	disabled := map[string]int{}
	groups := runtime.groups()
	for _, group := range groups {
		disabled[group.Name] = boolMetric(!group.Enabled)
	}
	writeLabelled(w, "meshgw_kube_group_disabled", "gauge", "Whether the gateway turned a group off.", "group",
		disabled)
	_, _ = fmt.Fprintf(w, "# HELP meshgw_kube_rbaccheck_success_timestamp_seconds When every group was last "+
		"checked whole; 0 while one never was.\n# TYPE meshgw_kube_rbaccheck_success_timestamp_seconds gauge\n"+
		"meshgw_kube_rbaccheck_success_timestamp_seconds %d\n", oldestCheck(groups))
	_, _ = fmt.Fprintf(w, "# HELP meshgw_kube_listener_open Whether the kubectl listener is open.\n"+
		"# TYPE meshgw_kube_listener_open gauge\nmeshgw_kube_listener_open %d\n",
		boolMetric(runtime.listener.Listening()))
	writeLabelled(w, "meshgw_kube_limited_total", "counter", "Connections and requests refused at a limit, by limit.",
		"limit", runtime.proxy.Limited())
	writeLabelled(w, "meshgw_kube_audit_refused_total", "counter",
		"Type A operations Core did not record, by reason.", "reason", runtime.proxy.Unrecorded())
	audit := runtime.recorder.Snapshot()
	writeLabelled(w, "meshgw_kube_audit_queue", "gauge", "Type A intents waiting for Core, by state.", "state",
		map[string]int{"queued": audit.Queued, "in_flight": audit.InFlight})
	_, _ = fmt.Fprintf(w, "# HELP meshgw_kube_audit_rate Intents a second the gateway sends Core now.\n"+
		"# TYPE meshgw_kube_audit_rate gauge\nmeshgw_kube_audit_rate %g\n"+
		"# HELP meshgw_kube_audit_paused Whether Core asked the gateway to wait.\n"+
		"# TYPE meshgw_kube_audit_paused gauge\nmeshgw_kube_audit_paused %d\n"+
		"# HELP meshgw_kube_audit_reports_dropped_total Outcomes dropped when their queue was full.\n"+
		"# TYPE meshgw_kube_audit_reports_dropped_total counter\nmeshgw_kube_audit_reports_dropped_total %d\n"+
		"# HELP meshgw_kube_memory_pressure Whether the heap is past its watermark.\n"+
		"# TYPE meshgw_kube_memory_pressure gauge\nmeshgw_kube_memory_pressure %d\n"+
		"# HELP meshgw_heap_bytes Live heap at the last GC.\n# TYPE meshgw_heap_bytes gauge\nmeshgw_heap_bytes %d\n",
		audit.Rate, boolMetric(audit.Paused), audit.DroppedReports, boolMetric(runtime.memory.Pressure()),
		runtime.memory.heap.Load())
}

// oldestCheck is the oldest of the groups' last whole checks in Unix
// seconds, or 0 when a group was never checked, whatever the groups' order
// (review b6a M5).
func oldestCheck(groups []groupStatus) int64 {
	var oldest time.Time
	for _, group := range groups {
		if group.CheckedAt.IsZero() {
			return 0
		}
		if oldest.IsZero() || group.CheckedAt.Before(oldest) {
			oldest = group.CheckedAt
		}
	}
	if oldest.IsZero() {
		return 0
	}
	return oldest.Unix()
}

// labelValue escapes a Prometheus label value: backslash, quote, newline
// (review b6a L7).
func labelValue(value string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(value)
}

// writeLabelled writes one metric with a label, its values in label order.
func writeLabelled[V int | uint64](w io.Writer, name, kind, help, label string, values map[string]V) {
	_, _ = fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		_, _ = fmt.Fprintf(w, "%s{%s=\"%s\"} %d\n", name, label, labelValue(key), values[key])
	}
}

func boolMetric(value bool) int {
	if value {
		return 1
	}
	return 0
}
