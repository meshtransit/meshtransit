package oidc

import (
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/prometheus/client_golang/prometheus"
)

// IssueTelemetry owns bounded issuance metrics for explicit private registration.
// Construction neither registers globally nor enables browser login.
type IssueTelemetry struct {
	active   prometheus.Gauge
	results  *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

// NewIssueTelemetry constructs no-data aggregate metrics without I/O.
func NewIssueTelemetry() *IssueTelemetry {
	// Dashboard: meshtransit_oidc_session_issuances_active
	// Alert (for: 5m): meshtransit_oidc_session_issuances_active >= 256
	active := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meshtransit_oidc_session_issuances_active",
		Help: "Owned Account Session issuance requests.",
	})
	// Dashboard: sum by (result) (rate(meshtransit_oidc_session_issuances_total[5m]))
	// Alert (for: 2m): sum(rate(meshtransit_oidc_session_issuances_total{result=~\"unavailable|commit_unknown|cleanup_failed\"}[5m])) > 0
	results := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "meshtransit_oidc_session_issuances_total",
		Help: "Session issuance by closed result, without identity or bearer.",
	}, []string{"result"})
	// Dashboard: histogram_quantile(0.99, sum(rate(meshtransit_oidc_session_issuance_duration_seconds_bucket[5m])) by (le))
	// Alert (for: 5m): histogram_quantile(0.99, sum(rate(meshtransit_oidc_session_issuance_duration_seconds_bucket[5m])) by (le)) > 10
	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "meshtransit_oidc_session_issuance_duration_seconds",
		Help:    "Complete issuance request duration including joined cleanup.",
		Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30},
	}, []string{"result"})
	return &IssueTelemetry{active: active, results: results, duration: duration}
}

// IssueOpened records owned work without receiving request data.
func (telemetry *IssueTelemetry) IssueOpened() { telemetry.active.Inc() }

// IssueClosed maps unknown numeric values to one fixed label.
func (telemetry *IssueTelemetry) IssueClosed(outcome oidcauth.IssueOutcome, elapsed time.Duration) {
	label := "unknown"
	switch outcome {
	case oidcauth.IssueConfirmed:
		label = "confirmed"
	case oidcauth.IssueRejected:
		label = "rejected"
	case oidcauth.IssueUnavailable:
		label = "unavailable"
	case oidcauth.IssueLimited:
		label = "limited"
	case oidcauth.IssueCommitUnknown:
		label = "commit_unknown"
	case oidcauth.IssueCleanupFailed:
		label = "cleanup_failed"
	}
	telemetry.active.Dec()
	telemetry.results.WithLabelValues(label).Inc()
	telemetry.duration.WithLabelValues(label).Observe(max(elapsed.Seconds(), 0))
}

// Describe implements the private collector contract.
func (telemetry *IssueTelemetry) Describe(descriptions chan<- *prometheus.Desc) {
	telemetry.active.Describe(descriptions)
	telemetry.results.Describe(descriptions)
	telemetry.duration.Describe(descriptions)
}

// Collect emits only fixed-name bounded-label metrics.
func (telemetry *IssueTelemetry) Collect(metrics chan<- prometheus.Metric) {
	telemetry.active.Collect(metrics)
	telemetry.results.Collect(metrics)
	telemetry.duration.Collect(metrics)
}

var (
	_ oidcauth.IssueObserver = (*IssueTelemetry)(nil)
	_ prometheus.Collector   = (*IssueTelemetry)(nil)
)
