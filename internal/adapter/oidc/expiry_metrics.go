package oidc

import (
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/authexpiry"
	"github.com/prometheus/client_golang/prometheus"
)

// ExpiryTelemetry owns no-data metrics registered only on the private health server.
// Running/last-success observations do not prove intended Deployment coverage.
type ExpiryTelemetry struct {
	running, active, lastSuccess     prometheus.Gauge
	attempted, confirmed, batchLimit prometheus.Counter
	results                          *prometheus.CounterVec
	duration                         *prometheus.HistogramVec
}

// NewExpiryTelemetry constructs fixed-name metrics without global registration.
func NewExpiryTelemetry() *ExpiryTelemetry {
	// Dashboard: meshtransit_oidc_expiry_worker_running
	// Alert (for: 2m): meshtransit_oidc_expiry_worker_running != 1
	running := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meshtransit_oidc_expiry_worker_running", Help: "One owned expiry polling loop is running.",
	})
	// Dashboard: meshtransit_oidc_expiry_passes_active
	// Alert (for: 1m): meshtransit_oidc_expiry_passes_active > 1
	active := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meshtransit_oidc_expiry_passes_active", Help: "Owned sequential expiry passes including cleanup.",
	})
	// Dashboard: time() - meshtransit_oidc_expiry_last_success_timestamp_seconds
	// Alert (for: 2m): time() - meshtransit_oidc_expiry_last_success_timestamp_seconds > 120
	lastSuccess := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meshtransit_oidc_expiry_last_success_timestamp_seconds",
		Help: "Last completed successful pass; zero before success, not cleanup coverage.",
	})
	// Dashboard: sum by (result) (rate(meshtransit_oidc_expiry_passes_total[5m]))
	// Alert (for: 2m): sum(rate(meshtransit_oidc_expiry_passes_total{result="cleanup_failed"}[5m])) > 0
	results := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "meshtransit_oidc_expiry_passes_total", Help: "Expiry passes by closed operator outcome.",
	}, []string{"result"})
	// Dashboard: histogram_quantile(0.99,
	//   sum(rate(meshtransit_oidc_expiry_pass_duration_seconds_bucket[5m])) by (le))
	// Alert (for: 5m): use that dashboard expression > 30.
	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "meshtransit_oidc_expiry_pass_duration_seconds", Help: "Pass duration including joined rollback.",
		Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 35},
	}, []string{"result"})
	// Dashboard: rate(meshtransit_oidc_expiry_units_attempted_total[5m])
	// Alert (for: 5m): rate(meshtransit_oidc_expiry_units_attempted_total[5m]) > 0
	//   and rate(meshtransit_oidc_expiry_units_confirmed_total[5m]) == 0
	attempted := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "meshtransit_oidc_expiry_units_attempted_total", Help: "Validated attempted no-grant expiry units.",
	})
	// Dashboard: rate(meshtransit_oidc_expiry_units_confirmed_total[5m])
	// Shares the attempted-without-confirmed alert above; hidden durable commits are not receipts.
	confirmed := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "meshtransit_oidc_expiry_units_confirmed_total", Help: "Released confirmed expiry receipts, not all commits.",
	})
	// Dashboard: rate(meshtransit_oidc_expiry_batch_limit_reached_total[5m])
	// Alert (for: 5m): rate(meshtransit_oidc_expiry_batch_limit_reached_total[5m]) > 0
	batchLimit := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "meshtransit_oidc_expiry_batch_limit_reached_total", Help: "Passes that attempted the configured batch limit.",
	})
	return &ExpiryTelemetry{
		running: running, active: active, lastSuccess: lastSuccess, results: results,
		duration: duration, attempted: attempted, confirmed: confirmed, batchLimit: batchLimit,
	}
}

// WorkerRunning records loop liveness, never login readiness or assignment.
func (telemetry *ExpiryTelemetry) WorkerRunning(running bool) {
	value := float64(0)
	if running {
		value = 1
	}
	telemetry.running.Set(value)
}

// PassOpened records exactly one owned pass without request data.
func (telemetry *ExpiryTelemetry) PassOpened() { telemetry.active.Inc() }

// PassClosed accepts only bounded numbers and maps unknown categories to one label.
func (telemetry *ExpiryTelemetry) PassClosed(observation authexpiry.Observation) {
	pass := observation.Pass
	validCounts := pass.Attempted >= 0 && pass.Attempted <= 128 &&
		pass.Confirmed >= 0 && pass.Confirmed <= pass.Attempted
	if !validCounts {
		observation.Outcome = authexpiry.Invalid
		observation.BatchLimitReached = false
		pass.Attempted, pass.Confirmed = 0, 0
	}
	label := expiryOutcomeLabel(observation.Outcome)
	telemetry.active.Dec()
	telemetry.results.WithLabelValues(label).Inc()
	telemetry.duration.WithLabelValues(label).Observe(max(observation.Elapsed.Seconds(), 0))
	telemetry.attempted.Add(float64(pass.Attempted))
	telemetry.confirmed.Add(float64(pass.Confirmed))
	if observation.BatchLimitReached && pass.Attempted > 0 {
		telemetry.batchLimit.Inc()
	}
	if observation.Outcome == authexpiry.Empty || observation.Outcome == authexpiry.Confirmed {
		telemetry.lastSuccess.Set(float64(time.Now().Unix()))
	}
}

func expiryOutcomeLabel(outcome authexpiry.Outcome) string {
	switch outcome {
	case authexpiry.Empty:
		return "empty"
	case authexpiry.Confirmed:
		return "confirmed"
	case authexpiry.Unavailable:
		return "unavailable"
	case authexpiry.Deadline:
		return "deadline"
	case authexpiry.CommitUnknown:
		return "commit_unknown"
	case authexpiry.CleanupFailed:
		return "cleanup_failed"
	case authexpiry.Canceled:
		return "canceled"
	case authexpiry.Invalid:
		return "invalid"
	default:
		return "unknown"
	}
}

// Describe implements explicit private collection without global effects.
func (telemetry *ExpiryTelemetry) Describe(descriptions chan<- *prometheus.Desc) {
	for _, collector := range telemetry.collectors() {
		collector.Describe(descriptions)
	}
}

// Collect emits fixed names/labels, never identity or proof data.
func (telemetry *ExpiryTelemetry) Collect(metrics chan<- prometheus.Metric) {
	for _, collector := range telemetry.collectors() {
		collector.Collect(metrics)
	}
}

func (telemetry *ExpiryTelemetry) collectors() []prometheus.Collector {
	return []prometheus.Collector{
		telemetry.running, telemetry.active, telemetry.lastSuccess, telemetry.results,
		telemetry.duration, telemetry.attempted, telemetry.confirmed, telemetry.batchLimit,
	}
}

var (
	_ authexpiry.Observer  = (*ExpiryTelemetry)(nil)
	_ prometheus.Collector = (*ExpiryTelemetry)(nil)
)
