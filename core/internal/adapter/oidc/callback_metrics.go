package oidc

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"meshtransit.net/core/internal/domain/identity/oidcauth"
)

// CallbackTelemetry owns isolated application metrics, not public registration.
type CallbackTelemetry struct {
	active   prometheus.Gauge
	results  *prometheus.CounterVec
	duration *prometheus.HistogramVec
	emails   *prometheus.CounterVec
}

// NewCallbackTelemetry constructs no-data metrics without I/O or global effects.
func NewCallbackTelemetry() *CallbackTelemetry {
	// Dashboard: meshtransit_oidc_browser_callbacks_active
	// Alert (for: 5m): meshtransit_oidc_browser_callbacks_active >= 128
	active := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meshtransit_oidc_browser_callbacks_active",
		Help: "Owned browser callback application requests including joined cleanup.",
	})
	// Dashboard: sum by (result) (rate(meshtransit_oidc_browser_callbacks_total[5m]))
	// Alert (for: 2m): sum(rate(meshtransit_oidc_browser_callbacks_total{
	//   result=~"unavailable|commit_unknown|cleanup_failed"}[5m])) > 0
	results := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "meshtransit_oidc_browser_callbacks_total",
		Help: "Browser callback application completion by closed result, without credentials or identity.",
	}, []string{"result"})
	// Dashboard: histogram_quantile(0.99, sum(rate(
	//   meshtransit_oidc_browser_callback_duration_seconds_bucket[5m])) by (le))
	// Alert (for: 5m): use the dashboard expression > 30.
	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "meshtransit_oidc_browser_callback_duration_seconds",
		Help:    "Complete callback application lifetime including separately bounded joined cleanup.",
		Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 45},
	}, []string{"result"})
	// Dashboard: sum by (result) (rate(meshtransit_account_email_record_total[1h]))
	// Alert (for: 30m): sum(rate(meshtransit_account_email_record_total{result="failed"}[30m])) > 0
	emails := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "meshtransit_account_email_record_total",
		Help: "Verified-email steps at browser sign-in by closed result, without the email or identity.",
	}, []string{"result"})
	return &CallbackTelemetry{active: active, results: results, duration: duration, emails: emails}
}

// CallbackOpened observes owned lifetime without any request data.
func (telemetry *CallbackTelemetry) CallbackOpened() { telemetry.active.Inc() }

// CallbackClosed folds arbitrary numeric outcomes into one fixed unknown label.
func (telemetry *CallbackTelemetry) CallbackClosed(outcome oidcauth.CallbackOutcome, elapsed time.Duration) {
	label := outcome.String()
	telemetry.active.Dec()
	telemetry.results.WithLabelValues(label).Inc()
	telemetry.duration.WithLabelValues(label).Observe(max(elapsed.Seconds(), 0))
}

// AccountEmailStep counts one email step by its closed result.
func (telemetry *CallbackTelemetry) AccountEmailStep(outcome oidcauth.AccountEmailOutcome) {
	telemetry.emails.WithLabelValues(outcome.String()).Inc()
}

// Describe implements the explicit private collector contract.
func (telemetry *CallbackTelemetry) Describe(descriptions chan<- *prometheus.Desc) {
	telemetry.active.Describe(descriptions)
	telemetry.results.Describe(descriptions)
	telemetry.duration.Describe(descriptions)
	telemetry.emails.Describe(descriptions)
}

// Collect emits only fixed names and bounded closed-result labels.
func (telemetry *CallbackTelemetry) Collect(metrics chan<- prometheus.Metric) {
	telemetry.active.Collect(metrics)
	telemetry.results.Collect(metrics)
	telemetry.duration.Collect(metrics)
	telemetry.emails.Collect(metrics)
}

var (
	_ oidcauth.CallbackObserver     = (*CallbackTelemetry)(nil)
	_ oidcauth.AccountEmailObserver = (*CallbackTelemetry)(nil)
	_ prometheus.Collector          = (*CallbackTelemetry)(nil)
)
