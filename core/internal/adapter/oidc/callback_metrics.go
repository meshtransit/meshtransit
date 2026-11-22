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
	refusals *prometheus.CounterVec
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
	// Dashboard: sum by (reason) (rate(meshtransit_invitation_refused_total[1h]))
	// Alert (for: 15m): sum(rate(meshtransit_invitation_refused_total{reason="email_mismatch"}[15m])) * 900 > 5
	//   (someone trying invitation links with other accounts, TD-SEC-37; a provider sending a malformed or
	//   IDN address counts here too). "invalid" mixes refusals with faults (a missing grant): read it
	//   with the error logs.
	refusals := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "meshtransit_invitation_refused_total",
		Help: "Invitation links a sign-in could not use, by closed reason, without the link, email or identity.",
	}, []string{"reason"})
	return &CallbackTelemetry{active: active, results: results, duration: duration, emails: emails, refusals: refusals}
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

// InvitationRefused counts one refused invitation link by its closed reason.
func (telemetry *CallbackTelemetry) InvitationRefused(refusal oidcauth.InvitationRefusal) {
	telemetry.refusals.WithLabelValues(refusal.String()).Inc()
}

// Describe implements the explicit private collector contract.
func (telemetry *CallbackTelemetry) Describe(descriptions chan<- *prometheus.Desc) {
	telemetry.active.Describe(descriptions)
	telemetry.results.Describe(descriptions)
	telemetry.duration.Describe(descriptions)
	telemetry.emails.Describe(descriptions)
	telemetry.refusals.Describe(descriptions)
}

// Collect emits only fixed names and bounded closed-result labels.
func (telemetry *CallbackTelemetry) Collect(metrics chan<- prometheus.Metric) {
	telemetry.active.Collect(metrics)
	telemetry.results.Collect(metrics)
	telemetry.duration.Collect(metrics)
	telemetry.emails.Collect(metrics)
	telemetry.refusals.Collect(metrics)
}

var (
	_ oidcauth.CallbackObserver     = (*CallbackTelemetry)(nil)
	_ oidcauth.AccountEmailObserver = (*CallbackTelemetry)(nil)
	_ oidcauth.InvitationObserver   = (*CallbackTelemetry)(nil)
	_ prometheus.Collector          = (*CallbackTelemetry)(nil)
)
