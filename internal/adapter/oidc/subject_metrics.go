package oidc

import (
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/prometheus/client_golang/prometheus"
)

// SubjectTelemetry owns no-data resolution metrics for a private operator registry.
// The caller must register explicitly; no global registry or public route is used.
type SubjectTelemetry struct {
	active      prometheus.Gauge
	resolutions *prometheus.CounterVec
	duration    *prometheus.HistogramVec
}

// NewSubjectTelemetry constructs bounded metrics without I/O or global effects.
func NewSubjectTelemetry() *SubjectTelemetry {
	// Dashboard: meshtransit_oidc_subject_resolutions_active
	// Alert (for: 5m): meshtransit_oidc_subject_resolutions_active >= 256
	active := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meshtransit_oidc_subject_resolutions_active",
		Help: "Owned existing-subject reads; never Session authority.",
	})
	// Dashboard: sum by (result) (rate(meshtransit_oidc_subject_resolutions_total[5m]))
	// Alert (for: 2m): sum(rate(meshtransit_oidc_subject_resolutions_total{result="unavailable"}[5m])) > 0
	resolutions := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "meshtransit_oidc_subject_resolutions_total",
			Help: "Existing-subject resolution by closed result, without identity.",
		},
		[]string{"result"},
	)
	// Dashboard: histogram_quantile(0.99, sum(rate(meshtransit_oidc_subject_resolution_duration_seconds_bucket[5m])) by (le))
	// Alert (for: 5m): histogram_quantile(0.99, sum(rate(meshtransit_oidc_subject_resolution_duration_seconds_bucket[5m])) by (le)) > 10
	duration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "meshtransit_oidc_subject_resolution_duration_seconds",
			Help:    "Complete subject-resolution request duration.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
		},
		[]string{"result"},
	)
	return &SubjectTelemetry{active: active, resolutions: resolutions, duration: duration}
}

// SubjectResolutionOpened records one owned call without receiving request data.
func (telemetry *SubjectTelemetry) SubjectResolutionOpened() { telemetry.active.Inc() }

// SubjectResolutionClosed maps even unknown numeric values into one fixed label.
func (telemetry *SubjectTelemetry) SubjectResolutionClosed(outcome oidcauth.SubjectResolutionOutcome, duration time.Duration) {
	label := "unknown"
	switch outcome {
	case oidcauth.SubjectResolutionResolved:
		label = "resolved"
	case oidcauth.SubjectResolutionRejected:
		label = "rejected"
	case oidcauth.SubjectResolutionUnavailable:
		label = "unavailable"
	case oidcauth.SubjectResolutionLimited:
		label = "limited"
	}
	telemetry.active.Dec()
	telemetry.resolutions.WithLabelValues(label).Inc()
	telemetry.duration.WithLabelValues(label).Observe(max(duration.Seconds(), 0))
}

// Describe implements prometheus.Collector without global registration.
func (telemetry *SubjectTelemetry) Describe(descriptions chan<- *prometheus.Desc) {
	telemetry.active.Describe(descriptions)
	telemetry.resolutions.Describe(descriptions)
	telemetry.duration.Describe(descriptions)
}

// Collect implements prometheus.Collector for the private operator surface.
func (telemetry *SubjectTelemetry) Collect(metrics chan<- prometheus.Metric) {
	telemetry.active.Collect(metrics)
	telemetry.resolutions.Collect(metrics)
	telemetry.duration.Collect(metrics)
}

var (
	_ oidcauth.SubjectResolutionObserver = (*SubjectTelemetry)(nil)
	_ prometheus.Collector               = (*SubjectTelemetry)(nil)
)
