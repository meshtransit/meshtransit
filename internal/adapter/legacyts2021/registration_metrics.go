package legacyts2021

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type registrationResult uint8

const (
	registrationAuthorized registrationResult = iota
	registrationInvalidRequest
	registrationAuthenticationFailed
	registrationConflict
	registrationCanceled
	registrationUnavailable
)

type registrationMetrics struct {
	active   prometheus.Gauge
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

func newRegistrationMetrics() registrationMetrics {
	// Dashboard: meshtransit_control_registrations_active
	active := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meshtransit_control_registrations_active",
		Help: "Number of authenticated registration requests currently being processed.",
	})
	// Dashboard: sum by (result) (rate(meshtransit_control_registration_requests_total[5m]))
	// Alert: sum(rate(meshtransit_control_registration_requests_total{result="unavailable"}[5m])) > 0
	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "meshtransit_control_registration_requests_total",
		Help: "Total authenticated registration requests by bounded terminal result.",
	}, []string{"result"})
	// Dashboard: histogram_quantile(0.99, sum by (le, result) (rate(meshtransit_control_registration_duration_seconds_bucket[5m])))
	// Alert: histogram_quantile(0.99, sum by (le) (rate(meshtransit_control_registration_duration_seconds_bucket[5m]))) > 5
	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "meshtransit_control_registration_duration_seconds",
		Help:    "Authenticated registration request duration by bounded terminal result.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
	}, []string{"result"})
	for _, result := range allRegistrationResults() {
		label := result.label()
		requests.WithLabelValues(label)
		duration.WithLabelValues(label)
	}
	return registrationMetrics{active: active, requests: requests, duration: duration}
}

func (metrics registrationMetrics) collectors() [3]prometheus.Collector {
	return [3]prometheus.Collector{metrics.active, metrics.requests, metrics.duration}
}

func (metrics registrationMetrics) start() time.Time {
	metrics.active.Inc()
	return time.Now()
}

func (metrics registrationMetrics) finish(startedAt time.Time, result registrationResult) {
	metrics.active.Dec()
	label := result.label()
	metrics.requests.WithLabelValues(label).Inc()
	metrics.duration.WithLabelValues(label).Observe(time.Since(startedAt).Seconds())
}

func allRegistrationResults() [6]registrationResult {
	return [6]registrationResult{
		registrationAuthorized,
		registrationInvalidRequest,
		registrationAuthenticationFailed,
		registrationConflict,
		registrationCanceled,
		registrationUnavailable,
	}
}

func (result registrationResult) label() string {
	switch result {
	case registrationAuthorized:
		return "authorized"
	case registrationInvalidRequest:
		return "invalid_request"
	case registrationAuthenticationFailed:
		return "authentication_failed"
	case registrationConflict:
		return "conflict"
	case registrationCanceled:
		return "canceled"
	case registrationUnavailable:
		return "unavailable"
	default:
		return "internal_failure"
	}
}
