package httpapi

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// LoginCallbackTelemetry observes syntax only on an explicitly owned private registry.
// No counter or category proves authentication, target coverage or public readiness.
type LoginCallbackTelemetry struct {
	inputs   *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

// NewLoginCallbackTelemetry constructs isolated fixed-label metrics without registration.
func NewLoginCallbackTelemetry() *LoginCallbackTelemetry {
	// Dashboard: sum by (result) (rate(meshtransit_browser_callback_inputs_total[5m]))
	// Alert (for: 5m): sum(rate(meshtransit_browser_callback_inputs_total{result="invalid"}[5m])) > 10
	inputs := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "meshtransit_browser_callback_inputs_total",
		Help: "Callback syntax observations; received code/error is not authentication.",
	}, []string{"result"})
	// Dashboard: histogram_quantile(0.99,
	//   sum(rate(meshtransit_browser_callback_input_duration_seconds_bucket[5m])) by (le))
	// Alert (for: 5m): use that dashboard expression > 0.5.
	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "meshtransit_browser_callback_input_duration_seconds",
		Help:    "Bounded callback syntax parsing duration, excluding authority/provider work.",
		Buckets: []float64{.000001, .00001, .0001, .001, .01, .1, .5, 1},
	}, []string{"result"})
	return &LoginCallbackTelemetry{inputs: inputs, duration: duration}
}

// ObserveLoginCallback accepts only closed categories and numeric elapsed time.
func (telemetry *LoginCallbackTelemetry) ObserveLoginCallback(outcome LoginCallbackOutcome, elapsed time.Duration) {
	label := outcome.String()
	telemetry.inputs.WithLabelValues(label).Inc()
	telemetry.duration.WithLabelValues(label).Observe(max(elapsed.Seconds(), 0))
}

// Describe implements explicit private collection without global effects.
func (telemetry *LoginCallbackTelemetry) Describe(descriptions chan<- *prometheus.Desc) {
	telemetry.inputs.Describe(descriptions)
	telemetry.duration.Describe(descriptions)
}

// Collect emits only fixed metric names and bounded labels.
func (telemetry *LoginCallbackTelemetry) Collect(metrics chan<- prometheus.Metric) {
	telemetry.inputs.Collect(metrics)
	telemetry.duration.Collect(metrics)
}

var (
	_ LoginCallbackObserver = (*LoginCallbackTelemetry)(nil)
	_ prometheus.Collector  = (*LoginCallbackTelemetry)(nil)
)
