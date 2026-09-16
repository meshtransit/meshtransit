package httpapi

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// LoginCapsuleTelemetry records no-grant transport only on an explicit private registry.
type LoginCapsuleTelemetry struct {
	operations *prometheus.CounterVec
	duration   *prometheus.HistogramVec
}

// NewLoginCapsuleTelemetry has no global/runtime registration effects.
func NewLoginCapsuleTelemetry() *LoginCapsuleTelemetry {
	// Dashboard: sum by (operation, result) (rate(meshtransit_browser_callback_capsule_operations_total[5m]))
	// Alert (for: 5m): sum(rate(meshtransit_browser_callback_capsule_operations_total{result="unavailable"}[5m])) > 1
	operations := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "meshtransit_browser_callback_capsule_operations_total",
		Help: "No-grant callback capture/open observations, not authentication or HTTP delivery.",
	}, []string{"operation", "result"})
	// Dashboard: histogram_quantile(0.99,
	//   sum(rate(meshtransit_browser_callback_capsule_duration_seconds_bucket[5m])) by (le, operation))
	// Alert (for: 5m): use that dashboard expression > 0.5.
	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "meshtransit_browser_callback_capsule_duration_seconds",
		Help:    "Bounded no-grant callback capture/open duration, excluding authority/provider work.",
		Buckets: []float64{.000001, .00001, .0001, .001, .01, .1, .5, 1},
	}, []string{"operation", "result"})
	return &LoginCapsuleTelemetry{operations: operations, duration: duration}
}

// ObserveLoginCapsule coalesces unsupported enum values and clamps negative duration.
func (telemetry *LoginCapsuleTelemetry) ObserveLoginCapsule(
	operation LoginCapsuleOperation,
	outcome LoginCapsuleOutcome,
	elapsed time.Duration,
) {
	telemetry.operations.WithLabelValues(operation.String(), outcome.String()).Inc()
	telemetry.duration.WithLabelValues(operation.String(), outcome.String()).Observe(max(elapsed.Seconds(), 0))
}

// Describe implements explicitly owned collection.
func (telemetry *LoginCapsuleTelemetry) Describe(descriptions chan<- *prometheus.Desc) {
	telemetry.operations.Describe(descriptions)
	telemetry.duration.Describe(descriptions)
}

// Collect emits only fixed metric names and bounded labels.
func (telemetry *LoginCapsuleTelemetry) Collect(metrics chan<- prometheus.Metric) {
	telemetry.operations.Collect(metrics)
	telemetry.duration.Collect(metrics)
}

var (
	_ LoginCapsuleObserver = (*LoginCapsuleTelemetry)(nil)
	_ prometheus.Collector = (*LoginCapsuleTelemetry)(nil)
)
