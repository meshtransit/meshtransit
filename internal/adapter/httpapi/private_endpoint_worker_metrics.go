package httpapi

import (
	"errors"

	"github.com/meshtransit/meshtransit/internal/sharing/endpointpublication"
	"github.com/prometheus/client_golang/prometheus"
)

// ErrInvalidPrivateEndpointWorkerMetrics reports a missing telemetry source.
var ErrInvalidPrivateEndpointWorkerMetrics = errors.New("invalid Private Endpoint worker metrics")

type privateEndpointWorkerMetricsCollector struct {
	telemetry  *endpointpublication.Telemetry
	running    *prometheus.Desc
	passes     *prometheus.Desc
	candidates *prometheus.Desc
	listErrors *prometheus.Desc
	attempts   *prometheus.Desc
}

// NewPrivateEndpointWorkerMetricsCollector exposes bounded-label process telemetry.
func NewPrivateEndpointWorkerMetricsCollector(
	telemetry *endpointpublication.Telemetry,
) (prometheus.Collector, error) {
	if telemetry == nil {
		return nil, ErrInvalidPrivateEndpointWorkerMetrics
	}
	return &privateEndpointWorkerMetricsCollector{
		telemetry: telemetry,
		// Alert: meshtransit_private_endpoint_worker_running != 1 for an enabled worker.
		running: prometheus.NewDesc(
			"meshtransit_private_endpoint_worker_running",
			"Whether the configured Private Endpoint reconciliation worker is running.", nil, nil,
		),
		passes: prometheus.NewDesc(
			"meshtransit_private_endpoint_worker_passes_total",
			"Total bounded Private Endpoint reconciliation passes.", nil, nil,
		),
		// Alert: meshtransit_private_endpoint_worker_candidates{operation="withdrawal"} > 0 for 60s.
		candidates: prometheus.NewDesc(
			"meshtransit_private_endpoint_worker_candidates",
			"Candidates returned by the latest successful bounded selection.",
			[]string{"operation"}, nil,
		),
		// Alert: rate(meshtransit_private_endpoint_worker_list_errors_total[5m]) > 0.
		listErrors: prometheus.NewDesc(
			"meshtransit_private_endpoint_worker_list_errors_total",
			"Total candidate-list failures by closed operation.",
			[]string{"operation"}, nil,
		),
		// Alert: rate(meshtransit_private_endpoint_worker_attempts_total{result="deferred"}[5m]) > 0.
		attempts: prometheus.NewDesc(
			"meshtransit_private_endpoint_worker_attempts_total",
			"Total endpoint reconciliation attempts by closed operation and result.",
			[]string{"operation", "result"}, nil,
		),
	}, nil
}

func (collector *privateEndpointWorkerMetricsCollector) Describe(descriptions chan<- *prometheus.Desc) {
	descriptions <- collector.running
	descriptions <- collector.passes
	descriptions <- collector.candidates
	descriptions <- collector.listErrors
	descriptions <- collector.attempts
}

func (collector *privateEndpointWorkerMetricsCollector) Collect(metrics chan<- prometheus.Metric) {
	snapshot := collector.telemetry.Snapshot()
	running := 0.0
	if snapshot.Running {
		running = 1
	}
	metrics <- prometheus.MustNewConstMetric(collector.running, prometheus.GaugeValue, running)
	metrics <- prometheus.MustNewConstMetric(collector.passes, prometheus.CounterValue, float64(snapshot.Passes))
	for _, item := range []struct {
		operation  string
		candidates int64
		errors     uint64
		succeeded  uint64
		deferred   uint64
	}{
		{operation: "publication", candidates: snapshot.PublicationCandidates, errors: snapshot.PublicationListErrors, succeeded: snapshot.PublicationSucceeded, deferred: snapshot.PublicationDeferred},
		{operation: "withdrawal", candidates: snapshot.WithdrawalCandidates, errors: snapshot.WithdrawalListErrors, succeeded: snapshot.WithdrawalSucceeded, deferred: snapshot.WithdrawalDeferred},
	} {
		metrics <- prometheus.MustNewConstMetric(collector.candidates, prometheus.GaugeValue, float64(item.candidates), item.operation)
		metrics <- prometheus.MustNewConstMetric(collector.listErrors, prometheus.CounterValue, float64(item.errors), item.operation)
		metrics <- prometheus.MustNewConstMetric(collector.attempts, prometheus.CounterValue, float64(item.succeeded), item.operation, "succeeded")
		metrics <- prometheus.MustNewConstMetric(collector.attempts, prometheus.CounterValue, float64(item.deferred), item.operation, "deferred")
	}
}
