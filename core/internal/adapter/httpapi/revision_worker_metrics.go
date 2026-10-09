package httpapi

import (
	"github.com/prometheus/client_golang/prometheus"

	"meshtransit.net/core/internal/domain/network/revisionworker"
)

type revisionWorkerMetricsCollector struct {
	telemetry               revisionWorkerTelemetry
	readyBacklogDesc        *prometheus.Desc
	oldestReadyAgeDesc      *prometheus.Desc
	backlogObservationsDesc *prometheus.Desc
	claimOperationsDesc     *prometheus.Desc
	claimedEventsDesc       *prometheus.Desc
	deliveryAttemptsDesc    *prometheus.Desc
}

type revisionWorkerTelemetry interface {
	Snapshot() revisionworker.TelemetrySnapshot
}

func newRevisionWorkerMetricsCollector(
	telemetry revisionWorkerTelemetry,
) *revisionWorkerMetricsCollector {
	return &revisionWorkerMetricsCollector{
		telemetry: telemetry,
		// Dashboard: meshtransit_revision_worker_ready_backlog_events
		// Alert: meshtransit_revision_worker_ready_backlog_events > 0
		readyBacklogDesc: prometheus.NewDesc(
			"meshtransit_revision_worker_ready_backlog_events",
			"Number of Network-revision outbox events currently eligible for claim.",
			nil,
			nil,
		),
		// Dashboard: meshtransit_revision_worker_oldest_ready_event_age_seconds
		// Alert: meshtransit_revision_worker_oldest_ready_event_age_seconds > 60
		oldestReadyAgeDesc: prometheus.NewDesc(
			"meshtransit_revision_worker_oldest_ready_event_age_seconds",
			"Age in seconds of the oldest Network-revision event eligible for claim.",
			nil,
			nil,
		),
		// Dashboard: rate(meshtransit_revision_worker_backlog_observations_total[5m])
		// Alert: rate(meshtransit_revision_worker_backlog_observations_total{result="error"}[5m]) > 0
		backlogObservationsDesc: prometheus.NewDesc(
			"meshtransit_revision_worker_backlog_observations_total",
			"Total backlog observations by bounded result.",
			[]string{"result"},
			nil,
		),
		// Dashboard: rate(meshtransit_revision_worker_claim_operations_total[5m])
		// Alert: rate(meshtransit_revision_worker_claim_operations_total{result="error"}[5m]) > 0
		claimOperationsDesc: prometheus.NewDesc(
			"meshtransit_revision_worker_claim_operations_total",
			"Total bounded outbox claim operations by result.",
			[]string{"result"},
			nil,
		),
		// Dashboard: rate(meshtransit_revision_worker_claimed_events_total[5m])
		claimedEventsDesc: prometheus.NewDesc(
			"meshtransit_revision_worker_claimed_events_total",
			"Total Network-revision outbox events claimed for delivery.",
			nil,
			nil,
		),
		// Dashboard: sum by (result) (rate(meshtransit_revision_worker_delivery_attempts_total[5m]))
		// Alert: rate(meshtransit_revision_worker_delivery_attempts_total{result="failed"}[5m]) > 0
		deliveryAttemptsDesc: prometheus.NewDesc(
			"meshtransit_revision_worker_delivery_attempts_total",
			"Total Network-revision delivery attempts by bounded result.",
			[]string{"result"},
			nil,
		),
	}
}

func (collector *revisionWorkerMetricsCollector) Describe(descriptions chan<- *prometheus.Desc) {
	descriptions <- collector.readyBacklogDesc
	descriptions <- collector.oldestReadyAgeDesc
	descriptions <- collector.backlogObservationsDesc
	descriptions <- collector.claimOperationsDesc
	descriptions <- collector.claimedEventsDesc
	descriptions <- collector.deliveryAttemptsDesc
}

func (collector *revisionWorkerMetricsCollector) Collect(metrics chan<- prometheus.Metric) {
	snapshot := collector.telemetry.Snapshot()
	metrics <- prometheus.MustNewConstMetric(
		collector.readyBacklogDesc,
		prometheus.GaugeValue,
		float64(snapshot.ReadyBacklogEvents),
	)
	metrics <- prometheus.MustNewConstMetric(
		collector.oldestReadyAgeDesc,
		prometheus.GaugeValue,
		snapshot.OldestReadyEventAge.Seconds(),
	)
	collectCounterResults(
		metrics,
		collector.backlogObservationsDesc,
		[]counterResult{
			{label: "success", value: snapshot.BacklogSuccessTotal},
			{label: "error", value: snapshot.BacklogErrorTotal},
		},
	)
	collectCounterResults(
		metrics,
		collector.claimOperationsDesc,
		[]counterResult{
			{label: "success", value: snapshot.ClaimSuccessTotal},
			{label: "error", value: snapshot.ClaimErrorTotal},
		},
	)
	metrics <- prometheus.MustNewConstMetric(
		collector.claimedEventsDesc,
		prometheus.CounterValue,
		float64(snapshot.ClaimedEventsTotal),
	)
	collectCounterResults(
		metrics,
		collector.deliveryAttemptsDesc,
		[]counterResult{
			{label: "delivered", value: snapshot.DeliveredTotal},
			{label: "deferred", value: snapshot.DeferredTotal},
			{label: "failed", value: snapshot.FailedTotal},
		},
	)
}

type counterResult struct {
	label string
	value uint64
}

func collectCounterResults(
	metrics chan<- prometheus.Metric,
	description *prometheus.Desc,
	results []counterResult,
) {
	for _, result := range results {
		metrics <- prometheus.MustNewConstMetric(
			description,
			prometheus.CounterValue,
			float64(result.value),
			result.label,
		)
	}
}
