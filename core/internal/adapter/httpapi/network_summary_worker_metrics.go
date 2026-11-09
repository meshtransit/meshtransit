package httpapi

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
	"meshtransit.net/core/internal/domain/networksummary"
)

// ErrInvalidNetworkSummaryWorkerMetrics reports a missing owned worker source.
var ErrInvalidNetworkSummaryWorkerMetrics = errors.New("invalid network summary worker metrics")

type networkSummaryWorkerMetricsCollector struct {
	worker           *networksummary.Worker
	running, pending *prometheus.Desc
	marks            *prometheus.Desc
	lag, computing   *prometheus.Desc
	counters         []networkSummaryCounter
}

type networkSummaryCounter struct {
	descriptor *prometheus.Desc
	value      func(networksummary.Measurements) uint64
}

// NewNetworkSummaryWorkerMetricsCollector exposes fixed, identifier-free
// measurements. Alert when the lag stays above a minute: Console figures
// are falling behind.
func NewNetworkSummaryWorkerMetricsCollector(worker *networksummary.Worker) (prometheus.Collector, error) {
	if worker == nil {
		return nil, ErrInvalidNetworkSummaryWorkerMetrics
	}
	counter := func(name, help string, value func(networksummary.Measurements) uint64) networkSummaryCounter {
		return networkSummaryCounter{descriptor: prometheus.NewDesc(name, help, nil, nil), value: value}
	}
	return &networkSummaryWorkerMetricsCollector{worker: worker,
		running: prometheus.NewDesc("meshtransit_network_summary_worker_running",
			"Whether the configured Network summary worker is running.", nil, nil),
		pending: prometheus.NewDesc("meshtransit_network_summary_pending",
			"Networks whose summary waits for a change to be counted, read every 15 s.", nil, nil),
		marks: prometheus.NewDesc("meshtransit_network_summary_marks",
			"Changes not yet folded into the summary queue (counted up to 100 000), read every 15 s.", nil, nil),
		lag: prometheus.NewDesc("meshtransit_network_summary_lag_seconds",
			"Age of the oldest change not yet in a Network summary, read every 15 s.", nil, nil),
		computing: prometheus.NewDesc("meshtransit_network_summary_compute_seconds_total",
			"Total time spent counting Network summaries.", nil, nil),
		counters: []networkSummaryCounter{
			counter("meshtransit_network_summary_worker_passes_total", "Total Network summary claim passes.",
				func(m networksummary.Measurements) uint64 { return m.Passes }),
			counter("meshtransit_network_summary_worker_claimed_total", "Total Networks claimed for counting.",
				func(m networksummary.Measurements) uint64 { return m.Claimed }),
			counter("meshtransit_network_summary_worker_stored_total", "Total Network summaries stored.",
				func(m networksummary.Measurements) uint64 { return m.Stored }),
			counter("meshtransit_network_summary_worker_stale_total",
				"Total counts not stored because a newer summary was already stored.",
				func(m networksummary.Measurements) uint64 { return m.Stale }),
			counter("meshtransit_network_summary_worker_gone_total", "Total claimed Networks that no longer exist.",
				func(m networksummary.Measurements) uint64 { return m.Gone }),
			counter("meshtransit_network_summary_worker_failures_total", "Total failed claims, counts or stores.",
				func(m networksummary.Measurements) uint64 { return m.Failed }),
		},
	}, nil
}

func (collector *networkSummaryWorkerMetricsCollector) Describe(descriptions chan<- *prometheus.Desc) {
	descriptions <- collector.running
	descriptions <- collector.pending
	descriptions <- collector.lag
	descriptions <- collector.marks
	descriptions <- collector.computing
	for _, counter := range collector.counters {
		descriptions <- counter.descriptor
	}
}

func (collector *networkSummaryWorkerMetricsCollector) Collect(metrics chan<- prometheus.Metric) {
	snapshot := collector.worker.Snapshot()
	running := 0.0
	if snapshot.Running {
		running = 1
	}
	metrics <- prometheus.MustNewConstMetric(collector.running, prometheus.GaugeValue, running)
	metrics <- prometheus.MustNewConstMetric(collector.pending, prometheus.GaugeValue, float64(snapshot.Pending))
	metrics <- prometheus.MustNewConstMetric(collector.lag, prometheus.GaugeValue, snapshot.Lag.Seconds())
	metrics <- prometheus.MustNewConstMetric(collector.marks, prometheus.GaugeValue, float64(snapshot.Marks))
	metrics <- prometheus.MustNewConstMetric(collector.computing, prometheus.CounterValue, snapshot.Computing.Seconds())
	for _, counter := range collector.counters {
		metrics <- prometheus.MustNewConstMetric(counter.descriptor, prometheus.CounterValue,
			float64(counter.value(snapshot)))
	}
}
