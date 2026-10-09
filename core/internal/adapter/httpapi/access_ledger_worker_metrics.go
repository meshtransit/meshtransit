package httpapi

import (
	"errors"

	"github.com/meshtransit/meshtransit/core/internal/domain/accessgraph/ledger"
	"github.com/prometheus/client_golang/prometheus"
)

// ErrInvalidAccessLedgerWorkerMetrics reports a missing owned worker source.
var ErrInvalidAccessLedgerWorkerMetrics = errors.New("invalid access ledger worker metrics")

type accessLedgerWorkerMetricsCollector struct {
	worker  *ledger.Worker
	running *prometheus.Desc
	counter []accessLedgerCounter
}

type accessLedgerCounter struct {
	descriptor *prometheus.Desc
	value      func(ledger.Measurements) uint64
}

// NewAccessLedgerWorkerMetricsCollector exposes fixed, identifier-free
// measurements. A growing deferred count means history is falling behind.
func NewAccessLedgerWorkerMetricsCollector(worker *ledger.Worker) (prometheus.Collector, error) {
	if worker == nil {
		return nil, ErrInvalidAccessLedgerWorkerMetrics
	}
	counter := func(name, help string, value func(ledger.Measurements) uint64) accessLedgerCounter {
		return accessLedgerCounter{descriptor: prometheus.NewDesc(name, help, nil, nil), value: value}
	}
	return &accessLedgerWorkerMetricsCollector{worker: worker,
		running: prometheus.NewDesc("meshtransit_access_ledger_worker_running", "Whether the configured access ledger worker is running.", nil, nil),
		counter: []accessLedgerCounter{
			counter("meshtransit_access_ledger_worker_passes_total", "Total access ledger discovery passes.",
				func(m ledger.Measurements) uint64 { return m.Passes }),
			counter("meshtransit_access_ledger_worker_discovery_errors_total", "Total failed access ledger discovery passes.",
				func(m ledger.Measurements) uint64 { return m.DiscoveryErrors }),
			counter("meshtransit_access_ledger_worker_recorded_total", "Total sealed access edge snapshots.",
				func(m ledger.Measurements) uint64 { return m.Recorded }),
			counter("meshtransit_access_ledger_worker_unchanged_total", "Total revisions recorded without an edge change.",
				func(m ledger.Measurements) uint64 { return m.Unchanged }),
			counter("meshtransit_access_ledger_worker_deferred_total", "Total deferred access ledger records.",
				func(m ledger.Measurements) uint64 { return m.Deferred }),
			counter("meshtransit_access_ledger_worker_pruned_total", "Total ledger rows removed past retention.",
				func(m ledger.Measurements) uint64 { return m.Pruned }),
			counter("meshtransit_access_ledger_worker_prune_errors_total", "Total failed access ledger retention rounds.",
				func(m ledger.Measurements) uint64 { return m.PruneErrors }),
		},
	}, nil
}

func (collector *accessLedgerWorkerMetricsCollector) Describe(descriptions chan<- *prometheus.Desc) {
	descriptions <- collector.running
	for _, counter := range collector.counter {
		descriptions <- counter.descriptor
	}
}

func (collector *accessLedgerWorkerMetricsCollector) Collect(metrics chan<- prometheus.Metric) {
	snapshot := collector.worker.Snapshot()
	running := 0.0
	if snapshot.Running {
		running = 1
	}
	metrics <- prometheus.MustNewConstMetric(collector.running, prometheus.GaugeValue, running)
	for _, counter := range collector.counter {
		metrics <- prometheus.MustNewConstMetric(counter.descriptor, prometheus.CounterValue, float64(counter.value(snapshot)))
	}
}
