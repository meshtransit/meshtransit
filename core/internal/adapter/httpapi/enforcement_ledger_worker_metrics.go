package httpapi

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"

	"meshtransit.net/core/internal/domain/node/enforcementledger"
)

// ErrInvalidEnforcementLedgerWorkerMetrics rejects a missing worker.
var ErrInvalidEnforcementLedgerWorkerMetrics = errors.New("invalid enforcement ledger worker metrics")

type enforcementLedgerCounter struct {
	descriptor *prometheus.Desc
	value      func(enforcementledger.Measurements) uint64
}

type enforcementLedgerWorkerMetricsCollector struct {
	worker  *enforcementledger.Worker
	running *prometheus.Desc
	counter []enforcementLedgerCounter
}

// NewEnforcementLedgerWorkerMetricsCollector exposes identifier-free worker
// measurements.
func NewEnforcementLedgerWorkerMetricsCollector(worker *enforcementledger.Worker) (prometheus.Collector, error) {
	if worker == nil {
		return nil, ErrInvalidEnforcementLedgerWorkerMetrics
	}
	counter := func(name, help string, value func(enforcementledger.Measurements) uint64) enforcementLedgerCounter {
		return enforcementLedgerCounter{descriptor: prometheus.NewDesc(name, help, nil, nil), value: value}
	}
	// Alert: rate(meshtransit_enforcement_ledger_worker_audited_total[15m]) > 0 means a Device
	// started or stopped enforcing other rules than it was given.
	return &enforcementLedgerWorkerMetricsCollector{worker: worker,
		running: prometheus.NewDesc("meshtransit_enforcement_ledger_worker_running",
			"Whether the configured enforcement ledger worker is running.", nil, nil),
		counter: []enforcementLedgerCounter{
			counter("meshtransit_enforcement_ledger_worker_passes_total", "Total enforcement ledger passes.",
				func(m enforcementledger.Measurements) uint64 { return m.Passes }),
			counter("meshtransit_enforcement_ledger_worker_read_errors_total", "Total failed enforcement ledger reads.",
				func(m enforcementledger.Measurements) uint64 { return m.ReadErrors }),
			counter("meshtransit_enforcement_ledger_worker_recorded_total", "Total enforcement intervals opened.",
				func(m enforcementledger.Measurements) uint64 { return m.Recorded }),
			counter("meshtransit_enforcement_ledger_worker_audited_total",
				"Total sealed enforcement mismatch and restore events.",
				func(m enforcementledger.Measurements) uint64 { return m.Audited }),
			counter("meshtransit_enforcement_ledger_worker_unchanged_total",
				"Total observations already recorded by another pass.",
				func(m enforcementledger.Measurements) uint64 { return m.Unchanged }),
			counter("meshtransit_enforcement_ledger_worker_deferred_total", "Total deferred enforcement records.",
				func(m enforcementledger.Measurements) uint64 { return m.Deferred }),
			counter("meshtransit_enforcement_ledger_worker_pruned_total", "Total rows removed past retention.",
				func(m enforcementledger.Measurements) uint64 { return m.Pruned }),
			counter("meshtransit_enforcement_ledger_worker_prune_errors_total", "Total failed retention rounds.",
				func(m enforcementledger.Measurements) uint64 { return m.PruneErrors }),
		},
	}, nil
}

func (collector *enforcementLedgerWorkerMetricsCollector) Describe(descriptions chan<- *prometheus.Desc) {
	descriptions <- collector.running
	for _, counter := range collector.counter {
		descriptions <- counter.descriptor
	}
}

func (collector *enforcementLedgerWorkerMetricsCollector) Collect(metrics chan<- prometheus.Metric) {
	snapshot := collector.worker.Snapshot()
	running := 0.0
	if snapshot.Running {
		running = 1
	}
	metrics <- prometheus.MustNewConstMetric(collector.running, prometheus.GaugeValue, running)
	for _, counter := range collector.counter {
		metrics <- prometheus.MustNewConstMetric(counter.descriptor, prometheus.CounterValue,
			float64(counter.value(snapshot)))
	}
}
