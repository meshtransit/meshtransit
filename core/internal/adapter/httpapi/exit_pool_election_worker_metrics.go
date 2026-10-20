package httpapi

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"

	"meshtransit.net/core/internal/domain/primaryelection"
)

// ErrInvalidExitPoolElectionWorkerMetrics rejects a missing worker.
var ErrInvalidExitPoolElectionWorkerMetrics = errors.New("invalid Exit Pool election worker metrics")

type exitPoolElectionCounter struct {
	descriptor *prometheus.Desc
	value      func(primaryelection.Measurements) uint64
}

type exitPoolElectionWorkerMetricsCollector struct {
	worker  *primaryelection.Worker
	running *prometheus.Desc
	counter []exitPoolElectionCounter
	pools   *prometheus.Desc
	nodes   *prometheus.Desc
}

// exitNodeStates names exit node statuses for the nodes gauge.
var exitNodeStates = map[primaryelection.Status]string{
	primaryelection.StatusUsable: "usable", primaryelection.StatusHoldDown: "hold_down",
	primaryelection.StatusDraining: "draining", primaryelection.StatusFailed: "failed",
	primaryelection.StatusIneligible: "ineligible",
}

// NewExitPoolElectionWorkerMetricsCollector exposes identifier-free Exit
// Pool election measurements.
func NewExitPoolElectionWorkerMetricsCollector(worker *primaryelection.Worker) (prometheus.Collector, error) {
	if worker == nil {
		return nil, ErrInvalidExitPoolElectionWorkerMetrics
	}
	counter := func(name, help string, value func(primaryelection.Measurements) uint64) exitPoolElectionCounter {
		return exitPoolElectionCounter{descriptor: prometheus.NewDesc(name, help, nil, nil), value: value}
	}
	// Alert: meshtransit_exit_pool_election_pools{state=~"degraded|unserved"}
	// > 0 for 5m means an Exit Pool no exit node can serve.
	return &exitPoolElectionWorkerMetricsCollector{worker: worker,
		pools: prometheus.NewDesc("meshtransit_exit_pool_election_pools",
			"Exit Pools by whether an exit node can serve them, at the last sweep that read health.",
			[]string{"state"}, nil),
		nodes: prometheus.NewDesc("meshtransit_exit_pool_election_nodes",
			"Exit nodes by status, at the last sweep that read health.", []string{"state"}, nil),
		running: prometheus.NewDesc("meshtransit_exit_pool_election_worker_running",
			"Whether the Exit Pool election worker is running.", nil, nil),
		counter: []exitPoolElectionCounter{
			counter("meshtransit_exit_pool_election_worker_passes_total", "Total Exit Pool election passes.",
				func(m primaryelection.Measurements) uint64 { return m.Passes }),
			counter("meshtransit_exit_pool_election_worker_read_errors_total",
				"Total failed Exit Pool or health reads.",
				func(m primaryelection.Measurements) uint64 { return m.ReadErrors }),
			counter("meshtransit_exit_pool_election_worker_elections_total", "Total primaries recorded.",
				func(m primaryelection.Measurements) uint64 { return m.Elections }),
			counter("meshtransit_exit_pool_election_worker_write_errors_total", "Total failed primary records.",
				func(m primaryelection.Measurements) uint64 { return m.WriteErrors }),
		},
	}, nil
}

func (collector *exitPoolElectionWorkerMetricsCollector) Describe(descriptions chan<- *prometheus.Desc) {
	descriptions <- collector.running
	descriptions <- collector.pools
	descriptions <- collector.nodes
	for _, counter := range collector.counter {
		descriptions <- counter.descriptor
	}
}

func (collector *exitPoolElectionWorkerMetricsCollector) Collect(metrics chan<- prometheus.Metric) {
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
	if snapshot.Tally == nil {
		return
	}
	for state, count := range map[string]uint64{"served": snapshot.Tally.GroupsServed,
		"degraded": snapshot.Tally.GroupsDegraded, "unserved": snapshot.Tally.GroupsUnserved} {
		metrics <- prometheus.MustNewConstMetric(collector.pools, prometheus.GaugeValue, float64(count), state)
	}
	for status, state := range exitNodeStates {
		metrics <- prometheus.MustNewConstMetric(collector.nodes, prometheus.GaugeValue,
			float64(snapshot.Tally.Members[status]), state)
	}
}
