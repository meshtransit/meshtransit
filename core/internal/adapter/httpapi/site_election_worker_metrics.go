package httpapi

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"

	"meshtransit.net/core/internal/domain/site/election"
)

// ErrInvalidSiteElectionWorkerMetrics rejects a missing worker.
var ErrInvalidSiteElectionWorkerMetrics = errors.New("invalid Site election worker metrics")

type siteElectionCounter struct {
	descriptor *prometheus.Desc
	value      func(election.Measurements) uint64
}

type siteElectionWorkerMetricsCollector struct {
	worker  *election.Worker
	running *prometheus.Desc
	counter []siteElectionCounter
}

// NewSiteElectionWorkerMetricsCollector exposes identifier-free worker
// measurements.
func NewSiteElectionWorkerMetricsCollector(worker *election.Worker) (prometheus.Collector, error) {
	if worker == nil {
		return nil, ErrInvalidSiteElectionWorkerMetrics
	}
	counter := func(name, help string, value func(election.Measurements) uint64) siteElectionCounter {
		return siteElectionCounter{descriptor: prometheus.NewDesc(name, help, nil, nil), value: value}
	}
	// Alert: rate(meshtransit_site_election_worker_elections_total[15m]) > 0
	// means a Site's primary router changed.
	return &siteElectionWorkerMetricsCollector{worker: worker,
		running: prometheus.NewDesc("meshtransit_site_election_worker_running",
			"Whether the Site election worker is running.", nil, nil),
		counter: []siteElectionCounter{
			counter("meshtransit_site_election_worker_passes_total", "Total Site election passes.",
				func(m election.Measurements) uint64 { return m.Passes }),
			counter("meshtransit_site_election_worker_read_errors_total", "Total failed Site or health reads.",
				func(m election.Measurements) uint64 { return m.ReadErrors }),
			counter("meshtransit_site_election_worker_elections_total", "Total primaries recorded.",
				func(m election.Measurements) uint64 { return m.Elections }),
			counter("meshtransit_site_election_worker_write_errors_total", "Total failed primary records.",
				func(m election.Measurements) uint64 { return m.WriteErrors }),
		},
	}, nil
}

func (collector *siteElectionWorkerMetricsCollector) Describe(descriptions chan<- *prometheus.Desc) {
	descriptions <- collector.running
	for _, counter := range collector.counter {
		descriptions <- counter.descriptor
	}
}

func (collector *siteElectionWorkerMetricsCollector) Collect(metrics chan<- prometheus.Metric) {
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
