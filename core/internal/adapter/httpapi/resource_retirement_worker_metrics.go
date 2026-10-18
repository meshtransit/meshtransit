package httpapi

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
	"meshtransit.net/core/internal/domain/resource/retirement"
)

// ErrInvalidResourceRetirementWorkerMetrics reports a missing owned worker source.
var ErrInvalidResourceRetirementWorkerMetrics = errors.New("invalid Resource retirement worker metrics")

type resourceRetirementWorkerMetricsCollector struct {
	worker                                                       *retirement.Worker
	running, passes, discoveryErrors, retired, deferred, blocked *prometheus.Desc
}

// NewResourceRetirementWorkerMetricsCollector exposes fixed, identifier-free
// measurements of the worker that retires the Resources of removed Devices.
// A growing deferred count means retired Devices still hold Resource names.
func NewResourceRetirementWorkerMetricsCollector(worker *retirement.Worker) (prometheus.Collector, error) {
	if worker == nil {
		return nil, ErrInvalidResourceRetirementWorkerMetrics
	}
	const prefix = "meshtransit_resource_retirement_worker_"
	return &resourceRetirementWorkerMetricsCollector{worker: worker,
		running:         prometheus.NewDesc(prefix+"running", "Whether the configured Resource retirement worker is running.", nil, nil),
		passes:          prometheus.NewDesc(prefix+"passes_total", "Total finite Resource retirement discovery passes.", nil, nil),
		discoveryErrors: prometheus.NewDesc(prefix+"discovery_errors_total", "Total failed or invalid Resource retirement discovery pages.", nil, nil),
		retired:         prometheus.NewDesc(prefix+"retired_total", "Total Resources retired because their Device was removed.", nil, nil),
		deferred:        prometheus.NewDesc(prefix+"deferred_total", "Total Resource retirements that failed and are retried.", nil, nil),
		blocked:         prometheus.NewDesc(prefix+"blocked_total", "Total Resource retirements postponed because a share, rule or Resource Group still uses the Resource.", nil, nil),
	}, nil
}

func (collector *resourceRetirementWorkerMetricsCollector) Describe(descriptions chan<- *prometheus.Desc) {
	for _, descriptor := range []*prometheus.Desc{collector.running, collector.passes, collector.discoveryErrors, collector.retired, collector.deferred, collector.blocked} {
		descriptions <- descriptor
	}
}

func (collector *resourceRetirementWorkerMetricsCollector) Collect(metrics chan<- prometheus.Metric) {
	snapshot := collector.worker.Snapshot()
	running := 0.0
	if snapshot.Running {
		running = 1
	}
	metrics <- prometheus.MustNewConstMetric(collector.running, prometheus.GaugeValue, running)
	for _, measurement := range []struct {
		descriptor *prometheus.Desc
		value      uint64
	}{{collector.passes, snapshot.Passes}, {collector.discoveryErrors, snapshot.DiscoveryErrors}, {collector.retired, snapshot.Retired}, {collector.deferred, snapshot.Deferred}, {collector.blocked, snapshot.Blocked}} {
		metrics <- prometheus.MustNewConstMetric(measurement.descriptor, prometheus.CounterValue, float64(measurement.value))
	}
}
