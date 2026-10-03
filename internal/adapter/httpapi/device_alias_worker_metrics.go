package httpapi

import (
	"errors"

	"github.com/meshtransit/meshtransit/internal/sharing/devicealias"
	"github.com/prometheus/client_golang/prometheus"
)

// ErrInvalidDeviceAliasWorkerMetrics reports a missing owned worker source.
var ErrInvalidDeviceAliasWorkerMetrics = errors.New("invalid Device alias worker metrics")

type deviceAliasWorkerMetricsCollector struct {
	worker                                              *devicealias.Worker
	running, passes, discoveryErrors, changed, deferred *prometheus.Desc
}

// NewDeviceAliasWorkerMetricsCollector exposes fixed, identifier-free measurements.
func NewDeviceAliasWorkerMetricsCollector(worker *devicealias.Worker) (prometheus.Collector, error) {
	if worker == nil {
		return nil, ErrInvalidDeviceAliasWorkerMetrics
	}
	return &deviceAliasWorkerMetricsCollector{worker: worker,
		running:         prometheus.NewDesc("meshtransit_device_alias_worker_running", "Whether the configured Device alias worker is running.", nil, nil),
		passes:          prometheus.NewDesc("meshtransit_device_alias_worker_passes_total", "Total finite Device alias discovery passes.", nil, nil),
		discoveryErrors: prometheus.NewDesc("meshtransit_device_alias_worker_discovery_errors_total", "Total failed or invalid Device alias discovery pages.", nil, nil),
		changed:         prometheus.NewDesc("meshtransit_device_alias_worker_changes_total", "Total successfully committed Device alias lifecycle changes.", nil, nil),
		deferred:        prometheus.NewDesc("meshtransit_device_alias_worker_deferred_total", "Total deferred Device alias lifecycle changes.", nil, nil),
	}, nil
}

func (collector *deviceAliasWorkerMetricsCollector) Describe(descriptions chan<- *prometheus.Desc) {
	for _, descriptor := range []*prometheus.Desc{collector.running, collector.passes, collector.discoveryErrors, collector.changed, collector.deferred} {
		descriptions <- descriptor
	}
}

func (collector *deviceAliasWorkerMetricsCollector) Collect(metrics chan<- prometheus.Metric) {
	snapshot := collector.worker.Snapshot()
	running := 0.0
	if snapshot.Running {
		running = 1
	}
	metrics <- prometheus.MustNewConstMetric(collector.running, prometheus.GaugeValue, running)
	for _, measurement := range []struct {
		descriptor *prometheus.Desc
		value      uint64
	}{{collector.passes, snapshot.Passes}, {collector.discoveryErrors, snapshot.DiscoveryErrors}, {collector.changed, snapshot.Changed}, {collector.deferred, snapshot.Deferred}} {
		metrics <- prometheus.MustNewConstMetric(measurement.descriptor, prometheus.CounterValue, float64(measurement.value))
	}
}
