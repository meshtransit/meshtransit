package httpapi

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
	"meshtransit.net/core/internal/domain/sharing/contractexpiry"
)

// ErrInvalidContractExpiryWorkerMetrics reports a missing owned worker source.
var ErrInvalidContractExpiryWorkerMetrics = errors.New("invalid Trust Contract expiry worker metrics")

type contractEndWorkerMetricsCollector struct {
	worker                                            *contractexpiry.Worker
	running, passes, discoveryErrors, ended, deferred *prometheus.Desc
}

// NewContractExpiryWorkerMetricsCollector exposes fixed, identifier-free
// measurements. A growing deferred count means names are not being released.
func NewContractExpiryWorkerMetricsCollector(worker *contractexpiry.Worker) (prometheus.Collector, error) {
	return newContractEndWorkerMetricsCollector(worker, "meshtransit_contract_expiry_worker_",
		"Trust Contract expiry", "expired_total", "Total Trust Contracts finalized as expired.")
}

// NewContractDeviceRemovalWorkerMetricsCollector measures the worker that ends
// shares of removed provider Devices. A growing deferred count means ended
// shares still hold their names and aliases.
func NewContractDeviceRemovalWorkerMetricsCollector(worker *contractexpiry.Worker) (prometheus.Collector, error) {
	return newContractEndWorkerMetricsCollector(worker, "meshtransit_contract_device_removal_worker_",
		"Trust Contract device removal", "ended_total", "Total Trust Contracts ended because their provider Device was removed.")
}

func newContractEndWorkerMetricsCollector(worker *contractexpiry.Worker, prefix, subject, endedName, endedHelp string) (prometheus.Collector, error) {
	if worker == nil {
		return nil, ErrInvalidContractExpiryWorkerMetrics
	}
	return &contractEndWorkerMetricsCollector{worker: worker,
		running:         prometheus.NewDesc(prefix+"running", "Whether the configured "+subject+" worker is running.", nil, nil),
		passes:          prometheus.NewDesc(prefix+"passes_total", "Total finite "+subject+" discovery passes.", nil, nil),
		discoveryErrors: prometheus.NewDesc(prefix+"discovery_errors_total", "Total failed or invalid "+subject+" discovery pages.", nil, nil),
		ended:           prometheus.NewDesc(prefix+endedName, endedHelp, nil, nil),
		deferred:        prometheus.NewDesc(prefix+"deferred_total", "Total deferred "+subject+" finalizations.", nil, nil),
	}, nil
}

func (collector *contractEndWorkerMetricsCollector) Describe(descriptions chan<- *prometheus.Desc) {
	for _, descriptor := range []*prometheus.Desc{collector.running, collector.passes, collector.discoveryErrors, collector.ended, collector.deferred} {
		descriptions <- descriptor
	}
}

func (collector *contractEndWorkerMetricsCollector) Collect(metrics chan<- prometheus.Metric) {
	snapshot := collector.worker.Snapshot()
	running := 0.0
	if snapshot.Running {
		running = 1
	}
	metrics <- prometheus.MustNewConstMetric(collector.running, prometheus.GaugeValue, running)
	for _, measurement := range []struct {
		descriptor *prometheus.Desc
		value      uint64
	}{{collector.passes, snapshot.Passes}, {collector.discoveryErrors, snapshot.DiscoveryErrors}, {collector.ended, snapshot.Ended}, {collector.deferred, snapshot.Deferred}} {
		metrics <- prometheus.MustNewConstMetric(measurement.descriptor, prometheus.CounterValue, float64(measurement.value))
	}
}
