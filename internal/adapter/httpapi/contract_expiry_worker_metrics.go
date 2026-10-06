package httpapi

import (
	"errors"

	"github.com/meshtransit/meshtransit/internal/sharing/contractexpiry"
	"github.com/prometheus/client_golang/prometheus"
)

// ErrInvalidContractExpiryWorkerMetrics reports a missing owned worker source.
var ErrInvalidContractExpiryWorkerMetrics = errors.New("invalid Trust Contract expiry worker metrics")

type contractExpiryWorkerMetricsCollector struct {
	worker                                              *contractexpiry.Worker
	running, passes, discoveryErrors, expired, deferred *prometheus.Desc
}

// NewContractExpiryWorkerMetricsCollector exposes fixed, identifier-free
// measurements. A growing deferred count means names are not being released.
func NewContractExpiryWorkerMetricsCollector(worker *contractexpiry.Worker) (prometheus.Collector, error) {
	if worker == nil {
		return nil, ErrInvalidContractExpiryWorkerMetrics
	}
	return &contractExpiryWorkerMetricsCollector{worker: worker,
		running:         prometheus.NewDesc("meshtransit_contract_expiry_worker_running", "Whether the configured Trust Contract expiry worker is running.", nil, nil),
		passes:          prometheus.NewDesc("meshtransit_contract_expiry_worker_passes_total", "Total finite Trust Contract expiry discovery passes.", nil, nil),
		discoveryErrors: prometheus.NewDesc("meshtransit_contract_expiry_worker_discovery_errors_total", "Total failed or invalid Trust Contract expiry discovery pages.", nil, nil),
		expired:         prometheus.NewDesc("meshtransit_contract_expiry_worker_expired_total", "Total Trust Contracts finalized as expired.", nil, nil),
		deferred:        prometheus.NewDesc("meshtransit_contract_expiry_worker_deferred_total", "Total deferred Trust Contract expiry finalizations.", nil, nil),
	}, nil
}

func (collector *contractExpiryWorkerMetricsCollector) Describe(descriptions chan<- *prometheus.Desc) {
	for _, descriptor := range []*prometheus.Desc{collector.running, collector.passes, collector.discoveryErrors, collector.expired, collector.deferred} {
		descriptions <- descriptor
	}
}

func (collector *contractExpiryWorkerMetricsCollector) Collect(metrics chan<- prometheus.Metric) {
	snapshot := collector.worker.Snapshot()
	running := 0.0
	if snapshot.Running {
		running = 1
	}
	metrics <- prometheus.MustNewConstMetric(collector.running, prometheus.GaugeValue, running)
	for _, measurement := range []struct {
		descriptor *prometheus.Desc
		value      uint64
	}{{collector.passes, snapshot.Passes}, {collector.discoveryErrors, snapshot.DiscoveryErrors}, {collector.expired, snapshot.Expired}, {collector.deferred, snapshot.Deferred}} {
		metrics <- prometheus.MustNewConstMetric(measurement.descriptor, prometheus.CounterValue, float64(measurement.value))
	}
}
