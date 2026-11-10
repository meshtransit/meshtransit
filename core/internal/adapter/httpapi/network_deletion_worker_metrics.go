package httpapi

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
	"meshtransit.net/core/internal/domain/network/deletion"
)

// ErrInvalidNetworkDeletionWorkerMetrics reports a missing owned worker source.
var ErrInvalidNetworkDeletionWorkerMetrics = errors.New("invalid network deletion worker metrics")

type networkDeletionWorkerMetricsCollector struct {
	worker                             *deletion.Worker
	running, pending, lag              *prometheus.Desc
	steps, revoked, completed, failure *prometheus.Desc
}

// NewNetworkDeletionWorkerMetricsCollector exposes fixed, identifier-free
// measurements. Alert when the lag passes an hour: a deleted Network's
// Devices and prefixes are not being released.
func NewNetworkDeletionWorkerMetricsCollector(worker *deletion.Worker) (prometheus.Collector, error) {
	if worker == nil {
		return nil, ErrInvalidNetworkDeletionWorkerMetrics
	}
	describe := func(name, help string) *prometheus.Desc { return prometheus.NewDesc(name, help, nil, nil) }
	return &networkDeletionWorkerMetricsCollector{worker: worker,
		running: describe("meshtransit_network_deletion_worker_running",
			"Whether the configured Network deletion worker is running."),
		pending: describe("meshtransit_network_deletion_pending", "Network deletions not finished yet."),
		lag:     describe("meshtransit_network_deletion_lag_seconds", "Age of the oldest unfinished Network deletion."),
		steps:   describe("meshtransit_network_deletion_worker_steps_total", "Total deletion steps committed."),
		revoked: describe("meshtransit_network_deletion_worker_devices_revoked_total",
			"Total Devices revoked because their Network was deleted."),
		completed: describe("meshtransit_network_deletion_worker_completed_total",
			"Total Network deletions completed."),
		failure: describe("meshtransit_network_deletion_worker_failures_total", "Total failed deletion steps."),
	}, nil
}

func (collector *networkDeletionWorkerMetricsCollector) Describe(descriptions chan<- *prometheus.Desc) {
	for _, description := range []*prometheus.Desc{collector.running, collector.pending, collector.lag,
		collector.steps, collector.revoked, collector.completed, collector.failure} {
		descriptions <- description
	}
}

func (collector *networkDeletionWorkerMetricsCollector) Collect(metrics chan<- prometheus.Metric) {
	snapshot := collector.worker.Snapshot()
	running := 0.0
	if snapshot.Running {
		running = 1
	}
	gauge := func(description *prometheus.Desc, value float64) {
		metrics <- prometheus.MustNewConstMetric(description, prometheus.GaugeValue, value)
	}
	counter := func(description *prometheus.Desc, value uint64) {
		metrics <- prometheus.MustNewConstMetric(description, prometheus.CounterValue, float64(value))
	}
	gauge(collector.running, running)
	gauge(collector.pending, float64(snapshot.Pending))
	gauge(collector.lag, snapshot.Lag.Seconds())
	counter(collector.steps, snapshot.Steps)
	counter(collector.revoked, snapshot.Revoked)
	counter(collector.completed, snapshot.Completed)
	counter(collector.failure, snapshot.Failures)
}

// NewSignedOutDeviceWorkerMetricsCollector exposes the worker that removes
// Devices signed out past their hold (schema 284). Alert when the lag
// passes a day: such Devices keep their addresses and names.
func NewSignedOutDeviceWorkerMetricsCollector(worker *deletion.Worker) (prometheus.Collector, error) {
	if worker == nil {
		return nil, ErrInvalidNetworkDeletionWorkerMetrics
	}
	describe := func(name, help string) *prometheus.Desc { return prometheus.NewDesc(name, help, nil, nil) }
	return &networkDeletionWorkerMetricsCollector{worker: worker,
		running: describe("meshtransit_signed_out_device_worker_running",
			"Whether the configured signed-out Device worker is running."),
		pending: describe("meshtransit_signed_out_devices_due", "Devices signed out past their hold, not removed yet."),
		lag: describe("meshtransit_signed_out_devices_due_lag_seconds",
			"How long the longest-due signed-out Device has waited past its hold."),
		steps: describe("meshtransit_signed_out_device_worker_steps_total", "Total removal steps committed."),
		revoked: describe("meshtransit_signed_out_device_worker_devices_revoked_total",
			"Total Devices removed because they stayed signed out past their hold."),
		completed: describe("meshtransit_signed_out_device_worker_completed_total",
			"Unused by this worker; always zero."),
		failure: describe("meshtransit_signed_out_device_worker_failures_total", "Total failed removal steps."),
	}, nil
}
