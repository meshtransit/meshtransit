package httpapi

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"

	"meshtransit.net/core/internal/domain/kubeca/lifecycle"
)

// ErrInvalidKubernetesCAWorkerMetrics reports a missing owned worker source.
var ErrInvalidKubernetesCAWorkerMetrics = errors.New("invalid Kubernetes CA worker metrics")

type kubernetesCAWorkerMetricsCollector struct {
	worker  *lifecycle.Worker
	gauges  []kubernetesCAGauge
	counter []kubernetesCACounter
}

type kubernetesCAGauge struct {
	descriptor *prometheus.Desc
	value      func(lifecycle.Measurements) bool
}

type kubernetesCACounter struct {
	descriptor *prometheus.Desc
	value      func(lifecycle.Measurements) uint64
}

// NewKubernetesCAWorkerMetricsCollector exposes fixed, identifier-free
// measurements of the Kubernetes CA worker. Alert on custody not ready, a
// suffix mismatch, or failures that keep growing (K1a4 §17.3).
func NewKubernetesCAWorkerMetricsCollector(worker *lifecycle.Worker) (prometheus.Collector, error) {
	if worker == nil {
		return nil, ErrInvalidKubernetesCAWorkerMetrics
	}
	gauge := func(name, help string, value func(lifecycle.Measurements) bool) kubernetesCAGauge {
		return kubernetesCAGauge{descriptor: prometheus.NewDesc(name, help, nil, nil), value: value}
	}
	counter := func(name, help string, value func(lifecycle.Measurements) uint64) kubernetesCACounter {
		return kubernetesCACounter{descriptor: prometheus.NewDesc(name, help, nil, nil), value: value}
	}
	return &kubernetesCAWorkerMetricsCollector{
		worker: worker,
		gauges: []kubernetesCAGauge{
			gauge("meshtransit_kubernetes_ca_worker_running", "Whether the Kubernetes CA worker is running.",
				func(m lifecycle.Measurements) bool { return m.Running }),
			gauge("meshtransit_kubernetes_ca_custody_ready", "Whether the worker holds its CA key custody.",
				func(m lifecycle.Measurements) bool { return m.CustodyReady }),
			gauge("meshtransit_kubernetes_ca_suffix_mismatch",
				"Whether the worker's DNS suffix differs from the recorded one, which stops all CA work.",
				func(m lifecycle.Measurements) bool { return m.SuffixMismatch }),
			gauge("meshtransit_kubernetes_ca_restore_suspected",
				"Whether CA work is stopped because the database looks restored, until an operator reconciles.",
				func(m lifecycle.Measurements) bool { return m.RestoreSuspected }),
			gauge("meshtransit_kubernetes_ca_restore_marks_unavailable",
				"Whether the worker could not compare its restore marks kept in Redis: the restore tripwire is off.",
				func(m lifecycle.Measurements) bool { return m.MarksUnavailable }),
		},
		counter: []kubernetesCACounter{
			counter("meshtransit_kubernetes_ca_worker_passes_total", "Total Kubernetes CA worker passes.",
				func(m lifecycle.Measurements) uint64 { return m.Passes }),
			counter("meshtransit_kubernetes_ca_networks_total", "Total Networks the CA worker looked at.",
				func(m lifecycle.Measurements) uint64 { return m.Networks }),
			counter("meshtransit_kubernetes_ca_changes_total", "Total Network CA changes applied.",
				func(m lifecycle.Measurements) uint64 { return m.Changed }),
			counter("meshtransit_kubernetes_ca_plan_changed_total",
				"Total prepared CA changes dropped because the Network changed meanwhile.",
				func(m lifecycle.Measurements) uint64 { return m.PlanChanged }),
			counter("meshtransit_kubernetes_ca_failures_total", "Total Network CA changes that failed and were postponed.",
				func(m lifecycle.Measurements) uint64 { return m.Failures }),
			counter("meshtransit_kubernetes_ca_created_total", "Total cluster CAs created.",
				func(m lifecycle.Measurements) uint64 { return m.Created }),
			counter("meshtransit_kubernetes_ca_moved_total", "Total cluster CA state changes.",
				func(m lifecycle.Measurements) uint64 { return m.Moved }),
			counter("meshtransit_kubernetes_ca_busy_total",
				"Total Networks skipped because another worker or an operator held them.",
				func(m lifecycle.Measurements) uint64 { return m.Busy }),
			counter("meshtransit_kubernetes_ca_misnamed_total",
				"Total looks at clusters whose roots sign for another name; only an operator renames them.",
				func(m lifecycle.Measurements) uint64 { return m.Misnamed }),
			counter("meshtransit_kubernetes_ca_retire_requests_done_total",
				"Total requests to retire a CA the worker carried out.",
				func(m lifecycle.Measurements) uint64 { return m.Retired }),
			counter("meshtransit_kubernetes_ca_retire_requests_refused_total",
				"Total requests to retire a CA the worker refused: expired, changed, guard or gone.",
				func(m lifecycle.Measurements) uint64 { return m.RetireRefused }),
		},
	}, nil
}

func (collector *kubernetesCAWorkerMetricsCollector) Describe(descriptions chan<- *prometheus.Desc) {
	for _, gauge := range collector.gauges {
		descriptions <- gauge.descriptor
	}
	for _, counter := range collector.counter {
		descriptions <- counter.descriptor
	}
}

func (collector *kubernetesCAWorkerMetricsCollector) Collect(metrics chan<- prometheus.Metric) {
	snapshot := collector.worker.Snapshot()
	for _, gauge := range collector.gauges {
		value := 0.0
		if gauge.value(snapshot) {
			value = 1
		}
		metrics <- prometheus.MustNewConstMetric(gauge.descriptor, prometheus.GaugeValue, value)
	}
	for _, counter := range collector.counter {
		metrics <- prometheus.MustNewConstMetric(counter.descriptor, prometheus.CounterValue,
			float64(counter.value(snapshot)))
	}
}
