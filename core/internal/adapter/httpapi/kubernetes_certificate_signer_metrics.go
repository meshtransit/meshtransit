package httpapi

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"

	"meshtransit.net/core/internal/domain/kubeca/signing"
)

// ErrInvalidKubernetesCertificateSignerMetrics reports a missing owned
// worker source.
var ErrInvalidKubernetesCertificateSignerMetrics = errors.New("invalid Kubernetes certificate signer metrics")

type kubernetesCertificateSignerMetricsCollector struct {
	worker                      *signing.Worker
	running, suspended, pending *prometheus.Desc
	issued, requeued, released  *prometheus.Desc
	lost, failures, refused     *prometheus.Desc
}

// NewKubernetesCertificateSignerMetricsCollector exposes fixed,
// identifier-free measurements of the gateway certificate signer (a3 §6).
// Alert on a signer suspended while requests wait, on a queue that keeps
// growing, and on failures or refusals for token, proof or revoked that
// climb.
func NewKubernetesCertificateSignerMetricsCollector(worker *signing.Worker) (prometheus.Collector, error) {
	if worker == nil {
		return nil, ErrInvalidKubernetesCertificateSignerMetrics
	}
	describe := func(name, help string, labels ...string) *prometheus.Desc {
		return prometheus.NewDesc(name, help, labels, nil)
	}
	return &kubernetesCertificateSignerMetricsCollector{
		worker:  worker,
		running: describe("meshtransit_kubernetes_certificate_signer_running", "Whether the certificate signer runs."),
		suspended: describe("meshtransit_kubernetes_certificate_signer_suspended",
			"Whether the signer signs nothing: no custody, a restore suspected, or another DNS suffix."),
		pending: describe("meshtransit_kubernetes_certificate_queue_depth",
			"Gateway certificate requests waiting, as of the signer's last claim."),
		issued: describe("meshtransit_kubernetes_certificates_issued_total",
			"Total gateway replica certificates issued."),
		requeued: describe("meshtransit_kubernetes_certificate_signing_requeued_total",
			"Total certificates signed again because the intermediate changed meanwhile."),
		released: describe("meshtransit_kubernetes_certificate_signing_released_total",
			"Total requests given back unsigned (custody trouble, a restore suspected, the signer stopping)."),
		lost: describe("meshtransit_kubernetes_certificate_signing_lost_total",
			"Total requests whose claim ran out before they were settled."),
		failures: describe("meshtransit_kubernetes_certificate_signing_failures_total",
			"Total signing or store failures."),
		refused: describe("meshtransit_kubernetes_certificate_signing_refused_total",
			"Total gateway certificate requests refused, by reason.", "reason"),
	}, nil
}

func (collector *kubernetesCertificateSignerMetricsCollector) Describe(descriptions chan<- *prometheus.Desc) {
	for _, descriptor := range []*prometheus.Desc{
		collector.running, collector.suspended, collector.pending, collector.issued, collector.requeued,
		collector.released, collector.lost, collector.failures, collector.refused,
	} {
		descriptions <- descriptor
	}
}

func (collector *kubernetesCertificateSignerMetricsCollector) Collect(metrics chan<- prometheus.Metric) {
	snapshot := collector.worker.Snapshot()
	flag := func(value bool) float64 {
		if value {
			return 1
		}
		return 0
	}
	metrics <- prometheus.MustNewConstMetric(collector.running, prometheus.GaugeValue, flag(snapshot.Running))
	metrics <- prometheus.MustNewConstMetric(collector.suspended, prometheus.GaugeValue,
		flag(!snapshot.CustodyReady || snapshot.Suspected || snapshot.SuffixMismatch))
	metrics <- prometheus.MustNewConstMetric(collector.pending, prometheus.GaugeValue, float64(snapshot.Pending))
	for descriptor, value := range map[*prometheus.Desc]uint64{
		collector.issued: snapshot.Issued, collector.requeued: snapshot.Requeued, collector.released: snapshot.Released,
		collector.lost: snapshot.Lost, collector.failures: snapshot.Failures,
	} {
		metrics <- prometheus.MustNewConstMetric(descriptor, prometheus.CounterValue, float64(value))
	}
	for _, reason := range signing.KnownReasons {
		metrics <- prometheus.MustNewConstMetric(collector.refused, prometheus.CounterValue,
			float64(snapshot.Refused[reason]), string(reason))
	}
}
