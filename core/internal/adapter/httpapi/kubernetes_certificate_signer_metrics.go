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
	worker                                 *signing.Worker
	running, suspended, unchecked, pending *prometheus.Desc
	issued, requeued, released             *prometheus.Desc
	lost, failures, refused                *prometheus.Desc
	fleet, struggling, measured            *prometheus.Desc
}

// NewKubernetesCertificateSignerMetricsCollector exposes fixed,
// identifier-free measurements of the gateway certificate signer (a3 §6).
// Alert on a signer suspended while requests wait, on a queue that keeps
// growing, and on failures or refusals for token, proof or revoked that
// climb. The fleet gauges cover every gateway replica, in clusters an
// operator cannot scrape (a4d). Every worker replica exports the whole
// fleet: aggregate with max(), never sum(). Alert on struggling replicas
// above 0 for 30 minutes, on max_over_time of it over an hour above 0 for 2
// hours (a backing-off gateway asks once an hour), and on a scan older than
// 15 minutes.
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
			"Whether the signer signs nothing: no custody, a restore suspected, the restore tripwire not checked lately, or another DNS suffix."),
		unchecked: describe("meshtransit_kubernetes_certificate_signer_tripwire_unchecked",
			"Whether signing waits because the restore tripwire was not checked in the last 10 minutes."),
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
		fleet: describe("meshtransit_kubernetes_gateway_replicas_by_certificate",
			"Active gateway replicas of active clusters by their latest certificate: valid, expiring within 10 hours, or missing (none or expired; a replica scaled to zero stays missing).",
			"state"),
		struggling: describe("meshtransit_kubernetes_gateway_replicas_struggling",
			"Gateway replicas that asked within 10 minutes and got no certificate: refused, waiting over a minute, or still none or one expiring within 10 hours."),
		measured: describe("meshtransit_kubernetes_gateway_fleet_measured_timestamp_seconds",
			"When the signer last counted the gateway fleet (Unix seconds); 0: not yet."),
	}, nil
}

func (collector *kubernetesCertificateSignerMetricsCollector) Describe(descriptions chan<- *prometheus.Desc) {
	for _, descriptor := range []*prometheus.Desc{
		collector.running, collector.suspended, collector.unchecked, collector.pending, collector.issued, collector.requeued,
		collector.released, collector.lost, collector.failures, collector.refused, collector.fleet, collector.struggling,
		collector.measured,
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
		flag(!snapshot.CustodyReady || snapshot.Suspected || snapshot.Unchecked || snapshot.SuffixMismatch))
	metrics <- prometheus.MustNewConstMetric(collector.unchecked, prometheus.GaugeValue, flag(snapshot.Unchecked))
	metrics <- prometheus.MustNewConstMetric(collector.pending, prometheus.GaugeValue, float64(snapshot.Pending))
	for descriptor, value := range map[*prometheus.Desc]uint64{
		collector.issued: snapshot.Issued, collector.requeued: snapshot.Requeued, collector.released: snapshot.Released,
		collector.lost: snapshot.Lost, collector.failures: snapshot.Failures,
	} {
		metrics <- prometheus.MustNewConstMetric(descriptor, prometheus.CounterValue, float64(value))
	}
	fleet := snapshot.Fleet
	for state, count := range map[string]int64{"valid": fleet.Valid, "expiring": fleet.Expiring, "missing": fleet.Missing} {
		metrics <- prometheus.MustNewConstMetric(collector.fleet, prometheus.GaugeValue, float64(count), state)
	}
	metrics <- prometheus.MustNewConstMetric(collector.struggling, prometheus.GaugeValue, float64(fleet.Struggling))
	measured := 0.0
	if !fleet.MeasuredAt.IsZero() {
		measured = float64(fleet.MeasuredAt.Unix())
	}
	metrics <- prometheus.MustNewConstMetric(collector.measured, prometheus.GaugeValue, measured)
	for _, reason := range signing.KnownReasons {
		metrics <- prometheus.MustNewConstMetric(collector.refused, prometheus.CounterValue,
			float64(snapshot.Refused[reason]), string(reason))
	}
}
