package httpapi

import (
	"github.com/prometheus/client_golang/prometheus"

	"meshtransit.net/core/internal/domain/network/revisionfeed"
)

type revisionFeedMetricsCollector struct {
	telemetry     *revisionfeed.Telemetry
	connectedDesc *prometheus.Desc
	watchersDesc  *prometheus.Desc
	wakeupsDesc   *prometheus.Desc
	fanoutDesc    *prometheus.Desc
	reconnectDesc *prometheus.Desc
}

// NewRevisionFeedMetricsCollector exposes bounded-cardinality subscriber and
// local fan-out health to the private operator registry.
func NewRevisionFeedMetricsCollector(
	telemetry *revisionfeed.Telemetry,
) (prometheus.Collector, error) {
	if telemetry == nil {
		return nil, ErrInvalidMetrics
	}
	return &revisionFeedMetricsCollector{
		telemetry: telemetry,
		connectedDesc: prometheus.NewDesc(
			"meshtransit_revision_feed_subscriber_connected",
			"Whether the process-owned Network revision subscription is connected.",
			nil,
			nil,
		),
		watchersDesc: prometheus.NewDesc(
			"meshtransit_revision_feed_watchers_active",
			"Number of active process-local Network revision watchers.",
			nil,
			nil,
		),
		wakeupsDesc: prometheus.NewDesc(
			"meshtransit_revision_feed_wakeups_received_total",
			"Total validated Network revision wakeups received from Redis.",
			nil,
			nil,
		),
		fanoutDesc: prometheus.NewDesc(
			"meshtransit_revision_feed_fanout_total",
			"Total local watcher notifications by bounded result.",
			[]string{"result"},
			nil,
		),
		reconnectDesc: prometheus.NewDesc(
			"meshtransit_revision_feed_reconnect_total",
			"Total Network revision subscription reconnect outcomes.",
			[]string{"result"},
			nil,
		),
	}, nil
}

func (collector *revisionFeedMetricsCollector) Describe(descriptions chan<- *prometheus.Desc) {
	descriptions <- collector.connectedDesc
	descriptions <- collector.watchersDesc
	descriptions <- collector.wakeupsDesc
	descriptions <- collector.fanoutDesc
	descriptions <- collector.reconnectDesc
}

func (collector *revisionFeedMetricsCollector) Collect(metrics chan<- prometheus.Metric) {
	snapshot := collector.telemetry.Snapshot()
	metrics <- prometheus.MustNewConstMetric(
		collector.connectedDesc,
		prometheus.GaugeValue,
		boolMetricValue(snapshot.Connected),
	)
	metrics <- prometheus.MustNewConstMetric(
		collector.watchersDesc,
		prometheus.GaugeValue,
		float64(snapshot.ActiveWatchers),
	)
	metrics <- prometheus.MustNewConstMetric(
		collector.wakeupsDesc,
		prometheus.CounterValue,
		float64(snapshot.WakeupsTotal),
	)
	collectCounterResults(
		metrics,
		collector.fanoutDesc,
		[]counterResult{
			{label: "delivered", value: snapshot.DeliveredTotal},
			{label: "coalesced", value: snapshot.CoalescedTotal},
		},
	)
	collectCounterResults(
		metrics,
		collector.reconnectDesc,
		[]counterResult{
			{label: "attempt", value: snapshot.ReconnectTotal},
			{label: "success", value: snapshot.RecoveredTotal},
		},
	)
}
