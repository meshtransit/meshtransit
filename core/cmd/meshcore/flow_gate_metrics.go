package main

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"meshtransit.net/core/internal/control/mapsession"
)

// flowGateMetrics exports the ticket gate (connection logs design §16e
// C72): whether it is open, the receiver instances it saw, how old the
// newest report is and the tickets it held back. No label names a Network;
// alert on the gate closed while any Network logs.
type flowGateMetrics struct {
	gate      *mapsession.FlowGateCache
	now       func() time.Time
	open      *prometheus.Desc
	fresh     *prometheus.Desc
	accepting *prometheus.Desc
	age       *prometheus.Desc
	withheld  *prometheus.Desc
	failed    *prometheus.Desc
	readAge   *prometheus.Desc
}

func newFlowGateMetrics(gate *mapsession.FlowGateCache, now func() time.Time) *flowGateMetrics {
	return &flowGateMetrics{
		gate: gate, now: now,
		open: prometheus.NewDesc("meshtransit_flowlog_ticket_gate_open",
			"1 when a connection log receiver can take the tickets this replica signs.", nil, nil),
		fresh: prometheus.NewDesc("meshtransit_flowlog_receivers_fresh",
			"Connection log receiver instances that reported in the last 10 minutes.", nil, nil),
		accepting: prometheus.NewDesc("meshtransit_flowlog_receivers_accepting",
			"Fresh receiver instances that accept the protocol and hold the Noise key Core names.", nil, nil),
		age: prometheus.NewDesc("meshtransit_flowlog_receiver_report_age_seconds",
			"Age of the newest receiver report when the gate was last read.", nil, nil),
		withheld: prometheus.NewDesc("meshtransit_flowlog_tickets_withheld_total",
			"Connection log tickets the gate held back.", nil, nil),
		failed: prometheus.NewDesc("meshtransit_flowlog_ticket_gate_read_failed",
			"1 when the last read of the ticket gate failed (the gate is closed).", nil, nil),
		readAge: prometheus.NewDesc("meshtransit_flowlog_ticket_gate_read_age_seconds",
			"Age of the last read of the ticket gate: streams read it only while some Network logs, so the "+
				"other gauges are as of that read.", nil, nil),
	}
}

// Describe implements prometheus.Collector.
func (metrics *flowGateMetrics) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range []*prometheus.Desc{
		metrics.open, metrics.fresh, metrics.accepting, metrics.age, metrics.withheld, metrics.failed, metrics.readAge,
	} {
		ch <- desc
	}
}

// Collect implements prometheus.Collector.
func (metrics *flowGateMetrics) Collect(ch chan<- prometheus.Metric) {
	snapshot := metrics.gate.Snapshot()
	ch <- prometheus.MustNewConstMetric(metrics.withheld, prometheus.CounterValue, float64(snapshot.Withheld))
	if !snapshot.Read {
		return
	}
	ch <- prometheus.MustNewConstMetric(metrics.open, prometheus.GaugeValue, boolMetric(snapshot.Open))
	ch <- prometheus.MustNewConstMetric(metrics.failed, prometheus.GaugeValue, boolMetric(snapshot.Failed))
	ch <- prometheus.MustNewConstMetric(metrics.readAge, prometheus.GaugeValue,
		metrics.now().Sub(snapshot.ReadAt).Seconds())
	if snapshot.Failed {
		return
	}
	ch <- prometheus.MustNewConstMetric(metrics.fresh, prometheus.GaugeValue, float64(snapshot.Gate.Fresh))
	ch <- prometheus.MustNewConstMetric(metrics.accepting, prometheus.GaugeValue, float64(snapshot.Gate.Accepting))
	if !snapshot.Gate.Newest.IsZero() {
		ch <- prometheus.MustNewConstMetric(metrics.age, prometheus.GaugeValue,
			snapshot.Gate.CheckedAt.Sub(snapshot.Gate.Newest).Seconds())
	}
}

func boolMetric(value bool) float64 {
	if value {
		return 1
	}
	return 0
}
