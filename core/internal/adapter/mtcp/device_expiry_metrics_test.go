package mtcp

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestExpiringDevicesCountsOnlySoonAndLiveExpiries(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.October, 18, 10, 0, 0, 0, time.UTC)
	server := &Server{options: Options{Now: func() time.Time { return now }}, live: make(map[*Session]struct{})}
	for _, expiry := range []time.Time{
		{},                                     // no map sent yet
		now.Add(-time.Minute),                  // already expired
		now.Add(time.Hour),                     // within a day
		now.Add(24 * time.Hour),                // exactly a day
		now.Add(10 * 24 * time.Hour),           // within 14 days
		now.Add(14*24*time.Hour + time.Minute), // further off
		time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC), // never expires
	} {
		session := &Session{}
		if !expiry.IsZero() {
			session.deviceKeyExpiry.Store(expiry.UnixMilli())
		}
		server.live[session] = struct{}{}
	}
	within14d, within1d := server.expiringDevices()
	if within14d != 3 || within1d != 2 {
		t.Fatalf("expiringDevices() = %d, %d; want 3, 2", within14d, within1d)
	}
}

func TestExpiringDeviceGaugeReportsBothWindows(t *testing.T) {
	t.Parallel()
	metrics := NewMetrics()
	if got := collectExpiring(t, metrics); got["14d"] != 0 || got["1d"] != 0 {
		t.Fatalf("unbound gauge = %v", got)
	}
	metrics.countExpiringDevices(func() (int, int) { return 5, 2 })
	if got := collectExpiring(t, metrics); got["14d"] != 5 || got["1d"] != 2 || len(got) != 2 {
		t.Fatalf("bound gauge = %v", got)
	}
}

func collectExpiring(t *testing.T, metrics *Metrics) map[string]float64 {
	t.Helper()
	registry := prometheus.NewRegistry()
	registry.MustRegister(metrics.expiring)
	families, err := registry.Gather()
	if err != nil || len(families) != 1 {
		t.Fatalf("gather = %d families, %v", len(families), err)
	}
	values := map[string]float64{}
	for _, metric := range families[0].GetMetric() {
		labels := metric.GetLabel()
		if len(labels) != 1 || labels[0].GetName() != "within" {
			t.Fatalf("labels = %v", labels)
		}
		values[labels[0].GetValue()] = metric.GetGauge().GetValue()
	}
	return values
}
