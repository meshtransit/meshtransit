package mtcp

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"meshtransit.net/shared/key"
)

func TestServerReportsLatestControlKeyExpiry(t *testing.T) {
	next, err := key.NewControlPrivate(nil)
	if err != nil {
		t.Fatal(err)
	}
	latest := time.Unix(1_900_000_000, 0)
	metrics := NewMetrics()
	newFixture(t, func(options *Options) {
		options.Metrics = metrics
		options.Keys = append(options.Keys, ControlKey{Private: next, NotAfter: latest})
	})
	registry := prometheus.NewRegistry()
	registry.MustRegister(metrics.Collectors()...)
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "meshtransit_mtcp_control_key_not_after_timestamp_seconds" {
			continue
		}
		if got := family.GetMetric()[0].GetGauge().GetValue(); got != float64(latest.Unix()) {
			t.Fatalf("control key expiry gauge = %v, want %d", got, latest.Unix())
		}
		return
	}
	t.Fatal("control key expiry gauge not exported")
}
