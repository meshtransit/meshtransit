package main

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	postgresmapsession "meshtransit.net/core/internal/adapter/postgres/mapsession"
)

func TestMapInventoryCollectorExportsEachSnapshotSource(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(newMapInventoryCollector(func() postgresmapsession.InventoryStats {
		return postgresmapsession.InventoryStats{Shared: 3, Direct: 2, Derived: 7, Reads: 1, PolicyMismatches: 0}
	}))
	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	got := map[string]float64{}
	for _, family := range families {
		if family.GetName() != "meshtransit_map_snapshots_total" {
			continue
		}
		for _, metric := range family.GetMetric() {
			got[metric.GetLabel()[0].GetValue()] = metric.GetCounter().GetValue()
		}
	}
	want := map[string]float64{"shared": 3, "direct": 2, "derived": 7}
	if len(got) != len(want) {
		t.Fatalf("snapshot sources = %v, want %v", got, want)
	}
	for source, value := range want {
		if got[source] != value {
			t.Fatalf("snapshot sources = %v, want %v", got, want)
		}
	}
}
