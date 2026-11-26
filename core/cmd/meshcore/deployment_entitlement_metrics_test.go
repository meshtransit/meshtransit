package main

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func gatherEntitlementInEffect(t *testing.T, inEffect *entitlementInEffect) map[string]float64 {
	t.Helper()
	registry := prometheus.NewRegistry()
	if err := registry.Register(inEffect); err != nil {
		t.Fatal(err)
	}
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]float64{}
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			if len(metric.GetLabel()) != 0 || metric.GetGauge() == nil {
				t.Fatalf("%s: want one unlabelled gauge", family.GetName())
			}
			values[family.GetName()] = metric.GetGauge().GetValue()
		}
	}
	return values
}

func TestEntitlementInEffectExportsTheHighestGeneration(t *testing.T) {
	t.Parallel()
	if values := gatherEntitlementInEffect(t, &entitlementInEffect{}); len(values) != 0 {
		t.Fatalf("no generation seen yet, exported %v", values)
	}
	inEffect := &entitlementInEffect{}
	first := time.Date(2027, 11, 1, 0, 0, 0, 0, time.UTC)
	renewed := first.Add(365 * 24 * time.Hour)
	inEffect.observe(4, first)
	inEffect.observe(5, renewed)
	inEffect.observe(4, first) // a stale report never hides a renewal
	inEffect.observe(0, first) // nothing seen
	inEffect.observe(6, time.Time{})
	values := gatherEntitlementInEffect(t, inEffect)
	if len(values) != 2 ||
		values["meshtransit_deployment_entitlement_expiry_timestamp_seconds"] != float64(renewed.Unix()) ||
		values["meshtransit_deployment_entitlement_generation"] != 5 {
		t.Fatalf("exported %v", values)
	}
	var absent *entitlementInEffect
	absent.observe(7, renewed) // nil-safe: no entitlement configured
}
