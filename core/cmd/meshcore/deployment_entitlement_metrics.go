package main

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	entitlementExpiryDesc = prometheus.NewDesc(
		"meshtransit_deployment_entitlement_expiry_timestamp_seconds",
		"When the Deployment entitlement in effect expires (Unix seconds); grace starts then.",
		nil, nil)
	entitlementGenerationDesc = prometheus.NewDesc(
		"meshtransit_deployment_entitlement_generation",
		"Generation of the Deployment entitlement in effect, as this process last saw it.",
		nil, nil)
)

// entitlementInEffect is the entitlement generation this process last saw
// in effect: the one startup recorded or found newer, then the one each
// self-renewal attempt read or recorded. It adds no database read of its own.
// The highest generation wins, so a stale report never hides a renewal.
// Alert on the max across api replicas, since a replica that does not renew
// only learns of a renewal at its next start:
//
//	max(meshtransit_deployment_entitlement_expiry_timestamp_seconds) - time() < 30 * 86400
//
// Nothing is exported until a generation is seen (no entitlement mounted).
type entitlementInEffect struct {
	mu         sync.Mutex
	generation int64
	expiresAt  time.Time
}

func (inEffect *entitlementInEffect) observe(generation int64, expiresAt time.Time) {
	if inEffect == nil || generation <= 0 || expiresAt.IsZero() {
		return
	}
	inEffect.mu.Lock()
	defer inEffect.mu.Unlock()
	if generation >= inEffect.generation {
		inEffect.generation, inEffect.expiresAt = generation, expiresAt
	}
}

func (inEffect *entitlementInEffect) Describe(descs chan<- *prometheus.Desc) {
	descs <- entitlementExpiryDesc
	descs <- entitlementGenerationDesc
}

func (inEffect *entitlementInEffect) Collect(metrics chan<- prometheus.Metric) {
	inEffect.mu.Lock()
	generation, expiresAt := inEffect.generation, inEffect.expiresAt
	inEffect.mu.Unlock()
	if generation == 0 {
		return
	}
	metrics <- prometheus.MustNewConstMetric(entitlementExpiryDesc, prometheus.GaugeValue,
		float64(expiresAt.Unix()))
	metrics <- prometheus.MustNewConstMetric(entitlementGenerationDesc, prometheus.GaugeValue,
		float64(generation))
}
