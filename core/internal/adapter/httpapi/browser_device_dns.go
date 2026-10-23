package httpapi

import (
	"time"

	"meshtransit.net/core/internal/domain/node/distribution"
)

type deviceDNSItem struct {
	// Enforcement is enforced (it applies what it was sent), applying
	// (within a minute of the delivery), mismatch, not_reported, user_off
	// (turned off on the Device), apply_failed (the host refused it) or
	// unknown (Core recorded no digest of what it sent).
	Enforcement     string  `json:"enforcement"`
	DeliveredDigest *string `json:"delivered_digest"`
	DeliveredRoutes *int    `json:"delivered_routes"`
	EnforcedDigest  *string `json:"enforced_digest"`
	EnforcedRoutes  *int    `json:"enforced_routes"`
	// Resolvers is how the Device's resolver last saw the zones' resolvers;
	// empty when it reported none, or none in the last 15 minutes.
	Resolvers []deviceResolverHealthItem `json:"resolvers"`
	// HealthReportedAt is when Core received that health.
	HealthReportedAt *time.Time `json:"health_reported_at"`
}

type deviceResolverHealthItem struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
	// State is ok, broken (skipped by its circuit breaker), stopped (a
	// resolver Device that stopped answering, asked last), refusing (its
	// last answer was SERVFAIL or REFUSED) or idle.
	State  string     `json:"state"`
	LastOK *time.Time `json:"last_ok_at"`
}

// newDeviceDNSItem describes the DNS a Device applies; nil for a Device
// without DNS evidence (no dns.root1).
func newDeviceDNSItem(device distribution.Device) *deviceDNSItem {
	observation := device.Observation
	if device.DNSEnforcement == "" {
		return nil
	}
	item := &deviceDNSItem{Enforcement: string(device.DNSEnforcement), Resolvers: []deviceResolverHealthItem{}}
	if dns := observation.DNS; !dns.IsZero() {
		digest, routes := dns.Digest.String(), dns.Routes
		item.DeliveredDigest, item.DeliveredRoutes = &digest, &routes
	}
	if dns := observation.EnforcedDNS; !dns.IsZero() {
		digest, routes := dns.Digest.String(), dns.Routes
		item.EnforcedDigest, item.EnforcedRoutes = &digest, &routes
	}
	for _, health := range device.DNSHealth {
		resolver := deviceResolverHealthItem{Address: health.Resolver.Addr().String(), Port: health.Resolver.Port(),
			State: health.State}
		if !health.LastOK.IsZero() {
			at := health.LastOK.UTC()
			resolver.LastOK = &at
		}
		item.Resolvers = append(item.Resolvers, resolver)
	}
	// A report of no resolver still says when the Device last reported.
	if !device.DNSHealthAt.IsZero() {
		at := device.DNSHealthAt.UTC()
		item.HealthReportedAt = &at
	}
	return item
}
