package distribution

import (
	"net/netip"
	"time"

	"meshtransit.net/shared/dnsdigest"
	"meshtransit.net/shared/policydigest"
)

// DNSSummary is the DNS digest of a Device's DNS routes and search domains
// (DNS design D1b §8) and how many routes it covers; the zero value means
// none was recorded, as for a client without dns.root1.
type DNSSummary struct {
	Digest policydigest.Digest
	Routes int
}

// IsZero reports that no DNS digest was recorded.
func (dns DNSSummary) IsZero() bool { return dns == DNSSummary{} }

func (dns DNSSummary) isValid() bool {
	return dns.IsZero() || !dns.Digest.IsZero() && dns.Routes >= 0 && dns.Routes <= dnsdigest.MaximumRoutes
}

// DNSHealthStale is how long a Device's resolver health stays current
// without a new report: it reports at least every 5 minutes (mtcp-v1 §8.6).
const DNSHealthStale = 15 * time.Minute

// Reasons a Device applies no DNS, as it reports them.
const (
	DNSReasonUserOff     = "user_off"
	DNSReasonApplyFailed = "apply_failed"
)

// DNSEnforcement is how the DNS a Device applies compares with what it was
// delivered: an Enforcement, or the reason it applies none.
type DNSEnforcement string

// DNSEnforcement values beyond the shared Enforcement ones.
const (
	DNSEnforcementUserOff     DNSEnforcement = DNSReasonUserOff
	DNSEnforcementApplyFailed DNSEnforcement = DNSReasonApplyFailed
)

// ClassifyDNSEnforcement compares the DNS digest a Device reports with the
// one it was last delivered, as ClassifyRouteEnforcement does for routes:
// the reason it applies none first, unknown when Core recorded no digest of
// what it sent, then enforced, applying within
// EnforcementGrace of the delivery, not reported, or mismatch. Empty for a
// Device without DNS evidence (no dns.root1).
func ClassifyDNSEnforcement(observation Observation, now time.Time) DNSEnforcement {
	switch {
	case !observation.Known || (observation.DNS.IsZero() && observation.EnforcedDNS.IsZero() &&
		observation.DNSReason == ""):
		return ""
	case observation.DNSReason != "":
		return DNSEnforcement(observation.DNSReason)
	case observation.DNS.IsZero():
		// Core could not record what it sent: no fault of the Device.
		return DNSEnforcement(EnforcementUnknown)
	case !observation.EnforcedDNS.IsZero() && observation.EnforcedDNS == observation.DNS:
		return DNSEnforcement(EnforcementEnforced)
	case now.Sub(observation.DeliveredAt) < EnforcementGrace:
		return DNSEnforcement(EnforcementApplying)
	case observation.EnforcedDNS.IsZero():
		return DNSEnforcement(EnforcementNotReported)
	default:
		return DNSEnforcement(EnforcementMismatch)
	}
}

// CurrentDNSHealth returns the Device's resolver health while it is current;
// false when it reported none or its last report is older than
// DNSHealthStale.
func CurrentDNSHealth(observation Observation, now time.Time) ([]ResolverHealth, bool) {
	if !observation.Known || observation.DNSHealthAt.IsZero() || now.Sub(observation.DNSHealthAt) > DNSHealthStale {
		return nil, false
	}
	return append([]ResolverHealth{}, observation.DNSHealth...), true
}

// Resolver states a Device's resolver reports (mtcp-v1 §8.6).
const (
	ResolverOK       = "ok"
	ResolverBroken   = "broken"
	ResolverStopped  = "stopped"
	ResolverRefusing = "refusing"
	ResolverIdle     = "idle"
)

// ResolverHealth is one resolver of the zones a Device applies, as its
// resolver sees it; LastOK is zero when it has not answered since the zones
// were applied.
type ResolverHealth struct {
	Resolver netip.AddrPort
	State    string
	LastOK   time.Time
}

// IsValid reports an address, a port and a known state.
func (health ResolverHealth) IsValid() bool {
	switch health.State {
	case ResolverOK, ResolverBroken, ResolverStopped, ResolverRefusing, ResolverIdle:
		return health.Resolver.IsValid() && health.Resolver.Port() != 0
	default:
		return false
	}
}

// validDNS checks the DNS evidence: digests, a digest or a known reason
// for what the Device applied, and resolver health with its time.
func validDNS(observation Observation) bool {
	if !observation.DNS.isValid() || !observation.EnforcedDNS.isValid() {
		return false
	}
	switch observation.DNSReason {
	case "":
	case DNSReasonUserOff, DNSReasonApplyFailed:
		if !observation.EnforcedDNS.IsZero() {
			return false
		}
	default:
		return false
	}
	if (len(observation.DNSHealth) != 0) && observation.DNSHealthAt.IsZero() {
		return false
	}
	for _, health := range observation.DNSHealth {
		if !health.IsValid() {
			return false
		}
	}
	return true
}
