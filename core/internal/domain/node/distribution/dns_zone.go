package distribution

import (
	"context"
	"net/netip"
	"time"

	"meshtransit.net/core/internal/domain/node"
)

// DNSOfflineAfter is how long without a touch a Device counts as offline in
// a zone's counts: a live stream touches its delivery record every minute.
const DNSOfflineAfter = 3 * time.Minute

// DNSZoneApplication counts the Devices that hold a zone by how the DNS they
// apply compares with what they were sent (DNS design D1b §8). Only Devices
// that report what they apply (dns.root1) are counted.
type DNSZoneApplication struct {
	Enforced, Applying, Mismatch, NotReported, Unknown, UserOff, ApplyFailed, Offline int
}

// Total is how many Devices were counted.
func (counts DNSZoneApplication) Total() int {
	return counts.Enforced + counts.Applying + counts.Mismatch + counts.NotReported + counts.Unknown +
		counts.UserOff + counts.ApplyFailed + counts.Offline
}

// DNSZoneReceivers answers which of up to DNSZoneReceiversBatch Devices a
// zone is still sent to, for the counts to leave out the Devices that hold
// it only in a stale index entry (TD-CORE-87).
type DNSZoneReceivers func(ctx context.Context, devices []node.ID) (map[node.ID]struct{}, error)

// DNSZoneReceiversBatch is how many Devices one DNSZoneReceivers call takes.
const DNSZoneReceiversBatch = 1_000

// IsOffline reports whether a Device was not seen within DNSOfflineAfter.
func (application DNSApplication) IsOffline(now time.Time) bool {
	return application.SeenAt.IsZero() || now.Sub(application.SeenAt) > DNSOfflineAfter
}

// DNSApplication is what Core holds of one Device's DNS for the counts: the
// digest sent, the digest it applied or why it applies none, when the
// current DNS was delivered and when the Device was last seen.
type DNSApplication struct {
	Sent        DNSSummary
	Enforced    DNSSummary
	Reason      string
	DeliveredAt time.Time
	SeenAt      time.Time
}

// Count adds one Device's application to the counts: offline when it was
// not seen within DNSOfflineAfter, otherwise as ClassifyDNSEnforcement.
func (counts *DNSZoneApplication) Count(application DNSApplication, now time.Time) {
	if application.IsOffline(now) {
		counts.Offline++
		return
	}
	observation := Observation{Known: true, DNS: application.Sent, EnforcedDNS: application.Enforced,
		DNSReason: application.Reason, DeliveredAt: application.DeliveredAt}
	switch ClassifyDNSEnforcement(observation, now) {
	case DNSEnforcement(EnforcementEnforced):
		counts.Enforced++
	case DNSEnforcement(EnforcementApplying):
		counts.Applying++
	case DNSEnforcement(EnforcementMismatch):
		counts.Mismatch++
	case DNSEnforcement(EnforcementNotReported):
		counts.NotReported++
	case DNSEnforcementUserOff:
		counts.UserOff++
	case DNSEnforcementApplyFailed:
		counts.ApplyFailed++
	default:
		counts.Unknown++
	}
}

// ResolverHealthCount counts the Devices whose resolver reported one
// resolver in each state within DNSHealthStale (DNS design D1b §9).
type ResolverHealthCount struct {
	Resolver                            netip.AddrPort
	OK, Broken, Stopped, Refusing, Idle int
}

// ResolverStates are the states counted, in ResolverHealthCount's order.
var ResolverStates = [...]string{ResolverOK, ResolverBroken, ResolverStopped, ResolverRefusing, ResolverIdle}
