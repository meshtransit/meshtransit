package distribution

import (
	"testing"
	"time"

	"meshtransit.net/shared/policydigest"
)

func TestDNSZoneApplicationCount(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	sent := DNSSummary{Digest: policydigest.Digest{1}, Routes: 2}
	other := DNSSummary{Digest: policydigest.Digest{2}, Routes: 2}
	settled := now.Add(-time.Hour)
	var counts DNSZoneApplication
	for _, application := range []DNSApplication{
		{Sent: sent, Enforced: sent, DeliveredAt: settled, SeenAt: now},
		{Sent: sent, Enforced: sent, DeliveredAt: settled, SeenAt: now.Add(-time.Minute)},
		{Sent: sent, Enforced: other, DeliveredAt: settled, SeenAt: now},
		{Sent: sent, DeliveredAt: now.Add(-time.Second), SeenAt: now},
		{Sent: sent, DeliveredAt: settled, SeenAt: now},
		{Sent: sent, Reason: DNSReasonUserOff, DeliveredAt: settled, SeenAt: now},
		{Sent: sent, Reason: DNSReasonApplyFailed, DeliveredAt: settled, SeenAt: now},
		{Sent: sent, Enforced: sent, DeliveredAt: settled, SeenAt: now.Add(-DNSOfflineAfter - time.Second)},
		{Enforced: sent, DeliveredAt: settled, SeenAt: now},
	} {
		counts.Count(application, now)
	}
	want := DNSZoneApplication{Enforced: 2, Applying: 1, Mismatch: 1, NotReported: 1, Unknown: 1, UserOff: 1,
		ApplyFailed: 1, Offline: 1}
	if counts != want || counts.Total() != 9 {
		t.Fatalf("counts = %+v, want %+v", counts, want)
	}
}
