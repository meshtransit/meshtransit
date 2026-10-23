package daemon

import (
	"context"
	"testing"
	"time"

	"meshtransit.net/client/internal/networkmap"
)

// recordingDNS records the revision of each snapshot applied.
type recordingDNS struct{ applied []uint64 }

func (r *recordingDNS) Apply(_ context.Context, snapshot networkmap.Snapshot) (bool, error) {
	r.applied = append(r.applied, snapshot.Revision)
	return true, nil
}
func (r *recordingDNS) Reset(context.Context) error { return nil }
func (r *recordingDNS) Close(context.Context) error { return nil }

// A map callback that applies DNS after a newer map reached the failover
// applies the newer one: the older never lands last.
func TestApplyNewestDNSNeverAppliesAnOlderMap(t *testing.T) {
	t.Parallel()
	dns := &recordingDNS{}
	service := &Service{dns: dns}
	failover := newRouteFailover(time.Now)
	failover.effective(networkmap.Snapshot{Revision: 7})
	if _, _, err := service.applyNewestDNS(t.Context(), failover, networkmap.Snapshot{Revision: 6}); err != nil {
		t.Fatal(err)
	}
	// A failover that never saw a map leaves the snapshot given.
	if _, _, err := service.applyNewestDNS(t.Context(), newRouteFailover(time.Now),
		networkmap.Snapshot{Revision: 5}); err != nil {
		t.Fatal(err)
	}
	if len(dns.applied) != 2 || dns.applied[0] != 7 || dns.applied[1] != 5 {
		t.Fatalf("applied revisions = %v", dns.applied)
	}
}
