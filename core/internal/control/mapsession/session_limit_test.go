package mapsession

import (
	"slices"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/sharing/sharingtest"
)

func TestSessionPeerLimitFollowsTheClientDeclaration(t *testing.T) {
	t.Parallel()
	request, err := NewRequest(snapshotFixture(t).NodeKey())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		configured int
		large      bool
		want       int
	}{
		{0, false, LegacyPeerLimit},
		{0, true, DefaultPeerLimit},
		{100, false, 100},
		{5_000, true, 5_000},
	} {
		session := request
		if test.large {
			session = request.WithLargeMap()
		}
		if got := (ServiceOptions{PeerLimit: test.configured}).sessionPeerLimit(session); got != test.want {
			t.Errorf("limit %d, large %v: session limit %d, want %d", test.configured, test.large, got, test.want)
		}
	}
	if request.LargeMap() || !request.WithLargeMap().LargeMap() {
		t.Fatal("WithLargeMap changed the original request or did not declare")
	}
}

// TestSessionLimitBoundsALegacyClientMap: a client without map.large1 gets
// 256 of 300 authorized peers and the map reports itself limited; the same
// snapshot within the limit is unchanged.
func TestSessionLimitBoundsALegacyClientMap(t *testing.T) {
	t.Parallel()
	snapshot, _ := limitedNetworkFixture(t, LegacyPeerLimit+44)
	legacy, err := snapshot.withSessionLimit(LegacyPeerLimit)
	if err != nil {
		t.Fatal(err)
	}
	if sent, authorized := legacy.PeerLimit(); sent != LegacyPeerLimit || authorized != LegacyPeerLimit+44 ||
		!legacy.IsPeerLimited() {
		t.Fatalf("legacy session: %d of %d peers, limited %v", sent, authorized, legacy.IsPeerLimited())
	}
	large, err := snapshot.withSessionLimit(DefaultPeerLimit)
	if err != nil {
		t.Fatal(err)
	}
	if sent, authorized := large.PeerLimit(); sent != LegacyPeerLimit+44 || authorized != sent || large.IsPeerLimited() {
		t.Fatalf("large session: %d of %d peers", sent, authorized)
	}
	// Limiting again (a refresh of a limited map) keeps the total.
	again, err := legacy.withSessionLimit(LegacyPeerLimit)
	if err != nil {
		t.Fatal(err)
	}
	if _, authorized := again.PeerLimit(); authorized != LegacyPeerLimit+44 {
		t.Fatalf("a second limit forgot the total: %d", authorized)
	}
}

// TestSessionLimitKeepsTheOldestShares: past the session limit, a map keeps
// the shares of the oldest contracts, never a newer one in their place, and
// reports the rest omitted.
func TestSessionLimitKeepsTheOldestShares(t *testing.T) {
	t.Parallel()
	ports, err := policy.NewPortRange(443, 443)
	if err != nil {
		t.Fatal(err)
	}
	provider, consumer, _ := directDeviceFixture(t, policy.ProtocolTCP, []policy.PortRange{ports})
	projections := make([]DirectDeviceProjection, 0, 4)
	for _, variant := range []uint16{4, 2, 3, 1} {
		evidence := sharingtest.New(t, sharingtest.Params{
			ProviderScope: provider.Scope(), ConsumerScope: consumer.Scope(), ProviderDeviceID: provider.NodeID(),
			ConsumerDeviceID: consumer.NodeID(), ProviderAddress: provider.Addresses()[0].Addr(),
			EvaluatedAt: provider.CreatedAt().Add(time.Hour), RecoveryEpoch: provider.RecoveryEpoch(),
			Protocol: policy.ProtocolTCP, Ports: []policy.PortRange{ports}, Variant: variant,
		})
		projection, err := NewDirectDeviceProjection(directDeviceParams(t, provider, provider, consumer, evidence))
		if err != nil {
			t.Fatalf("variant %d: %v", variant, err)
		}
		projections = append(projections, projection)
	}
	shared, err := provider.WithDirectDeviceProjections(projections)
	if err != nil {
		t.Fatal(err)
	}
	limited, err := shared.withSessionLimit(2)
	if err != nil {
		t.Fatal(err)
	}
	kept := limited.directDeviceProjections
	if len(kept) != 2 || kept[0].ContractID().String() >= kept[1].ContractID().String() ||
		kept[1].ContractID().String() >= shared.directDeviceProjections[2].ContractID().String() {
		t.Fatalf("kept %d shares, not the two oldest", len(kept))
	}
	if !limited.IsPeerLimited() || limited.omittedShares != 2 {
		t.Fatalf("limited %v, omitted %d, want 2", limited.IsPeerLimited(), limited.omittedShares)
	}
	if sent, authorized := limited.PeerLimit(); sent != 1 || authorized != 3 {
		t.Fatalf("PeerLimit() = %d, %d", sent, authorized)
	}
	if within, err := shared.withSessionLimit(4); err != nil || len(within.directDeviceProjections) != 4 ||
		within.IsPeerLimited() {
		t.Fatalf("shares within the limit changed: %v", err)
	}
	// The store's own omissions add to the session's.
	stored, err := shared.WithOmittedShares(1)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.IsPeerLimited() {
		t.Fatal("a store omission did not limit the map")
	}
	if both, err := stored.withSessionLimit(2); err != nil || both.omittedShares != 3 {
		t.Fatalf("omitted %d, want 3: %v", both.omittedShares, err)
	}
	if _, err := shared.WithOmittedShares(-1); err == nil {
		t.Fatal("negative omissions accepted")
	}
}

// TestRelayGrantNamesEveryShareWithRelayZones: a session without
// relay.zones2 gets a relay grant for its 31 oldest contracts (an MTT1
// ticket); one that negotiated it names all of them.
func TestRelayGrantNamesEveryShareWithRelayZones(t *testing.T) {
	t.Parallel()
	ports, err := policy.NewPortRange(443, 443)
	if err != nil {
		t.Fatal(err)
	}
	provider, consumer, _ := directDeviceFixture(t, policy.ProtocolTCP, []policy.PortRange{ports})
	const shares = MaximumRelayGrantContracts + 9
	projections := make([]DirectDeviceProjection, 0, shares)
	for variant := range uint16(shares) {
		evidence := sharingtest.New(t, sharingtest.Params{
			ProviderScope: provider.Scope(), ConsumerScope: consumer.Scope(), ProviderDeviceID: provider.NodeID(),
			ConsumerDeviceID: consumer.NodeID(), ProviderAddress: provider.Addresses()[0].Addr(),
			EvaluatedAt: provider.CreatedAt().Add(time.Hour), RecoveryEpoch: provider.RecoveryEpoch(),
			Protocol: policy.ProtocolTCP, Ports: []policy.PortRange{ports}, Variant: variant + 1,
		})
		projection, err := NewDirectDeviceProjection(directDeviceParams(t, provider, provider, consumer, evidence))
		if err != nil {
			t.Fatalf("variant %d: %v", variant, err)
		}
		projections = append(projections, projection)
	}
	shared, err := provider.WithDirectDeviceProjections(projections)
	if err != nil {
		t.Fatal(err)
	}
	self := connectivityFixture(t, shared.NodeID(), shared.SessionGeneration(), 7, "198.51.100.9:41641", true)
	if shared, err = shared.WithConnectivity([]Connectivity{self}); err != nil {
		t.Fatal(err)
	}
	legacy, ok := shared.RelayGrantRequest()
	if !ok || len(legacy.TrustContracts) != MaximumRelayGrantContracts {
		t.Fatalf("legacy grant names %d contracts, want %d", len(legacy.TrustContracts), MaximumRelayGrantContracts)
	}
	shared.relayZones = true
	zones, ok := shared.RelayGrantRequest()
	if !ok || len(zones.TrustContracts) != shares || !slices.Equal(zones.TrustContracts[:MaximumRelayGrantContracts], legacy.TrustContracts) {
		t.Fatalf("relay.zones2 grant names %d contracts, want %d", len(zones.TrustContracts), shares)
	}
	if legacy.equal(zones) {
		t.Fatal("a grant for 31 contracts covers the request for all of them")
	}
	request, err := NewRequest(shared.NodeKey())
	if err != nil {
		t.Fatal(err)
	}
	if request.RelayZones() || !request.WithRelayZones().RelayZones() {
		t.Fatal("WithRelayZones did not declare, or changed the original")
	}
}
