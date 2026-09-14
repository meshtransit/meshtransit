package mapsession

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/meshtransit/meshtransit/internal/network"
)

func TestSnapshotOwnsAddressCollection(t *testing.T) {
	snapshot := snapshotFixture(t)
	addresses := snapshot.Addresses()
	addresses[0] = netip.MustParsePrefix("100.64.0.99/32")
	if got := snapshot.Addresses()[0]; got != netip.MustParsePrefix("100.64.0.1/32") {
		t.Fatalf("snapshot address = %v after caller mutation", got)
	}
}

func TestSnapshotRejectsUnsafeAuthorityState(t *testing.T) {
	valid := snapshotFixture(t)
	params := valid.params()
	for _, test := range []struct {
		name   string
		mutate func(*SnapshotParams)
	}{
		{name: "missing scope", mutate: func(value *SnapshotParams) { value.Scope = network.Scope{} }},
		{name: "zero revision", mutate: func(value *SnapshotParams) { value.NetworkRevision = 0 }},
		{name: "zero recovery epoch", mutate: func(value *SnapshotParams) { value.RecoveryEpoch = 0 }},
		{name: "zero session generation", mutate: func(value *SnapshotParams) { value.SessionGeneration = 0 }},
		{name: "zero numeric Node ID", mutate: func(value *SnapshotParams) { value.NumericNodeID = 0 }},
		{name: "unsafe numeric Node ID", mutate: func(value *SnapshotParams) { value.NumericNodeID = maximumSafeNumericID + 1 }},
		{name: "zero owner ID", mutate: func(value *SnapshotParams) { value.NumericOwnerID = 0 }},
		{name: "missing address", mutate: func(value *SnapshotParams) { value.Addresses = nil }},
		{name: "network address", mutate: func(value *SnapshotParams) {
			value.Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/24")}
		}},
		{name: "duplicate address family", mutate: func(value *SnapshotParams) {
			value.Addresses = []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
				netip.MustParsePrefix("100.64.0.2/32"),
			}
		}},
		{name: "expiry before creation", mutate: func(value *SnapshotParams) { value.KeyExpiry = value.CreatedAt }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := params
			candidate.Addresses = append([]netip.Prefix(nil), params.Addresses...)
			test.mutate(&candidate)
			if _, err := NewSnapshot(candidate); !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("NewSnapshot() error = %v, want ErrInvalidSnapshot", err)
			}
		})
	}
}
