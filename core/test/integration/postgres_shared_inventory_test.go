//go:build integration

package integration

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/control/mapsession"
)

// assertSharedInventoryMatchesDirectRead loads each identity's snapshot
// through a shared-inventory store and through the direct candidate read
// and requires identical authority (scale-out design S1: the derived
// snapshot must equal the reference read for every fixture).
func assertSharedInventoryMatchesDirectRead(
	ctx context.Context,
	t *testing.T,
	pool *postgresadapter.Pool,
	direct mapsession.SnapshotStore,
	identities ...control.AuthenticatedNode,
) {
	t.Helper()
	shared, err := postgresadapter.NewMapSessionStore(pool, postgresadapter.MapSessionOptions{
		StatementTimeout:          5 * time.Second,
		IdleTimeout:               5 * time.Second,
		PeerCandidateLimit:        mapsession.MaximumPeerCandidates,
		PolicyRuleLimit:           mapsession.MaximumPacketPolicyRules,
		RelayDirectory:            integrationRelayDirectory(t),
		SharedInventory:           true,
		InventoryStatementTimeout: 30 * time.Second,
		InventoryMaxAge:           30 * time.Second,
	})
	if err != nil {
		t.Fatalf("shared NewMapSessionStore() error = %v", err)
	}
	loaded := 0
	for index, identity := range identities {
		want, wantErr := direct.Load(ctx, identity)
		got, gotErr := shared.Load(ctx, identity)
		if (wantErr == nil) != (gotErr == nil) ||
			errors.Is(wantErr, mapsession.ErrUnauthorized) != errors.Is(gotErr, mapsession.ErrUnauthorized) ||
			errors.Is(wantErr, mapsession.ErrSuspended) != errors.Is(gotErr, mapsession.ErrSuspended) {
			t.Fatalf("identity %d: shared error %v, direct error %v", index, gotErr, wantErr)
		}
		if wantErr != nil {
			continue
		}
		loaded++
		if got.NodeID() != want.NodeID() || got.Scope() != want.Scope() ||
			got.NetworkRevision() != want.NetworkRevision() || got.SessionGeneration() != want.SessionGeneration() ||
			!got.KeyExpiry().Equal(want.KeyExpiry()) || !got.PacketPolicy().Equal(want.PacketPolicy()) ||
			!reflect.DeepEqual(got.Addresses(), want.Addresses()) {
			t.Fatalf("identity %d: shared self %+v differs from direct %+v", index, got, want)
		}
		if !reflect.DeepEqual(got.PeerCandidates(), want.PeerCandidates()) {
			t.Fatalf("identity %d: shared candidates %+v differ from direct %+v", index, got.PeerCandidates(), want.PeerCandidates())
		}
		if !reflect.DeepEqual(got.AuthorizedPeers(), want.AuthorizedPeers()) {
			t.Fatalf("identity %d: shared peers %+v differ from direct %+v", index, got.AuthorizedPeers(), want.AuthorizedPeers())
		}
		gotDNS, gotDNSErr := got.SharedDNSRecords()
		wantDNS, wantDNSErr := want.SharedDNSRecords()
		if !reflect.DeepEqual(got.InboundPacketRules(), want.InboundPacketRules()) ||
			!reflect.DeepEqual(got.SharingScopes(), want.SharingScopes()) ||
			!got.ProjectionExpiry().Equal(want.ProjectionExpiry()) ||
			!reflect.DeepEqual(gotDNS, wantDNS) || (gotDNSErr == nil) != (wantDNSErr == nil) {
			t.Fatalf("identity %d: shared direct projections differ from direct read", index)
		}
	}
	stats := shared.InventoryStats()
	if loaded > 0 && (stats.Shared != uint64(loaded) || stats.Reads == 0) {
		t.Fatalf("shared inventory never used: %+v", stats)
	}
}
