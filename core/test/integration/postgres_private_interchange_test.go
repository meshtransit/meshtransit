//go:build integration

package integration

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/interchange"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/shared/key"
)

type noSharedRelays struct{}

func (noSharedRelays) Uses(string, key.RelayPublic) bool { return false }

func privateInterchangeSpec(t *testing.T, code string, relayKey key.RelayPublic, networks ...network.ID) interchange.Spec {
	t.Helper()
	return interchange.Spec{Name: "Office relay", RegionCode: code, HostName: "relay.office.example.com",
		IPv4: netip.MustParseAddr("203.0.113.40"), RelayKey: relayKey, UDPPort: 3479, TLSPort: 443, STUNPort: 3478,
		Networks: interchange.SortNetworks(networks)}
}

func networkRevision(ctx context.Context, t *testing.T, admin *pgx.Conn, id network.ID) int64 {
	t.Helper()
	var revision int64
	if err := admin.QueryRow(ctx, `SELECT revision.network_revision FROM mesh_ops.network_revision AS revision
JOIN mesh.network AS network ON network.id = revision.network_id WHERE network.public_id = $1::UUID`,
		id.String()).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	return revision
}

// assertPostgreSQLPrivateInterchange qualifies schema 139 through the
// production store: interchange.read gates the list and interchange.manage
// changes; foreign Networks, reused keys and stale versions are refused;
// every change advances the revision of the Networks it touched, records one
// Workspace event plus a wake event per Network, and the directory serves the
// active relays. It leaves no relay behind.
func assertPostgreSQLPrivateInterchange(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool) {
	t.Helper()
	options := postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second}
	store, err := postgresadapter.NewPrivateInterchangeStore(runtimePool, options)
	if err != nil {
		t.Fatal(err)
	}
	service, err := interchange.NewService(store, accountsession.SystemClock{}, interchange.SystemIDs{}, noSharedRelays{})
	if err != nil {
		t.Fatal(err)
	}
	directoryStore, err := postgresadapter.NewPrivateInterchangeDirectoryStore(runtimePool)
	if err != nil {
		t.Fatal(err)
	}
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	owner := managementRBACAccountSessionFixture(t)
	member := authorityConfirmerAccountSessionFixture(t)
	workspaceID, _ := owner.LoginWorkspaceID()
	production, err := network.ParseID(guardrailFixtureNetwork)
	if err != nil {
		t.Fatal(err)
	}
	relayKey := key.RelayPublic{0x40, 0x41}

	if listing, err := service.List(ctx, owner, workspaceID); err != nil || len(listing.Interchanges) != 0 || !listing.CanManage {
		t.Fatalf("owner relays = %+v, error = %v", listing, err)
	}
	if _, err := service.List(ctx, member, workspaceID); !errors.Is(err, interchange.ErrForbidden) {
		t.Fatalf("plain member listed relays: %v", err)
	}
	spec := privateInterchangeSpec(t, "office-hn", relayKey, production)
	if _, err := service.Create(ctx, member, workspaceID, spec, newCorrelationID(t)); !errors.Is(err, interchange.ErrForbidden) {
		t.Fatalf("plain member created a relay: %v", err)
	}
	foreign := privateInterchangeSpec(t, "office-hn", relayKey, network.ID(newCorrelationID(t)))
	if _, err := service.Create(ctx, owner, workspaceID, foreign, newCorrelationID(t)); !errors.Is(err, interchange.ErrUnknownNetwork) {
		t.Fatalf("relay over a foreign Network: %v", err)
	}
	revisionBefore := networkRevision(ctx, t, admin, production)
	created, err := service.Create(ctx, owner, workspaceID, spec, newCorrelationID(t))
	if err != nil || created.Interchange.Version != 1 || created.Interchange.RegionID < 1000 ||
		len(created.Advanced) != 1 || created.Advanced[0].NetworkID != production {
		t.Fatalf("owner create = %+v, error = %v", created, err)
	}
	if got := networkRevision(ctx, t, admin, production); got != revisionBefore+1 {
		t.Fatalf("Network revision %d, want %d", got, revisionBefore+1)
	}
	id := created.Interchange.ID
	if _, err := service.Create(ctx, owner, workspaceID, privateInterchangeSpec(t, "office-hcm", relayKey),
		newCorrelationID(t)); !errors.Is(err, interchange.ErrConflict) {
		t.Fatalf("a reused relay key: %v", err)
	}

	directory, err := directoryStore.ReadPrivateInterchanges(ctx)
	if err != nil || directory.Revision <= 0 {
		t.Fatalf("directory = %+v, error = %v", directory, err)
	}
	if granted := directory.ForNetwork(production); len(granted) != 1 || granted[0].Spec.RelayKey != relayKey ||
		granted[0].RegionID != created.Interchange.RegionID {
		t.Fatalf("relays of the Network = %+v", granted)
	}
	if relay, found := directory.ByKey(relayKey); !found || relay.ID != id {
		t.Fatalf("relay by key = %+v %v", relay, found)
	}

	// Removing the Network from the relay advances it again; a stale update
	// is refused.
	ungranted := privateInterchangeSpec(t, "office-hn", relayKey)
	updated, err := service.Update(ctx, owner, workspaceID, id, 1, ungranted, newCorrelationID(t))
	if err != nil || updated.Interchange.Version != 2 || len(updated.Interchange.Spec.Networks) != 0 ||
		len(updated.Advanced) != 1 {
		t.Fatalf("owner update = %+v, error = %v", updated, err)
	}
	if _, err := service.Update(ctx, owner, workspaceID, id, 1, ungranted, newCorrelationID(t)); !errors.Is(err, interchange.ErrVersionConflict) {
		t.Fatalf("stale update: %v", err)
	}
	later, err := directoryStore.ReadPrivateInterchanges(ctx)
	if err != nil || later.Revision < directory.Revision || len(later.ForNetwork(production)) != 0 {
		t.Fatalf("directory after update = %+v, error = %v", later, err)
	}
	deleted, err := service.Delete(ctx, owner, workspaceID, id, 2, newCorrelationID(t))
	if err != nil || !deleted.Deleted {
		t.Fatalf("owner delete = %+v, error = %v", deleted, err)
	}
	if listing, err := service.List(ctx, owner, workspaceID); err != nil || len(listing.Interchanges) != 0 {
		t.Fatalf("relays after delete = %+v, error = %v", listing, err)
	}
	var workspaceEvents, wakeEvents int64
	if err := admin.QueryRow(ctx, `SELECT
 count(*) FILTER (WHERE action LIKE 'interchange.%' AND network_id IS NULL),
 count(*) FILTER (WHERE network_id IS NOT NULL)
FROM mesh_audit.audit_event WHERE target_kind = 'private_interchange' AND target_public_id = $1::UUID`,
		id.String()).Scan(&workspaceEvents, &wakeEvents); err != nil {
		t.Fatal(err)
	}
	if workspaceEvents != 3 || wakeEvents != 2 {
		t.Fatalf("audit events: %d on the Workspace stream, %d wake events; want 3 and 2", workspaceEvents, wakeEvents)
	}
}
