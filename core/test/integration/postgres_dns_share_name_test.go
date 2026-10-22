//go:build integration

package integration

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/dnszone"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/sharing"
)

// assertPostgreSQLDNSShareNames checks DNS names that point at a share the
// Network imports (DNS design D3a, schema 217): a live share is a target, an
// ended or unknown one is not, the name reads back with its share, and a Core
// that does not know shares (the v1 functions) never sees the name.
func assertPostgreSQLDNSShareNames(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool) {
	t.Helper()
	service := newIntegrationDNSZoneService(t, runtimePool, dnszone.DefaultLimits())
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	owner := managementRBACAccountSessionFixture(t)
	workspaceID, _ := owner.LoginWorkspaceID()

	// Earlier share tests leave contracts behind: a live one and an ended one
	// imported by Networks of this Workspace.
	var liveShare, liveNetwork string
	if err := admin.QueryRow(ctx, `SELECT imported.public_id::TEXT, net.public_id::TEXT
FROM mesh.imported_resource AS imported
JOIN mesh.trust_contract AS contract ON contract.id = imported.trust_contract_id
JOIN mesh.network AS net ON net.id = imported.network_id
JOIN mesh.workspace AS workspace ON workspace.id = imported.workspace_id
WHERE workspace.public_id = $1::UUID AND imported.state IN ('activating', 'active')
  AND contract.state IN ('activating', 'active') AND contract.expires_at > pg_catalog.now()
ORDER BY imported.created_at LIMIT 1`, workspaceID.String()).Scan(&liveShare, &liveNetwork); err != nil {
		t.Fatalf("no live imported share in the fixture Workspace: %v", err)
	}
	var endedShare string
	if err := admin.QueryRow(ctx, `SELECT imported.public_id::TEXT
FROM mesh.imported_resource AS imported
JOIN mesh.network AS net ON net.id = imported.network_id
WHERE net.public_id = $1::UUID AND imported.state NOT IN ('activating', 'active')
ORDER BY imported.created_at LIMIT 1`, liveNetwork).Scan(&endedShare); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal(err)
	}
	networkID, err := network.ParseID(liveNetwork)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	share, err := sharing.ParseImportedResourceID(liveShare)
	if err != nil {
		t.Fatal(err)
	}

	created, err := service.Create(ctx, owner, scope, dnszone.Definition{Domain: "apps.share.internal",
		OtherNames: dnszone.OtherNXDomain}, false, newCorrelationID(t))
	if err != nil {
		t.Fatalf("create a zone for share names: %v", err)
	}
	zone := created.Zone.ID
	// The zone goes with its names, whatever fails below.
	defer func() {
		if _, err := service.Delete(ctx, owner, scope, zone, created.Zone.Version, true, newCorrelationID(t)); err != nil {
			t.Errorf("delete the zone with its share name: %v", err)
		}
	}()
	shareTarget := dnszone.NameTarget{ShareID: share}
	app, err := service.CreateName(ctx, owner, scope, zone, dnszone.NameDefinition{Label: "app",
		Kind: dnszone.NameAddress, Target: shareTarget}, newCorrelationID(t))
	if err != nil || app.Name.Target.ShareID != share || app.Name.Share == nil || !app.Name.Share.Active ||
		!app.Name.Share.ContractID.IsValid() || app.Name.Share.Name == "" || app.Name.Target.DeviceID.IsValid() {
		t.Fatalf("a name to a live share = %+v, error = %v", app, err)
	}
	listed, err := service.ListNames(ctx, owner, scope, zone, dnszone.NameID{}, "", 10)
	if err != nil || len(listed.Names) != 1 || listed.Names[0].Target.ShareID != share {
		t.Fatalf("the share name listed = %+v, error = %v", listed, err)
	}

	unknown, err := sharing.ParseImportedResourceID("01890f00-0000-7000-8000-00000000d301")
	if err != nil {
		t.Fatal(err)
	}
	refused := map[string]sharing.ImportedResourceID{"an unknown share": unknown}
	if endedShare == "" {
		t.Log("no ended share in the fixture Network: the ended-share case did not run")
	} else {
		ended, err := sharing.ParseImportedResourceID(endedShare)
		if err != nil {
			t.Fatal(err)
		}
		refused["an ended share"] = ended
	}
	for name, target := range refused {
		_, err := service.ApplyNames(ctx, owner, scope, zone, []dnszone.NameOperation{{
			Operation: dnszone.OperationCreate,
			Definition: dnszone.NameDefinition{Label: "other", Kind: dnszone.NameAddress,
				Target: dnszone.NameTarget{ShareID: target}},
		}}, newCorrelationID(t))
		var operation *dnszone.OperationError
		if !errors.Is(err, dnszone.ErrShareTargetInvalid) || !errors.As(err, &operation) || operation.Index != 0 {
			t.Fatalf("a name to %s: %v", name, err)
		}
	}

	// A Core that does not know shares: the name is not there for it.
	listedV1, code := legacyDNSCall(ctx, t, admin, scope, `SELECT mesh_ops.list_dns_names_v1(
 $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT,$10::UUID,$11::UUID,
 $12::UUID,NULL,NULL,10)::TEXT`, append(legacySessionArguments(owner, scope), zone.String())...)
	if code != "" || !strings.Contains(listedV1, `"names": []`) || strings.Contains(listedV1, "share_id") {
		t.Fatalf("v1 list of a zone with a share name = %s (%s)", listedV1, code)
	}
	if _, code := legacyDNSCall(ctx, t, admin, scope, `SELECT mesh_ops.read_dns_name_v1(
 $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT,$10::UUID,$11::UUID,
 $12::UUID,$13::UUID)::TEXT`, append(legacySessionArguments(owner, scope), zone.String(),
		app.Name.ID.String())...); code != "MTZ0F" {
		t.Fatalf("v1 read of a share name: %s", code)
	}
	if _, code := legacyDNSCall(ctx, t, admin, scope, `SELECT mesh_ops.change_dns_names_v1(
 $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT,$10::UUID,$11::UUID,
 $12::UUID,$13::JSONB,2000,10000,200,$14::UUID)::TEXT`, append(legacySessionArguments(owner, scope), zone.String(),
		`[{"op":"delete","name_id":"`+app.Name.ID.String()+`","expected_version":1}]`,
		newCorrelationID(t).String())...); code != "MTZ0F" {
		t.Fatalf("v1 delete of a share name: %s", code)
	}
	if _, code := legacyDNSCall(ctx, t, admin, scope, `SELECT mesh_ops.change_dns_names_v1(
 $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT,$10::UUID,$11::UUID,
 $12::UUID,$13::JSONB,2000,10000,200,$14::UUID)::TEXT`, append(legacySessionArguments(owner, scope), zone.String(),
		`[{"op":"create","name_id":"`+newCorrelationID(t).String()+`","label":"v1","kind":"address","share_id":"`+
			liveShare+`"}]`, newCorrelationID(t).String())...); code != "22023" {
		t.Fatalf("v1 create of a share name: %s", code)
	}
	if counted, code := legacyDNSCall(ctx, t, admin, scope, `SELECT pg_catalog.count(*)::TEXT
FROM mesh_ops.load_map_network_dns_names_v1(10001) AS name WHERE name.fqdn = 'app.apps.share.internal'`); code != "" ||
		counted != "0" {
		t.Fatalf("the v1 map reader read a share name: %s (%s)", counted, code)
	}
	var mapRows int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh.network_dns_name AS name
JOIN mesh.network AS net ON net.id = name.network_id
WHERE net.public_id = $1::UUID AND name.state = 'active' AND name.share_public_id IS NOT NULL`,
		liveNetwork).Scan(&mapRows); err != nil || mapRows != 1 {
		t.Fatalf("stored share names = %d, error = %v", mapRows, err)
	}

	// A share name can point elsewhere and back, and a no-op keeps it.
	moved, err := service.UpdateName(ctx, owner, scope, zone, app.Name.ID, app.Name.Version,
		dnszone.NameDefinition{Kind: dnszone.NameAddress, Target: dnszone.NameTarget{
			Addresses: []netip.Addr{netip.MustParseAddr("10.0.5.40")}}}, newCorrelationID(t))
	if err != nil || moved.Name.Target.ShareID.IsValid() || moved.Name.Share != nil || moved.Name.Version != 2 {
		t.Fatalf("a share name moved to an address = %+v, error = %v", moved, err)
	}
	back, err := service.UpdateName(ctx, owner, scope, zone, app.Name.ID, moved.Name.Version,
		dnszone.NameDefinition{Kind: dnszone.NameAddress, Target: shareTarget}, newCorrelationID(t))
	if err != nil || back.Name.Target.ShareID != share || back.Name.Share == nil || back.Name.Version != 3 {
		t.Fatalf("the name back to its share = %+v, error = %v", back, err)
	}
	same, err := service.UpdateName(ctx, owner, scope, zone, app.Name.ID, back.Name.Version,
		dnszone.NameDefinition{Kind: dnszone.NameAddress, Target: shareTarget}, newCorrelationID(t))
	if err != nil || same.Changed || same.Name.Version != 3 {
		t.Fatalf("a share name updated to itself = %+v, error = %v", same, err)
	}
}
