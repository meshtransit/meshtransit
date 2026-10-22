//go:build integration

package integration

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/dnszone"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

func countDNSNameAudit(ctx context.Context, t *testing.T, admin *pgx.Conn, action string) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh_audit.audit_event
WHERE target_kind = 'network_dns_name' AND action = $1`, action).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func operationIndex(err error) int {
	var failure *dnszone.OperationError
	if errors.As(err, &failure) {
		return failure.Index
	}
	return -1
}

// legacyDNSCall runs one schema 213 or 214 function as the runtime role of
// a Core that knows no names (a rollback) would, in the Network's scope, and
// rolls back. It returns the function's text result and its SQLSTATE.
func legacyDNSCall(ctx context.Context, t *testing.T, admin *pgx.Conn, scope network.Scope, query string,
	args ...any) (string, string) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
		t.Fatal(err)
	}
	var workspaceInternal, networkInternal int64
	if err := tx.QueryRow(ctx, `SELECT workspace_internal_id, network_internal_id
FROM mesh_ops.set_network_scope($1::UUID, $2::UUID)`, scope.WorkspaceID().String(),
		scope.NetworkID().String()).Scan(&workspaceInternal, &networkInternal); err != nil {
		t.Fatal(err)
	}
	var result string
	if err := tx.QueryRow(ctx, query, args...).Scan(&result); err != nil {
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) {
			return "", pgError.Code
		}
		t.Fatal(err)
	}
	return result, ""
}

func legacySessionArguments(session accountsession.Session, scope network.Scope) []any {
	return append(ownerSessionArguments(session, scope.WorkspaceID().String())[:10], scope.NetworkID().String())
}

// legacyDeleteDNSZone deletes a zone through schema 213's change.
func legacyDeleteDNSZone(ctx context.Context, t *testing.T, admin *pgx.Conn, session accountsession.Session,
	scope network.Scope, zone dnszone.ID, version int64) string {
	t.Helper()
	changeID, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	_, code := legacyDNSCall(ctx, t, admin, scope, `SELECT mesh_ops.change_dns_zone_v1(
 $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT,$10::UUID,$11::UUID,
 'delete',$12::UUID,$13::BIGINT,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,$14::UUID)::TEXT`,
		append(legacySessionArguments(session, scope), zone.String(), version, changeID.String())...)
	return code
}

// assertPostgreSQLDNSNames qualifies schema 215 through the production
// store: zones of kind nxdomain and host; names that point at a Device,
// fixed addresses or another name; one transaction per apply with one
// audit event per changed name and one revision; the name, CNAME, target
// and limit rules in the database; nested zones that take names only when
// asked; zones deleted with their names only when asked; and schema 213 and
// 214 functions that keep a Core without names (a rollback) to forward zones
// and never move or delete a name. It leaves no zone or name behind.
func assertPostgreSQLDNSNames(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool) {
	t.Helper()
	service := newIntegrationDNSZoneService(t, runtimePool, dnszone.DefaultLimits())
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	owner := managementRBACAccountSessionFixture(t)
	member := authorityConfirmerAccountSessionFixture(t)
	workspaceID, _ := owner.LoginWorkspaceID()
	networkID, err := network.ParseID(guardrailFixtureNetwork)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	fixtureDevices := activeFixtureDevices(ctx, t, admin, 2)
	device := fixtureDevices[0]

	created, err := service.Create(ctx, owner, scope, dnszone.Definition{Domain: "corp.internal",
		OtherNames: dnszone.OtherNXDomain}, false, newCorrelationID(t))
	if err != nil || created.Zone.OtherNames != dnszone.OtherNXDomain || len(created.Zone.Resolvers) != 0 ||
		created.Zone.FailureMode != dnszone.FailOpen || created.Zone.NameCount != 0 {
		t.Fatalf("create an nxdomain zone = %+v, error = %v", created, err)
	}
	corp := created.Zone.ID
	address := func(text string) dnszone.NameTarget {
		return dnszone.NameTarget{Addresses: []netip.Addr{netip.MustParseAddr(text)}}
	}
	create := func(label string, kind dnszone.NameKind, target dnszone.NameTarget) dnszone.NameOperation {
		return dnszone.NameOperation{Operation: dnszone.OperationCreate,
			Definition: dnszone.NameDefinition{Label: label, Kind: kind, Target: target}}
	}
	first := []dnszone.NameOperation{
		create("printer", dnszone.NameAddress, address("10.0.5.20")),
		create("git", dnszone.NameAddress, dnszone.NameTarget{DeviceID: device}),
		create("wiki", dnszone.NameCNAME, dnszone.NameTarget{CNAME: "corp.atlassian.net"}),
		create("@", dnszone.NameAddress, address("2001:db8::10")),
	}
	if _, err := service.ApplyNames(ctx, member, scope, corp, first, newCorrelationID(t)); !errors.Is(err,
		dnszone.ErrForbidden) {
		t.Fatalf("a plain member changed names: %v", err)
	}
	networkBefore, _ := fixtureNetworkRevisions(ctx, t, admin)
	dnsBefore := fixtureDNSRevision(ctx, t, admin)
	applied, err := service.ApplyNames(ctx, owner, scope, corp, first, newCorrelationID(t))
	if err != nil || !applied.Changed || len(applied.Outcomes) != 4 {
		t.Fatalf("apply = %+v, error = %v", applied, err)
	}
	git := applied.Outcomes[1].Name
	if git.FQDN != "git.corp.internal" || git.Label != "git" || git.Device == nil || git.Device.State != "active" ||
		applied.Outcomes[3].Name.Label != "@" || applied.Outcomes[3].Name.FQDN != "corp.internal" ||
		applied.Outcomes[2].Name.Target.CNAME != "corp.atlassian.net" {
		t.Fatalf("names = %+v", applied.Outcomes)
	}
	if networkAfter, _ := fixtureNetworkRevisions(ctx, t, admin); networkAfter != networkBefore+1 ||
		fixtureDNSRevision(ctx, t, admin) != dnsBefore+1 || countDNSNameAudit(ctx, t, admin, "dns_name.created") != 4 {
		t.Fatal("one apply did not advance the revisions once with one audit event per name")
	}
	var wakes bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM mesh_ops.outbox_event
WHERE event_class = 'network.revision.advanced' AND payload->>'dns_name_id' = $1::TEXT)`,
		git.ID.String()).Scan(&wakes); err != nil || !wakes {
		t.Fatalf("the name change does not wake map sessions: %v", err)
	}

	// Pages in name order, with the zone and its count; a prefix filters.
	page, err := service.ListNames(ctx, owner, scope, corp, dnszone.NameID{}, "", 2)
	if err != nil || len(page.Names) != 2 || !page.HasMore || page.Names[0].FQDN != "corp.internal" ||
		page.Names[1].FQDN != "git.corp.internal" || page.Zone.NameCount != 4 || !page.CanManage {
		t.Fatalf("first page = %+v, error = %v", page, err)
	}
	if next, err := service.ListNames(ctx, owner, scope, corp, page.Names[1].ID, "", 10); err != nil ||
		len(next.Names) != 2 || next.HasMore || next.Names[0].FQDN != "printer.corp.internal" {
		t.Fatalf("second page = %+v, error = %v", next, err)
	}
	if found, err := service.ListNames(ctx, owner, scope, corp, dnszone.NameID{}, "wi", 10); err != nil ||
		len(found.Names) != 1 || found.Names[0].Kind != dnszone.NameCNAME || found.Names[0].Target.DeviceID.IsValid() {
		t.Fatalf("names starting with wi = %+v, error = %v", found, err)
	}
	if reading, err := service.ReadName(ctx, owner, scope, corp, git.ID); err != nil || reading.Name.Version != 1 {
		t.Fatalf("read a name = %+v, error = %v", reading, err)
	}
	assertDNSNameMaps(ctx, t, admin, runtimePool, device, fixtureDevices[1])

	// DNS changes reach maps together: the apply's wakeups wait for the
	// window it opened, and the next change shares it.
	var window time.Time
	var held int64
	if err := admin.QueryRow(ctx, `SELECT min(available_at), count(*) FILTER (WHERE available_at > occurred + INTERVAL '1 second')
FROM (SELECT event.available_at, identity.occurred_at AS occurred
      FROM mesh_ops.outbox_event AS event
      JOIN mesh_audit.audit_event_identity AS identity ON identity.change_public_id = event.change_public_id
      WHERE event.aggregate_kind = 'network_dns_name' AND event.payload->>'dns_name_id' = $1::TEXT) AS events`,
		git.ID.String()).Scan(&window, &held); err != nil || held == 0 {
		t.Fatalf("the name's wakeup is not held: %d held, error = %v", held, err)
	}
	// Zone changes earlier in this test may have opened the window.
	if applied.AppliesWithin < time.Second || applied.AppliesWithin > 30*time.Second {
		t.Fatalf("applies within %s", applied.AppliesWithin)
	}

	// The database refuses what Go would: a name twice, a Device of no
	// Network, a CNAME chain that loops; a refused apply writes nothing.
	unknownDevice := node.ID(newCorrelationID(t))
	for label, test := range map[string]struct {
		operations []dnszone.NameOperation
		want       error
		index      int
	}{
		"a name twice": {[]dnszone.NameOperation{create("lab", dnszone.NameAddress, address("10.0.5.30")),
			create("printer", dnszone.NameAddress, address("10.0.5.21"))}, dnszone.ErrNameTaken, 1},
		"an unknown Device": {[]dnszone.NameOperation{create("nas", dnszone.NameAddress,
			dnszone.NameTarget{DeviceID: unknownDevice})}, dnszone.ErrNameTargetInvalid, 0},
		"a CNAME loop": {[]dnszone.NameOperation{
			create("a", dnszone.NameCNAME, dnszone.NameTarget{CNAME: "b.corp.internal"}),
			create("b", dnszone.NameCNAME, dnszone.NameTarget{CNAME: "a.corp.internal"})}, dnszone.ErrCNAMELoop, -1},
	} {
		if _, err := service.ApplyNames(ctx, owner, scope, corp, test.operations, newCorrelationID(t)); !errors.Is(err,
			test.want) || operationIndex(err) != test.index {
			t.Errorf("%s: %v at %d, want %v at %d", label, err, operationIndex(err), test.want, test.index)
		}
	}
	if count, _ := service.ListNames(ctx, owner, scope, corp, dnszone.NameID{}, "", 10); len(count.Names) != 4 {
		t.Fatalf("a refused apply left %d names", len(count.Names))
	}

	// One apply deletes a name and creates it again as another kind; an
	// update to the same target writes nothing; a stale version fails.
	wiki := applied.Outcomes[2].Name
	swapped, err := service.ApplyNames(ctx, owner, scope, corp, []dnszone.NameOperation{
		create("wiki", dnszone.NameAddress, address("10.0.5.40")),
		{Operation: dnszone.OperationDelete, NameID: wiki.ID, ExpectedVersion: 1},
	}, newCorrelationID(t))
	if err != nil || !swapped.Outcomes[1].Name.Deleted || swapped.Outcomes[0].Name.Kind != dnszone.NameAddress {
		t.Fatalf("delete and create one name = %+v, error = %v", swapped, err)
	}
	var shared bool
	if err := admin.QueryRow(ctx, `SELECT bool_and(available_at = $1) FROM mesh_ops.outbox_event
WHERE aggregate_kind = 'network_dns_name' AND payload->>'dns_name_id' = $2::TEXT`, window,
		wiki.ID.String()).Scan(&shared); err != nil || !shared {
		t.Fatalf("the next DNS change does not share the window: %v", err)
	}
	dnsBefore = fixtureDNSRevision(ctx, t, admin)
	if same, err := service.UpdateName(ctx, owner, scope, corp, git.ID, 1, dnszone.NameDefinition{
		Kind: dnszone.NameAddress, Target: dnszone.NameTarget{DeviceID: device}}, newCorrelationID(t)); err != nil ||
		same.Changed || fixtureDNSRevision(ctx, t, admin) != dnsBefore {
		t.Fatalf("no-op update = %+v, error = %v", same, err)
	}
	moved, err := service.UpdateName(ctx, owner, scope, corp, git.ID, 1, dnszone.NameDefinition{
		Kind: dnszone.NameAddress, Target: address("10.0.5.50")}, newCorrelationID(t))
	if err != nil || !moved.Changed || moved.Name.Version != 2 || moved.Previous == nil ||
		countDNSNameAudit(ctx, t, admin, "dns_name.updated") != 1 {
		t.Fatalf("update = %+v, error = %v", moved, err)
	}
	if _, err := service.DeleteName(ctx, owner, scope, corp, git.ID, 1, newCorrelationID(t)); !errors.Is(err,
		dnszone.ErrVersionConflict) {
		t.Fatalf("stale delete: %v", err)
	}
	if _, err := service.ReadName(ctx, owner, scope, corp, wiki.ID); !errors.Is(err, dnszone.ErrNameNotFound) {
		t.Fatalf("read a deleted name: %v", err)
	}

	// A longer zone takes the names under it only when asked; then it holds
	// them and the shorter zone no longer may.
	if _, err := service.CreateName(ctx, owner, scope, corp, dnszone.NameDefinition{Label: "build.dev",
		Kind: dnszone.NameAddress, Target: address("10.0.6.1")}, newCorrelationID(t)); err != nil {
		t.Fatal(err)
	}
	dev := dnszone.Definition{Domain: "dev.corp.internal", OtherNames: dnszone.OtherHost}
	if _, err := service.Create(ctx, owner, scope, dev, false, newCorrelationID(t)); !errors.Is(err,
		dnszone.ErrZoneHoldsNames) {
		t.Fatalf("a zone over names without adopting them: %v", err)
	}
	adopted, err := service.Create(ctx, owner, scope, dev, true, newCorrelationID(t))
	if err != nil || adopted.Names != 1 || adopted.Zone.NameCount != 1 {
		t.Fatalf("a zone that adopts names = %+v, error = %v", adopted, err)
	}
	if _, err := service.CreateName(ctx, owner, scope, corp, dnszone.NameDefinition{Label: "ci.dev",
		Kind: dnszone.NameAddress, Target: address("10.0.6.2")}, newCorrelationID(t)); !errors.Is(err,
		dnszone.ErrNameInOtherZone) {
		t.Fatalf("a name a longer zone holds: %v", err)
	}
	if parent, err := service.Read(ctx, owner, scope, corp); err != nil || parent.Zone.NameCount != 4 {
		t.Fatalf("the shorter zone after adoption = %+v, error = %v", parent, err)
	}

	// A CNAME updated to its own name is a loop; a zone over its name limit
	// answers dns_name_limit; the database requires an update's version; the
	// apex of a single-label zone is a name.
	printer := applied.Outcomes[0].Name
	if _, err := service.UpdateName(ctx, owner, scope, corp, printer.ID, 1, dnszone.NameDefinition{
		Kind: dnszone.NameCNAME, Target: dnszone.NameTarget{CNAME: "printer.corp.internal"}},
		newCorrelationID(t)); !errors.Is(err, dnszone.ErrCNAMELoop) {
		t.Fatalf("a CNAME to its own name: %v", err)
	}
	zoneLimits := dnszone.DefaultLimits()
	zoneLimits.NamesPerZone = 4
	if _, err := newIntegrationDNSZoneService(t, runtimePool, zoneLimits).CreateName(ctx, owner, scope, corp,
		dnszone.NameDefinition{Label: "extra", Kind: dnszone.NameAddress, Target: address("10.0.5.70")},
		newCorrelationID(t)); !errors.Is(err, dnszone.ErrNameLimit) {
		t.Fatalf("a name over the zone limit: %v", err)
	}
	if _, code := legacyDNSCall(ctx, t, admin, scope, `SELECT mesh_ops.change_dns_names_v1(
 $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT,$10::UUID,$11::UUID,
 $12::UUID,$13::JSONB,2000,10000,200,$14::UUID)::TEXT`, append(legacySessionArguments(owner, scope), corp.String(),
		`[{"op":"delete","name_id":"`+printer.ID.String()+`"}]`, newCorrelationID(t).String())...); code != "22023" {
		t.Fatalf("a delete without a version: %s", code)
	}
	lan, err := service.Create(ctx, owner, scope, dnszone.Definition{Domain: "lan", OtherNames: dnszone.OtherNXDomain},
		false, newCorrelationID(t))
	if err != nil {
		t.Fatal(err)
	}
	if apex, err := service.CreateName(ctx, owner, scope, lan.Zone.ID, dnszone.NameDefinition{Label: "@",
		Kind: dnszone.NameAddress, Target: address("192.168.1.1")}, newCorrelationID(t)); err != nil ||
		apex.Name.FQDN != "lan" {
		t.Fatalf("the apex of a single-label zone = %+v, error = %v", apex, err)
	}
	if _, err := service.Delete(ctx, owner, scope, lan.Zone.ID, 1, true, newCorrelationID(t)); err != nil {
		t.Fatal(err)
	}

	// Names in host zones have their own limit; a domain on the Internet is
	// never nxdomain.
	if _, err := service.Create(ctx, owner, scope, dnszone.Definition{Domain: "corp.com",
		OtherNames: dnszone.OtherNXDomain, PublicConfirmed: true}, false, newCorrelationID(t)); !errors.Is(err,
		dnszone.ErrNXDomainPublic) {
		t.Fatalf("an nxdomain public zone: %v", err)
	}
	hostLimits := dnszone.DefaultLimits()
	hostLimits.HostNamesPerNetwork = 2
	strict := newIntegrationDNSZoneService(t, runtimePool, hostLimits)
	public, err := strict.Create(ctx, owner, scope, dnszone.Definition{Domain: "corp.com",
		OtherNames: dnszone.OtherHost, PublicConfirmed: true}, false, newCorrelationID(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strict.ApplyNames(ctx, owner, scope, public.Zone.ID, []dnszone.NameOperation{
		create("git", dnszone.NameAddress, address("10.0.5.60")),
		create("mail", dnszone.NameAddress, address("10.0.5.61")),
	}, newCorrelationID(t)); !errors.Is(err, dnszone.ErrNameLimit) {
		t.Fatalf("names over the host zone limit: %v", err)
	}
	if _, err := strict.CreateName(ctx, owner, scope, public.Zone.ID, dnszone.NameDefinition{Label: "git",
		Kind: dnszone.NameAddress, Target: address("10.0.5.60")}, newCorrelationID(t)); err != nil {
		t.Fatal(err)
	}
	var publicAudited bool
	if err := admin.QueryRow(ctx, `SELECT (payload->>'public_zone')::BOOLEAN FROM mesh_audit.audit_event
WHERE target_kind = 'network_dns_name' ORDER BY event_identity_id DESC LIMIT 1`).Scan(&publicAudited); err != nil ||
		!publicAudited {
		t.Fatalf("a name in a public zone is not audited as one: %v", err)
	}

	// A Core without names sees forward zones only, never deletes a zone
	// that holds names, never creates one over names, and its maps carry
	// forward zones only.
	forward, err := service.Create(ctx, owner, scope, dnszone.Definition{Domain: "fwd.internal",
		FailureMode: dnszone.FailOpen, Resolvers: []dnszone.Resolver{{Address: netip.MustParseAddr("1.1.1.1"),
			Port: dnszone.DNSPort}}}, false, newCorrelationID(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateName(ctx, owner, scope, forward.Zone.ID, dnszone.NameDefinition{Label: "x.sub",
		Kind: dnszone.NameAddress, Target: address("10.0.7.1")}, newCorrelationID(t)); err != nil {
		t.Fatal(err)
	}
	listed, code := legacyDNSCall(ctx, t, admin, scope, `SELECT mesh_ops.list_dns_zones_v1(
 $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT,$10::UUID,$11::UUID,
 NULL,100)::TEXT`, legacySessionArguments(owner, scope)...)
	if code != "" || !strings.Contains(listed, `"fwd.internal"`) || strings.Contains(listed, `"corp.internal"`) ||
		strings.Contains(listed, "name_count") {
		t.Fatalf("schema 213's list = %s, %s", listed, code)
	}
	if _, code := legacyDNSCall(ctx, t, admin, scope, `SELECT mesh_ops.read_dns_zone_v1(
 $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT,$10::UUID,$11::UUID,
 $12::UUID)::TEXT`, append(legacySessionArguments(owner, scope), corp.String())...); code != "P0002" {
		t.Fatalf("schema 213 reads an nxdomain zone: %s", code)
	}
	if code := legacyDeleteDNSZone(ctx, t, admin, owner, scope, forward.Zone.ID, 1); code != "MTZ01" {
		t.Fatalf("schema 213 deletes a zone that holds names: %s", code)
	}
	if code := legacyDeleteDNSZone(ctx, t, admin, owner, scope, corp, 1); code != "P0002" {
		t.Fatalf("schema 213 deletes an nxdomain zone: %s", code)
	}
	changeID := newCorrelationID(t)
	zoneID := newCorrelationID(t)
	if _, code := legacyDNSCall(ctx, t, admin, scope, `SELECT mesh_ops.change_dns_zone_v1(
 $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT,$10::UUID,$11::UUID,
 'create',$12::UUID,NULL,'sub.fwd.internal','open','[{"address":"1.1.1.1","port":53}]'::JSONB,'{}'::UUID[],NULL,
 'private','x/net test',FALSE,200,7,9744,$13::UUID)::TEXT`,
		append(legacySessionArguments(owner, scope), zoneID.String(), changeID.String())...); code != "MTZ01" {
		t.Fatalf("schema 213 creates a zone over names: %s", code)
	}
	mapped, _ := legacyDNSCall(ctx, t, admin, scope, `SELECT COALESCE(string_agg(domain, ',' ORDER BY domain), '')
FROM mesh_ops.load_map_network_dns_zones_v1(1025)`)
	if mapped != "fwd.internal" {
		t.Fatalf("schema 214's map reader returns %q", mapped)
	}

	// Rules the database holds whoever writes: fixed addresses, a zone on
	// the Internet never nxdomain, every name in its longest zone.
	var guarded bool
	if err := admin.QueryRow(ctx, `SELECT mesh_ops.dns_name_addresses_valid_internal_v1('{10.0.5.20,2001:db8::1}')
AND NOT mesh_ops.dns_name_addresses_valid_internal_v1('{100.64.0.7}')
AND NOT mesh_ops.dns_name_addresses_valid_internal_v1('{fd7a:115c::1}')
AND NOT mesh_ops.dns_name_addresses_valid_internal_v1('{10.0.5.20,10.0.5.20}')
AND NOT mesh_ops.dns_name_addresses_valid_internal_v1('{10.0.5.0/24}')
AND NOT mesh_ops.dns_name_addresses_valid_internal_v1('{::ffff:10.0.0.1}')
AND NOT mesh_ops.dns_name_addresses_valid_internal_v1('{}')`).Scan(&guarded); err != nil || !guarded {
		t.Fatalf("the database address guard = %v, error = %v", guarded, err)
	}
	assertDNSNameDatabaseGuard(ctx, t, admin, `UPDATE mesh.network_dns_zone SET other_names = 'nxdomain',
 version = version + 1 WHERE public_id = $1::UUID`, public.Zone.ID.String())
	assertDNSNameDatabaseGuard(ctx, t, admin, `UPDATE mesh.network_dns_name
 SET zone_id = (SELECT id FROM mesh.network_dns_zone WHERE public_id = $1::UUID), version = version + 1
 WHERE fqdn = 'printer.corp.internal' AND state = 'active'`, forward.Zone.ID.String())

	// A zone that holds names is deleted with them only when asked.
	if _, err := service.Delete(ctx, owner, scope, corp, 1, false, newCorrelationID(t)); !errors.Is(err,
		dnszone.ErrZoneHoldsNames) {
		t.Fatalf("deleted a zone that holds names: %v", err)
	}
	for _, zone := range []dnszone.ID{corp, adopted.Zone.ID, public.Zone.ID, forward.Zone.ID} {
		if deleted, err := service.Delete(ctx, owner, scope, zone, 1, true, newCorrelationID(t)); err != nil ||
			deleted.Names == 0 {
			t.Fatalf("delete a zone with its names = %+v, error = %v", deleted, err)
		}
	}
	var left int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh.network_dns_name WHERE state = 'active'`).Scan(
		&left); err != nil || left != 0 {
		t.Fatalf("%d names left, error = %v", left, err)
	}
}

// assertDNSNameDatabaseGuard runs a change the database must refuse, with a
// change context so only the rule under test can refuse it.
func assertDNSNameDatabaseGuard(ctx context.Context, t *testing.T, admin *pgx.Conn, statement string, args ...any) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('mesh.change_public_id', $1, TRUE)`,
		newCorrelationID(t).String()); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, statement, args...)
	if err == nil {
		_, err = tx.Exec(ctx, `SET CONSTRAINTS mesh.network_dns_name_placed, mesh.network_dns_zone_names_placed IMMEDIATE`)
	}
	var pgError *pgconn.PgError
	if !errors.As(err, &pgError) || pgError.Code != "23514" {
		t.Fatalf("the database allowed %q: %v", statement, err)
	}
}
