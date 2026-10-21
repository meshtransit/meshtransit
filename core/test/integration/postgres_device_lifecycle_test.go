//go:build integration

package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/devicelifecycle"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/inventory"
	"meshtransit.net/core/internal/domain/publicid"
)

func newIntegrationDeviceLifecycle(t *testing.T, runtimePool *postgresadapter.Pool) *devicelifecycle.Service {
	t.Helper()
	store, err := postgresadapter.NewDeviceLifecycleStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service, err := devicelifecycle.NewService(store, accountsession.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

type integrationDeviceRow struct {
	version        int64
	state          string
	ownership      string
	ownerKind      string
	reason         *string
	handover       *string
	hostname       string
	hostnameLocked bool
	expiresAt      time.Time
}

func readIntegrationDevice(ctx context.Context, t *testing.T, admin *pgx.Conn, device node.ID) integrationDeviceRow {
	t.Helper()
	var row integrationDeviceRow
	if err := admin.QueryRow(ctx, `SELECT device.version, device.state, device.ownership, owner.kind,
    device.suspended_reason, handover.public_id::TEXT, device.hostname, device.hostname_locked, device.expires_at
FROM mesh.device AS device
JOIN mesh.principal AS owner ON owner.id = device.owner_principal_id
LEFT JOIN mesh.principal AS handover ON handover.id = device.handover_principal_id
WHERE device.public_id = $1::UUID`, device.String()).Scan(&row.version, &row.state, &row.ownership,
		&row.ownerKind, &row.reason, &row.handover, &row.hostname, &row.hostnameLocked, &row.expiresAt); err != nil {
		t.Fatal(err)
	}
	return row
}

func countDeviceAudit(ctx context.Context, t *testing.T, admin *pgx.Conn, device node.ID, action string) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh_audit.audit_event
WHERE target_kind = 'device' AND target_public_id = $1::UUID AND action = $2`, device.String(), action).
		Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// assertPostgreSQLDeviceLifecycle qualifies schema 125 through the production
// store: device.quarantine suspends and resumes, device.transfer hands a
// Device to the Workspace (its service principal, never expiring) or starts a
// handover to an eligible member that a resume cancels, device.manage renames
// and locks the hostname, every change advances the Network revision with
// one audit event, and the Console inventory reports ownership and
// suspension. It leaves the Device active and Workspace-owned.
func assertPostgreSQLDeviceLifecycle(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool) {
	t.Helper()
	lifecycle := newIntegrationDeviceLifecycle(t, runtimePool)
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
	devices := activeFixtureDevices(ctx, t, admin, 2)
	device, other := devices[0], devices[1]
	change := func(session accountsession.Session, request devicelifecycle.Request) (devicelifecycle.Result, error) {
		request.Scope, request.DeviceID = scope, device
		request.ExpectedVersion = readIntegrationDevice(ctx, t, admin, device).version
		request.CorrelationID = newCorrelationID(t)
		return lifecycle.Change(ctx, session, request)
	}

	if _, err := change(member, devicelifecycle.Request{Action: devicelifecycle.ActionSuspend,
		Reason: "Not allowed"}); !errors.Is(err, devicelifecycle.ErrForbidden) {
		t.Fatalf("plain member suspended a Device: %v", err)
	}
	networkBefore, _ := fixtureNetworkRevisions(ctx, t, admin)
	suspended, err := change(owner, devicelifecycle.Request{Action: devicelifecycle.ActionSuspend, Reason: "Lost laptop"})
	if err != nil || suspended.After.State != "suspended" || suspended.After.SuspendedReason != devicelifecycle.SuspendedByAdmin {
		t.Fatalf("suspend = %+v, %v", suspended, err)
	}
	if networkAfter, _ := fixtureNetworkRevisions(ctx, t, admin); networkAfter != networkBefore+1 ||
		countDeviceAudit(ctx, t, admin, device, "device.suspended") != 1 {
		t.Fatal("suspension must advance the Network once with one audit event")
	}
	if _, err := change(owner, devicelifecycle.Request{Action: devicelifecycle.ActionSuspend,
		Reason: "Again"}); !errors.Is(err, devicelifecycle.ErrWrongState) {
		t.Fatalf("suspended a suspended Device: %v", err)
	}
	stale := devicelifecycle.Request{Scope: scope, DeviceID: device, Action: devicelifecycle.ActionResume,
		ExpectedVersion: suspended.Before.Version, Reason: "Stale", CorrelationID: newCorrelationID(t)}
	if _, err := lifecycle.Change(ctx, owner, stale); !errors.Is(err, devicelifecycle.ErrVersionConflict) {
		t.Fatalf("stale resume: %v", err)
	}
	if !mapSessionSuspended(ctx, t, admin, device) {
		t.Fatal("schema 126 must report the suspended Device to its own map session")
	}
	if resumed, err := change(owner, devicelifecycle.Request{Action: devicelifecycle.ActionResume,
		Reason: "Found it"}); err != nil || resumed.After.State != "active" {
		t.Fatalf("resume = %+v, %v", resumed, err)
	}
	if mapSessionSuspended(ctx, t, admin, device) {
		t.Fatal("schema 126 must not report an active Device as suspended")
	}
	assertMapSessionRevoked(ctx, t, admin, device)

	// A handover needs an active member of the Workspace and Network.
	if _, err := change(owner, devicelifecycle.Request{Action: devicelifecycle.ActionTransferMember,
		NewOwner: newCorrelationID(t), Reason: "Nobody"}); !errors.Is(err, devicelifecycle.ErrIneligibleOwner) {
		t.Fatalf("handover to a stranger: %v", err)
	}
	ownerPrincipal := publicid.ID(owner.PrincipalID())
	original := readIntegrationDevice(ctx, t, admin, device)
	handover, err := change(owner, devicelifecycle.Request{Action: devicelifecycle.ActionTransferMember,
		NewOwner: ownerPrincipal, Reason: "Laptop to the owner"})
	if errors.Is(err, devicelifecycle.ErrWrongState) {
		// The fixture Device already belongs to the owner: hand it to the Workspace first.
		if _, err := change(owner, devicelifecycle.Request{Action: devicelifecycle.ActionTransferWorkspace,
			Reason: "Server"}); err != nil {
			t.Fatal(err)
		}
		handover, err = change(owner, devicelifecycle.Request{Action: devicelifecycle.ActionTransferMember,
			NewOwner: ownerPrincipal, Reason: "Laptop to the owner"})
	}
	if err != nil || handover.After.State != "suspended" ||
		handover.After.SuspendedReason != devicelifecycle.SuspendedForHandover || handover.After.HandoverTo != ownerPrincipal {
		t.Fatalf("handover = %+v, %v (original %+v)", handover, err, original)
	}
	if cancelled, err := change(owner, devicelifecycle.Request{Action: devicelifecycle.ActionResume,
		Reason: "Cancel handover"}); err != nil || cancelled.After.State != "active" || cancelled.After.HandoverTo.IsValid() {
		t.Fatalf("cancel handover = %+v, %v", cancelled, err)
	}

	assertDeviceExtension(ctx, t, admin, lifecycle, scope, owner, member)

	// To the Workspace: owned by its service principal and never expiring.
	if row := readIntegrationDevice(ctx, t, admin, device); row.ownership != "workspace" {
		if _, err := change(owner, devicelifecycle.Request{Action: devicelifecycle.ActionTransferWorkspace,
			Reason: "Server"}); err != nil {
			t.Fatalf("transfer to the Workspace: %v", err)
		}
	}
	row := readIntegrationDevice(ctx, t, admin, device)
	if row.ownership != "workspace" || row.ownerKind != "service" || row.state != "active" ||
		row.expiresAt.Year() != 2200 || countDeviceAudit(ctx, t, admin, device, "device.ownership_transferred") < 1 {
		t.Fatalf("Workspace Device = %+v", row)
	}
	if _, err := change(owner, devicelifecycle.Request{Action: devicelifecycle.ActionTransferWorkspace,
		Reason: "Again"}); !errors.Is(err, devicelifecycle.ErrWrongState) {
		t.Fatalf("transferred a Workspace Device to the Workspace: %v", err)
	}
	// Schema 180: a Workspace Device never expires, so it is never extended.
	if _, err := change(owner, devicelifecycle.Request{Action: devicelifecycle.ActionExtend,
		Extension: time.Hour, Reason: "Server"}); !errors.Is(err, devicelifecycle.ErrWrongState) {
		t.Fatalf("extended a Workspace Device: %v", err)
	}

	// Rename: unique in the Network, locked against client logins.
	otherName := readIntegrationDevice(ctx, t, admin, other).hostname
	taken, _ := node.ParseHostname(otherName)
	if _, err := change(owner, devicelifecycle.Request{Action: devicelifecycle.ActionRename,
		Hostname: taken}); !errors.Is(err, devicelifecycle.ErrHostnameTaken) {
		t.Fatalf("rename to a taken hostname: %v", err)
	}
	// Schema 169: nor to one whose DNS label another Device holds.
	otherLabel := deviceDNSLabel(ctx, t, admin, other)
	sameLabel, _ := node.ParseHostname(otherLabel + ".elsewhere")
	if otherLabel == "" {
		t.Fatal("an active Device holds no DNS label")
	}
	if _, err := change(owner, devicelifecycle.Request{Action: devicelifecycle.ActionRename,
		Hostname: sameLabel}); !errors.Is(err, devicelifecycle.ErrHostnameTaken) {
		t.Fatalf("rename to a taken DNS label: %v", err)
	}
	fresh, _ := node.ParseHostname("lifecycle-server")
	if renamed, err := change(owner, devicelifecycle.Request{Action: devicelifecycle.ActionRename,
		Hostname: fresh}); err != nil || renamed.After.Hostname != "lifecycle-server" || !renamed.After.HostnameLocked {
		t.Fatalf("rename = %+v, %v", renamed, err)
	}
	if label := deviceDNSLabel(ctx, t, admin, device); label != "lifecycle-server" {
		t.Fatalf("renamed Device DNS label = %q, want lifecycle-server", label)
	}
	// Schema 181: the rename is stamped with its transaction's time.
	assertUpdatedByDatabaseClock(ctx, t, admin, "device", device.String())
	assertNoCallerClockNow(ctx, t, admin)

	inventoryStore, err := postgresadapter.NewConsoleDeviceInventoryStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	// Schema 184: the Network permission check waits for a member change
	// without holding the session.
	page, err := runWhileWorkspaceChanging(ctx, t, admin, "read_console_devices_v5", owner.ID().String(),
		func() (inventory.ReadResult, error) {
			return inventoryStore.ReadDevices(ctx, owner, scope, inventory.Query{Limit: 100})
		})
	if err != nil {
		t.Fatalf("read inventory: %v", err)
	}
	for _, listed := range page.Devices {
		if listed.ID() == device {
			label, labeled := listed.DNSLabel()
			if listed.Lifecycle().Ownership != "workspace" || listed.Hostname() != "lifecycle-server" ||
				!labeled || label.String() != "lifecycle-server" || !page.WorkspaceCode.IsValid() ||
				!page.NetworkCode.IsValid() {
				t.Fatalf("inventory lifecycle = %+v, label %q, codes %q %q", listed.Lifecycle(), label,
					page.WorkspaceCode, page.NetworkCode)
			}
			assertConsoleDeviceAddresses(ctx, t, admin, inventoryStore, owner, scope, device)
			return
		}
	}
	t.Fatal("inventory lacks the Device")
}

// assertConsoleDeviceAddresses checks schema 209: one Device's read names the
// mesh addresses it holds, exactly its active primary leases, IPv4 first.
func assertConsoleDeviceAddresses(ctx context.Context, t *testing.T, admin *pgx.Conn,
	store *postgresadapter.ConsoleDeviceInventoryStore, session accountsession.Session,
	scope network.Scope, device node.ID,
) {
	t.Helper()
	var want []string
	if err := admin.QueryRow(ctx, `SELECT COALESCE(pg_catalog.array_agg(pg_catalog.host(lease.address)
	        ORDER BY lease.family, lease.address), ARRAY[]::TEXT[])
	    FROM mesh.node_address_lease AS lease
	    JOIN mesh.device AS device ON device.id = lease.device_id
	    WHERE device.public_id = $1 AND lease.state = 'active' AND lease.lease_role = 'primary'`,
		device.String()).Scan(&want); err != nil {
		t.Fatal(err)
	}
	record, err := store.ReadDevice(ctx, session, scope, device)
	if err != nil || !record.Found {
		t.Fatalf("read Device = %+v, %v", record, err)
	}
	got := make([]string, len(record.Addresses))
	for index, address := range record.Addresses {
		got[index] = address.String()
	}
	if len(want) == 0 || strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Device addresses = %v, want its active primary leases %v", got, want)
	}
}

// assertPostgreSQLBrowserHandover completes a schema 125 handover through
// the real browser login: the browser-registered Device moves to the
// Workspace, is handed to the member who registered it, and that member's
// next browser login on the Device makes them its owner again, active, with
// a device.handover_completed audit event.
func assertPostgreSQLBrowserHandover(
	ctx context.Context, t *testing.T, admin *pgx.Conn, runtime *postgresadapter.Pool,
	intents *postgresadapter.BrowserIntentStore,
	approvals *postgresadapter.BrowserApprovalStore,
	completion *postgresadapter.BrowserCompletionStore,
	deploymentID deployment.ID, epoch int64, session accountsession.Digest,
	networkID network.ID, identity node.RegistrationIdentity, hostname node.Hostname,
	created registration.Result,
) {
	t.Helper()
	lifecycle := newIntegrationDeviceLifecycle(t, runtime)
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	owner := managementRBACAccountSessionFixture(t)
	workspaceID, _ := owner.LoginWorkspaceID()
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	device := created.NodeID()
	for _, request := range []devicelifecycle.Request{
		{Action: devicelifecycle.ActionTransferWorkspace, Reason: "Reassign laptop"},
		{Action: devicelifecycle.ActionTransferMember, NewOwner: publicid.ID(owner.PrincipalID()), Reason: "Back to owner"},
	} {
		request.Scope, request.DeviceID, request.CorrelationID = scope, device, newCorrelationID(t)
		request.ExpectedVersion = readIntegrationDevice(ctx, t, admin, device).version
		if _, err := lifecycle.Change(ctx, owner, request); err != nil {
			t.Fatalf("%s: %v", request.Action, err)
		}
	}
	if row := readIntegrationDevice(ctx, t, admin, device); row.state != "suspended" || row.ownership != "workspace" {
		t.Fatalf("pending handover = %+v", row)
	}
	id, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	intentID, err := enrollment.ParseBrowserIntentID(id.String())
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := enrollment.NewBrowserIntentNonce()
	if err != nil {
		t.Fatal(err)
	}
	token, err := intents.Issue(ctx, deploymentID, epoch, identity, hostname, intentID, nonce,
		5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if approved, err := approvals.Approve(ctx, session, token.Encoded(), networkID); err != nil || !approved {
		t.Fatalf("handover approval = %v: %v", approved, err)
	}
	result, found, err := completion.Complete(ctx, identity, hostname, token.Encoded())
	if err != nil || !found || result.NodeID() != device || result.Disposition() != registration.DispositionResumed {
		t.Fatalf("handover login = %+v/%v/%v", result, found, err)
	}
	row := readIntegrationDevice(ctx, t, admin, device)
	if row.state != "active" || row.ownership != "member" || row.ownerKind != "account" || row.handover != nil ||
		row.expiresAt.Year() == 2200 || countDeviceAudit(ctx, t, admin, device, "device.handover_completed") != 1 {
		t.Fatalf("completed handover = %+v", row)
	}
}

// mapSessionSuspended asks schema 126, as the runtime role, whether the
// Device's current machine and node key belong to a suspended Device.
func mapSessionSuspended(ctx context.Context, t *testing.T, admin *pgx.Conn, device node.ID) bool {
	t.Helper()
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	var fingerprint, nodeKey []byte
	if err := transaction.QueryRow(ctx, `SELECT machine.fingerprint, node_key.public_key
FROM mesh.device AS device
JOIN mesh.device_machine_key_epoch AS machine
  ON machine.workspace_id = device.workspace_id AND machine.network_id = device.network_id
 AND machine.device_id = device.id AND machine.epoch = device.current_machine_key_epoch
JOIN mesh.device_node_key_epoch AS node_key
  ON node_key.workspace_id = device.workspace_id AND node_key.network_id = device.network_id
 AND node_key.device_id = device.id AND node_key.epoch = device.current_node_key_epoch
WHERE device.public_id = $1::UUID`, device.String()).Scan(&fingerprint, &nodeKey); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(ctx, "SET LOCAL ROLE mesh_runtime"); err != nil {
		t.Fatal(err)
	}
	var suspended bool
	if err := transaction.QueryRow(ctx, `SELECT mesh_ops.map_session_suspended_v1($1::BYTEA, $2::BYTEA)`,
		fingerprint, nodeKey).Scan(&suspended); err != nil {
		t.Fatal(err)
	}
	var wrongKey bool
	if err := transaction.QueryRow(ctx, `SELECT mesh_ops.map_session_suspended_v1($1::BYTEA, $2::BYTEA)`,
		fingerprint, make([]byte, 32)).Scan(&wrongKey); err != nil || wrongKey {
		t.Fatalf("another node key must never learn the suspension: %t, %v", wrongKey, err)
	}
	return suspended
}

// assertMapSessionRevoked qualifies schema 161 inside a transaction it rolls
// back: an active Device is not revoked; once revoked, its own keys learn it
// and another node key never does.
func assertMapSessionRevoked(ctx context.Context, t *testing.T, admin *pgx.Conn, device node.ID) {
	t.Helper()
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	var deviceID int64
	var fingerprint, nodeKey []byte
	if err := transaction.QueryRow(ctx, `SELECT device.id, machine.fingerprint, node_key.public_key
FROM mesh.device AS device
JOIN mesh.device_machine_key_epoch AS machine
  ON machine.workspace_id = device.workspace_id AND machine.network_id = device.network_id
 AND machine.device_id = device.id AND machine.epoch = device.current_machine_key_epoch
JOIN mesh.device_node_key_epoch AS node_key
  ON node_key.workspace_id = device.workspace_id AND node_key.network_id = device.network_id
 AND node_key.device_id = device.id AND node_key.epoch = device.current_node_key_epoch
WHERE device.public_id = $1::UUID`, device.String()).Scan(&deviceID, &fingerprint, &nodeKey); err != nil {
		t.Fatal(err)
	}
	revokedFor := func(machine, key []byte) bool {
		t.Helper()
		if _, err := transaction.Exec(ctx, "SET LOCAL ROLE mesh_runtime"); err != nil {
			t.Fatal(err)
		}
		var result bool
		if err := transaction.QueryRow(ctx, `SELECT mesh_ops.map_session_revoked_v1($1::BYTEA, $2::BYTEA)`,
			machine, key).Scan(&result); err != nil {
			t.Fatal(err)
		}
		if _, err := transaction.Exec(ctx, "RESET ROLE"); err != nil {
			t.Fatal(err)
		}
		return result
	}
	revoked := func(key []byte) bool { t.Helper(); return revokedFor(fingerprint, key) }
	if revoked(nodeKey) {
		t.Fatal("schema 161 must not report an active Device as revoked")
	}
	if _, err := transaction.Exec(ctx, `SELECT pg_catalog.set_config('mesh.change_public_id', $1, TRUE)`,
		newCorrelationID(t).String()); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(ctx, `SELECT mesh_ops.revoke_member_device_internal_v1($1, 'qualification',
    pg_catalog.clock_timestamp())`, deviceID); err != nil {
		t.Fatal(err)
	}
	if !revoked(nodeKey) {
		t.Fatal("schema 161 must report the revoked Device to its own keys")
	}
	if revoked(make([]byte, 32)) {
		t.Fatal("another node key must never learn the revocation")
	}
	for name, keys := range map[string][2][]byte{
		"another machine": {make([]byte, 32), nodeKey},
		"no machine":      {nil, nodeKey},
		"no node key":     {fingerprint, nil},
		"short machine":   {fingerprint[:31], nodeKey},
		"short node key":  {fingerprint, nodeKey[:31]},
	} {
		if revokedFor(keys[0], keys[1]) {
			t.Fatalf("schema 161 answered revoked for %s", name)
		}
	}
}

// deviceDNSLabel returns the DNS label a Device holds ("" for none).
func deviceDNSLabel(ctx context.Context, t *testing.T, admin *pgx.Conn, device node.ID) string {
	t.Helper()
	var label string
	err := admin.QueryRow(ctx, `SELECT label.dns_label FROM mesh.device_dns_label AS label
JOIN mesh.device AS device ON device.workspace_id = label.workspace_id
 AND device.network_id = label.network_id AND device.id = label.device_id
WHERE device.public_id = $1::UUID`, device.String()).Scan(&label)
	if errors.Is(err, pgx.ErrNoRows) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return label
}

// assertDeviceExtension qualifies schema 180: device.manage extends a member
// Device only once it expired or expires within a day, by one hour to seven
// days from the database clock, moving its expiry later, with one audit event
// and one Network revision.
func assertDeviceExtension(ctx context.Context, t *testing.T, admin *pgx.Conn, lifecycle *devicelifecycle.Service,
	scope network.Scope, owner, member accountsession.Session) {
	t.Helper()
	var text string
	if err := admin.QueryRow(ctx, `SELECT public_id::TEXT FROM mesh.device
WHERE workspace_id = 103 AND network_id = 203 AND state = 'active' AND deleted_at IS NULL
  AND ownership = 'member' AND expires_at < '2200-01-01'
ORDER BY expires_at DESC, public_id LIMIT 1`).Scan(&text); err != nil {
		t.Fatalf("find a member Device to extend: %v", err)
	}
	device, err := node.ParseID(text)
	if err != nil {
		t.Fatal(err)
	}
	request := func(action devicelifecycle.Action, extension time.Duration) devicelifecycle.Request {
		return devicelifecycle.Request{Scope: scope, DeviceID: device,
			Action: action, Extension: extension, Reason: "Owner is travelling",
			ExpectedVersion: readIntegrationDevice(ctx, t, admin, device).version, CorrelationID: newCorrelationID(t)}
	}
	extend := func(session accountsession.Session, extension time.Duration) (devicelifecycle.Result, error) {
		return lifecycle.Change(ctx, session, request(devicelifecycle.ActionExtend, extension))
	}
	expireIntegrationDevice(ctx, t, admin, device)
	if _, err := extend(member, time.Hour); !errors.Is(err, devicelifecycle.ErrForbidden) {
		t.Fatalf("a member without device.manage extended a Device: %v", err)
	}
	stale := request(devicelifecycle.ActionExtend, time.Hour)
	stale.ExpectedVersion--
	if _, err := lifecycle.Change(ctx, owner, stale); !errors.Is(err, devicelifecycle.ErrVersionConflict) {
		t.Fatalf("stale extension: %v", err)
	}
	if extended, err := extend(owner, time.Hour); err != nil || extended.After.ExpiresAt.Before(time.Now()) {
		t.Fatalf("extend an expired Device by an hour = %+v, %v", extended, err)
	}
	networkBefore, _ := fixtureNetworkRevisions(ctx, t, admin)
	extended, err := extend(owner, 24*time.Hour)
	if err != nil {
		t.Fatalf("extend an expired Device: %v", err)
	}
	var now time.Time
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.now()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	if remaining := extended.After.ExpiresAt.Sub(now); remaining < 23*time.Hour || remaining > 24*time.Hour {
		t.Fatalf("extended expiry %v is %v from now, want about a day", extended.After.ExpiresAt, remaining)
	}
	if networkAfter, _ := fixtureNetworkRevisions(ctx, t, admin); networkAfter != networkBefore+1 ||
		countDeviceAudit(ctx, t, admin, device, "device.expiry_extended") != 2 {
		t.Fatal("an extension must advance the Network once with one audit event")
	}
	// A shorter extension would move the expiry earlier.
	if _, err := extend(owner, time.Hour); !errors.Is(err, devicelifecycle.ErrWrongState) {
		t.Fatalf("an extension moved the expiry earlier: %v", err)
	}
	// A suspended Device is extended but stays suspended.
	if _, err := lifecycle.Change(ctx, owner, request(devicelifecycle.ActionSuspend, 0)); err != nil {
		t.Fatalf("suspend the extended Device: %v", err)
	}
	week, err := extend(owner, 7*24*time.Hour)
	if err != nil || week.After.State != "suspended" || week.After.SuspendedReason != devicelifecycle.SuspendedByAdmin {
		t.Fatalf("extend a suspended Device = %+v, %v", week, err)
	}
	if _, err := lifecycle.Change(ctx, owner, request(devicelifecycle.ActionResume, 0)); err != nil {
		t.Fatalf("resume the extended Device: %v", err)
	}
	// Seven days from expiry it is outside the one-day window.
	if _, err := extend(owner, 7*24*time.Hour); !errors.Is(err, devicelifecycle.ErrWrongState) {
		t.Fatalf("extended a Device far from expiry: %v", err)
	}
}

// expireIntegrationDevice ends a Device's life an hour ago, with the
// evidence the audit trigger requires.
func expireIntegrationDevice(ctx context.Context, t *testing.T, admin *pgx.Conn, device node.ID) {
	t.Helper()
	version := readIntegrationDevice(ctx, t, admin, device).version
	networkRevision, _ := fixtureNetworkRevisions(ctx, t, admin)
	commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
		changePublicID: "01890f01-0000-7000-8000-000000001801",
		eventPublicID:  "01890f02-0000-7000-8000-000000001801",
		outboxPublicID: "01890f03-0000-7000-8000-000000001801",
		streamID:       203, aggregateKind: "device", aggregatePublicID: device.String(),
		aggregateVersion: version + 1, networkRevision: networkRevision + 1,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "device.expiry.fixture", permission: "system.bootstrap",
		outboxEventClass: "device.expiry.fixture",
	}, func(tx pgx.Tx) {
		if _, err := tx.Exec(ctx, `UPDATE mesh.device
SET expires_at = pg_catalog.now() - INTERVAL '1 hour', version = version + 1, updated_at = pg_catalog.now()
WHERE public_id = $1::UUID`, device.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT * FROM mesh_ops.set_network_scope(
'01890f00-0000-7000-8000-000000000103'::UUID,'01890f00-0000-7000-8000-000000000203'::UUID)`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT * FROM mesh_ops.advance_network_inventory_revision()`); err != nil {
			t.Fatal(err)
		}
	})
}
