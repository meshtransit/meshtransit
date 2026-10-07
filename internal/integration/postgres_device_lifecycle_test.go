//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/devicelifecycle"
	"github.com/meshtransit/meshtransit/internal/enrollment"
	"github.com/meshtransit/meshtransit/internal/enrollment/registration"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/publicid"
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
	if resumed, err := change(owner, devicelifecycle.Request{Action: devicelifecycle.ActionResume,
		Reason: "Found it"}); err != nil || resumed.After.State != "active" {
		t.Fatalf("resume = %+v, %v", resumed, err)
	}

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

	// Rename: unique in the Network, locked against client logins.
	otherName := readIntegrationDevice(ctx, t, admin, other).hostname
	taken, _ := node.ParseHostname(otherName)
	if _, err := change(owner, devicelifecycle.Request{Action: devicelifecycle.ActionRename,
		Hostname: taken}); !errors.Is(err, devicelifecycle.ErrHostnameTaken) {
		t.Fatalf("rename to a taken hostname: %v", err)
	}
	fresh, _ := node.ParseHostname("lifecycle-server")
	if renamed, err := change(owner, devicelifecycle.Request{Action: devicelifecycle.ActionRename,
		Hostname: fresh}); err != nil || renamed.After.Hostname != "lifecycle-server" || !renamed.After.HostnameLocked {
		t.Fatalf("rename = %+v, %v", renamed, err)
	}

	inventoryStore, err := postgresadapter.NewConsoleDeviceInventoryStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	page, err := inventoryStore.ReadDevices(ctx, owner, scope, node.ID{}, 100, time.Now())
	if err != nil {
		t.Fatalf("read inventory: %v", err)
	}
	for _, listed := range page.Devices {
		if listed.ID() == device {
			if listed.Lifecycle().Ownership != "workspace" || listed.Hostname() != "lifecycle-server" {
				t.Fatalf("inventory lifecycle = %+v", listed.Lifecycle())
			}
			return
		}
	}
	t.Fatal("inventory lacks the Device")
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
		time.Now().Add(5*time.Minute))
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
