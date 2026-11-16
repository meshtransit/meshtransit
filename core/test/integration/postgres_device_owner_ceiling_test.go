//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/devicelifecycle"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/revocation"
)

const (
	ceilingAdminHolderID = "01890f00-0000-7000-8000-000000009301"
	ceilingPlainHolderID = "01890f00-0000-7000-8000-000000009302"
)

// assertDeviceOwnerCeiling qualifies schema 295 (TD-SEC-87): acting on a
// member's Device needs the delegation ceiling over every role its owner
// holds, and only the Workspace owner acts on the owner's Devices. An
// it_admin (who grants only it_admin) changes and revokes nothing on the
// owner's or an admin's Device, but still acts on a plain member's; the
// owner acts on every Device. Device leaves with its original owner.
func assertDeviceOwnerCeiling(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool, lifecycle *devicelifecycle.Service, scope network.Scope,
	owner, itAdmin accountsession.Session, device node.ID) {
	t.Helper()
	var ownership string
	var ownerID, custodianID int64
	if err := admin.QueryRow(ctx, `SELECT ownership, owner_principal_id, custodian_principal_id
FROM mesh.device WHERE public_id = $1::UUID`, device.String()).Scan(&ownership, &ownerID, &custodianID); err != nil {
		t.Fatal(err)
	}
	runRemovalFixture(ctx, t, admin, []removalFixtureStatement{
		{sql: `INSERT INTO mesh.principal (id, public_id, deployment_id, kind, state)
OVERRIDING SYSTEM VALUE VALUES (9301, $1::UUID, 1, 'account', 'active'), (9302, $2::UUID, 1, 'account', 'active')`,
			args: []any{ceilingAdminHolderID, ceilingPlainHolderID}},
		{sql: `INSERT INTO mesh.workspace_membership (id, public_id, deployment_id, workspace_id, principal_id, state,
    valid_from)
OVERRIDING SYSTEM VALUE VALUES
    (9301, pg_catalog.uuidv7(), 1, 103, 9301, 'active', now() - INTERVAL '1 hour'),
    (9302, pg_catalog.uuidv7(), 1, 103, 9302, 'active', now() - INTERVAL '1 hour')`},
		{sql: `INSERT INTO mesh.workspace_role_assignment (id, public_id, deployment_id, workspace_id, principal_id,
    workspace_membership_id, role_key, state, authority_generation, valid_from, version, created_at, updated_at)
OVERRIDING SYSTEM VALUE VALUES (9301, pg_catalog.uuidv7(), 1, 103, 9301, 9301, 'admin', 'active', 1,
    now() - INTERVAL '1 minute', 1, now() - INTERVAL '1 minute', now() - INTERVAL '1 minute')`},
	})
	removeITAdmin := seedEnrollmentKeyRole(ctx, t, admin, itAdmin, 1998, "it_admin")
	defer func() {
		removeITAdmin()
		runRemovalFixture(ctx, t, admin, []removalFixtureStatement{
			{sql: `UPDATE mesh.device SET ownership = $2, owner_principal_id = $3, custodian_principal_id = $4
WHERE public_id = $1::UUID`, args: []any{device.String(), ownership, ownerID, custodianID}},
			{sql: `DELETE FROM mesh.workspace_role_assignment WHERE id = 9301`},
			{sql: `DELETE FROM mesh.workspace_membership WHERE id IN (9301, 9302)`},
			{sql: `DELETE FROM mesh.principal WHERE id IN (9301, 9302)`},
		})
	}()
	ownedBy := func(principal int64) {
		t.Helper()
		runRemovalFixture(ctx, t, admin, []removalFixtureStatement{{sql: `UPDATE mesh.device
SET ownership = 'member', owner_principal_id = $2, custodian_principal_id = $2 WHERE public_id = $1::UUID`,
			args: []any{device.String(), principal}}})
	}
	act := func(session accountsession.Session, action devicelifecycle.Action) error {
		t.Helper()
		_, err := lifecycle.Change(ctx, session, devicelifecycle.Request{Scope: scope, DeviceID: device,
			Action: action, Reason: "Ceiling", ExpectedVersion: readIntegrationDevice(ctx, t, admin, device).version,
			CorrelationID: newCorrelationID(t)})
		return err
	}
	revocations := newIntegrationDeviceRevocationService(t, runtimePool)

	for _, holder := range []struct {
		name      string
		principal int64
	}{{"the owner's", 11}, {"an admin's", 9301}} {
		ownedBy(holder.principal)
		before := readIntegrationDevice(ctx, t, admin, device)
		if err := act(itAdmin, devicelifecycle.ActionSuspend); !errors.Is(err, devicelifecycle.ErrForbidden) {
			t.Fatalf("it_admin suspended %s Device: %v", holder.name, err)
		}
		if err := act(itAdmin, devicelifecycle.ActionTransferWorkspace); !errors.Is(err, devicelifecycle.ErrForbidden) {
			t.Fatalf("it_admin took %s Device for the Workspace: %v", holder.name, err)
		}
		if _, err := revocations.Revoke(ctx, deviceOwnerCeilingRevocation(t, scope, device, before.version,
			itAdmin)); !errors.Is(err, revocation.ErrForbidden) {
			t.Fatalf("it_admin revoked %s Device: %v", holder.name, err)
		}
		if after := readIntegrationDevice(ctx, t, admin, device); after.version != before.version ||
			after.state != "active" {
			t.Fatalf("%s Device changed: %+v, want %+v", holder.name, after, before)
		}
	}
	// The owner acts on an admin's Device.
	if err := act(owner, devicelifecycle.ActionSuspend); err != nil {
		t.Fatalf("owner suspended an admin's Device: %v", err)
	}
	if err := act(owner, devicelifecycle.ActionResume); err != nil {
		t.Fatalf("owner resumed an admin's Device: %v", err)
	}
	// A Workspace Device is anyone's with the permission.
	runRemovalFixture(ctx, t, admin, []removalFixtureStatement{{sql: `UPDATE mesh.device SET ownership = 'workspace'
WHERE public_id = $1::UUID`, args: []any{device.String()}}})
	if err := act(itAdmin, devicelifecycle.ActionSuspend); err != nil {
		t.Fatalf("it_admin suspended a Workspace Device: %v", err)
	}
	if err := act(itAdmin, devicelifecycle.ActionResume); err != nil {
		t.Fatalf("it_admin resumed a Workspace Device: %v", err)
	}
	// it_admin still acts on a plain member's Device.
	ownedBy(9302)
	if err := act(itAdmin, devicelifecycle.ActionSuspend); err != nil {
		t.Fatalf("it_admin suspended a plain member's Device: %v", err)
	}
	if err := act(itAdmin, devicelifecycle.ActionResume); err != nil {
		t.Fatalf("it_admin resumed a plain member's Device: %v", err)
	}
}

func deviceOwnerCeilingRevocation(t *testing.T, scope network.Scope, device node.ID, version int64,
	session accountsession.Session) revocation.Command {
	t.Helper()
	reason, err := revocation.NewReason("Ceiling check")
	if err != nil {
		t.Fatal(err)
	}
	proof, err := integrationDeviceRevocationDigester(t).Proof(integrationDeviceRevocationIdempotencyKey(0x95))
	if err != nil {
		t.Fatal(err)
	}
	command, err := revocation.NewCommand(revocation.CommandParams{
		Scope: scope, NodeID: device, ExpectedVersion: version, AccountSession: session,
		Reason: reason, IdempotencyEvidence: proof,
	})
	if err != nil {
		t.Fatal(err)
	}
	return command
}
