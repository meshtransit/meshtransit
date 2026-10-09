//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/devicelifecycle"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/memberlifecycle"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

const integrationSuspendedMemberID = "01890f00-0000-7000-8000-000000001961"

// assertPostgreSQLMemberSuspension qualifies schema 127 through the
// production store with a member created for this check: a plain member
// cannot suspend anyone, nobody suspends the owner or themselves, suspending
// the member suspends exactly their active Devices (reason member) and
// advances that Network once with evidence, a member-suspended Device cannot
// be resumed on its own, and resuming the member restores those Devices while
// an administrator's own suspension stays. The fixture is undone afterwards.
func assertPostgreSQLMemberSuspension(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool) {
	t.Helper()
	store, err := postgresadapter.NewMemberLifecycleStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	members, err := memberlifecycle.NewService(store, accountsession.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	devices := newIntegrationDeviceLifecycle(t, runtimePool)
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	owner := managementRBACAccountSessionFixture(t)
	plain := authorityConfirmerAccountSessionFixture(t)
	workspaceID, _ := owner.LoginWorkspaceID()
	networkID, err := network.ParseID(guardrailFixtureNetwork)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	fixture := activeFixtureDevices(ctx, t, admin, 2)
	laptop, parked := fixture[0], fixture[1]
	restore := seedSuspendableMember(ctx, t, admin, laptop.String(), parked.String())
	defer restore()
	memberID, err := publicid.Parse(integrationSuspendedMemberID)
	if err != nil {
		t.Fatal(err)
	}
	change := func(session accountsession.Session, member publicid.ID, action memberlifecycle.Action) (
		memberlifecycle.Result, error) {
		return members.Change(ctx, session, memberlifecycle.Request{
			WorkspaceID: workspaceID, MemberID: member, Action: action, Reason: "Integration check",
			CorrelationID: newCorrelationID(t),
		})
	}

	if _, err := change(plain, memberID, memberlifecycle.ActionSuspend); !errors.Is(err, memberlifecycle.ErrForbidden) {
		t.Fatalf("plain member suspended a member: %v", err)
	}
	if _, err := change(owner, publicid.ID(owner.PrincipalID()), memberlifecycle.ActionSuspend); !errors.Is(err,
		memberlifecycle.ErrProtected) {
		t.Fatalf("owner suspended themselves: %v", err)
	}
	if _, err := change(owner, memberID, memberlifecycle.ActionResume); !errors.Is(err, memberlifecycle.ErrWrongState) {
		t.Fatalf("resumed an active member: %v", err)
	}
	networkBefore, _ := fixtureNetworkRevisions(ctx, t, admin)
	suspended, err := change(owner, memberID, memberlifecycle.ActionSuspend)
	if err != nil || suspended.After.State != "suspended" || len(suspended.Devices) != 1 ||
		suspended.Devices[0].DeviceID != laptop || len(suspended.Networks) != 1 {
		t.Fatalf("suspend = %+v, %v", suspended, err)
	}
	if networkAfter, _ := fixtureNetworkRevisions(ctx, t, admin); networkAfter != networkBefore+1 {
		t.Fatalf("member suspension advanced the Network %d → %d, want once", networkBefore, networkAfter)
	}
	if row := readIntegrationDevice(ctx, t, admin, laptop); row.state != "suspended" || row.reason == nil ||
		*row.reason != "member" {
		t.Fatalf("member's Device = %+v, want suspended with the member", row)
	}
	// One event on the Workspace stream and one on the stream of the Network
	// whose maps it rebuilt.
	if count := countMemberAudit(ctx, t, admin, "member.suspended"); count != 2 {
		t.Fatalf("member suspension recorded %d events, want the Workspace one and the Network one", count)
	}
	if _, err := devices.Change(ctx, owner, devicelifecycle.Request{
		Scope: scope, DeviceID: laptop, Action: devicelifecycle.ActionResume, Reason: "Too early",
		ExpectedVersion: readIntegrationDevice(ctx, t, admin, laptop).version, CorrelationID: newCorrelationID(t),
	}); !errors.Is(err, devicelifecycle.ErrWrongState) {
		t.Fatalf("resumed a member-suspended Device on its own: %v", err)
	}
	if _, err := change(owner, memberID, memberlifecycle.ActionSuspend); !errors.Is(err, memberlifecycle.ErrWrongState) {
		t.Fatalf("suspended a suspended member: %v", err)
	}

	resumed, err := change(owner, memberID, memberlifecycle.ActionResume)
	if err != nil || resumed.After.State != "active" || len(resumed.Devices) != 1 || resumed.Devices[0].DeviceID != laptop {
		t.Fatalf("resume = %+v, %v", resumed, err)
	}
	if row := readIntegrationDevice(ctx, t, admin, laptop); row.state != "active" || row.reason != nil {
		t.Fatalf("resumed member's Device = %+v", row)
	}
	if row := readIntegrationDevice(ctx, t, admin, parked); row.state != "suspended" || row.reason == nil ||
		*row.reason != "admin" {
		t.Fatalf("an administrator's suspension must stay: %+v", row)
	}
}

func countMemberAudit(ctx context.Context, t *testing.T, admin *pgx.Conn, action string) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh_audit.audit_event
WHERE target_kind = 'workspace_membership' AND target_public_id = $1::UUID AND action = $2`,
		integrationSuspendedMemberID, action).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// seedSuspendableMember adds an account member to Workspace 103 who owns the
// first Device (active) and the second (suspended by an administrator), and
// returns the function that puts both Devices back and revokes the member.
// Triggers are bypassed only for this fixture, never for the code under test.
func seedSuspendableMember(ctx context.Context, t *testing.T, admin *pgx.Conn, laptop, parked string) func() {
	t.Helper()
	type saved struct {
		owner, custodian int64
		ownership, state string
		reason           *string
	}
	read := func(device string) saved {
		var row saved
		if err := admin.QueryRow(ctx, `SELECT owner_principal_id, custodian_principal_id, ownership, state,
    suspended_reason FROM mesh.device WHERE public_id = $1::UUID`, device).Scan(&row.owner, &row.custodian,
			&row.ownership, &row.state, &row.reason); err != nil {
			t.Fatal(err)
		}
		return row
	}
	original := map[string]saved{laptop: read(laptop), parked: read(parked)}
	bypass := func(statements []string, arguments ...[]any) {
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `RESET ROLE; SET LOCAL session_replication_role = replica`); err != nil {
			t.Fatal(err)
		}
		for index, statement := range statements {
			var args []any
			if index < len(arguments) {
				args = arguments[index]
			}
			if _, err := tx.Exec(ctx, statement, args...); err != nil {
				t.Fatalf("member fixture: %v", err)
			}
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	bypass([]string{
		`INSERT INTO mesh.principal (id, public_id, deployment_id, kind, state) OVERRIDING SYSTEM VALUE
VALUES (1961, '` + integrationSuspendedMemberID + `', 1, 'account', 'active')`,
		`INSERT INTO mesh.account (id, public_id, deployment_id, principal_id, display_name, session_generation, recovery_state)
OVERRIDING SYSTEM VALUE VALUES (1962, '01890f00-0000-7000-8000-000000001962', 1, 1961, 'Suspendable Member', 1, 'verified')`,
		`INSERT INTO mesh.workspace_membership (id, public_id, deployment_id, workspace_id, principal_id, state,
    authority_generation, valid_from) OVERRIDING SYSTEM VALUE
VALUES (1963, '01890f00-0000-7000-8000-000000001963', 1, 103, 1961, 'active', 1, now() - INTERVAL '1 minute')`,
		`UPDATE mesh.device SET ownership = 'member', owner_principal_id = 1961, custodian_principal_id = 1961
WHERE public_id = $1::UUID`,
		`UPDATE mesh.device SET ownership = 'member', owner_principal_id = 1961, custodian_principal_id = 1961,
    state = 'suspended', suspended_reason = 'admin' WHERE public_id = $1::UUID`,
	}, nil, nil, nil, []any{laptop}, []any{parked})
	return func() {
		statements := []string{`UPDATE mesh.workspace_membership SET state = 'revoked' WHERE id = 1963`}
		arguments := [][]any{nil}
		for device, row := range original {
			statements = append(statements, `UPDATE mesh.device SET ownership = $2, owner_principal_id = $3,
    custodian_principal_id = $4, state = $5, suspended_reason = $6 WHERE public_id = $1::UUID`)
			arguments = append(arguments, []any{device, row.ownership, row.owner, row.custodian, row.state, row.reason})
		}
		bypass(statements, arguments...)
	}
}
