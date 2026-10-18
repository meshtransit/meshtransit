//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/authorization"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/memberlifecycle"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace/roles"
)

const (
	// A Workspace member who is not in Network 203 until added.
	networkJoinerID = "01890f00-0000-7000-8000-000000009190"
	// A suspended Workspace member.
	networkSuspendedID = "01890f00-0000-7000-8000-000000009193"
	// An active Workspace member an admin adds.
	networkLateJoinerID = "01890f00-0000-7000-8000-000000009196"
	// An active Workspace member with a custom role binding on Network 203.
	networkBoundID   = "01890f00-0000-7000-8000-000000009200"
	networkFixtureID = "01890f00-0000-7000-8000-000000000203"
)

// networkMemberFixture is the production service and the sessions it is
// driven with.
type networkMemberFixture struct {
	service   *memberlifecycle.NetworkService
	roles     *roles.Service
	owner     accountsession.Session
	confirmer accountsession.Session
	scope     network.Scope
}

func newNetworkMemberFixture(t *testing.T, runtimePool *postgresadapter.Pool) networkMemberFixture {
	t.Helper()
	store, err := postgresadapter.NewNetworkMemberStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service, err := memberlifecycle.NewNetworkService(store, accountsession.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	owner := managementRBACAccountSessionFixture(t)
	workspaceID, _ := owner.LoginWorkspaceID()
	networkID, err := network.ParseID(networkFixtureID)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	return networkMemberFixture{
		service: service, roles: newIntegrationRoleService(t, runtimePool), owner: owner,
		confirmer: authorityConfirmerAccountSessionFixture(t), scope: scope,
	}
}

func (fixture networkMemberFixture) add(ctx context.Context, t *testing.T, session accountsession.Session,
	members ...string) (memberlifecycle.NetworkAdditionResult, error) {
	t.Helper()
	ids := make([]publicid.ID, len(members))
	for index, member := range members {
		ids[index] = mustIntegrationPublicID(t, member)
	}
	return fixture.service.Add(ctx, session, fixture.scope, ids, newCorrelationID(t))
}

func (fixture networkMemberFixture) remove(ctx context.Context, t *testing.T, session accountsession.Session,
	member string, plans ...memberlifecycle.DevicePlan) (memberlifecycle.NetworkRemovalResult, error) {
	t.Helper()
	return fixture.service.Remove(ctx, session, memberlifecycle.NetworkRemovalRequest{
		Scope: fixture.scope, MemberID: mustIntegrationPublicID(t, member), Reason: "Integration check",
		Devices: plans, CorrelationID: newCorrelationID(t),
	})
}

// grant assigns a built-in role to the confirmer and returns its revocation.
func (fixture networkMemberFixture) grant(ctx context.Context, t *testing.T, principal string,
	role authorization.BuiltinRole, networkID network.ID) func() {
	t.Helper()
	command := newAssignCommand(t, fixture.owner, nil, mustIntegrationPublicID(t, principal), role, networkID)
	if _, err := fixture.roles.Assign(ctx, command); err != nil {
		t.Fatalf("assign %s: %v", role, err)
	}
	return func() {
		if _, err := fixture.roles.Revoke(ctx, newRevokeCommand(t, fixture.owner, nil, command.AssignmentID, 1)); err != nil {
			t.Fatalf("revoke %s: %v", role, err)
		}
	}
}

func mustIntegrationPublicID(t *testing.T, text string) publicid.ID {
	t.Helper()
	id, err := publicid.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// assertPostgreSQLNetworkMembers qualifies schema 166 through the production
// store. A Workspace member outside Network 203 cannot pick it for browser
// enrollment until the owner adds them; a plain member, a network_admin and
// a Network-scope auditor cannot change members, and the auditor sees only
// the Network's own members; it_admin and admin add members; a suspended
// member and a stranger are refused; each addition is one event on the
// Network stream. Removing a member hands their Devices in the Network over
// as planned and revokes the rest, cancels the handover waiting for them,
// revokes their key and Network role there, keeps their Workspace membership
// and Workspace role, advances the Network once and records one event that
// wakes it. The owner and the actor are protected. Everything it adds is
// removed again and the Devices are put back.
func assertPostgreSQLNetworkMembers(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool) {
	t.Helper()
	fixture := newNetworkMemberFixture(t, runtimePool)
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	seedNetworkMemberPrincipals(ctx, t, admin)
	owner, confirmer := fixture.owner, fixture.confirmer
	confirmerID := publicid.ID(confirmer.PrincipalID()).String()
	ownerID := publicid.ID(owner.PrincipalID()).String()

	// The confirmer is removed again at the end, which must not touch any
	// Device another check relies on.
	var owned int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh.device WHERE network_id = 203 AND owner_principal_id = 13
  AND ownership = 'member' AND deleted_at IS NULL`).Scan(&owned); err != nil || owned != 0 {
		t.Fatalf("the confirmer owns %d Devices of Network 203: %v", owned, err)
	}

	// Red: outside the Network, the confirmer cannot enroll into it.
	if confirmerCanEnrollInto(ctx, t, admin, runtimePool, fixture.scope) {
		t.Fatal("a Workspace member outside the Network can already enroll into it")
	}
	if _, err := fixture.service.List(ctx, confirmer, fixture.scope, publicid.ID{}, 10); !errors.Is(err,
		memberlifecycle.ErrForbidden) {
		t.Fatalf("plain member listed Network members: %v", err)
	}
	if _, err := fixture.add(ctx, t, confirmer, confirmerID); !errors.Is(err, memberlifecycle.ErrForbidden) {
		t.Fatalf("plain member added themselves: %v", err)
	}

	page, err := fixture.service.List(ctx, owner, fixture.scope, publicid.ID{}, memberlifecycle.MaximumNetworkMemberPage)
	if err != nil || !page.CanManage {
		t.Fatalf("owner list = %+v, %v", page, err)
	}
	if member := findNetworkMember(page, confirmerID); member == nil || member.Membership != nil ||
		member.WorkspaceState != "active" {
		t.Fatalf("confirmer in owner list = %+v", member)
	}
	if member := findNetworkMember(page, networkSuspendedID); member == nil || member.WorkspaceState != "suspended" {
		t.Fatalf("suspended member in owner list = %+v", member)
	}
	first, err := fixture.service.List(ctx, owner, fixture.scope, publicid.ID{}, 1)
	if err != nil || len(first.Members) != 1 || !first.HasMore {
		t.Fatalf("first page = %+v, %v", first, err)
	}
	second, err := fixture.service.List(ctx, owner, fixture.scope, first.Members[0].PrincipalID, 1)
	if err != nil || len(second.Members) != 1 ||
		second.Members[0].PrincipalID.String() <= first.Members[0].PrincipalID.String() {
		t.Fatalf("second page = %+v, %v", second, err)
	}

	// Green: the owner adds the confirmer (and themselves, if needed), who
	// can then enroll into the Network. A repeat changes nothing.
	added, err := fixture.add(ctx, t, owner, confirmerID, ownerID)
	if err != nil || len(added.Added)+len(added.Unchanged) != 2 || findAdded(added, confirmerID) == nil {
		t.Fatalf("owner add = %+v, %v", added, err)
	}
	if !confirmerCanEnrollInto(ctx, t, admin, runtimePool, fixture.scope) {
		t.Fatal("an added member cannot enroll into the Network")
	}
	if count := countNetworkMemberAudit(ctx, t, admin, confirmerID, "network.member.added"); count != 1 {
		t.Fatalf("addition recorded %d Network events, want 1", count)
	}
	again, err := fixture.add(ctx, t, owner, confirmerID)
	if err != nil || len(again.Added) != 0 || len(again.Unchanged) != 1 {
		t.Fatalf("repeated add = %+v, %v", again, err)
	}
	if count := countNetworkMemberAudit(ctx, t, admin, confirmerID, "network.member.added"); count != 1 {
		t.Fatalf("a repeated addition recorded evidence: %d", count)
	}
	if _, err := fixture.add(ctx, t, owner, networkSuspendedID); !errors.Is(err, memberlifecycle.ErrWrongState) {
		t.Fatalf("suspended member added: %v", err)
	}
	if _, err := fixture.add(ctx, t, owner, "01890f00-0000-7000-8000-00000000919f"); !errors.Is(err,
		memberlifecycle.ErrNotFound) {
		t.Fatalf("stranger added: %v", err)
	}

	assertNetworkMemberRoles(ctx, t, fixture)

	// it_admin adds a member; the removal below runs against them.
	revokeITAdmin := fixture.grant(ctx, t, confirmerID, authorization.BuiltinRoleITAdmin, network.ID{})
	if added, err := fixture.add(ctx, t, confirmer, networkJoinerID); err != nil || len(added.Added) != 1 {
		t.Fatalf("it_admin add = %+v, %v", added, err)
	}
	assertNetworkMemberRemoval(ctx, t, admin, fixture)
	revokeITAdmin()

	// admin adds a member too.
	revokeAdmin := fixture.grant(ctx, t, confirmerID, authorization.BuiltinRoleAdmin, network.ID{})
	if added, err := fixture.add(ctx, t, confirmer, networkLateJoinerID); err != nil || len(added.Added) != 1 {
		t.Fatalf("admin add = %+v, %v", added, err)
	}
	revokeAdmin()

	assertNetworkMemberCeiling(ctx, t, admin, fixture)

	// Put the Network back as it was.
	if _, err := fixture.remove(ctx, t, owner, confirmerID); err != nil {
		t.Fatalf("remove the confirmer afterwards: %v", err)
	}
	if confirmerCanEnrollInto(ctx, t, admin, runtimePool, fixture.scope) {
		t.Fatal("a removed member can still enroll into the Network")
	}
}

// assertNetworkMemberRoles checks what roles without network.member.manage
// may do.
func assertNetworkMemberRoles(ctx context.Context, t *testing.T, fixture networkMemberFixture) {
	t.Helper()
	confirmerID := publicid.ID(fixture.confirmer.PrincipalID()).String()
	revoke := fixture.grant(ctx, t, confirmerID, authorization.BuiltinRoleNetworkAdmin, network.ID{})
	page, err := fixture.service.List(ctx, fixture.confirmer, fixture.scope, publicid.ID{}, 200)
	if err != nil || page.CanManage || findNetworkMember(page, networkJoinerID) == nil {
		t.Fatalf("network_admin list = %+v, %v", page, err)
	}
	if _, err := fixture.add(ctx, t, fixture.confirmer, networkJoinerID); !errors.Is(err, memberlifecycle.ErrForbidden) {
		t.Fatalf("network_admin added a member: %v", err)
	}
	revoke()
	// A Network-scope auditor reads the Network's members but not the rest
	// of the Workspace.
	revoke = fixture.grant(ctx, t, confirmerID, authorization.BuiltinRoleAuditor, fixture.scope.NetworkID())
	page, err = fixture.service.List(ctx, fixture.confirmer, fixture.scope, publicid.ID{}, 200)
	if err != nil || page.CanManage || findNetworkMember(page, confirmerID) == nil ||
		findNetworkMember(page, networkJoinerID) != nil {
		t.Fatalf("Network auditor list = %+v, %v", page, err)
	}
	for _, member := range page.Members {
		if member.Membership == nil {
			t.Fatalf("Network auditor saw a Workspace member outside the Network: %+v", member)
		}
	}
	revoke()
}

// assertNetworkMemberRemoval removes the joiner, who owns three Devices of
// the Network, is the pending recipient of a fourth, issued a key for it and
// holds a Workspace role and a role for this Network.
func assertNetworkMemberRemoval(ctx context.Context, t *testing.T, admin *pgx.Conn, fixture networkMemberFixture) {
	t.Helper()
	owner, confirmer := fixture.owner, fixture.confirmer
	confirmerID := publicid.ID(confirmer.PrincipalID()).String()
	ownerID := publicid.ID(owner.PrincipalID()).String()
	devices := activeFixtureDevices(ctx, t, admin, 4)
	moved, handed, unnamed, incoming := devices[0], devices[1], devices[2], devices[3]
	restore := seedNetworkMemberDevices(ctx, t, admin, devices)
	defer restore()
	revokeBilling := fixture.grant(ctx, t, networkJoinerID, authorization.BuiltinRoleBillingAdmin, network.ID{})
	defer revokeBilling()
	networkRole := newAssignCommand(t, owner, nil, mustIntegrationPublicID(t, networkJoinerID),
		authorization.BuiltinRoleAuditor, fixture.scope.NetworkID())
	if _, err := fixture.roles.Assign(ctx, networkRole); err != nil {
		t.Fatalf("assign Network auditor: %v", err)
	}

	if _, err := fixture.remove(ctx, t, confirmer, ownerID); !errors.Is(err, memberlifecycle.ErrProtected) {
		t.Fatalf("it_admin removed the owner: %v", err)
	}
	if _, err := fixture.remove(ctx, t, confirmer, confirmerID); !errors.Is(err, memberlifecycle.ErrProtected) {
		t.Fatalf("it_admin removed themselves: %v", err)
	}
	if _, err := fixture.remove(ctx, t, owner, networkJoinerID, memberlifecycle.DevicePlan{
		DeviceID: incoming, Action: memberlifecycle.DeviceTransferWorkspace,
	}); !errors.Is(err, memberlifecycle.ErrPlan) {
		t.Fatalf("plan with someone else's Device = %v", err)
	}
	if _, err := fixture.remove(ctx, t, owner, networkJoinerID, memberlifecycle.DevicePlan{
		DeviceID: handed, Action: memberlifecycle.DeviceTransferMember,
		NewOwnerID: mustIntegrationPublicID(t, networkLateJoinerID),
	}); !errors.Is(err, memberlifecycle.ErrNewOwner) {
		t.Fatalf("handover to a Workspace member outside the Network = %v", err)
	}
	if row := readIntegrationDevice(ctx, t, admin, unnamed); row.state != "active" || row.ownership != "member" {
		t.Fatalf("a refused removal changed a Device: %+v", row)
	}

	networkBefore, _ := fixtureNetworkRevisions(ctx, t, admin)
	// Schema 182: the removal runs while a share holds the Network revision.
	removed, err := removeWhileNetworkRevisionHeld(ctx, t, admin, func() (memberlifecycle.NetworkRemovalResult, error) {
		return fixture.service.Remove(ctx, owner, memberlifecycle.NetworkRemovalRequest{
			Scope: fixture.scope, MemberID: mustIntegrationPublicID(t, networkJoinerID), Reason: "Integration check",
			Devices: []memberlifecycle.DevicePlan{
				{DeviceID: moved, Action: memberlifecycle.DeviceTransferWorkspace},
				{DeviceID: handed, Action: memberlifecycle.DeviceTransferMember,
					NewOwnerID: mustIntegrationPublicID(t, confirmerID)},
			},
			CorrelationID: newCorrelationID(t),
		})
	})
	if err != nil || removed.After.State != "revoked" || len(removed.Devices) != 3 ||
		removed.HandoversCancelled != 1 || removed.KeysRevoked != 1 || removed.RolesRevoked != 1 ||
		removed.Network.NetworkID != fixture.scope.NetworkID() {
		t.Fatalf("remove = %+v, %v", removed, err)
	}
	if networkAfter, _ := fixtureNetworkRevisions(ctx, t, admin); networkAfter != networkBefore+1 ||
		removed.Network.NetworkRevision != networkAfter {
		t.Fatalf("removal advanced the Network %d → %d, want once", networkBefore, networkAfter)
	}
	if row := readIntegrationDevice(ctx, t, admin, moved); row.ownership != "workspace" || row.state != "active" {
		t.Fatalf("Device moved to the Workspace = %+v", row)
	}
	if row := readIntegrationDevice(ctx, t, admin, handed); row.state != "suspended" || row.reason == nil ||
		*row.reason != "handover" || row.handover == nil || *row.handover != confirmerID {
		t.Fatalf("Device handed over = %+v", row)
	}
	if row := readIntegrationDevice(ctx, t, admin, unnamed); row.state != "revoked" {
		t.Fatalf("unnamed Device = %+v, want revoked", row)
	}
	if active := activeKeyEpochs(ctx, t, admin, unnamed); active != 0 {
		t.Fatalf("revoked Device kept %d active keys", active)
	}
	if row := readIntegrationDevice(ctx, t, admin, incoming); row.state != "suspended" || row.reason == nil ||
		*row.reason != "admin" || row.handover != nil {
		t.Fatalf("Device waiting for the member = %+v, want suspended for an administrator", row)
	}
	assertNetworkMemberRemovalRows(ctx, t, admin, networkRole.AssignmentID)
	if count := countNetworkMemberAudit(ctx, t, admin, networkJoinerID, "network.member.removed"); count != 1 {
		t.Fatalf("removal recorded %d Network events, want 1", count)
	}
	if count := countNetworkWakeups(ctx, t, admin, networkJoinerID); count != 1 {
		t.Fatalf("removal queued %d Network wakeups, want 1", count)
	}
	if _, err := fixture.remove(ctx, t, owner, networkJoinerID); !errors.Is(err, memberlifecycle.ErrNotFound) {
		t.Fatalf("removed a removed member: %v", err)
	}
}

// removeWhileNetworkRevisionHeld qualifies schema 182. Another transaction,
// standing in for a share, holds the Network revision while the removal
// runs; once the removal holds the Workspace and waits for the revision, that
// transaction takes the Workspace FOR KEY SHARE, as the foreign key check of
// its audit event does. With the Workspace locked FOR UPDATE it would wait
// for the removal, which waits for it: a deadlock. It must get the lock at
// once, within a timeout shorter than deadlock detection, and the removal
// then completes. Nothing is written; the request is built before it runs.
func removeWhileNetworkRevisionHeld(ctx context.Context, t *testing.T, admin *pgx.Conn,
	remove func() (memberlifecycle.NetworkRemovalResult, error),
) (memberlifecycle.NetworkRemovalResult, error) {
	t.Helper()
	share, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		if err := share.Close(cleanupCtx); err != nil {
			t.Errorf("close share connection: %v", err)
		}
	}()
	held, err := share.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackIntegrationTransaction(ctx, t, held)
	if _, err := held.Exec(ctx, `SELECT 1 FROM mesh_ops.network_revision
WHERE workspace_id = 103 AND network_id = 203 FOR UPDATE`); err != nil {
		t.Fatalf("hold the Network revision: %v", err)
	}
	type outcome struct {
		result memberlifecycle.NetworkRemovalResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := remove()
		done <- outcome{result: result, err: err}
	}()
	waitForFunctionBlockedBy(ctx, t, admin, "remove_network_member_v1", share.PgConn().PID())
	assertNoWorkspaceForUpdate(ctx, t, admin)
	// Below the default one-second deadlock_timeout, so a regression fails
	// here as a lock timeout instead of a deadlock the removal might retry.
	if _, err := held.Exec(ctx, `SET LOCAL lock_timeout = '500ms'`); err != nil {
		t.Fatal(err)
	}
	if _, err := held.Exec(ctx, `SELECT 1 FROM mesh.workspace WHERE id = 103 FOR KEY SHARE`); err != nil {
		t.Fatalf("a foreign key check waited for the removal holding the Workspace: %v", err)
	}
	if err := held.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case finished := <-done:
		return finished.result, finished.err
	case <-time.After(30 * time.Second):
		t.Fatal("the removal did not finish after the Network revision was released")
		return memberlifecycle.NetworkRemovalResult{}, nil
	}
}

// assertNoWorkspaceForUpdate checks that no SQL function locks a Workspace
// row FOR UPDATE, which foreign key checks would wait for.
func assertNoWorkspaceForUpdate(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	rows, err := admin.Query(ctx, `SELECT function.proname
FROM pg_catalog.pg_proc AS function
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = function.pronamespace
WHERE namespace.nspname IN ('mesh', 'mesh_ops', 'mesh_audit')
  AND function.prosrc ~* 'FROM\s+mesh\.workspace\s+AS\s+\w+[^;]*?FOR\s+UPDATE'
ORDER BY 1`)
	if err != nil {
		t.Fatalf("read functions: %v", err)
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("read functions: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("functions still lock the Workspace FOR UPDATE: %v", names)
	}
}

// assertNetworkMemberRemovalRows checks what the removal ended and kept.
func assertNetworkMemberRemovalRows(ctx context.Context, t *testing.T, admin *pgx.Conn, networkRole publicid.ID) {
	t.Helper()
	var networkMembership, workspaceMembership, networkAssignment, credential string
	var workspaceRoles int64
	if err := admin.QueryRow(ctx, `SELECT
    (SELECT state FROM mesh.network_membership WHERE principal_id = 9190 AND network_id = 203
       ORDER BY id DESC LIMIT 1),
    (SELECT state FROM mesh.workspace_membership WHERE id = 9192),
    (SELECT state FROM mesh.workspace_role_assignment WHERE public_id = $1::UUID),
    (SELECT state FROM mesh.enrollment_credential WHERE id = 9199),
    (SELECT count(*) FROM mesh.workspace_role_assignment WHERE principal_id = 9190 AND network_id IS NULL
       AND state = 'active')`, networkRole.String()).Scan(&networkMembership, &workspaceMembership,
		&networkAssignment, &credential, &workspaceRoles); err != nil {
		t.Fatal(err)
	}
	if networkMembership != "revoked" || workspaceMembership != "active" || networkAssignment != "revoked" ||
		credential != "revoked" || workspaceRoles != 1 {
		t.Fatalf("after removal: network %s, workspace %s, Network role %s, key %s, Workspace roles %d",
			networkMembership, workspaceMembership, networkAssignment, credential, workspaceRoles)
	}
}

func findNetworkMember(page memberlifecycle.NetworkMemberPage, principal string) *memberlifecycle.NetworkMember {
	for index := range page.Members {
		if page.Members[index].PrincipalID.String() == principal {
			return &page.Members[index]
		}
	}
	return nil
}

func findAdded(result memberlifecycle.NetworkAdditionResult, principal string) *memberlifecycle.NetworkMembership {
	for index := range result.Added {
		if result.Added[index].PrincipalID.String() == principal {
			return &result.Added[index]
		}
	}
	return nil
}

// countNetworkMemberAudit counts one action's events about a member on
// Network 203's stream.
func countNetworkMemberAudit(ctx context.Context, t *testing.T, admin *pgx.Conn, member, action string) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh_audit.audit_event
WHERE target_kind = 'network_membership' AND target_public_id = $1::UUID AND action = $2
  AND workspace_id = 103 AND network_id = 203 AND permission = 'network.member.manage'`, member, action).
		Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func countNetworkWakeups(ctx context.Context, t *testing.T, admin *pgx.Conn, member string) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh_ops.outbox_event
WHERE aggregate_kind = 'network_membership' AND aggregate_public_id = $1::UUID
  AND event_class = 'network.revision.advanced' AND network_id = 203`, member).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// confirmerCanEnrollInto reports whether the confirmer's browser enrollment
// choices in Workspace 103 include the Network.
func confirmerCanEnrollInto(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool,
	scope network.Scope) bool {
	t.Helper()
	var epoch int64
	var keyText string
	var material []byte
	if err := admin.QueryRow(ctx, `SELECT deployment.recovery_epoch, session.token_digest_key_id, session.token_digest
FROM mesh.account_session AS session JOIN mesh.deployment AS deployment ON deployment.id = session.deployment_id
WHERE session.public_id = $1::UUID`, integrationAuthorityConfirmerSessionID).Scan(&epoch, &keyText, &material); err != nil {
		t.Fatal(err)
	}
	keyID, err := accountsession.NewDigestKeyID(keyText)
	if err != nil {
		t.Fatal(err)
	}
	var value [32]byte
	copy(value[:], material)
	digest, err := accountsession.NewDigest(keyID, value)
	if err != nil {
		t.Fatal(err)
	}
	deploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	store, err := postgresadapter.NewAccountSessionStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	choices, found, err := store.ReadBrowserEnrollmentNetworksInWorkspace(ctx, deploymentID, epoch, digest,
		scope.WorkspaceID(), network.ID{}, 100)
	if err != nil || !found {
		t.Fatalf("read the confirmer's enrollment choices: %v/%v", found, err)
	}
	for _, choice := range choices.Networks {
		if choice.NetworkID == scope.NetworkID() {
			return true
		}
	}
	return false
}

// seedNetworkMemberPrincipals adds to Workspace 103 the joiner (with an
// enrollment key for Network 203), a suspended member, a late joiner and a
// member with a custom role binding on Network 203, none of them in Network
// 203. Triggers are bypassed only for this fixture.
func seedNetworkMemberPrincipals(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	statements := []removalFixtureStatement{}
	for _, person := range []struct {
		principal, account, membership int
		name, state                    string
	}{
		{9190, 9191, 9192, "Network Joiner", "active"},
		{9193, 9194, 9195, "Suspended Member", "suspended"},
		{9196, 9197, 9198, "Late Joiner", "active"},
		{9200, 9201, 9202, "Bound Member", "active"},
	} {
		statements = append(statements,
			removalFixtureStatement{sql: `INSERT INTO mesh.principal (id, public_id, deployment_id, kind, state)
OVERRIDING SYSTEM VALUE VALUES ($1::BIGINT, ('01890f00-0000-7000-8000-00000000' || $1::BIGINT::TEXT)::UUID, 1,
    'account', 'active')`,
				args: []any{person.principal}},
			removalFixtureStatement{sql: `INSERT INTO mesh.account (id, public_id, deployment_id, principal_id, display_name,
    session_generation, recovery_state) OVERRIDING SYSTEM VALUE
VALUES ($1::BIGINT, ('01890f00-0000-7000-8000-00000000' || $1::BIGINT::TEXT)::UUID, 1, $2::BIGINT, $3::TEXT, 1,
    'verified')`,
				args: []any{person.account, person.principal, person.name}},
			removalFixtureStatement{sql: `INSERT INTO mesh.workspace_membership (id, public_id, deployment_id, workspace_id,
    principal_id, state, authority_generation, valid_from) OVERRIDING SYSTEM VALUE
VALUES ($1::BIGINT, ('01890f00-0000-7000-8000-00000000' || $1::BIGINT::TEXT)::UUID, 1, 103, $2::BIGINT, $3::TEXT, 1,
    now() - INTERVAL '1 minute')`,
				args: []any{person.membership, person.principal, person.state}})
	}
	statements = append(statements, removalFixtureStatement{sql: `INSERT INTO mesh.enrollment_credential (id, public_id,
    workspace_id, network_id, enrollment_profile_id, issuer_principal_id, digest_algorithm, digest_key_id,
    token_digest, token_fingerprint, issued_recovery_epoch, use_limit_kind, max_uses, used_count, valid_from,
    expires_at, state)
OVERRIDING SYSTEM VALUE SELECT 9199, '01890f00-0000-7000-8000-000000009199', 103, 203, profile.id, 9190,
    'hmac-sha256-v1', 'network-member-check', pg_catalog.sha256('network-member-check'::BYTEA),
    pg_catalog.substr(pg_catalog.sha256('network-member-check-fingerprint'::BYTEA), 1, 16), 1,
    'bounded', 1, 0, now() - INTERVAL '1 minute', now() + INTERVAL '1 hour', 'active'
FROM mesh.enrollment_profile AS profile WHERE profile.workspace_id = 103 AND profile.network_id = 203
ORDER BY profile.id LIMIT 1`})
	statements = append(statements, removalFixtureStatement{sql: `INSERT INTO mesh.role_binding (id, public_id,
    deployment_id, workspace_id, network_id, principal_id, workspace_membership_id, role_definition_id, state,
    valid_from) OVERRIDING SYSTEM VALUE
VALUES (9203, '01890f00-0000-7000-8000-000000009203', 1, 103, 203, 9200, 9202, 842, 'active',
    now() - INTERVAL '1 minute')`})
	runRemovalFixture(ctx, t, admin, statements)
}

// seedNetworkMemberDevices gives the joiner the first three Devices and makes
// the joiner the pending recipient of the fourth. It returns the function
// that puts every Device and key epoch back.
func seedNetworkMemberDevices(ctx context.Context, t *testing.T, admin *pgx.Conn, devices []node.ID) func() {
	t.Helper()
	ids := make([]string, len(devices))
	for index, device := range devices {
		ids[index] = device.String()
	}
	runRemovalFixture(ctx, t, admin, []removalFixtureStatement{
		{sql: `CREATE TEMP TABLE network_member_device_backup AS SELECT * FROM mesh.device
WHERE public_id = ANY ($1::UUID[])`, args: []any{ids}},
		{sql: `CREATE TEMP TABLE network_member_machine_backup AS SELECT key_epoch.* FROM mesh.device_machine_key_epoch
AS key_epoch JOIN mesh.device AS device ON device.id = key_epoch.device_id WHERE device.public_id = ANY ($1::UUID[])`,
			args: []any{ids}},
		{sql: `CREATE TEMP TABLE network_member_node_backup AS SELECT key_epoch.* FROM mesh.device_node_key_epoch
AS key_epoch JOIN mesh.device AS device ON device.id = key_epoch.device_id WHERE device.public_id = ANY ($1::UUID[])`,
			args: []any{ids}},
		{sql: `UPDATE mesh.device SET ownership = 'member', owner_principal_id = 9190, custodian_principal_id = 9190
WHERE public_id = ANY ($1::UUID[]) AND public_id <> ($1::UUID[])[4]`, args: []any{ids}},
		{sql: `UPDATE mesh.device SET state = 'suspended', suspended_reason = 'handover', handover_principal_id = 9190
WHERE public_id = ($1::UUID[])[4]`, args: []any{ids}},
	})
	return func() {
		runRemovalFixture(ctx, t, admin, []removalFixtureStatement{
			{sql: `UPDATE mesh.device AS device SET ownership = backup.ownership,
    owner_principal_id = backup.owner_principal_id, custodian_principal_id = backup.custodian_principal_id,
    state = backup.state, suspended_reason = backup.suspended_reason,
    handover_principal_id = backup.handover_principal_id, expires_at = backup.expires_at
FROM network_member_device_backup AS backup WHERE device.id = backup.id`},
			{sql: `UPDATE mesh.device_machine_key_epoch AS key_epoch SET state = backup.state,
    valid_until = backup.valid_until, revocation_reason = backup.revocation_reason
FROM network_member_machine_backup AS backup WHERE key_epoch.id = backup.id`},
			{sql: `UPDATE mesh.device_node_key_epoch AS key_epoch SET state = backup.state,
    valid_until = backup.valid_until, revocation_reason = backup.revocation_reason
FROM network_member_node_backup AS backup WHERE key_epoch.id = backup.id`},
			{sql: `DROP TABLE network_member_device_backup, network_member_machine_backup, network_member_node_backup`},
		})
	}
}

// assertNetworkMemberCeiling checks the delegation ceiling of a removal by
// the scope of each role: an it_admin bound to this Network removes a member
// whose roles are bound to this Network, but not a Workspace admin, a holder
// of any Workspace-scope role or a member with a custom role binding of the
// Network; a Workspace it_admin removes the custom binding holder but not a
// Workspace admin. It leaves no member or role behind.
func assertNetworkMemberCeiling(ctx context.Context, t *testing.T, admin *pgx.Conn, fixture networkMemberFixture) {
	t.Helper()
	owner, confirmer := fixture.owner, fixture.confirmer
	confirmerID := publicid.ID(confirmer.PrincipalID()).String()
	if added, err := fixture.add(ctx, t, owner, networkJoinerID, networkBoundID); err != nil || len(added.Added) != 2 {
		t.Fatalf("owner add = %+v, %v", added, err)
	}
	networkAuditor := newAssignCommand(t, owner, nil, mustIntegrationPublicID(t, networkLateJoinerID),
		authorization.BuiltinRoleAuditor, fixture.scope.NetworkID())
	if _, err := fixture.roles.Assign(ctx, networkAuditor); err != nil {
		t.Fatalf("assign Network auditor: %v", err)
	}
	revokeWorkspaceAdmin := fixture.grant(ctx, t, networkJoinerID, authorization.BuiltinRoleAdmin, network.ID{})

	revokeNetworkITAdmin := fixture.grant(ctx, t, confirmerID, authorization.BuiltinRoleITAdmin,
		fixture.scope.NetworkID())
	for _, member := range []string{networkJoinerID, networkBoundID} {
		if _, err := fixture.remove(ctx, t, confirmer, member); !errors.Is(err, memberlifecycle.ErrForbidden) {
			t.Fatalf("Network it_admin removed %s: %v", member, err)
		}
	}
	revokeWorkspaceAuditor := fixture.grant(ctx, t, networkLateJoinerID, authorization.BuiltinRoleAuditor,
		network.ID{})
	if _, err := fixture.remove(ctx, t, confirmer, networkLateJoinerID); !errors.Is(err,
		memberlifecycle.ErrForbidden) {
		t.Fatalf("Network it_admin removed a Workspace auditor: %v", err)
	}
	revokeWorkspaceAuditor()
	removed, err := fixture.remove(ctx, t, confirmer, networkLateJoinerID)
	if err != nil || removed.RolesRevoked != 1 {
		t.Fatalf("Network it_admin removing a Network auditor = %+v, %v", removed, err)
	}
	var auditorState string
	if err := admin.QueryRow(ctx, `SELECT state FROM mesh.workspace_role_assignment WHERE public_id = $1::UUID`,
		networkAuditor.AssignmentID.String()).Scan(&auditorState); err != nil || auditorState != "revoked" {
		t.Fatalf("Network auditor role after removal = %s, %v", auditorState, err)
	}
	revokeNetworkITAdmin()

	revokeWorkspaceITAdmin := fixture.grant(ctx, t, confirmerID, authorization.BuiltinRoleITAdmin, network.ID{})
	if _, err := fixture.remove(ctx, t, confirmer, networkJoinerID); !errors.Is(err, memberlifecycle.ErrForbidden) {
		t.Fatalf("Workspace it_admin removed a Workspace admin: %v", err)
	}
	removed, err = fixture.remove(ctx, t, confirmer, networkBoundID)
	if err != nil || removed.RolesRevoked != 1 {
		t.Fatalf("Workspace it_admin removing a custom binding holder = %+v, %v", removed, err)
	}
	var bindingState string
	if err := admin.QueryRow(ctx, `SELECT state FROM mesh.role_binding WHERE id = 9203`).Scan(&bindingState); err != nil ||
		bindingState != "revoked" {
		t.Fatalf("custom role binding after removal = %s, %v", bindingState, err)
	}
	revokeWorkspaceITAdmin()

	if _, err := fixture.remove(ctx, t, owner, networkJoinerID); err != nil {
		t.Fatalf("owner removing a Workspace admin from the Network: %v", err)
	}
	revokeWorkspaceAdmin()
}
