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
	"meshtransit.net/core/internal/domain/guardrail"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/sharing"
	"meshtransit.net/core/internal/domain/workspace/roles"
)

const guardrailFixtureNetwork = "01890f00-0000-7000-8000-000000000203"

func newIntegrationGuardrailService(t *testing.T, runtimePool *postgresadapter.Pool) *guardrail.Service {
	t.Helper()
	store, err := postgresadapter.NewGuardrailStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service, err := guardrail.NewService(store, accountsession.SystemClock{}, guardrail.SystemIDs{})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func newIntegrationRoleService(t *testing.T, runtimePool *postgresadapter.Pool) *roles.Service {
	t.Helper()
	store, err := postgresadapter.NewWorkspaceRoleStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service, err := roles.NewService(store, accountsession.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func productionSharingLock(t *testing.T, mode guardrail.Mode, direction guardrail.Direction) guardrail.Spec {
	t.Helper()
	production, err := network.ParseID(guardrailFixtureNetwork)
	if err != nil {
		t.Fatal(err)
	}
	return guardrail.Spec{Kind: guardrail.KindNetworkSharing, Name: "Production shares nothing", Mode: mode,
		Sharing: guardrail.NetworkSharingParams{Networks: []network.ID{production}, Direction: direction}}
}

func newCorrelationID(t *testing.T) publicid.ID {
	t.Helper()
	id, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// assertPostgreSQLGuardrails qualifies schema 119 through the production
// store: guardrail.read gates the list, guardrail.manage creating and
// narrowing, guardrail.weaken loosening and deleting; stale versions and
// foreign Networks are refused, and each committed change is one audit event
// on the Workspace stream. It leaves no guardrail or role behind.
func assertPostgreSQLGuardrails(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool) {
	t.Helper()
	service := newIntegrationGuardrailService(t, runtimePool)
	roleService := newIntegrationRoleService(t, runtimePool)
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	owner := managementRBACAccountSessionFixture(t)
	member := authorityConfirmerAccountSessionFixture(t)
	workspaceID, _ := owner.LoginWorkspaceID()
	memberPrincipal := publicid.ID(member.PrincipalID())
	auditBefore := countGuardrailAudit(ctx, t, admin)

	if listing, err := service.List(ctx, owner, workspaceID); err != nil || len(listing.Guardrails) != 0 ||
		!listing.CanManage || !listing.CanWeaken {
		t.Fatalf("owner guardrails = %+v, error = %v", listing, err)
	}
	if _, err := service.List(ctx, member, workspaceID); !errors.Is(err, guardrail.ErrForbidden) {
		t.Fatalf("plain member listed guardrails: %v", err)
	}
	spec := productionSharingLock(t, guardrail.ModeEnforce, guardrail.DirectionOutgoing)
	if _, err := service.Create(ctx, member, workspaceID, spec, newCorrelationID(t)); !errors.Is(err, guardrail.ErrForbidden) {
		t.Fatalf("plain member created a guardrail: %v", err)
	}
	foreign := spec
	foreign.Sharing.Networks = []network.ID{network.ID(newCorrelationID(t))}
	if _, err := service.Create(ctx, owner, workspaceID, foreign, newCorrelationID(t)); !errors.Is(err, guardrail.ErrUnknownNetwork) {
		t.Fatalf("guardrail over a foreign Network: %v", err)
	}
	created, err := service.Create(ctx, owner, workspaceID, spec, newCorrelationID(t))
	if err != nil || created.Guardrail.Version != 1 || created.Guardrail.Mode != guardrail.ModeEnforce {
		t.Fatalf("owner create = %+v, error = %v", created, err)
	}
	id := created.Guardrail.ID

	// it_admin reads guardrails but cannot change them.
	itAdmin := newAssignCommand(t, owner, workspaceID, memberPrincipal, authorization.BuiltinRoleITAdmin, network.ID{})
	if _, err := roleService.Assign(ctx, itAdmin); err != nil {
		t.Fatalf("assign it_admin: %v", err)
	}
	if listing, err := service.List(ctx, member, workspaceID); err != nil || len(listing.Guardrails) != 1 ||
		listing.Guardrails[0].ID != id || listing.CanManage || listing.CanWeaken {
		t.Fatalf("it_admin guardrails = %+v, error = %v", listing, err)
	}
	narrowed := productionSharingLock(t, guardrail.ModeEnforce, guardrail.DirectionBoth)
	if _, err := service.Update(ctx, member, workspaceID, id, 1, narrowed, newCorrelationID(t)); !errors.Is(err, guardrail.ErrForbidden) {
		t.Fatalf("it_admin changed a guardrail: %v", err)
	}
	if _, err := roleService.Revoke(ctx, newRevokeCommand(t, owner, workspaceID, itAdmin.AssignmentID, 1)); err != nil {
		t.Fatalf("revoke it_admin: %v", err)
	}

	// security_admin manages and weakens guardrails.
	security := newAssignCommand(t, owner, workspaceID, memberPrincipal, authorization.BuiltinRoleSecurityAdmin, network.ID{})
	if _, err := roleService.Assign(ctx, security); err != nil {
		t.Fatalf("assign security_admin: %v", err)
	}
	defer func() {
		if _, err := roleService.Revoke(ctx, newRevokeCommand(t, owner, workspaceID, security.AssignmentID, 1)); err != nil {
			t.Errorf("revoke security_admin: %v", err)
		}
	}()
	if listing, err := service.List(ctx, member, workspaceID); err != nil || !listing.CanManage || !listing.CanWeaken {
		t.Fatalf("security_admin guardrails = %+v, error = %v", listing, err)
	}
	updated, err := service.Update(ctx, member, workspaceID, id, 1, narrowed, newCorrelationID(t))
	if err != nil || updated.Guardrail.Version != 2 || updated.Guardrail.Sharing.Direction != guardrail.DirectionBoth {
		t.Fatalf("security_admin narrowed = %+v, error = %v", updated, err)
	}
	if _, err := service.Update(ctx, member, workspaceID, id, 1, narrowed, newCorrelationID(t)); !errors.Is(err, guardrail.ErrVersionConflict) {
		t.Fatalf("stale update: %v", err)
	}
	auditOnly := productionSharingLock(t, guardrail.ModeAudit, guardrail.DirectionBoth)
	weakened, err := service.Update(ctx, member, workspaceID, id, 2, auditOnly, newCorrelationID(t))
	if err != nil || weakened.Guardrail.Version != 3 || weakened.Guardrail.Mode != guardrail.ModeAudit {
		t.Fatalf("security_admin switched to audit = %+v, error = %v", weakened, err)
	}
	if !latestGuardrailEventWeakened(ctx, t, admin, id) {
		t.Fatal("switching to audit mode was not recorded as weakening")
	}
	deleted, err := service.Delete(ctx, member, workspaceID, id, 3, newCorrelationID(t))
	if err != nil || !deleted.Deleted {
		t.Fatalf("security_admin delete = %+v, error = %v", deleted, err)
	}
	if _, err := service.Delete(ctx, member, workspaceID, id, 4, newCorrelationID(t)); !errors.Is(err, guardrail.ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if listing, err := service.List(ctx, owner, workspaceID); err != nil || len(listing.Guardrails) != 0 {
		t.Fatalf("guardrails after delete = %+v, error = %v", listing, err)
	}
	if got := countGuardrailAudit(ctx, t, admin); got != auditBefore+4 {
		t.Fatalf("guardrail audit events = %d, want %d", got-auditBefore, 4)
	}
	assertGuardrailEventsOnWorkspaceStream(ctx, t, admin, id)
}

func countGuardrailAudit(ctx context.Context, t *testing.T, admin *pgx.Conn) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh_audit.audit_event
WHERE target_kind = 'guardrail'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func latestGuardrailEventWeakened(ctx context.Context, t *testing.T, admin *pgx.Conn, id publicid.ID) bool {
	t.Helper()
	var weakened bool
	if err := admin.QueryRow(ctx, `SELECT (payload->>'weakened')::BOOLEAN FROM mesh_audit.audit_event
WHERE target_kind = 'guardrail' AND target_public_id = $1::UUID
ORDER BY event_identity_id DESC LIMIT 1`, id.String()).Scan(&weakened); err != nil {
		t.Fatal(err)
	}
	return weakened
}

// assertGuardrailEventsOnWorkspaceStream checks guardrail evidence lands on
// the Workspace's own stream, never a Network stream.
func assertGuardrailEventsOnWorkspaceStream(ctx context.Context, t *testing.T, admin *pgx.Conn, id publicid.ID) {
	t.Helper()
	var outside int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh_audit.audit_event
WHERE target_kind = 'guardrail' AND target_public_id = $1::UUID
  AND (workspace_id IS DISTINCT FROM 103 OR network_id IS NOT NULL)`, id.String()).Scan(&outside); err != nil {
		t.Fatal(err)
	}
	if outside != 0 {
		t.Fatalf("%d guardrail events outside the Workspace stream", outside)
	}
}

// blockShareWithGuardrail creates an enforced guardrail that locks the
// provider Network, proves the offer is refused naming it, then switches it to
// audit mode so the real offer goes through with recorded findings. It
// returns the guardrail and its version for retireShareGuardrail.
func blockShareWithGuardrail(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool,
	service *sharing.Service, blocked sharing.CreateOfferParams) guardrail.Guardrail {
	t.Helper()
	guardrails := newIntegrationGuardrailService(t, runtimePool)
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	owner := managementRBACAccountSessionFixture(t)
	workspaceID, _ := owner.LoginWorkspaceID()
	created, err := guardrails.Create(ctx, owner, workspaceID,
		productionSharingLock(t, guardrail.ModeEnforce, guardrail.DirectionOutgoing), newCorrelationID(t))
	if err != nil {
		t.Fatalf("create share guardrail: %v", err)
	}
	command, err := sharing.NewCreateOffer(blocked)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.CreateOffer(ctx, command)
	var violation *guardrail.ViolationError
	if !errors.As(err, &violation) || len(violation.Findings) != 1 ||
		violation.Findings[0].GuardrailID != created.Guardrail.ID ||
		violation.Findings[0].Reason != guardrail.ReasonSharingLocked {
		t.Fatalf("offer out of a locked Network: %v", err)
	}
	audit, err := guardrails.Update(ctx, owner, workspaceID, created.Guardrail.ID, 1,
		productionSharingLock(t, guardrail.ModeAudit, guardrail.DirectionOutgoing), newCorrelationID(t))
	if err != nil {
		t.Fatalf("switch share guardrail to audit: %v", err)
	}
	return audit.Guardrail
}

// retireShareGuardrail checks the offer created under an audit-mode guardrail
// recorded its finding on the acting side only, then deletes the guardrail.
func retireShareGuardrail(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool,
	offerID interface{ String() string }, rail guardrail.Guardrail) {
	t.Helper()
	var recorded int64
	var mode string
	if err := admin.QueryRow(ctx, `SELECT count(*), coalesce(max(finding->>'mode'), '')
FROM mesh_audit.audit_event AS event,
     LATERAL jsonb_array_elements(event.payload->'guardrail_findings') AS finding
WHERE event.target_kind = 'share_offer' AND event.target_public_id = $1::UUID
  AND event.action = 'share_offer.created' AND finding->>'guardrail_id' = $2::TEXT`,
		offerID.String(), rail.ID.String()).Scan(&recorded, &mode); err != nil {
		t.Fatal(err)
	}
	if recorded != 1 || mode != string(guardrail.ModeAudit) {
		t.Fatalf("audit-mode findings recorded = %d (mode %q), want one on the acting side", recorded, mode)
	}
	guardrails := newIntegrationGuardrailService(t, runtimePool)
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	owner := managementRBACAccountSessionFixture(t)
	workspaceID, _ := owner.LoginWorkspaceID()
	if _, err := guardrails.Delete(ctx, owner, workspaceID, rail.ID, rail.Version, newCorrelationID(t)); err != nil {
		t.Fatalf("delete share guardrail: %v", err)
	}
}

// assertActiveReleaseImportedPath checks, as the runtime role, that the
// Network's active release reports the path its imported rule opens, so an
// enforced guardrail does not block it retroactively. It switches the
// transaction's role; call it last before rolling back.
func assertActiveReleaseImportedPath(ctx context.Context, t *testing.T, transaction pgx.Tx, path string) {
	t.Helper()
	if _, err := transaction.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
		t.Fatal(err)
	}
	var found bool
	if err := transaction.QueryRow(ctx, `SELECT mesh_ops.active_release_imported_paths_v1() ? $1::TEXT`,
		path).Scan(&found); err != nil {
		t.Fatalf("read active release paths: %v", err)
	}
	if !found {
		t.Fatalf("active release paths omit %s", path)
	}
}
