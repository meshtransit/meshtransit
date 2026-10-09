//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/core/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace/creation"
)

// assertPostgreSQLWorkspaceCreation drives schema 99 through the production
// store with entitlement limits derived from the current counts: create,
// replay, ID reuse, duplicate name, per-Account quota, Deployment ceiling and
// an expired entitlement. Generations 4..6 are recorded here.
func assertPostgreSQLWorkspaceCreation(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool) {
	t.Helper()
	options := postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second}
	entitlements, err := postgresadapter.NewDeploymentEntitlementStore(runtimePool, options)
	if err != nil {
		t.Fatal(err)
	}
	store, err := postgresadapter.NewWorkspaceCreationStore(runtimePool, options)
	if err != nil {
		t.Fatal(err)
	}
	service, err := creation.NewService(store, accountsession.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	owner := managementRBACAccountSessionFixture(t)
	member := authorityConfirmerAccountSessionFixture(t)
	var active, owned int64
	if err := admin.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE p.public_id = $1::UUID)
FROM mesh.workspace w JOIN mesh.principal p ON p.id = w.owner_principal_id
WHERE w.state = 'active' AND w.deleted_at IS NULL`, owner.PrincipalID().String()).Scan(&active, &owned); err != nil {
		t.Fatal(err)
	}
	f := newEntitlementFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	limits := f.verifiedWindow(t, "01890f00-0000-7000-8000-0000000e0004", 4, active+2, owned+2, "cloud",
		now.Add(-time.Minute), now.Add(30*24*time.Hour), 0)
	if outcome, err := entitlements.Record(ctx, limits); err != nil || outcome != postgresadapter.EntitlementRecorded {
		t.Fatalf("record creation limits = %q, %v", outcome, err)
	}
	auditBefore := countAuditTarget(ctx, t, admin, "workspace")

	first := newCreateCommand(t, owner, "Engineering")
	created, err := service.Create(ctx, first)
	if err != nil || created.Replayed || created.Version != 1 || !created.DisplayCode.IsValid() {
		t.Fatalf("create = %+v, %v", created, err)
	}
	replay, err := service.Create(ctx, first)
	if err != nil || !replay.Replayed || replay.DisplayCode != created.DisplayCode {
		t.Fatalf("replay = %+v, %v", replay, err)
	}
	reused := first
	reused.DisplayName = "Something else"
	if _, err := service.Create(ctx, reused); !errors.Is(err, creation.ErrConflict) {
		t.Fatalf("reused ID: %v", err)
	}
	if _, err := service.Create(ctx, newCreateCommand(t, owner, "engineering")); !errors.Is(err, creation.ErrConflict) {
		t.Fatalf("duplicate owned name: %v", err)
	}
	if _, err := service.Create(ctx, newCreateCommand(t, owner, "Operations")); err != nil {
		t.Fatalf("second Workspace within quota: %v", err)
	}
	if _, err := service.Create(ctx, newCreateCommand(t, owner, "Finance")); !errors.Is(err, creation.ErrAccountLimit) &&
		!errors.Is(err, creation.ErrDeploymentLimit) {
		t.Fatalf("quota not enforced: %v", err)
	}
	if _, err := service.Create(ctx, newCreateCommand(t, member, "Member Space")); !errors.Is(err, creation.ErrDeploymentLimit) {
		t.Fatalf("Deployment ceiling not enforced: %v", err)
	}
	if countAuditTarget(ctx, t, admin, "workspace") != auditBefore+2 {
		t.Fatal("each created Workspace needs exactly one audit event")
	}
	var memberships, pools int64
	if err := admin.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM mesh.workspace_membership m JOIN mesh.workspace w ON w.id = m.workspace_id
  WHERE w.public_id = $1::UUID AND m.principal_id = w.owner_principal_id AND m.state = 'active'),
 (SELECT count(*) FROM mesh.address_pool p JOIN mesh.workspace w ON w.id = p.workspace_id
  WHERE w.public_id = $1::UUID AND p.purpose = 'node_overlay')`, first.WorkspaceID.String()).Scan(&memberships, &pools); err != nil {
		t.Fatal(err)
	}
	if memberships != 1 || pools != 2 {
		t.Fatalf("created Workspace memberships=%d pools=%d", memberships, pools)
	}

	expired := f.verifiedWindow(t, "01890f00-0000-7000-8000-0000000e0005", 5, active+10, owned+5, "cloud",
		now.Add(-10*24*time.Hour), now.Add(-24*time.Hour), 0)
	if _, err := entitlements.Record(ctx, expired); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Create(ctx, newCreateCommand(t, member, "After Expiry")); !errors.Is(err, creation.ErrEntitlementExpired) {
		t.Fatalf("expired entitlement: %v", err)
	}
	restored := f.verifiedWindow(t, "01890f00-0000-7000-8000-0000000e0006", 6, active+10, owned+5, "cloud",
		now.Add(-time.Minute), now.Add(30*24*time.Hour), 0)
	if _, err := entitlements.Record(ctx, restored); err != nil {
		t.Fatal(err)
	}
}

func newCreateCommand(t *testing.T, session accountsession.Session, name string) creation.Command {
	t.Helper()
	id, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	correlation, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	return creation.Command{Session: session, WorkspaceID: workspace.ID(id), DisplayName: name, CorrelationID: correlation}
}
