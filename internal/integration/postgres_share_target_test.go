//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/sharing/target"
)

// assertPostgreSQLShareTarget drives schema 105 through the production store:
// a share.offer holder resolves a Network in another Workspace and one in its
// own by display code; an unknown code is not found; a Session without
// share.offer on the provider Network learns nothing.
func assertPostgreSQLShareTarget(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool) {
	t.Helper()
	store, err := postgresadapter.NewShareTargetStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service, err := target.NewService(store, accountsession.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	owner := managementRBACAccountSessionFixture(t)
	provider := resourceAuthorityScope(t, 103, 203)
	remote := resourceAuthorityScope(t, 102, 202)
	local := resourceAuthorityScope(t, 103, 204)

	resolved, err := service.Resolve(ctx, target.Query{Session: owner, Provider: provider,
		NetworkCode: networkDisplayCode(ctx, t, admin, remote.NetworkID().String())})
	if err != nil || resolved.Scope != remote || !resolved.CrossWorkspace(provider) || !resolved.WorkspaceCode.IsValid() {
		t.Fatalf("cross-Workspace target = %+v, %v", resolved, err)
	}
	sameWorkspace, err := service.Resolve(ctx, target.Query{Session: owner, Provider: provider,
		NetworkCode: networkDisplayCode(ctx, t, admin, local.NetworkID().String())})
	if err != nil || sameWorkspace.Scope != local || sameWorkspace.CrossWorkspace(provider) {
		t.Fatalf("same-Workspace target = %+v, %v", sameWorkspace, err)
	}
	unknown, err := identity.ParseDisplayCode("000000000001")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Resolve(ctx, target.Query{Session: owner, Provider: provider, NetworkCode: unknown}); !errors.Is(err, target.ErrNotFound) {
		t.Fatalf("unknown code: %v", err)
	}
	member := authorityConfirmerAccountSessionFixture(t)
	if _, err := service.Resolve(ctx, target.Query{Session: member, Provider: provider,
		NetworkCode: networkDisplayCode(ctx, t, admin, remote.NetworkID().String())}); !errors.Is(err, target.ErrForbidden) {
		t.Fatalf("Session without share.offer: %v", err)
	}
}

func networkDisplayCode(ctx context.Context, t *testing.T, admin *pgx.Conn, networkPublicID string) identity.DisplayCode {
	t.Helper()
	var value string
	if err := admin.QueryRow(ctx, `SELECT display_code FROM mesh_ops.tenant_display_identity
WHERE network_public_id = $1::UUID`, networkPublicID).Scan(&value); err != nil {
		t.Fatalf("read Network display code: %v", err)
	}
	code, err := identity.ParseDisplayCode(value)
	if err != nil {
		t.Fatal(err)
	}
	return code
}
