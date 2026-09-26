//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
)

func assertPostgreSQLAccountSessionLogout(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	runtimePool *postgresadapter.Pool,
) {
	t.Helper()
	keyring, token, _ := integrationManagementAccountSessionSecurity(t)
	store, err := postgresadapter.NewAccountSessionLogoutStore(
		runtimePool,
		postgresadapter.AccountSessionLogoutOptions{
			StatementTimeout: 5 * time.Second,
			LockTimeout:      5 * time.Second,
			IdleTimeout:      10 * time.Second,
		},
	)
	if err != nil {
		t.Fatal("construct Account Session logout store", err)
	}
	digests, err := keyring.Digests(token)
	if err != nil || len(digests) != 1 {
		t.Fatal("derive Account Session logout digest", err)
	}
	otherDeployment, err := deployment.ParseID("01890f00-0000-7000-8000-000000000002")
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string]struct {
		deploymentID deployment.ID
		epoch        int64
	}{
		"wrong deployment": {deploymentID: otherDeployment, epoch: token.RecoveryEpoch()},
		"wrong epoch":      {deploymentID: token.DeploymentID(), epoch: token.RecoveryEpoch() + 1},
	} {
		id, version, found, revokeErr := store.Revoke(
			ctx,
			candidate.deploymentID,
			candidate.epoch,
			digests[0],
		)
		if revokeErr != nil || found || id.IsValid() || version != 0 {
			t.Fatalf("%s disclosed or revoked another scope", name)
		}
	}
	service, err := accountsession.NewLogoutService(keyring, store)
	if err != nil {
		t.Fatal("construct durable Account Session logout", err)
	}
	revoked, err := service.Logout(ctx, token)
	if err != nil || !revoked {
		t.Fatal("durable Account Session logout failed", err)
	}
	var state, reason string
	var version int64
	var ended bool
	if err := admin.QueryRow(ctx, `SELECT
    state,
    end_reason,
    ended_at IS NOT NULL,
    version
FROM mesh.account_session
WHERE public_id = $1::UUID`, integrationManagementSessionPublicID).Scan(
		&state,
		&reason,
		&ended,
		&version,
	); err != nil {
		t.Fatal("query logged-out Account Session", err)
	}
	if state != "revoked" || reason != "local_logout" || !ended || version != 2 {
		t.Fatalf("durable logout state=%s reason=%s ended=%t version=%d", state, reason, ended, version)
	}
	revoked, err = service.Logout(ctx, token)
	if err != nil || revoked {
		t.Fatal("logout replay was not an idempotent no-match", err)
	}
	var runtimeCanLogout, workerCanLogout bool
	if err := admin.QueryRow(ctx, `SELECT
    pg_catalog.has_function_privilege(
        'mesh_runtime',
        'mesh_ops.logout_account_session_v1(uuid,bigint,text,text,bytea)',
        'EXECUTE'
    ),
    pg_catalog.has_function_privilege(
        'mesh_worker',
        'mesh_ops.logout_account_session_v1(uuid,bigint,text,text,bytea)',
        'EXECUTE'
    )`).Scan(&runtimeCanLogout, &workerCanLogout); err != nil {
		t.Fatal("query Account Session logout privileges", err)
	}
	if !runtimeCanLogout || workerCanLogout {
		t.Fatalf("logout privileges runtime=%t worker=%t", runtimeCanLogout, workerCanLogout)
	}
}
