//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/core/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
)

func assertPostgreSQLAccountSessionActivity(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	runtimePool *postgresadapter.Pool,
) {
	t.Helper()
	keyring, token, _ := integrationActivityAccountSessionSecurity(t)
	digests, err := keyring.Digests(token)
	if err != nil || len(digests) != 1 {
		t.Fatal("derive activity digest", err)
	}
	store, err := postgresadapter.NewAccountSessionStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal("construct activity session store", err)
	}
	session, found, err := store.Resolve(ctx, token.DeploymentID(), token.RecoveryEpoch(), digests[0])
	if err != nil || !found || session.Version() != 1 {
		t.Fatalf("ordinary read touched Account Session: found=%t version=%d err=%v", found, session.Version(), err)
	}
	session, found, err = store.Resolve(accountsession.WithActivity(ctx),
		token.DeploymentID(), token.RecoveryEpoch(), digests[0])
	if err != nil || !found || session.Version() != 2 ||
		session.IdleExpiresAt().Before(time.Now().Add(59*time.Minute)) {
		t.Fatalf("activity renewal failed: found=%t version=%d idle=%s err=%v",
			found, session.Version(), session.IdleExpiresAt(), err)
	}
	var auditCount, outboxCount int
	if err := admin.QueryRow(ctx, `SELECT
    (SELECT count(*) FROM mesh_audit.audit_event AS event
     WHERE event.target_kind='account_session'
       AND event.target_public_id='01890f00-0000-7000-8000-000000000814'::UUID
       AND event.action='account_session.touched'),
    (SELECT count(*) FROM mesh_ops.outbox_event AS event
     WHERE event.aggregate_kind='account_session'
       AND event.aggregate_public_id='01890f00-0000-7000-8000-000000000814'::UUID
       AND event.event_class='identity.account_session.touched')`).Scan(&auditCount, &outboxCount); err != nil {
		t.Fatal("read activity evidence", err)
	}
	if auditCount != 1 || outboxCount != 1 {
		t.Fatalf("activity audit/outbox=%d/%d, want 1/1", auditCount, outboxCount)
	}
	session, found, err = store.Resolve(accountsession.WithActivity(ctx),
		token.DeploymentID(), token.RecoveryEpoch(), digests[0])
	if err != nil || !found || session.Version() != 2 {
		t.Fatalf("renewal was not throttled: found=%t version=%d err=%v", found, session.Version(), err)
	}
}
