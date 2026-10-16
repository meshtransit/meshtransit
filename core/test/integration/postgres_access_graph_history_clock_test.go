//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/accessgraph/ledger"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
)

// assertAccessGraphHistoryOnDatabaseClock reads the access edge ledger
// through the production store and checks that the database clock decides
// its present: a read without an instant answers at the store transaction's
// database time, a past instant is read as asked, and an instant after the
// database clock's present is refused as a bad request by SQL.
func assertAccessGraphHistoryOnDatabaseClock(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool, session accountsession.Session, scope network.Scope,
) {
	t.Helper()
	store, err := postgresadapter.NewAccessGraphHistoryStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service, err := ledger.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	databaseNow := func() time.Time {
		t.Helper()
		var at time.Time
		if err := admin.QueryRow(ctx, `SELECT pg_catalog.clock_timestamp()`).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at.UTC()
	}
	before := databaseNow()
	present, err := service.Read(ctx, session, scope, ledger.Query{Limit: 10})
	after := databaseNow()
	if err != nil || present.At.Before(before) || present.At.After(after) {
		t.Fatalf("present history read at %s, error %v; want between the database's %s and %s",
			present.At, err, before, after)
	}
	past := before.Add(-time.Minute)
	if page, err := service.Read(ctx, session, scope, ledger.Query{At: past, Limit: 10}); err != nil ||
		!page.At.Equal(past.Truncate(time.Microsecond)) {
		t.Fatalf("past history read at %s, error %v; want %s", page.At, err, past)
	}
	future := databaseNow().Add(time.Minute)
	if _, err := service.Read(ctx, session, scope, ledger.Query{At: future, Limit: 10}); !errors.Is(err,
		ledger.ErrInvalidRequest) {
		t.Fatalf("history read after the database clock's present: %v", err)
	}
}
