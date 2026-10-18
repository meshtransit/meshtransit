//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// runWhileWorkspaceShared qualifies schema 183. Another Workspace change,
// past its permission check, holds the Workspace row FOR SHARE while run
// executes the SQL function named function. Once that function waits for
// the row, the other change upgrades its lock to FOR NO KEY UPDATE, as its
// own write does next. If the function had taken the row FOR SHARE in its
// permission check before asking for FOR NO KEY UPDATE, each would wait for
// the other: a deadlock. The upgrade must succeed within a timeout shorter
// than deadlock detection, and run then completes.
func runWhileWorkspaceShared[R any](ctx context.Context, t *testing.T, admin *pgx.Conn, function string,
	run func() (R, error),
) (R, error) {
	t.Helper()
	other, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		if err := other.Close(cleanupCtx); err != nil {
			t.Errorf("close Workspace change connection: %v", err)
		}
	}()
	held, err := other.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackIntegrationTransaction(ctx, t, held)
	if _, err := held.Exec(ctx, `SELECT 1 FROM mesh.workspace WHERE id = 103 FOR SHARE`); err != nil {
		t.Fatalf("share the Workspace: %v", err)
	}
	type outcome struct {
		result R
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := run()
		done <- outcome{result: result, err: err}
	}()
	waitForFunctionBlockedBy(ctx, t, admin, function, other.PgConn().PID())
	// Below the default one-second deadlock_timeout, so a regression fails
	// here as a lock timeout instead of a deadlock the caller might retry.
	if _, err := held.Exec(ctx, `SET LOCAL lock_timeout = '500ms'`); err != nil {
		t.Fatal(err)
	}
	if _, err := held.Exec(ctx, `SELECT 1 FROM mesh.workspace WHERE id = 103 FOR NO KEY UPDATE`); err != nil {
		t.Fatalf("%s holds the Workspace FOR SHARE while it waits for it: %v", function, err)
	}
	if err := held.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case finished := <-done:
		return finished.result, finished.err
	case <-time.After(30 * time.Second):
		t.Fatalf("%s did not finish after the Workspace was released", function)
		var zero R
		return zero, nil
	}
}

// waitForFunctionBlockedBy waits until a backend running the SQL function
// named function is blocked by the backend holder.
func waitForFunctionBlockedBy(ctx context.Context, t *testing.T, admin *pgx.Conn, function string, holder uint32) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.After(10 * time.Second)
	for {
		var waiting bool
		if err := admin.QueryRow(ctx, `SELECT EXISTS (
    SELECT 1 FROM pg_catalog.pg_stat_activity
    WHERE wait_event_type = 'Lock' AND query LIKE '%' || $1 || '%'
      AND $2::BIGINT = ANY (pg_catalog.pg_blocking_pids(pid)::BIGINT[]))`, function, int64(holder)).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline:
			t.Fatalf("%s never waited for the held lock", function)
		}
	}
}

// runWhileWorkspaceChanging qualifies schema 184. A member change holds the
// Workspace row FOR NO KEY UPDATE while run executes the SQL function named
// function for the Account Session sessionID, whose permission check then
// waits for that row. The member change next writes the caller's session
// row, as a removal or suspension ends its sessions. If the permission check
// had locked the session row before waiting for the Workspace, each would
// wait for the other: a deadlock. The write must get the session row within
// a timeout shorter than deadlock detection, and run then completes.
func runWhileWorkspaceChanging[R any](ctx context.Context, t *testing.T, admin *pgx.Conn, function, sessionID string,
	run func() (R, error),
) (R, error) {
	t.Helper()
	change, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		if err := change.Close(cleanupCtx); err != nil {
			t.Errorf("close member change connection: %v", err)
		}
	}()
	held, err := change.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackIntegrationTransaction(ctx, t, held)
	if _, err := held.Exec(ctx, `SELECT 1 FROM mesh.workspace WHERE id = 103 FOR NO KEY UPDATE`); err != nil {
		t.Fatalf("lock the Workspace: %v", err)
	}
	type outcome struct {
		result R
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := run()
		done <- outcome{result: result, err: err}
	}()
	waitForFunctionBlockedBy(ctx, t, admin, function, change.PgConn().PID())
	if _, err := held.Exec(ctx, `SET LOCAL lock_timeout = '500ms'`); err != nil {
		t.Fatal(err)
	}
	if _, err := held.Exec(ctx, `SELECT 1 FROM mesh.account_session WHERE public_id = $1::UUID FOR NO KEY UPDATE`,
		sessionID); err != nil {
		t.Fatalf("%s holds its session while it waits for the Workspace: %v", function, err)
	}
	if err := held.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case finished := <-done:
		return finished.result, finished.err
	case <-time.After(30 * time.Second):
		t.Fatalf("%s did not finish after the Workspace was released", function)
		var zero R
		return zero, nil
	}
}
