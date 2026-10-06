//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

// assertSessionAuthorityPlanning pins migration 107: every session-anchored
// PL/pgSQL authority function keeps its written join order and one cached
// generic plan. Re-planning their ten-table RLS joins on each call cost about
// 170 ms and 40 MB of planner memory. A CREATE OR REPLACE that drops these
// settings, or a new session-anchored function without them, fails here.
func assertSessionAuthorityPlanning(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	rows, err := admin.Query(ctx, `SELECT procedure.oid::regprocedure::TEXT
FROM pg_catalog.pg_proc AS procedure
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
JOIN pg_catalog.pg_language AS language ON language.oid = procedure.prolang
WHERE namespace.nspname = 'mesh_ops'
  AND language.lanname = 'plpgsql'
  AND (procedure.prosrc ~ 'mesh\.account_session\M'
       OR procedure.proname ~ '^read_console_management_scopes_v[0-9]+$')
  AND NOT (COALESCE(procedure.proconfig, ARRAY[]::TEXT[]) @> ARRAY[
      'join_collapse_limit=1', 'from_collapse_limit=1', 'plan_cache_mode=force_generic_plan'
  ]::TEXT[])
ORDER BY 1`)
	if err != nil {
		t.Fatalf("read session authority planner settings: %v", err)
	}
	missing, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("collect session authority planner settings: %v", err)
	}
	if len(missing) != 0 {
		t.Fatalf("session authority functions without cached written-order plans: %v", missing)
	}
	var covered int
	if err := admin.QueryRow(ctx, `SELECT count(*)
FROM pg_catalog.pg_proc AS procedure
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
WHERE namespace.nspname = 'mesh_ops'
  AND procedure.proconfig @> ARRAY['plan_cache_mode=force_generic_plan']::TEXT[]`).Scan(&covered); err != nil {
		t.Fatalf("count session authority planner settings: %v", err)
	}
	if covered < 31 {
		t.Fatalf("session authority functions with cached plans = %d, want at least 31", covered)
	}
}
