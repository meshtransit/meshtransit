//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
)

// allocationRows bounds the rows one registration allocation statement may
// touch whatever the Network's size: a floor row, an index probe, a few
// hostname probes. allocationWindowRows bounds one full lease window (256
// leases, each with a probe of its Device), still far below the 2,000 leases
// of the prefix a scan of it would read.
const (
	allocationRows       = 64
	allocationWindow     = 256
	allocationWindowRows = 4 * allocationWindow
)

// assertRegistrationAllocationPlansScale proves schema 157: under the
// allocator lock, registration's address and hostname statements touch a
// bounded number of rows in a prefix and Network of thousands of Devices,
// with stale statistics and under a generic plan. The Devices are added in
// a transaction that rolls back.
func assertRegistrationAllocationPlansScale(ctx context.Context, t *testing.T) {
	t.Helper()
	adminConfig := loadIntegrationAdminConfig(t)
	var mu sync.Mutex
	var plans []string
	admin := openIntegrationPostgreSQLConnection(ctx, t, adminConfig.PostgreSQL.Address,
		adminConfig.PostgreSQL.Database, adminConfig.PostgreSQL.User, adminConfig.PostgreSQL.PasswordFile,
		adminConfig.PostgreSQL.CAFile, adminConfig.ConnectTimeout, func(connConfig *pgx.ConnConfig) {
			connConfig.OnNotice = func(_ *pgconn.PgConn, notice *pgconn.Notice) {
				if _, plan, found := strings.Cut(notice.Message, "plan:"); found {
					mu.Lock()
					plans = append(plans, plan)
					mu.Unlock()
				}
			}
		})
	seed := newShareScaleSeed(ctx, t, admin, mapReaderPlanDevices)
	side := seed.sides[0]
	prefix := netip.MustParsePrefix(side.prefix)
	first := prefix.Addr().Next()
	pastSeed := first
	for range len(side.devices) {
		pastSeed = pastSeed.Next()
	}
	host := func(address netip.Addr) string { return netip.PrefixFrom(address, 32).String() }

	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatalf("begin registration allocation plan check: %v", err)
	}
	defer rollbackIntegrationTransaction(ctx, t, transaction)
	setIntegrationChange(ctx, t, transaction, shareScaleUUID(t))
	side.insert(ctx, t, transaction)
	if _, err := transaction.Exec(ctx, `INSERT INTO mesh_ops.registration_address_floor (
    workspace_id, network_id, network_prefix_id, prefix, floor_address)
VALUES ($1, $2, $3, $4::CIDR, $5::INET)
ON CONFLICT (network_prefix_id) DO UPDATE SET floor_address = EXCLUDED.floor_address`,
		shareScaleWorkspace, side.network, side.prefixID, side.prefix, host(pastSeed)); err != nil {
		t.Fatalf("set the scale prefix's address floor: %v", err)
	}
	for _, statement := range []string{
		"LOAD 'auto_explain'",
		"SET LOCAL auto_explain.log_min_duration = 0",
		"SET LOCAL auto_explain.log_analyze = on",
		"SET LOCAL auto_explain.log_timing = off",
		"SET LOCAL auto_explain.log_nested_statements = on",
		"SET LOCAL auto_explain.log_format = 'json'",
		"SET LOCAL client_min_messages = 'log'",
	} {
		if _, err := transaction.Exec(ctx, statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	if _, err := transaction.Exec(ctx, `SELECT pg_catalog.set_config('mesh.workspace_id', $1::BIGINT::TEXT, TRUE),
        pg_catalog.set_config('mesh.network_id', $2::BIGINT::TEXT, TRUE)`, shareScaleWorkspace, side.network); err != nil {
		t.Fatalf("set registration allocation scope: %v", err)
	}
	statements := postgresadapter.RegistrationAllocationPlanStatements()
	taken := fmt.Sprintf("scale-%d.example", side.devices[0].id)
	// The address statements run on statistics from before the Network
	// grew. The hostname probe is checked once mesh.device is analyzed: on
	// statistics that do not know a new Workspace at all, the planner may
	// probe another Workspace-led index until autovacuum analyzes the table
	// (documented on the statement); with them it must stay a probe.
	addressChecks := []allocationPlanCheck{
		{"address floor", "address floor", []any{side.prefixID}, 1, allocationRows},
		{"reclaimable below the floor", "reclaimable address",
			[]any{side.prefixID, host(first), host(pastSeed)}, 0, allocationRows},
		{"lease window at the floor", "lease window",
			[]any{side.prefixID, allocationWindow, host(pastSeed)}, 0, allocationRows},
		{"lease window over the seeded leases", "lease window",
			[]any{side.prefixID, allocationWindow, host(first)}, allocationWindow, allocationWindowRows},
	}
	hostnameChecks := []allocationPlanCheck{
		{"hostname candidates", "hostname candidates",
			[]any{shareScaleWorkspace, side.network, []string{taken, "unseeded-name.example"}, nil}, 1, allocationRows},
	}
	run := func(checks []allocationPlanCheck) {
		for _, mode := range []string{"auto", "force_generic_plan"} {
			if _, err := transaction.Exec(ctx, "SELECT pg_catalog.set_config('plan_cache_mode', $1, TRUE)", mode); err != nil {
				t.Fatalf("set plan_cache_mode %s: %v", mode, err)
			}
			for call := range 6 {
				for _, check := range checks {
					statement, known := statements[check.statement]
					if !known {
						t.Fatalf("no registration allocation statement %q", check.statement)
					}
					mu.Lock()
					plans = plans[:0]
					mu.Unlock()
					returned := countRows(ctx, t, transaction, statement, check.args)
					flushPlans(ctx, t, transaction)
					mu.Lock()
					touched, plan := allocationRowsTouched(t, check.name, plans)
					mu.Unlock()
					if returned != check.rows || touched > check.maxRows {
						t.Fatalf("%s (%s, call %d): %d rows returned (want %d), %d touched (at most %d) in\n%s",
							check.name, mode, call, returned, check.rows, touched, check.maxRows, plan)
					}
				}
			}
		}
	}
	run(addressChecks)
	if _, err := transaction.Exec(ctx, "ANALYZE mesh.device"); err != nil {
		t.Fatalf("analyze mesh.device: %v", err)
	}
	run(hostnameChecks)
}

type allocationPlanCheck struct {
	name, statement string
	args            []any
	rows, maxRows   int64
}

func countRows(ctx context.Context, t *testing.T, transaction pgx.Tx, statement string, args []any) int64 {
	t.Helper()
	rows, err := transaction.Query(ctx, statement, args...)
	if err != nil {
		t.Fatalf("run %q: %v", strings.SplitN(statement, "\n", 2)[0], err)
	}
	defer rows.Close()
	var count int64
	for rows.Next() {
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read %q: %v", strings.SplitN(statement, "\n", 2)[0], err)
	}
	return count
}

// allocationRowsTouched is mapReaderRowsTouched for statements that may
// touch no row at all (an index probe that finds nothing).
func allocationRowsTouched(t *testing.T, name string, plans []string) (int64, string) {
	t.Helper()
	if len(plans) == 0 {
		t.Fatalf("%s: auto_explain reported no plan", name)
	}
	worst, worstPlan := int64(-1), ""
	for _, text := range plans {
		var plan struct {
			Plan mapReaderPlanNode `json:"Plan"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(text)), &plan); err != nil {
			t.Fatalf("decode auto_explain plan: %v\n%s", err, text)
		}
		if touched := int64(rowsTouched(plan.Plan)); touched > worst {
			worst, worstPlan = touched, text
		}
	}
	return worst, worstPlan
}
