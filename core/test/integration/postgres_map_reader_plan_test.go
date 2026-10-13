//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// mapReaderPlanDevices is how many Devices the plan check adds to one
// Network; mapReaderRowsPerDevice bounds the rows every scan of one reader
// call may touch per listed Device (the Device, its two key epochs, owner and
// leases, and the joins over them, about a dozen). A reader that rescans the
// Network for each Device touches thousands per Device.
const (
	mapReaderPlanDevices   = 2000
	mapReaderRowsPerDevice = 32
	// shareReaderRows bounds the rows a share reader may touch for a
	// Device without shares, whatever the Network's size: authenticating
	// the Device is a few key lookups.
	shareReaderRows = 200
)

// assertMapReaderPlansScale proves schemas 152 and 155: the inventory and
// per-Device candidate readers stay linear in the Network's size, and the
// share readers authenticate a Device in constant work, while the planner's
// statistics still describe the Network before it grew, and under a generic
// plan. The Devices are added in a transaction that rolls back.
func assertMapReaderPlansScale(ctx context.Context, t *testing.T) {
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
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatalf("begin map reader plan check: %v", err)
	}
	defer rollbackIntegrationTransaction(ctx, t, transaction)
	setIntegrationChange(ctx, t, transaction, shareScaleUUID(t))
	seed.sides[0].insert(ctx, t, transaction)
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
        pg_catalog.set_config('mesh.network_id', $2::BIGINT::TEXT, TRUE)`, shareScaleWorkspace, shareScaleProvider); err != nil {
		t.Fatalf("set map reader scope: %v", err)
	}
	self := seed.providers[0]
	machine, key := self.machine.Fingerprint(), self.key.Bytes()
	readers := []struct {
		name, query string
		args        []any
	}{
		{"inventory", `SELECT count(*) FROM mesh_ops.load_map_network_devices_v1(200001)`, nil},
		{"candidates", `SELECT count(*) FROM mesh_ops.load_map_peer_candidates_v2($1::BYTEA, $2::BYTEA, 10001)`,
			[]any{machine[:], key[:]}},
	}
	shareReaders := []struct{ name, query string }{
		{"direct shares", `SELECT count(*) FROM mesh_ops.load_direct_share_map_edges_v1($1::BYTEA, $2::BYTEA, 257)`},
		{"alias shares", `SELECT count(*) FROM mesh_ops.load_device_alias_map_edges_v7($1::BYTEA, $2::BYTEA, 10000)`},
		{"sharing dependencies", `SELECT count(*) FROM mesh_ops.load_device_sharing_dependencies_v6($1::BYTEA, $2::BYTEA, 10000)`},
	}
	for _, mode := range []string{"auto", "force_generic_plan"} {
		if _, err := transaction.Exec(ctx, "SELECT pg_catalog.set_config('plan_cache_mode', $1, TRUE)", mode); err != nil {
			t.Fatalf("set plan_cache_mode %s: %v", mode, err)
		}
		// Six calls: PL/pgSQL plans its statements for custom values the
		// first five times, then may keep a generic plan.
		for call := range 6 {
			for _, reader := range readers {
				mu.Lock()
				plans = plans[:0]
				mu.Unlock()
				var listed int
				if err := transaction.QueryRow(ctx, reader.query, reader.args...).Scan(&listed); err != nil {
					t.Fatalf("%s (%s, call %d): %v", reader.name, mode, call, err)
				}
				flushPlans(ctx, t, transaction)
				if listed < mapReaderPlanDevices-1 {
					t.Fatalf("%s (%s) listed %d Devices, want at least %d", reader.name, mode, listed, mapReaderPlanDevices-1)
				}
				mu.Lock()
				touched, statement := mapReaderRowsTouched(t, plans)
				mu.Unlock()
				if touched > mapReaderRowsPerDevice*int64(listed) {
					t.Fatalf("%s (%s, call %d) touched %d rows for %d Devices in\n%s",
						reader.name, mode, call, touched, listed, statement)
				}
				if call == 5 {
					t.Logf("%s (%s): %d rows touched for %d Devices", reader.name, mode, touched, listed)
				}
			}
			for _, reader := range shareReaders {
				mu.Lock()
				plans = plans[:0]
				mu.Unlock()
				var edges int
				if err := transaction.QueryRow(ctx, reader.query, machine[:], key[:]).Scan(&edges); err != nil {
					t.Fatalf("%s (%s, call %d): %v", reader.name, mode, call, err)
				}
				flushPlans(ctx, t, transaction)
				mu.Lock()
				touched, statement := mapReaderRowsTouched(t, plans)
				mu.Unlock()
				if edges != 0 || touched > shareReaderRows {
					t.Fatalf("%s (%s, call %d): %d edges, touched %d rows in\n%s",
						reader.name, mode, call, edges, touched, statement)
				}
			}
		}
	}
}

// flushPlans runs a trivial statement: with the extended protocol a
// statement's portal, and so its auto_explain plan, ends with the next
// statement, so this delivers the last reader's plan before it is checked.
func flushPlans(ctx context.Context, t *testing.T, transaction pgx.Tx) {
	t.Helper()
	if _, err := transaction.Exec(ctx, "SELECT 1"); err != nil {
		t.Fatalf("flush auto_explain plans: %v", err)
	}
}

// mapReaderPlanNode is the part of an EXPLAIN (ANALYZE, FORMAT JSON) node the
// check reads.
type mapReaderPlanNode struct {
	NodeType      string              `json:"Node Type"`
	ActualRows    float64             `json:"Actual Rows"`
	ActualLoops   float64             `json:"Actual Loops"`
	RemovedFilter float64             `json:"Rows Removed by Filter"`
	RemovedJoin   float64             `json:"Rows Removed by Join Filter"`
	Plans         []mapReaderPlanNode `json:"Plans"`
}

// mapReaderRowsTouched returns, for the costliest statement among plans, the
// rows its scans returned or filtered out over all their loops, and its plan.
func mapReaderRowsTouched(t *testing.T, plans []string) (int64, string) {
	t.Helper()
	var worst int64
	var worstPlan string
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
	if worstPlan == "" {
		t.Fatal("auto_explain reported no plan")
	}
	return worst, worstPlan
}

func rowsTouched(node mapReaderPlanNode) float64 {
	total := 0.0
	if strings.Contains(node.NodeType, "Scan") || strings.Contains(node.NodeType, "Join") ||
		node.NodeType == "Nested Loop" {
		total += (node.ActualRows + node.RemovedFilter + node.RemovedJoin) * node.ActualLoops
	}
	for _, child := range node.Plans {
		total += rowsTouched(child)
	}
	return total
}
