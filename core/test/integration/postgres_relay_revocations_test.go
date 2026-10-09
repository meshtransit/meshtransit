//go:build integration

package integration

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
)

// assertPostgreSQLRelayRevocations qualifies schema 135: the runtime role
// reads what relays must stop honouring, the window is bounded, and every
// recently ended node key epoch and ended Trust Contract is listed.
func assertPostgreSQLRelayRevocations(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool) {
	t.Helper()
	store, err := postgresadapter.NewRelayRevocationStore(runtimePool)
	if err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.now()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadRelayRevocations(ctx, now.Add(-2*time.Hour)); err == nil {
		t.Fatal("a window longer than one hour was accepted")
	}
	// Fixtures earlier in the run ended key epochs and contracts; widen the
	// view to everything that ended in the last hour.
	since := now.Add(-59 * time.Minute)
	revoked, err := store.ReadRelayRevocations(ctx, since)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := admin.Query(ctx, `SELECT ended.public_key FROM mesh.device_node_key_epoch AS ended
WHERE ended.state <> 'active' AND ended.updated_at >= $1
  AND NOT EXISTS (SELECT 1 FROM mesh.device_node_key_epoch AS live
      JOIN mesh.device AS device ON device.id = live.device_id AND live.epoch = device.current_node_key_epoch
      WHERE live.public_key = ended.public_key AND live.state = 'active' AND device.state = 'active')`, since)
	if err != nil {
		t.Fatal(err)
	}
	ended, err := pgx.CollectRows(rows, pgx.RowTo[[]byte])
	if err != nil {
		t.Fatal(err)
	}
	for _, public := range ended {
		if !slices.Contains(revoked.NodeKeys, [32]byte(public)) {
			t.Fatalf("ended node key epoch %x not revoked", public)
		}
	}
	rows, err = admin.Query(ctx, `SELECT pg_catalog.uuid_send(public_id) FROM mesh.trust_contract
WHERE ended_at >= $1`, since)
	if err != nil {
		t.Fatal(err)
	}
	contracts, err := pgx.CollectRows(rows, pgx.RowTo[[]byte])
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range contracts {
		if !slices.Contains(revoked.TrustContracts, [16]byte(id)) {
			t.Fatalf("ended Trust Contract %x not revoked", id)
		}
	}
	var active int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh.device_node_key_epoch AS node_key
JOIN mesh.device AS device ON device.id = node_key.device_id AND node_key.epoch = device.current_node_key_epoch
WHERE device.state = 'active' AND device.deleted_at IS NULL AND node_key.state = 'active'
  AND node_key.public_key = ANY($1::BYTEA[])`, toByteSlices(revoked.NodeKeys)).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 0 {
		t.Fatalf("%d active Devices have their live node key revoked", active)
	}
	t.Logf("relay revocations: %d node keys, %d Trust Contracts", len(revoked.NodeKeys), len(revoked.TrustContracts))
}

func toByteSlices(keys [][32]byte) [][]byte {
	out := make([][]byte, len(keys))
	for i := range keys {
		out[i] = keys[i][:]
	}
	return out
}
