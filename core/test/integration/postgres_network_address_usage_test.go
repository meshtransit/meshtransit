//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/network/addressusage"
)

// assertNetworkAddressUsage qualifies schema 159: a Session with
// network.read reads, per address range of the Network, the counts an
// independent count of the leases gives, and the IPv4 capacity.
func assertNetworkAddressUsage(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool,
	session accountsession.Session, scope network.Scope) {
	t.Helper()
	store, err := postgresadapter.NewNetworkAddressUsageStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service, err := addressusage.NewService(store, integrationClock{})
	if err != nil {
		t.Fatal(err)
	}
	state, err := service.Read(ctx, session, scope)
	if err != nil {
		t.Fatalf("read address usage: %v", err)
	}
	rows, err := admin.Query(ctx, `SELECT prefix.prefix::TEXT,
    CASE WHEN prefix.family = 4 THEN (1::BIGINT << (32 - masklen(prefix.prefix))) - 2
         WHEN masklen(prefix.prefix) >= 96 THEN (1::BIGINT << (128 - masklen(prefix.prefix))) - 1 ELSE 0 END,
    count(*) FILTER (WHERE lease.state = 'active' AND device.state <> 'revoked' AND device.expires_at > now()),
    count(*) FILTER (WHERE lease.state = 'active' AND device.state <> 'revoked' AND device.expires_at <= now()),
    count(*) FILTER (WHERE (lease.state = 'quarantined' AND lease.quarantine_until > now())
        OR (lease.state = 'active' AND device.state = 'revoked' AND device.updated_at + INTERVAL '24 hours' > now()))
FROM mesh.network_prefix AS prefix
JOIN mesh.network AS net ON net.id = prefix.network_id
LEFT JOIN mesh.node_address_lease AS lease ON lease.network_prefix_id = prefix.id
LEFT JOIN mesh.device AS device ON device.id = lease.device_id
WHERE net.public_id = $1::UUID AND prefix.state = 'active' AND prefix.deleted_at IS NULL
GROUP BY prefix.id, prefix.family, prefix.prefix
ORDER BY prefix.family, prefix.prefix`, scope.NetworkID().String())
	if err != nil {
		t.Fatal(err)
	}
	type expected struct {
		prefix                      string
		capacity, inUse, expired, h int64
	}
	var want []expected
	for rows.Next() {
		var row expected
		if err := rows.Scan(&row.prefix, &row.capacity, &row.inUse, &row.expired, &row.h); err != nil {
			t.Fatal(err)
		}
		want = append(want, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(state.Ranges) != len(want) || len(want) == 0 {
		t.Fatalf("ranges = %+v, want %+v", state.Ranges, want)
	}
	for index, usage := range state.Ranges {
		row := want[index]
		if usage.Prefix.String() != row.prefix || usage.Capacity != row.capacity || usage.InUse != row.inUse ||
			usage.HeldByExpired != row.expired || usage.HeldAfterRevocation != row.h {
			t.Errorf("range %d = %+v, want %+v", index, usage, row)
		}
	}
}
