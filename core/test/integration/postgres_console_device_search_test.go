//go:build integration

package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/inventory"
)

// assertPostgreSQLConsoleDeviceSearch lists a Network's Devices through the
// production store (schema 177): in byte order of (hostname, public ID) with
// removed Devices included, filtered by a name prefix and by whether a Device
// can connect, continued from a cursor; reads one Device with how it was
// enrolled; and finds no Device of another Network.
func assertPostgreSQLConsoleDeviceSearch(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool) {
	t.Helper()
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	owner := managementRBACAccountSessionFixture(t)
	workspaceID, _ := owner.LoginWorkspaceID()
	networkID, err := network.ParseID(guardrailFixtureNetwork)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	store, err := postgresadapter.NewConsoleDeviceInventoryStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service, err := inventory.NewService(store, integrationShiftedClock{})
	if err != nil {
		t.Fatal(err)
	}

	type row struct {
		id, hostname, kind string
		active             bool
	}
	var expected []row
	rows, err := admin.Query(ctx, `SELECT device.public_id::TEXT, device.hostname, device.registered_by_kind,
    device.state = 'active' AND device.expires_at > pg_catalog.now()
FROM mesh.device AS device JOIN mesh.network AS net ON net.id = device.network_id
WHERE net.public_id = $1::UUID
ORDER BY device.hostname COLLATE "C", device.public_id`, networkID.String())
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var item row
		if err := rows.Scan(&item.id, &item.hostname, &item.kind, &item.active); err != nil {
			t.Fatal(err)
		}
		expected = append(expected, item)
	}
	rows.Close()
	if len(expected) < 2 {
		t.Fatalf("the fixture Network holds %d Devices, want at least 2", len(expected))
	}

	all, err := service.List(ctx, owner, scope, inventory.Query{Limit: inventory.MaximumPageSize})
	if err != nil || len(all.Devices()) != len(expected) {
		t.Fatalf("list every Device = %d, %v; want %d", len(all.Devices()), err, len(expected))
	}
	for index, device := range all.Devices() {
		if device.ID().String() != expected[index].id {
			t.Fatalf("Device %d is %s %s, want %s %s", index, device.Hostname(), device.ID(),
				expected[index].hostname, expected[index].id)
		}
	}

	first, err := service.List(ctx, owner, scope, inventory.Query{Limit: 1})
	cursor, more := first.Next()
	if err != nil || len(first.Devices()) != 1 || !more {
		t.Fatalf("first page = %d, more %t, %v", len(first.Devices()), more, err)
	}
	second, err := service.List(ctx, owner, scope, inventory.Query{Limit: 1, Cursor: cursor})
	if err != nil || len(second.Devices()) != 1 || second.Devices()[0].ID().String() != expected[1].id {
		t.Fatalf("second page = %+v, %v; want %s", second.Devices(), err, expected[1].id)
	}

	prefix := expected[0].hostname[:min(3, len(expected[0].hostname))]
	named, err := service.List(ctx, owner, scope, inventory.Query{Limit: inventory.MaximumPageSize, NamePrefix: prefix})
	want := 0
	for _, item := range expected {
		if strings.HasPrefix(item.hostname, prefix) {
			want++
		}
	}
	if err != nil || len(named.Devices()) != want {
		t.Fatalf("names starting with %q = %d, %v; want %d", prefix, len(named.Devices()), err, want)
	}

	for state, active := range map[inventory.StateFilter]bool{inventory.StateActive: true, inventory.StateInactive: false} {
		page, err := service.List(ctx, owner, scope, inventory.Query{Limit: inventory.MaximumPageSize, State: state})
		want := 0
		for _, item := range expected {
			if item.active == active {
				want++
			}
		}
		if err != nil || len(page.Devices()) != want {
			t.Fatalf("%s Devices = %d, %v; want %d", state, len(page.Devices()), err, want)
		}
	}

	for _, item := range expected[:2] {
		id, _ := node.ParseID(item.id)
		record, err := service.Get(ctx, owner, scope, id)
		if err != nil || record.Device.ID() != id || record.Enrollment.ByKey != (item.kind == "credential") {
			t.Fatalf("read Device %s = %+v, %v", item.id, record.Enrollment, err)
		}
	}
	firstID, _ := node.ParseID(expected[0].id)
	names, err := service.Names(ctx, owner, scope, []node.ID{firstID})
	if err != nil || names[firstID] != expected[0].hostname {
		t.Fatalf("names = %v, %v; want %s", names, err, expected[0].hostname)
	}

	distributionStore, err := postgresadapter.NewDeviceDistributionStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range expected {
		id, _ := node.ParseID(item.id)
		target, err := distributionStore.ReadTarget(ctx, owner, scope, id)
		var state string
		if err := admin.QueryRow(ctx, `SELECT state FROM mesh.device WHERE public_id = $1::UUID`, item.id).
			Scan(&state); err != nil {
			t.Fatal(err)
		}
		connectable := state == "active" || state == "suspended"
		if err != nil || target.Scope != scope || target.NetworkRevision < 1 ||
			len(target.Devices) != map[bool]int{true: 1, false: 0}[connectable] {
			t.Fatalf("distribution target of %s (%s) = %+v, %v", item.hostname, state, target, err)
		}
	}

	var foreign string
	if err := admin.QueryRow(ctx, `SELECT device.public_id::TEXT FROM mesh.device AS device
JOIN mesh.network AS net ON net.id = device.network_id WHERE net.public_id <> $1::UUID
ORDER BY device.id LIMIT 1`, networkID.String()).Scan(&foreign); err != nil {
		t.Fatal(err)
	}
	foreignID, _ := node.ParseID(foreign)
	if _, err := service.Get(ctx, owner, scope, foreignID); !errors.Is(err, inventory.ErrNotFound) {
		t.Fatalf("a Device of another Network was read in this one: %v", err)
	}
	if names, err := service.Names(ctx, owner, scope, []node.ID{foreignID}); err != nil || len(names) != 0 {
		t.Fatalf("a Device of another Network was named in this one: %v, %v", names, err)
	}
	if _, err := service.List(ctx, authorityConfirmerAccountSessionFixture(t), scope,
		inventory.Query{Limit: 10}); !errors.Is(err, inventory.ErrForbidden) {
		t.Fatalf("a session without device.read listed Devices: %v", err)
	}
}
