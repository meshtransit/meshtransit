//go:build integration

package integration

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/network/aliasrange"
	"meshtransit.net/core/internal/domain/publicid"
)

type integrationClock struct{}

func (integrationClock) Now() time.Time { return time.Now().UTC() }

// assertNetworkAliasRanges qualifies schema 113: a receiving Network chooses
// where shared Devices appear inside the Deployment frame, Resource Aliases
// are allocated inside that range, retained aliases are never excluded, and
// other Networks may choose the same range.
func assertNetworkAliasRanges(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	runtimePool *postgresadapter.Pool,
	session accountsession.Session,
	providerScope, consumerScope network.Scope,
) {
	t.Helper()
	// The shared fixture role gains network.read and network.update here.
	var networkRevision int64
	if err := admin.QueryRow(ctx, `SELECT network_revision FROM mesh_ops.network_revision
WHERE workspace_id = 103 AND network_id = 203`).Scan(&networkRevision); err != nil {
		t.Fatal(err)
	}
	commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
		changePublicID:         "01890f01-0000-7000-8000-000000000880",
		eventPublicID:          "01890f02-0000-7000-8000-000000000880",
		outboxPublicID:         "01890f03-0000-7000-8000-000000000880",
		streamID:               203,
		aggregateKind:          "role_permission",
		aggregatePublicID:      "01890f00-0000-7000-8000-000000000880",
		aggregateVersion:       1,
		networkRevision:        networkRevision,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "management_rbac.seeded",
		permission:             "system.bootstrap",
		outboxEventClass:       "management_rbac.seeded",
	}, func(transaction pgx.Tx) {
		for _, grant := range []struct {
			id         int
			permission string
		}{{880, "network.read"}, {881, "network.update"}} {
			if _, err := transaction.Exec(ctx, `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT $1::BIGINT, ('01890f00-0000-7000-8000-' || lpad($1::TEXT, 12, '0'))::UUID, 1, 103, 842, permission.id
FROM mesh.permission AS permission WHERE permission.permission_key = $2::TEXT`, grant.id, grant.permission); err != nil {
				t.Fatalf("grant %s: %v", grant.permission, err)
			}
		}
	})
	store, err := postgresadapter.NewNetworkAliasRangeStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service, err := aliasrange.NewService(store, integrationClock{})
	if err != nil {
		t.Fatal(err)
	}
	state, err := service.Read(ctx, session, consumerScope)
	if err != nil {
		t.Fatalf("read alias ranges: %v", err)
	}
	// Receiving shares in this suite hold IPv6 Resource Aliases only.
	if !state.IPv6.Frame.IsValid() || state.IPv6.Prefix.IsValid() ||
		state.IPv6.Retained < 1 || state.ShareLimit != aliasrange.ShareLimit || state.LiveShares < 1 {
		t.Fatalf("initial alias range state = %+v", state)
	}
	keeping := netip.PrefixFrom(lowestRetainedResourceAlias(ctx, t, admin, consumerScope, 6), 120).Masked()
	excluding := keeping.Addr()
	for range 256 {
		excluding = excluding.Next()
	}
	excludingRange := netip.PrefixFrom(excluding, 120)
	if !state.IPv6.Frame.Contains(excludingRange.Addr()) {
		t.Fatalf("test range %s does not fit frame %s", excludingRange, state.IPv6.Frame)
	}

	update := func(version int64, ipv4, ipv6 aliasrange.Change) (aliasrange.Result, error) {
		correlation, err := publicid.New()
		if err != nil {
			t.Fatal(err)
		}
		return service.Update(ctx, aliasrange.Command{Session: session, Scope: consumerScope, ExpectedVersion: version,
			IPv4: ipv4, IPv6: ipv6, CorrelationID: correlation})
	}
	for _, rejected := range []struct {
		name       string
		version    int64
		ipv4, ipv6 aliasrange.Change
		want       error
	}{
		{name: "outside the IPv4 frame", version: state.Version,
			ipv4: aliasrange.Change{Present: true, Prefix: netip.MustParsePrefix("198.18.42.0/24")}, want: aliasrange.ErrOutsideFrame},
		{name: "outside the IPv6 frame", version: state.Version,
			ipv6: aliasrange.Change{Present: true, Prefix: netip.MustParsePrefix("fd99::/120")}, want: aliasrange.ErrOutsideFrame},
		{name: "excludes a retained alias", version: state.Version,
			ipv6: aliasrange.Change{Present: true, Prefix: excludingRange}, want: aliasrange.ErrInUse},
		{name: "stale version", version: state.Version + 5,
			ipv6: aliasrange.Change{Present: true, Prefix: keeping}, want: aliasrange.ErrVersionConflict},
	} {
		if _, err := update(rejected.version, rejected.ipv4, rejected.ipv6); !errors.Is(err, rejected.want) {
			t.Fatalf("%s: error = %v, want %v", rejected.name, err, rejected.want)
		}
	}

	result, err := update(state.Version, aliasrange.Change{}, aliasrange.Change{Present: true, Prefix: keeping})
	if err != nil || !result.Changed || result.State.Version <= state.Version || result.State.IPv6.Prefix != keeping {
		t.Fatalf("choose alias range = %+v, %v", result, err)
	}
	repeated, err := update(result.State.Version, aliasrange.Change{}, aliasrange.Change{Present: true, Prefix: keeping})
	if err != nil || repeated.Changed || repeated.State.Version != result.State.Version {
		t.Fatalf("repeat alias range = %+v, %v", repeated, err)
	}

	// New Resource Aliases for this receiving Network fall inside its range.
	if allocated := allocateIntegrationResourceAlias(ctx, t, admin, providerScope, consumerScope, 6); !keeping.Contains(allocated) {
		t.Fatalf("alias %s outside the chosen range %s", allocated, keeping)
	}

	// Another Network may choose the same range.
	same, err := service.Read(ctx, session, providerScope)
	if err != nil {
		t.Fatalf("read provider alias ranges: %v", err)
	}
	correlation, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	if shared, err := service.Update(ctx, aliasrange.Command{Session: session, Scope: providerScope,
		ExpectedVersion: same.Version, IPv6: aliasrange.Change{Present: true, Prefix: keeping},
		CorrelationID: correlation}); err != nil || shared.State.IPv6.Prefix != keeping {
		t.Fatalf("a second Network choosing the same range = %+v, %v", shared, err)
	}

	cleared, err := update(result.State.Version, aliasrange.Change{}, aliasrange.Change{Present: true})
	if err != nil || !cleared.Changed || cleared.State.IPv6.Prefix.IsValid() {
		t.Fatalf("clear alias ranges = %+v, %v", cleared, err)
	}
	var events int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_audit.audit_event
WHERE action = 'network.alias_range.updated' AND target_public_id = $1::UUID
  AND permission = 'network.update' AND actor_principal_public_id IS NOT NULL`,
		consumerScope.NetworkID().String()).Scan(&events); err != nil || events != 2 {
		t.Fatalf("alias range audit events = %d, %v", events, err)
	}
	assertRuntimeCannotWriteAliasRanges(ctx, t, admin)
}

func lowestRetainedResourceAlias(ctx context.Context, t *testing.T, admin *pgx.Conn, scope network.Scope, family int) netip.Addr {
	t.Helper()
	var text string
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.host(pg_catalog.min(address))
FROM (
    SELECT lease.address FROM mesh.device_alias_lease AS lease
    JOIN mesh.network AS consumer ON consumer.id = lease.consumer_network_id
    WHERE consumer.public_id = $1::UUID AND lease.alias_role = 'resource' AND lease.family = $2::INTEGER
      AND lease.state IN ('reserved', 'quarantined')
    UNION ALL
    SELECT lease.resource_alias FROM mesh.federation_alias_lease AS lease
    JOIN mesh.network AS consumer ON consumer.id = lease.consumer_network_id
    WHERE consumer.public_id = $1::UUID AND lease.family = $2::INTEGER AND lease.state IN ('reserved', 'active')
) AS retained(address)`, scope.NetworkID().String(), family).Scan(&text); err != nil {
		t.Fatalf("read retained Resource Aliases: %v", err)
	}
	address, err := netip.ParseAddr(text)
	if err != nil {
		t.Fatalf("no retained IPv%d Resource Alias in the receiving Network: %v", family, err)
	}
	return address
}

func allocateIntegrationResourceAlias(ctx context.Context, t *testing.T, admin *pgx.Conn,
	providerScope, consumerScope network.Scope, family int) netip.Addr {
	t.Helper()
	var text string
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.host(mesh_ops.allocate_network_scoped_alias_v1(
    consumer.deployment_id, pool.id, provider.id, consumer_network.id))
FROM mesh.network AS provider
JOIN mesh.network AS consumer_network ON consumer_network.public_id = $2::UUID
JOIN mesh.workspace AS consumer ON consumer.id = consumer_network.workspace_id
JOIN mesh.address_pool AS pool ON pool.deployment_id = consumer.deployment_id AND pool.workspace_id IS NULL
 AND pool.purpose = 'federation_resource_alias' AND pool.family = $3::INTEGER AND pool.state = 'active'
WHERE provider.public_id = $1::UUID
ORDER BY pool.id LIMIT 1`, providerScope.NetworkID().String(), consumerScope.NetworkID().String(), family).Scan(&text); err != nil {
		t.Fatalf("allocate IPv%d Resource Alias: %v", family, err)
	}
	address, err := netip.ParseAddr(text)
	if err != nil {
		t.Fatal(err)
	}
	return address
}

func assertRuntimeCannotWriteAliasRanges(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	if _, err := transaction.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
		t.Fatal(err)
	}
	_, err = transaction.Exec(ctx, `UPDATE mesh.network_alias_range SET prefix = NULL`)
	assertPostgreSQLCode(t, err, "42501")
}
