//go:build integration

package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

const integrationAdmitLoginRouteSQL = `SELECT mesh_ops.admit_oidc_login_route_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID, $5::BIGINT, $6::BIGINT,
    $7::TEXT, $8::TEXT, $9::TEXT, $10::TEXT, $11::TEXT,
    $12::TEXT, $13::TEXT, $14::TEXT[], $15::TEXT[], $16::TEXT
)`

func assertPostgreSQLAuthTransactionAdmission(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	runtime *pgx.Conn,
	pool *postgresadapter.Pool,
) {
	t.Helper()
	template := integrationAuthTransactionPending(t, integrationAuthRouteParams{
		providerGeneration: 1, recoveryEpoch: 1,
		workspacePublicID: "01890f00-0000-7000-8000-000000000101",
	}, [4]string{
		"01890f00-0000-7000-8000-000000000958", "01890f01-0000-7000-8000-000000000958",
		"01890f02-0000-7000-8000-000000000958", "01890f03-0000-7000-8000-000000000958",
	})
	store, err := postgresadapter.NewAuthTransactionStore(pool, postgresadapter.AuthTransactionOptions{
		StatementTimeout: 5 * time.Second, LockTimeout: time.Second, IdleTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	before := authAdmissionAuthorityCounts(ctx, t, admin)
	for range 2 {
		if err := store.Admit(ctx, template.Route()); err != nil {
			t.Fatalf("runtime Admit() error = %v", err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := store.Admit(canceled, template.Route()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled runtime Admit() error = %v", err)
	}
	assertLoginRouteAdmissionPrivileges(ctx, t, admin)
	arguments := integrationLoginRouteArguments(template.Route())
	for _, candidate := range []struct {
		name  string
		index int
		value any
	}{
		{name: "other deployment", index: 0, value: "01890f00-0000-7000-8000-000000000002"},
		{name: "unmapped workspace", index: 1, value: "01890f00-0000-7000-8000-000000000102"},
		{name: "other provider", index: 2, value: "01890f00-0000-7000-8000-000000000602"},
		{name: "other client", index: 3, value: "01890f00-0000-7000-8000-000000000622"},
		{name: "stale provider generation", index: 4, value: int64(2)},
		{name: "stale recovery epoch", index: 5, value: int64(2)},
		{name: "issuer", index: 6, value: "https://other.example.test/realms/main"},
		{name: "discovery", index: 7, value: "https://other.example.test/discovery"},
		{name: "authorization endpoint", index: 8, value: "https://other.example.test/auth"},
		{name: "token endpoint", index: 9, value: "https://other.example.test/token"},
		{name: "jwks endpoint", index: 10, value: "https://other.example.test/jwks"},
		{name: "oidc client id", index: 11, value: "other-client"},
		{name: "client authentication", index: 12, value: "private_key_jwt"},
		{name: "scope ordering", index: 13, value: []string{"profile", "openid"}},
		{name: "scope widening", index: 13, value: []string{"openid", "profile", "email"}},
		{name: "algorithm", index: 14, value: []string{"ES256"}},
		{name: "unregistered callback", index: 15, value: "https://console.example.test/other-callback"},
		{name: "null scope", index: 13, value: nil},
		{name: "empty scope", index: 13, value: []string{}},
		{name: "oversized scope", index: 13, value: []string{"openid", strings.Repeat("x", 129)}},
		{name: "oversized issuer", index: 6, value: "https://" + strings.Repeat("x", 2049)},
		{name: "invalid uuid version", index: 1, value: "01890f00-0000-4000-8000-000000000101"},
		{name: "invalid uuid variant", index: 1, value: "01890f00-0000-7000-c000-000000000101"},
	} {
		t.Run("route admission "+candidate.name, func(t *testing.T) {
			changed := append([]any(nil), arguments...)
			changed[candidate.index] = candidate.value
			transaction, err := runtime.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackIntegrationTransaction(ctx, t, transaction)
			if _, err := transaction.Exec(ctx, `SELECT pg_catalog.set_config(
    'mesh.requested_workspace_public_id', '01890f00-0000-7000-8000-000000000101', TRUE
)`); err != nil {
				t.Fatal(err)
			}
			var admitted bool
			if err := transaction.QueryRow(ctx, integrationAdmitLoginRouteSQL, changed...).Scan(&admitted); err != nil {
				t.Fatalf("read-only admission error = %v", err)
			}
			if admitted {
				t.Fatal("mismatched or invalid route admitted")
			}
			assertAdmissionScopeCleared(ctx, t, transaction)
		})
	}
	assertLoginRouteAdmissionLifecycle(ctx, t, admin, arguments)
	if after := authAdmissionAuthorityCounts(ctx, t, admin); before != after {
		t.Fatalf("admission changed durable authority counts: before=%v after=%v", before, after)
	}
	// Creation still repeats the authoritative checks; successful admission is
	// not permission to create a transaction using a later stale generation.
	stale := integrationAuthTransactionPending(t, integrationAuthRouteParams{
		providerGeneration: 2, recoveryEpoch: 1,
		workspacePublicID: "01890f00-0000-7000-8000-000000000101",
	}, [4]string{
		"01890f00-0000-7000-8000-000000000959", "01890f01-0000-7000-8000-000000000959",
		"01890f02-0000-7000-8000-000000000959", "01890f03-0000-7000-8000-000000000959",
	})
	if err := store.Admit(ctx, stale.Route()); !errors.Is(err, postgresadapter.ErrAuthTransactionRouteUnavailable) {
		t.Fatalf("stale runtime Admit() error = %v", err)
	}
	assertPostgreSQLBrowserLoginHTTP(ctx, t, admin, store)
	assertAdmissionRevocationDuringDiscovery(ctx, t, admin, store)
}

func assertAdmissionRevocationDuringDiscovery(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	store *postgresadapter.AuthTransactionStore,
) {
	t.Helper()
	t.Run("provider revoked after admission during discovery", func(t *testing.T) {
		template := integrationAuthTransactionPending(t, integrationAuthRouteParams{
			providerGeneration: 1, recoveryEpoch: 1,
			workspacePublicID: "01890f00-0000-7000-8000-000000000101",
		}, [4]string{
			"01890f00-0000-7000-8000-000000000963", "01890f01-0000-7000-8000-000000000963",
			"01890f02-0000-7000-8000-000000000963", "01890f03-0000-7000-8000-000000000963",
		})
		if err := store.Admit(ctx, template.Route()); err != nil {
			t.Fatal(err)
		}
		transactions := &integrationAuthStartTransactions{store: store}
		dependencies := integrationAuthStartDependencies(t, template, store, transactions)
		dependencies.Metadata = integrationAdmissionMetadata{resolve: func(ctx context.Context, route oidcauth.Route) (oidcauth.Metadata, error) {
			// Synchronous synthetic discovery hook: commit the revocation after
			// read admission, before the application opens its creation unit.
			setAdmissionFixtureProviderState(ctx, t, admin, "suspended", 2, "964")
			return (integrationAuthStartMetadata{}).Resolve(ctx, route)
		}}
		defer setAdmissionFixtureProviderState(ctx, t, admin, "active", 3, "965")
		service, err := oidcauth.NewStartService(oidcauth.StartOptions{
			RequestTimeout: 10 * time.Second, PendingLifetime: 5 * time.Minute,
			RollbackTimeout: 2 * time.Second, ResolveTimeout: 2 * time.Second,
		}, dependencies)
		if err != nil {
			t.Fatal(err)
		}
		result, err := service.Start(ctx, template.Route())
		if err == nil || result.IsValid() || transactions.begins != 1 || transactions.creates != 1 || transactions.commits != 0 {
			t.Fatal("revocation during discovery bypassed the creation recheck")
		}
		if err := store.Admit(ctx, template.Route()); !errors.Is(err, postgresadapter.ErrAuthTransactionRouteUnavailable) {
			t.Fatalf("revoked route still admitted: %v", err)
		}
		var created int
		if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh.auth_transaction
WHERE public_id = $1::UUID`, template.TransactionID().String()).Scan(&created); err != nil {
			t.Fatal(err)
		}
		if created != 0 {
			t.Fatal("revoked route persisted an authentication transaction")
		}
	})
}

type integrationAdmissionMetadata struct {
	resolve func(context.Context, oidcauth.Route) (oidcauth.Metadata, error)
}

func (metadata integrationAdmissionMetadata) Resolve(ctx context.Context, route oidcauth.Route) (oidcauth.Metadata, error) {
	return metadata.resolve(ctx, route)
}

func setAdmissionFixtureProviderState(ctx context.Context, t *testing.T, admin *pgx.Conn, state string, version int64, suffix string) {
	t.Helper()
	commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
		changePublicID: "01890f01-0000-7000-8000-000000000" + suffix,
		eventPublicID:  "01890f02-0000-7000-8000-000000000" + suffix,
		outboxPublicID: "01890f03-0000-7000-8000-000000000" + suffix,
		streamID:       1, aggregateKind: "identity_provider", aggregatePublicID: integrationIdentityProviderPublicID,
		aggregateVersion: version, actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action: "identity_provider.updated", permission: "identity_provider.manage",
		outboxEventClass: "identity_provider.updated",
	}, func(transaction pgx.Tx) {
		if _, err := transaction.Exec(ctx, `UPDATE mesh.identity_provider
SET state = $2::TEXT, version = $3::BIGINT,
    updated_at = GREATEST(pg_catalog.transaction_timestamp(), updated_at)
WHERE public_id = $1::UUID`, integrationIdentityProviderPublicID, state, version); err != nil {
			t.Fatal(err)
		}
	})
}

func assertLoginRouteAdmissionLifecycle(ctx context.Context, t *testing.T, admin *pgx.Conn, arguments []any) {
	t.Helper()
	for _, candidate := range []struct {
		name  string
		query string
	}{
		{name: "deployment suspended", query: "UPDATE mesh.deployment SET state = 'suspended' WHERE id = 1"},
		{name: "deployment quarantined", query: "UPDATE mesh.deployment SET recovery_state = 'quarantined' WHERE id = 1"},
		{name: "recovery epoch changed", query: "UPDATE mesh.deployment SET recovery_epoch = 2 WHERE id = 1"},
		{name: "workspace suspended", query: "UPDATE mesh.workspace SET state = 'suspended' WHERE id = 101"},
		{name: "workspace deleted", query: "UPDATE mesh.workspace SET state = 'deleted', deleted_at = pg_catalog.transaction_timestamp() WHERE id = 101"},
		{name: "provider suspended", query: "UPDATE mesh.identity_provider SET state = 'suspended' WHERE id = 601"},
		{name: "provider quarantined", query: "UPDATE mesh.identity_provider SET recovery_state = 'quarantined' WHERE id = 601"},
		{name: "legacy endpoints absent", query: "UPDATE mesh.identity_provider SET authorization_endpoint = NULL, token_endpoint = NULL WHERE id = 601"},
		{name: "generation not yet valid", query: "UPDATE mesh.identity_provider_generation SET valid_from = pg_catalog.transaction_timestamp() + INTERVAL '1 minute' WHERE id = 611"},
		{name: "generation revoked", query: "UPDATE mesh.identity_provider_generation SET state = 'revoked', valid_until = pg_catalog.transaction_timestamp() WHERE id = 611"},
		{name: "client suspended", query: "UPDATE mesh.identity_provider_client SET state = 'suspended' WHERE id = 621"},
		{name: "public client", query: "UPDATE mesh.identity_provider_client SET client_kind = 'public', client_auth_method = 'none', credential_reference = NULL WHERE id = 621"},
		{name: "code flow absent", query: "UPDATE mesh.identity_provider_client SET allowed_flows = ARRAY['device_authorization'], redirect_uris = ARRAY[]::TEXT[] WHERE id = 621"},
		{name: "binding suspended", query: "UPDATE mesh.workspace_identity_provider SET state = 'suspended' WHERE id = 631"},
		{name: "organization binding", query: `UPDATE mesh.workspace_identity_provider SET
    organization_digest_algorithm = 'hmac-sha256-v1', organization_digest_key_id = 'integration-v1',
    organization_digest = pg_catalog.decode(pg_catalog.repeat('33', 32), 'hex') WHERE id = 631`},
	} {
		t.Run("durable route "+candidate.name, func(t *testing.T) {
			transaction, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackIntegrationTransaction(ctx, t, transaction)
			setIntegrationChange(ctx, t, transaction, "01890f01-0000-7000-8000-000000000960")
			// Security: all queries are the fixed synthetic manifest above, never
			// external strings. Preserve the required authority version transition
			// in every rollback-only probe, without changing production constraints.
			query := strings.Replace(candidate.query, " WHERE id =", ", version = version + 1, "+
				"updated_at = GREATEST(pg_catalog.transaction_timestamp(), updated_at) WHERE id =", 1)
			if _, err := transaction.Exec(ctx, query); err != nil {
				t.Fatalf("prepare rolled-back lifecycle probe: %v", err)
			}
			var admitted bool
			if err := transaction.QueryRow(ctx, integrationAdmitLoginRouteSQL, arguments...).Scan(&admitted); err != nil {
				t.Fatal(err)
			}
			if admitted {
				t.Fatal("inactive durable route admitted")
			}
			assertAdmissionScopeCleared(ctx, t, transaction)
			// These schema-contract probes never commit unaudited authority changes.
		})
	}
}

func integrationLoginRouteArguments(route oidcauth.Route) []any {
	return []any{
		route.DeploymentID().String(), route.WorkspaceID().String(), route.ProviderID().String(), route.ClientID().String(),
		route.ProviderGeneration(), route.RecoveryEpoch(), route.Issuer(), route.DiscoveryURI(),
		route.AuthorizationEndpoint(), route.TokenEndpoint(), route.JWKSURI(), route.OIDCClientID(),
		route.ClientAuthMethod(), route.Scopes(), route.AllowedAlgorithms(), route.RedirectURI(),
	}
}

func assertAdmissionScopeCleared(ctx context.Context, t *testing.T, transaction pgx.Tx) {
	t.Helper()
	var requested string
	if err := transaction.QueryRow(ctx, `SELECT COALESCE(
    pg_catalog.current_setting('mesh.requested_workspace_public_id', TRUE), ''
)`).Scan(&requested); err != nil {
		t.Fatal(err)
	}
	if requested != "" {
		t.Fatal("admission leaked caller-selected Workspace scope")
	}
}

func authAdmissionAuthorityCounts(ctx context.Context, t *testing.T, admin *pgx.Conn) [5]int64 {
	t.Helper()
	var counts [5]int64
	if err := admin.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*) FROM mesh.auth_transaction),
    (SELECT pg_catalog.count(*) FROM mesh_audit.authority_mutation),
    (SELECT pg_catalog.count(*) FROM mesh_audit.audit_event),
    (SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event),
    (SELECT COALESCE(pg_catalog.sum(network_revision), 0)::BIGINT FROM mesh_ops.network_revision)
`).Scan(&counts[0], &counts[1], &counts[2], &counts[3], &counts[4]); err != nil {
		t.Fatal(err)
	}
	return counts
}

func assertLoginRouteAdmissionPrivileges(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	var hardened, runtimeAllowed, workerAllowed, observerAllowed, tableAllowed bool
	if err := admin.QueryRow(ctx, `SELECT
    function.prosecdef AND NOT owner.rolsuper AND NOT owner.rolbypassrls
      AND owner.rolname = 'mesh_migrator'
      AND function.proconfig @> ARRAY['search_path=pg_catalog, mesh, mesh_ops']::TEXT[],
    pg_catalog.has_function_privilege('mesh_runtime', function.oid, 'EXECUTE'),
    pg_catalog.has_function_privilege('mesh_worker', function.oid, 'EXECUTE'),
    pg_catalog.has_function_privilege('mesh_observer', function.oid, 'EXECUTE'),
    pg_catalog.has_table_privilege('mesh_runtime', 'mesh.identity_provider', 'SELECT')
      OR pg_catalog.has_table_privilege('mesh_runtime', 'mesh.identity_provider_client', 'SELECT')
FROM pg_catalog.pg_proc AS function
JOIN pg_catalog.pg_namespace AS schema ON schema.oid = function.pronamespace
JOIN pg_catalog.pg_roles AS owner ON owner.oid = function.proowner
WHERE schema.nspname = 'mesh_ops' AND function.proname = 'admit_oidc_login_route_v1'
`).Scan(&hardened, &runtimeAllowed, &workerAllowed, &observerAllowed, &tableAllowed); err != nil {
		t.Fatal(err)
	}
	if !hardened || !runtimeAllowed || workerAllowed || observerAllowed || tableAllowed {
		t.Fatal("route admission widened runtime or non-runtime privileges")
	}
}
