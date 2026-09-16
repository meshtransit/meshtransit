//go:build integration

package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	redisadapter "github.com/meshtransit/meshtransit/internal/adapter/redis"
	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

type privateFactoryIntegrationStorage struct {
	runtime *postgresadapter.Pool
	admin   *pgx.Conn
	redis   config.RedisConfig
}

func openPrivateFactoryIntegrationStorage(t *testing.T) *privateFactoryIntegrationStorage {
	t.Helper()
	migration, err := config.LoadMigration(os.LookupEnv)
	if err != nil {
		t.Fatal("load owned migration profile")
	}
	process, err := config.Load(os.LookupEnv)
	if err != nil || process.Storage == nil {
		t.Fatal("load owned runtime profile")
	}
	if process.Storage.PostgreSQL.Runtime == nil {
		t.Fatal("runtime credentials are required")
	}
	pg := process.Storage.PostgreSQL
	dedicatedDatabase := migration.PostgreSQL.Database == "meshtransit_private_factory"
	matchingDatabase := pg.Database == migration.PostgreSQL.Database && pg.Address == migration.PostgreSQL.Address
	owned := dedicatedDatabase && matchingDatabase
	postgresRoles := migration.PostgreSQL.User == "mesh_migrator" && pg.Runtime.User == "mesh_runtime"
	roles := postgresRoles && process.Storage.Redis.Username == "mesh_worker"
	ownedAddresses := pg.Address == "meshtransit-postgres:5432" && process.Storage.Redis.Address == "meshtransit-redis:6379"
	if !owned || !roles {
		t.Fatal("refuse anything except the explicit owned Linux fixture scope")
	}
	if !ownedAddresses {
		t.Fatal("refuse anything except the explicit owned Linux fixture scope")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	runner, err := postgresadapter.OpenMigrationRunner(ctx, postgresadapter.MigrationOptions{
		Address: migration.PostgreSQL.Address, Database: migration.PostgreSQL.Database,
		User: migration.PostgreSQL.User, PasswordFile: migration.PostgreSQL.PasswordFile, CAFile: migration.PostgreSQL.CAFile,
		ConnectTimeout: migration.ConnectTimeout, LockTimeout: migration.LockTimeout, StatementTimeout: migration.StatementTimeout,
		Actor: migration.Actor, CodeRelease: "private-factory-integration@local",
	})
	if err != nil {
		t.Fatal("open owned migration runner")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer stop()
		if err := runner.Close(cleanup); err != nil {
			t.Error("close owned migration runner")
		}
	})
	status, err := runner.Status(ctx)
	if err != nil || status.State != postgresadapter.MigrationStateUninitialized {
		t.Fatal("refuse initialized fixture database before writes")
	}
	result, err := runner.Up(ctx)
	invalidSchema := result.Status.State != postgresadapter.MigrationStateClean || result.Status.CurrentVersion != result.Status.LatestVersion
	if err != nil || invalidSchema {
		t.Fatal("apply all released migrations")
	}
	pool, err := openPostgresRolePool(ctx, postgresadapter.PoolRoleRuntime, pg, *pg.Runtime, 5*time.Second)
	if err != nil {
		t.Fatal("open real runtime pool")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer stop()
		if err := pool.Shutdown(cleanup); err != nil {
			t.Error("close owned runtime pool")
		}
	})
	if err := pool.Check(ctx); err != nil {
		t.Fatal("verify runtime schema and role readiness")
	}
	adminProfile, err := config.LoadMigration(func(key string) (string, bool) {
		switch key {
		case "MESHTRANSIT_MIGRATION_POSTGRES_USER":
			return "postgres", true
		case "MESHTRANSIT_MIGRATION_POSTGRES_PASSWORD_FILE":
			return os.LookupEnv("MESHTRANSIT_TEST_POSTGRES_ADMIN_PASSWORD_FILE")
		default:
			return os.LookupEnv(key)
		}
	})
	if err != nil {
		t.Fatal("load separate fixture seed authority")
	}
	storage := &privateFactoryIntegrationStorage{runtime: pool, admin: openPrivateFactoryAdmin(ctx, t, adminProfile), redis: process.Storage.Redis}
	storage.seed(t, "deployment", privateIdentityID(t, 1).String(), func(seedContext context.Context, tx pgx.Tx) {
		privateFactoryExec(seedContext, t, tx, `INSERT INTO mesh.deployment
(id, installation_public_id, profile, state, schema_epoch, authority_generation, recovery_epoch, recovery_state)
OVERRIDING SYSTEM VALUE VALUES (1,$1::UUID,'cloud','active',1,1,1,'verified')`, privateIdentityID(t, 1).String())
		privateFactoryExec(seedContext, t, tx, `INSERT INTO mesh_audit.audit_stream (id,deployment_id,scope_kind)
OVERRIDING SYSTEM VALUE VALUES (1,1,'deployment')`)
	})
	storage.seed(t, "principal", privateIdentityID(t, 2).String(), func(seedContext context.Context, tx pgx.Tx) {
		privateFactoryExec(seedContext, t, tx, `INSERT INTO mesh.principal (id,public_id,deployment_id,kind,state)
OVERRIDING SYSTEM VALUE VALUES (11,$1::UUID,1,'account','active')`, privateIdentityID(t, 2).String())
	})
	return storage
}

func openPrivateFactoryAdmin(ctx context.Context, t *testing.T, profile config.MigrationConfig) *pgx.Conn {
	t.Helper()
	password, err := profile.PostgreSQL.PasswordFile.Read()
	if err != nil {
		t.Fatal("read private fixture seed credential")
	}
	ca, err := profile.PostgreSQL.CAFile.Read()
	if err != nil {
		t.Fatal("read private fixture seed trust")
	}
	host, portString, err := net.SplitHostPort(profile.PostgreSQL.Address)
	if err != nil {
		t.Fatal("parse owned fixture address")
	}
	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil || port == 0 {
		t.Fatal("parse owned fixture port")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("parse owned fixture trust")
	}
	connection, err := pgx.ParseConfig("host=localhost port=5432 user=placeholder dbname=placeholder sslmode=disable")
	if err != nil {
		t.Fatal("construct explicit fixture connection")
	}
	connection.Host, connection.Port, connection.Database = host, uint16(port), profile.PostgreSQL.Database
	connection.User, connection.Password, connection.ConnectTimeout = profile.PostgreSQL.User, password, 5*time.Second
	connection.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: host}
	connection.Fallbacks, connection.RequireAuth = nil, "scram-sha-256"
	connection.RuntimeParams["statement_timeout"] = "5000"
	connection.RuntimeParams["lock_timeout"] = "2000"
	connection.RuntimeParams["idle_in_transaction_session_timeout"] = "10000"
	admin, err := pgx.ConnectConfig(ctx, connection)
	if err != nil {
		t.Fatal("connect owned verified-TLS seed authority")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer stop()
		if err := admin.Close(cleanup); err != nil {
			t.Error("close fixture seed connection")
		}
	})
	return admin
}

func (storage *privateFactoryIntegrationStorage) openRedis(t *testing.T) (*redisadapter.Client, func() error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cache, err := redisadapter.Open(ctx, redisadapter.Options{
		Address: storage.redis.Address, Username: storage.redis.Username, PasswordFile: storage.redis.PasswordFile,
		CAFile: storage.redis.CAFile, PoolSize: storage.redis.PoolSize, RequestTimeout: time.Second,
	})
	if err != nil {
		t.Fatal("open real fixture Redis")
	}
	closed := false
	closeCache := func() error {
		if closed {
			return nil
		}
		closed = true
		return cache.Close()
	}
	t.Cleanup(func() {
		if err := closeCache(); err != nil {
			t.Error("close owned Redis client")
		}
	})
	if err := cache.Check(ctx); err != nil {
		t.Fatal("verify fixture TLS/ACL Redis readiness")
	}
	return cache, closeCache
}

func (storage *privateFactoryIntegrationStorage) seedRoute(t *testing.T, route oidcauth.Route) {
	t.Helper()
	storage.seed(t, "workspace", route.WorkspaceID().String(), func(ctx context.Context, tx pgx.Tx) {
		privateFactoryExec(ctx, t, tx, `INSERT INTO mesh.workspace
(public_id,deployment_id,owner_principal_id,display_name,name_key,state)
VALUES ($1::UUID,1,11,'Private factory fixture',$2,'active')`, route.WorkspaceID().String(), "fixture-"+route.WorkspaceID().String())
	})
	storage.seed(t, "identity_provider", route.ProviderID().String(), func(ctx context.Context, tx pgx.Tx) {
		// This resident fixture-only issuer key is not an external-subject key.
		var material [32]byte
		if _, err := rand.Read(material[:]); err != nil {
			t.Fatal("generate fixture issuer key")
		}
		issuerMAC := hmac.New(sha256.New, material[:])
		_, _ = issuerMAC.Write([]byte(route.Issuer()))
		clear(material[:])
		trustHash := sha256.Sum256([]byte(route.DiscoveryURI()))
		generationID, err := publicid.New()
		if err != nil {
			t.Fatal("generate fixture trust-generation identity")
		}
		bindingID, err := publicid.New()
		if err != nil {
			t.Fatal("generate fixture provider-binding identity")
		}
		privateFactoryExec(ctx, t, tx, `INSERT INTO mesh.identity_provider
(public_id,deployment_id,issuer,issuer_digest_algorithm,issuer_digest_key_id,issuer_digest,
protocol,authority_kind,discovery_uri,authorization_endpoint,token_endpoint,jwks_uri,current_generation,recovery_state,state)
VALUES ($1::UUID,1,$2,'hmac-sha256-v1','fixture-v1',$3,'oidc','managed_oidc',$4,$5,$6,$7,1,'verified','active')`,
			route.ProviderID().String(), route.Issuer(), issuerMAC.Sum(nil), route.DiscoveryURI(), route.AuthorizationEndpoint(), route.TokenEndpoint(), route.JWKSURI())
		privateFactoryExec(ctx, t, tx, `INSERT INTO mesh.identity_provider_generation
(public_id,deployment_id,identity_provider_id,generation,trust_configuration_semantic_hash,recovery_mode,valid_from,state)
SELECT $1::UUID,1,id,1,$2,'initial',pg_catalog.transaction_timestamp(),'current'
FROM mesh.identity_provider WHERE public_id=$3::UUID`, generationID.String(), trustHash[:], route.ProviderID().String())
		privateFactoryExec(ctx, t, tx, `INSERT INTO mesh.identity_provider_client
(public_id,deployment_id,identity_provider_id,client_kind,client_id,allowed_flows,allowed_scopes,allowed_algorithms,
redirect_uris,post_logout_redirect_uris,pkce_s256_required,client_auth_method,credential_reference,state)
SELECT $1::UUID,1,id,'confidential',$2,ARRAY['authorization_code'],$3::TEXT[],$4::TEXT[],
ARRAY[$5]::TEXT[],ARRAY['https://console.example.test/logout/complete'],TRUE,'client_secret_basic','secret://fixture/client','active'
FROM mesh.identity_provider WHERE public_id=$6::UUID`, route.ClientID().String(), route.OIDCClientID(), route.Scopes(), route.AllowedAlgorithms(), route.RedirectURI(), route.ProviderID().String())
		privateFactoryExec(ctx, t, tx, `INSERT INTO mesh.workspace_identity_provider
(public_id,deployment_id,workspace_id,identity_provider_id,identity_provider_client_id,admission_mode,minimum_assurance,routing_priority,state)
SELECT $1::UUID,1,w.id,p.id,c.id,'invitation_only','urn:meshtransit:assurance:mfa',10,'active'
FROM mesh.workspace w,mesh.identity_provider p,mesh.identity_provider_client c
WHERE w.public_id=$2::UUID AND p.public_id=$3::UUID AND c.public_id=$4::UUID`,
			bindingID.String(), route.WorkspaceID().String(), route.ProviderID().String(), route.ClientID().String())
	})
}

func (storage *privateFactoryIntegrationStorage) seed(t *testing.T, kind, target string, mutate func(context.Context, pgx.Tx)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	tx, err := storage.admin.Begin(ctx)
	if err != nil {
		t.Fatal("begin audited private fixture seed")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		if err := tx.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error("rollback fixture seed")
		}
	}()
	_, ids, err := (oidcauth.SystemStartIDs{}).NewStartIDs()
	if err != nil {
		t.Fatal("generate fresh fixture audit identities")
	}
	if _, err := tx.Exec(ctx, "SELECT pg_catalog.set_config('mesh.change_public_id',$1,TRUE)", ids.ChangeID().String()); err != nil {
		t.Fatal("bind fixture mutation change")
	}
	mutate(ctx, tx)
	var sequence, appended int64
	var previous []byte
	if err := tx.QueryRow(ctx, `SELECT next_sequence,latest_event_hash FROM mesh_audit.audit_stream WHERE id=1`).Scan(&sequence, &previous); err != nil {
		t.Fatal("read fixture audit head")
	}
	hash := sha256.New()
	_, _ = hash.Write(previous)
	_, _ = hash.Write([]byte(ids.ChangeID().String()))
	_, _ = hash.Write([]byte(ids.AuditEventID().String()))
	if err := tx.QueryRow(ctx, `SELECT mesh_audit.append_authority_evidence(
1,$1::UUID,$2::UUID,$3::BIGINT,$4::BYTEA,$5::BYTEA,$6::TEXT,$7::UUID,1,NULL::BIGINT,NULL::UUID,
$8::TEXT,'system.bootstrap',NULL::UUID,NULL::BYTEA,NULL::BYTEA,'{}'::JSONB,$8::TEXT,'{}'::JSONB)`,
		ids.AuditEventID().String(), ids.OutboxEventID().String(), sequence, previous, hash.Sum(nil), kind, target, kind+".created").Scan(&appended); err != nil || appended != sequence {
		t.Fatal("append exact fixture audit/outbox evidence")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal("commit audited fixture seed")
	}
}

func privateFactoryExec(ctx context.Context, t *testing.T, tx pgx.Tx, query string, arguments ...any) {
	t.Helper()
	result, err := tx.Exec(ctx, query, arguments...)
	if err != nil || result.RowsAffected() != 1 {
		t.Fatal("write exactly one audited fixture row")
	}
}

type privateFactoryIntegrationCensus struct {
	transactions, sessions, accounts, subjects, memberships, roles int64
	networks, revisions, mutations, audit, outbox, principals      int64
}

func (storage *privateFactoryIntegrationStorage) census(t *testing.T) privateFactoryIntegrationCensus {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var counts privateFactoryIntegrationCensus
	err := storage.admin.QueryRow(ctx, `SELECT
(SELECT count(*) FROM mesh.auth_transaction),(SELECT count(*) FROM mesh.account_session),
(SELECT count(*) FROM mesh.account),(SELECT count(*) FROM mesh.identity_subject),
(SELECT count(*) FROM mesh.workspace_membership),(SELECT count(*) FROM mesh.role_binding),
(SELECT count(*) FROM mesh.network),(SELECT COALESCE(sum(network_revision),0) FROM mesh_ops.network_revision),
(SELECT count(*) FROM mesh_audit.authority_mutation),(SELECT count(*) FROM mesh_audit.audit_event),
(SELECT count(*) FROM mesh_ops.outbox_event),(SELECT count(*) FROM mesh.principal)`).Scan(
		&counts.transactions, &counts.sessions, &counts.accounts, &counts.subjects,
		&counts.memberships, &counts.roles, &counts.networks, &counts.revisions,
		&counts.mutations, &counts.audit, &counts.outbox, &counts.principals)
	if err != nil {
		t.Fatal("read bounded unrelated-authority census")
	}
	return counts
}
