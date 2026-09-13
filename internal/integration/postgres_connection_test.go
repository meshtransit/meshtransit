//go:build integration

package integration

import (
	"context"
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
	"github.com/meshtransit/meshtransit/internal/config"
)

const integrationCleanupTimeout = 5 * time.Second

func loadIntegrationAdminConfig(t *testing.T) config.MigrationConfig {
	t.Helper()

	adminPasswordFile, ok := os.LookupEnv("MESHTRANSIT_TEST_POSTGRES_ADMIN_PASSWORD_FILE")
	if !ok || adminPasswordFile == "" {
		t.Fatal("MESHTRANSIT_TEST_POSTGRES_ADMIN_PASSWORD_FILE is required")
	}
	adminConfig, err := config.LoadMigration(func(key string) (string, bool) {
		switch key {
		case "MESHTRANSIT_MIGRATION_POSTGRES_USER":
			return "postgres", true
		case "MESHTRANSIT_MIGRATION_POSTGRES_PASSWORD_FILE":
			return adminPasswordFile, true
		default:
			return os.LookupEnv(key)
		}
	})
	if err != nil {
		t.Fatalf("load integration PostgreSQL admin config: %v", err)
	}
	return adminConfig
}

func openIntegrationMigrationRunner(
	ctx context.Context,
	t *testing.T,
	migrationConfig config.MigrationConfig,
) *postgresadapter.MigrationRunner {
	t.Helper()

	runner, err := postgresadapter.OpenMigrationRunner(ctx, postgresadapter.MigrationOptions{
		Address:          migrationConfig.PostgreSQL.Address,
		Database:         migrationConfig.PostgreSQL.Database,
		User:             migrationConfig.PostgreSQL.User,
		PasswordFile:     migrationConfig.PostgreSQL.PasswordFile,
		CAFile:           migrationConfig.PostgreSQL.CAFile,
		ConnectTimeout:   migrationConfig.ConnectTimeout,
		LockTimeout:      migrationConfig.LockTimeout,
		StatementTimeout: migrationConfig.StatementTimeout,
		Actor:            migrationConfig.Actor,
		CodeRelease:      "integration-test@local",
	})
	if err != nil {
		t.Fatalf("postgres.OpenMigrationRunner() error = %v", err)
	}
	t.Cleanup(func() {
		closeContext, cancel := context.WithTimeout(context.Background(), migrationConfig.ConnectTimeout)
		defer cancel()
		if err := runner.Close(closeContext); err != nil {
			t.Errorf("MigrationRunner.Close() error = %v", err)
		}
	})
	return runner
}

func openIntegrationWorkerConnection(
	ctx context.Context,
	t *testing.T,
	adminConfig config.MigrationConfig,
) *pgx.Conn {
	t.Helper()

	workerConfig := loadIntegrationWorkerConfig(t, adminConfig)
	postgresConfig := workerConfig.Storage.PostgreSQL
	if postgresConfig.Worker == nil {
		t.Fatal("worker integration configuration did not load worker PostgreSQL credentials")
	}
	workerRoleConfig := *postgresConfig.Worker
	return openIntegrationPostgreSQLConnection(
		ctx,
		t,
		postgresConfig.Address,
		postgresConfig.Database,
		workerRoleConfig.User,
		workerRoleConfig.PasswordFile,
		postgresConfig.CAFile,
		workerConfig.Dependencies.CheckTimeout,
	)
}

func openIntegrationWorkerPool(
	ctx context.Context,
	t *testing.T,
	adminConfig config.MigrationConfig,
) *postgresadapter.Pool {
	t.Helper()

	workerConfig := loadIntegrationWorkerConfig(t, adminConfig)
	postgresConfig := workerConfig.Storage.PostgreSQL
	if postgresConfig.Worker == nil {
		t.Fatal("worker integration configuration did not load worker PostgreSQL credentials")
	}
	workerRoleConfig := *postgresConfig.Worker
	pool, err := postgresadapter.Open(ctx, postgresadapter.Options{
		Role:           postgresadapter.PoolRoleWorker,
		Address:        postgresConfig.Address,
		Database:       postgresConfig.Database,
		User:           workerRoleConfig.User,
		PasswordFile:   workerRoleConfig.PasswordFile,
		CAFile:         postgresConfig.CAFile,
		MaxConnections: workerRoleConfig.MaxConnections,
		ConnectTimeout: workerConfig.Dependencies.CheckTimeout,
	})
	if err != nil {
		t.Fatalf("postgres.Open() worker pool error = %v", err)
	}
	t.Cleanup(func() {
		if err := pool.Close(); err != nil {
			t.Errorf("worker PostgreSQL pool Close() error = %v", err)
		}
	})
	return pool
}

func loadIntegrationWorkerConfig(
	t *testing.T,
	adminConfig config.MigrationConfig,
) config.Config {
	t.Helper()

	workerPasswordFile, ok := os.LookupEnv("MESHTRANSIT_TEST_POSTGRES_WORKER_PASSWORD_FILE")
	if !ok || workerPasswordFile == "" {
		t.Fatal("MESHTRANSIT_TEST_POSTGRES_WORKER_PASSWORD_FILE is required")
	}
	workerConfig, err := config.Load(func(key string) (string, bool) {
		switch key {
		case "MESHTRANSIT_ROLE":
			return "worker", true
		case "MESHTRANSIT_POSTGRES_ADDRESS":
			return adminConfig.PostgreSQL.Address, true
		case "MESHTRANSIT_POSTGRES_DATABASE":
			return adminConfig.PostgreSQL.Database, true
		case "MESHTRANSIT_POSTGRES_WORKER_USER":
			return "mesh_worker", true
		case "MESHTRANSIT_POSTGRES_WORKER_PASSWORD_FILE":
			return workerPasswordFile, true
		default:
			return os.LookupEnv(key)
		}
	})
	if err != nil {
		t.Fatalf("load integration PostgreSQL worker config: %v", err)
	}
	if workerConfig.Storage == nil {
		t.Fatal("worker integration configuration did not load storage")
	}
	return workerConfig
}

func openIntegrationPostgreSQLConnection(
	ctx context.Context,
	t *testing.T,
	address string,
	database string,
	user string,
	passwordFile config.SecretFile,
	caFile config.TrustFile,
	connectTimeout time.Duration,
) *pgx.Conn {
	t.Helper()

	password, err := passwordFile.Read()
	if err != nil {
		t.Fatalf("read integration PostgreSQL credential: %v", err)
	}
	caPEM, err := caFile.Read()
	if err != nil {
		t.Fatalf("read integration PostgreSQL CA: %v", err)
	}
	host, portValue, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("split integration PostgreSQL address: %v", err)
	}
	port, err := strconv.ParseUint(portValue, 10, 16)
	if err != nil || port == 0 {
		t.Fatalf("parse integration PostgreSQL port %q: %v", portValue, err)
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caPEM) {
		t.Fatal("parse integration PostgreSQL CA bundle")
	}
	connectionConfig, err := pgx.ParseConfig(
		"host=localhost port=5432 user=placeholder dbname=placeholder sslmode=disable",
	)
	if err != nil {
		t.Fatalf("parse integration PostgreSQL base config: %v", err)
	}
	connectionConfig.Host = host
	connectionConfig.Port = uint16(port)
	connectionConfig.Database = database
	connectionConfig.User = user
	connectionConfig.Password = password
	connectionConfig.ConnectTimeout = connectTimeout
	connectionConfig.TLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootCAs,
		ServerName: host,
	}
	connectionConfig.Fallbacks = nil
	connectionConfig.RequireAuth = "scram-sha-256"
	connectionConfig.RuntimeParams["application_name"] = "meshcore-integration"
	connection, err := pgx.ConnectConfig(ctx, connectionConfig)
	if err != nil {
		t.Fatalf("connect integration PostgreSQL role %q: %v", user, err)
	}
	t.Cleanup(func() {
		closeContext, cancel := context.WithTimeout(context.Background(), connectTimeout)
		defer cancel()
		if err := connection.Close(closeContext); err != nil {
			t.Errorf("close integration PostgreSQL role %q: %v", user, err)
		}
	})
	return connection
}

func rollbackIntegrationTransaction(ctx context.Context, t *testing.T, transaction pgx.Tx) {
	t.Helper()

	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), integrationCleanupTimeout)
	defer cancel()
	if err := transaction.Rollback(rollbackCtx); err != nil &&
		!errors.Is(err, pgx.ErrTxClosed) {
		t.Errorf("rollback integration transaction: %v", err)
	}
}
