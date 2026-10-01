// Package postgres implements the PostgreSQL infrastructure boundary.
package postgres

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	postgresmapsession "github.com/meshtransit/meshtransit/internal/adapter/postgres/mapsession"
	"github.com/meshtransit/meshtransit/internal/adapter/postgres/registrationintake"
	"github.com/meshtransit/meshtransit/internal/app"
	"github.com/meshtransit/meshtransit/internal/config"
)

const (
	maxConnectionLifetime       = 30 * time.Minute
	maxConnectionLifetimeJitter = 5 * time.Minute
	maxConnectionIdleTime       = 5 * time.Minute
	healthCheckPeriod           = 30 * time.Second
)

var (
	// ErrInvalidOptions indicates missing or unsafe PostgreSQL settings.
	ErrInvalidOptions = errors.New("invalid postgres options")
	// ErrOpen indicates that PostgreSQL pool construction failed.
	ErrOpen = errors.New("open postgres pool")
	// ErrPoolInUse indicates that shutdown found an acquired connection. The
	// owner must join every pool consumer before retrying cleanup.
	ErrPoolInUse = errors.New("postgres pool still in use")
)

// Options contains one validated PostgreSQL pool configuration.
type Options struct {
	Role           PoolRole
	Address        string
	Database       string
	User           string
	PasswordFile   config.SecretFile
	CAFile         config.TrustFile
	MaxConnections int32
	ConnectTimeout time.Duration
}

// Pool is the concrete PostgreSQL dependency owned by the composition root.
type Pool struct {
	role                            PoolRole
	ping                            func(context.Context) error
	checkWritable                   func(context.Context) error
	checkSchema                     func(context.Context) error
	outboxDatabase                  outboxDatabase
	registrationReplayDatabase      registrationReplayDatabase
	registrationTransactionDatabase registrationTransactionDatabase
	policyPublicationDatabase       policyPublicationDatabase
	policyApprovalDatabase          policyApprovalDatabase
	resourceAuthorityDatabase       resourceAuthorityDatabase
	deviceRevocationDatabase        deviceRevocationDatabase
	authTransactionDatabase         authTransactionDatabase
	accountSessionDatabase          accountSessionDatabase
	browserIntentDatabase           browserIntentDatabase
	accountSessionLogoutDatabase    accountSessionLogoutDatabase
	mapSessionStore                 func(
		postgresmapsession.Options,
	) (*postgresmapsession.Store, error)
	registrationIntake func(
		registrationintake.Options,
	) (*registrationintake.Transactions, error)
	metrics  *postgresPoolMetrics
	acquired func() int32
	reset    func()
	close    func()
	closeMu  sync.Mutex
	closed   bool
}

// Open constructs a lazy, bounded TLS-only PostgreSQL pool. Connectivity is
// checked synchronously by the application monitor before listeners start.
func Open(ctx context.Context, options Options) (*Pool, error) {
	if ctx == nil || !options.Role.valid() {
		return nil, ErrInvalidOptions
	}
	password, err := options.PasswordFile.Read()
	if err != nil {
		return nil, errors.Join(ErrOpen, err)
	}
	caPEM, err := options.CAFile.Read()
	if err != nil {
		return nil, errors.Join(ErrOpen, err)
	}
	poolConfig, err := buildPoolConfig(options, password, caPEM)
	if err != nil {
		return nil, err
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrOpen, err)
	}
	metrics := newPostgresPoolMetrics(options.Role, func() postgresPoolStats {
		return snapshotPostgresPoolStats(pool.Stat())
	})
	return &Pool{
		role: options.Role,
		ping: pool.Ping,
		checkWritable: func(ctx context.Context) error {
			connection, err := pool.Acquire(ctx)
			if err != nil {
				return err
			}
			defer connection.Release()
			return pgconn.ValidateConnectTargetSessionAttrsReadWrite(
				ctx,
				connection.Conn().PgConn(),
			)
		},
		outboxDatabase:                  pgxOutboxDatabase{pool: pool},
		registrationReplayDatabase:      pgxRegistrationReplayDatabase{pool: pool},
		registrationTransactionDatabase: pgxRegistrationTransactionDatabase{pool: pool},
		policyPublicationDatabase:       pgxPolicyPublicationDatabase{pool: pool},
		policyApprovalDatabase:          pgxPolicyApprovalDatabase{pool: pool},
		resourceAuthorityDatabase:       pgxResourceAuthorityDatabase{pool: pool},
		deviceRevocationDatabase:        pgxDeviceRevocationDatabase{pool: pool},
		authTransactionDatabase:         pgxAuthTransactionDatabase{pool: pool},
		accountSessionDatabase:          pgxAccountSessionDatabase{pool: pool},
		browserIntentDatabase:           pgxBrowserIntentDatabase{pool: pool},
		accountSessionLogoutDatabase:    pgxAccountSessionLogoutDatabase{pool: pool},
		mapSessionStore: func(
			options postgresmapsession.Options,
		) (*postgresmapsession.Store, error) {
			return postgresmapsession.NewStore(pool, options, metrics)
		},
		registrationIntake: func(
			options registrationintake.Options,
		) (*registrationintake.Transactions, error) {
			return registrationintake.NewTransactions(
				pool,
				options,
				metrics,
			)
		},
		checkSchema: func(ctx context.Context) error {
			return checkRuntimeSchemaCompatibility(ctx, pool, options.User)
		},
		metrics:  metrics,
		acquired: func() int32 { return pool.Stat().AcquiredConns() },
		reset:    pool.Reset,
		close:    pool.Close,
	}, nil
}

// Component identifies this dependency to the application monitor.
func (*Pool) Component() app.Component { return app.ComponentPostgreSQL }

// Check verifies a PostgreSQL round trip within the caller's context.
func (pool *Pool) Check(ctx context.Context) error {
	if ctx == nil || pool == nil || pool.ping == nil || pool.checkWritable == nil ||
		pool.checkSchema == nil || pool.reset == nil {
		return ErrInvalidOptions
	}
	startedAt := time.Now()
	err := pool.ping(ctx)
	pool.metrics.observeOperation(postgresOperationPing, time.Since(startedAt), err)
	if err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}
	startedAt = time.Now()
	err = pool.checkWritable(ctx)
	pool.metrics.observeOperation(postgresOperationWritableCheck, time.Since(startedAt), err)
	if err != nil {
		// A demoted primary may keep existing sessions alive while rejecting
		// writes. Retire every pooled session so the next acquisition resolves
		// the stable endpoint and validates the newly promoted primary.
		pool.reset()
		return fmt.Errorf("check postgres writable primary: %w", err)
	}
	startedAt = time.Now()
	err = pool.checkSchema(ctx)
	pool.metrics.observeOperation(postgresOperationSchemaCheck, time.Since(startedAt), err)
	if err != nil {
		return fmt.Errorf("check postgres schema: %w", err)
	}
	return nil
}

// Shutdown releases an idle pool without starting an unbounded cleanup
// goroutine. The application must join every pool consumer before calling it.
func (pool *Pool) Shutdown(ctx context.Context) error {
	if ctx == nil || pool == nil || pool.acquired == nil || pool.close == nil {
		return ErrInvalidOptions
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	pool.closeMu.Lock()
	defer pool.closeMu.Unlock()
	if pool.closed {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if acquired := pool.acquired(); acquired != 0 {
		return fmt.Errorf("%w: %d connection(s) acquired", ErrPoolInUse, acquired)
	}
	pool.close()
	pool.closed = true
	return nil
}

// Close releases the pool once for callers outside the process lifecycle. It
// refuses to wait for acquired connections and is safe to call more than once.
func (pool *Pool) Close() error {
	return pool.Shutdown(context.Background())
}

func buildPoolConfig(options Options, password string, caPEM []byte) (*pgxpool.Config, error) {
	host, portValue, err := net.SplitHostPort(options.Address)
	if err != nil || !options.Role.valid() || host == "" || options.Database == "" || options.User == "" || password == "" ||
		options.MaxConnections <= 0 || options.ConnectTimeout <= 0 {
		return nil, ErrInvalidOptions
	}
	port, err := strconv.ParseUint(portValue, 10, 16)
	if err != nil || port == 0 {
		return nil, ErrInvalidOptions
	}

	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caPEM) {
		return nil, ErrInvalidOptions
	}

	poolConfig, err := pgxpool.ParseConfig(
		"host=localhost port=5432 user=placeholder dbname=placeholder sslmode=disable target_session_attrs=read-write",
	)
	if err != nil {
		return nil, fmt.Errorf("%w: parse safe base config: %w", ErrOpen, err)
	}
	poolConfig.ConnConfig.Host = host
	poolConfig.ConnConfig.Port = uint16(port)
	poolConfig.ConnConfig.Database = options.Database
	poolConfig.ConnConfig.User = options.User
	poolConfig.ConnConfig.Password = password
	poolConfig.ConnConfig.ConnectTimeout = options.ConnectTimeout
	poolConfig.ConnConfig.TLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootCAs,
		ServerName: host,
	}
	poolConfig.ConnConfig.Fallbacks = nil
	poolConfig.ConnConfig.RequireAuth = "scram-sha-256"
	poolConfig.ConnConfig.RuntimeParams["application_name"] = options.Role.applicationName()
	poolConfig.MaxConns = options.MaxConnections
	poolConfig.MinConns = 0
	poolConfig.MinIdleConns = 0
	poolConfig.MaxConnLifetime = maxConnectionLifetime
	poolConfig.MaxConnLifetimeJitter = maxConnectionLifetimeJitter
	poolConfig.MaxConnIdleTime = maxConnectionIdleTime
	poolConfig.HealthCheckPeriod = healthCheckPeriod
	poolConfig.PingTimeout = options.ConnectTimeout
	return poolConfig, nil
}
