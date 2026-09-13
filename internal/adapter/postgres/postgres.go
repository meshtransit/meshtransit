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

	"github.com/jackc/pgx/v5/pgxpool"
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
	role                       PoolRole
	ping                       func(context.Context) error
	checkSchema                func(context.Context) error
	outboxDatabase             outboxDatabase
	registrationReplayDatabase registrationReplayDatabase
	metrics                    *postgresPoolMetrics
	acquired                   func() int32
	close                      func()
	closeMu                    sync.Mutex
	closed                     bool
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
	return &Pool{
		role:                       options.Role,
		ping:                       pool.Ping,
		outboxDatabase:             pgxOutboxDatabase{pool: pool},
		registrationReplayDatabase: pgxRegistrationReplayDatabase{pool: pool},
		checkSchema: func(ctx context.Context) error {
			return checkRuntimeSchemaCompatibility(ctx, pool, options.User)
		},
		metrics: newPostgresPoolMetrics(options.Role, func() postgresPoolStats {
			return snapshotPostgresPoolStats(pool.Stat())
		}),
		acquired: func() int32 { return pool.Stat().AcquiredConns() },
		close:    pool.Close,
	}, nil
}

// Component identifies this dependency to the application monitor.
func (*Pool) Component() app.Component { return app.ComponentPostgreSQL }

// Check verifies a PostgreSQL round trip within the caller's context.
func (pool *Pool) Check(ctx context.Context) error {
	if ctx == nil || pool == nil || pool.ping == nil || pool.checkSchema == nil {
		return ErrInvalidOptions
	}
	startedAt := time.Now()
	err := pool.ping(ctx)
	pool.metrics.observeOperation(postgresOperationPing, time.Since(startedAt), err)
	if err != nil {
		return fmt.Errorf("ping postgres: %w", err)
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
		"host=localhost port=5432 user=placeholder dbname=placeholder sslmode=disable",
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
