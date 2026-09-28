//go:build dexbroker

package dexbroker

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/meshtransit/meshtransit/internal/config"

	dexsql "github.com/dexidp/dex/storage/sql"
)

const (
	minimumPostgreSQLConnections = 1
	maximumPostgreSQLConnections = 50
	minimumPostgreSQLTimeout     = time.Second
	maximumPostgreSQLTimeout     = 30 * time.Second
	minimumConnectionLifetime    = time.Minute
	maximumConnectionLifetime    = 24 * time.Hour
	postgresVerifyFull           = "verify-full"
)

var (
	// ErrInvalidPostgreSQLResource indicates missing or unsafe runtime storage input.
	ErrInvalidPostgreSQLResource = errors.New("invalid dex broker postgres resource")
	// ErrOpenPostgreSQLResource indicates that runtime storage could not open against the prepared schema.
	ErrOpenPostgreSQLResource = errors.New("open dex broker postgres resource")
	// ErrCheckPostgreSQLResource indicates a failed bounded connectivity or schema check.
	ErrCheckPostgreSQLResource = errors.New("check dex broker postgres resource")
	// ErrClosePostgreSQLResource indicates that the owned runtime storage could not close.
	ErrClosePostgreSQLResource = errors.New("close dex broker postgres resource")
)

// PostgreSQLResourceOptions contains one dedicated, DML-only broker runtime
// pool budget. It is intentionally independent from MeshCore runtime/worker
// storage and from the separately operated migration identity.
type PostgreSQLResourceOptions struct {
	Address               string
	Database              string
	User                  string
	PasswordFile          config.SecretFile
	CAFile                config.TrustFile
	MaxOpenConnections    int
	MaxIdleConnections    int
	ConnectTimeout        time.Duration
	MaxConnectionLifetime time.Duration
}

type preparedPostgreSQLOpener func(
	context.Context,
	*dexsql.Postgres,
	*slog.Logger,
) (dexsql.PreparedPostgresStorage, error)

// PostgreSQLResource owns one prepared-schema Dex storage handle. Checks and
// long-lived runtime borrowers are admitted until shutdown begins; shutdown
// waits for every admitted use before closing the handle exactly once.
type PostgreSQLResource struct {
	mu          sync.Mutex
	storage     dexsql.PreparedPostgresStorage
	activeUses  int
	usesDrained chan struct{}
	closing     bool
	closed      bool
	closeResult error
}

// OpenPostgreSQLResource opens a TLS-verified runtime pool without running DDL.
// The exact schema level and first database round trip are checked by the
// qualified Dex compatibility boundary before this function succeeds.
func OpenPostgreSQLResource(
	ctx context.Context,
	options PostgreSQLResourceOptions,
	logger *slog.Logger,
) (*PostgreSQLResource, error) {
	return openPostgreSQLResource(ctx, options, logger, func(
		ctx context.Context,
		postgres *dexsql.Postgres,
		logger *slog.Logger,
	) (dexsql.PreparedPostgresStorage, error) {
		return postgres.OpenWithPreparedSchema(ctx, logger)
	})
}

func openPostgreSQLResource(
	ctx context.Context,
	options PostgreSQLResourceOptions,
	logger *slog.Logger,
	opener preparedPostgreSQLOpener,
) (*PostgreSQLResource, error) {
	if opener == nil {
		return nil, ErrInvalidPostgreSQLResource
	}
	host, port, valid := validatePostgreSQLResourceOptions(ctx, options, logger)
	if !valid {
		return nil, ErrInvalidPostgreSQLResource
	}
	postgres, err := newPostgreSQLStorageConfiguration(options, host, port)
	if err != nil {
		return nil, err
	}

	storage, err := opener(ctx, postgres, logger)
	if err != nil || isNilStorage(storage) {
		if !isNilStorage(storage) {
			_ = storage.Close()
		}
		return nil, ErrOpenPostgreSQLResource
	}
	drained := make(chan struct{})
	close(drained)
	return &PostgreSQLResource{storage: storage, usesDrained: drained}, nil
}

func newPostgreSQLStorageConfiguration(
	options PostgreSQLResourceOptions,
	host string,
	port uint16,
) (*dexsql.Postgres, error) {
	password, err := options.PasswordFile.Read()
	if err != nil {
		return nil, ErrOpenPostgreSQLResource
	}
	caContents, err := options.CAFile.Read()
	clear(caContents)
	if err != nil {
		return nil, ErrOpenPostgreSQLResource
	}
	caPath, err := options.CAFile.PathForDriver()
	if err != nil {
		return nil, ErrOpenPostgreSQLResource
	}
	return &dexsql.Postgres{
		NetworkDB: dexsql.NetworkDB{
			Database:          options.Database,
			User:              options.User,
			Password:          password,
			Host:              host,
			Port:              port,
			ConnectionTimeout: int(options.ConnectTimeout / time.Second),
			MaxOpenConns:      options.MaxOpenConnections,
			MaxIdleConns:      options.MaxIdleConnections,
			ConnMaxLifetime:   int(options.MaxConnectionLifetime / time.Second),
		},
		SSL: dexsql.SSL{Mode: postgresVerifyFull, CAFile: caPath},
	}, nil
}

func validatePostgreSQLResourceOptions(
	ctx context.Context,
	options PostgreSQLResourceOptions,
	logger *slog.Logger,
) (string, uint16, bool) {
	if ctx == nil || ctx.Err() != nil || logger == nil ||
		!validPostgreSQLIdentifier(options.Database) || !validPostgreSQLIdentifier(options.User) ||
		options.MaxOpenConnections < minimumPostgreSQLConnections ||
		options.MaxOpenConnections > maximumPostgreSQLConnections ||
		options.MaxIdleConnections < minimumPostgreSQLConnections ||
		options.MaxIdleConnections > options.MaxOpenConnections ||
		!wholeSecondsInRange(options.ConnectTimeout, minimumPostgreSQLTimeout, maximumPostgreSQLTimeout) ||
		!wholeSecondsInRange(options.MaxConnectionLifetime, minimumConnectionLifetime, maximumConnectionLifetime) {
		return "", 0, false
	}
	host, rawPort, err := net.SplitHostPort(options.Address)
	if err != nil || !validPostgreSQLHost(host) {
		return "", 0, false
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || port == 0 {
		return "", 0, false
	}
	return host, uint16(port), true
}

func validPostgreSQLIdentifier(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character <= ' ' || character == 127 {
			return false
		}
	}
	return true
}

func validPostgreSQLHost(host string) bool {
	if host == "" || strings.TrimSpace(host) != host {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for index, character := range label {
			letter := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
			digit := character >= '0' && character <= '9'
			if !letter && !digit && (character != '-' || index == 0 || index == len(label)-1) {
				return false
			}
		}
	}
	return true
}

func wholeSecondsInRange(value, minimum, maximum time.Duration) bool {
	return value >= minimum && value <= maximum && value%time.Second == 0
}

// Check performs a context-bounded database round trip and exact schema-level
// verification. It never mutates storage or runs migrations.
func (resource *PostgreSQLResource) Check(ctx context.Context) error {
	storage, err := resource.beginUse(ctx)
	if err != nil {
		return err
	}
	defer resource.finishUse()
	if err := storage.CheckPreparedSchema(ctx); err != nil {
		return ErrCheckPostgreSQLResource
	}
	return nil
}

func (resource *PostgreSQLResource) beginUse(ctx context.Context) (dexsql.PreparedPostgresStorage, error) {
	if resource == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrInvalidPostgreSQLResource
	}
	resource.mu.Lock()
	defer resource.mu.Unlock()
	if resource.closing || resource.closed || isNilStorage(resource.storage) {
		return nil, ErrCheckPostgreSQLResource
	}
	if resource.activeUses == 0 {
		resource.usesDrained = make(chan struct{})
	}
	resource.activeUses++
	return resource.storage, nil
}

func (resource *PostgreSQLResource) finishUse() {
	resource.mu.Lock()
	defer resource.mu.Unlock()
	resource.activeUses--
	if resource.activeUses == 0 {
		close(resource.usesDrained)
	}
}

func (resource *PostgreSQLResource) borrowStorage(
	ctx context.Context,
) (dexsql.PreparedPostgresStorage, func(), error) {
	storage, err := resource.beginUse(ctx)
	if err != nil {
		return nil, nil, err
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(resource.finishUse) }
	return storage, release, nil
}

// Shutdown stops new uses, joins admitted checks and runtime borrowers within
// ctx, and closes the owned storage exactly once. A timeout retains the handle
// for a later retry.
func (resource *PostgreSQLResource) Shutdown(ctx context.Context) error {
	if resource == nil || ctx == nil {
		return ErrInvalidPostgreSQLResource
	}
	resource.mu.Lock()
	if resource.closed {
		result := resource.closeResult
		resource.mu.Unlock()
		return result
	}
	if resource.usesDrained == nil || isNilStorage(resource.storage) {
		resource.mu.Unlock()
		return ErrInvalidPostgreSQLResource
	}
	resource.closing = true
	drained := resource.usesDrained
	resource.mu.Unlock()

	select {
	case <-drained:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	resource.mu.Lock()
	defer resource.mu.Unlock()
	if resource.closed {
		return resource.closeResult
	}
	if err := resource.storage.Close(); err != nil {
		resource.closeResult = ErrClosePostgreSQLResource
	}
	resource.storage = nil
	resource.closed = true
	return resource.closeResult
}

// String conceals connection metadata and the storage graph.
func (*PostgreSQLResource) String() string { return "[REDACTED]" }

// GoString conceals connection metadata and the storage graph.
func (*PostgreSQLResource) GoString() string { return "dexbroker.PostgreSQLResource([REDACTED])" }

// LogValue prevents the storage graph from entering structured logs.
func (*PostgreSQLResource) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON refuses accidental publication of the storage graph.
func (*PostgreSQLResource) MarshalJSON() ([]byte, error) { return nil, ErrInvalidPostgreSQLResource }

// String conceals every runtime connection option.
func (PostgreSQLResourceOptions) String() string { return "[REDACTED]" }

// GoString conceals detailed formatting of runtime connection options.
func (PostgreSQLResourceOptions) GoString() string {
	return "dexbroker.PostgreSQLResourceOptions([REDACTED])"
}

// LogValue conceals runtime connection options in structured logs.
func (PostgreSQLResourceOptions) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON refuses accidental publication of runtime connection options.
func (PostgreSQLResourceOptions) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalidPostgreSQLResource
}
