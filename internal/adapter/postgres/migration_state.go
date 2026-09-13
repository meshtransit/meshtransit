package postgres

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/migrations"
)

const (
	minimumPostgreSQLVersion  = 160000
	maxMigrationMetadataBytes = 128
)

var (
	// ErrInvalidMigrationOptions indicates missing or unsafe one-shot migration
	// connection or execution settings.
	ErrInvalidMigrationOptions = errors.New("invalid postgres migration options")
	// ErrMigrationPreflight indicates that the database or migration identity
	// does not satisfy the supported migration envelope.
	ErrMigrationPreflight = errors.New("postgres migration preflight failed")
	// ErrMigrationState indicates unknown, drifted, dirty, or incompatible
	// durable migration state.
	ErrMigrationState = errors.New("invalid postgres migration state")
)

// MigrationOptions contains one direct, TLS-only migration connection and its
// bounded operation metadata.
type MigrationOptions struct {
	Address          string
	Database         string
	User             string
	PasswordFile     config.SecretFile
	CAFile           config.TrustFile
	ConnectTimeout   time.Duration
	LockTimeout      time.Duration
	StatementTimeout time.Duration
	Actor            string
	CodeRelease      string
}

// MigrationState is a stable operator-facing schema state.
type MigrationState string

const (
	// MigrationStateUninitialized means no MeshTransit migration catalog exists.
	MigrationStateUninitialized MigrationState = "uninitialized"
	// MigrationStatePending means known forward migrations have not been applied.
	MigrationStatePending MigrationState = "pending"
	// MigrationStateClean means every migration known to this binary is applied.
	MigrationStateClean MigrationState = "clean"
)

// MigrationStatus is a bounded, non-sensitive view of schema compatibility.
type MigrationStatus struct {
	CurrentVersion int64
	LatestVersion  int64
	State          MigrationState
}

type migrationPreflight struct {
	serverVersion       int
	extensionVersion    string
	currentUser         string
	superuser           bool
	createDatabase      bool
	createRole          bool
	replication         bool
	bypassRLS           bool
	databaseOwner       bool
	supportRolesSafe    bool
	roleMembershipsSafe bool
}

type appliedMigration struct {
	version  int64
	checksum string
	result   string
}

type schemaCompatibility struct {
	currentVersion          int64
	minimumReaderGeneration int64
	maximumReaderGeneration int64
	minimumWriterGeneration int64
	maximumWriterGeneration int64
	state                   string
}

type migrationDatabaseState struct {
	initialized   bool
	applied       []appliedMigration
	compatibility schemaCompatibility
}

func buildMigrationConnectionConfig(
	options MigrationOptions,
	password string,
	caPEM []byte,
) (*pgx.ConnConfig, error) {
	host, portValue, err := net.SplitHostPort(options.Address)
	if err != nil || host == "" || options.Database == "" || options.User == "" || password == "" ||
		options.ConnectTimeout <= 0 || options.LockTimeout <= 0 || options.StatementTimeout <= 0 ||
		options.LockTimeout >= options.StatementTimeout || !validMigrationMetadata(options.Actor) ||
		!validMigrationMetadata(options.CodeRelease) {
		return nil, ErrInvalidMigrationOptions
	}
	port, err := strconv.ParseUint(portValue, 10, 16)
	if err != nil || port == 0 {
		return nil, ErrInvalidMigrationOptions
	}

	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caPEM) {
		return nil, ErrInvalidMigrationOptions
	}
	connectionConfig, err := pgx.ParseConfig(
		"host=localhost port=5432 user=placeholder dbname=placeholder sslmode=disable",
	)
	if err != nil {
		return nil, errors.Join(ErrInvalidMigrationOptions, err)
	}
	connectionConfig.Host = host
	connectionConfig.Port = uint16(port)
	connectionConfig.Database = options.Database
	connectionConfig.User = options.User
	connectionConfig.Password = password
	connectionConfig.ConnectTimeout = options.ConnectTimeout
	connectionConfig.TLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootCAs,
		ServerName: host,
	}
	connectionConfig.Fallbacks = nil
	connectionConfig.RequireAuth = "scram-sha-256"
	connectionConfig.RuntimeParams["application_name"] = "meshcore-migrator"
	return connectionConfig, nil
}

func validateMigrationPreflight(expectedUser string, preflight migrationPreflight) error {
	if preflight.serverVersion < minimumPostgreSQLVersion || preflight.currentUser != expectedUser {
		return ErrMigrationPreflight
	}
	if !supportedBtreeGistVersion(preflight.extensionVersion) {
		return ErrMigrationPreflight
	}
	if preflight.superuser || preflight.createDatabase || preflight.createRole ||
		preflight.replication || preflight.bypassRLS || !preflight.databaseOwner ||
		!preflight.supportRolesSafe ||
		!preflight.roleMembershipsSafe {
		return ErrMigrationPreflight
	}
	return nil
}

func supportedBtreeGistVersion(version string) bool {
	switch version {
	case "1.7", "1.8":
		return true
	default:
		return false
	}
}

func migrationSupportRoles() []string {
	return []string{
		"mesh_runtime",
		"mesh_worker",
		"mesh_audit_writer",
		"mesh_share_writer",
		"mesh_observer",
	}
}

func validateMigrationState(
	catalog []migrations.Migration,
	applicationGeneration int64,
	state migrationDatabaseState,
) (MigrationStatus, error) {
	if !validMigrationCatalog(catalog) || applicationGeneration <= 0 {
		return MigrationStatus{}, ErrMigrationState
	}
	latestVersion := catalog[len(catalog)-1].Version
	if !state.initialized {
		if len(state.applied) != 0 || state.compatibility.currentVersion != 0 {
			return MigrationStatus{}, ErrMigrationState
		}
		return MigrationStatus{
			CurrentVersion: 0,
			LatestVersion:  latestVersion,
			State:          MigrationStateUninitialized,
		}, nil
	}

	compatibility := state.compatibility
	if compatibility.state != "clean" || compatibility.currentVersion < 1 ||
		compatibility.currentVersion > latestVersion ||
		!withinGeneration(
			applicationGeneration,
			compatibility.minimumReaderGeneration,
			compatibility.maximumReaderGeneration,
		) ||
		!withinGeneration(
			applicationGeneration,
			compatibility.minimumWriterGeneration,
			compatibility.maximumWriterGeneration,
		) ||
		int64(len(state.applied)) != compatibility.currentVersion {
		return MigrationStatus{}, ErrMigrationState
	}
	for index, applied := range state.applied {
		expected := catalog[index]
		if applied.version != expected.Version || applied.checksum != expected.Checksum || applied.result != "succeeded" {
			return MigrationStatus{}, ErrMigrationState
		}
	}

	migrationState := MigrationStateClean
	if compatibility.currentVersion < latestVersion {
		migrationState = MigrationStatePending
	}
	return MigrationStatus{
		CurrentVersion: compatibility.currentVersion,
		LatestVersion:  latestVersion,
		State:          migrationState,
	}, nil
}

func validMigrationCatalog(catalog []migrations.Migration) bool {
	if len(catalog) == 0 {
		return false
	}
	for index, migration := range catalog {
		if migration.Version != int64(index+1) || migration.Checksum == "" || migration.Description == "" ||
			migration.SQL == "" ||
			!withinGeneration(
				migration.MinimumReaderGeneration,
				migration.MinimumReaderGeneration,
				migration.MaximumReaderGeneration,
			) ||
			!withinGeneration(
				migration.MinimumWriterGeneration,
				migration.MinimumWriterGeneration,
				migration.MaximumWriterGeneration,
			) {
			return false
		}
	}
	return true
}

func withinGeneration(generation, minimum, maximum int64) bool {
	return minimum > 0 && maximum >= minimum && generation >= minimum && generation <= maximum
}

func validMigrationMetadata(value string) bool {
	if value == "" || len(value) > maxMigrationMetadataBytes || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < '!' || character > '~' {
			return false
		}
	}
	return true
}
