package postgres

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/platform/config"
)

// The database bootstrap (V1-11 step 2, docs/v1-11-bootstrap-design.md §4):
// the chart's bootstrap Job runs it as the database's administrator before
// any migration, on an empty server or an existing one, self-run or managed.
// Every step reads first and changes only what differs, so a steady-state
// run writes nothing.
//
// A managed service's administrator is not a superuser: it has CREATEROLE
// and CREATEDB and holds ADMIN on the roles it created (PostgreSQL ≥ 16).
// The spike (§12) showed what that needs: never mention SUPERUSER,
// REPLICATION or BYPASSRLS in ALTER ROLE; SET on a role to create a database
// it owns; the rows createrole_self_grant adds removed with GRANTED BY.

// postgresIdentifier is a role or database name the bootstrap writes
// unquoted-safe: lower case, digits and underscores (managed services name
// their administrators doadmin, postgres, ...).
var postgresIdentifier = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

var (
	// ErrInvalidServerBootstrap reports options the bootstrap cannot use.
	ErrInvalidServerBootstrap = errors.New("postgres bootstrap: invalid options")
	// ErrBootstrapAdmin reports an administrator that cannot run it.
	ErrBootstrapAdmin = errors.New("postgres bootstrap: the administrator needs superuser, or CREATEROLE and CREATEDB")
	// ErrBootstrapUnsafeRole reports an existing MeshTransit role with an
	// attribute only a superuser may clear (SUPERUSER, REPLICATION,
	// BYPASSRLS).
	ErrBootstrapUnsafeRole = errors.New("postgres bootstrap: a MeshTransit role has an attribute only a superuser can clear")
	// ErrBootstrapLoginPasswordDiffers reports a login whose password does
	// not match its Secret, not created by this installation: changing it
	// could lock out what uses it (roles belong to the whole server).
	ErrBootstrapLoginPasswordDiffers = errors.New("postgres bootstrap: a login's password differs and the login is not this installation's; set rotateLogins to change it")
	// ErrBootstrapDatabaseOwner reports a database owned by another role.
	ErrBootstrapDatabaseOwner = errors.New("postgres bootstrap: a database has another owner")
	// ErrBootstrapMembership reports a membership the administrator cannot
	// remove or narrow (granted by another role).
	ErrBootstrapMembership = errors.New("postgres bootstrap: a membership granted by another role cannot be removed")
	// ErrBootstrapSignIn reports a sign-in refused before the password was
	// checked (pg_hba.conf has no entry for the login and database): the
	// password can be neither proved nor safely changed.
	ErrBootstrapSignIn = errors.New("postgres bootstrap: the server refused the login before checking its password (pg_hba.conf)")
	// ErrBootstrapBusy reports another bootstrap running on the server.
	ErrBootstrapBusy = errors.New("postgres bootstrap: another bootstrap holds the lock")
)

// bootstrapLockKey is the advisory lock one bootstrap holds, in the
// maintenance database, for its whole run.
const bootstrapLockKey int64 = 0x6d65736862747370 // "meshbtsp"

// bootstrapMarker is what Marker may hold: COMMENT takes no parameters, so
// no quote or backslash.
var bootstrapMarker = regexp.MustCompile(`^[A-Za-z0-9:._-]{1,256}$`)

// installationRole reports a name the administrator must not be: a role
// the bootstrap creates and narrows.
func installationRole(name string) bool {
	return strings.HasPrefix(name, "mesh_") || strings.HasPrefix(name, "identity_")
}

// ServerBootstrapLogin is one login role and what it must be a member of.
type ServerBootstrapLogin struct {
	Name string
	// Database is where the login signs in (its pods' database): the
	// password check signs in there, so per-database pg_hba.conf lines
	// apply as they do for the pods.
	Database string
	// Password is nil for a login that authenticates otherwise
	// (mesh_observer); the caller clears it after the run.
	Password    []byte
	MemberOf    []string
	NotMemberOf []string
}

// ServerBootstrapDatabase is a database and its owner.
type ServerBootstrapDatabase struct {
	Name, Owner string
}

// ServerBootstrapOptions configure one run.
type ServerBootstrapOptions struct {
	Address string
	// MaintenanceDatabase is where the administrator connects ("postgres").
	MaintenanceDatabase string
	Admin               string
	AdminPasswordFile   config.SecretFile
	CAFile              config.TrustFile
	ConnectTimeout      time.Duration
	StatementTimeout    time.Duration
	// Marker is written as the comment of every role the bootstrap
	// creates ("meshtransit:<deployment>"): a later run may change the
	// password of a marked login only.
	Marker    string
	Logins    []ServerBootstrapLogin
	Databases []ServerBootstrapDatabase
	// CoreDatabase and Migrator (one of Logins, the owner of
	// CoreDatabase): the bootstrap connects as it to create btree_gist and
	// give the administrator CONNECT (migrations take it from PUBLIC).
	CoreDatabase string
	Migrator     string
	// RotateLogins lets a run change the password of any listed login.
	RotateLogins bool
}

// ServerBootstrapReport names what a run changed; empty when nothing differed.
type ServerBootstrapReport struct {
	Created          []string `json:"created,omitempty"`
	PasswordsChanged []string `json:"passwords_changed,omitempty"`
	Fixed            []string `json:"fixed,omitempty"`
	Granted          []string `json:"granted,omitempty"`
	Revoked          []string `json:"revoked,omitempty"`
	Databases        []string `json:"databases_created,omitempty"`
}

type serverBootstrapRun struct {
	options   ServerBootstrapOptions
	admin     *pgx.Conn
	superuser bool
	caPEM     []byte
	report    ServerBootstrapReport
}

// BootstrapServer prepares the server for Core's migrations; see the package
// comment above. It returns what it changed.
func BootstrapServer(ctx context.Context, options ServerBootstrapOptions) (ServerBootstrapReport, error) {
	if err := options.validate(); err != nil {
		return ServerBootstrapReport{}, err
	}
	password, err := options.AdminPasswordFile.Read()
	if err != nil {
		return ServerBootstrapReport{}, errors.Join(ErrMigrationOpen, err)
	}
	caPEM, err := options.CAFile.Read()
	if err != nil {
		return ServerBootstrapReport{}, errors.Join(ErrMigrationOpen, err)
	}
	admin, err := options.connect(ctx, options.MaintenanceDatabase, options.Admin, []byte(password), caPEM)
	if err != nil {
		return ServerBootstrapReport{}, err
	}
	defer func() { _ = admin.Close(context.WithoutCancel(ctx)) }()
	run := &serverBootstrapRun{options: options, admin: admin, caPEM: caPEM}
	for _, step := range []func(context.Context) error{
		run.preflight, run.lock, run.silence, run.removeSelfGrants, run.ensureGroups, run.ensureLogins, run.ensureDatabases,
		run.removeSelfGrants, run.prepareCoreDatabase,
	} {
		if err := step(ctx); err != nil {
			return run.report, err
		}
	}
	return run.report, nil
}

func (options ServerBootstrapOptions) validate() error {
	names := []string{options.Admin, options.MaintenanceDatabase, options.CoreDatabase, options.Migrator}
	for _, login := range options.Logins {
		names = append(names, login.Name, login.Database)
		names = append(names, login.MemberOf...)
		names = append(names, login.NotMemberOf...)
		if login.Password != nil && validLoginPassword(login.Password) != nil {
			return fmt.Errorf("%w: login %s password", ErrInvalidServerBootstrap, login.Name)
		}
	}
	for _, database := range options.Databases {
		names = append(names, database.Name, database.Owner)
	}
	for _, name := range names {
		if !postgresIdentifier.MatchString(name) {
			return fmt.Errorf("%w: name %q", ErrInvalidServerBootstrap, name)
		}
	}
	migrator := slices.IndexFunc(options.Logins, func(login ServerBootstrapLogin) bool { return login.Name == options.Migrator })
	core := slices.IndexFunc(options.Databases, func(database ServerBootstrapDatabase) bool {
		return database.Name == options.CoreDatabase
	})
	if migrator < 0 || options.Logins[migrator].Password == nil || core < 0 ||
		options.Databases[core].Owner != options.Migrator || installationRole(options.Admin) ||
		options.Address == "" || options.ConnectTimeout <= 0 || options.StatementTimeout < time.Second ||
		!bootstrapMarker.MatchString(options.Marker) {
		return ErrInvalidServerBootstrap
	}
	return nil
}

func (options ServerBootstrapOptions) connect(ctx context.Context, database, user string, password, caPEM []byte) (*pgx.Conn, error) {
	connectionConfig, err := buildMigrationConnectionConfig(MigrationOptions{
		Address: options.Address, Database: database, User: user,
		ConnectTimeout: options.ConnectTimeout, LockTimeout: options.StatementTimeout / 2,
		StatementTimeout: options.StatementTimeout, Actor: "bootstrap", CodeRelease: "bootstrap",
	}, string(password), caPEM)
	if err != nil {
		return nil, errors.Join(ErrMigrationOpen, ErrInvalidServerBootstrap)
	}
	connectionConfig.RuntimeParams["application_name"] = "meshcore-bootstrap"
	// The bootstrap runs statement by statement, outside a transaction: the
	// limits hold for the session (a GRANT behind an operator's transaction
	// waits no longer than lock_timeout).
	connectionConfig.RuntimeParams["statement_timeout"] = postgresTimeoutValue(options.StatementTimeout)
	connectionConfig.RuntimeParams["lock_timeout"] = postgresTimeoutValue(options.StatementTimeout / 2)
	connectionConfig.RuntimeParams["idle_in_transaction_session_timeout"] = postgresTimeoutValue(options.StatementTimeout)
	connection, err := pgx.ConnectConfig(ctx, connectionConfig)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMigrationOpen, err)
	}
	return connection, nil
}

func (run *serverBootstrapRun) exec(ctx context.Context, statement string) error {
	_, err := run.admin.Exec(ctx, statement)
	return err
}

func (run *serverBootstrapRun) preflight(ctx context.Context) error {
	var version int
	var createRole, createDatabase bool
	if err := run.admin.QueryRow(ctx, `SELECT pg_catalog.current_setting('server_version_num')::integer,
    role.rolsuper, role.rolcreaterole, role.rolcreatedb
FROM pg_catalog.pg_roles AS role WHERE role.rolname = CURRENT_USER`).Scan(
		&version, &run.superuser, &createRole, &createDatabase); err != nil {
		return fmt.Errorf("bootstrap preflight: %w", err)
	}
	if version < minimumPostgreSQLVersion {
		return fmt.Errorf("%w: PostgreSQL %d is older than 18", ErrBootstrapAdmin, version)
	}
	if !run.superuser && (!createRole || !createDatabase) {
		return ErrBootstrapAdmin
	}
	return nil
}

// lock holds the bootstrap's advisory lock for the run (released when the
// connection closes): a second bootstrap fails at once rather than undoing
// the first's temporary grant.
func (run *serverBootstrapRun) lock(ctx context.Context) error {
	var locked bool
	if err := run.admin.QueryRow(ctx, `SELECT pg_catalog.pg_try_advisory_lock($1)`, bootstrapLockKey).Scan(&locked); err != nil {
		return fmt.Errorf("take bootstrap lock: %w", err)
	}
	if !locked {
		return ErrBootstrapBusy
	}
	return nil
}

// silence keeps password verifiers out of the server's logs for the
// session (statements, failing, slow and sampled statements) when the
// administrator may set those settings: a superuser, or one granted SET on
// them. A managed administrator usually may not; the provider's log policy
// then applies (docs/release-1-risk-acceptance.md L1).
func (run *serverBootstrapRun) silence(ctx context.Context) error {
	var allowed bool
	if err := run.admin.QueryRow(ctx, `SELECT pg_catalog.has_parameter_privilege('log_statement', 'SET')
    AND pg_catalog.has_parameter_privilege('log_min_error_statement', 'SET')
    AND pg_catalog.has_parameter_privilege('log_min_duration_statement', 'SET')
    AND pg_catalog.has_parameter_privilege('log_min_duration_sample', 'SET')
    AND pg_catalog.has_parameter_privilege('log_transaction_sample_rate', 'SET')`).Scan(&allowed); err != nil {
		return fmt.Errorf("read log settings privilege: %w", err)
	}
	if !allowed {
		return nil
	}
	for _, statement := range []string{
		"SET log_statement = 'none'", "SET log_min_error_statement = 'panic'", "SET log_min_duration_statement = -1",
		"SET log_min_duration_sample = -1", "SET log_transaction_sample_rate = 0",
	} {
		if err := run.exec(ctx, statement); err != nil {
			return fmt.Errorf("silence logs: %w", err)
		}
	}
	return nil
}

// removeSelfGrants removes the memberships the administrator granted
// itself in MeshTransit roles: the rows createrole_self_grant adds when it
// creates a role, and a temporary SET a stopped run left. The ADMIN-only
// grant PostgreSQL records (grantor the bootstrap superuser) stays: the
// migration preflight allows it, and it is what lets the administrator
// manage the role.
func (run *serverBootstrapRun) removeSelfGrants(ctx context.Context) error {
	if run.superuser {
		return nil
	}
	rows, err := run.admin.Query(ctx, `SELECT granted.rolname
FROM pg_catalog.pg_auth_members AS membership
JOIN pg_catalog.pg_roles AS granted ON granted.oid = membership.roleid
JOIN pg_catalog.pg_roles AS member ON member.oid = membership.member
WHERE member.rolname = CURRENT_USER AND membership.grantor = member.oid AND NOT membership.admin_option
  AND (granted.rolname LIKE 'mesh\_%' OR granted.rolname = ANY($1::text[]))`, run.roleNames())
	if err != nil {
		return fmt.Errorf("read self-grants: %w", err)
	}
	roles, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return fmt.Errorf("read self-grants: %w", err)
	}
	for _, role := range roles {
		statement := "REVOKE " + pgx.Identifier{role}.Sanitize() + " FROM CURRENT_USER GRANTED BY CURRENT_USER"
		if err := run.exec(ctx, statement); err != nil {
			return fmt.Errorf("remove self-grant %s: %w", role, err)
		}
		run.report.Revoked = append(run.report.Revoked, "self:"+role)
	}
	return nil
}

func (run *serverBootstrapRun) roleNames() []string {
	names := []string{}
	for _, login := range run.options.Logins {
		names = append(names, login.Name)
		names = append(names, login.MemberOf...)
	}
	return names
}

type roleState struct {
	exists                                               bool
	superuser, createRole, createDB, replication, bypass bool
	canLogin, inherit                                    bool
	expires                                              bool // VALID UNTIL a finite time
	comment                                              string
	settings                                             []string // databases with settings ("" = every database)
}

func (run *serverBootstrapRun) readRole(ctx context.Context, name string) (roleState, error) {
	state := roleState{}
	err := run.admin.QueryRow(ctx, `SELECT role.rolsuper, role.rolcreaterole, role.rolcreatedb, role.rolreplication,
    role.rolbypassrls, role.rolcanlogin, role.rolinherit,
    role.rolvaliduntil IS NOT NULL AND role.rolvaliduntil <> 'infinity'::timestamptz,
    COALESCE(pg_catalog.shobj_description(role.oid, 'pg_authid'), '')
FROM pg_catalog.pg_roles AS role WHERE role.rolname = $1`, name).Scan(
		&state.superuser, &state.createRole, &state.createDB, &state.replication, &state.bypass,
		&state.canLogin, &state.inherit, &state.expires, &state.comment)
	if errors.Is(err, pgx.ErrNoRows) {
		return state, nil
	}
	if err != nil {
		return state, fmt.Errorf("read role %s: %w", name, err)
	}
	state.exists = true
	rows, err := run.admin.Query(ctx, `SELECT COALESCE(database.datname, '')
FROM pg_catalog.pg_db_role_setting AS setting
JOIN pg_catalog.pg_roles AS role ON role.oid = setting.setrole
LEFT JOIN pg_catalog.pg_database AS database ON database.oid = setting.setdatabase
WHERE role.rolname = $1`, name)
	if err != nil {
		return state, fmt.Errorf("read role %s settings: %w", name, err)
	}
	state.settings, err = pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return state, fmt.Errorf("read role %s settings: %w", name, err)
	}
	return state, nil
}

func (run *serverBootstrapRun) ensureGroups(ctx context.Context) error {
	seen := map[string]bool{}
	for _, login := range run.options.Logins {
		for _, group := range login.MemberOf {
			if seen[group] {
				continue
			}
			seen[group] = true
			state, err := run.readRole(ctx, group)
			if err != nil {
				return err
			}
			if err := run.ensureRole(ctx, group, state, false, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

// ensureRole creates name (LOGIN when login, with password's verifier when
// given) or makes an existing one's attributes and settings what Core
// needs. It never mentions SUPERUSER, REPLICATION or BYPASSRLS to change a
// role: only a superuser may, and a role created here never has them.
func (run *serverBootstrapRun) ensureRole(ctx context.Context, name string, state roleState, login bool, password []byte) error {
	identifier := pgx.Identifier{name}.Sanitize()
	loginAttribute := "NOLOGIN"
	if login {
		loginAttribute = "LOGIN"
	}
	if !state.exists {
		statement := "CREATE ROLE " + identifier + " " + loginAttribute +
			" INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
		if password != nil {
			verifier, err := scramVerifier(password, rand.Reader)
			if err != nil {
				return err
			}
			if !scramVerifierPattern.MatchString(verifier) {
				return errors.New("scram verifier has an unexpected form")
			}
			statement += " PASSWORD '" + verifier + "'"
		}
		if err := run.exec(ctx, statement); err != nil {
			return fmt.Errorf("create role %s: %w", name, err)
		}
		if err := run.mark(ctx, name); err != nil {
			return err
		}
		run.report.Created = append(run.report.Created, name)
		return nil
	}
	if state.superuser || state.replication || state.bypass {
		if !run.superuser {
			return fmt.Errorf("%w: %s", ErrBootstrapUnsafeRole, name)
		}
		if err := run.exec(ctx, "ALTER ROLE "+identifier+" NOSUPERUSER NOREPLICATION NOBYPASSRLS"); err != nil {
			return fmt.Errorf("fix role %s: %w", name, err)
		}
		run.report.Fixed = append(run.report.Fixed, name+":superuser")
	}
	if state.createRole || state.createDB || state.canLogin != login || !state.inherit || state.expires {
		// An expired VALID UNTIL refuses the right password like a wrong one.
		if err := run.exec(ctx, "ALTER ROLE "+identifier+" "+loginAttribute+
			" INHERIT NOCREATEDB NOCREATEROLE VALID UNTIL 'infinity'"); err != nil {
			return fmt.Errorf("fix role %s: %w", name, err)
		}
		run.report.Fixed = append(run.report.Fixed, name+":attributes")
	}
	for _, database := range state.settings {
		statement := "ALTER ROLE " + identifier + " RESET ALL"
		if database != "" {
			statement = "ALTER ROLE " + identifier + " IN DATABASE " + pgx.Identifier{database}.Sanitize() + " RESET ALL"
		}
		if err := run.exec(ctx, statement); err != nil {
			return fmt.Errorf("reset role %s settings: %w", name, err)
		}
		run.report.Fixed = append(run.report.Fixed, name+":settings")
	}
	return nil
}

func (run *serverBootstrapRun) mark(ctx context.Context, name string) error {
	// validate checked the marker holds no quote; COMMENT takes no parameters.
	marker := run.options.Marker
	if !bootstrapMarker.MatchString(marker) {
		return ErrInvalidServerBootstrap
	}
	if err := run.exec(ctx, "COMMENT ON ROLE "+pgx.Identifier{name}.Sanitize()+" IS '"+marker+"'"); err != nil {
		return fmt.Errorf("mark role %s: %w", name, err)
	}
	return nil
}

func (run *serverBootstrapRun) ensureLogins(ctx context.Context) error {
	for _, login := range run.options.Logins {
		state, err := run.readRole(ctx, login.Name)
		if err != nil {
			return err
		}
		if err := run.ensureRole(ctx, login.Name, state, true, login.Password); err != nil {
			return err
		}
		if state.exists && login.Password != nil {
			if err := run.ensurePassword(ctx, login, state); err != nil {
				return err
			}
		}
		if err := run.ensureMemberships(ctx, login); err != nil {
			return err
		}
	}
	return nil
}

// ensurePassword authenticates as the login with its Secret's password and
// changes nothing when that works. Otherwise it sets the password only for
// a login this installation created (its marker) or with RotateLogins.
func (run *serverBootstrapRun) ensurePassword(ctx context.Context, login ServerBootstrapLogin, state roleState) error {
	matches, err := run.authenticates(ctx, login)
	if err != nil {
		return err
	}
	if matches {
		if state.comment == "" {
			// A login made before the bootstrap (by hand) that already
			// matches becomes this installation's.
			return run.mark(ctx, login.Name)
		}
		return nil
	}
	if state.comment != run.options.Marker && !run.options.RotateLogins {
		return fmt.Errorf("%w: %s", ErrBootstrapLoginPasswordDiffers, login.Name)
	}
	verifier, err := scramVerifier(login.Password, rand.Reader)
	if err != nil {
		return err
	}
	if !scramVerifierPattern.MatchString(verifier) {
		return errors.New("scram verifier has an unexpected form")
	}
	if err := run.exec(ctx, "ALTER ROLE "+pgx.Identifier{login.Name}.Sanitize()+" PASSWORD '"+verifier+"'"); err != nil {
		return fmt.Errorf("set login %s password: %w", login.Name, err)
	}
	run.report.PasswordsChanged = append(run.report.PasswordsChanged, login.Name)
	return run.mark(ctx, login.Name)
}

// authenticates reports whether the login signs in with its password, to
// its own database. A refusal after authentication (no CONNECT, or no such
// database yet) still proves the password.
func (run *serverBootstrapRun) authenticates(ctx context.Context, login ServerBootstrapLogin) (bool, error) {
	connection, err := run.options.connect(ctx, login.Database, login.Name, login.Password, run.caPEM)
	if err == nil {
		_ = connection.Close(context.WithoutCancel(ctx))
		return true, nil
	}
	switch authenticationOutcome(err) {
	case authenticationRefused:
		return false, nil
	case authenticationPassed:
		return true, nil
	case authenticationNotChecked:
		return false, fmt.Errorf("%w: %s to %s", ErrBootstrapSignIn, login.Name, login.Database)
	default:
		return false, fmt.Errorf("sign in as %s: %w", login.Name, err)
	}
}

type authenticationResult int

const (
	authenticationUnknown authenticationResult = iota
	authenticationRefused
	authenticationPassed
	authenticationNotChecked
)

// authenticationOutcome reads a failed connection: 28P01 is a wrong
// password (or an expired one, which ensureRole clears first); 28000 comes
// before the password is checked (no pg_hba.conf entry, or NOLOGIN); 42501
// (no CONNECT) and 3D000 (no such database) come only after authentication.
func authenticationOutcome(err error) authenticationResult {
	var server *pgconn.PgError
	if !errors.As(err, &server) {
		return authenticationUnknown
	}
	switch server.Code {
	case "28P01":
		return authenticationRefused
	case "28000":
		return authenticationNotChecked
	case "42501", "3D000":
		return authenticationPassed
	default:
		return authenticationUnknown
	}
}

// ensureMemberships grants each MemberOf role with INHERIT and without SET
// or ADMIN, and removes each NotMemberOf membership.
func (run *serverBootstrapRun) ensureMemberships(ctx context.Context, login ServerBootstrapLogin) error {
	identifier := pgx.Identifier{login.Name}.Sanitize()
	for _, group := range login.MemberOf {
		var exists, inherit, set, admin bool
		err := run.admin.QueryRow(ctx, `SELECT true, bool_or(membership.inherit_option), bool_or(membership.set_option),
    bool_or(membership.admin_option)
FROM pg_catalog.pg_auth_members AS membership
JOIN pg_catalog.pg_roles AS granted ON granted.oid = membership.roleid
JOIN pg_catalog.pg_roles AS member ON member.oid = membership.member
WHERE granted.rolname = $1 AND member.rolname = $2
HAVING count(*) > 0`, group, login.Name).Scan(&exists, &inherit, &set, &admin)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("read membership %s in %s: %w", login.Name, group, err)
		}
		if exists && inherit && !set && !admin {
			continue
		}
		if err := run.narrowMembership(ctx, login.Name, group); err != nil {
			return err
		}
		run.report.Granted = append(run.report.Granted, login.Name+"<"+group)
	}
	for _, role := range login.NotMemberOf {
		var member bool
		if err := run.admin.QueryRow(ctx, `SELECT pg_catalog.pg_has_role($1, $2, 'MEMBER')`,
			login.Name, role).Scan(&member); err != nil {
			return fmt.Errorf("read membership %s in %s: %w", login.Name, role, err)
		}
		if !member {
			continue
		}
		if err := run.exec(ctx, "REVOKE "+pgx.Identifier{role}.Sanitize()+" FROM "+identifier); err != nil {
			return fmt.Errorf("revoke %s from %s: %w", role, login.Name, err)
		}
		if err := run.admin.QueryRow(ctx, `SELECT pg_catalog.pg_has_role($1, $2, 'MEMBER')`,
			login.Name, role).Scan(&member); err != nil {
			return fmt.Errorf("read membership %s in %s: %w", login.Name, role, err)
		}
		if member {
			return fmt.Errorf("%w: %s in %s", ErrBootstrapMembership, login.Name, role)
		}
		run.report.Revoked = append(run.report.Revoked, login.Name+"<"+role)
	}
	return nil
}

// narrowMembership makes login a member of group with INHERIT and without
// SET or ADMIN. GRANT and REVOKE ... OPTION change only the administrator's
// own row: a row another grantor left with SET or ADMIN is narrowed with
// GRANTED BY that grantor (a superuser may), else the run fails rather than
// report a repair that did not happen.
func (run *serverBootstrapRun) narrowMembership(ctx context.Context, login, group string) error {
	identifier, granted := pgx.Identifier{login}.Sanitize(), pgx.Identifier{group}.Sanitize()
	for _, statement := range []string{
		"GRANT " + granted + " TO " + identifier + " WITH INHERIT TRUE, SET FALSE",
		"REVOKE ADMIN OPTION FOR " + granted + " FROM " + identifier,
	} {
		if err := run.exec(ctx, statement); err != nil {
			return fmt.Errorf("grant %s to %s: %w", group, login, err)
		}
	}
	rows, err := run.admin.Query(ctx, `SELECT grantor.rolname, membership.set_option, membership.admin_option
FROM pg_catalog.pg_auth_members AS membership
JOIN pg_catalog.pg_roles AS granted ON granted.oid = membership.roleid
JOIN pg_catalog.pg_roles AS member ON member.oid = membership.member
JOIN pg_catalog.pg_roles AS grantor ON grantor.oid = membership.grantor
WHERE granted.rolname = $1 AND member.rolname = $2 AND (membership.set_option OR membership.admin_option)`, group, login)
	if err != nil {
		return fmt.Errorf("read membership %s in %s: %w", login, group, err)
	}
	type wideRow struct {
		grantor    string
		set, admin bool
	}
	wide, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (wideRow, error) {
		var value wideRow
		return value, row.Scan(&value.grantor, &value.set, &value.admin)
	})
	if err != nil {
		return fmt.Errorf("read membership %s in %s: %w", login, group, err)
	}
	for _, row := range wide {
		if !run.superuser || !postgresIdentifier.MatchString(row.grantor) {
			return fmt.Errorf("%w: %s in %s, granted by %s", ErrBootstrapMembership, login, group, row.grantor)
		}
		by := " GRANTED BY " + pgx.Identifier{row.grantor}.Sanitize()
		for option, held := range map[string]bool{"SET": row.set, "ADMIN": row.admin} {
			if !held {
				continue
			}
			if err := run.exec(ctx, "REVOKE "+option+" OPTION FOR "+granted+" FROM "+identifier+by); err != nil {
				return fmt.Errorf("narrow %s in %s: %w", login, group, err)
			}
		}
	}
	return nil
}

// ensureDatabases creates each missing database owned by its role. A
// non-superuser needs SET on the owner for that: it grants itself SET for
// the one statement (CREATE DATABASE cannot run in a transaction) and
// removes the grant at once; removeSelfGrants clears one a stopped run left.
func (run *serverBootstrapRun) ensureDatabases(ctx context.Context) error {
	for _, database := range run.options.Databases {
		var owner string
		err := run.admin.QueryRow(ctx, `SELECT pg_catalog.pg_get_userbyid(datdba)::text
FROM pg_catalog.pg_database WHERE datname = $1`, database.Name).Scan(&owner)
		if err == nil {
			if owner != database.Owner {
				return fmt.Errorf("%w: %s is owned by %s", ErrBootstrapDatabaseOwner, database.Name, owner)
			}
			continue
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("read database %s: %w", database.Name, err)
		}
		ownerIdentifier := pgx.Identifier{database.Owner}.Sanitize()
		if !run.superuser {
			if err := run.exec(ctx, "GRANT "+ownerIdentifier+" TO CURRENT_USER WITH SET TRUE, INHERIT FALSE"); err != nil {
				return fmt.Errorf("take SET on %s: %w", database.Owner, err)
			}
		}
		createErr := run.exec(ctx, "CREATE DATABASE "+pgx.Identifier{database.Name}.Sanitize()+" OWNER "+ownerIdentifier)
		if !run.superuser {
			if err := run.exec(ctx, "REVOKE "+ownerIdentifier+" FROM CURRENT_USER GRANTED BY CURRENT_USER"); err != nil {
				return errors.Join(createErr, fmt.Errorf("drop SET on %s: %w", database.Owner, err))
			}
		}
		if createErr != nil {
			return fmt.Errorf("create database %s: %w", database.Name, createErr)
		}
		run.report.Databases = append(run.report.Databases, database.Name)
	}
	return nil
}

// prepareCoreDatabase connects as the migrator (the Core database's owner):
// btree_gist, which the migration preflight requires and no migration
// creates, is a trusted extension its owner may create; and the
// administrator gets CONNECT, which the migrations take from PUBLIC, so the
// operator command can run as it.
func (run *serverBootstrapRun) prepareCoreDatabase(ctx context.Context) error {
	index := slices.IndexFunc(run.options.Logins, func(login ServerBootstrapLogin) bool { return login.Name == run.options.Migrator })
	migrator, err := run.options.connect(ctx, run.options.CoreDatabase, run.options.Migrator,
		run.options.Logins[index].Password, run.caPEM)
	if err != nil {
		return fmt.Errorf("connect as %s: %w", run.options.Migrator, err)
	}
	defer func() { _ = migrator.Close(context.WithoutCancel(ctx)) }()
	var extension bool
	if err := migrator.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_extension WHERE extname = 'btree_gist')`).
		Scan(&extension); err != nil {
		return fmt.Errorf("read btree_gist: %w", err)
	}
	if !extension {
		if _, err := migrator.Exec(ctx, "CREATE EXTENSION IF NOT EXISTS btree_gist WITH SCHEMA public"); err != nil {
			return fmt.Errorf("create btree_gist: %w", err)
		}
		run.report.Created = append(run.report.Created, "extension:btree_gist")
	}
	if run.superuser {
		return nil
	}
	// A grant of its own, not CONNECT through PUBLIC: the first migration
	// takes PUBLIC's away.
	var connect bool
	if err := migrator.QueryRow(ctx, `SELECT EXISTS (
    SELECT 1 FROM pg_catalog.pg_database AS database,
        pg_catalog.aclexplode(COALESCE(database.datacl, pg_catalog.acldefault('d', database.datdba))) AS acl
    WHERE database.datname = pg_catalog.current_database() AND acl.privilege_type = 'CONNECT'
      AND acl.grantee = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1))`,
		run.options.Admin).Scan(&connect); err != nil {
		return fmt.Errorf("read CONNECT: %w", err)
	}
	if connect {
		return nil
	}
	statement := "GRANT CONNECT ON DATABASE " + pgx.Identifier{run.options.CoreDatabase}.Sanitize() +
		" TO " + pgx.Identifier{run.options.Admin}.Sanitize()
	if _, err := migrator.Exec(ctx, statement); err != nil {
		return fmt.Errorf("grant CONNECT to %s: %w", run.options.Admin, err)
	}
	run.report.Granted = append(run.report.Granted, run.options.Admin+":connect")
	return nil
}
