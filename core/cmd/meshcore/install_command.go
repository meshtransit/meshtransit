package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/core/internal/platform/observability"
	"meshtransit.net/core/migrations"
)

// installLogins is every login the database bootstrap may keep, in order:
// the migrator first (it owns the Core database), the serving logins, the
// observer (no password), then the identity broker's.
var installLogins = []string{
	"mesh_migrator", "mesh_runtime", "mesh_control", "mesh_worker", "mesh_all", "mesh_observer",
	"identity_migrator", "identity_runtime",
}

// runInstall runs "meshcore install bootstrap postgres" (V1-11 step 2): as
// the database administrator, create or check the logins, group roles and
// databases Core's migrations need, changing only what differs.
func runInstall(ctx context.Context, args []string, lookup config.LookupFunc, output, errorOutput io.Writer,
	bootstrap func(context.Context, postgresadapter.ServerBootstrapOptions) (postgresadapter.ServerBootstrapReport, error),
) int {
	logger, err := observability.NewLogger(errorOutput, slog.LevelInfo)
	if err != nil {
		return 1
	}
	if len(args) != 2 || args[0] != "bootstrap" || args[1] != "postgres" || bootstrap == nil {
		if _, err := io.WriteString(errorOutput, usage); err != nil {
			return 1
		}
		return 2
	}
	bootstrapConfig, err := config.LoadServerBootstrap(lookup)
	if err != nil {
		logger.ErrorContext(ctx, "install bootstrap failed", "error_code", "invalid_bootstrap_configuration", "error", err)
		return 1
	}
	options, err := serverBootstrapOptions(bootstrapConfig)
	defer func() {
		for _, login := range options.Logins {
			clear(login.Password)
		}
	}()
	if err != nil {
		code := "bootstrap_password_unreadable"
		var unknown errBootstrapUnknownLogin
		if errors.As(err, &unknown) {
			code = "bootstrap_unknown_login"
		}
		logger.ErrorContext(ctx, "install bootstrap failed", "error_code", code, "login", err.Error())
		return 1
	}
	report, err := bootstrap(ctx, options)
	if err != nil {
		logger.ErrorContext(ctx, "install bootstrap failed", "error_code", serverBootstrapErrorCode(err), "error", err)
		return 1
	}
	encoder := json.NewEncoder(output)
	if err := encoder.Encode(struct {
		Operation string `json:"operation"`
		postgresadapter.ServerBootstrapReport
	}{Operation: "install bootstrap postgres", ServerBootstrapReport: report}); err != nil {
		return 1
	}
	return 0
}

// errBootstrapUnknownLogin names a login the bootstrap does not keep.
type errBootstrapUnknownLogin string

func (login errBootstrapUnknownLogin) Error() string { return string(login) }

// errBootstrapPasswordUnreadable names the login whose file did not read.
type errBootstrapPasswordUnreadable string

func (login errBootstrapPasswordUnreadable) Error() string { return string(login) }

func serverBootstrapOptions(bootstrapConfig config.ServerBootstrapConfig) (postgresadapter.ServerBootstrapOptions, error) {
	options := postgresadapter.ServerBootstrapOptions{
		Address: bootstrapConfig.Address, MaintenanceDatabase: bootstrapConfig.MaintenanceDatabase,
		Admin: bootstrapConfig.Admin, AdminPasswordFile: bootstrapConfig.AdminPasswordFile,
		CAFile: bootstrapConfig.CAFile, ConnectTimeout: bootstrapConfig.ConnectTimeout,
		StatementTimeout: bootstrapConfig.StatementTimeout, Marker: bootstrapConfig.Marker,
		CoreDatabase: bootstrapConfig.CoreDatabase, Migrator: "mesh_migrator",
		RotateLogins: bootstrapConfig.RotateLogins,
		Databases:    []postgresadapter.ServerBootstrapDatabase{{Name: bootstrapConfig.CoreDatabase, Owner: "mesh_migrator"}},
	}
	if bootstrapConfig.IdentityDatabase != "" {
		options.Databases = append(options.Databases,
			postgresadapter.ServerBootstrapDatabase{Name: bootstrapConfig.IdentityDatabase, Owner: "identity_migrator"})
	}
	for name := range bootstrapConfig.LoginPasswordFiles {
		if !slices.Contains(installLogins, name) {
			// A typo would otherwise leave the intended login unmanaged.
			return options, errBootstrapUnknownLogin(name)
		}
	}
	catalog := map[string]migrations.OperatorLogin{}
	for _, login := range migrations.OperatorLogins() {
		catalog[login.Name] = login
	}
	for _, name := range installLogins {
		file, configured := bootstrapConfig.LoginPasswordFiles[name]
		if !configured && name != "mesh_observer" {
			continue
		}
		login := postgresadapter.ServerBootstrapLogin{
			Name: name, Database: bootstrapConfig.CoreDatabase, MemberOf: migrations.OperatorRequiredGroups(name),
		}
		if strings.HasPrefix(name, "identity_") {
			login.Database = bootstrapConfig.IdentityDatabase
		}
		if entry, ok := catalog[name]; ok {
			login.NotMemberOf = entry.NotMemberOf
		}
		if configured {
			password, err := file.Read()
			if err != nil {
				return options, errBootstrapPasswordUnreadable(name)
			}
			login.Password = []byte(password)
		}
		options.Logins = append(options.Logins, login)
	}
	return options, nil
}

func serverBootstrapErrorCode(err error) string {
	for _, known := range []struct {
		err  error
		code string
	}{
		{postgresadapter.ErrBootstrapAdmin, "bootstrap_admin_insufficient"},
		{postgresadapter.ErrBootstrapUnsafeRole, "bootstrap_unsafe_role"},
		{postgresadapter.ErrBootstrapLoginPasswordDiffers, "bootstrap_login_password_differs"},
		{postgresadapter.ErrBootstrapDatabaseOwner, "bootstrap_database_owner"},
		{postgresadapter.ErrBootstrapMembership, "bootstrap_membership"},
		{postgresadapter.ErrBootstrapSignIn, "bootstrap_sign_in_refused"},
		{postgresadapter.ErrBootstrapBusy, "bootstrap_busy"},
		{postgresadapter.ErrInvalidServerBootstrap, "invalid_bootstrap_configuration"},
		{postgresadapter.ErrMigrationOpen, "bootstrap_open_failure"},
	} {
		if errors.Is(err, known.err) {
			return known.code
		}
	}
	return "bootstrap_failure"
}
