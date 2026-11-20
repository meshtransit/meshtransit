package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"

	"meshtransit.net/core/internal/adapter/kubeapi"
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

// installDependencies are what "meshcore install" reaches outside the
// process; tests replace them.
type installDependencies struct {
	bootstrap      func(context.Context, postgresadapter.ServerBootstrapOptions) (postgresadapter.ServerBootstrapReport, error)
	databaseExists func(context.Context, postgresadapter.ServerBootstrapOptions, string) (bool, error)
	secretStore    func() (installSecretStore, error)
	readPlan       func(path string) ([]byte, error)
	pods           func() (rolloutLister, error)
	random         io.Reader
}

func productionInstallDependencies() installDependencies {
	return installDependencies{
		bootstrap:      postgresadapter.BootstrapServer,
		databaseExists: postgresadapter.ServerCoreSchemaExists,
		secretStore: func() (installSecretStore, error) {
			kubeConfig, err := kubeapi.InCluster()
			if err != nil {
				return nil, err
			}
			return kubeapi.New(kubeConfig)
		},
		readPlan: readInstallPlan,
		pods: func() (rolloutLister, error) {
			kubeConfig, err := kubeapi.InCluster()
			if err != nil {
				return nil, err
			}
			return kubeapi.New(kubeConfig)
		},
		random: rand.Reader,
	}
}

// runInstall runs "meshcore install bootstrap postgres|kubernetes" (V1-11
// step 2) and "meshcore install wait-rollout" (step 3, see
// runInstallWaitRollout). postgres: as the database administrator, create or check the
// logins, group roles and databases Core's migrations need, changing only
// what differs, with the logins' passwords from files. kubernetes: first
// create or check the plan's Secrets (and publish their public halves),
// then the same database step with the passwords from those Secrets.
func runInstall(ctx context.Context, args []string, lookup config.LookupFunc, output, errorOutput io.Writer,
	dependencies installDependencies,
) int {
	logger, err := observability.NewLogger(errorOutput, slog.LevelInfo)
	if err != nil {
		return 1
	}
	switch strings.Join(args, " ") {
	case "wait-rollout":
		if dependencies.pods != nil {
			return runInstallWaitRollout(ctx, lookup, output, errorOutput, dependencies.pods, rolloutPoll)
		}
	case "bootstrap postgres":
		if dependencies.bootstrap != nil {
			return runInstallPostgres(ctx, lookup, output, logger, dependencies)
		}
	case "bootstrap kubernetes":
		if dependencies.bootstrap != nil {
			return runInstallKubernetes(ctx, lookup, output, logger, dependencies)
		}
	}
	return writeInstallUsage(errorOutput)
}

func writeInstallUsage(errorOutput io.Writer) int {
	if _, err := io.WriteString(errorOutput, usage); err != nil {
		return 1
	}
	return 2
}

func runInstallPostgres(ctx context.Context, lookup config.LookupFunc, output io.Writer, logger *slog.Logger,
	dependencies installDependencies,
) int {
	bootstrapConfig, err := config.LoadServerBootstrap(lookup)
	if err != nil {
		logger.ErrorContext(ctx, "install bootstrap failed", "error_code", "invalid_bootstrap_configuration", "error", err)
		return 1
	}
	passwords := map[string][]byte{}
	defer clearPasswords(passwords)
	for name, file := range bootstrapConfig.LoginPasswordFiles {
		password, err := file.Read()
		if err != nil {
			logger.ErrorContext(ctx, "install bootstrap failed", "error_code", "bootstrap_password_unreadable", "login", name)
			return 1
		}
		passwords[name] = []byte(password)
	}
	options, err := serverBootstrapOptions(bootstrapConfig, passwords)
	if err != nil {
		logger.ErrorContext(ctx, "install bootstrap failed", "error_code", "bootstrap_unknown_login", "login", err.Error())
		return 1
	}
	report, err := dependencies.bootstrap(ctx, options)
	if err != nil {
		logger.ErrorContext(ctx, "install bootstrap failed", "error_code", serverBootstrapErrorCode(err), "error", err)
		return 1
	}
	return writeInstallReport(output, struct {
		Operation string `json:"operation"`
		postgresadapter.ServerBootstrapReport
	}{Operation: "install bootstrap postgres", ServerBootstrapReport: report})
}

func writeInstallReport(output io.Writer, report any) int {
	if err := json.NewEncoder(output).Encode(report); err != nil {
		return 1
	}
	return 0
}

func clearPasswords(passwords map[string][]byte) {
	for _, password := range passwords {
		clear(password)
	}
}

// errBootstrapUnknownLogin names a login the bootstrap does not keep.
type errBootstrapUnknownLogin string

func (login errBootstrapUnknownLogin) Error() string { return string(login) }

// serverBootstrapOptions builds the database step's options; passwords maps
// a login to its password (the caller clears them after the run).
func serverBootstrapOptions(bootstrapConfig config.ServerBootstrapConfig, passwords map[string][]byte,
) (postgresadapter.ServerBootstrapOptions, error) {
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
	for name := range passwords {
		if !slices.Contains(installLogins, name) || name == "mesh_observer" {
			// A typo would otherwise leave the intended login unmanaged.
			return options, errBootstrapUnknownLogin(name)
		}
	}
	catalog := map[string]migrations.OperatorLogin{}
	for _, login := range migrations.OperatorLogins() {
		catalog[login.Name] = login
	}
	for _, name := range installLogins {
		password, configured := passwords[name]
		if !configured && name != "mesh_observer" {
			continue
		}
		login := postgresadapter.ServerBootstrapLogin{
			Name: name, Database: bootstrapConfig.CoreDatabase, MemberOf: migrations.OperatorRequiredGroups(name),
			Password: password,
		}
		if strings.HasPrefix(name, "identity_") {
			login.Database = bootstrapConfig.IdentityDatabase
		}
		if entry, ok := catalog[name]; ok {
			login.NotMemberOf = entry.NotMemberOf
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
