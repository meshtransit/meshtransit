package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/platform/bootstrap"
	"meshtransit.net/core/internal/platform/buildinfo"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/core/internal/platform/observability"
	"meshtransit.net/core/internal/platform/selfhost"
)

// imageUser is the uid and gid MeshTransit images run as: generated files
// belong to it when setup runs as root.
const imageUser = 65532

type setupPaths struct {
	config string
	layout selfhost.Layout
}

type setupCommand struct {
	ctx         context.Context
	paths       setupPaths
	output      io.Writer
	errorOutput io.Writer
	logger      *slog.Logger
	owner       *selfhost.Owner
	now         func() time.Time
}

// runSetup is "meshcore setup init|secrets|approve-identity|render|check|apply|migrate|renew-tls"
// (docs: self-host-config-design.md). Output names files and states, never
// secret values. migrate runs inside the server's containers, as the image
// user: it only reads run/ and talks to the database.
func runSetup(ctx context.Context, args []string, output, errorOutput io.Writer) int {
	logger, err := observability.NewLogger(errorOutput, slog.LevelInfo)
	if err != nil || len(args) == 0 {
		_, _ = io.WriteString(errorOutput, usage)
		return 2
	}
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	configPath := flags.String("config", filepath.Join(selfhost.OperatorDir, "config.yaml"), "config.yaml")
	stateDir := flags.String("state-dir", "/var/lib/meshtransit", "secrets/ and run/ live here")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return 2
	}
	command := setupCommand{
		ctx: ctx, output: output, errorOutput: errorOutput, logger: logger, now: time.Now,
		paths: setupPaths{config: *configPath, layout: selfhost.Layout{
			SecretsDir: filepath.Join(*stateDir, "secrets"), RunDir: filepath.Join(*stateDir, "run"),
		}},
	}
	if os.Geteuid() == 0 {
		command.owner = &selfhost.Owner{UID: imageUser, GID: imageUser}
	}
	steps := map[string][]func() error{
		"init":             {command.init},
		"secrets":          {command.secrets},
		"approve-identity": {command.approve},
		"render":           {command.render},
		"check":            {command.check},
		"apply":            {command.secrets, command.approveIfNew, command.render, command.check},
		"migrate":          {command.migrateReported},
		"renew-tls":        {command.renewTLS},
	}
	operation := args[0]
	run, ok := steps[operation]
	if !ok {
		_, _ = io.WriteString(errorOutput, usage)
		return 2
	}
	fail := func(err error) int {
		logger.ErrorContext(ctx, "setup failed", "error_code", "setup_"+strings.ReplaceAll(operation, "-", "_"),
			"error", err)
		return 1
	}
	if operation != "init" && operation != "migrate" {
		// One setup run at a time over the state directory. migrate writes
		// nothing there; the database serializes its own migrations.
		// renew-tls runs in a container that mounts only the secrets, the
		// lock and the renew directory: the state directory is not its own.
		if operation != "renew-tls" {
			if err := prepareStateDir(*stateDir, command.owner); err != nil {
				return fail(err)
			}
		}
		unlock, err := selfhost.LockSetup(*stateDir)
		if err != nil {
			return fail(err)
		}
		defer unlock()
	}
	for _, step := range run {
		if err := step(); err != nil {
			return fail(err)
		}
	}
	return 0
}

// prepareStateDir makes the state directory root-owned with the image
// group, so containers running as the image user reach secrets/ and run/
// and nobody else does. A link is refused.
func prepareStateDir(stateDir string, owner *selfhost.Owner) error {
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return err
	}
	info, err := os.Lstat(stateDir)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("%s must be a directory", stateDir)
	}
	if owner == nil {
		return nil
	}
	if err := os.Chown(stateDir, 0, owner.GID); err != nil {
		return err
	}
	return os.Chmod(stateDir, 0o750) // #nosec G302 -- a directory the image group must enter.
}

func (command setupCommand) report(value any) error {
	return json.NewEncoder(command.output).Encode(value)
}

func (command setupCommand) loadConfig() (selfhost.Config, error) {
	contents, err := os.ReadFile(command.paths.config)
	if err != nil {
		return selfhost.Config{}, fmt.Errorf("read config.yaml: %w", err)
	}
	return selfhost.ParseConfig(contents)
}

func (command setupCommand) init() error {
	if err := os.MkdirAll(filepath.Dir(command.paths.config), 0o750); err != nil {
		return err
	}
	file, err := os.OpenFile(command.paths.config, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return command.report(map[string]any{"operation": "init", "config": command.paths.config, "written": false})
	}
	if err != nil {
		return err
	}
	if _, err := file.Write(selfhost.SampleConfig()); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return command.report(map[string]any{"operation": "init", "config": command.paths.config, "written": true})
}

func (command setupCommand) secrets() error {
	config, err := command.loadConfig()
	if err != nil {
		return err
	}
	if err := selfhost.PrepareOperatorFiles(config, command.owner); err != nil {
		return err
	}
	report, err := selfhost.GenerateSecrets(config, command.paths.layout.SecretsDir,
		selfhost.GenerateOptions{Now: command.now(), Owner: command.owner})
	if err != nil {
		return err
	}
	restart, err := selfhost.PendingRestart(command.paths.layout.SecretsDir)
	if err != nil {
		return err
	}
	return command.report(map[string]any{"operation": "secrets", "created": nonNil(report.Created),
		"kept": len(report.Kept), "renewed": nonNil(report.Renewed), "restart": nonNil(restart)})
}

// renewTLS renews the internal TLS that is due (the host's timer runs it
// each day, then restarts what the restart file names) and records the
// outcome in renew/status.json, failure included.
func (command setupCommand) renewTLS() error {
	now := command.now()
	secretsDir := command.paths.layout.SecretsDir
	var report selfhost.RenewReport
	config, err := command.loadConfig()
	if err == nil {
		report, err = selfhost.RenewTLS(config, secretsDir, selfhost.GenerateOptions{Now: now, Owner: command.owner})
	}
	report.Renewed, report.Restart = nonNil(report.Renewed), nonNil(report.Restart)
	statusErr := selfhost.WriteRenewStatus(secretsDir, now, report, err)
	reportErr := command.report(map[string]any{"operation": "renew-tls", "result": report})
	return errors.Join(err, statusErr, reportErr)
}

func (command setupCommand) approve() error {
	config, err := command.loadConfig()
	if err != nil {
		return err
	}
	state, err := selfhost.ApproveIdentity(config, command.paths.layout, identityFingerprintFromSettings, command.owner)
	if err != nil {
		return err
	}
	return command.report(map[string]any{"operation": "approve-identity",
		"connector_generation": state.ConnectorGeneration, "core_client_generation": state.CoreClientGeneration})
}

// approveIfNew approves the identity configuration of a new installation
// only; a change to an approved one waits for "setup approve-identity".
func (command setupCommand) approveIfNew() error {
	state, err := selfhost.LoadState(command.paths.layout.SecretsDir)
	if err != nil || state.IdentityFingerprint != "" {
		return err
	}
	return command.approve()
}

// render writes run/. While an identity change waits for approval it writes
// nothing and fails: Core would refuse to start the broker.
func (command setupCommand) render() error {
	config, err := command.loadConfig()
	if err != nil {
		return err
	}
	state, err := selfhost.LoadState(command.paths.layout.SecretsDir)
	if err != nil {
		return err
	}
	status, err := selfhost.CheckIdentity(config, state, command.paths.layout, identityFingerprintFromSettings)
	if err != nil {
		return err
	}
	if status == selfhost.IdentityChanged {
		return errors.New("the identity configuration changed: review it, then run setup approve-identity")
	}
	keys, err := selfhost.LoadPublicKeys(command.paths.layout.SecretsDir)
	if err != nil {
		return err
	}
	rendered, err := selfhost.Render(config, state, keys, command.paths.layout)
	if err != nil {
		return err
	}
	if err := prepareRunDir(command.paths.layout.RunDir, command.owner); err != nil {
		return err
	}
	if err := selfhost.PrepareRenewDir(command.paths.layout.SecretsDir); err != nil {
		return err
	}
	for _, name := range selfhost.DataDirs {
		if err := prepareDataDir(filepath.Join(filepath.Dir(command.paths.layout.SecretsDir), name),
			command.owner); err != nil {
			return err
		}
	}
	names := make([]string, 0, len(rendered.Files))
	for name, contents := range rendered.Files {
		if err := replaceFile(command.paths.layout.RunDir, name, contents, command.owner); err != nil {
			return err
		}
		names = append(names, name)
	}
	slices.Sort(names)
	return command.report(map[string]any{"operation": "render", "files": names, "identity": "approved"})
}

// prepareRunDir makes the rendered files' directory, owned by the image
// group (root:65532 0750): root on the host runs compose from these files
// each night (the TLS renewal timer), so the image user, which every
// container runs as, must not be able to change them. A link is refused.
func prepareRunDir(runDir string, owner *selfhost.Owner) error {
	if err := os.MkdirAll(runDir, 0o750); err != nil {
		return err
	}
	info, err := os.Lstat(runDir)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("%s must be a directory", runDir)
	}
	if owner == nil {
		return nil
	}
	if err := os.Chown(runDir, 0, owner.GID); err != nil {
		return err
	}
	return os.Chmod(runDir, 0o750) // #nosec G302 -- a directory the image group reads.
}

// check loads every rendered file with Core's own loaders: what passes here
// is what the processes will accept. A failure reports the stage and, for a
// configuration error, the setting it names (Core's configuration errors
// name settings, never values).
func (command setupCommand) check() error {
	stage, err := command.checkStages()
	if err == nil {
		return command.report(map[string]any{"operation": "check", "valid": true})
	}
	failure := map[string]any{"operation": "check", "valid": false, "stage": stage}
	if errors.Is(err, config.ErrInvalid) {
		failure["setting"] = strings.TrimPrefix(err.Error(), config.ErrInvalid.Error()+": ")
	}
	if reportErr := command.report(failure); reportErr != nil {
		return reportErr
	}
	return fmt.Errorf("check failed at %s", stage)
}

func (command setupCommand) checkStages() (string, error) {
	run := command.paths.layout.RunDir
	core, err := readEnvFile(filepath.Join(run, "core.env"))
	if err != nil {
		return "core.env", err
	}
	processConfig, err := config.Load(settingsLookup(core))
	if err != nil {
		return "core.env", err
	}
	if processConfig.PrivateLogin == nil {
		return "core.env", errors.New("no login profile")
	}
	profile, err := processConfig.PrivateLogin.Load(command.ctx, processConfig)
	if err != nil {
		return "private-login.json", err
	}
	// What serve reads at start: the listener's certificate and key and the
	// client secret, each with its file mode rules.
	construction, err := profile.LoadConstruction(command.ctx)
	if err != nil {
		return "login listener files", err
	}
	construction.Clear()
	material, err := profile.Keys().Load(command.ctx)
	if err != nil {
		return "login keys", err
	}
	subjectKey, err := bootstrapSubjectKey(material.SubjectActive)
	material.Clear()
	if err != nil {
		return "login subject key", err
	}
	bootstrapSettings, err := readEnvFile(filepath.Join(run, "bootstrap.env"))
	if err != nil {
		return "bootstrap.env", err
	}
	if _, err := config.Load(settingsLookup(bootstrapSettings)); err != nil {
		return "bootstrap.env", err
	}
	plan, err := config.LoadBootstrapPlan(settingsLookup(bootstrapSettings))
	if err != nil {
		return "bootstrap.env", err
	}
	_, err = bootstrap.NewPlan(plan, profile.Route(), subjectKey)
	clear(plan)
	if err != nil {
		return "bootstrap-plan.json", err
	}
	migration, err := readEnvFile(filepath.Join(run, "migrate.env"))
	if err != nil {
		return "migrate.env", err
	}
	if _, err := config.LoadMigration(settingsLookup(migration)); err != nil {
		return "migrate.env", err
	}
	if _, err := config.LoadOperatorMigration(settingsLookup(migration)); err != nil {
		return "migrate.env (operator)", err
	}
	identity, err := readEnvFile(filepath.Join(run, "identity-migrate.env"))
	if err != nil {
		return "identity-migrate.env", err
	}
	if _, err := config.LoadMigration(settingsLookup(identity)); err != nil {
		return "identity-migrate.env", err
	}
	return "", nil
}

func settingsLookup(settings map[string]string) config.LookupFunc {
	return func(name string) (string, bool) {
		value, ok := settings[name]
		return value, ok
	}
}

func readEnvFile(path string) (map[string]string, error) { return selfhost.ReadEnvFile(path) }

// replaceFile writes a rendered file: render output is regenerated on every
// run, so an existing file is replaced, atomically.
func replaceFile(dir, name string, contents []byte, owner *selfhost.Owner) error {
	temporary, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if err := temporary.Chmod(0o640); err != nil {
		_ = temporary.Close()
		return err
	}
	if owner != nil {
		// root's, readable by the image group (prepareRunDir).
		if err := temporary.Chown(0, owner.GID); err != nil {
			_ = temporary.Close()
			return err
		}
	}
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, filepath.Join(dir, name))
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

// migrateReported runs migrate and names the step that failed in the
// output (the log redacts error text).
func (command setupCommand) migrateReported() error {
	err := command.migrate()
	if err != nil {
		_ = command.report(map[string]any{"operation": "migrate", "done": false, "failed": migrateStage(err)})
	}
	return err
}

// migrateStage is the leading "stage:" of a migrate error, never its cause.
func migrateStage(err error) string {
	stage, _, _ := strings.Cut(err.Error(), ":")
	return stage
}

// migrate installs or upgrades the database in the one safe order
// (deployment.md): the login roles' passwords, operator steps, schema,
// operator steps after rollout, verify; then the identity broker's own
// database and its runtime grants; then, on a new installation only,
// bootstrap. Every step is idempotent, so the same command installs and
// upgrades. Core must not serve a newer release before it succeeds.
func (command setupCommand) migrate() error {
	run := command.paths.layout.RunDir
	migration, err := readEnvFile(filepath.Join(run, "migrate.env"))
	if err != nil {
		return err
	}
	lookup := settingsLookup(migration)
	if err := command.setLoginPasswords(lookup); err != nil {
		return err
	}
	for _, step := range []struct {
		name string
		run  func() int
	}{
		{"operator steps", func() int {
			return runMigrateOperator(command.ctx, []string{"apply"}, lookup, command.output, command.errorOutput,
				openOperatorService)
		}},
		{"migrate up", func() int {
			return runMigrate(command.ctx, "up", lookup, command.output, command.errorOutput, openMigrationService)
		}},
		{"operator steps after rollout", func() int {
			return runMigrateOperator(command.ctx, []string{"apply", "--after-rollout"}, lookup, command.output,
				command.errorOutput, openOperatorService)
		}},
		{"migrate verify", func() int {
			return runMigrate(command.ctx, "verify", lookup, command.output, command.errorOutput, openMigrationService)
		}},
	} {
		if step.run() != 0 {
			return fmt.Errorf("%s failed", step.name)
		}
	}
	if err := command.migrateIdentity(run); err != nil {
		return err
	}
	if err := command.bootstrapIfNew(run); err != nil {
		return err
	}
	return command.report(map[string]any{"operation": "migrate", "done": true})
}

// setLoginPasswords stores, as the superuser, a fresh verifier of every
// login role's password file, so a password file setup regenerated never
// locks its role out (PostgreSQL ran postgres-init.sql only once).
func (command setupCommand) setLoginPasswords(lookup config.LookupFunc) error {
	operator, err := config.LoadOperatorMigration(lookup)
	if err != nil {
		return fmt.Errorf("login passwords: %w", err)
	}
	verifiers, err := selfhost.LoginVerifiers(command.paths.layout)
	if err != nil {
		return fmt.Errorf("login passwords: %w", err)
	}
	roles := make([]postgresadapter.RoleVerifier, 0, len(verifiers))
	for _, verifier := range verifiers {
		roles = append(roles, postgresadapter.RoleVerifier{Role: verifier.Role, Verifier: verifier.Verifier})
	}
	if err := postgresadapter.SetLoginRolePasswords(command.ctx, postgresadapter.MigrationOptions{
		Address: operator.PostgreSQL.Address, Database: operator.PostgreSQL.Database,
		User: operator.PostgreSQL.User, PasswordFile: operator.PostgreSQL.PasswordFile,
		CAFile: operator.PostgreSQL.CAFile, ConnectTimeout: operator.ConnectTimeout,
		LockTimeout: operator.LockTimeout, StatementTimeout: operator.StatementTimeout,
		Actor: "setup", CodeRelease: buildinfo.Release(),
	}, roles); err != nil {
		return fmt.Errorf("login passwords: %w", err)
	}
	return command.report(map[string]any{"operation": "login passwords", "roles": len(roles)})
}

// bootstrapIfNew applies the installation plan only while the database
// holds no Deployment. After that the Console owns accounts and Workspaces:
// a later run must not recreate a first admin someone removed, and a
// Deployment in recovery must not stop Core from starting.
func (command setupCommand) bootstrapIfNew(run string) error {
	settings, err := readEnvFile(filepath.Join(run, "bootstrap.env"))
	if err != nil {
		return err
	}
	lookup := settingsLookup(settings)
	migration, err := config.LoadMigration(lookup)
	if err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}
	installed, err := postgresadapter.DeploymentInstalled(command.ctx, postgresadapter.MigrationOptions{
		Address: migration.PostgreSQL.Address, Database: migration.PostgreSQL.Database,
		User: migration.PostgreSQL.User, PasswordFile: migration.PostgreSQL.PasswordFile,
		CAFile: migration.PostgreSQL.CAFile, ConnectTimeout: migration.ConnectTimeout,
		LockTimeout: migration.LockTimeout, StatementTimeout: migration.StatementTimeout,
		Actor: migration.Actor, CodeRelease: buildinfo.Release(),
	})
	if err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}
	if installed {
		return command.report(map[string]any{"operation": "bootstrap", "skipped": "already installed"})
	}
	if runBootstrap(command.ctx, "apply", lookup, command.output, command.errorOutput) != 0 {
		return errors.New("bootstrap failed")
	}
	return nil
}

func (command setupCommand) migrateIdentity(run string) error {
	settings, err := readEnvFile(filepath.Join(run, "identity-migrate.env"))
	if err != nil {
		return err
	}
	migration, err := config.LoadMigration(settingsLookup(settings))
	if err != nil {
		return fmt.Errorf("identity-migrate.env: %w", err)
	}
	if err := migrateIdentityStorage(command.ctx, migration, command.logger); err != nil {
		return fmt.Errorf("identity broker schema: %w", err)
	}
	if err := postgresadapter.GrantIdentityRuntime(command.ctx, postgresadapter.MigrationOptions{
		Address: migration.PostgreSQL.Address, Database: migration.PostgreSQL.Database,
		User: migration.PostgreSQL.User, PasswordFile: migration.PostgreSQL.PasswordFile,
		CAFile: migration.PostgreSQL.CAFile, ConnectTimeout: migration.ConnectTimeout,
		LockTimeout: migration.LockTimeout, StatementTimeout: migration.StatementTimeout,
		Actor: migration.Actor, CodeRelease: buildinfo.Release(),
	}, selfhost.IdentityRuntimeRole); err != nil {
		return fmt.Errorf("identity broker grants: %w", err)
	}
	return command.report(map[string]any{"operation": "identity storage", "migrated": true})
}

// prepareDataDir makes a bundled datastore's data directory, owned by the
// image user and private to it (0700); a link is refused. An existing one
// keeps its contents.
func prepareDataDir(dir string, owner *selfhost.Owner) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("%s must be a directory", dir)
	}
	if owner == nil {
		return nil
	}
	if err := os.Chown(dir, owner.UID, owner.GID); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700) // #nosec G302 -- a private directory.
}
