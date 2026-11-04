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

	"meshtransit.net/core/internal/platform/bootstrap"
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
	ctx    context.Context
	paths  setupPaths
	output io.Writer
	logger *slog.Logger
	owner  *selfhost.Owner
	now    func() time.Time
}

// runSetup is "meshcore setup init|secrets|approve-identity|render|check|apply"
// (docs: self-host-config-design.md). Output names files and states, never
// secret values.
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
		ctx: ctx, output: output, logger: logger, now: time.Now,
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
		"apply":            {command.secrets, command.approveIfNew, command.renderApproved, command.check},
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
	if operation != "init" {
		// One setup run at a time over the state directory.
		if err := prepareStateDir(*stateDir, command.owner); err != nil {
			return fail(err)
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
	return command.report(map[string]any{"operation": "secrets", "created": nonNil(report.Created),
		"kept": len(report.Kept)})
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

func (command setupCommand) render() error {
	return command.renderFiles(false)
}

// renderApproved renders for apply, which leaves run/ untouched and fails
// while an identity change waits for approval (Core would refuse to start
// the broker).
func (command setupCommand) renderApproved() error {
	return command.renderFiles(true)
}

func (command setupCommand) renderFiles(requireApproved bool) error {
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
	if requireApproved && status == selfhost.IdentityChanged {
		return errors.New("the identity configuration changed: review it, then run setup approve-identity")
	}
	rendered, err := selfhost.Render(config, state, command.paths.layout)
	if err != nil {
		return err
	}
	if err := prepareRunDir(command.paths.layout.RunDir, command.owner); err != nil {
		return err
	}
	names := make([]string, 0, len(rendered.Files))
	for name, contents := range rendered.Files {
		if err := replaceFile(command.paths.layout.RunDir, name, contents, command.owner); err != nil {
			return err
		}
		names = append(names, name)
	}
	slices.Sort(names)
	identity := map[selfhost.IdentityStatus]string{
		selfhost.IdentityApproved: "approved", selfhost.IdentityChanged: "changed: run setup approve-identity",
	}[status]
	return command.report(map[string]any{"operation": "render", "files": names, "identity": identity})
}

// prepareRunDir makes the rendered files' directory, owned by the image
// user (0750); a link is refused.
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
	if err := os.Chown(runDir, owner.UID, owner.GID); err != nil {
		return err
	}
	return os.Chmod(runDir, 0o750) // #nosec G302 -- a directory the image user reads.
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
		if err := temporary.Chown(owner.UID, owner.GID); err != nil {
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
