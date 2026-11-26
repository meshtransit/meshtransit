package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"meshtransit.net/core/internal/platform/buildinfo"
	"meshtransit.net/core/internal/platform/selfhost"
	"meshtransit.net/core/internal/platform/selfhost/backup"
)

const (
	// backupLockWait bounds how long a backup waits for a setup run (apply,
	// renew-tls) to release the lock before it reads the files.
	backupLockWait = 10 * time.Minute
	// backupCaddyData is where the backup and restore containers mount
	// Caddy's data volume (selfhost.backupCaddyDataMount).
	backupCaddyData = "/caddy-data"
	// backupFailureKeep is how long a failure the backup recorded itself
	// keeps its specific code against the unit's generic one.
	backupFailureKeep = 4 * time.Hour
	// minimumFreeSpace is kept free beside a backup: PostgreSQL panics when
	// its WAL cannot be written, so a backup must never fill the disk.
	minimumFreeSpace = 1 << 30
)

// errBackupDiskSpace reports too little free space to back up safely.
var errBackupDiskSpace = errors.New("not enough free disk space for a backup")

type backupOptions struct {
	dbStdin          bool
	recordFailure    bool
	from             string
	identity         string
	expectDeployment string
	expectSHA256     string
	noSHA256Check    bool
	replace          bool
}

func (options *backupOptions) register(flags *flag.FlagSet) {
	flags.BoolVar(&options.dbStdin, "db-stdin", false, "backup: read pg_basebackup's tar stream on stdin")
	flags.BoolVar(&options.recordFailure, "record-failure", false, "backup: record that the nightly run failed")
	flags.StringVar(&options.from, "from", "", "backup-verify, restore: the backup file")
	flags.StringVar(&options.identity, "identity", "", "backup-verify, restore: age identity file, or - for stdin")
	flags.StringVar(&options.expectDeployment, "expect-deployment", "", "backup-verify, restore: the Deployment ID")
	flags.StringVar(&options.expectSHA256, "expect-sha256", "",
		"backup-verify, restore: the file's SHA-256 as recorded off the server")
	flags.BoolVar(&options.noSHA256Check, "no-sha256-check", false,
		"restore: accept a file without its recorded SHA-256 (anyone holding a recipient can forge one)")
	flags.BoolVar(&options.replace, "replace", false, "restore: set aside existing data instead of refusing")
}

// backupRun is "setup backup --db-stdin": one encrypted backup file, the
// database read from stdin, the files read under the setup lock, then
// retention, status and the optional S3 copy.
func (command setupCommand) backupRun() error {
	config, err := command.loadConfig()
	if err != nil {
		return err
	}
	settings := config.BackupSettings()
	if settings == nil {
		return errors.New("backup is not enabled in config.yaml")
	}
	if command.backup.recordFailure {
		return recordBackupFailure(*settings, command.now())
	}
	if !command.backup.dbStdin {
		return errors.New("setup backup reads the database on stdin (--db-stdin); the backup unit runs it")
	}
	started := command.now()
	status, _ := backup.ReadStatus(settings.Dir)
	result, err := command.writeBackup(config, *settings, started, status.Size)
	status.LastAttempt, status.Offsite = command.now(), settings.S3 != nil
	if err != nil {
		status.LastResult = backupErrorCode(err)
		if writeErr := backup.WriteStatus(settings.Dir, settings.TextfileDir, status); writeErr != nil {
			return errors.Join(err, writeErr)
		}
		return err
	}
	status.LastResult, status.LastSuccess = "ok", status.LastAttempt
	status.File, status.SHA256, status.Size = filepath.Base(result.file), result.sha256, result.size
	status.DurationSeconds = status.LastAttempt.Sub(started).Seconds()
	var offsiteErr error
	if settings.S3 != nil {
		offsiteErr = command.uploadBackup(*settings.S3, result)
		if offsiteErr == nil {
			status.OffsiteLastSuccess = command.now()
		} else {
			status.LastResult = "backup_offsite_failed"
		}
	}
	if err := backup.WriteStatus(settings.Dir, settings.TextfileDir, status); err != nil {
		return errors.Join(offsiteErr, err)
	}
	report := map[string]any{
		"operation": "backup", "file": status.File, "sha256": result.sha256, "size": result.size,
		"postgres": result.manifest.Postgres, "skipped_caddy_entries": result.skipped, "pruned": result.pruned,
		"offsite": settings.S3 != nil && offsiteErr == nil,
	}
	if result.pruneErr != nil {
		// The new file is good: a failed prune only leaves old files.
		report["warning"] = "retention failed: " + result.pruneErr.Error()
	}
	if reportErr := command.report(report); reportErr != nil {
		return errors.Join(offsiteErr, reportErr)
	}
	return offsiteErr
}

type writtenBackup struct {
	file, sha256 string
	size         int64
	manifest     backup.Manifest
	skipped      int
	pruned       []string
	pruneErr     error
	deployment   string
}

func (command setupCommand) writeBackup(config selfhost.Config, settings selfhost.Backup, started time.Time,
	lastSize int64,
) (writtenBackup, error) {
	state, err := selfhost.LoadState(command.paths.layout.SecretsDir)
	if err != nil {
		return writtenBackup{}, err
	}
	recipients, err := settings.BackupRecipients()
	if err != nil {
		return writtenBackup{}, err
	}
	operator, err := operatorFiles(command.paths.config, config)
	if err != nil {
		return writtenBackup{}, err
	}
	if err := checkFreeSpace(settings.Dir, command.paths.layout.SecretsDir, lastSize); err != nil {
		return writtenBackup{}, err
	}
	pending, err := backup.Create(settings.Dir, backup.Name(state.DeploymentID, started))
	if err != nil {
		return writtenBackup{}, err
	}
	build := buildinfo.Current()
	meta := backup.Meta{DeploymentID: state.DeploymentID, Created: started.UTC(), CoreVersion: build.Version,
		CoreRevision: build.Revision, CoreImage: config.Images.Core, PostgresImage: selfhost.PostgresImage()}
	stateDir := filepath.Dir(command.paths.layout.SecretsDir)
	source := backup.Source{
		DB: command.input, SecretsDir: command.paths.layout.SecretsDir, Operator: operator,
		Lock: func() (func(), error) { return lockWithin(command.ctx, stateDir, backupLockWait) },
	}
	if info, err := os.Stat(backupCaddyData); err == nil && info.IsDir() {
		source.CaddyDataDir = backupCaddyData
	}
	result, err := backup.Write(pending, recipients, meta, source)
	if err != nil {
		pending.Abort()
		return writtenBackup{}, err
	}
	file, size, sum, err := pending.Commit()
	if err != nil {
		return writtenBackup{}, err
	}
	pruned, pruneErr := backup.Prune(settings.Dir, state.DeploymentID, settings.Keep, filepath.Base(file),
		command.now())
	return writtenBackup{file: file, sha256: sum, size: size, manifest: result.Manifest, skipped: result.Skipped,
		pruned: pruned, pruneErr: pruneErr, deployment: state.DeploymentID}, nil
}

// checkFreeSpace keeps twice the last backup plus 1 GiB free where the
// backup goes, and 1 GiB where PostgreSQL writes. secrets/ is measured, not
// the state directory: in the backup container only secrets/ is a bind
// mount of the host's state filesystem (where postgres/ lives); the state
// directory itself is the container's own layer.
func checkFreeSpace(backupDir, secretsDir string, lastSize int64) error {
	need := uint64(minimumFreeSpace)
	if lastSize > 0 {
		need += 2 * uint64(lastSize) // #nosec G115 -- a positive size.
	}
	for dir, want := range map[string]uint64{backupDir: need, secretsDir: minimumFreeSpace} {
		free, err := backup.FreeBytes(dir)
		if err != nil {
			return fmt.Errorf("free space of %s: %w", dir, err)
		}
		if free < want {
			return fmt.Errorf("%w: %s has %d MiB free, needs %d MiB", errBackupDiskSpace, dir, free>>20, want>>20)
		}
	}
	return nil
}

func (command setupCommand) uploadBackup(target selfhost.BackupS3, written writtenBackup) error {
	return backup.S3{Endpoint: target.Endpoint, Region: target.Region, Bucket: target.Bucket, Prefix: target.Prefix,
		CredentialsFile: target.CredentialsFile}.Upload(command.ctx, written.deployment, written.file, written.sha256)
}

// operatorFiles are config.yaml and every file it names, each archived by
// its path under the operator's directory and restored to the same path:
// without the OIDC client secret the restored server stops on the identity
// fingerprint. A path outside the directory fails the backup.
func operatorFiles(configPath string, config selfhost.Config) ([]backup.OperatorFile, error) {
	paths := []string{configPath, config.Login.ClientSecretFile}
	if config.Mail != nil && config.Mail.SMTP.PasswordFile != "" {
		paths = append(paths, config.Mail.SMTP.PasswordFile)
	}
	if settings := config.BackupSettings(); settings != nil && settings.S3 != nil {
		paths = append(paths, settings.S3.CredentialsFile)
	}
	files := make([]backup.OperatorFile, 0, len(paths))
	seen := map[string]bool{}
	for _, location := range paths {
		if location == "" {
			continue
		}
		relative, err := filepath.Rel(selfhost.OperatorDir, filepath.Clean(location))
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, "../") ||
			filepath.IsAbs(relative) {
			return nil, fmt.Errorf("%s is outside %s: keep config.yaml and its files there", location,
				selfhost.OperatorDir)
		}
		if seen[relative] {
			continue // one file named twice
		}
		seen[relative] = true
		files = append(files, backup.OperatorFile{Name: filepath.ToSlash(relative), Path: location})
	}
	return files, nil
}

// lockWithin takes the setup lock, retrying while another run holds it.
func lockWithin(ctx context.Context, stateDir string, wait time.Duration) (func(), error) {
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		unlock, err := selfhost.LockSetup(stateDir)
		if err == nil || !errors.Is(err, selfhost.ErrSetupLocked) {
			return unlock, err
		}
		retry := time.NewTimer(5 * time.Second)
		select {
		case <-ctx.Done():
			retry.Stop()
			return nil, ctx.Err()
		case <-deadline.C:
			retry.Stop()
			return nil, err
		case <-retry.C:
		}
	}
}

func backupErrorCode(err error) string {
	switch {
	case errors.Is(err, backup.ErrDatabase):
		return "backup_database_invalid"
	case errors.Is(err, errBackupDiskSpace):
		return "backup_disk_space"
	case errors.Is(err, backup.ErrInvalid):
		return "backup_invalid"
	default:
		return "backup_failed"
	}
}

// recordBackupFailure runs when the nightly unit failed: the metrics must
// show it even when the backup never started (docker down, a lock never
// released). A specific code the backup recorded in this run is kept.
func recordBackupFailure(settings selfhost.Backup, now time.Time) error {
	status, err := backup.ReadStatus(settings.Dir)
	if err != nil {
		status = backup.Status{}
	}
	recent := now.Sub(status.LastAttempt) < backupFailureKeep && status.LastResult != "ok" && status.LastResult != ""
	if !recent {
		status.LastResult = "backup_run_failed"
	}
	status.LastAttempt, status.Offsite = now, settings.S3 != nil
	return backup.WriteStatus(settings.Dir, settings.TextfileDir, status)
}

// prepareBackupDir checks the backup directory setup apply sees (the
// operator makes it, root's 0700, and mounts it into the setup container)
// and, before the first run, writes a status that exports
// meshtransit_backup_configured: a timer never installed then still alerts
// (no success ever recorded). A missing directory is refused rather than
// created inside the setup container, where it would vanish.
func prepareBackupDir(config selfhost.Config) error {
	settings := config.BackupSettings()
	if settings == nil {
		return nil
	}
	for _, dir := range []string{settings.Dir, settings.TextfileDir} {
		if dir == "" {
			continue
		}
		if info, err := os.Lstat(dir); err != nil || !info.IsDir() {
			return fmt.Errorf("backup: %s is not a directory here: create it on the host and add "+
				"-v %s:%s to the setup command", dir, dir, dir)
		}
	}
	if info, err := os.Lstat(settings.Dir); err != nil || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("backup: %s must be mode 0700 (it holds every secret, encrypted)", settings.Dir)
	}
	if _, err := os.Lstat(filepath.Join(settings.Dir, backup.StatusName)); err == nil {
		return nil
	}
	return backup.WriteStatus(settings.Dir, settings.TextfileDir, backup.Status{Offsite: settings.S3 != nil})
}
