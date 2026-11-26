package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"filippo.io/age"

	"meshtransit.net/core/internal/platform/buildinfo"
	"meshtransit.net/core/internal/platform/selfhost"
	"meshtransit.net/core/internal/platform/selfhost/backup"
)

// restoreMarker marks a state directory a restore has started writing and
// not finished: setup secrets would otherwise fill the gaps with new keys,
// which breaks every enrollment key and session of the restored database.
const restoreMarker = ".restore-incomplete"

// refuseIncompleteRestore stops setup runs that generate or render while a
// restore is unfinished.
func refuseIncompleteRestore(stateDir string) error {
	if _, err := os.Lstat(filepath.Join(stateDir, restoreMarker)); err == nil {
		return errors.New("a restore did not finish: run setup restore again with --replace before anything else")
	}
	return nil
}

// reportFailure prints why an operator-run command failed: the log redacts
// errors, and these name only paths, flags and checks, never a secret (age
// and the archive's own errors carry no key material).
func (command setupCommand) reportFailure(operation string, err error) error {
	return errors.Join(err, command.report(map[string]any{"operation": operation, "result": "failed",
		"reason": err.Error()}))
}

// backupVerify is "setup backup-verify": the first restore pass, writing
// nothing. Any image may verify a file.
func (command setupCommand) backupVerify() error {
	identities, err := command.readIdentities()
	if err != nil {
		return command.reportFailure("backup-verify", err)
	}
	manifest, sum, err := command.verifyBackup(identities, backup.Expect{DeploymentID: command.backup.expectDeployment,
		AnyImage: true})
	if err != nil {
		return command.reportFailure("backup-verify", err)
	}
	return command.report(map[string]any{"operation": "backup-verify", "result": "ok", "sha256": sum,
		"meta": manifest.Meta, "postgres": manifest.Postgres, "members": len(manifest.Members)})
}

// verifyBackup runs pass 1 over the file, hashing the ciphertext as it
// goes; with --expect-sha256 the hash must match.
func (command setupCommand) verifyBackup(identities []age.Identity, expect backup.Expect) (
	backup.Manifest, string, error,
) {
	var manifest backup.Manifest
	sum, err := readBackupFile(command.backup.from, func(in io.Reader) error {
		var err error
		manifest, err = backup.Verify(in, identities, expect)
		return err
	})
	if err != nil {
		return backup.Manifest{}, "", err
	}
	if err := command.checkSHA256(sum); err != nil {
		return backup.Manifest{}, "", err
	}
	return manifest, sum, nil
}

func (command setupCommand) checkSHA256(sum string) error {
	if command.backup.expectSHA256 == "" {
		return nil
	}
	if !strings.EqualFold(command.backup.expectSHA256, sum) {
		return fmt.Errorf("the file's SHA-256 %s is not the recorded %s", sum, command.backup.expectSHA256)
	}
	return nil
}

// readBackupFile opens the file and hands use a reader that hashes every
// byte; whatever use leaves unread is read too, so the hash covers the
// whole file.
func readBackupFile(location string, use func(io.Reader) error) (string, error) {
	file, err := backup.OpenRegular(location)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	digest := sha256.New()
	reader := io.TeeReader(file, digest)
	if err := use(reader); err != nil {
		return "", err
	}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func (command setupCommand) readIdentities() ([]age.Identity, error) {
	if command.backup.from == "" || command.backup.identity == "" || command.backup.expectDeployment == "" {
		return nil, errors.New("--from, --identity and --expect-deployment are required")
	}
	var source io.Reader
	if command.backup.identity == "-" {
		source = command.input
	} else {
		location := filepath.Clean(command.backup.identity)
		if !filepath.IsAbs(location) || strings.HasPrefix(location, "/etc/") || strings.HasPrefix(location, "/var/lib/") {
			return nil, errors.New("keep the backup identity off the server: pass it with --identity - " +
				"(for example ssh keyhost cat key | docker run -i …)")
		}
		file, err := backup.OpenRegular(location)
		if err != nil {
			return nil, err
		}
		defer func() { _ = file.Close() }()
		source = file
	}
	identities, err := age.ParseIdentities(io.LimitReader(source, 64<<10))
	if err != nil {
		return nil, fmt.Errorf("backup identity: %w", err)
	}
	return identities, nil
}

// restore is "setup restore": both passes over the backup file, into a
// stopped server whose data directories are empty (or set aside with
// --replace). It must run with the backup's own Core image.
func (command setupCommand) restore() error {
	if err := command.restoreSteps(); err != nil {
		return command.reportFailure("restore", err)
	}
	return nil
}

func (command setupCommand) restoreSteps() error {
	if command.backup.expectSHA256 == "" && !command.backup.noSHA256Check {
		return errors.New("--expect-sha256 is required: compare the file with the SHA-256 recorded off the " +
			"server (age does not authenticate who made it); --no-sha256-check accepts the risk")
	}
	if command.backup.identity == "-" && command.backup.from == "-" {
		return errors.New("the identity and the backup cannot both come from stdin")
	}
	stateDir := filepath.Dir(command.paths.layout.SecretsDir)
	if _, err := os.Lstat(filepath.Join(stateDir, "postgres", "pgdata", "postmaster.pid")); err == nil {
		return errors.New("postgres/pgdata/postmaster.pid exists: docker compose down first; if PostgreSQL " +
			"crashed and no container runs (docker ps), remove the stale file")
	}
	if _, err := os.Lstat(filepath.Join(stateDir, restoreMarker)); err == nil && !command.backup.replace {
		return errors.New("an earlier restore did not finish: run it again with --replace")
	}
	build := buildinfo.Current()
	expect := backup.Expect{DeploymentID: command.backup.expectDeployment, CoreVersion: build.Version,
		CoreRevision: build.Revision, PostgresMajor: selfhost.PostgresMajor()}
	identities, err := command.readIdentities()
	if err != nil {
		return err
	}
	verified, sum, err := command.verifyBackup(identities, expect)
	if err != nil {
		return err
	}
	if missing := missingSecrets(backup.SecretNames(verified.Members)); len(missing) != 0 {
		return fmt.Errorf("the backup lacks secrets/%s: setup would generate new ones", strings.Join(missing, ", "))
	}
	operator := operatorMembers(verified)
	if !command.backup.replace {
		for _, name := range operator {
			if _, err := os.Lstat(filepath.Join(selfhost.OperatorDir, filepath.FromSlash(name))); err == nil {
				return fmt.Errorf("%s/%s exists: restore refuses to overwrite it (--replace sets it aside)",
					selfhost.OperatorDir, name)
			}
		}
	}
	// Every refusal happens before anything changes: a refused restore
	// leaves no marker behind.
	if err := command.checkRestoreTargets(stateDir); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stateDir, restoreMarker), []byte(sum+"\n"), 0o600); err != nil {
		return err
	}
	stamp := command.now().UTC().Format("20060102T150405Z")
	staging := filepath.Join(selfhost.OperatorDir, ".restore-"+stamp)
	targets, setAside, err := command.prepareRestoreTargets(stateDir, staging, stamp)
	if err != nil {
		return err
	}
	second, err := readBackupFile(command.backup.from, func(in io.Reader) error {
		return backup.Extract(in, identities, verified, expect, targets)
	})
	if err == nil && second != sum {
		err = errors.New("the file changed between the two passes")
	}
	if err != nil {
		return fmt.Errorf("restore failed and left partial data: run it again with --replace: %w", err)
	}
	restored, err := moveOperatorFiles(staging, operator, stamp, command.owner)
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(stateDir, restoreMarker)); err != nil {
		return err
	}
	return command.report(map[string]any{
		"operation": "restore", "result": "ok", "sha256": sum, "meta": verified.Meta, "postgres": verified.Postgres,
		"operator_files": restored, "set_aside": setAside,
		"next": "edit relay addresses for this server, then setup apply with this same image, docker compose up -d, " +
			"install the backup and TLS timers again, delete the set-aside copies once checked (runbook backup-restore.md)",
	})
}

func missingSecrets(archived []string) []string {
	var missing []string
	for _, name := range selfhost.RequiredSecrets() {
		if !slices.Contains(archived, name) {
			missing = append(missing, name)
		}
	}
	return missing
}

// operatorMembers are the operator files in the backup, by their path
// under the operator's directory.
func operatorMembers(manifest backup.Manifest) []string {
	var names []string
	for _, member := range manifest.Members {
		if rest, ok := strings.CutPrefix(member.Name, backup.OperatorDir+"/"); ok && member.SHA256 != "" {
			names = append(names, rest)
		}
	}
	return names
}

// checkRestoreTargets refuses, without changing anything, data restore
// would overwrite without --replace, and a missing Caddy volume.
func (command setupCommand) checkRestoreTargets(stateDir string) error {
	entries, err := os.ReadDir(backupCaddyData)
	if err != nil {
		return fmt.Errorf("mount the caddy-data volume at %s: %w", backupCaddyData, err)
	}
	if command.backup.replace {
		return nil
	}
	if len(entries) != 0 {
		return fmt.Errorf("%s is not empty: restore refuses to overwrite it (--replace empties it)", backupCaddyData)
	}
	for _, name := range []string{"secrets", "postgres", "redis"} {
		dir := filepath.Join(stateDir, name)
		entries, err := os.ReadDir(dir)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if len(entries) != 0 {
			return fmt.Errorf("%s is not empty: restore refuses to overwrite it (--replace sets it aside)", dir)
		}
	}
	return nil
}

// prepareRestoreTargets makes each top-level directory's empty target.
// secrets/, postgres/ and redis/ (whose generations would run ahead of the
// restored database) are set aside with --replace, renamed, never deleted;
// Caddy's data, a volume mount, is emptied (certificates are issued again).
// The operator's files land in a staging directory first.
func (command setupCommand) prepareRestoreTargets(stateDir, staging, stamp string) (
	map[string]backup.Placement, []string, error,
) {
	var setAside []string
	uid, gid := -1, -1
	if command.owner != nil {
		uid, gid = command.owner.UID, command.owner.GID
	}
	for _, name := range []string{"secrets", "postgres", "redis"} {
		dir := filepath.Join(stateDir, name)
		entries, err := os.ReadDir(dir)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, nil, err
		}
		if len(entries) != 0 {
			if !command.backup.replace {
				return nil, nil, fmt.Errorf("%s is not empty: restore refuses to overwrite it (--replace sets it aside)",
					dir)
			}
			aside := dir + ".before-restore-" + stamp
			if err := os.Rename(dir, aside); err != nil {
				return nil, nil, err
			}
			setAside = append(setAside, aside)
		}
		if name != "redis" {
			if err := mkdirOwned(dir, uid, gid); err != nil {
				return nil, nil, err
			}
		}
	}
	pgdata := filepath.Join(stateDir, "postgres", "pgdata")
	if err := mkdirOwned(pgdata, uid, gid); err != nil {
		return nil, nil, err
	}
	if err := emptyCaddyData(command.backup.replace); err != nil {
		return nil, nil, err
	}
	if err := os.Mkdir(staging, 0o700); err != nil {
		return nil, nil, err
	}
	// The image user owns the database and secrets/; the operator's files
	// stay root's until setup apply sets the ones it names.
	return map[string]backup.Placement{
		backup.PostgresDir:  {Root: pgdata, UID: uid, GID: gid, DirMode: 0o700, FileMode: 0o600},
		backup.SecretsDir:   {Root: filepath.Join(stateDir, "secrets"), UID: uid, GID: gid, DirMode: 0o700, FileMode: 0o640},
		backup.OperatorDir:  {Root: staging, UID: -1, GID: -1, DirMode: 0o700, FileMode: 0o600},
		backup.CaddyDataDir: {Root: backupCaddyData, UID: -1, GID: -1, DirMode: 0o700, FileMode: 0o600},
	}, setAside, nil
}

func mkdirOwned(dir string, uid, gid int) error {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("%s must be a directory", dir)
	}
	if uid >= 0 {
		if err := os.Chown(dir, uid, gid); err != nil {
			return err
		}
	}
	return os.Chmod(dir, 0o700) // #nosec G302 -- a private directory.
}

func emptyCaddyData(replace bool) error {
	entries, err := os.ReadDir(backupCaddyData)
	if err != nil {
		return fmt.Errorf("mount the caddy-data volume at %s: %w", backupCaddyData, err)
	}
	if len(entries) == 0 {
		return nil
	}
	if !replace {
		return fmt.Errorf("%s is not empty: restore refuses to overwrite it (--replace empties it)", backupCaddyData)
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(backupCaddyData, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

// moveOperatorFiles moves the restored operator files from staging to the
// same path under the operator's directory; an existing file is set aside
// (restore checked --replace before writing anything). New subdirectories
// are root's with the image group, like the directory itself.
func moveOperatorFiles(staging string, names []string, stamp string, owner *selfhost.Owner) ([]string, error) {
	for _, name := range names {
		target := filepath.Join(selfhost.OperatorDir, filepath.FromSlash(name))
		if parent := path.Dir(name); parent != "." {
			if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
				return nil, err
			}
			if owner != nil {
				if err := os.Chown(filepath.Dir(target), 0, owner.GID); err != nil {
					return nil, err
				}
			}
		}
		if _, err := os.Lstat(target); err == nil {
			if err := os.Rename(target, target+".before-restore-"+stamp); err != nil {
				return nil, err
			}
		}
		if err := os.Rename(filepath.Join(staging, filepath.FromSlash(name)), target); err != nil {
			return nil, err
		}
	}
	if err := os.RemoveAll(staging); err != nil {
		return nil, err
	}
	return names, nil
}
