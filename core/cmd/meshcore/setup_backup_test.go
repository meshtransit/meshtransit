package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/platform/selfhost"
	"meshtransit.net/core/internal/platform/selfhost/backup"
)

func TestRecordBackupFailureKeepsARecentCode(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "backups")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	settings := selfhost.Backup{Dir: dir}
	now := time.Date(2026, 11, 26, 2, 30, 0, 0, time.UTC)
	// A run that never reached the container: generic code.
	if err := recordBackupFailure(settings, now); err != nil {
		t.Fatal(err)
	}
	status, err := backup.ReadStatus(dir)
	if err != nil || status.LastResult != "backup_run_failed" || !status.LastAttempt.Equal(now) {
		t.Fatalf("status = %+v %v", status, err)
	}
	// The backup's own code from this run stays.
	if err := backup.WriteStatus(dir, "", backup.Status{LastAttempt: now, LastResult: "backup_database_invalid",
		LastSuccess: now.Add(-24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := recordBackupFailure(settings, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	status, err = backup.ReadStatus(dir)
	if err != nil || status.LastResult != "backup_database_invalid" || !status.LastSuccess.Equal(now.Add(-24*time.Hour)) {
		t.Fatalf("status = %+v %v", status, err)
	}
	// An old success is not this run's: the failure is recorded.
	if err := backup.WriteStatus(dir, "", backup.Status{LastAttempt: now.Add(-24 * time.Hour), LastResult: "ok"}); err != nil {
		t.Fatal(err)
	}
	if err := recordBackupFailure(settings, now); err != nil {
		t.Fatal(err)
	}
	if status, _ := backup.ReadStatus(dir); status.LastResult != "backup_run_failed" {
		t.Fatalf("status = %+v", status)
	}
}

func TestOperatorFilesAreTheConfigAndWhatItNames(t *testing.T) {
	t.Parallel()
	// #nosec G101 -- file paths, not credentials.
	config := selfhost.Config{Login: selfhost.Login{ClientSecretFile: "/etc/meshtransit/oidc/secret"},
		Mail:   &selfhost.Mail{SMTP: selfhost.SMTP{PasswordFile: "/etc/meshtransit/smtp/secret"}},
		Backup: &selfhost.Backup{Enabled: true, S3: &selfhost.BackupS3{CredentialsFile: "/etc/meshtransit/backup-s3"}}}
	files, err := operatorFiles("/etc/meshtransit/config.yaml", config)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, file := range files {
		names = append(names, file.Name)
	}
	// Two files of one base name in different directories are both kept,
	// each under its own path.
	if strings.Join(names, ",") != "config.yaml,oidc/secret,smtp/secret,backup-s3" {
		t.Fatalf("operator files = %v", names)
	}
	for _, configPath := range []string{"/root/config.yaml", "/etc/meshtransit/../shadow", "/etc/meshtransit"} {
		if _, err := operatorFiles(configPath, config); err == nil {
			t.Errorf("config at %s accepted", configPath)
		}
	}
}

func TestMissingSecretsAndWarnings(t *testing.T) {
	t.Parallel()
	all := selfhost.RequiredSecrets()
	if missing := missingSecrets(all); len(missing) != 0 {
		t.Fatalf("missing = %v", missing)
	}
	if missing := missingSecrets(all[1:]); len(missing) != 1 || missing[0] != all[0] {
		t.Fatalf("missing = %v", missing)
	}
	warnings := strings.Join(configWarnings(selfhost.Config{}), "\n")
	if !strings.Contains(warnings, "backup is off") {
		t.Errorf("warnings without backup: %s", warnings)
	}
	warnings = strings.Join(configWarnings(selfhost.Config{Backup: &selfhost.Backup{Enabled: true,
		Recipients: []string{"age1x"}}}), "\n")
	if !strings.Contains(warnings, "no s3 copy") || !strings.Contains(warnings, "one recipient") {
		t.Errorf("warnings: %s", warnings)
	}
}
