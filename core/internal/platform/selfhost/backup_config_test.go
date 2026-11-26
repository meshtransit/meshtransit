package selfhost

import (
	"errors"
	"strings"
	"testing"

	"filippo.io/age"
	"gopkg.in/yaml.v3"
)

func backupRecipient(t *testing.T) string {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return identity.Recipient().String()
}

func TestBackupConfigValidates(t *testing.T) {
	t.Parallel()
	recipient := backupRecipient(t)
	good := validConfig + "backup:\n  enabled: true\n  recipients: [" + recipient + "]\n"
	config, err := ParseConfig([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	settings := config.BackupSettings()
	if settings == nil || settings.Dir != DefaultBackupDir || settings.Keep != DefaultBackupKeep {
		t.Fatalf("defaults = %+v", settings)
	}
	if recipients, err := settings.BackupRecipients(); err != nil || len(recipients) != 1 {
		t.Fatalf("recipients = %v %v", recipients, err)
	}
	off, err := ParseConfig([]byte(validConfig + "backup:\n  enabled: false\n"))
	if err != nil || off.BackupSettings() != nil {
		t.Fatalf("disabled backup: %v %v", off.BackupSettings(), err)
	}
	s3 := "  s3:\n    endpoint: https://s3.example.com\n    region: auto\n    bucket: mesh-backups\n" +
		"    prefix: server-1\n    credentials_file: /etc/meshtransit/backup-s3\n"
	if _, err := ParseConfig([]byte(good + s3)); err != nil {
		t.Fatalf("s3: %v", err)
	}
	for name, extra := range map[string]string{
		"no recipient":    "backup:\n  enabled: true\n",
		"bad recipient":   "backup:\n  enabled: true\n  recipients: [age1nope]\n",
		"twice":           "backup:\n  enabled: true\n  recipients: [" + recipient + ", " + recipient + "]\n",
		"relative dir":    "backup:\n  enabled: true\n  dir: backups\n  recipients: [" + recipient + "]\n",
		"state dir":       "backup:\n  enabled: true\n  dir: /var/lib/meshtransit/backups\n  recipients: [" + recipient + "]\n",
		"operator dir":    "backup:\n  enabled: true\n  dir: /etc/meshtransit\n  recipients: [" + recipient + "]\n",
		"root":            "backup:\n  enabled: true\n  dir: /\n  recipients: [" + recipient + "]\n",
		"parent of state": "backup:\n  enabled: true\n  dir: /var/lib\n  recipients: [" + recipient + "]\n",
		"keep":            "backup:\n  enabled: true\n  keep: 400\n  recipients: [" + recipient + "]\n",
		"http s3":         "backup:\n  enabled: true\n  recipients: [" + recipient + "]\n" + strings.Replace(s3, "https", "http", 1),
		"s3 creds outside": "backup:\n  enabled: true\n  recipients: [" + recipient + "]\n" +
			strings.Replace(s3, "/etc/meshtransit/backup-s3", "/root/s3", 1),
		"unknown field": "backup:\n  enabled: true\n  password: x\n  recipients: [" + recipient + "]\n",
	} {
		if _, err := ParseConfig([]byte(validConfig + extra)); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

func TestBackupServiceAndUnits(t *testing.T) {
	t.Parallel()
	off, err := Render(testConfig(t), approvedState(), testKeys, testLayout)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := off.Files[backupServiceUnit]; found || strings.Contains(string(off.Files["compose.yaml"]), "backup") {
		t.Fatal("backup rendered while off")
	}
	config, err := ParseConfig([]byte(validConfig + "backup:\n  enabled: true\n  recipients: [" + backupRecipient(t) +
		"]\n  textfile_dir: /var/lib/node_exporter/textfile\n"))
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := Render(config, approvedState(), testKeys, testLayout)
	if err != nil {
		t.Fatal(err)
	}
	var compose struct {
		Services map[string]map[string]any `yaml:"services"`
		Networks map[string]any            `yaml:"networks"`
	}
	if err := yaml.Unmarshal(rendered.Files["compose.yaml"], &compose); err != nil {
		t.Fatal(err)
	}
	service := compose.Services[backupService]
	text, err := yaml.Marshal(service)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"network_mode: none", "driver: none", "- DAC_READ_SEARCH", "- ALL",
		"source: caddy-data", "target: /caddy-data", "/var/backups/meshtransit", "/var/lib/node_exporter/textfile",
		"- --db-stdin", "- maintenance", "no-new-privileges:true", "cpu_shares: 256"} {
		if !strings.Contains(string(text), want) {
			t.Errorf("backup service lacks %q:\n%s", want, text)
		}
	}
	if _, found := compose.Networks[backupEgressNetwork]; found {
		t.Error("egress network without s3")
	}
	unit := string(rendered.Files[backupServiceUnit])
	for _, want := range []string{"ExecStart=/usr/bin/bash /var/lib/meshtransit/run/meshtransit-backup.sh\n",
		"ExecStopPost=/usr/bin/bash /var/lib/meshtransit/run/meshtransit-backup.sh record-failure\n",
		"IOSchedulingClass=idle", "TimeoutStartSec=4h"} {
		if !strings.Contains(unit, want) {
			t.Errorf("backup unit lacks %q:\n%s", want, unit)
		}
	}
	script := string(rendered.Files[backupScript])
	for _, want := range []string{
		"set -euo pipefail\n",
		"docker compose -f /var/lib/meshtransit/run/compose.yaml exec -T postgres sh -c " +
			`'PGPASSWORD="$(cat /var/lib/meshtransit/secrets/postgres-superuser-password)" exec pg_basebackup ` +
			"-h /var/run/postgresql -U postgres -D - -Ft -X fetch --checkpoint=fast --max-rate=64M' |\n",
		"  docker compose -f /var/lib/meshtransit/run/compose.yaml --profile maintenance run --rm -T backup\n",
		`[ "${SERVICE_RESULT:-}" = success ] && exit 0`, "setup backup --record-failure",
		"--filter label=com.docker.compose.service=backup", `docker kill $ids`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("backup script lacks %q:\n%s", want, script)
		}
	}
	// The database never passes through docker compose run's stdout.
	left, _, _ := strings.Cut(script[strings.Index(script, "fi\n"):], " |")
	if strings.Contains(left, " run ") {
		t.Errorf("base backup runs in compose run (its stdout reaches the log driver): %s", left)
	}
	if !strings.Contains(string(rendered.Files[backupTimerUnit]), "OnCalendar=*-*-* 02:15:00") {
		t.Errorf("timer:\n%s", rendered.Files[backupTimerUnit])
	}
	withS3, err := ParseConfig([]byte(validConfig + "backup:\n  enabled: true\n  recipients: [" + backupRecipient(t) +
		"]\n  s3:\n    endpoint: https://s3.example.com\n    region: auto\n    bucket: mesh-backups\n" +
		"    credentials_file: /etc/meshtransit/backup-s3\n"))
	if err != nil {
		t.Fatal(err)
	}
	rendered, err = Render(withS3, approvedState(), testKeys, testLayout)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(rendered.Files["compose.yaml"], &compose); err != nil {
		t.Fatal(err)
	}
	if _, found := compose.Networks[backupEgressNetwork]; !found ||
		compose.Services[backupService]["network_mode"] != nil {
		t.Errorf("s3 backup networks: %v / %v", compose.Networks, compose.Services[backupService])
	}
}

func TestRequiredSecretsIncludeState(t *testing.T) {
	t.Parallel()
	names := RequiredSecrets()
	if !strings.Contains(strings.Join(names, ","), "account-session-digest.key") ||
		names[len(names)-1] != "state.json" {
		t.Fatalf("RequiredSecrets() = %v", names)
	}
}
