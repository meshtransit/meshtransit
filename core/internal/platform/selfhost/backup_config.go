package selfhost

import (
	"net/url"
	"path"
	"regexp"
	"strings"

	"filippo.io/age"
)

// Defaults of the backup block (V1-51).
const (
	DefaultBackupDir  = "/var/backups/meshtransit"
	DefaultBackupKeep = 14
	maxBackupKeep     = 366
)

var (
	bucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	regionName = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	keyPrefix  = regexp.MustCompile(`^[A-Za-z0-9._/-]{0,128}$`)
)

// Backup is config.yaml's backup block: a nightly physical backup of the
// databases with secrets/, the operator's files and Caddy's data, encrypted
// to recipients whose private keys never come to this server.
type Backup struct {
	Enabled     bool      `yaml:"enabled"`
	Dir         string    `yaml:"dir"`
	Keep        int       `yaml:"keep"`
	Recipients  []string  `yaml:"recipients"`
	TextfileDir string    `yaml:"textfile_dir"`
	S3          *BackupS3 `yaml:"s3"`
}

// BackupS3 is an optional off-server copy: an S3-compatible bucket and a
// credential that should only allow PutObject. The credential file stays
// root's (mode 0600): only the backup container, which runs as root, reads
// it.
type BackupS3 struct {
	Endpoint        string `yaml:"endpoint"`
	Region          string `yaml:"region"`
	Bucket          string `yaml:"bucket"`
	Prefix          string `yaml:"prefix"`
	CredentialsFile string `yaml:"credentials_file"`
}

// BackupSettings returns the block with defaults filled in; nil when
// backups are off.
func (config Config) BackupSettings() *Backup {
	if config.Backup == nil || !config.Backup.Enabled {
		return nil
	}
	settings := *config.Backup
	if settings.Dir == "" {
		settings.Dir = DefaultBackupDir
	}
	if settings.Keep == 0 {
		settings.Keep = DefaultBackupKeep
	}
	return &settings
}

// BackupRecipients parses the recipients (validated with the config).
func (backup Backup) BackupRecipients() ([]age.Recipient, error) {
	recipients := make([]age.Recipient, 0, len(backup.Recipients))
	for _, value := range backup.Recipients {
		recipient, err := age.ParseX25519Recipient(value)
		if err != nil {
			return nil, invalid("backup.recipients")
		}
		recipients = append(recipients, recipient)
	}
	return recipients, nil
}

func (backup Backup) validate() error {
	if !backup.Enabled {
		return nil
	}
	settings := Config{Backup: &backup}.BackupSettings()
	switch {
	case len(backup.Recipients) == 0 || len(backup.Recipients) > 8:
		return invalid("backup.recipients")
	case !backupDirectory(settings.Dir):
		return invalid("backup.dir")
	case settings.Keep < 1 || settings.Keep > maxBackupKeep:
		return invalid("backup.keep")
	case backup.TextfileDir != "" && !backupDirectory(backup.TextfileDir):
		return invalid("backup.textfile_dir")
	}
	seen := map[string]bool{}
	for _, value := range backup.Recipients {
		if _, err := age.ParseX25519Recipient(value); err != nil || seen[value] {
			return invalid("backup.recipients")
		}
		seen[value] = true
	}
	if backup.S3 != nil {
		return backup.S3.validate()
	}
	return nil
}

func (target BackupS3) validate() error {
	endpoint, err := url.Parse(target.Endpoint)
	switch {
	case err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || (endpoint.Path != "" && endpoint.Path != "/") ||
		endpoint.RawQuery != "" || endpoint.User != nil || endpoint.Fragment != "":
		return invalid("backup.s3.endpoint")
	case !regionName.MatchString(target.Region):
		return invalid("backup.s3.region")
	case !bucketName.MatchString(target.Bucket):
		return invalid("backup.s3.bucket")
	case !keyPrefix.MatchString(target.Prefix) || strings.Contains(target.Prefix, ".."):
		return invalid("backup.s3.prefix")
	case !validPath(target.CredentialsFile):
		return invalid("backup.s3.credentials_file")
	}
	return nil
}

// backupDirectory accepts a clean absolute directory outside the paths
// setup owns: a backup kept in the state or operator directory would be
// restored over, or mounted into containers that must not see it.
func backupDirectory(value string) bool {
	if !validValue(value, 2, 1024) || !path.IsAbs(value) || path.Clean(value) != value || value == "/" ||
		strings.ContainsAny(value, " :,\"'\\") {
		return false
	}
	for _, owned := range []string{OperatorDir, "/var/lib/meshtransit", "/var/lib/docker"} {
		if value == owned || strings.HasPrefix(value, owned+"/") || strings.HasPrefix(owned, value+"/") {
			return false
		}
	}
	return true
}
