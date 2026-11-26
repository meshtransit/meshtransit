// Package backup writes and restores the one-server backup file (V1-51):
// age(zstd(tar)) holding PostgreSQL's base backup, secrets/, the operator's
// files and Caddy's data, with manifest.json last. The format streams: no
// member is buffered, and no plaintext reaches the disk on either side.
package backup

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"time"
)

// Format is the backup file format this package writes and reads.
const Format = 1

// Top-level directories of the archive; manifest.json is the last member.
const (
	PostgresDir  = "postgres"
	SecretsDir   = "secrets"
	OperatorDir  = "operator"
	CaddyDataDir = "caddy-data"
	ManifestName = "manifest.json"
)

var (
	// ErrInvalid reports a backup file this package refuses: unknown
	// format, unsafe member, missing or mismatching hash, or a manifest
	// that does not match the expected Deployment or image.
	ErrInvalid = errors.New("invalid backup")
	// ErrDatabase reports a PostgreSQL base backup stream that is
	// incomplete or does not match its own backup_manifest.
	ErrDatabase = errors.New("invalid database stream")
)

// Meta identifies where and how a backup was made.
type Meta struct {
	DeploymentID  string    `json:"deployment_id"`
	Created       time.Time `json:"created"`
	CoreVersion   string    `json:"core_version"`
	CoreRevision  string    `json:"core_revision"`
	CoreImage     string    `json:"core_image"`
	PostgresImage string    `json:"postgres_image"`
}

// Member is one archived file with its size and SHA-256.
type Member struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Postgres describes the base backup the archive holds.
type Postgres struct {
	Version          string `json:"pg_version"`
	SystemIdentifier uint64 `json:"system_identifier"`
	Files            int    `json:"files"`
}

// Manifest is manifest.json: the last member, naming every other one.
type Manifest struct {
	Format   int      `json:"format"`
	Meta     Meta     `json:"meta"`
	Postgres Postgres `json:"postgres"`
	Members  []Member `json:"members"`
	Secrets  []string `json:"secrets"`
}

// cleanName returns a member name that stays under one of the archive's
// top-level directories: relative, no "..", no empty or dot elements.
func cleanName(name string) (string, error) {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("%w: member name %q", ErrInvalid, name)
	}
	trimmed := strings.TrimSuffix(name, "/")
	if cleaned := path.Clean(trimmed); cleaned != trimmed || cleaned == "." {
		return "", fmt.Errorf("%w: member name %q", ErrInvalid, name)
	}
	for _, element := range strings.Split(trimmed, "/") {
		if element == ".." || element == "." || element == "" {
			return "", fmt.Errorf("%w: member name %q", ErrInvalid, name)
		}
	}
	top, _, _ := strings.Cut(trimmed, "/")
	switch top {
	case PostgresDir, SecretsDir, OperatorDir, CaddyDataDir:
		if top == trimmed {
			return "", fmt.Errorf("%w: member name %q", ErrInvalid, name)
		}
	case ManifestName:
	default:
		return "", fmt.Errorf("%w: member outside the archive's directories: %q", ErrInvalid, name)
	}
	return trimmed, nil
}
