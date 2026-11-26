package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Suffix ends every backup file's name.
const Suffix = ".mtbackup"

// fileName is meshtransit-<deployment>-<UTC>.mtbackup: names sort by time.
var fileName = regexp.MustCompile(`^meshtransit-([a-z0-9][a-z0-9_-]{0,62})-(\d{8}T\d{6}Z)\.mtbackup$`)

// Name is the backup file's name for a Deployment at a time.
func Name(deploymentID string, at time.Time) string {
	return "meshtransit-" + strings.ToLower(deploymentID) + "-" + at.UTC().Format("20060102T150405Z") + Suffix
}

// Pending is a backup file being written: a hidden temporary name in the
// backup directory, renamed only when Commit has synced it.
type Pending struct {
	dir, name, temporary string
	file                 *os.File
	digest               hash.Hash
	size                 int64
}

// Create starts a backup file in dir. The directory must be a real
// directory (not a link) that only root can enter.
func Create(dir, name string) (*Pending, error) {
	if err := checkDir(dir); err != nil {
		return nil, err
	}
	if !fileName.MatchString(name) {
		return nil, fmt.Errorf("%w: backup name %q", ErrInvalid, name)
	}
	temporary := filepath.Join(dir, "."+name+".partial")
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollow, 0o600) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("create backup file: %w", err)
	}
	return &Pending{dir: dir, name: name, temporary: temporary, file: file, digest: sha256.New()}, nil
}

func (pending *Pending) Write(p []byte) (int, error) {
	written, err := pending.file.Write(p)
	pending.digest.Write(p[:written])
	pending.size += int64(written)
	return written, err
}

// Commit syncs the file, renames it into place and syncs the directory. It
// returns the final path, the size and the file's SHA-256.
func (pending *Pending) Commit() (string, int64, string, error) {
	if err := pending.file.Sync(); err != nil {
		pending.Abort()
		return "", 0, "", fmt.Errorf("sync backup: %w", err)
	}
	if err := pending.file.Close(); err != nil {
		pending.Abort()
		return "", 0, "", fmt.Errorf("close backup: %w", err)
	}
	final := filepath.Join(pending.dir, pending.name)
	if err := os.Rename(pending.temporary, final); err != nil {
		_ = os.Remove(pending.temporary)
		return "", 0, "", fmt.Errorf("rename backup: %w", err)
	}
	if err := syncDir(pending.dir); err != nil {
		return "", 0, "", err
	}
	return final, pending.size, hex.EncodeToString(pending.digest.Sum(nil)), nil
}

// Abort removes the temporary file.
func (pending *Pending) Abort() {
	_ = pending.file.Close()
	_ = os.Remove(pending.temporary)
}

// partialAge is how old a partial file must be before Prune removes it: a
// run in progress (the unit allows four hours) keeps its own.
const partialAge = 5 * time.Hour

// Prune keeps the newest keep backups of deploymentID in dir and removes
// older ones. It never removes current (the file this run just wrote), even
// when a clock set back makes older runs sort after it. Only names this
// package writes are touched, never through a link. It also removes
// partial files a killed run left behind, once older than any run.
func Prune(dir, deploymentID string, keep int, current string, now time.Time) ([]string, error) {
	if keep < 1 {
		return nil, fmt.Errorf("%w: keep %d", ErrInvalid, keep)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("list backups: %w", err)
	}
	var mine []string
	var removed []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".meshtransit-") && strings.HasSuffix(name, Suffix+".partial") &&
			entry.Type().IsRegular() {
			if info, err := entry.Info(); err == nil && now.Sub(info.ModTime()) > partialAge &&
				os.Remove(filepath.Join(dir, name)) == nil {
				removed = append(removed, name)
			}
			continue
		}
		match := fileName.FindStringSubmatch(name)
		if match == nil || match[1] != strings.ToLower(deploymentID) || !entry.Type().IsRegular() || name == current {
			continue
		}
		mine = append(mine, name)
	}
	sort.Strings(mine)
	// current counts as one of the keep.
	for len(mine) > keep-1 {
		if err := os.Remove(filepath.Join(dir, mine[0])); err != nil {
			return removed, fmt.Errorf("prune %s: %w", mine[0], err)
		}
		removed = append(removed, mine[0])
		mine = mine[1:]
	}
	return removed, syncDir(dir)
}

// checkDir requires an absolute, real directory without access for group
// or others (it holds every secret, encrypted).
func checkDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("%w: backup directory must be absolute", ErrInvalid)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("backup directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s must be a directory of mode 0700", ErrInvalid, dir)
	}
	return nil
}

func syncDir(dir string) error {
	handle, err := os.Open(dir) // #nosec G304 -- the backup directory.
	if err != nil {
		return fmt.Errorf("sync backup directory: %w", err)
	}
	defer func() { _ = handle.Close() }()
	if err := handle.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) {
		return fmt.Errorf("sync backup directory: %w", err)
	}
	return nil
}

// Status is what the last run did, kept in status.json and exported as a
// node_exporter textfile.
type Status struct {
	LastAttempt        time.Time `json:"last_attempt"`
	LastSuccess        time.Time `json:"last_success,omitzero"`
	LastResult         string    `json:"last_result"` // "ok" or an error code
	File               string    `json:"file,omitempty"`
	SHA256             string    `json:"sha256,omitempty"`
	Size               int64     `json:"size,omitempty"`
	DurationSeconds    float64   `json:"duration_seconds,omitempty"`
	OffsiteLastSuccess time.Time `json:"offsite_last_success,omitzero"`
	Offsite            bool      `json:"offsite"`
}

// StatusName is the status file in the backup directory.
const StatusName = "status.json"

// ReadStatus reads status.json; a missing file is an empty status.
func ReadStatus(dir string) (Status, error) {
	body, err := os.ReadFile(filepath.Join(dir, StatusName)) // #nosec G304 -- the backup directory.
	if errors.Is(err, os.ErrNotExist) {
		return Status{}, nil
	}
	if err != nil {
		return Status{}, fmt.Errorf("read backup status: %w", err)
	}
	var status Status
	if err := json.Unmarshal(body, &status); err != nil {
		return Status{}, fmt.Errorf("read backup status: %w", err)
	}
	return status, nil
}

// WriteStatus replaces status.json and, when textfileDir is set, the
// node_exporter textfile meshtransit_backup.prom, each atomically.
func WriteStatus(dir, textfileDir string, status Status) error {
	body, err := json.MarshalIndent(status, "", " ")
	if err != nil {
		return fmt.Errorf("backup status: %w", err)
	}
	if err := replaceFile(dir, StatusName, append(body, '\n'), 0o600); err != nil {
		return err
	}
	if textfileDir == "" {
		return nil
	}
	return replaceFile(textfileDir, "meshtransit_backup.prom", []byte(Metrics(status)), 0o644)
}

// Metrics renders the status in the Prometheus text format. A time never
// reached is left out, so an alert on its age fires on absence instead of
// on a 1970 value.
func Metrics(status Status) string {
	var lines []string
	gauge := func(name, help string, value float64) {
		lines = append(lines, "# HELP "+name+" "+help, "# TYPE "+name+" gauge", fmt.Sprintf("%s %g", name, value))
	}
	unix := func(at time.Time) float64 { return float64(at.Unix()) }
	gauge("meshtransit_backup_configured", "Whether nightly backups are enabled on this server.", 1)
	if !status.LastAttempt.IsZero() {
		gauge("meshtransit_backup_last_attempt_timestamp_seconds", "When the last backup run ended.",
			unix(status.LastAttempt))
		result := 0.0
		if status.LastResult == "ok" {
			result = 1
		}
		gauge("meshtransit_backup_last_result", "Whether the last backup run succeeded (1) or failed (0).", result)
	}
	if !status.LastSuccess.IsZero() {
		gauge("meshtransit_backup_last_success_timestamp_seconds", "When the last good backup was written.",
			unix(status.LastSuccess))
		gauge("meshtransit_backup_size_bytes", "Size of the last good backup file.", float64(status.Size))
		gauge("meshtransit_backup_duration_seconds", "How long the last good backup took.", status.DurationSeconds)
	}
	if status.Offsite {
		gauge("meshtransit_backup_offsite_configured", "Whether backups are copied off the server.", 1)
		if !status.OffsiteLastSuccess.IsZero() {
			gauge("meshtransit_backup_offsite_last_success_timestamp_seconds",
				"When the last backup reached the off-server copy.", unix(status.OffsiteLastSuccess))
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

func replaceFile(dir, name string, body []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	cleanup := func() { _ = os.Remove(temporary.Name()) }
	if _, err := io.Copy(temporary, strings.NewReader(string(body))); err != nil {
		_ = temporary.Close()
		cleanup()
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		cleanup()
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		cleanup()
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := temporary.Close(); err != nil {
		cleanup()
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := os.Rename(temporary.Name(), filepath.Join(dir, name)); err != nil {
		cleanup()
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

// OpenRegular opens a regular file for reading, never through a final
// link and never blocking on a FIFO.
func OpenRegular(location string) (*os.File, error) {
	file, err := os.OpenFile(location, os.O_RDONLY|openSafely, 0) // #nosec G304 -- operator-named files.
	if err != nil {
		return nil, err
	}
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrInvalid, location)
	}
	return file, nil
}
