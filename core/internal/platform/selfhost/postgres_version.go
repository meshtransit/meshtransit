package selfhost

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ErrPostgresMajorMismatch reports a data directory written by another
// PostgreSQL major version than the one this Core image runs: starting it
// would fail, or a downgrade would corrupt it. A release that changes the
// major ships its own pg_upgrade step; a restore runs with the backup's
// own Core image (V1-51).
var ErrPostgresMajorMismatch = errors.New("postgres data directory belongs to another PostgreSQL major version")

// PostgresMajor is the major version of the PostgreSQL image this Core
// image renders ("18" of postgres:18.6-…).
func PostgresMajor() string {
	tag := strings.TrimPrefix(postgresImage, "postgres:")
	major, _, _ := strings.Cut(tag, ".")
	return major
}

// CheckPostgresMajor refuses a data directory whose PG_VERSION names
// another major version. An absent directory or file (a new install)
// passes. The directory belongs to the PostgreSQL container's user: the file
// is read through an os.Root over postgres/ (no link can lead outside it),
// without blocking on a FIFO, at most 16 bytes, and a value that is not a
// version is not echoed.
func CheckPostgresMajor(stateDir string) error {
	root, err := os.OpenRoot(filepath.Join(stateDir, "postgres"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open postgres data: %w", err)
	}
	defer func() { _ = root.Close() }()
	file, err := root.OpenFile("pgdata/PG_VERSION", os.O_RDONLY|openSafely, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read PG_VERSION: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("%w: PG_VERSION is not a regular file", ErrPostgresMajorMismatch)
	}
	contents, err := io.ReadAll(io.LimitReader(file, 16))
	if err != nil {
		return fmt.Errorf("read PG_VERSION: %w", err)
	}
	found := strings.TrimSpace(string(contents))
	if !postgresMajorValue.MatchString(found) {
		return fmt.Errorf("%w: PG_VERSION does not hold a version", ErrPostgresMajorMismatch)
	}
	if found != PostgresMajor() {
		return fmt.Errorf("%w: data %s, image %s", ErrPostgresMajorMismatch, found, PostgresMajor())
	}
	return nil
}

var postgresMajorValue = regexp.MustCompile(`^[0-9]{1,3}$`)

// PostgresImage is the PostgreSQL image this Core image renders.
func PostgresImage() string { return postgresImage }
