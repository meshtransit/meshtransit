//go:build unix

package selfhost

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// readRegularFile reads a regular file of at most limit bytes without
// following a symbolic link: setup runs as root over directories the image
// user owns.
func readRegularFile(path string, limit int64) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- setup's own directories.
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("%s: not a regular file of at most %d bytes", filepath.Base(path), limit)
	}
	return io.ReadAll(io.LimitReader(file, limit+1))
}

// LockSetup takes stateDir's setup lock, so two setup runs never interleave
// (a CA written by one and leaves signed by the other). It fails at once
// when another run holds the lock. The returned function releases it.
func LockSetup(stateDir string) (func(), error) {
	if !filepath.IsAbs(stateDir) {
		return nil, fmt.Errorf("%w: state directory must be absolute", ErrSecrets)
	}
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return nil, fmt.Errorf("%w: create state directory: %w", ErrSecrets, err)
	}
	file, err := os.OpenFile(filepath.Join(stateDir, ".setup.lock"),
		os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- the state directory.
	if err != nil {
		return nil, fmt.Errorf("%w: open lock: %w", ErrSecrets, err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { // #nosec G115 -- a file descriptor.
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: another setup run holds the lock", ErrSecrets)
		}
		return nil, fmt.Errorf("%w: lock: %w", ErrSecrets, err)
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN) // #nosec G115 -- a file descriptor.
		_ = file.Close()
	}, nil
}
