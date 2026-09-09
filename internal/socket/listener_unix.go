//go:build !windows

// Package socket creates and owns the daemon's local Unix listener.
package socket

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const socketMode = 0o660

// Listen creates a Unix stream socket without overwriting regular files or a live socket.
func Listen(path string) (net.Listener, error) {
	return listen(path, "unix")
}

func listen(path, network string) (net.Listener, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("socket path must be absolute")
	}

	dir := filepath.Dir(path)
	if err := ensureSocketDir(dir); err != nil {
		return nil, err
	}
	if err := clearStaleSocket(path, network); err != nil {
		return nil, err
	}

	listener, err := (&net.ListenConfig{}).Listen(context.Background(), network, path)
	if err != nil {
		return nil, fmt.Errorf("listening on unix socket: %w", err)
	}
	if err := os.Chmod(path, socketMode); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)

		return nil, fmt.Errorf("setting unix socket permissions: %w", err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		_ = listener.Close()
		_ = os.Remove(path)

		return nil, fmt.Errorf("inspecting created unix socket: %w", err)
	}

	return &ownedListener{
		Listener: listener,
		path:     path,
		info:     info,
	}, nil
}

type ownedListener struct {
	net.Listener
	path string
	info os.FileInfo
	once sync.Once
}

func (l *ownedListener) Close() error {
	var closeErr error
	l.once.Do(func() {
		closeErr = l.Listener.Close()
		current, err := os.Lstat(l.path)
		if err == nil && os.SameFile(current, l.info) {
			removeErr := os.Remove(l.path)
			closeErr = errors.Join(closeErr, removeErr)
		}
	})

	return closeErr
}

func ensureSocketDir(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("creating socket directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspecting socket directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("socket parent must be a directory, not a link")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("socket directory permissions %04o permit writes by group or others", info.Mode().Perm())
	}

	return nil
}

func clearStaleSocket(path, network string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspecting existing socket path: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return errors.New("socket path exists and is not a unix socket")
	}

	dialer := &net.Dialer{Timeout: 200 * time.Millisecond}
	connection, dialErr := dialer.DialContext(context.Background(), network, path)
	if dialErr == nil {
		_ = connection.Close()

		return errors.New("another meshd instance is already listening")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("removing stale unix socket: %w", err)
	}

	return nil
}
