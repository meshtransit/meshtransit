// Package hostcred provisions the host-bound systemd credential that protects
// MeshTransit identity records on Linux.
package hostcred

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/meshtransit/meshd/internal/secretstore"
)

const (
	defaultPath            = "/etc/credstore.encrypted/meshd.identity-key"
	systemdToolPath        = "/usr/bin/systemd-creds"
	fileName               = "meshd.identity-key"
	maximumCredentialBytes = 64 << 10
)

type commandRunner func(
	context.Context,
	string,
	[]string,
	io.Reader,
	io.Writer,
) error

// Config contains the fixed provisioning boundaries. Non-default values are
// intended for deterministic tests, not the packaged command.
type Config struct {
	Path         string
	RecoveryPath string
	Random       io.Reader
	run          commandRunner
}

// Provision creates the encrypted host credential once, verifies that systemd
// can recover the exact key, and refuses unsafe existing paths.
func Provision(ctx context.Context, cfg Config) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("provisioning host credential: %w", err)
	}
	var err error
	cfg, err = normalizeConfig(cfg)
	if err != nil {
		return err
	}
	if err := prepareBackend(ctx, cfg); err != nil {
		return err
	}

	info, err := os.Lstat(cfg.Path)
	if err == nil {
		if err := validateCredentialInfo(info); err != nil {
			return err
		}

		return verifyExisting(ctx, cfg)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspecting encrypted identity credential: %w", err)
	}
	if _, recoveryErr := os.Lstat(cfg.RecoveryPath); recoveryErr == nil {
		return ErrRecoveryAvailable
	} else if !errors.Is(recoveryErr, os.ErrNotExist) {
		return fmt.Errorf("inspecting identity credential recovery copy: %w", recoveryErr)
	}

	return createCredential(ctx, cfg)
}

func normalizeConfig(cfg Config) (Config, error) {
	if cfg.Path == "" {
		cfg.Path = defaultPath
	}
	if cfg.RecoveryPath == "" {
		cfg.RecoveryPath = cfg.Path + ".recovery"
	}
	if cfg.Random == nil {
		cfg.Random = rand.Reader
	}
	if cfg.run == nil {
		cfg.run = runCommand
	}
	if err := validateConfig(cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func prepareBackend(ctx context.Context, cfg Config) error {
	if err := prepareCredentialDirectory(filepath.Dir(cfg.Path)); err != nil {
		return err
	}
	if err := cfg.run(
		ctx,
		systemdToolPath,
		[]string{"--no-pager", "setup"},
		nil,
		io.Discard,
	); err != nil {
		return fmt.Errorf("initializing systemd host credential key: %w", err)
	}

	return nil
}

func validateConfig(cfg Config) error {
	if !filepath.IsAbs(cfg.Path) ||
		filepath.Clean(cfg.Path) == string(filepath.Separator) {
		return errors.New("hostcred: credential path must be an absolute file")
	}
	if !filepath.IsAbs(cfg.RecoveryPath) ||
		filepath.Clean(cfg.RecoveryPath) == string(filepath.Separator) ||
		filepath.Clean(cfg.RecoveryPath) == filepath.Clean(cfg.Path) ||
		filepath.Dir(filepath.Clean(cfg.RecoveryPath)) != filepath.Dir(filepath.Clean(cfg.Path)) {
		return errors.New("hostcred: recovery path must be a different file in the credential directory")
	}

	return nil
}

func prepareCredentialDirectory(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating encrypted credential directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspecting encrypted credential directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("hostcred: credential directory must not be a link")
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // Directories require execute bits.
		return fmt.Errorf("restricting encrypted credential directory: %w", err)
	}

	return nil
}

func createCredential(ctx context.Context, cfg Config) error {
	key := make([]byte, secretstore.KeySize)
	if _, err := io.ReadFull(cfg.Random, key); err != nil {
		clear(key)

		return fmt.Errorf("reading identity-key randomness: %w", err)
	}
	defer clear(key)

	temporaryPath, err := encryptTemporary(ctx, cfg, key)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := os.Link(temporaryPath, cfg.Path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return verifyExisting(ctx, cfg)
		}

		return fmt.Errorf("installing encrypted identity credential: %w", err)
	}
	if err := os.Remove(temporaryPath); err != nil {
		return fmt.Errorf("removing linked credential temporary file: %w", err)
	}

	return syncDirectory(filepath.Dir(cfg.Path))
}

func verifyExisting(ctx context.Context, cfg Config) error {
	credential := &boundedBuffer{maximum: secretstore.MaxCredentialSize}
	if err := cfg.run(
		ctx,
		systemdToolPath,
		[]string{"--no-pager", "--name=" + fileName, "decrypt", cfg.Path, "-"},
		nil,
		credential,
	); err != nil {
		credential.Clear()

		return fmt.Errorf("verifying encrypted identity credential: %w", err)
	}
	defer credential.Clear()
	protector, err := secretstore.NewFromCredential(credential.Bytes())
	if err != nil {
		return errors.New("hostcred: encrypted identity credential has an invalid format")
	}
	defer func() { _ = protector.Close() }()

	return nil
}

func verifyCredential(
	ctx context.Context,
	cfg Config,
	path string,
	expected []byte,
) error {
	decrypted := &boundedBuffer{maximum: secretstore.MaxCredentialSize}
	if err := cfg.run(
		ctx,
		systemdToolPath,
		[]string{"--no-pager", "--name=" + fileName, "decrypt", path, "-"},
		nil,
		decrypted,
	); err != nil {
		decrypted.Clear()

		return fmt.Errorf("verifying new encrypted identity credential: %w", err)
	}
	decryptedBytes := decrypted.Bytes()
	defer decrypted.Clear()
	if len(decryptedBytes) != len(expected) ||
		subtle.ConstantTimeCompare(decryptedBytes, expected) != 1 {
		return errors.New("hostcred: encrypted identity credential did not round trip")
	}

	return nil
}

func validateCredentialInfo(info os.FileInfo) error {
	if err := validateCredentialShape(info); err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("hostcred: encrypted identity credential permissions are too broad")
	}

	return nil
}

func validateCredentialShape(info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("hostcred: encrypted identity credential must be a regular file")
	}
	if info.Size() <= 0 || info.Size() > maximumCredentialBytes {
		return errors.New("hostcred: encrypted identity credential has an invalid size")
	}
	return nil
}

func syncDirectory(path string) (syncErr error) {
	directory, err := os.Open(path) //nolint:gosec // The path is fixed or validated configuration.
	if err != nil {
		return fmt.Errorf("opening encrypted credential directory for sync: %w", err)
	}
	defer func() { syncErr = errors.Join(syncErr, directory.Close()) }()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("syncing encrypted credential directory: %w", err)
	}

	return nil
}

func runCommand(
	ctx context.Context,
	name string,
	args []string,
	stdin io.Reader,
	stdout io.Writer,
) error {
	if name != systemdToolPath {
		return errors.New("hostcred: refusing untrusted credential command")
	}
	//nolint:gosec // The executable is fixed and callers construct the bounded argument sets internally.
	command := exec.CommandContext(ctx, systemdToolPath, args...)
	command.Stdin = stdin
	command.Stdout = stdout
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return fmt.Errorf("running trusted credential command: %w", err)
	}

	return nil
}

type boundedBuffer struct {
	buffer  bytes.Buffer
	maximum int
}

func (b *boundedBuffer) Write(input []byte) (int, error) {
	if b == nil || len(input) > b.maximum-b.buffer.Len() {
		return 0, errors.New("hostcred: decrypted credential exceeds size limit")
	}

	return b.buffer.Write(input)
}

func (b *boundedBuffer) Bytes() []byte {
	if b == nil {
		return nil
	}

	return b.buffer.Bytes()
}

func (b *boundedBuffer) Clear() {
	if b == nil {
		return
	}
	clear(b.buffer.Bytes())
	b.buffer.Reset()
}
