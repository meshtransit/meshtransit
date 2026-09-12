package hostcred

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/meshtransit/meshd/internal/secretstore"
)

var (
	// ErrRotationPending indicates that the active credential still retains a fallback key.
	ErrRotationPending = errors.New("hostcred: identity-key rotation is pending")
	// ErrRotationNotPending indicates that there is no fallback key to finalize.
	ErrRotationNotPending = errors.New("hostcred: identity-key rotation is not pending")
	// ErrRecoveryAvailable prevents provisioning a new key over recoverable state.
	ErrRecoveryAvailable = errors.New("hostcred: identity-key recovery copy is available")
	// ErrRecoveryMissing indicates that the durable rotation recovery copy is absent.
	ErrRecoveryMissing = errors.New("hostcred: identity-key recovery copy is missing")
	// ErrRecoveryInvalid indicates that primary and recovery state do not form a safe transaction.
	ErrRecoveryInvalid = errors.New("hostcred: identity-key recovery state is invalid")
)

// ActiveVerifier proves that persistent identity records are readable with the
// supplied active key. The key is borrowed only for the duration of the call
// and must not be retained.
type ActiveVerifier func(context.Context, []byte) error

// Rotate stages a fresh active key with the current key as its read-only
// fallback. A verified host-encrypted recovery copy is installed before the
// primary credential is atomically replaced.
func Rotate(ctx context.Context, cfg Config) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("rotating host credential: %w", err)
	}
	var err error
	cfg, err = normalizeConfig(cfg)
	if err != nil {
		return err
	}
	if err := prepareBackend(ctx, cfg); err != nil {
		return err
	}

	current, err := decryptCredential(ctx, cfg, cfg.Path)
	if err != nil {
		return err
	}
	defer clear(current)
	hasFallback, err := secretstore.CredentialHasFallback(current)
	if err != nil {
		return ErrRecoveryInvalid
	}
	if hasFallback {
		return ErrRotationPending
	}

	if _, err := os.Lstat(cfg.RecoveryPath); err == nil {
		return resumeRotation(ctx, cfg, current)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspecting identity-key recovery copy: %w", err)
	}

	newKey := make([]byte, secretstore.KeySize)
	if _, err := io.ReadFull(cfg.Random, newKey); err != nil {
		clear(newKey)

		return fmt.Errorf("reading identity-key rotation randomness: %w", err)
	}
	defer clear(newKey)
	keySet, err := secretstore.EncodeKeySet(newKey, current)
	if err != nil {
		return fmt.Errorf("building identity-key rotation credential: %w", err)
	}
	defer clear(keySet)

	temporaryPath, err := encryptTemporary(ctx, cfg, keySet)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := os.Link(temporaryPath, cfg.RecoveryPath); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrRecoveryInvalid
		}

		return fmt.Errorf("installing identity-key recovery copy: %w", err)
	}
	if err := syncDirectory(filepath.Dir(cfg.Path)); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, cfg.Path); err != nil {
		return fmt.Errorf("activating identity-key rotation credential: %w", err)
	}

	return syncDirectory(filepath.Dir(cfg.Path))
}

func resumeRotation(ctx context.Context, cfg Config, current []byte) error {
	recovery, err := decryptCredential(ctx, cfg, cfg.RecoveryPath)
	if err != nil {
		return fmt.Errorf("validating identity-key recovery copy: %w", err)
	}
	defer clear(recovery)
	matches, err := secretstore.CredentialFallbackMatches(recovery, current)
	if err != nil || !matches {
		return ErrRecoveryInvalid
	}

	return replaceWithLinkedCopy(cfg.RecoveryPath, cfg.Path)
}

// Finalize removes the fallback from the primary credential only after the
// caller proves that every identity is readable by the active key. The durable
// recovery copy remains until Commit succeeds.
func Finalize(ctx context.Context, cfg Config, verify ActiveVerifier) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("finalizing host credential rotation: %w", err)
	}
	if verify == nil {
		return errors.New("hostcred: active-key verifier is required")
	}
	var err error
	cfg, err = normalizeConfig(cfg)
	if err != nil {
		return err
	}
	if err := prepareBackend(ctx, cfg); err != nil {
		return err
	}

	current, err := decryptCredential(ctx, cfg, cfg.Path)
	if err != nil {
		return err
	}
	defer clear(current)
	hasFallback, err := secretstore.CredentialHasFallback(current)
	if err != nil {
		return ErrRecoveryInvalid
	}
	if !hasFallback {
		return ErrRotationNotPending
	}
	if err := verifyRecoveryMatches(ctx, cfg, current); err != nil {
		return err
	}

	activeKey, err := secretstore.CopyActiveKey(current)
	if err != nil {
		return ErrRecoveryInvalid
	}
	defer clear(activeKey)
	if err := verify(ctx, activeKey); err != nil {
		return fmt.Errorf("verifying identities with active key: %w", err)
	}

	temporaryPath, err := encryptTemporary(ctx, cfg, activeKey)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := os.Rename(temporaryPath, cfg.Path); err != nil {
		return fmt.Errorf("finalizing identity-key credential: %w", err)
	}

	return syncDirectory(filepath.Dir(cfg.Path))
}

// Commit removes the recovery copy after both the active credential and every
// identity record have been verified. It is the only operation that deletes
// fallback key material.
func Commit(ctx context.Context, cfg Config, verify ActiveVerifier) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("committing host credential rotation: %w", err)
	}
	if verify == nil {
		return errors.New("hostcred: active-key verifier is required")
	}
	var err error
	cfg, err = normalizeConfig(cfg)
	if err != nil {
		return err
	}
	if err := prepareBackend(ctx, cfg); err != nil {
		return err
	}

	current, err := decryptCredential(ctx, cfg, cfg.Path)
	if err != nil {
		return err
	}
	defer clear(current)
	hasFallback, err := secretstore.CredentialHasFallback(current)
	if err != nil {
		return ErrRecoveryInvalid
	}
	if hasFallback {
		return ErrRotationPending
	}

	recovery, err := decryptCredential(ctx, cfg, cfg.RecoveryPath)
	if errors.Is(err, os.ErrNotExist) {
		return ErrRecoveryMissing
	}
	if err != nil {
		return fmt.Errorf("validating identity-key recovery copy: %w", err)
	}
	defer clear(recovery)
	recoveryHasFallback, err := secretstore.CredentialHasFallback(recovery)
	if err != nil || !recoveryHasFallback {
		return ErrRecoveryInvalid
	}
	recoveryActive, err := secretstore.CopyActiveKey(recovery)
	if err != nil {
		return ErrRecoveryInvalid
	}
	defer clear(recoveryActive)
	if subtle.ConstantTimeCompare(current, recoveryActive) != 1 {
		return ErrRecoveryInvalid
	}
	if err := verify(ctx, current); err != nil {
		return fmt.Errorf("verifying identities with active key: %w", err)
	}
	if err := os.Remove(cfg.RecoveryPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrRecoveryMissing
		}

		return fmt.Errorf("removing identity-key recovery copy: %w", err)
	}

	return syncDirectory(filepath.Dir(cfg.Path))
}

// Recover atomically restores the verified host-encrypted recovery copy as the
// primary credential. It never removes the recovery copy.
func Recover(ctx context.Context, cfg Config) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("recovering host credential: %w", err)
	}
	var err error
	cfg, err = normalizeConfig(cfg)
	if err != nil {
		return err
	}
	if err := prepareBackend(ctx, cfg); err != nil {
		return err
	}
	recovery, err := decryptCredential(ctx, cfg, cfg.RecoveryPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrRecoveryMissing
		}

		return fmt.Errorf("validating identity-key recovery copy: %w", err)
	}
	hasFallback, err := secretstore.CredentialHasFallback(recovery)
	if err != nil || !hasFallback {
		clear(recovery)

		return ErrRecoveryInvalid
	}
	clear(recovery)
	if info, err := os.Lstat(cfg.Path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return ErrRecoveryInvalid
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspecting primary identity credential: %w", err)
	}

	return replaceWithLinkedCopy(cfg.RecoveryPath, cfg.Path)
}

func verifyRecoveryMatches(ctx context.Context, cfg Config, current []byte) error {
	recovery, err := decryptCredential(ctx, cfg, cfg.RecoveryPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrRecoveryMissing
		}

		return fmt.Errorf("validating identity-key recovery copy: %w", err)
	}
	defer clear(recovery)
	if len(current) != len(recovery) || subtle.ConstantTimeCompare(current, recovery) != 1 {
		return ErrRecoveryInvalid
	}

	return nil
}

func decryptCredential(ctx context.Context, cfg Config, path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if err := validateCredentialInfo(info); err != nil {
		return nil, err
	}

	credential := &boundedBuffer{maximum: secretstore.MaxCredentialSize}
	if err := cfg.run(
		ctx,
		systemdToolPath,
		[]string{"--no-pager", "--name=" + fileName, "decrypt", path, "-"},
		nil,
		credential,
	); err != nil {
		credential.Clear()

		return nil, fmt.Errorf("decrypting identity credential: %w", err)
	}
	defer credential.Clear()
	encoded := append([]byte(nil), credential.Bytes()...)
	if _, err := secretstore.CredentialHasFallback(encoded); err != nil {
		clear(encoded)

		return nil, errors.New("hostcred: encrypted identity credential has an invalid format")
	}

	return encoded, nil
}

func encryptTemporary(ctx context.Context, cfg Config, plaintext []byte) (string, error) {
	if _, err := secretstore.CredentialHasFallback(plaintext); err != nil {
		return "", errors.New("hostcred: refusing invalid identity credential plaintext")
	}
	temporary, err := os.CreateTemp(filepath.Dir(cfg.Path), ".meshd.identity-key-*.tmp")
	if err != nil {
		return "", fmt.Errorf("reserving encrypted credential path: %w", err)
	}
	temporaryPath := temporary.Name()
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)

		return "", fmt.Errorf("closing encrypted credential reservation: %w", err)
	}
	if err := os.Remove(temporaryPath); err != nil {
		return "", fmt.Errorf("releasing encrypted credential reservation: %w", err)
	}
	removeOnError := true
	defer func() {
		if removeOnError {
			_ = os.Remove(temporaryPath)
		}
	}()

	if err := cfg.run(
		ctx,
		systemdToolPath,
		[]string{
			"--no-pager",
			"--with-key=host",
			"--name=" + fileName,
			"encrypt",
			"-",
			temporaryPath,
		},
		bytes.NewReader(plaintext),
		io.Discard,
	); err != nil {
		return "", fmt.Errorf("encrypting identity credential: %w", err)
	}
	info, err := os.Lstat(temporaryPath)
	if err != nil {
		return "", fmt.Errorf("inspecting new encrypted identity credential: %w", err)
	}
	if err := validateCredentialShape(info); err != nil {
		return "", err
	}
	if err := os.Chmod(temporaryPath, 0o600); err != nil {
		return "", fmt.Errorf("restricting encrypted identity credential: %w", err)
	}
	if err := syncRegularFile(temporaryPath); err != nil {
		return "", err
	}
	if err := verifyCredential(ctx, cfg, temporaryPath, plaintext); err != nil {
		return "", err
	}

	removeOnError = false

	return temporaryPath, nil
}

func replaceWithLinkedCopy(source, destination string) error {
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".meshd.identity-key-link-*.tmp")
	if err != nil {
		return fmt.Errorf("reserving credential recovery path: %w", err)
	}
	temporaryPath := temporary.Name()
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)

		return fmt.Errorf("closing credential recovery reservation: %w", err)
	}
	if err := os.Remove(temporaryPath); err != nil {
		return fmt.Errorf("releasing credential recovery reservation: %w", err)
	}
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := os.Link(source, temporaryPath); err != nil {
		return fmt.Errorf("linking credential recovery copy: %w", err)
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return fmt.Errorf("restoring credential recovery copy: %w", err)
	}

	return syncDirectory(filepath.Dir(destination))
}

func syncRegularFile(path string) (syncErr error) {
	file, err := os.Open(path) //nolint:gosec // The path is a same-directory temporary file.
	if err != nil {
		return fmt.Errorf("opening encrypted credential for sync: %w", err)
	}
	defer func() { syncErr = errors.Join(syncErr, file.Close()) }()
	if err := file.Sync(); err != nil {
		return fmt.Errorf("syncing encrypted identity credential: %w", err)
	}

	return nil
}
