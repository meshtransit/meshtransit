package selfhost

import (
	"fmt"
	"os"
	"path/filepath"
)

// PrepareOperatorFiles makes the operator's directory and the secret files
// config.yaml names readable by the image user and nobody else: the
// directory root-owned with the image group (0750), each file owned by the
// image user (0600). A link or a non-regular file is refused. Without an
// owner (not root) it only checks.
func PrepareOperatorFiles(config Config, owner *Owner) error {
	paths := []string{config.Login.ClientSecretFile}
	if config.Mail != nil && config.Mail.SMTP.PasswordFile != "" {
		paths = append(paths, config.Mail.SMTP.PasswordFile)
	}
	info, err := os.Lstat(OperatorDir)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("%w: %s must be a directory", ErrSecrets, OperatorDir)
	}
	if owner != nil {
		if err := os.Chown(OperatorDir, 0, owner.GID); err != nil {
			return fmt.Errorf("%w: chown %s: %w", ErrSecrets, OperatorDir, err)
		}
		if err := os.Chmod(OperatorDir, 0o750); err != nil { // #nosec G302 -- a directory the image group must enter.
			return fmt.Errorf("%w: chmod %s: %w", ErrSecrets, OperatorDir, err)
		}
	}
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
			return fmt.Errorf("%w: %s must be a regular file of at most 4 KiB", ErrSecrets, filepath.Base(path))
		}
		if owner == nil {
			continue
		}
		if err := os.Lchown(path, owner.UID, owner.GID); err != nil {
			return fmt.Errorf("%w: chown %s: %w", ErrSecrets, filepath.Base(path), err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("%w: chmod %s: %w", ErrSecrets, filepath.Base(path), err)
		}
	}
	return nil
}
