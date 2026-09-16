package config

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
)

type privateIdentityKeySnapshot struct {
	reference SecretFile
	info      os.FileInfo
}

func (reference SecretFile) readPrivateIdentityKey(ctx context.Context) ([32]byte, error) {
	result, _, err := reference.readPrivateIdentityKeySnapshot(ctx)
	return result, err
}

func (reference SecretFile) readPrivateIdentityKeySnapshot(
	ctx context.Context,
) (result [32]byte, snapshot privateIdentityKeySnapshot, resultErr error) {
	validPath := len(reference.path) <= 4096 && validateFilePath(reference.path) == nil
	if ctx == nil || ctx.Err() != nil || !validPath {
		return result, snapshot, ErrInvalid
	}
	// #nosec G304 -- bounded canonical operator reference, scoped to its parent.
	root, err := os.OpenRoot(filepath.Dir(reference.path))
	if err != nil {
		return result, snapshot, ErrInvalid
	}
	defer func() {
		if root.Close() != nil || ctx.Err() != nil {
			resultErr = ErrInvalid
		}
		if resultErr != nil {
			clear(result[:])
			snapshot = privateIdentityKeySnapshot{}
		}
	}()
	name := filepath.Base(reference.path)
	file, err := openPrivateIdentityKey(root, name)
	if err != nil {
		return result, snapshot, ErrInvalid
	}
	before, statErr := file.Stat()
	if statErr != nil || !validPrivateKeyFileInfo(before) || ctx.Err() != nil {
		if file.Close() != nil {
			return result, snapshot, ErrInvalid
		}
		return result, snapshot, ErrInvalid
	}
	contents, readErr := io.ReadAll(io.LimitReader(file, 46))
	defer clear(contents)
	after, afterErr := file.Stat()
	current, currentErr := root.Stat(name)
	closeErr := file.Close()
	failedIO := readErr != nil || afterErr != nil || currentErr != nil || closeErr != nil
	if failedIO || ctx.Err() != nil {
		return result, snapshot, ErrInvalid
	}
	if !unchangedPrivateKeyFile(before, after) || !unchangedPrivateKeyFile(after, current) ||
		int64(len(contents)) != before.Size() {
		return result, snapshot, ErrInvalid
	}
	result, resultErr = decodePrivateIdentityKey(contents)
	if resultErr == nil {
		snapshot = privateIdentityKeySnapshot{reference: reference, info: after}
	}
	return result, snapshot, resultErr
}

// Check every previously loaded path after the complete read, without reloading
// or merging new key material. Detect ordinary projected-mount rotation, not a
// privileged writer restoring inode metadata or a global filesystem transaction.
func (snapshot privateIdentityKeySnapshot) stillCurrent(ctx context.Context) (valid bool) {
	if ctx == nil || ctx.Err() != nil || snapshot.info == nil {
		return false
	}
	// #nosec G304 -- snapshot reference came from the validated bounded profile.
	root, err := os.OpenRoot(filepath.Dir(snapshot.reference.path))
	if err != nil {
		return false
	}
	defer func() {
		if root.Close() != nil || ctx.Err() != nil {
			valid = false
		}
	}()
	current, err := root.Stat(filepath.Base(snapshot.reference.path))
	return err == nil && unchangedPrivateKeyFile(snapshot.info, current)
}

func validPrivateKeyFileInfo(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() {
		return false
	}
	validMode := info.Mode() == 0o400 || info.Mode() == 0o600
	return validMode && info.Size() >= 43 && info.Size() <= 45
}

func unchangedPrivateKeyFile(before, after os.FileInfo) bool {
	return validPrivateKeyFileInfo(before) && validPrivateKeyFileInfo(after) &&
		os.SameFile(before, after) && before.Mode() == after.Mode() &&
		before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())
}

func decodePrivateIdentityKey(contents []byte) ([32]byte, error) {
	var decoded [32]byte
	if len(contents) < 43 || len(contents) > 45 {
		return decoded, ErrInvalid
	}
	contents = bytes.TrimSuffix(contents, []byte("\r\n"))
	contents = bytes.TrimSuffix(contents, []byte("\n"))
	if len(contents) != 43 {
		return decoded, ErrInvalid
	}
	for _, character := range contents {
		isLetterOrDigit := character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
		if !isLetterOrDigit && character != '-' && character != '_' {
			return decoded, ErrInvalid
		}
	}
	n, err := base64.RawURLEncoding.Strict().Decode(decoded[:], contents)
	var zero [32]byte
	if err != nil || n != 32 || subtle.ConstantTimeCompare(decoded[:], zero[:]) == 1 {
		clear(decoded[:])
		return decoded, ErrInvalid
	}
	return decoded, nil
}
