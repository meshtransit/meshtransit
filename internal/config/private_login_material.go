package config

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

// PrivateLoginMaterial is an exclusively owned construction candidate. Clear it
// after constructors copy its bytes; this does not erase resident consumer copies.
type PrivateLoginMaterial struct {
	CertificatePEM, PrivateKeyPEM, ClientSecret []byte
}

// LoadMaterial reads only the profile's bounded protected local references.
func (profile *PrivateLoginConfig) LoadMaterial(ctx context.Context) (*PrivateLoginMaterial, error) {
	if profile == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, privateIdentityKeyTimeout)
	defer cancel()
	result := &PrivateLoginMaterial{}
	accepted := false
	defer func() {
		if !accepted {
			result.Clear()
		}
	}()
	for _, field := range []struct {
		file        SecretFile
		limit       int64
		destination *[]byte
	}{
		{file: profile.cert, limit: 64 * 1024, destination: &result.CertificatePEM},
		{file: profile.privateKey, limit: 64 * 1024, destination: &result.PrivateKeyPEM},
		{file: profile.clientSecret, limit: 4096, destination: &result.ClientSecret},
	} {
		contents, err := readPrivateLoginFile(ctx, field.file, field.limit)
		if err != nil {
			return nil, ErrInvalid
		}
		*field.destination = contents
	}
	if ctx.Err() != nil {
		return nil, ErrInvalid
	}
	accepted = true
	return result, nil
}

// Clear erases only this owner's temporary buffers, never shared resident keys.
func (material *PrivateLoginMaterial) Clear() {
	if material == nil {
		return
	}
	clear(material.CertificatePEM)
	clear(material.PrivateKeyPEM)
	clear(material.ClientSecret)
	material.CertificatePEM, material.PrivateKeyPEM, material.ClientSecret = nil, nil, nil
}

// Local trusted mounts are required: contexts cannot preempt filesystem syscalls.
// O_NONBLOCK avoids blocking FIFO opens on supported Linux/macOS targets. os.Root
// confines projected symlinks to the validated parent. No raw error is released.
func readPrivateLoginFile(ctx context.Context, reference SecretFile, limit int64) (result []byte, resultErr error) {
	validPath := len(reference.path) <= 4096 && validateFilePath(reference.path) == nil
	if ctx == nil || ctx.Err() != nil || !validPath || limit <= 0 || limit > 64*1024 {
		return nil, ErrInvalid
	}
	// #nosec G304 -- explicit canonical operator reference confined to its parent.
	root, err := os.OpenRoot(filepath.Dir(reference.path))
	if err != nil {
		return nil, ErrInvalid
	}
	defer func() {
		if root.Close() != nil || ctx.Err() != nil {
			resultErr = ErrInvalid
		}
		if resultErr != nil {
			clear(result)
			result = nil
		}
	}()
	name := filepath.Base(reference.path)
	file, err := openPrivateIdentityKey(root, name)
	if err != nil {
		return nil, ErrInvalid
	}
	before, err := file.Stat()
	if err != nil || !validPrivateLoginFileInfo(before, limit) {
		if file.Close() != nil {
			return nil, ErrInvalid
		}
		return nil, ErrInvalid
	}
	result, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	after, statErr := file.Stat()
	current, currentErr := root.Stat(name)
	closeErr := file.Close()
	failedIO := readErr != nil || statErr != nil || currentErr != nil || closeErr != nil
	if failedIO || !unchangedPrivateLoginFile(before, after, limit) || !unchangedPrivateLoginFile(after, current, limit) ||
		int64(len(result)) != before.Size() || ctx.Err() != nil {
		return result, ErrInvalid
	}
	return result, nil
}

func validPrivateLoginFileInfo(info os.FileInfo, limit int64) bool {
	if info == nil || !info.Mode().IsRegular() {
		return false
	}
	privateMode := info.Mode() == 0o400 || info.Mode() == 0o600
	return privateMode && info.Size() > 0 && info.Size() <= limit
}

func unchangedPrivateLoginFile(before, after os.FileInfo, limit int64) bool {
	return validPrivateLoginFileInfo(before, limit) && validPrivateLoginFileInfo(after, limit) &&
		os.SameFile(before, after) && before.Mode() == after.Mode() && before.Size() == after.Size() &&
		before.ModTime().Equal(after.ModTime())
}

// String redacts the temporary secret candidate.
func (PrivateLoginMaterial) String() string { return redactedValue }

// GoString redacts the candidate under Go-syntax formatting.
func (PrivateLoginMaterial) GoString() string { return redactedValue }

// LogValue redacts the candidate in structured logs.
func (PrivateLoginMaterial) LogValue() slog.Value { return slog.StringValue(redactedValue) }

// MarshalJSON refuses serialization of temporary secret material.
func (PrivateLoginMaterial) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
