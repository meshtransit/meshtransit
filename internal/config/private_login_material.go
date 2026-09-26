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
	snapshots                                   [3]privateLoginFileSnapshot
}

// LoadMaterial reads only the profile's bounded protected local references.
func (profile *PrivateLoginConfig) LoadMaterial(ctx context.Context) (*PrivateLoginMaterial, error) {
	if profile == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, privateIdentityKeyTimeout)
	defer cancel()
	return profile.loadMaterialCandidate(ctx, readPrivateLoginFileSnapshot)
}

type privateLoginFileReader func(context.Context, SecretFile, int64) ([]byte, privateLoginFileSnapshot, error)

// Only local deterministic fixtures replace the reader. Public loading always
// uses the scoped production reader; this is not a process configuration seam.
func (profile *PrivateLoginConfig) loadMaterialCandidate(
	ctx context.Context,
	read privateLoginFileReader,
) (*PrivateLoginMaterial, error) {
	result := &PrivateLoginMaterial{}
	accepted := false
	defer func() {
		if !accepted {
			result.Clear()
		}
	}()
	for index, field := range []struct {
		file        SecretFile
		limit       int64
		destination *[]byte
	}{
		{file: profile.cert, limit: 64 * 1024, destination: &result.CertificatePEM},
		{file: profile.privateKey, limit: 64 * 1024, destination: &result.PrivateKeyPEM},
		{file: profile.clientSecret, limit: 4096, destination: &result.ClientSecret},
	} {
		contents, snapshot, err := read(ctx, field.file, field.limit)
		if err != nil {
			clear(contents)
			return nil, ErrInvalid
		}
		*field.destination = contents
		result.snapshots[index] = snapshot
	}
	if !result.stillCurrent(ctx) {
		return nil, ErrInvalid
	}
	accepted = true
	return result, nil
}

func (material *PrivateLoginMaterial) stillCurrent(ctx context.Context) bool {
	if material == nil || len(material.CertificatePEM) == 0 || len(material.PrivateKeyPEM) == 0 ||
		len(material.ClientSecret) == 0 {
		return false
	}
	for _, snapshot := range material.snapshots {
		if !snapshot.stillCurrent(ctx) {
			return false
		}
	}
	return ctx.Err() == nil
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
	material.snapshots = [3]privateLoginFileSnapshot{}
}

type privateLoginFileSnapshot struct {
	reference SecretFile
	info      os.FileInfo
	limit     int64
}

// Local trusted mounts are required: contexts cannot preempt filesystem syscalls.
// O_NONBLOCK avoids blocking FIFO opens on supported Linux/macOS targets. os.Root
// confines projected symlinks to the validated parent. No raw error is released.
func readPrivateLoginFile(ctx context.Context, reference SecretFile, limit int64) (result []byte, resultErr error) {
	result, _, resultErr = readPrivateLoginFileSnapshot(ctx, reference, limit)
	return result, resultErr
}

func readPrivateLoginFileSnapshot(
	ctx context.Context,
	reference SecretFile,
	limit int64,
) (result []byte, snapshot privateLoginFileSnapshot, resultErr error) {
	validPath := len(reference.path) <= 4096 && validateFilePath(reference.path) == nil
	if ctx == nil || ctx.Err() != nil || !validPath || limit <= 0 || limit > 64*1024 {
		return nil, snapshot, ErrInvalid
	}
	// #nosec G304 -- explicit canonical operator reference confined to its parent.
	root, err := os.OpenRoot(filepath.Dir(reference.path))
	if err != nil {
		return nil, snapshot, ErrInvalid
	}
	defer func() {
		if root.Close() != nil || ctx.Err() != nil {
			resultErr = ErrInvalid
		}
		if resultErr != nil {
			clear(result)
			result = nil
			snapshot = privateLoginFileSnapshot{}
		}
	}()
	name := filepath.Base(reference.path)
	file, err := openPrivateIdentityKey(root, name)
	if err != nil {
		return nil, snapshot, ErrInvalid
	}
	before, err := file.Stat()
	if err != nil || !validPrivateLoginFileInfo(before, limit) {
		if file.Close() != nil {
			return nil, snapshot, ErrInvalid
		}
		return nil, snapshot, ErrInvalid
	}
	result, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	after, statErr := file.Stat()
	current, currentErr := root.Stat(name)
	closeErr := file.Close()
	failedIO := readErr != nil || statErr != nil || currentErr != nil || closeErr != nil
	if failedIO || !unchangedPrivateLoginFile(before, after, limit) || !unchangedPrivateLoginFile(after, current, limit) ||
		int64(len(result)) != before.Size() || ctx.Err() != nil {
		return result, snapshot, ErrInvalid
	}
	snapshot = privateLoginFileSnapshot{reference: reference, info: after, limit: limit}
	return result, snapshot, nil
}

// This checks metadata only, never reloading or combining newer secret bytes.
func (snapshot privateLoginFileSnapshot) stillCurrent(ctx context.Context) (valid bool) {
	validPath := len(snapshot.reference.path) <= 4096 && validateFilePath(snapshot.reference.path) == nil
	validLimit := snapshot.limit > 0 && snapshot.limit <= 64*1024
	if ctx == nil || ctx.Err() != nil || !validPath || !validLimit || snapshot.info == nil {
		return false
	}
	// #nosec G304 -- bounded validated snapshot reference, confined to its parent.
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
	return err == nil && unchangedPrivateLoginFile(snapshot.info, current, snapshot.limit)
}

func validPrivateLoginFileInfo(info os.FileInfo, limit int64) bool {
	if info == nil || !info.Mode().IsRegular() {
		return false
	}
	return validProtectedFileMode(info.Mode()) && info.Size() > 0 && info.Size() <= limit
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
