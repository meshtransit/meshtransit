//go:build windows

package secretstore

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"

	"meshtransit.net/client/internal/privatefile"
)

// maxSealedKeyBytes bounds a DPAPI-sealed key file.
const maxSealedKeyBytes = 4 << 10

// LoadDPAPI opens a key file sealed with DPAPI for the account meshd runs
// as (LocalSystem): only a process running as SYSTEM can unseal it, and the
// file itself is readable only by SYSTEM and Administrators.
func LoadDPAPI(path string) (*Protector, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%w: key path must be absolute", ErrKeyInvalid)
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrKeyMissing
	}
	if errors.Is(err, os.ErrPermission) {
		return nil, ErrKeyLocked
	}
	if err != nil {
		return nil, fmt.Errorf("inspecting secret-store key: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 ||
		info.Size() > maxSealedKeyBytes {
		return nil, fmt.Errorf("%w: key must be a small regular file", ErrKeyInvalid)
	}
	if err := privatefile.CheckFile(path, info); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyInvalid, err)
	}
	file, err := os.Open(path) //nolint:gosec // The path is absolute and checked above.
	if err != nil {
		return nil, fmt.Errorf("opening secret-store key: %w", err)
	}
	defer func() { _ = file.Close() }()
	sealed, err := io.ReadAll(io.LimitReader(file, maxSealedKeyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading secret-store key: %w", err)
	}
	credential, err := unprotect(sealed)
	if err != nil {
		return nil, fmt.Errorf("%w: unsealing: %w", ErrKeyInvalid, err)
	}
	defer clear(credential)

	return NewFromCredential(credential)
}

// CreateDPAPI generates a new envelope key, seals it with DPAPI and writes
// it to path, which must not exist, in a directory restricted to SYSTEM and
// Administrators.
func CreateDPAPI(path string) (*Protector, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%w: key path must be absolute", ErrKeyInvalid)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating the key directory: %w", err)
	}
	if err := privatefile.RestrictDir(dir); err != nil {
		return nil, err
	}
	key := make([]byte, KeySize)
	defer clear(key)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating the envelope key: %w", err)
	}
	sealed, err := protect(key)
	if err != nil {
		return nil, fmt.Errorf("sealing the envelope key: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // Absolute path.
	if err != nil {
		return nil, fmt.Errorf("creating the key file: %w", err)
	}
	if _, err := file.Write(sealed); err != nil {
		_ = file.Close()
		_ = os.Remove(path)

		return nil, fmt.Errorf("writing the key file: %w", err)
	}
	if err := errors.Join(file.Sync(), file.Close()); err != nil {
		_ = os.Remove(path)

		return nil, fmt.Errorf("writing the key file: %w", err)
	}

	return New(key)
}

func protect(plaintext []byte) ([]byte, error) {
	return dpapi(plaintext, func(in, out *windows.DataBlob) error {
		return windows.CryptProtectData(in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, out)
	})
}

func unprotect(sealed []byte) ([]byte, error) {
	return dpapi(sealed, func(in, out *windows.DataBlob) error {
		return windows.CryptUnprotectData(in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, out)
	})
}

// dpapi runs one DPAPI call and copies its LocalAlloc'd result out.
func dpapi(input []byte, call func(in, out *windows.DataBlob) error) ([]byte, error) {
	if len(input) == 0 {
		return nil, errors.New("empty DPAPI input")
	}
	in := windows.DataBlob{Size: uint32(len(input)), Data: &input[0]} //nolint:gosec // Bounded by the callers.
	var out windows.DataBlob
	if err := call(&in, &out); err != nil {
		return nil, err
	}
	defer func() { _, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data))) }() //nolint:gosec // DPAPI allocation.
	allocated := unsafe.Slice(out.Data, out.Size)                                         //nolint:gosec // DPAPI returns Size bytes at Data.
	result := make([]byte, len(allocated))
	copy(result, allocated)
	clear(allocated)

	return result, nil
}
