//go:build windows

package secretstore

import (
	"crypto/rand"
	"crypto/subtle"
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

// dpapiEntropy is mixed into every seal. It does not stop code running as
// LocalSystem, which can read meshd's memory anyway, but a generic DPAPI
// unseal of the file no longer opens the key.
var dpapiEntropy = []byte("MeshTransit meshd identity envelope key v1")

// ErrKeyNotResealed reports a key sealed before meshd used entropy that
// opened but could not be rewritten. The key works; the next start retries.
var ErrKeyNotResealed = errors.New("secretstore: old key file not resealed")

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
	sealed, err := readSealedKey(path)
	if err != nil {
		return nil, err
	}
	credential, old, err := unprotectAny(sealed)
	if err != nil {
		return nil, fmt.Errorf("%w: unsealing: %w", ErrKeyInvalid, err)
	}
	defer clear(credential)
	protector, err := NewFromCredential(credential)
	if err != nil || !old {
		return protector, err
	}
	if err := reseal(path, credential); err != nil {
		return protector, fmt.Errorf("%w: %w", ErrKeyNotResealed, err)
	}

	return protector, nil
}

// readSealedKey reads the key file and closes it, so that reseal can
// replace it: Windows does not rename over a file that is still open.
func readSealedKey(path string) ([]byte, error) {
	file, err := os.Open(path) //nolint:gosec // The path is absolute and checked by the caller.
	if err != nil {
		return nil, fmt.Errorf("opening secret-store key: %w", err)
	}
	defer func() { _ = file.Close() }()
	sealed, err := io.ReadAll(io.LimitReader(file, maxSealedKeyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading secret-store key: %w", err)
	}

	return sealed, nil
}

// unprotectAny opens a key sealed with meshd's entropy, or one sealed before
// meshd used it (old is then true).
func unprotectAny(sealed []byte) (credential []byte, old bool, err error) {
	credential, err = unprotect(sealed)
	if err == nil {
		return credential, false, nil
	}
	credential, oldErr := unprotectWithout(sealed)
	if oldErr != nil {
		return nil, false, err
	}

	return credential, true, nil
}

// reseal replaces the key file with credential sealed with entropy. The new
// file is written next to it, checked to open to the same credential, and
// renamed over it, so a failure leaves the old file in place. It inherits
// the key directory's access list.
func reseal(path string, credential []byte) error {
	// An older meshd may have left the key directory open to users; the new
	// file must inherit only SYSTEM and Administrators.
	if err := privatefile.RestrictDir(filepath.Dir(path)); err != nil {
		return err
	}
	sealed, err := protect(credential)
	if err != nil {
		return fmt.Errorf("sealing: %w", err)
	}
	check, err := unprotect(sealed)
	if err != nil {
		return fmt.Errorf("checking the new seal: %w", err)
	}
	same := subtle.ConstantTimeCompare(check, credential) == 1
	clear(check)
	if !same {
		return errors.New("the new seal does not open to the same key")
	}
	temporary := path + ".reseal"
	_ = os.Remove(temporary)                                                      // a leftover of an interrupted earlier attempt
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // Next to the checked key.
	if err != nil {
		return fmt.Errorf("creating %s: %w", temporary, err)
	}
	if _, err := file.Write(sealed); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)

		return fmt.Errorf("writing %s: %w", temporary, err)
	}
	if err := errors.Join(file.Sync(), file.Close()); err != nil {
		_ = os.Remove(temporary)

		return fmt.Errorf("writing %s: %w", temporary, err)
	}
	if err := privatefile.CheckFile(temporary, nil); err != nil {
		_ = os.Remove(temporary)

		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)

		return fmt.Errorf("replacing the key file: %w", err)
	}

	return nil
}

// CreateDPAPI generates a new envelope key, seals it with DPAPI and writes
// it to path, which must not exist, in a directory restricted to SYSTEM and
// Administrators.
func CreateDPAPI(path string) (*Protector, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%w: key path must be absolute", ErrKeyInvalid)
	}
	dir := filepath.Dir(path)
	if err := privatefile.PrepareDir(dir, 0o700); err != nil {
		return nil, fmt.Errorf("preparing the key directory: %w", err)
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
	entropy := entropyBlob()

	return dpapi(plaintext, func(in, out *windows.DataBlob) error {
		return windows.CryptProtectData(in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, out)
	})
}

func unprotect(sealed []byte) ([]byte, error) {
	entropy := entropyBlob()

	return dpapi(sealed, func(in, out *windows.DataBlob) error {
		return windows.CryptUnprotectData(in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, out)
	})
}

// unprotectWithout opens a key sealed before meshd used entropy.
func unprotectWithout(sealed []byte) ([]byte, error) {
	return dpapi(sealed, func(in, out *windows.DataBlob) error {
		return windows.CryptUnprotectData(in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, out)
	})
}

func entropyBlob() windows.DataBlob {
	return windows.DataBlob{Size: uint32(len(dpapiEntropy)), Data: &dpapiEntropy[0]} //nolint:gosec // A short constant.
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
