package config

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
)

const (
	maxCredentialBytes = 4 * 1024
	maxPrivateKeyBytes = 64 * 1024
	maxTrustBytes      = 1024 * 1024
	redactedValue      = "[REDACTED]"
)

// SecretFile is an opaque validated credential file reference. All formatting
// is redacted; Read returns the credential without modifying internal state.
type SecretFile struct {
	path string
}

// TrustFile is an opaque validated CA bundle file reference. All formatting is
// redacted.
type TrustFile struct {
	path string
}

// PrivateKeyFile is an opaque validated multiline private-key file reference.
// All formatting is redacted.
type PrivateKeyFile struct {
	path string
}

// NewSecretFile validates an absolute credential-file reference without
// reading its contents. The referenced file is revalidated when Read is called.
func NewSecretFile(path string) (SecretFile, error) {
	if err := validateFilePath(path); err != nil {
		return SecretFile{}, ErrInvalid
	}
	return SecretFile{path: path}, nil
}

// NewTrustFile validates an absolute trust-bundle reference without reading
// its contents. The referenced file is revalidated when Read is called.
func NewTrustFile(path string) (TrustFile, error) {
	if err := validateFilePath(path); err != nil {
		return TrustFile{}, ErrInvalid
	}
	return TrustFile{path: path}, nil
}

// Read reads one bounded credential file and removes only its terminal line
// ending. Empty or multiline credentials are rejected.
func (file SecretFile) Read() (string, error) {
	contents, err := readBoundedRegularFile(file.path, maxCredentialBytes)
	if err != nil {
		return "", errors.Join(ErrInvalid, errors.New("credential file unavailable"))
	}
	credential := string(contents)
	credential = strings.TrimSuffix(credential, "\r\n")
	credential = strings.TrimSuffix(credential, "\n")
	if credential == "" || strings.ContainsAny(credential, "\x00\r\n") {
		return "", errors.Join(ErrInvalid, errors.New("credential file content rejected"))
	}
	return credential, nil
}

// Read returns one bounded CA bundle. Certificate parsing belongs to the TLS
// adapter that consumes it.
func (file TrustFile) Read() ([]byte, error) {
	contents, err := readBoundedRegularFile(file.path, maxTrustBytes)
	if err != nil || len(contents) == 0 {
		return nil, errors.Join(ErrInvalid, errors.New("trust file unavailable"))
	}
	return contents, nil
}

// PathForDriver returns the validated absolute reference only for database
// drivers that must reopen a CA bundle by path. Callers must not retain,
// format, or log the returned value.
func (file TrustFile) PathForDriver() (string, error) {
	if err := validateFilePath(file.path); err != nil {
		return "", ErrInvalid
	}
	return file.path, nil
}

// Read returns one bounded private-key document without transforming its bytes.
func (file PrivateKeyFile) Read() ([]byte, error) {
	contents, err := readBoundedRegularFile(file.path, maxPrivateKeyBytes)
	if err != nil || len(contents) == 0 || bytes.IndexByte(contents, 0) >= 0 {
		clear(contents)
		return nil, errors.Join(ErrInvalid, errors.New("private key file unavailable"))
	}
	return contents, nil
}

// String implements fmt.Stringer without revealing the referenced path.
func (SecretFile) String() string { return redactedValue }

// GoString implements fmt.GoStringer without revealing the referenced path.
func (SecretFile) GoString() string { return redactedValue }

// LogValue implements slog.LogValuer without revealing the referenced path.
func (SecretFile) LogValue() slog.Value { return slog.StringValue(redactedValue) }

// String implements fmt.Stringer without revealing the referenced path.
func (TrustFile) String() string { return redactedValue }

// GoString implements fmt.GoStringer without revealing the referenced path.
func (TrustFile) GoString() string { return redactedValue }

// LogValue implements slog.LogValuer without revealing the referenced path.
func (TrustFile) LogValue() slog.Value { return slog.StringValue(redactedValue) }

// String implements fmt.Stringer without revealing the referenced path.
func (PrivateKeyFile) String() string { return redactedValue }

// GoString implements fmt.GoStringer without revealing the referenced path.
func (PrivateKeyFile) GoString() string { return redactedValue }

// LogValue implements slog.LogValuer without revealing the referenced path.
func (PrivateKeyFile) LogValue() slog.Value { return slog.StringValue(redactedValue) }

func readBoundedRegularFile(path string, limit int64) ([]byte, error) {
	// #nosec G304 -- path is a validated absolute operator-supplied file reference.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.Join(ErrInvalid, err, file.Close())
	}
	contents, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(contents)) > limit {
		return nil, ErrInvalid
	}
	return contents, nil
}
