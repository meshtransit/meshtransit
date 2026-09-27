package config

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"strings"
)

const (
	envRelayDirectoryFile   = "MESHTRANSIT_RELAY_DIRECTORY_FILE"
	envRelayDirectorySHA256 = "MESHTRANSIT_RELAY_DIRECTORY_SHA256"
	relayDigestPrefix       = "sha256:"
)

// RelayDirectoryConfig is a validated digest-pinned local snapshot reference.
// Formatting is redacted because the path can reveal deployment topology.
type RelayDirectoryConfig struct {
	path   string
	digest [sha256.Size]byte
}

// NewRelayDirectoryConfig validates a canonical absolute path and non-zero
// lowercase SHA-256 digest without reading the referenced snapshot.
func NewRelayDirectoryConfig(path, digest string) (RelayDirectoryConfig, error) {
	if err := validateFilePath(path); err != nil {
		return RelayDirectoryConfig{}, ErrInvalid
	}
	parsed, err := parseRelayDirectoryDigest(digest)
	if err != nil {
		return RelayDirectoryConfig{}, ErrInvalid
	}
	return RelayDirectoryConfig{path: path, digest: parsed}, nil
}

// Values returns the validated path and digest for the composition root. The
// path must not be formatted, logged, or retained outside startup composition.
func (config RelayDirectoryConfig) Values() (string, [sha256.Size]byte, error) {
	if err := validateFilePath(config.path); err != nil || config.digest == ([sha256.Size]byte{}) {
		return "", [sha256.Size]byte{}, ErrInvalid
	}
	return config.path, config.digest, nil
}

// String redacts the snapshot reference from ordinary formatting.
func (RelayDirectoryConfig) String() string { return redactedValue }

// GoString redacts the snapshot reference from Go-syntax formatting.
func (RelayDirectoryConfig) GoString() string { return redactedValue }

// LogValue redacts the snapshot reference from structured logs.
func (RelayDirectoryConfig) LogValue() slog.Value { return slog.StringValue(redactedValue) }

func loadRelayDirectoryConfig(lookup LookupFunc) (RelayDirectoryConfig, error) {
	path, err := requiredFile(lookup, envRelayDirectoryFile)
	if err != nil {
		return RelayDirectoryConfig{}, err
	}
	digest, ok := lookup(envRelayDirectorySHA256)
	if !ok {
		return RelayDirectoryConfig{}, settingError(envRelayDirectorySHA256)
	}
	config, err := NewRelayDirectoryConfig(path, digest)
	if err != nil {
		return RelayDirectoryConfig{}, settingError(envRelayDirectorySHA256)
	}
	return config, nil
}

func parseRelayDirectoryDigest(value string) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	if !strings.HasPrefix(value, relayDigestPrefix) {
		return digest, ErrInvalid
	}
	encoded := strings.TrimPrefix(value, relayDigestPrefix)
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != sha256.Size ||
		relayDigestPrefix+hex.EncodeToString(decoded) != value {
		return digest, ErrInvalid
	}
	copy(digest[:], decoded)
	if digest == ([sha256.Size]byte{}) {
		return [sha256.Size]byte{}, ErrInvalid
	}
	return digest, nil
}
