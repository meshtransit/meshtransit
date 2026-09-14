package legacyts2021

import (
	"bytes"
	"errors"
	"log/slog"

	"tailscale.com/types/key"
)

// ErrInvalidControlPrivateKey reports malformed or non-canonical Noise key
// material without disclosing the rejected value.
var ErrInvalidControlPrivateKey = errors.New("legacyts2021: invalid control private key")

// ControlPrivateKey is the server-held Noise identity for the pinned client
// profile. All ordinary and structured formatting is redacted.
type ControlPrivateKey struct {
	value key.MachinePrivate
}

// ParseControlPrivateKey parses canonical private-key text loaded from an
// operator-controlled secret file.
func ParseControlPrivateKey(encoded string) (ControlPrivateKey, error) {
	var privateKey key.MachinePrivate
	if encoded == "" || privateKey.UnmarshalText([]byte(encoded)) != nil || privateKey.IsZero() {
		return ControlPrivateKey{}, ErrInvalidControlPrivateKey
	}
	canonical, err := privateKey.MarshalText()
	if err != nil || !bytes.Equal(canonical, []byte(encoded)) {
		clear(canonical)
		return ControlPrivateKey{}, ErrInvalidControlPrivateKey
	}
	clear(canonical)
	return ControlPrivateKey{value: privateKey}, nil
}

// IsValid reports whether the value contains a usable Noise server identity.
func (privateKey ControlPrivateKey) IsValid() bool {
	return !privateKey.value.IsZero()
}

// String prevents private key material from entering ordinary logs.
func (ControlPrivateKey) String() string { return "[REDACTED]" }

// GoString prevents private key material from entering diagnostic formatting.
func (ControlPrivateKey) GoString() string {
	return "legacyts2021.ControlPrivateKey([REDACTED])"
}

// LogValue prevents private key material from entering structured logs.
func (ControlPrivateKey) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }
