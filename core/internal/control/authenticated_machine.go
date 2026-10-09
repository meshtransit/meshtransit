// Package control owns authenticated client-session boundaries and translates
// them into product application commands.
package control

import (
	"errors"
	"log/slog"

	"meshtransit.net/core/internal/domain/node"
)

// ErrInvalidAuthenticatedMachine reports a missing transport-authenticated identity.
var ErrInvalidAuthenticatedMachine = errors.New("control: invalid authenticated machine")

// AuthenticatedMachine is a machine public key whose possession was proven by
// the transport adapter. Untrusted request payloads must never construct it.
type AuthenticatedMachine struct {
	key node.MachineKey
}

// NewAuthenticatedMachine records a machine identity after transport authentication.
func NewAuthenticatedMachine(key node.MachineKey) (AuthenticatedMachine, error) {
	if !key.IsValid() {
		return AuthenticatedMachine{}, ErrInvalidAuthenticatedMachine
	}
	return AuthenticatedMachine{key: key}, nil
}

// IsValid reports whether the transport supplied a usable machine identity.
func (machine AuthenticatedMachine) IsValid() bool { return machine.key.IsValid() }

// String prevents authenticated machine identity from entering ordinary logs.
func (AuthenticatedMachine) String() string { return "[REDACTED]" }

// GoString prevents authenticated machine identity from entering diagnostic formatting.
func (AuthenticatedMachine) GoString() string { return "control.AuthenticatedMachine([REDACTED])" }

// LogValue prevents authenticated machine identity from entering structured logs.
func (AuthenticatedMachine) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }
