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
	// proven is the node key the session proved it holds (mtcp-v1 §6.4,
	// §6.7), or zero.
	proven node.Key
	// gateway marks a Kubernetes gateway's session: its map stream holds
	// the gateway's presence by holder (K1a1 plan §16.12).
	gateway bool
	// token is the pod token Core verified for this request's key rotation
	// (K1.1), or zero.
	token node.GatewayToken
}

// NewAuthenticatedMachine records a machine identity after transport authentication.
func NewAuthenticatedMachine(key node.MachineKey) (AuthenticatedMachine, error) {
	if !key.IsValid() {
		return AuthenticatedMachine{}, ErrInvalidAuthenticatedMachine
	}
	return AuthenticatedMachine{key: key}, nil
}

// WithProvenNodeKey returns the machine with the node key its session
// proved; stores tell the database, which serves a Kubernetes gateway only
// to a session that proved its node key.
func (machine AuthenticatedMachine) WithProvenNodeKey(nodeKey node.Key) AuthenticatedMachine {
	if !nodeKey.IsValid() {
		nodeKey = node.Key{}
	}
	machine.proven = nodeKey
	return machine
}

// ProvenNodeKey returns the node key the session proved, if any.
func (machine AuthenticatedMachine) ProvenNodeKey() (node.Key, bool) {
	return machine.proven, machine.proven.IsValid()
}

// provenAmong returns the proven node key when it is one of keys, else zero.
func (machine AuthenticatedMachine) provenAmong(keys ...node.Key) node.Key {
	for _, nodeKey := range keys {
		if machine.proven.IsValid() && machine.proven == nodeKey {
			return nodeKey
		}
	}
	return node.Key{}
}

// WithGatewayToken returns the machine with the pod token Core verified for
// its gateway's key rotation; the store records one use of it.
func (machine AuthenticatedMachine) WithGatewayToken(token node.GatewayToken) AuthenticatedMachine {
	if !token.IsValid() {
		token = node.GatewayToken{}
	}
	machine.token = token
	return machine
}

// GatewayToken returns the verified pod token, if any.
func (machine AuthenticatedMachine) GatewayToken() (node.GatewayToken, bool) {
	return machine.token, machine.token.IsValid()
}

// AsKubernetesGateway returns the machine marked as a Kubernetes gateway's.
func (machine AuthenticatedMachine) AsKubernetesGateway() AuthenticatedMachine {
	machine.gateway = true
	return machine
}

// KubernetesGateway returns the fingerprint of the machine key when the
// session serves a Kubernetes gateway.
func (machine AuthenticatedMachine) KubernetesGateway() ([32]byte, bool) {
	if !machine.gateway || !machine.IsValid() {
		return [32]byte{}, false
	}
	return machine.key.Fingerprint(), true
}

// IsValid reports whether the transport supplied a usable machine identity.
func (machine AuthenticatedMachine) IsValid() bool { return machine.key.IsValid() }

// String prevents authenticated machine identity from entering ordinary logs.
func (AuthenticatedMachine) String() string { return "[REDACTED]" }

// GoString prevents authenticated machine identity from entering diagnostic formatting.
func (AuthenticatedMachine) GoString() string { return "control.AuthenticatedMachine([REDACTED])" }

// LogValue prevents authenticated machine identity from entering structured logs.
func (AuthenticatedMachine) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }
