package control

import (
	"errors"
	"log/slog"

	"github.com/meshtransit/meshtransit/internal/node"
)

// ErrInvalidAuthenticatedNode reports an incomplete transport-bound Node identity.
var ErrInvalidAuthenticatedNode = errors.New("control: invalid authenticated node")

// AuthenticatedNode binds a Node key supplied by a request to the machine key
// proven by its transport. It carries identity only and grants no authority.
type AuthenticatedNode struct {
	machineFingerprint [32]byte
	nodeKey            node.Key
}

// BindNodeKey creates the identity used to resolve an authoritative Node session.
func (machine AuthenticatedMachine) BindNodeKey(nodeKey node.Key) (AuthenticatedNode, error) {
	if !machine.IsValid() || !nodeKey.IsValid() {
		return AuthenticatedNode{}, ErrInvalidAuthenticatedNode
	}
	return AuthenticatedNode{
		machineFingerprint: machine.key.Fingerprint(),
		nodeKey:            nodeKey,
	}, nil
}

// MachineFingerprint returns the transport-authenticated machine-key fingerprint.
func (identity AuthenticatedNode) MachineFingerprint() [32]byte {
	return identity.machineFingerprint
}

// NodeKey returns the request Node key bound to the authenticated machine.
func (identity AuthenticatedNode) NodeKey() node.Key { return identity.nodeKey }

// IsValid reports whether both sides of the session identity are present.
func (identity AuthenticatedNode) IsValid() bool {
	return identity.machineFingerprint != [32]byte{} && identity.nodeKey.IsValid()
}

// String prevents session identity from entering ordinary logs.
func (AuthenticatedNode) String() string { return "[REDACTED]" }

// GoString prevents session identity from entering diagnostic formatting.
func (AuthenticatedNode) GoString() string { return "control.AuthenticatedNode([REDACTED])" }

// LogValue prevents session identity from entering structured logs.
func (AuthenticatedNode) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }
