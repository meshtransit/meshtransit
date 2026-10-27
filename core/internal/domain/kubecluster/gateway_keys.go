package kubecluster

import (
	"context"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

// A Kubernetes gateway rotates its machine key at every start (mtcp-v1
// §6.8), at most MaximumMachineKeyRotations times within
// MachineKeyRotationWindow.
const (
	MaximumMachineKeyRotations = 30
	MachineKeyRotationWindow   = time.Hour
)

var (
	// ErrMachineKeyUsed reports a new machine key that a Device or gateway
	// used before: keys are never reused.
	ErrMachineKeyUsed = errors.New("kubernetes gateway: machine key used before")
	// ErrRotationLimited classifies a rotation refused by the budget; the
	// error also is a *RotationLimitedError.
	ErrRotationLimited = errors.New("kubernetes gateway: machine key rotation budget exhausted")
	// ErrGatewayTokenRefused reports a rotation the database refused for its
	// pod token: used for this key, checked against a trust that changed, or
	// no longer valid (schema 232). Nothing committed.
	ErrGatewayTokenRefused = errors.New("kubernetes gateway: pod token refused")
)

// RotationLimitedError reports a rotation refused by the budget.
type RotationLimitedError struct {
	RetryAfter time.Duration
}

func (err *RotationLimitedError) Error() string { return ErrRotationLimited.Error() }

// Is matches ErrRotationLimited.
func (err *RotationLimitedError) Is(target error) bool { return target == ErrRotationLimited }

// MachineKeyRotation moves a gateway from the machine key and node key its
// session proved to a new machine key, whose possession it proved too.
type MachineKeyRotation struct {
	MachineKey    node.MachineKey
	NodeKey       node.Key
	NewMachineKey node.MachineKey
	OperationID   publicid.ID
	// Token is the pod token Core verified for the rotation (K1.1).
	Token node.GatewayToken
}

// IsValid reports whether the keys and the token are present and the new
// key differs.
func (rotation MachineKeyRotation) IsValid() bool {
	return rotation.MachineKey.IsValid() && rotation.NodeKey.IsValid() && rotation.NewMachineKey.IsValid() &&
		rotation.NewMachineKey != rotation.MachineKey && rotation.OperationID.IsValid() && rotation.Token.IsValid()
}

// RotationTrust is what a gateway's rotation token must match (K1.1 design
// §8.3): the gateway Device the session proved, its cluster's signing trust
// and the pod its join named. A cluster without trust, or a Device that
// joined before K1.1, has TrustVersion 0 or an empty PodName.
type RotationTrust struct {
	DeviceID       node.ID
	TrustVersion   int64
	Issuer         string
	JWKS           []byte
	Namespace      string
	ServiceAccount string
	PodName        string
}

// Complete reports whether the rotation can be checked: trust and a bound
// pod.
func (trust RotationTrust) Complete() bool {
	return trust.DeviceID.IsValid() && trust.TrustVersion >= 1 && trust.Issuer != "" && len(trust.JWKS) > 0 &&
		trust.Namespace != "" && trust.ServiceAccount != "" && trust.PodName != ""
}

// MachineKeyRotations commits gateway machine key rotations: in one
// transaction, recording device.machine_key_rotated. A session that is not
// a proven gateway session gets ErrNotFound.
type MachineKeyRotations interface {
	RotateGatewayMachineKey(ctx context.Context, rotation MachineKeyRotation) error
	// ReadRotationTrust reads what the token of the gateway whose session
	// proved these keys must match; a session that is not a proven
	// gateway's gets ErrNotFound.
	ReadRotationTrust(ctx context.Context, machineKey node.MachineKey, nodeKey node.Key) (RotationTrust, error)
}
