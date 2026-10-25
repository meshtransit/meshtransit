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
}

// IsValid reports whether the keys are present and the new key differs.
func (rotation MachineKeyRotation) IsValid() bool {
	return rotation.MachineKey.IsValid() && rotation.NodeKey.IsValid() && rotation.NewMachineKey.IsValid() &&
		rotation.NewMachineKey != rotation.MachineKey && rotation.OperationID.IsValid()
}

// MachineKeyRotations commits gateway machine key rotations: in one
// transaction, recording device.machine_key_rotated. A session that is not
// a proven gateway session gets ErrNotFound.
type MachineKeyRotations interface {
	RotateGatewayMachineKey(ctx context.Context, rotation MachineKeyRotation) error
}
