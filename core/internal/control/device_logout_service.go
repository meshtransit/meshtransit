package control

import (
	"context"
	"errors"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

var (
	// ErrInvalidDeviceLogoutService reports a missing dependency.
	ErrInvalidDeviceLogoutService = errors.New("control: invalid device logout service")
	// ErrDeviceLogoutNotFound reports keys that are not the current keys of
	// an active Device: nothing is logged out.
	ErrDeviceLogoutNotFound = errors.New("control: no active device for these keys")
	// ErrDeviceLogoutNotPermitted reports a Device that cannot log out: a
	// Kubernetes gateway, which an administrator removes (schema 226).
	ErrDeviceLogoutNotPermitted = errors.New("control: device cannot log out")
	// ErrDeviceLogoutRevoked reports keys that were the current keys of a
	// Device revoked with them (or of a Device in a deleted Network): the
	// Device is already gone, and the node may erase these keys (mtcp-v1 §10).
	ErrDeviceLogoutRevoked = errors.New("control: device already removed")
	// ErrDeviceSignOutNotPermitted reports a Workspace Device asked to sign
	// out and be kept: nobody could sign it back in, so it is removed or left
	// (schema 283, MTL04).
	ErrDeviceSignOutNotPermitted = errors.New("control: a Workspace Device cannot sign out")
	// ErrDeviceLogoutUnavailable reports a logout that did not commit.
	ErrDeviceLogoutUnavailable = errors.New("control: device logout unavailable")
)

// Logout outcomes (schema 283).
const (
	// LogoutRemoved: the Device was revoked.
	LogoutRemoved = "removed"
	// LogoutSignedOut: the Device was signed out and kept.
	LogoutSignedOut = "signed_out"
	// LogoutUnchanged: the Device was already signed out; nothing changed.
	LogoutUnchanged = "unchanged"
)

// DeviceLogout is the committed outcome of a node logging itself out.
type DeviceLogout struct {
	Scope           network.Scope
	DeviceID        node.ID
	NetworkRevision int64
	// Outcome is LogoutRemoved, LogoutSignedOut or LogoutUnchanged.
	Outcome string
}

func (logout DeviceLogout) isValid() bool {
	switch logout.Outcome {
	case LogoutRemoved, LogoutSignedOut:
		return logout.DeviceID.IsValid() && logout.NetworkRevision > 0
	case LogoutUnchanged:
		return logout.DeviceID.IsValid()
	}
	return false
}

// DeviceLogoutStore revokes the active Device whose current keys the node
// proved, records evidence and advances the Network revision atomically, on
// the database clock. anyExpiry admits an expired Device: only for a node
// key the session proved by a proof, not merely named in its hello
// (TD-CORE-145). keepDevice signs the Device out and keeps it instead of
// revoking it (schema 283).
type DeviceLogoutStore interface {
	LogoutDevice(ctx context.Context, identity AuthenticatedNode, anyExpiry, keepDevice bool) (DeviceLogout, error)
}

// DeviceLogoutService lets a node deauthorize its own Device (MTCP Logout).
// Authority is the transport-proven machine key together with the Device's
// current node key; no account session is involved.
type DeviceLogoutService struct {
	store DeviceLogoutStore
}

// NewDeviceLogoutService validates its store.
func NewDeviceLogoutService(store DeviceLogoutStore) (*DeviceLogoutService, error) {
	if store == nil {
		return nil, ErrInvalidDeviceLogoutService
	}
	return &DeviceLogoutService{store: store}, nil
}

// Logout revokes the Device bound to machine and nodeKey. keyProven says the
// session proved nodeKey (an authorized map stream, or a key proof): only
// then may the Device have expired. keepDevice signs it out and keeps it.
func (service *DeviceLogoutService) Logout(ctx context.Context, machine AuthenticatedMachine,
	nodeKey node.Key, keyProven, keepDevice bool) (DeviceLogout, error) {
	if ctx == nil || service == nil || service.store == nil {
		return DeviceLogout{}, ErrInvalidDeviceLogoutService
	}
	identity, err := machine.BindNodeKey(nodeKey)
	if err != nil {
		return DeviceLogout{}, ErrDeviceLogoutNotFound
	}
	logout, err := service.store.LogoutDevice(ctx, identity, keyProven, keepDevice)
	if err != nil {
		return DeviceLogout{}, err
	}
	if !logout.isValid() || (!keepDevice && logout.Outcome != LogoutRemoved) {
		return DeviceLogout{}, ErrDeviceLogoutUnavailable
	}
	return logout, nil
}
