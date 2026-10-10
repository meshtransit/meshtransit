package control

import (
	"context"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

var (
	// ErrInvalidDeviceLogoutService reports a missing dependency.
	ErrInvalidDeviceLogoutService = errors.New("control: invalid device logout service")
	// ErrDeviceLogoutNotFound reports keys that are not the current keys of
	// an active Device: nothing is logged out.
	ErrDeviceLogoutNotFound = errors.New("control: no active device for these keys")
	// ErrDeviceLogoutUnavailable reports a logout that did not commit.
	ErrDeviceLogoutUnavailable = errors.New("control: device logout unavailable")
)

// DeviceLogout is the committed outcome of a node logging itself out.
type DeviceLogout struct {
	Scope           network.Scope
	DeviceID        node.ID
	NetworkRevision int64
}

// DeviceLogoutStore revokes the active Device whose current keys the node
// proved, records evidence and advances the Network revision atomically.
type DeviceLogoutStore interface {
	LogoutDevice(ctx context.Context, identity AuthenticatedNode, at time.Time) (DeviceLogout, error)
}

// DeviceLogoutService lets a node deauthorize its own Device (MTCP Logout).
// Authority is the transport-proven machine key together with the Device's
// current node key; no account session is involved.
type DeviceLogoutService struct {
	store DeviceLogoutStore
	now   func() time.Time
}

// NewDeviceLogoutService validates its store.
func NewDeviceLogoutService(store DeviceLogoutStore) (*DeviceLogoutService, error) {
	if store == nil {
		return nil, ErrInvalidDeviceLogoutService
	}
	return &DeviceLogoutService{store: store, now: time.Now}, nil
}

// Logout revokes the Device bound to machine and nodeKey.
func (service *DeviceLogoutService) Logout(ctx context.Context, machine AuthenticatedMachine,
	nodeKey node.Key) (DeviceLogout, error) {
	if ctx == nil || service == nil || service.store == nil {
		return DeviceLogout{}, ErrInvalidDeviceLogoutService
	}
	identity, err := machine.BindNodeKey(nodeKey)
	if err != nil {
		return DeviceLogout{}, ErrDeviceLogoutNotFound
	}
	logout, err := service.store.LogoutDevice(ctx, identity, service.now())
	if err != nil {
		return DeviceLogout{}, err
	}
	if !logout.DeviceID.IsValid() || logout.NetworkRevision <= 0 {
		return DeviceLogout{}, ErrDeviceLogoutUnavailable
	}
	return logout, nil
}
