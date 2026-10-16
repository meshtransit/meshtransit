package control

import (
	"context"
	"errors"
	"testing"

	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

type deviceLogoutStoreFixture struct {
	identity AuthenticatedNode
	logout   DeviceLogout
	err      error
}

func (store *deviceLogoutStoreFixture) LogoutDevice(_ context.Context, identity AuthenticatedNode) (
	DeviceLogout, error) {
	store.identity = identity
	return store.logout, store.err
}

func TestDeviceLogoutService(t *testing.T) {
	t.Parallel()
	if _, err := NewDeviceLogoutService(nil); !errors.Is(err, ErrInvalidDeviceLogoutService) {
		t.Fatalf("nil store: %v", err)
	}
	machine, err := NewAuthenticatedMachine(node.MachineKey{1})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := publicid.Parse("01890f90-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	device := node.ID(parsed)
	store := &deviceLogoutStoreFixture{logout: DeviceLogout{DeviceID: device, NetworkRevision: 4}}
	service, err := NewDeviceLogoutService(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Logout(t.Context(), machine, node.Key{}); !errors.Is(err, ErrDeviceLogoutNotFound) {
		t.Fatalf("zero node key: %v", err)
	}
	logout, err := service.Logout(t.Context(), machine, node.Key{2})
	if err != nil || logout.DeviceID != device || store.identity.NodeKey() != (node.Key{2}) ||
		store.identity.MachineFingerprint() != machine.key.Fingerprint() {
		t.Fatalf("logout = %+v, %v", logout, err)
	}
	store.logout = DeviceLogout{}
	if _, err := service.Logout(t.Context(), machine, node.Key{2}); !errors.Is(err, ErrDeviceLogoutUnavailable) {
		t.Fatalf("an empty outcome must not count as a logout: %v", err)
	}
	store.err = ErrDeviceLogoutNotFound
	if _, err := service.Logout(t.Context(), machine, node.Key{2}); !errors.Is(err, ErrDeviceLogoutNotFound) {
		t.Fatalf("store error: %v", err)
	}
}
