package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/identity"
)

// startRegisteredRun registers the test profile and runs the session loop
// until the test ends.
func startRegisteredRun(t *testing.T, service *Service, control *fakeControl) {
	t.Helper()
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	control.registrationResults = []controlplane.RegistrationResult{{
		State:             controlplane.RegistrationStateAuthorized,
		MachineAuthorized: true,
	}}
	if _, err := service.StartLogin(t.Context(), "credential"); err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	runResult := make(chan error, 1)
	go func() { runResult <- service.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-runResult; !errors.Is(err, context.Canceled) {
			t.Errorf("Run() error = %v, want context cancellation", err)
		}
	})
	waitForStreamStart(t, control)
}

func TestService_DownStaysDownUntilUp(t *testing.T) {
	t.Parallel()

	service, _, control, _, _ := newTestService(t)
	startRegisteredRun(t, service, control)

	down, err := service.Down(t.Context())
	if err != nil || down.State != ConnectionDown || !down.Changed {
		t.Fatalf("Down() = %+v, %v", down, err)
	}
	status, err := service.Status(t.Context())
	if err != nil || status.ControlSession != ControlSessionDown || status.State != StateOffline {
		t.Fatalf("Status() after Down = %+v, %v", status, err)
	}
	if !service.profiles.Snapshot().Disconnected {
		t.Fatal("Down did not persist the disconnected preference")
	}
	if again, err := service.Down(t.Context()); err != nil || again.Changed {
		t.Fatalf("repeat Down() = %+v, %v, want unchanged", again, err)
	}

	up, err := service.Up(t.Context())
	if err != nil || up.State != ConnectionUp || !up.Changed {
		t.Fatalf("Up() = %+v, %v", up, err)
	}
	waitForStreamStart(t, control)
	if again, err := service.Up(t.Context()); err != nil || again.Changed {
		t.Fatalf("repeat Up() = %+v, %v, want unchanged", again, err)
	}
}

func TestService_LogoutEndsTheDeviceAndReplacesItsKeys(t *testing.T) {
	t.Parallel()

	service, identities, control, profileID, _ := newTestService(t)
	startRegisteredRun(t, service, control)
	before, err := identities.Get(t.Context(), profileID)
	if err != nil {
		t.Fatalf("identity Get() error = %v", err)
	}
	oldMaterial := before.Material()
	defer clearIdentityMaterial(oldMaterial)

	result, err := service.Logout(t.Context())
	if err != nil || result.State != LogoutCompleted || result.AlreadyRemoved || result.ProfileID != profileID {
		t.Fatalf("Logout() = %+v, %v", result, err)
	}
	control.mu.Lock()
	logouts := cloneProtocolMaterials(control.logoutMaterials)
	control.mu.Unlock()
	defer clearProtocolMaterials(logouts)
	if len(logouts) != 1 || !bytes.Equal(logouts[0].NodePrivateKey, oldMaterial.NodePrivateKey) ||
		!bytes.Equal(logouts[0].MachinePrivateKey, oldMaterial.MachinePrivateKey) {
		t.Fatal("Logout was not authenticated with the Device's current keys")
	}
	assertCredentialsReplaced(t, identities, profileID, oldMaterial.MachinePrivateKey, oldMaterial.NodePrivateKey)
	waitForControlSession(t, service, ControlSessionInactive)

	again, err := service.Logout(t.Context())
	if err != nil || again.State != LogoutNotRegistered {
		t.Fatalf("Logout() of an unregistered profile = %+v, %v", again, err)
	}
}

func TestService_LogoutOfARemovedDeviceReplacesItsKeys(t *testing.T) {
	t.Parallel()

	service, identities, control, profileID, _ := newTestService(t)
	startRegisteredRun(t, service, control)
	before, err := identities.Get(t.Context(), profileID)
	if err != nil {
		t.Fatalf("identity Get() error = %v", err)
	}
	oldMaterial := before.Material()
	defer clearIdentityMaterial(oldMaterial)
	control.mu.Lock()
	control.logoutErr = fmt.Errorf("%w: not_authorized", controlplane.ErrDeviceNotAuthorized)
	control.mu.Unlock()

	result, err := service.Logout(t.Context())
	if err != nil || result.State != LogoutCompleted || !result.AlreadyRemoved {
		t.Fatalf("Logout() = %+v, %v, want an already removed Device", result, err)
	}
	assertCredentialsReplaced(t, identities, profileID, oldMaterial.MachinePrivateKey, oldMaterial.NodePrivateKey)
}

func TestService_LogoutKeepsTheDeviceWhenCoreFails(t *testing.T) {
	t.Parallel()

	service, identities, control, profileID, _ := newTestService(t)
	startRegisteredRun(t, service, control)
	before, err := identities.Get(t.Context(), profileID)
	if err != nil {
		t.Fatalf("identity Get() error = %v", err)
	}
	oldMaterial := before.Material()
	defer clearIdentityMaterial(oldMaterial)
	control.mu.Lock()
	control.logoutErr = fmt.Errorf("%w: logout unavailable", controlplane.ErrRegistrationTemporary)
	control.mu.Unlock()

	if _, err := service.Logout(t.Context()); !errors.Is(err, ErrLogout) {
		t.Fatalf("Logout() error = %v, want ErrLogout", err)
	}
	after, err := identities.Get(t.Context(), profileID)
	if err != nil {
		t.Fatalf("identity Get() error = %v", err)
	}
	afterMaterial := after.Material()
	defer clearIdentityMaterial(afterMaterial)
	if !after.IsRegistered() || !bytes.Equal(afterMaterial.NodePrivateKey, oldMaterial.NodePrivateKey) {
		t.Fatal("a failed logout changed the Device's identity")
	}
	waitForStreamStart(t, control)
}

func assertCredentialsReplaced(t *testing.T, identities *identity.Store, profileID string, oldMachine, oldNode []byte) {
	t.Helper()
	after, err := identities.Get(t.Context(), profileID)
	if err != nil {
		t.Fatalf("identity Get() after logout error = %v", err)
	}
	material := after.Material()
	defer clearIdentityMaterial(material)
	if after.IsRegistered() || after.HasPendingAuth() ||
		bytes.Equal(material.MachinePrivateKey, oldMachine) || bytes.Equal(material.NodePrivateKey, oldNode) {
		t.Fatalf("identity after logout = %s, want new unregistered keys", after)
	}
}

func TestService_LogoutRightAfterUpWaitsForAFreshDown(t *testing.T) {
	t.Parallel()

	service, identities, control, profileID, _ := newTestService(t)
	startRegisteredRun(t, service, control)
	if _, err := service.Down(t.Context()); err != nil {
		t.Fatalf("Down() error = %v", err)
	}
	if _, err := service.Up(t.Context()); err != nil {
		t.Fatalf("Up() error = %v", err)
	}
	// The status still says down from before Up; Logout must not trust it.
	acknowledged := service.downAcks.Load()
	result, err := service.Logout(t.Context())
	if err != nil || result.State != LogoutCompleted {
		t.Fatalf("Logout() = %+v, %v", result, err)
	}
	if service.downAcks.Load() <= acknowledged {
		t.Fatal("Logout went ahead on the down reported before it signalled")
	}
	if after, err := identities.Get(t.Context(), profileID); err != nil || after.IsRegistered() {
		t.Fatalf("identity after logout = %v, %v", after, err)
	}
}

func TestService_LogoutWhileDownStaysDown(t *testing.T) {
	t.Parallel()

	service, _, control, _, _ := newTestService(t)
	startRegisteredRun(t, service, control)
	if _, err := service.Down(t.Context()); err != nil {
		t.Fatalf("Down() error = %v", err)
	}
	if result, err := service.Logout(t.Context()); err != nil || result.State != LogoutCompleted {
		t.Fatalf("Logout() = %+v, %v", result, err)
	}
	if !service.profiles.Snapshot().Disconnected {
		t.Fatal("Logout cleared a meshctl down")
	}
	waitForControlSession(t, service, ControlSessionDown)
}
