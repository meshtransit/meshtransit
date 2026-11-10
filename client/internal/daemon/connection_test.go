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
	control.logoutErr = fmt.Errorf("%w: revoked", controlplane.ErrDeviceRemoved)
	control.mu.Unlock()

	result, err := service.Logout(t.Context())
	if err != nil || result.State != LogoutCompleted || !result.AlreadyRemoved {
		t.Fatalf("Logout() = %+v, %v, want an already removed Device", result, err)
	}
	assertCredentialsReplaced(t, identities, profileID, oldMaterial.MachinePrivateKey, oldMaterial.NodePrivateKey)
}

// TD-CLI-100: a refusal is ambiguous (an expired Device on an older Core
// still holds its address), so the keys stay.
func TestService_LogoutRefusedKeepsTheKeys(t *testing.T) {
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

	if _, err := service.Logout(t.Context()); !errors.Is(err, ErrLogout) ||
		!errors.Is(err, controlplane.ErrDeviceNotAuthorized) {
		t.Fatalf("Logout() error = %v, want a refused logout", err)
	}
	after, err := identities.Get(t.Context(), profileID)
	if err != nil {
		t.Fatalf("identity Get() error = %v", err)
	}
	material := after.Material()
	defer clearIdentityMaterial(material)
	if !bytes.Equal(material.MachinePrivateKey, oldMaterial.MachinePrivateKey) ||
		!bytes.Equal(material.NodePrivateKey, oldMaterial.NodePrivateKey) {
		t.Fatal("a refused logout replaced the profile's keys")
	}
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

func TestService_UpRetriesAPendingRecoveryOnly(t *testing.T) {
	t.Parallel()

	service, _, _, _, _ := newTestService(t)
	if _, err := service.Up(t.Context()); err != nil {
		t.Fatal(err)
	}
	drainSyncSignal(service)
	if _, err := service.Up(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(service.syncSignal) != 0 {
		t.Fatal("a repeated Up signalled a running session to restart")
	}
	service.runtimePending.Store(true)
	if _, err := service.Up(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(service.syncSignal) != 1 {
		t.Fatal("Up did not wake a pending runtime recovery")
	}
}

func drainSyncSignal(service *Service) {
	select {
	case <-service.syncSignal:
	default:
	}
}

// Schema 283: signing out keeps the profile's keys, so login brings the
// same Device back, and leaves it unregistered, so meshd stays off.
func TestService_SignOutKeepsTheKeys(t *testing.T) {
	t.Parallel()

	service, identities, control, profileID, _ := newTestService(t)
	startRegisteredRun(t, service, control)
	before, err := identities.Get(t.Context(), profileID)
	if err != nil {
		t.Fatalf("identity Get() error = %v", err)
	}
	oldMaterial := before.Material()
	defer clearIdentityMaterial(oldMaterial)

	result, err := service.SignOut(t.Context())
	if err != nil || result.State != LogoutSignedOut {
		t.Fatalf("SignOut() = %+v, %v", result, err)
	}
	after, err := identities.Get(t.Context(), profileID)
	if err != nil {
		t.Fatalf("identity Get() error = %v", err)
	}
	material := after.Material()
	defer clearIdentityMaterial(material)
	if after.IsRegistered() || !bytes.Equal(material.MachinePrivateKey, oldMaterial.MachinePrivateKey) ||
		!bytes.Equal(material.NodePrivateKey, oldMaterial.NodePrivateKey) {
		t.Fatalf("after sign out: registered %t, keys kept %t", after.IsRegistered(),
			bytes.Equal(material.NodePrivateKey, oldMaterial.NodePrivateKey))
	}
	control.mu.Lock()
	signOuts, logouts := len(control.signOutMaterials), len(control.logoutMaterials)
	control.mu.Unlock()
	if signOuts != 1 || logouts != 0 {
		t.Fatalf("sign outs %d, logouts %d, want one sign out", signOuts, logouts)
	}
}

// A server without device.signout1 would remove the Device: nothing changes.
func TestService_SignOutOnAnOlderServerChangesNothing(t *testing.T) {
	t.Parallel()

	service, identities, control, profileID, _ := newTestService(t)
	startRegisteredRun(t, service, control)
	control.mu.Lock()
	control.signOutErr = controlplane.ErrSignOutUnsupported
	control.mu.Unlock()

	if _, err := service.SignOut(t.Context()); !errors.Is(err, ErrSignOutUnsupported) {
		t.Fatalf("SignOut() error = %v, want ErrSignOutUnsupported", err)
	}
	after, err := identities.Get(t.Context(), profileID)
	if err != nil || !after.IsRegistered() {
		t.Fatalf("after a refused sign out: registered %t, %v", after.IsRegistered(), err)
	}
}

// A signed-out Device still exists: removing it goes to Core and resets the
// keys, signing out again asks nothing, status says so, and a key cannot
// bring it back.
func TestService_SignedOutDeviceCanStillBeRemoved(t *testing.T) {
	t.Parallel()

	service, identities, control, profileID, _ := newTestService(t)
	startRegisteredRun(t, service, control)
	before, err := identities.Get(t.Context(), profileID)
	if err != nil {
		t.Fatal(err)
	}
	oldMaterial := before.Material()
	defer clearIdentityMaterial(oldMaterial)
	if _, err := service.SignOut(t.Context()); err != nil {
		t.Fatalf("SignOut() error = %v", err)
	}
	if again, err := service.SignOut(t.Context()); err != nil || again.State != LogoutSignedOut {
		t.Fatalf("second SignOut() = %+v, %v", again, err)
	}
	status, err := service.Status(t.Context())
	if err != nil || status.Registration != RegistrationSignedOut {
		t.Fatalf("status registration = %q, %v", status.Registration, err)
	}
	if _, err := service.StartLogin(t.Context(), "mtc1.key.secret"); !errors.Is(err, ErrSignedOutNeedsSignIn) {
		t.Fatalf("StartLogin(key) error = %v, want ErrSignedOutNeedsSignIn", err)
	}
	result, err := service.Logout(t.Context())
	if err != nil || result.State != LogoutCompleted || result.AlreadyRemoved {
		t.Fatalf("Logout() after sign out = %+v, %v", result, err)
	}
	control.mu.Lock()
	signOuts, logouts := len(control.signOutMaterials), len(control.logoutMaterials)
	control.mu.Unlock()
	if signOuts != 1 || logouts != 1 {
		t.Fatalf("Core asked %d sign outs and %d logouts, want one of each", signOuts, logouts)
	}
	assertCredentialsReplaced(t, identities, profileID, oldMaterial.MachinePrivateKey, oldMaterial.NodePrivateKey)
}
