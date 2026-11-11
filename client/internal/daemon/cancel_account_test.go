package daemon

import (
	"errors"
	"path/filepath"
	"testing"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/profile"
)

// withDisplay gives a test service its display files.
func withDisplay(t *testing.T, service *Service) *profile.DisplayStore {
	t.Helper()
	display, err := profile.OpenDisplayStore(filepath.Join(t.TempDir(), "display"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = display.Close() })
	service.display = display
	return display
}

// addedPendingAccount registers the first profile, adds an account and
// starts its browser sign-in, which stays pending.
func addedPendingAccount(t *testing.T) (*Service, *fakeControl, string, string) {
	t.Helper()
	service, _, control, first, _ := newTestService(t)
	withDisplay(t, service)
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatal(err)
	}
	control.registrationResults = []controlplane.RegistrationResult{
		{State: controlplane.RegistrationStateAuthorized, MachineAuthorized: true},
		{State: controlplane.RegistrationStateAuthorizationRequired, AuthURL: "https://control.example.com/a/1"},
	}
	if _, err := service.StartLogin(t.Context(), "credential"); err != nil {
		t.Fatal(err)
	}
	added, _, err := service.AddAccount(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	if login, err := service.StartLogin(t.Context(), ""); err != nil || login.State != RegistrationPending {
		t.Fatalf("StartLogin(added) = %+v, %v; want pending", login, err)
	}
	return service, control, first, added.ID
}

// S4b §4.3: an added account that never held a Device is cancelled back to
// the account in use before, and removed.
func TestService_CancelAddAccount(t *testing.T) {
	t.Parallel()

	service, _, first, added := addedPendingAccount(t)
	if !service.CanCancelAddAccount(t.Context(), added) || service.CanCancelAddAccount(t.Context(), first) {
		t.Fatal("only the added pending account may be cancelled")
	}
	display, found := service.ProfileDisplay(added)
	if !found || !display.CreatedByAddAccount || display.PreviousProfileID != first || display.RegisteredOnce {
		t.Fatalf("added account display = %+v, %t", display, found)
	}
	removal, back, err := service.CancelAddAccount(t.Context(), added)
	if err != nil || back.ID != first || removal.Profile.ID != added {
		t.Fatalf("CancelAddAccount() = %+v, %+v, %v", removal, back, err)
	}
	snapshot := service.profiles.Snapshot()
	if snapshot.ActiveProfileID != first || len(snapshot.Profiles) != 1 {
		t.Fatalf("after cancel: active %s, %d profiles", snapshot.ActiveProfileID, len(snapshot.Profiles))
	}
	if _, found := service.ProfileDisplay(added); found {
		t.Fatal("the cancelled account's display stayed")
	}
}

// Cancel never takes an account that held a Device, a signed-out one, or
// one Add account did not create: they may be a Device signing in again.
func TestService_CancelAddAccountRefusals(t *testing.T) {
	t.Parallel()

	t.Run("registered once", func(t *testing.T) {
		t.Parallel()
		service, _, _, added := addedPendingAccount(t)
		service.displayRegistered(added)
		if _, _, err := service.CancelAddAccount(t.Context(), added); !errors.Is(err, ErrNotCancelable) {
			t.Fatalf("CancelAddAccount() = %v, want ErrNotCancelable", err)
		}
	})
	t.Run("not added", func(t *testing.T) {
		t.Parallel()
		service, _, control, first, _ := newTestService(t)
		withDisplay(t, service)
		if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
			t.Fatal(err)
		}
		control.registrationResults = []controlplane.RegistrationResult{
			{State: controlplane.RegistrationStateAuthorizationRequired, AuthURL: "https://control.example.com/a/2"},
		}
		if _, err := service.StartLogin(t.Context(), ""); err != nil {
			t.Fatal(err)
		}
		if _, _, err := service.CancelAddAccount(t.Context(), first); !errors.Is(err, ErrNotCancelable) {
			t.Fatalf("CancelAddAccount(first sign-in) = %v, want ErrNotCancelable", err)
		}
	})
	t.Run("gateway", func(t *testing.T) {
		t.Parallel()
		service, _, _, added := addedPendingAccount(t)
		service.gateway = true
		if _, _, err := service.CancelAddAccount(t.Context(), added); !errors.Is(err, ErrGatewayProfiles) {
			t.Fatalf("CancelAddAccount() on a gateway = %v", err)
		}
	})
}

// Stop signing in drops the pending approval and keeps the keys.
func TestService_StopSignIn(t *testing.T) {
	t.Parallel()

	service, _, _, pending := addedPendingAccount(t)
	if err := service.StopSignIn(t.Context(), pending); err != nil {
		t.Fatalf("StopSignIn() error = %v", err)
	}
	record, err := service.identities.Get(t.Context(), pending)
	if err != nil || record.HasPendingAuth() || record.IsRegistered() {
		t.Fatalf("after StopSignIn: pending %t, registered %t, %v", record.HasPendingAuth(), record.IsRegistered(), err)
	}
	if err := service.StopSignIn(t.Context(), pending); !errors.Is(err, ErrNoPendingAuthorization) {
		t.Fatalf("StopSignIn() with nothing pending = %v", err)
	}
	if err := service.StopSignIn(t.Context(), "0123456789abcdef0123456789abcdef"); !errors.Is(err,
		profile.ErrNotFound) {
		t.Fatalf("StopSignIn(unknown) = %v", err)
	}
	// Core may still approve the stopped link: the keys are not dropped
	// as holding no Device.
	if !service.mayHoldDevice(pending) {
		t.Fatal("a stopped sign-in must be treated as possibly holding a Device")
	}
}

// Review B2 N1: without its record, a stopped sign-in would read as holding
// no Device, so Stop keeps the approval instead.
func TestService_StopSignInNeedsItsRecord(t *testing.T) {
	t.Parallel()

	service, _, _, pending := addedPendingAccount(t)
	service.display = nil
	if err := service.StopSignIn(t.Context(), pending); !errors.Is(err, ErrStopSignInUnavailable) {
		t.Fatalf("StopSignIn() without display files = %v, want ErrStopSignInUnavailable", err)
	}
	record, err := service.identities.Get(t.Context(), pending)
	if err != nil || !record.HasPendingAuth() {
		t.Fatalf("the approval must stay: pending %t, %v", record.HasPendingAuth(), err)
	}
}

// Review B2 H1: keys an expired Device was renewing, then stopped, may
// still hold that Device: removing the profile asks Core, and a refusal is
// the stopped link still pending. A cancel never takes it.
func TestService_RemoveAfterAStoppedRenewalAsksCore(t *testing.T) {
	t.Parallel()

	service, _, control, first, _ := newTestService(t)
	withDisplay(t, service)
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatal(err)
	}
	control.registrationResults = []controlplane.RegistrationResult{
		{State: controlplane.RegistrationStateAuthorized, MachineAuthorized: true},
		{State: controlplane.RegistrationStateAuthorizationRequired, AuthURL: "https://control.example.com/a/9"},
	}
	if _, err := service.StartLogin(t.Context(), "credential"); err != nil {
		t.Fatal(err)
	}
	// The Device expired: its renewal waits for the browser, then stops.
	if _, err := service.identities.SetRegistration(t.Context(), first, "", false); err != nil {
		t.Fatal(err)
	}
	if login, err := service.StartLogin(t.Context(), ""); err != nil || login.State != RegistrationPending {
		t.Fatalf("renewal = %+v, %v", login, err)
	}
	if err := service.StopSignIn(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.CancelAddAccount(t.Context(), first); !errors.Is(err, ErrNotCancelable) {
		t.Fatalf("a renewed Device must never be cancelled: %v", err)
	}
	other, err := service.CreateProfile(t.Context(), profile.CreateInput{
		Name:       "other",
		ControlURL: "https://control.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ActivateProfile(t.Context(), other.ID); err != nil {
		t.Fatal(err)
	}
	control.mu.Lock()
	before := len(control.logoutURLs)
	control.logoutErr = controlplane.ErrDeviceNotAuthorized
	control.mu.Unlock()
	removal, err := service.RemoveProfile(t.Context(), first, false)
	control.mu.Lock()
	asked := len(control.logoutURLs) - before
	control.mu.Unlock()
	// The stopped link is still valid: approving it now would make a
	// Device nothing holds.
	if err != nil || removal.Device != ProfileDevicePending || asked == 0 {
		t.Fatalf("RemoveProfile() = %+v, %v; Core asked %d times; want Core asked, then pending", removal, err, asked)
	}
}

// Stopping a signed-out Device's sign-in leaves it signed out.
func TestService_StopSignInKeepsASignedOutDevice(t *testing.T) {
	t.Parallel()

	service, _, control, first, _ := newTestService(t)
	withDisplay(t, service)
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatal(err)
	}
	control.registrationResults = []controlplane.RegistrationResult{
		{State: controlplane.RegistrationStateAuthorized, MachineAuthorized: true},
		{State: controlplane.RegistrationStateAuthorizationRequired, AuthURL: "https://control.example.com/a/7"},
	}
	if _, err := service.StartLogin(t.Context(), "credential"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.identities.SetSignedOut(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := service.StartLogin(t.Context(), ""); err != nil {
		t.Fatal(err)
	}
	if err := service.StopSignIn(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	record, err := service.identities.Get(t.Context(), first)
	if err != nil || !record.SignedOut() || record.HasPendingAuth() {
		t.Fatalf("after StopSignIn: signed out %t, pending %t, %v", record.SignedOut(), record.HasPendingAuth(), err)
	}
}

// The display follows the profile's maps: names when a map carries them,
// kept when one does not, reset for a new Device; removal is recorded.
func TestService_DisplayFollowsMaps(t *testing.T) {
	t.Parallel()

	service, _, _, first, _ := newTestService(t)
	withDisplay(t, service)
	named := networkmap.Snapshot{
		Self: networkmap.Node{StableID: "dev-1", Name: "mac.example."},
		Identity: &networkmap.Identity{
			Network: "Lab", Workspace: "Acme", Ownership: networkmap.OwnershipMember,
			Owner: "Alice",
		},
	}
	service.displayMapApplied(first, named)
	unnamed := named
	unnamed.Identity = nil
	service.displayMapApplied(first, unnamed)
	display, found := service.ProfileDisplay(first)
	if !found || display.Network != "Lab" || display.Owner != "Alice" || display.DeviceID != "dev-1" ||
		!display.RegisteredOnce || display.Hostname != "mac.example." {
		t.Fatalf("display = %+v, %t", display, found)
	}
	service.displayDeviceRemoved(first)
	if display, _ := service.ProfileDisplay(first); display.RemovedAt == nil {
		t.Fatal("a removed Device was not recorded")
	}
	renewed := unnamed
	renewed.Self.StableID = "dev-2"
	service.displayMapApplied(first, renewed)
	display, _ = service.ProfileDisplay(first)
	if display.DeviceID != "dev-2" || display.Network != "" || display.RemovedAt != nil || !display.RegisteredOnce {
		t.Fatalf("a new Device must start over: %+v", display)
	}
	service.gateway = true
	service.displayMapApplied(first, named)
	if display, _ := service.ProfileDisplay(first); display.Network != "" {
		t.Fatal("a gateway keeps no display")
	}
}

// S4c §4: the display keeps the owner's email by the map's field; without
// it (an older Core) only while the same person owns the same Device.
func TestService_DisplayKeepsTheOwnersEmail(t *testing.T) {
	t.Parallel()

	service, _, _, first, _ := newTestService(t)
	withDisplay(t, service)
	snapshot := func(owner, email string, known bool) networkmap.Snapshot {
		return networkmap.Snapshot{
			Self: networkmap.Node{StableID: "dev-1", Name: "mac.example."},
			Identity: &networkmap.Identity{
				Network: "Lab", Workspace: "Acme", Ownership: networkmap.OwnershipMember, Owner: owner,
				Email: email, EmailKnown: known,
			},
		}
	}
	emailOf := func() string {
		display, _ := service.ProfileDisplay(first)
		return display.OwnerEmail
	}
	service.displayMapApplied(first, snapshot("Alice", "alice@example.test", true))
	if emailOf() != "alice@example.test" {
		t.Fatalf("email = %q", emailOf())
	}
	service.displayMapApplied(first, snapshot("Alice", "", false))
	if emailOf() != "alice@example.test" {
		t.Fatal("a map from an older Core must keep the email of the same owner")
	}
	service.displayMapApplied(first, snapshot("Bob", "", false))
	if emailOf() != "" {
		t.Fatal("a new owner without an email must not show the last owner's")
	}
	service.displayMapApplied(first, snapshot("Bob", "bob@example.test", true))
	service.displayMapApplied(first, snapshot("Bob", "", true))
	if emailOf() != "" {
		t.Fatal("an empty email field means the account has none")
	}
	service.displayMapApplied(first, snapshot("Bob", "bob@example.test", true))
	renewed := snapshot("Bob", "", false)
	renewed.Self.StableID = "dev-2"
	service.displayMapApplied(first, renewed)
	if emailOf() != "" {
		t.Fatal("a new Device must start without an email")
	}
	// A damaged file never shows an email a map could not carry.
	if err := service.display.Update(first, func(display *Display) {
		display.OwnerEmail = "bob<x@example.test"
	}); err != nil {
		t.Fatal(err)
	}
	if emailOf() != "" {
		t.Fatal("an email Core's rule refuses must not show")
	}
}

// S4c §4, the rest of the keep/clear rule: a map without names keeps the
// email; ownership changing without the field clears it; sign-out and
// removal keep it in the file; a map changing only the email is written;
// a gateway never keeps one.
func TestService_DisplayOwnerEmailEdges(t *testing.T) {
	t.Parallel()

	service, _, _, first, _ := newTestService(t)
	withDisplay(t, service)
	snapshot := func(ownership, owner, email string, known bool) networkmap.Snapshot {
		return networkmap.Snapshot{
			Self: networkmap.Node{StableID: "dev-1", Name: "mac.example."},
			Identity: &networkmap.Identity{
				Network: "Lab", Workspace: "Acme", Ownership: ownership, Owner: owner, Email: email, EmailKnown: known,
			},
		}
	}
	emailOf := func() string {
		display, _ := service.ProfileDisplay(first)
		return display.OwnerEmail
	}
	service.displayMapApplied(first, snapshot(networkmap.OwnershipMember, "Alice", "", true))
	service.displayMapApplied(first, snapshot(networkmap.OwnershipMember, "Alice", "alice@example.test", true))
	if emailOf() != "alice@example.test" {
		t.Fatal("a map that changes only the email must be written")
	}
	unnamed := snapshot(networkmap.OwnershipMember, "Alice", "", false)
	unnamed.Identity = nil
	service.displayMapApplied(first, unnamed)
	if emailOf() != "alice@example.test" {
		t.Fatal("a map without names must keep the email")
	}
	service.displayDeviceRemoved(first)
	if display, _ := service.ProfileDisplay(first); display.OwnerEmail != "alice@example.test" ||
		display.RemovedAt == nil {
		t.Fatalf("a removed Device keeps its names and email: %+v", display)
	}
	service.displayMapApplied(first, snapshot(networkmap.OwnershipWorkspace, "", "", false))
	if stored, _ := service.display.Get(first); stored.OwnerEmail != "" {
		t.Fatal("a Device becoming the Workspace's must clear the stored email")
	}

	gateway, _, _, profileID, _ := newTestService(t)
	withDisplay(t, gateway)
	gateway.gateway = true
	gateway.displayMapApplied(profileID, snapshot(networkmap.OwnershipMember, "Alice", "alice@example.test", true))
	if _, found := gateway.display.Get(profileID); found {
		t.Fatal("a gateway keeps no display file")
	}
}
