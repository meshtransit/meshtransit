package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/identity"
	"meshtransit.net/client/internal/profile"
)

// newRemovalService registers the first profile's Device, then makes a
// second profile active, so the first is the one to remove.
func newRemovalService(t *testing.T) (*Service, *identity.Store, *fakeControl, string, string, string) {
	t.Helper()

	service, identities, control, first, stateDir := newTestService(t)
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
	second, err := service.CreateProfile(t.Context(), profile.CreateInput{
		Name:       "home",
		ControlURL: "https://other.example.com",
	})
	if err != nil {
		t.Fatalf("CreateProfile() error = %v", err)
	}
	if _, err := service.ActivateProfile(t.Context(), second.ID); err != nil {
		t.Fatalf("ActivateProfile() error = %v", err)
	}

	return service, identities, control, first, second.ID, stateDir
}

func assertProfileGone(t *testing.T, service *Service, identities *identity.Store, id string) {
	t.Helper()
	for _, item := range service.profiles.Snapshot().Profiles {
		if item.ID == id {
			t.Fatalf("profile %s is still listed", id)
		}
	}
	if _, err := identities.Get(t.Context(), id); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("identity Get() after removal = %v, want ErrNotFound", err)
	}
}

func logoutCalls(control *fakeControl) []controlplane.KeyMaterial {
	control.mu.Lock()
	defer control.mu.Unlock()
	return cloneProtocolMaterials(control.logoutMaterials)
}

func TestService_RemoveProfileRemovesItsDeviceWithItsOwnKeys(t *testing.T) {
	t.Parallel()

	service, identities, control, first, _, _ := newRemovalService(t)
	before, err := identities.Get(t.Context(), first)
	if err != nil {
		t.Fatalf("identity Get() error = %v", err)
	}
	material := before.Material()
	defer clearIdentityMaterial(material)

	removal, err := service.RemoveProfile(t.Context(), first, false)
	if err != nil || removal.Device != ProfileDeviceRemoved || removal.Profile.ID != first {
		t.Fatalf("RemoveProfile() = %+v, %v", removal, err)
	}
	calls := logoutCalls(control)
	defer clearProtocolMaterials(calls)
	if len(calls) != 1 || !bytes.Equal(calls[0].MachinePrivateKey, material.MachinePrivateKey) ||
		!bytes.Equal(calls[0].NodePrivateKey, material.NodePrivateKey) {
		t.Fatal("Core was not asked to remove the Device with the profile's own keys")
	}
	control.mu.Lock()
	urls, options := append([]string(nil), control.logoutURLs...), append([]controlplane.RegisterOptions(nil),
		control.logoutOptions...)
	control.mu.Unlock()
	// The removed profile's server and pin, not the active profile's.
	if len(urls) != 1 || urls[0] != "https://control.example.com" || options[0].PinnedFingerprint != testFingerprint {
		t.Fatalf("Logout went to %v with %+v, want the removed profile's server and pin", urls, options)
	}
	assertProfileGone(t, service, identities, first)
}

func TestService_RemoveProfileOfASignedOutDevice(t *testing.T) {
	t.Parallel()

	service, identities, control, first, _, _ := newRemovalService(t)
	if _, err := identities.SetSignedOut(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	removal, err := service.RemoveProfile(t.Context(), first, false)
	if err != nil || removal.Device != ProfileDeviceRemoved {
		t.Fatalf("RemoveProfile() = %+v, %v", removal, err)
	}
	if calls := logoutCalls(control); len(calls) != 1 {
		t.Fatalf("Logout calls = %d, want 1: a signed-out Device is still in the Network", len(calls))
	}
	assertProfileGone(t, service, identities, first)
}

func TestService_RemoveProfileOfAnAlreadyRemovedDevice(t *testing.T) {
	t.Parallel()

	service, identities, control, first, _, _ := newRemovalService(t)
	control.mu.Lock()
	control.logoutErr = fmt.Errorf("%w: revoked", controlplane.ErrDeviceRemoved)
	control.mu.Unlock()

	removal, err := service.RemoveProfile(t.Context(), first, false)
	if err != nil || removal.Device != ProfileDeviceAlreadyRemoved {
		t.Fatalf("RemoveProfile() = %+v, %v", removal, err)
	}
	assertProfileGone(t, service, identities, first)
}

// A refusal is ambiguous, so nothing is removed (TD-CLI-100, TD-CLI-102).
func TestService_RemoveProfileRefusedKeepsEverything(t *testing.T) {
	t.Parallel()

	for _, refusal := range []error{
		fmt.Errorf("%w: not_authorized", controlplane.ErrDeviceNotAuthorized),
		fmt.Errorf("%w: busy", controlplane.ErrRegistrationTemporary),
	} {
		service, identities, control, first, _, _ := newRemovalService(t)
		control.mu.Lock()
		control.logoutErr = refusal
		control.mu.Unlock()

		if _, err := service.RemoveProfile(t.Context(), first, false); !errors.Is(err, ErrProfileRemoval) ||
			!errors.Is(err, refusal) {
			t.Fatalf("RemoveProfile() error = %v, want a refused removal wrapping %v", err, refusal)
		}
		if _, err := identities.Get(t.Context(), first); err != nil {
			t.Fatalf("a refused removal dropped the keys: %v", err)
		}
		if !profileListed(service, first) {
			t.Fatal("a refused removal dropped the profile")
		}
	}
}

func TestService_RemoveProfileLocalSkipsCore(t *testing.T) {
	t.Parallel()

	service, identities, control, first, _, _ := newRemovalService(t)
	removal, err := service.RemoveProfile(t.Context(), first, true)
	if err != nil || removal.Device != ProfileDeviceLeft {
		t.Fatalf("RemoveProfile(local) = %+v, %v", removal, err)
	}
	if calls := logoutCalls(control); len(calls) != 0 {
		t.Fatalf("--local called Core %d times", len(calls))
	}
	assertProfileGone(t, service, identities, first)
}

func TestService_RemoveProfileRefusesTheActiveOne(t *testing.T) {
	t.Parallel()

	service, identities, control, first, second, _ := newRemovalService(t)
	if _, err := service.RemoveProfile(t.Context(), second, false); !errors.Is(err, profile.ErrActive) {
		t.Fatalf("RemoveProfile(active) error = %v, want profile.ErrActive", err)
	}
	if _, err := service.RemoveProfile(t.Context(), "ffffffffffffffffffffffffffffffff", false); !errors.Is(err,
		profile.ErrNotFound) {
		t.Fatalf("RemoveProfile(missing) error = %v, want profile.ErrNotFound", err)
	}
	if calls := logoutCalls(control); len(calls) != 0 {
		t.Fatalf("a refused removal called Core %d times", len(calls))
	}
	if _, err := identities.Get(t.Context(), first); err != nil || !profileListed(service, second) {
		t.Fatalf("nothing may change: %v", err)
	}
}

func TestService_RemoveProfileWithoutADevice(t *testing.T) {
	t.Parallel()

	service, identities, control, _, second, _ := newRemovalService(t)
	// Make the first profile active again: the second never enrolled.
	if _, err := service.ActivateProfile(t.Context(), service.profiles.Snapshot().Profiles[0].ID); err != nil {
		t.Fatal(err)
	}
	removal, err := service.RemoveProfile(t.Context(), second, false)
	if err != nil || removal.Device != ProfileDeviceNone {
		t.Fatalf("RemoveProfile() = %+v, %v", removal, err)
	}
	if calls := logoutCalls(control); len(calls) != 0 {
		t.Fatalf("a profile without a Device called Core %d times", len(calls))
	}
	assertProfileGone(t, service, identities, second)
}

// An unreadable record cannot be sent to Core: only --local drops it.
func TestService_RemoveProfileWithAnUnreadableRecord(t *testing.T) {
	t.Parallel()

	service, identities, control, first, _, stateDir := newRemovalService(t)
	record := filepath.Join(stateDir, "identities", first+".json")
	if err := os.WriteFile(record, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RemoveProfile(t.Context(), first, false); !errors.Is(err, ErrProfileRemoval) {
		t.Fatalf("RemoveProfile() error = %v, want ErrProfileRemoval", err)
	}
	if !profileListed(service, first) {
		t.Fatal("a failed removal dropped the profile")
	}
	removal, err := service.RemoveProfile(t.Context(), first, true)
	if err != nil || removal.Device != ProfileDeviceLeft {
		t.Fatalf("RemoveProfile(local) = %+v, %v", removal, err)
	}
	if calls := logoutCalls(control); len(calls) != 0 {
		t.Fatalf("an unreadable record was sent to Core %d times", len(calls))
	}
	assertProfileGone(t, service, identities, first)
	if _, err := os.Stat(record); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the unreadable record must be deleted: %v", err)
	}
}

func profileListed(service *Service, id string) bool {
	for _, item := range service.profiles.Snapshot().Profiles {
		if item.ID == id {
			return true
		}
	}
	return false
}

// TD-CLI-102: one unreadable record shows as unreadable, and the others are
// still listed.
func TestService_ProfileStatesReportsAnUnreadableRecord(t *testing.T) {
	t.Parallel()

	service, _, _, first, second, stateDir := newRemovalService(t)
	if err := os.WriteFile(filepath.Join(stateDir, "identities", first+".json"), []byte("{not json"),
		0o600); err != nil {
		t.Fatal(err)
	}
	states, err := service.ProfileStates(t.Context(), service.profiles.Snapshot().Profiles)
	if err != nil {
		t.Fatalf("ProfileStates() error = %v", err)
	}
	if states[first] != ProfileUnreadable || states[second] != ProfileUntrusted {
		t.Fatalf("ProfileStates() = %v, want %s unreadable and %s untrusted", states, first, second)
	}
}

// Review S2c-1 M2: a profile being removed cannot be made active.
func TestService_RemoveProfileBlocksItsActivation(t *testing.T) {
	t.Parallel()

	service, identities, control, first, second, _ := newRemovalService(t)
	activation := make(chan error, 1)
	control.mu.Lock()
	control.logoutHook = func() {
		_, err := service.ActivateProfile(t.Context(), first)
		activation <- err
	}
	control.mu.Unlock()
	removal, err := service.RemoveProfile(t.Context(), first, false)
	if err != nil || removal.Device != ProfileDeviceRemoved {
		t.Fatalf("RemoveProfile() = %+v, %v", removal, err)
	}
	if err := <-activation; !errors.Is(err, ErrProfileRemoving) {
		t.Fatalf("ActivateProfile() during removal = %v, want ErrProfileRemoving", err)
	}
	if active := service.profiles.Snapshot().ActiveProfileID; active != second {
		t.Fatalf("active profile = %s, want %s", active, second)
	}
	assertProfileGone(t, service, identities, first)
	if _, err := service.ActivateProfile(t.Context(), first); !errors.Is(err, profile.ErrNotFound) {
		t.Fatalf("ActivateProfile() after removal = %v, want ErrNotFound", err)
	}
}

// Review S2c-1 M3: switched away mid-rotation, Core may hold the new node
// key; a refusal of the current one is retried with it.
func TestService_RemoveProfileTriesAPendingNodeKey(t *testing.T) {
	t.Parallel()

	service, identities, control, first, _, _ := newRemovalService(t)
	pending, err := controlplane.GenerateNodePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(pending)
	if _, err := identities.BeginNodeKeyRotation(t.Context(), first, pending); err != nil {
		t.Fatal(err)
	}
	control.mu.Lock()
	control.logoutErrs = []error{fmt.Errorf("%w: replaced", controlplane.ErrDeviceNotAuthorized)}
	control.mu.Unlock()

	removal, err := service.RemoveProfile(t.Context(), first, false)
	if err != nil || removal.Device != ProfileDeviceRemoved {
		t.Fatalf("RemoveProfile() = %+v, %v", removal, err)
	}
	calls := logoutCalls(control)
	defer clearProtocolMaterials(calls)
	if len(calls) != 2 || !bytes.Equal(calls[1].NodePrivateKey, pending) ||
		!bytes.Equal(calls[0].MachinePrivateKey, calls[1].MachinePrivateKey) {
		t.Fatalf("Logout calls = %d, want the current then the pending node key", len(calls))
	}
	assertProfileGone(t, service, identities, first)
}

// Review S2c-1 M4: a profile only waiting for a browser approval holds no
// Device yet, but says so; a signed-out Device signing back in still holds one.
func TestService_RemoveProfileWithAPendingApproval(t *testing.T) {
	t.Parallel()

	service, identities, control, first, _, _ := newRemovalService(t)
	if _, err := identities.SetRegistration(t.Context(), first, "https://control.example.com/register/v1/x",
		false); err != nil {
		t.Fatal(err)
	}
	// A first sign-in never approved: Core knows no Device for these keys.
	control.mu.Lock()
	control.logoutErr = fmt.Errorf("%w: unknown", controlplane.ErrDeviceNotAuthorized)
	control.mu.Unlock()
	removal, err := service.RemoveProfile(t.Context(), first, false)
	if err != nil || removal.Device != ProfileDevicePending {
		t.Fatalf("RemoveProfile() = %+v, %v", removal, err)
	}
	assertProfileGone(t, service, identities, first)

	// Re-check S2c-1: a registered Device renewing its expiry waits for an
	// approval too; Core still holds it, so it is removed there.
	service, identities, control, first, _, _ = newRemovalService(t)
	if _, err := identities.SetRegistration(t.Context(), first, "https://control.example.com/register/v1/z",
		false); err != nil {
		t.Fatal(err)
	}
	control.mu.Lock()
	control.logoutErr = nil
	control.mu.Unlock()
	removal, err = service.RemoveProfile(t.Context(), first, false)
	if err != nil || removal.Device != ProfileDeviceRemoved || len(logoutCalls(control)) != 1 {
		t.Fatalf("RemoveProfile() of a renewing Device = %+v, %v", removal, err)
	}
	assertProfileGone(t, service, identities, first)

	service, identities, control, first, _, _ = newRemovalService(t)
	if _, err := identities.SetSignedOut(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := identities.SetRegistration(t.Context(), first, "https://control.example.com/register/v1/y",
		false); err != nil {
		t.Fatal(err)
	}
	removal, err = service.RemoveProfile(t.Context(), first, false)
	if err != nil || removal.Device != ProfileDeviceRemoved || len(logoutCalls(control)) != 1 {
		t.Fatalf("RemoveProfile() of a signed-out Device signing in = %+v, %v", removal, err)
	}
}

// Review S2c-1 M1: keys that could not be deleted fail the removal, and
// running it again finishes.
func TestService_RemoveProfileRetriesUndeletedKeys(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX directory permissions enforced")
	}

	service, identities, _, first, _, stateDir := newRemovalService(t)
	dir := filepath.Join(stateDir, "identities")
	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // a directory: read-only, not private-file mode
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // restores the store directory mode
	if _, err := service.RemoveProfile(t.Context(), first, false); !errors.Is(err, ErrProfileRemoval) {
		t.Fatalf("RemoveProfile() error = %v, want ErrProfileRemoval", err)
	}
	if !profileListed(service, first) {
		t.Fatal("the profile must stay listed while its keys remain")
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // restores the store directory mode
		t.Fatal(err)
	}
	removal, err := service.RemoveProfile(t.Context(), first, false)
	if err != nil || removal.Profile.ID != first {
		t.Fatalf("RemoveProfile() again = %+v, %v", removal, err)
	}
	assertProfileGone(t, service, identities, first)
}

func TestService_RemoveProfileRefusesAGateway(t *testing.T) {
	t.Parallel()

	service, _, _, first, _, _ := newRemovalService(t)
	service.gateway = true
	if _, err := service.RemoveProfile(t.Context(), first, false); !errors.Is(err, ErrGatewayProfiles) {
		t.Fatalf("RemoveProfile() on a gateway = %v, want ErrGatewayProfiles", err)
	}
	if !profileListed(service, first) {
		t.Fatal("a gateway refusal removed the profile")
	}
}
