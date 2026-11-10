package daemon

import (
	"errors"
	"testing"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/profile"
)

// Device logout design §7: an account is added as a profile for the same
// server with the same pinned key; the previous profile keeps its Device.
func TestService_AddAccount(t *testing.T) {
	t.Parallel()

	service, identities, control, first, _ := newTestService(t)
	if _, _, err := service.AddAccount(t.Context(), ""); !errors.Is(err, ErrAddAccountUntrusted) {
		t.Fatalf("AddAccount() untrusted = %v, want ErrAddAccountUntrusted", err)
	}
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.AddAccount(t.Context(), ""); !errors.Is(err, ErrAddAccountNoDevice) {
		t.Fatalf("AddAccount() without a Device = %v, want ErrAddAccountNoDevice", err)
	}
	control.registrationResults = []controlplane.RegistrationResult{{
		State: controlplane.RegistrationStateAuthorized, MachineAuthorized: true,
	}}
	if _, err := service.StartLogin(t.Context(), "credential"); err != nil {
		t.Fatal(err)
	}

	created, previous, err := service.AddAccount(t.Context(), "")
	if err != nil || previous.ID != first || created.Name != "test 2" ||
		created.ControlURL != "https://control.example.com" {
		t.Fatalf("AddAccount() = %+v, %+v, %v", created, previous, err)
	}
	status, err := service.Status(t.Context())
	if err != nil || status.ActiveProfileID != created.ID || status.ControlFingerprint != testFingerprint ||
		status.Registration != RegistrationUnregistered {
		t.Fatalf("after AddAccount: %+v, %v", status, err)
	}
	if record, err := identities.Get(t.Context(), first); err != nil || !record.IsRegistered() {
		t.Fatalf("the previous profile must keep its Device: %v", err)
	}
	// The next one is "test 3"; a name may be given.
	if _, err := service.ActivateProfile(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	named, _, err := service.AddAccount(t.Context(), "Work")
	if err != nil || named.Name != "Work" {
		t.Fatalf("AddAccount(Work) = %+v, %v", named, err)
	}
}

// A failed pin removes the new profile; the one in use is never switched away from.
func TestService_AddAccountRollsBack(t *testing.T) {
	t.Parallel()

	service, identities, control, first, _ := newTestService(t)
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatal(err)
	}
	control.registrationResults = []controlplane.RegistrationResult{{
		State: controlplane.RegistrationStateAuthorized, MachineAuthorized: true,
	}}
	if _, err := service.StartLogin(t.Context(), "credential"); err != nil {
		t.Fatal(err)
	}
	control.mu.Lock()
	control.bootstrapErr = errors.New("control unreachable")
	control.mu.Unlock()

	if _, _, err := service.AddAccount(t.Context(), ""); !errors.Is(err, ErrAddAccount) {
		t.Fatalf("AddAccount() error = %v, want ErrAddAccount", err)
	}
	snapshot := service.profiles.Snapshot()
	if snapshot.ActiveProfileID != first || len(snapshot.Profiles) != 1 {
		t.Fatalf("after a failed AddAccount: active %s, profiles %+v", snapshot.ActiveProfileID, snapshot.Profiles)
	}
	// The profile in use was never switched away from, and keeps its Device.
	if record, err := identities.Get(t.Context(), first); err != nil || !record.IsRegistered() {
		t.Fatalf("the profile in use must keep its Device: %v", err)
	}
}

func TestService_AddAccountRefusals(t *testing.T) {
	t.Parallel()

	service, _, control, _, _ := newTestService(t)
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatal(err)
	}
	control.registrationResults = []controlplane.RegistrationResult{{
		State: controlplane.RegistrationStateAuthorized, MachineAuthorized: true,
	}}
	if _, err := service.StartLogin(t.Context(), "credential"); err != nil {
		t.Fatal(err)
	}
	// A name already taken (the store folds case).
	if _, _, err := service.AddAccount(t.Context(), "TEST"); !errors.Is(err, profile.ErrDuplicate) {
		t.Fatalf("AddAccount(TEST) = %v, want profile.ErrDuplicate", err)
	}
	if got := len(service.profiles.Snapshot().Profiles); got != 1 {
		t.Fatalf("a refused name left %d profiles", got)
	}
	service.gateway = true
	if _, _, err := service.AddAccount(t.Context(), ""); !errors.Is(err, ErrGatewayProfiles) {
		t.Fatalf("AddAccount() on a gateway = %v, want ErrGatewayProfiles", err)
	}
}
