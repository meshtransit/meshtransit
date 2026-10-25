package meshgw

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/daemon"
	"meshtransit.net/client/internal/profile"
)

// fakeController plays the daemon for Enroll.
type fakeController struct {
	snapshot     profile.Snapshot
	registration string
	pinned       bool
	authURL      string
	trusted      []string
	logins       []string
	completions  int
	approved     bool
	// stillPending answers CompleteLogin as Core does when the approval has
	// not come within its poll: pending, with no error.
	stillPending bool
	// trustErr fails TrustControl trustFailures times; -1 fails it always.
	trustErr      error
	trustFailures int
	loginErr      error
}

func (f *fakeController) ListProfiles(context.Context) (profile.Snapshot, error) {
	return f.snapshot, nil
}

func (f *fakeController) CreateProfile(_ context.Context, input profile.CreateInput) (profile.Profile, error) {
	created := profile.Profile{ID: "00000000000000000000000000000001", Name: input.Name, ControlURL: input.ControlURL}
	f.snapshot.Profiles = append(f.snapshot.Profiles, created)
	f.snapshot.ActiveProfileID = created.ID
	return created, nil
}

func (f *fakeController) TrustControl(_ context.Context, fingerprint string) (daemon.ControlTrust, error) {
	f.trusted = append(f.trusted, fingerprint)
	if f.trustErr != nil && f.trustFailures != 0 {
		if f.trustFailures > 0 {
			f.trustFailures--
		}
		return daemon.ControlTrust{}, f.trustErr
	}
	f.pinned = true
	return daemon.ControlTrust{Fingerprint: fingerprint}, nil
}

func (f *fakeController) Status(context.Context) (daemon.Status, error) {
	trust := daemon.ControlTrustUnconfigured
	if f.pinned {
		trust = daemon.ControlTrustPinned
	}
	return daemon.Status{Registration: f.registration, ControlTrust: trust}, nil
}

func (f *fakeController) StartLogin(_ context.Context, key string) (daemon.Login, error) {
	f.logins = append(f.logins, key)
	if f.loginErr != nil {
		return daemon.Login{}, f.loginErr
	}
	if f.authURL != "" {
		f.registration = daemon.RegistrationPending
		return daemon.Login{AuthURL: f.authURL}, nil
	}
	f.registration = daemon.RegistrationRegistered
	return daemon.Login{State: daemon.RegistrationRegistered}, nil
}

func (f *fakeController) CompleteLogin(context.Context) (daemon.Login, error) {
	f.completions++
	if f.stillPending {
		return daemon.Login{State: daemon.RegistrationPending}, nil
	}
	if f.approved {
		f.registration = daemon.RegistrationRegistered
		return daemon.Login{State: daemon.RegistrationRegistered}, nil
	}
	return daemon.Login{}, daemon.ErrAuthorizationPending
}

// restored is a controller whose state came back from the Secret.
func restored(registration string) *fakeController {
	return &fakeController{
		registration: registration,
		pinned:       true,
		snapshot: profile.Snapshot{
			ActiveProfileID: "00000000000000000000000000000001",
			Profiles: []profile.Profile{
				{ID: "00000000000000000000000000000001", ControlURL: "https://control.example.com"},
			},
		},
	}
}

func enrollConfig(t *testing.T, key string) Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key-0")
	if key != "" {
		if err := os.WriteFile(path, []byte(key+"\n"), 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
	}
	return Config{ControlURL: "https://control.example.com", ControlFingerprint: testFingerprint, EnrollmentKeyFile: path}
}

// A first start creates the profile, pins Core's key and registers with the
// pod's enrollment key, all without a person.
func TestEnrollRegistersAFreshGateway(t *testing.T) {
	t.Parallel()
	controller := &fakeController{registration: daemon.RegistrationUnregistered}
	if err := Enroll(t.Context(), controller, enrollConfig(t, "mtk_key0")); err != nil {
		t.Fatalf("Enroll() error = %v", err)
	}
	if len(controller.snapshot.Profiles) != 1 || controller.snapshot.Profiles[0].ControlURL != "https://control.example.com" {
		t.Fatalf("profiles = %+v", controller.snapshot.Profiles)
	}
	if len(controller.trusted) != 1 || controller.trusted[0] != testFingerprint {
		t.Fatalf("trusted = %v, want the pinned fingerprint", controller.trusted)
	}
	if len(controller.logins) != 1 || controller.logins[0] != "mtk_key0" {
		t.Fatalf("logins = %v, want the trimmed key", controller.logins)
	}
}

// A restart with restored state neither pins nor logs in again: the stored
// pin follows Core's key rotations, which the configured one does not, and
// the enrollment key, used once, is not even read.
func TestEnrollKeepsARestoredGateway(t *testing.T) {
	t.Parallel()
	controller := restored(daemon.RegistrationRegistered)
	controller.trustErr, controller.trustFailures = daemon.ErrControlTrust, -1
	if err := Enroll(t.Context(), controller, enrollConfig(t, "")); err != nil {
		t.Fatalf("Enroll() error = %v", err)
	}
	if len(controller.trusted) != 0 || len(controller.logins) != 0 {
		t.Fatalf("trusted %v, logins %v; want neither", controller.trusted, controller.logins)
	}
}

// A replica whose registration waits for approval checks once whether it
// came; approved, it carries on.
func TestEnrollCompletesAnApprovedRegistration(t *testing.T) {
	t.Parallel()
	controller := restored(daemon.RegistrationPending)
	controller.approved = true
	if err := Enroll(t.Context(), controller, enrollConfig(t, "")); err != nil {
		t.Fatalf("Enroll() error = %v", err)
	}
	if controller.completions != 1 {
		t.Fatalf("completions = %d, want 1", controller.completions)
	}
}

// State for another Core, a Core that fails the pin, a Network that wants an
// administrator to approve the Device, or no enrollment key stop the
// gateway, and each is permanent.
func TestEnrollRefuses(t *testing.T) {
	t.Parallel()
	other := restored(daemon.RegistrationRegistered)
	other.snapshot.Profiles[0].ControlURL = "https://other.example.com"
	cases := map[string]struct {
		controller *fakeController
		key        string
		want       error
	}{
		"another Core": {other, "mtk_key0", ErrStateMismatch},
		"a failed pin": {
			&fakeController{registration: daemon.RegistrationUnregistered, trustErr: daemon.ErrControlTrust, trustFailures: -1},
			"mtk_key0", daemon.ErrControlTrust,
		},
		"approval on login": {
			&fakeController{registration: daemon.RegistrationUnregistered, authURL: "https://control.example.com/a/x"},
			"mtk_key0", ErrApprovalRequired,
		},
		"approval still pending": {restored(daemon.RegistrationPending), "", ErrApprovalRequired},
		"pending within the poll": {
			&fakeController{
				registration: daemon.RegistrationPending, pinned: true, stillPending: true,
				snapshot: restored(daemon.RegistrationPending).snapshot,
			},
			"", ErrApprovalRequired,
		},
		"no enrollment key": {&fakeController{registration: daemon.RegistrationUnregistered}, "", ErrEnrollmentKey},
		"a refused key": {
			&fakeController{
				registration: daemon.RegistrationUnregistered,
				loginErr:     fmt.Errorf("%w: key revoked", daemon.ErrRegistration),
			},
			"mtk_key0", daemon.ErrRegistration,
		},
	}
	for name, tc := range cases {
		err := Enroll(t.Context(), tc.controller, enrollConfig(t, tc.key))
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: Enroll() error = %v, want %v", name, err, tc.want)
		}
		if !permanent(err) {
			t.Errorf("%s: permanent(%v) = false", name, err)
		}
	}
	pinFails := cases["a failed pin"].controller
	if len(pinFails.logins) != 0 {
		t.Fatal("Enroll logged in to a Core that failed the pin")
	}
}

// Core unreachable, or busy, may pass: those are retried.
func TestEnrollTemporaryErrors(t *testing.T) {
	t.Parallel()
	for _, err := range []error{
		fmt.Errorf("%w: %w", daemon.ErrControlTrust, fmt.Errorf("%w: dial", controlplane.ErrRegistrationTemporary)),
		fmt.Errorf("%w: %w", daemon.ErrRegistration, controlplane.ErrRegistrationTemporary),
		errors.New("reading profiles: deadline exceeded"),
	} {
		if permanent(err) {
			t.Errorf("permanent(%v) = true, want a retry", err)
		}
	}
}
