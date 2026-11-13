package daemon

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/profile"
	"meshtransit.net/shared/key"
)

// profileMachineKey is the public machine key of a profile's identity.
func profileMachineKey(t *testing.T, service *Service, id string) ([32]byte, []byte) {
	t.Helper()
	record, err := service.identities.Get(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	material := record.Material()
	raw, err := controlplane.ParsePrivateKey(material.MachinePrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	machine, err := key.MachinePrivateFromBytes(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	return [32]byte(machine.Public()), material.MachinePrivateKey
}

// A browser sign-in proves the machine keys of the server's other profiles
// that may hold a Device (duplicate-device design §4.2); an enrollment key
// carries none.
func TestService_SignInProvesSiblings(t *testing.T) {
	t.Parallel()
	service, control, first, _ := addedPendingAccount(t)
	_, firstKey := profileMachineKey(t, service, first)
	control.mu.Lock()
	options := control.registerOptions
	control.mu.Unlock()
	if len(options) != 2 {
		t.Fatalf("%d registrations", len(options))
	}
	if len(options[0].SiblingMachinePrivateKeys) != 0 {
		t.Fatal("an enrollment key carried siblings")
	}
	if got := options[1].SiblingMachinePrivateKeys; len(got) != 1 || !bytes.Equal(got[0], firstKey) {
		t.Fatalf("the added account's sign-in proved %d siblings, want the first profile's key", len(got))
	}
}

// One browser sign-in waits per server (design §4.3): neither another
// sign-in nor another added account starts while one waits.
func TestService_OneSignInPendingPerServer(t *testing.T) {
	t.Parallel()
	service, control, first, added := addedPendingAccount(t)
	if _, err := service.ActivateProfile(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := service.StartLogin(t.Context(), ""); !errors.Is(err, ErrSignInPendingElsewhere) {
		t.Fatalf("StartLogin while another waits = %v", err)
	}
	var pending *SignInPendingElsewhereError
	if _, _, err := service.AddAccount(t.Context(), ""); !errors.As(err, &pending) || pending.ProfileID != added {
		t.Fatalf("AddAccount while another waits = %v", err)
	}
	if err := service.StopSignIn(t.Context(), added); err != nil {
		t.Fatal(err)
	}
	control.mu.Lock()
	control.registrationResults = []controlplane.RegistrationResult{
		{State: controlplane.RegistrationStateAuthorizationRequired, AuthURL: "https://control.example.com/a/3"},
	}
	control.mu.Unlock()
	if _, err := service.StartLogin(t.Context(), ""); err != nil {
		t.Fatalf("StartLogin after the other stopped = %v", err)
	}
}

// Core answering already_in_network switches to the profile already in
// that Network and removes the added one that never held a Device (§9).
func TestService_AlreadyInNetworkSwitches(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		signedOut bool
	}{{name: "signed in"}, {name: "signed out", signedOut: true}} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service, control, first, added := addedPendingAccount(t)
			public, _ := profileMachineKey(t, service, first)
			if test.signedOut {
				if _, err := service.identities.SetSignedOut(t.Context(), first); err != nil {
					t.Fatal(err)
				}
			}
			control.mu.Lock()
			control.registrationResults = []controlplane.RegistrationResult{
				{State: controlplane.RegistrationStateAlreadyInNetwork, SiblingMachineKey: public},
				{State: controlplane.RegistrationStateAuthorizationRequired, AuthURL: "https://control.example.com/a/9"},
			}
			control.mu.Unlock()
			login, err := service.CompleteLogin(t.Context())
			if err != nil || login.State != RegistrationAlreadyInNetwork || login.ProfileID != first {
				t.Fatalf("CompleteLogin = %+v, %v", login, err)
			}
			if (login.AuthURL != "") != test.signedOut {
				t.Fatalf("sign back in URL = %q", login.AuthURL)
			}
			snapshot := service.profiles.Snapshot()
			if snapshot.ActiveProfileID != first || len(snapshot.Profiles) != 1 {
				t.Fatalf("active %s, %d profiles", snapshot.ActiveProfileID, len(snapshot.Profiles))
			}
			if _, err := service.profileByID(added); err == nil {
				t.Fatal("the added account stayed")
			}
		})
	}
}

// A key no profile holds keeps the added account, without its sign-in.
func TestService_AlreadyInNetworkMissingSibling(t *testing.T) {
	t.Parallel()
	service, control, _, added := addedPendingAccount(t)
	control.mu.Lock()
	control.registrationResults = []controlplane.RegistrationResult{
		{State: controlplane.RegistrationStateAlreadyInNetwork, SiblingMachineKey: [32]byte{7}},
	}
	control.mu.Unlock()
	if _, err := service.CompleteLogin(t.Context()); !errors.Is(err, ErrSiblingProfileMissing) {
		t.Fatalf("CompleteLogin = %v", err)
	}
	record, err := service.identities.Get(t.Context(), added)
	if err != nil || record.HasPendingAuth() || len(record.SignInNodePrivateKey()) != 0 {
		t.Fatalf("the ended sign-in stayed: %v", err)
	}
	if service.profiles.Snapshot().ActiveProfileID != added {
		t.Fatal("switched away without a profile to switch to")
	}
}

// A crash after Core's answer was recorded finishes the switch on the next
// start (design N5).
func TestService_ResumeJoined(t *testing.T) {
	t.Parallel()
	service, _, first, added := addedPendingAccount(t)
	service.updateDisplay(added, func(display *Display) { display.JoinedProfileID = first })
	if _, err := service.identities.SetRegistration(t.Context(), added, "", false); err != nil {
		t.Fatal(err)
	}
	service.resumeJoined(t.Context())
	snapshot := service.profiles.Snapshot()
	if snapshot.ActiveProfileID != first || len(snapshot.Profiles) != 1 {
		t.Fatalf("active %s, %d profiles", snapshot.ActiveProfileID, len(snapshot.Profiles))
	}
}

// A waiting sign-in Core refused for good (expired) no longer blocks the
// server: asking about it ends it (design N4, review M3).
func TestService_StalePendingElsewhereEnds(t *testing.T) {
	t.Parallel()
	service, control, first, added := addedPendingAccount(t)
	if _, err := service.ActivateProfile(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	control.mu.Lock()
	control.registerFunc = func(_ context.Context, options controlplane.RegisterOptions,
	) (controlplane.RegistrationResult, error) {
		if options.FollowupURL != "" {
			return controlplane.RegistrationResult{}, &controlplane.RejectedError{Code: "expired"}
		}
		return controlplane.RegistrationResult{
			State:   controlplane.RegistrationStateAuthorizationRequired,
			AuthURL: "https://control.example.com/a/4",
		}, nil
	}
	control.mu.Unlock()
	login, err := service.StartLogin(t.Context(), "")
	if err != nil || login.State != RegistrationPending || login.ProfileID != first {
		t.Fatalf("StartLogin past an expired sign-in = %+v, %v", login, err)
	}
	if record, err := service.identities.Get(t.Context(), added); err != nil || record.HasPendingAuth() {
		t.Fatalf("the expired sign-in stayed: %v", err)
	}
}

// A crash after the switch was recorded but before the sign-in ended: the
// switch ends it, so it neither keeps the profile nor blocks the server
// (review M1).
func TestService_ResumeJoinedEndsTheSignIn(t *testing.T) {
	t.Parallel()
	service, _, first, added := addedPendingAccount(t)
	service.updateDisplay(added, func(display *Display) { display.JoinedProfileID = first })
	service.resumeJoined(t.Context())
	snapshot := service.profiles.Snapshot()
	if snapshot.ActiveProfileID != first || len(snapshot.Profiles) != 1 {
		t.Fatalf("active %s, %d profiles", snapshot.ActiveProfileID, len(snapshot.Profiles))
	}
}

// A profile that may hold a Device is never removed by a switch: only its
// marker goes.
func TestService_JoinKeepsAProfileThatMayHoldADevice(t *testing.T) {
	t.Parallel()
	service, control, first, added := addedPendingAccount(t)
	service.displayRegistered(added)
	public, _ := profileMachineKey(t, service, first)
	control.mu.Lock()
	control.registrationResults = []controlplane.RegistrationResult{
		{State: controlplane.RegistrationStateAlreadyInNetwork, SiblingMachineKey: public},
	}
	control.mu.Unlock()
	login, err := service.CompleteLogin(t.Context())
	if err != nil || login.ProfileID != first {
		t.Fatalf("CompleteLogin = %+v, %v", login, err)
	}
	if _, err := service.profileByID(added); err != nil {
		t.Fatal("a profile that held a Device was removed")
	}
	if display, _ := service.ProfileDisplay(added); display.JoinedProfileID != "" {
		t.Fatal("the switch marker stayed")
	}
	if service.profiles.Snapshot().ActiveProfileID != first {
		t.Fatal("not switched")
	}
}

// A signed-out sibling's sign-in starts only on the sibling itself: if
// another profile became active meanwhile, none starts (review M2).
func TestService_JoinStartsNoSignInOnAnotherProfile(t *testing.T) {
	t.Parallel()
	service, control, first, added := addedPendingAccount(t)
	if _, err := service.identities.SetSignedOut(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	service.updateDisplay(added, func(display *Display) { display.JoinedProfileID = first })
	if _, err := service.identities.SetRegistration(t.Context(), added, "", false); err != nil {
		t.Fatal(err)
	}
	third, err := service.CreateProfile(t.Context(), profile.CreateInput{
		Name:       "third",
		ControlURL: "https://other.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ActivateProfile(t.Context(), third.ID); err != nil {
		t.Fatal(err)
	}
	control.mu.Lock()
	before := len(control.registerOptions)
	control.mu.Unlock()
	login, err := service.finishJoined(t.Context(), added, "", true)
	if err != nil || login.AuthURL != "" {
		t.Fatalf("finishJoined = %+v, %v", login, err)
	}
	control.mu.Lock()
	after := len(control.registerOptions)
	control.mu.Unlock()
	if after != before || service.profiles.Snapshot().ActiveProfileID != third.ID {
		t.Fatal("a sign-in started on the profile in use")
	}
}
