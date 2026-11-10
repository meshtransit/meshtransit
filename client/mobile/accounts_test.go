package mobile

import (
	"errors"
	"fmt"
	"testing"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/daemon"
	"meshtransit.net/client/internal/profile"
)

// The app branches on these values (gomobile passes errors as text only).
func TestSignOutOutcome(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		result daemon.LogoutResult
		err    error
		want   string
	}{
		{daemon.LogoutResult{State: daemon.LogoutSignedOut}, nil, SignOutDone},
		{daemon.LogoutResult{State: daemon.LogoutNotRegistered}, nil, SignOutNoDevice},
		// Core removed an ephemeral Device instead of keeping it.
		{daemon.LogoutResult{State: daemon.LogoutCompleted}, nil, SignOutRemoved},
		{daemon.LogoutResult{}, fmt.Errorf("%w: old", daemon.ErrSignOutUnsupported), SignOutUnsupported},
		{daemon.LogoutResult{}, fmt.Errorf("%w: Workspace", daemon.ErrSignOutNotPermitted), SignOutNotPermitted},
	} {
		if got, err := signOutOutcome(test.result, test.err); err != nil || got != test.want {
			t.Errorf("signOutOutcome(%+v, %v) = %q, %v; want %q", test.result, test.err, got, err, test.want)
		}
	}
	if _, err := signOutOutcome(daemon.LogoutResult{State: "odd"}, nil); err == nil {
		t.Error("an unknown state must be an error, not a sign-out")
	}
	failure := errors.New("unreachable")
	if _, err := signOutOutcome(daemon.LogoutResult{}, failure); !errors.Is(err, failure) {
		t.Errorf("a failure must pass through: %v", err)
	}
}

func TestRemovalOutcome(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		removal daemon.ProfileRemoval
		err     error
		want    string
	}{
		{daemon.ProfileRemoval{Device: daemon.ProfileDeviceRemoved}, nil, "removed"},
		{daemon.ProfileRemoval{Device: daemon.ProfileDeviceLeft}, nil, "left"},
		{
			daemon.ProfileRemoval{},
			fmt.Errorf("%w: %w", daemon.ErrProfileRemoval, controlplane.ErrDeviceNotAuthorized),
			RemoveRefused,
		},
		{daemon.ProfileRemoval{}, profile.ErrActive, RemoveActive},
		{daemon.ProfileRemoval{}, daemon.ErrProfileRemoving, RemoveBusy},
		{
			daemon.ProfileRemoval{Device: daemon.ProfileDeviceRemoved},
			fmt.Errorf("%w: %w: disk", daemon.ErrProfileRemoval, daemon.ErrProfileStillListed),
			RemoveIncomplete + ":removed",
		},
	} {
		if got, err := removalOutcome(test.removal, test.err); err != nil || got != test.want {
			t.Errorf("removalOutcome(%+v, %v) = %q, %v; want %q", test.removal, test.err, got, err, test.want)
		}
	}
	failure := fmt.Errorf("%w: unreachable", daemon.ErrProfileRemoval)
	if _, err := removalOutcome(daemon.ProfileRemoval{}, failure); !errors.Is(err, failure) {
		t.Errorf("a failure must pass through: %v", err)
	}
}
