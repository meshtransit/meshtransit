package daemon

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"meshtransit.net/client/internal/profile"
)

var (
	// ErrAddAccountUntrusted means the active profile has no pinned control
	// key to share with the new account's profile.
	ErrAddAccountUntrusted = errors.New("daemon: the active profile's server is not trusted yet")
	// ErrAddAccountNoDevice means the active profile holds no Device yet: it
	// is where to sign in, and another profile would only pile up.
	ErrAddAccountNoDevice = errors.New("daemon: the active profile has no device yet")
	// ErrAddAccount means the new account's profile could not be set up;
	// nothing changed for the profile in use.
	ErrAddAccount = errors.New("daemon: adding an account failed")
	// ErrGatewayProfiles means a Kubernetes gateway keeps its one profile.
	ErrGatewayProfiles = errors.New("daemon: a Kubernetes gateway does not add or remove profiles")
)

// AddAccount creates a profile for the active profile's server, pins the
// same control key on it, then makes it active, so the next login signs
// another account in as a new Device while the previous profile keeps its
// own (device logout design §7). Profiles are switched, never logged out.
// name defaults to "<active name> N". A failure before the switch removes
// the new profile and leaves the one in use as it was. It returns the new
// profile and the previous one.
func (s *Service) AddAccount(ctx context.Context, name string) (profile.Profile, profile.Profile, error) {
	if s.gateway {
		return profile.Profile{}, profile.Profile{}, ErrGatewayProfiles
	}
	s.addAccountMu.Lock()
	defer s.addAccountMu.Unlock()
	status, err := s.Status(ctx)
	if err != nil {
		return profile.Profile{}, profile.Profile{}, err
	}
	if status.ActiveProfileID == "" || status.ControlFingerprint == "" {
		return profile.Profile{}, profile.Profile{}, ErrAddAccountUntrusted
	}
	// A profile whose sign-in ended without a Device (Core refused it, or it
	// was stopped: desktop UX A6) may add another account, with new keys;
	// one that never signed in, or still waits for approval, may not.
	switch status.Registration {
	case RegistrationPending:
		return profile.Profile{}, profile.Profile{}, ErrAddAccountNoDevice
	case RegistrationUnregistered:
		if display, found := s.ProfileDisplay(status.ActiveProfileID); !found || !display.SignInStopped {
			return profile.Profile{}, profile.Profile{}, ErrAddAccountNoDevice
		}
	}
	// One browser sign-in waits per server (duplicate-device §4.3, N4): no
	// profile is made for a second one. StartLogin checks it again.
	if current, err := s.profiles.Active(ctx); err == nil {
		release, err := s.acquireRegistration(ctx)
		if err != nil {
			return profile.Profile{}, profile.Profile{}, err
		}
		err = s.checkPendingElsewhere(ctx, current, status.ControlFingerprint)
		release()
		if err != nil {
			return profile.Profile{}, profile.Profile{}, err
		}
	}
	snapshot := s.profiles.Snapshot()
	var active profile.Profile
	taken := make(map[string]bool, len(snapshot.Profiles))
	for _, item := range snapshot.Profiles {
		taken[strings.ToLower(item.Name)] = true
		if item.ID == status.ActiveProfileID {
			active = item
		}
	}
	if active.ID == "" {
		return profile.Profile{}, profile.Profile{}, fmt.Errorf("%w: the active profile is not listed", ErrAddAccount)
	}
	// Added from an added account that never held a Device: going back
	// leads to the account in use before that one, not to the refused one.
	back := s.addAccountBack(active, snapshot.Profiles)
	if strings.TrimSpace(name) == "" {
		name = profile.NextName(active.Name, taken)
	}
	created, err := s.CreateProfile(ctx, profile.CreateInput{Name: name, ControlURL: active.ControlURL})
	if err != nil {
		return profile.Profile{}, profile.Profile{}, err
	}
	s.displayAccountAdded(created.ID, back.ID)
	// Pinned before it is active: the profile in use is untouched if the
	// server does not prove the key, and no other switch is pinned instead.
	if _, err := s.trustProfile(ctx, created, status.ControlFingerprint); err != nil {
		return profile.Profile{}, profile.Profile{}, errors.Join(fmt.Errorf("%w: pinning the server's key: %w",
			ErrAddAccount, err), s.dropAddedProfile(ctx, created.ID))
	}
	if _, err := s.ActivateProfile(ctx, created.ID); err != nil {
		return profile.Profile{}, profile.Profile{}, errors.Join(fmt.Errorf("%w: switching to it: %w", ErrAddAccount,
			err), s.dropAddedProfile(ctx, created.ID))
	}
	return created, back, nil
}

// addAccountBack is where cancelling an account added while active was in
// use goes back to: active itself, or, when active is an added account
// that never held a Device, the account it was added from.
func (s *Service) addAccountBack(active profile.Profile, profiles []profile.Profile) profile.Profile {
	display, found := s.ProfileDisplay(active.ID)
	if !found || !display.CreatedByAddAccount || display.RegisteredOnce || display.PreviousProfileID == "" {
		return active
	}
	for _, item := range profiles {
		if item.ID == display.PreviousProfileID {
			return item
		}
	}
	return active
}

// dropAddedProfile removes a profile AddAccount created and could not set
// up: it holds no Device, so nothing is asked of Core. Bounded, so a busy
// registration gate cannot hold the caller.
func (s *Service) dropAddedProfile(ctx context.Context, id string) error {
	dropCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revokedCredentialsWait)
	defer cancel()
	if _, err := s.RemoveProfile(dropCtx, id, true); err != nil && !errors.Is(err, profile.ErrNotFound) {
		return fmt.Errorf("removing the unused profile %s: %w", id, err)
	}
	return nil
}
