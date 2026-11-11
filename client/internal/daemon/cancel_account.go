package daemon

import (
	"context"
	"errors"
	"fmt"

	"meshtransit.net/client/internal/identity"
	"meshtransit.net/client/internal/profile"
)

// ErrNotCancelable means the profile is not an account Add account created
// that never held a Device and still waits for its first approval: it may
// be a signed-out or expired Device signing in again, which cancelling
// would remove (S4b §4.3). StopSignIn is its way out.
var ErrNotCancelable = errors.New("daemon: only an added account that never held a device can be cancelled")

// ErrStopSignInUnavailable means meshd could not record a stopped sign-in,
// so it kept the pending approval: without that record, removing the
// profile would drop keys Core may still hold a Device for.
var ErrStopSignInUnavailable = errors.New("daemon: the stopped sign-in could not be recorded; it is still pending")

// CanCancelAddAccount reports whether CancelAddAccount would take id: the
// apps show Cancel only then.
func (s *Service) CanCancelAddAccount(ctx context.Context, id string) bool {
	_, err := s.cancelTarget(ctx, id)
	return err == nil
}

// CancelAddAccount undoes an Add account whose browser approval is still
// pending: it switches back to the profile in use before (or another one
// that holds a Device) and removes the added one. It takes only a profile
// AddAccount created, never registered, and whose keys wait for their
// first approval, so it never removes a Device anyone used. If the
// approval lands just before, the brand-new Device is removed with it.
func (s *Service) CancelAddAccount(ctx context.Context, id string) (ProfileRemoval, profile.Profile, error) {
	if s.gateway {
		return ProfileRemoval{}, profile.Profile{}, ErrGatewayProfiles
	}
	s.addAccountMu.Lock()
	defer s.addAccountMu.Unlock()
	back, err := s.cancelTarget(ctx, id)
	if err != nil {
		return ProfileRemoval{}, profile.Profile{}, err
	}
	if s.profiles.Snapshot().ActiveProfileID == id {
		if _, err := s.ActivateProfile(ctx, back.ID); err != nil {
			return ProfileRemoval{}, profile.Profile{}, fmt.Errorf("switching back to %s: %w", back.ID, err)
		}
	}
	removal, err := s.RemoveProfile(ctx, id, false)
	if err != nil {
		return removal, back, err
	}
	return removal, back, nil
}

// cancelTarget checks id may be cancelled and returns the profile to go
// back to: the one in use when it was added, else another that holds a
// Device (registered or signed out).
func (s *Service) cancelTarget(ctx context.Context, id string) (profile.Profile, error) {
	if _, err := s.profileByID(id); err != nil {
		return profile.Profile{}, err
	}
	display, found := s.ProfileDisplay(id)
	if !found || !display.CreatedByAddAccount || display.RegisteredOnce {
		return profile.Profile{}, ErrNotCancelable
	}
	record, err := s.identities.Get(ctx, id)
	if errors.Is(err, identity.ErrNotFound) {
		return profile.Profile{}, ErrNotCancelable
	}
	if err != nil {
		return profile.Profile{}, fmt.Errorf("reading identity: %w", err)
	}
	if !record.HasPendingAuth() || record.IsRegistered() || record.SignedOut() {
		return profile.Profile{}, ErrNotCancelable
	}
	snapshot := s.profiles.Snapshot()
	var others []profile.Profile
	for _, item := range snapshot.Profiles {
		if item.ID == display.PreviousProfileID {
			return item, nil
		}
		if item.ID != id {
			others = append(others, item)
		}
	}
	states, err := s.ProfileStates(ctx, others)
	if err != nil {
		return profile.Profile{}, err
	}
	for _, item := range others {
		if state := states[item.ID]; state == RegistrationRegistered || state == RegistrationSignedOut {
			return item, nil
		}
	}
	return profile.Profile{}, ErrNotCancelable
}

// StopSignIn drops a profile's pending browser approval and keeps its keys:
// a signed-out Device stays signed out. Core is not asked. Approving the
// dropped link later does nothing: Core registers a Device only when meshd
// follows that link up, which Stop gave up, so the approval just expires
// (TD-CLI-106). The profile is still recorded as one that may hold a Device,
// so removing it or logging out asks Core first: the keys may hold one from
// before (S4b §4.3).
func (s *Service) StopSignIn(ctx context.Context, id string) error {
	if s.gateway {
		return ErrGatewayProfiles
	}
	release, err := s.acquireRegistration(ctx)
	if err != nil {
		return err
	}
	defer release()
	if _, err := s.profileByID(id); err != nil {
		return err
	}
	record, err := s.identities.Get(ctx, id)
	if errors.Is(err, identity.ErrNotFound) {
		return ErrNoPendingAuthorization
	}
	if err != nil {
		return fmt.Errorf("reading identity: %w", err)
	}
	if !record.HasPendingAuth() {
		return ErrNoPendingAuthorization
	}
	// Recorded first: keys without a pending approval that Core may still
	// approve must never read as holding no Device. Unrecorded, the
	// approval stays.
	if err := s.displaySignInStopped(id); err != nil {
		return err
	}
	if _, err := s.identities.SetRegistration(ctx, id, "", false); err != nil {
		return fmt.Errorf("dropping the pending approval: %w", err)
	}
	if s.profiles.Snapshot().ActiveProfileID == id {
		s.signalControlSync()
	}
	return nil
}

// profileByID returns a listed profile, or profile.ErrNotFound.
func (s *Service) profileByID(id string) (profile.Profile, error) {
	for _, item := range s.profiles.Snapshot().Profiles {
		if item.ID == id {
			return item, nil
		}
	}
	return profile.Profile{}, profile.ErrNotFound
}
