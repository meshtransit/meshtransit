package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/identity"
	"meshtransit.net/client/internal/profile"
	"meshtransit.net/shared/key"
)

// RegistrationAlreadyInNetwork is a login's state when the person chose,
// on the approval page, the Device another profile of this machine already
// is in that Network (duplicate-device design §9): no Device was made and
// meshd switched to that profile, whose ID the login carries.
const RegistrationAlreadyInNetwork = "already_in_network"

// maxSiblingProofs bounds the siblings a sign-in proves (mtcp-v1 §6.2).
const maxSiblingProofs = 16

var (
	// ErrSignInPendingElsewhere means another profile on the same server
	// waits for its browser sign-in: one at a time per server, so two new
	// accounts never wait unaware of each other (design §4.3). Stop that
	// sign-in, or switch to it.
	ErrSignInPendingElsewhere = errors.New("daemon: another account on this server is waiting for its browser sign-in")
	// ErrSiblingProfileMissing means Core switched the sign-in to a profile
	// that is no longer on this computer: the added profile is kept, and the
	// person signs in again.
	ErrSiblingProfileMissing = errors.New(
		"daemon: the account already in that Network is no longer on this computer",
	)
)

// SignInPendingElsewhereError names the profile whose sign-in waits.
type SignInPendingElsewhereError struct{ ProfileID string }

func (e *SignInPendingElsewhereError) Error() string {
	return ErrSignInPendingElsewhere.Error() + " (" + e.ProfileID + ")"
}

func (e *SignInPendingElsewhereError) Unwrap() error { return ErrSignInPendingElsewhere }

// sameServer reports whether item is another profile of active's server:
// the same control URL and pinned control key.
func (s *Service) sameServer(ctx context.Context, active, item profile.Profile, pin string,
) (identity.Record, bool) {
	if item.ID == active.ID || item.ControlURL != active.ControlURL {
		return identity.Record{}, false
	}
	record, err := s.identities.Get(ctx, item.ID)
	if err != nil || record.IsGateway() || record.ControlKeyFingerprint() != pin {
		return identity.Record{}, false
	}
	return record, true
}

// pendingProbeTimeout bounds asking Core about another profile's sign-in.
const pendingProbeTimeout = 3 * time.Second

// checkPendingElsewhere refuses with *SignInPendingElsewhereError when
// another profile of active's server waits for its browser sign-in. A
// waiting sign-in is first asked about once (design N4): one Core refused
// for good (expired, unknown) ends here, so an old one never blocks the
// server; one Core approved meanwhile completes. The caller holds the
// registration gate.
func (s *Service) checkPendingElsewhere(ctx context.Context, active profile.Profile, pin string) error {
	for _, item := range s.profiles.Snapshot().Profiles {
		record, ok := s.sameServer(ctx, active, item, pin)
		if !ok || !record.HasPendingAuth() {
			continue
		}
		probeCtx, cancel := context.WithTimeout(ctx, pendingProbeTimeout)
		login, err := s.registerWithRecord(probeCtx, ctx, item, record, "", record.PendingAuthURL())
		cancel()
		if _, refused := errors.AsType[*controlplane.RejectedError](err); refused {
			if endErr := s.endRefusedSignIn(ctx, item.ID); endErr != nil {
				return &SignInPendingElsewhereError{ProfileID: item.ID}
			}
			continue
		}
		if err == nil && login.State != RegistrationPending {
			continue // approved meanwhile, or switched to another account
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return &SignInPendingElsewhereError{ProfileID: item.ID}
	}
	return nil
}

// siblingMachineKeys returns the machine keys of active's other profiles on
// the same server that may hold a Device (design §4.2): registered, signed
// out, or held one before. At most 16; the caller clears them.
func (s *Service) siblingMachineKeys(ctx context.Context, active profile.Profile, pin string) [][]byte {
	var keys [][]byte
	for _, item := range s.profiles.Snapshot().Profiles {
		record, ok := s.sameServer(ctx, active, item, pin)
		if !ok || !record.IsRegistered() && !record.SignedOut() && !s.mayHoldDevice(item.ID) {
			continue
		}
		if len(keys) == maxSiblingProofs {
			if s.logger != nil {
				s.logger.WarnContext(ctx, "more accounts on this server than a sign-in proves; proving 16")
			}
			break
		}
		material := record.Material()
		keys = append(keys, append([]byte(nil), material.MachinePrivateKey...))
		clearIdentityMaterial(material)
	}
	return keys
}

// profileByMachineKey returns active's other profile on the same server
// whose machine key is public.
func (s *Service) profileByMachineKey(ctx context.Context, active profile.Profile, pin string,
	public [32]byte,
) (profile.Profile, bool) {
	for _, item := range s.profiles.Snapshot().Profiles {
		record, ok := s.sameServer(ctx, active, item, pin)
		if !ok {
			continue
		}
		material := record.Material()
		raw, err := controlplane.ParsePrivateKey(material.MachinePrivateKey)
		clearIdentityMaterial(material)
		if err != nil {
			continue
		}
		machine, err := key.MachinePrivateFromBytes(raw[:])
		clear(raw[:])
		if err == nil && [32]byte(machine.Public()) == public {
			return item, true
		}
	}
	return profile.Profile{}, false
}

// joinedExisting ends a sign-in Core answered already_in_network
// (design §9). It is Core's final answer: the pending approval and its key
// go. The switch to the sibling profile is recorded first (N5), so a crash
// before it happens is finished on the next start.
func (s *Service) joinedExisting(ctx context.Context, active profile.Profile, record identity.Record,
	sibling [32]byte,
) (Login, error) {
	found, ok := s.profileByMachineKey(ctx, active, record.ControlKeyFingerprint(), sibling)
	if ok && s.display != nil {
		if !s.updateDisplay(active.ID, func(display *Display) { display.JoinedProfileID = found.ID }) {
			return Login{}, fmt.Errorf("%w: recording the switch to the account already in that Network failed",
				ErrRegistration)
		}
	}
	if _, err := s.identities.SetRegistration(ctx, active.ID, "", false); err != nil {
		return Login{}, fmt.Errorf("ending the sign-in: %w", err)
	}
	if _, err := s.identities.SetSignInNodeKey(ctx, active.ID, nil); err != nil {
		return Login{}, fmt.Errorf("dropping the sign-in key: %w", err)
	}
	if !ok {
		return Login{}, ErrSiblingProfileMissing
	}
	return Login{ProfileID: found.ID, State: RegistrationAlreadyInNetwork, joinedFrom: active.ID}, nil
}

// joinedSibling is the profile a finished sign-in switches to: the marker,
// or, without a display store, the one Core named (review L2).
func (s *Service) joinedSibling(addedID, named string) (Display, string, bool) {
	display, found := s.ProfileDisplay(addedID)
	if found && display.JoinedProfileID != "" {
		return display, display.JoinedProfileID, true
	}
	if s.display == nil && named != "" {
		return Display{}, named, true
	}
	return display, "", false
}

// finishJoined switches from the profile whose sign-in Core answered
// already_in_network to the profile already in that Network, then removes
// the first when Add account made it and it never held a Device (design
// §9). A signed-out sibling starts its sign-in again when signIn is set: the
// approval page already said so. It returns the login the apps see.
func (s *Service) finishJoined(ctx context.Context, addedID, named string, signIn bool) (Login, error) {
	s.addAccountMu.Lock()
	defer s.addAccountMu.Unlock()
	display, siblingID, found := s.joinedSibling(addedID, named)
	if !found {
		// Another caller finished it first (review L1).
		if named != "" && s.profiles.Snapshot().ActiveProfileID == named {
			return Login{ProfileID: named, State: RegistrationAlreadyInNetwork}, nil
		}
		return Login{}, ErrNoPendingAuthorization
	}
	if _, err := s.profileByID(siblingID); err != nil {
		s.clearJoined(addedID)
		return Login{}, ErrSiblingProfileMissing
	}
	// Core's answer was final: a sign-in a crash left waiting ends now, or it
	// would keep the profile and block the server's next sign-in (review M1).
	if err := s.endJoinedSignIn(ctx, addedID); err != nil {
		return Login{}, err
	}
	if s.profiles.Snapshot().ActiveProfileID == addedID {
		if _, err := s.ActivateProfile(ctx, siblingID); err != nil {
			return Login{}, fmt.Errorf("switching to the account already in that Network: %w", err)
		}
	}
	if s.droppableAfterJoin(ctx, addedID, display) {
		if err := s.dropAddedProfile(ctx, addedID); err != nil {
			return Login{}, err
		}
	} else {
		s.clearJoined(addedID)
	}
	login := Login{ProfileID: siblingID, State: RegistrationAlreadyInNetwork}
	record, err := s.identities.Get(ctx, siblingID)
	if err != nil {
		// The switch happened; the apps read the profile's state next.
		return login, nil
	}
	switch {
	case record.HasPendingAuth():
		login.AuthURL = record.PendingAuthURL()
	case signIn && (record.SignedOut() || !record.IsRegistered()) &&
		s.profiles.Snapshot().ActiveProfileID == siblingID:
		// Only on the sibling itself: StartLogin signs in the active profile,
		// which the person may have changed meanwhile (review M2).
		started, err := s.StartLogin(ctx, "")
		if err != nil {
			return login, fmt.Errorf("signing in to the account already in that Network: %w", err)
		}
		login.AuthURL = started.AuthURL
	}
	return login, nil
}

// endJoinedSignIn drops a joined profile's pending approval and sign-in
// key, under the registration gate.
func (s *Service) endJoinedSignIn(ctx context.Context, id string) error {
	record, err := s.identities.Get(ctx, id)
	if errors.Is(err, identity.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading identity: %w", err)
	}
	if !record.HasPendingAuth() && len(record.SignInNodePrivateKey()) == 0 {
		return nil
	}
	release, err := s.acquireRegistration(ctx)
	if err != nil {
		return err
	}
	defer release()
	if _, err := s.identities.SetRegistration(ctx, id, "", false); err != nil {
		return fmt.Errorf("ending the sign-in: %w", err)
	}
	if _, err := s.identities.SetSignInNodeKey(ctx, id, nil); err != nil {
		return fmt.Errorf("dropping the sign-in key: %w", err)
	}
	return nil
}

func (s *Service) clearJoined(id string) {
	if s.display != nil {
		s.updateDisplay(id, func(display *Display) { display.JoinedProfileID = "" })
	}
}

// droppableAfterJoin: Add account made the profile and it never held a
// Device, so nothing is lost removing it (CancelAddAccount's rule without
// its pending approval, which Core ended).
func (s *Service) droppableAfterJoin(ctx context.Context, id string, display Display) bool {
	if !display.CreatedByAddAccount || display.RegisteredOnce || display.SignInStopped {
		return false
	}
	record, err := s.identities.Get(ctx, id)
	return err == nil && !record.IsRegistered() && !record.SignedOut() && !record.HasPendingAuth()
}

// resumeJoined finishes switches a crash interrupted (N5); it starts no
// sign-in.
func (s *Service) resumeJoined(ctx context.Context) {
	if s.display == nil || s.gateway {
		return
	}
	for _, item := range s.profiles.Snapshot().Profiles {
		display, found := s.ProfileDisplay(item.ID)
		if !found || display.JoinedProfileID == "" {
			continue
		}
		if _, err := s.finishJoined(ctx, item.ID, "", false); err != nil && s.logger != nil {
			s.logger.WarnContext(ctx, "finishing the switch to the account already in a Network failed",
				"profile_id", item.ID, "error", err)
		}
	}
}
