package daemon

import (
	"sync"

	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/profile"
)

// Display is what the apps show for a profile (device logout S4b §4.1).
type Display = profile.Display

// displayCache remembers, per profile, what the last map wrote, so a map
// that changes nothing for the display costs no disk read; and which
// profiles' writes failed, so a failing disk logs once per profile, not on
// every map.
type displayCache struct {
	mu      sync.Mutex
	applied map[string]displayApplied
	failing map[string]bool
}

type displayApplied struct {
	deviceID, hostname string
	identity           networkmap.Identity
	named              bool
}

// ProfileDisplay returns the display kept for a profile, and false when it
// has none (or meshd keeps none). Names a map could not carry (a damaged or
// edited file) are left out.
func (s *Service) ProfileDisplay(id string) (Display, bool) {
	if s.display == nil {
		return Display{}, false
	}
	display, found := s.display.Get(id)
	if !found {
		return Display{}, false
	}
	if display.Network != "" || display.Workspace != "" || display.Ownership != "" || display.Owner != "" {
		names := networkmap.Identity{
			Network: display.Network, Workspace: display.Workspace,
			Ownership: display.Ownership, Owner: display.Owner,
		}
		if networkmap.CheckIdentity(&names) != nil {
			display.Network, display.Workspace, display.Ownership, display.Owner = "", "", "", ""
		}
	}
	// Only a member's Device shows an email, and only one Core's rule takes.
	if display.OwnerEmail != "" &&
		(display.Ownership != networkmap.OwnershipMember || !networkmap.CheckEmail(display.OwnerEmail)) {
		display.OwnerEmail = ""
	}
	if display.Hostname != "" && !networkmap.CheckDisplayName(display.Hostname) {
		display.Hostname = ""
	}
	return display, true
}

// mayHoldDevice reports whether a profile whose keys are neither registered
// nor pending may still hold a Device Core knows: it held one before (an
// expiry), or its sign-in was stopped (the keys may be a signed-out
// Device's). Core is then asked before its keys are dropped (S4b §4.3).
func (s *Service) mayHoldDevice(profileID string) bool {
	display, found := s.ProfileDisplay(profileID)
	return found && (display.SignInStopped || display.RegisteredOnce && display.RemovedAt == nil)
}

// displayMapApplied records what the profile's map says of its Device: its
// ID and name, and its account's names when the map carries them (a map
// without them never erases the last ones). A new Device starts over. A
// Kubernetes gateway keeps no display.
func (s *Service) displayMapApplied(profileID string, snapshot networkmap.Snapshot) {
	if s.display == nil || s.gateway || snapshot.Self.StableID == "" {
		return
	}
	applied := displayApplied{deviceID: snapshot.Self.StableID, hostname: snapshot.Self.Name}
	if snapshot.Identity != nil {
		applied.identity, applied.named = *snapshot.Identity, true
	}
	if s.displayUnchanged(profileID, applied) {
		return
	}
	ok := s.updateDisplay(profileID, func(display *Display) {
		if display.DeviceID != "" && display.DeviceID != applied.deviceID {
			*display = Display{
				PreviousProfileID:   display.PreviousProfileID,
				CreatedByAddAccount: display.CreatedByAddAccount, RegisteredOnce: display.RegisteredOnce,
			}
		}
		display.DeviceID, display.Hostname, display.RegisteredOnce = applied.deviceID, applied.hostname, true
		display.RemovedAt, display.SignInStopped = nil, false
		if applied.named {
			display.OwnerEmail = nextOwnerEmail(*display, applied.identity)
			display.Network, display.Workspace = applied.identity.Network, applied.identity.Workspace
			display.Ownership, display.Owner = applied.identity.Ownership, applied.identity.Owner
		}
	})
	if ok {
		s.rememberDisplay(profileID, applied)
	}
}

// nextOwnerEmail is the email to keep once a map named the account (S4c §4):
// the map's own when it carried the field (empty: the account has none).
// Without the field (an older Core) the last one stays only while the same
// person owns the same Device: the map names no owner ID, so a new owner
// name or ownership clears it. A new Device has already reset the display.
// Accepted risk: a Device handed to someone with the same display name
// while Core runs without schema 288 keeps the last owner's email until
// Core sends the field again.
func nextOwnerEmail(current Display, identity networkmap.Identity) string {
	if identity.EmailKnown {
		return identity.Email
	}
	if current.Ownership == identity.Ownership && current.Owner == identity.Owner &&
		identity.Ownership == networkmap.OwnershipMember {
		return current.OwnerEmail
	}
	return ""
}

func (s *Service) displayUnchanged(profileID string, applied displayApplied) bool {
	s.displays.mu.Lock()
	defer s.displays.mu.Unlock()
	last, found := s.displays.applied[profileID]
	// A map without names leaves the last ones: it changes nothing then.
	return found && last.deviceID == applied.deviceID && last.hostname == applied.hostname &&
		(!applied.named || last.named && last.identity == applied.identity)
}

func (s *Service) rememberDisplay(profileID string, applied displayApplied) {
	s.displays.mu.Lock()
	defer s.displays.mu.Unlock()
	if s.displays.applied == nil {
		s.displays.applied = make(map[string]displayApplied)
	}
	if last, found := s.displays.applied[profileID]; found && !applied.named && last.deviceID == applied.deviceID {
		applied.identity, applied.named = last.identity, last.named
	}
	s.displays.applied[profileID] = applied
}

// forgetDisplay drops the profile from the cache: its file changed outside
// a map.
func (s *Service) forgetDisplay(profileID string) {
	s.displays.mu.Lock()
	defer s.displays.mu.Unlock()
	delete(s.displays.applied, profileID)
}

// displayRegistered marks that the profile has held a Device, before its
// registration is persisted: the two files are not written together, and
// a crash between them must leave a profile Cancel refuses, never one it
// removes (S4b §4.1).
func (s *Service) displayRegistered(profileID string) {
	if s.display == nil || s.gateway {
		return
	}
	if !s.updateDisplay(profileID, func(display *Display) { display.RegisteredOnce = true }) && s.logger != nil {
		// Cancel's other guard, the keys' own state, still refuses a
		// registered profile; this one matters only if it expires before a
		// map arrives.
		s.logger.Error("recording that the profile holds a device failed", "profile_id", profileID)
	}
}

// displaySignInStopped records that a pending approval was dropped. Without
// that record keys that may hold a Device from before would read as holding
// none, so a failure is returned and the approval is kept.
func (s *Service) displaySignInStopped(profileID string) error {
	if s.display == nil {
		return ErrStopSignInUnavailable
	}
	defer s.forgetDisplay(profileID)
	if !s.updateDisplay(profileID, func(display *Display) { display.SignInStopped = true }) {
		return ErrStopSignInUnavailable
	}
	return nil
}

// displayAccountAdded records that AddAccount created the profile while
// previous was in use.
func (s *Service) displayAccountAdded(profileID, previous string) {
	if s.display == nil {
		return
	}
	s.updateDisplay(profileID, func(display *Display) {
		display.CreatedByAddAccount, display.PreviousProfileID = true, previous
	})
}

// displayDeviceRemoved records that the profile's Device is gone (Core
// revoked or removed it, or the profile logged out with removal): the names
// stay, for the apps to say which one.
func (s *Service) displayDeviceRemoved(profileID string) {
	if s.display == nil || s.gateway {
		return
	}
	now := s.clock().UTC()
	s.updateDisplay(profileID, func(display *Display) {
		if display.RemovedAt == nil {
			display.RemovedAt = &now
		}
		display.SignInStopped = false
	})
	s.forgetDisplay(profileID)
}

// displayProfileRemoved drops the display with its profile.
func (s *Service) displayProfileRemoved(profileID string) {
	s.forgetDisplay(profileID)
	if s.display == nil {
		return
	}
	if err := s.display.Remove(profileID); err != nil && s.logger != nil {
		s.logger.Warn("removing the profile's display failed", "profile_id", profileID, "error", err)
	}
}

// updateDisplay applies change and reports whether it was written. A
// profile whose writes keep failing is logged once until one succeeds.
func (s *Service) updateDisplay(profileID string, change func(*Display)) bool {
	err := s.display.Update(profileID, change)
	s.displays.mu.Lock()
	defer s.displays.mu.Unlock()
	if err == nil {
		delete(s.displays.failing, profileID)
		return true
	}
	if !s.displays.failing[profileID] && s.logger != nil {
		s.logger.Warn("updating the profile's display failed", "profile_id", profileID, "error", err)
	}
	if s.displays.failing == nil {
		s.displays.failing = make(map[string]bool)
	}
	s.displays.failing[profileID] = true
	return false
}
