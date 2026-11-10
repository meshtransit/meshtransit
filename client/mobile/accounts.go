package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/daemon"
	"meshtransit.net/client/internal/profile"
)

// removeProfileTimeout bounds RemoveProfile: the registration gate, two
// answers from Core (20 s each) and the local writes.
const removeProfileTimeout = 70 * time.Second

// Outcomes the app shows for SignOut, besides an error (device logout
// design §3, §7). gomobile passes errors as text only, so the refusals a
// person acts on come back as values.
const (
	// SignOutDone: the Device is signed out and kept; logging in with the
	// browser signs the same Device back in.
	SignOutDone = "signed_out"
	// SignOutUnsupported: this server only removes Devices; nothing changed.
	SignOutUnsupported = "unsupported"
	// SignOutNotPermitted: a Workspace Device cannot sign out; it can only
	// be removed.
	SignOutNotPermitted = "not_permitted"
	// SignOutNoDevice: the active profile holds no Device; nothing changed.
	SignOutNoDevice = "none"
	// SignOutRemoved: Core removed the Device instead of keeping it (an
	// ephemeral Device): a new login makes a new Device.
	SignOutRemoved = "removed"
	// RemoveRefused: Core refused the profile's keys, so nothing was
	// removed; removing it locally only is what is left.
	RemoveRefused = "refused"
	// RemoveActive: the profile is the one in use; switch first.
	RemoveActive = "active"
	// RemoveBusy: the profile is being removed already; try again.
	RemoveBusy = "busy"
	// RemoveIncomplete: its keys are deleted but the profile is still
	// listed; removing it again finishes. It comes as "incomplete:<what
	// became of the Device>" (incomplete:removed, incomplete:left, …), since
	// a retry finds no keys and reports none.
	RemoveIncomplete = "incomplete"
)

// SignOut signs the active profile's Device out and keeps it: its address,
// name and rules stay in the Network, and it is offline until Login signs
// it back in (with the browser; an enrollment key is refused). It returns
// SignOutDone, SignOutRemoved, SignOutUnsupported, SignOutNotPermitted or
// SignOutNoDevice.
func (engine *Engine) SignOut() (outcome string, err error) {
	defer recoverPanic(&err)
	err = engine.act(func(ctx context.Context) error {
		result, signOutErr := engine.service.SignOut(ctx)
		var mapErr error
		outcome, mapErr = signOutOutcome(result, signOutErr)
		return mapErr
	})
	return outcome, err
}

// profileEntry is one profile as the app lists it.
type profileEntry struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	ControlURL string `json:"controlUrl"`
	Active     bool   `json:"active"`
	// State is registered, signed_out, authorization_required,
	// unregistered, untrusted or unreadable.
	State string `json:"state"`
}

type profileList struct {
	Version  int            `json:"version"`
	Profiles []profileEntry `json:"profiles"`
}

// ProfilesJSON lists the profiles (accounts) and each one's state, as
// {"version":1,"profiles":[{"id","name","controlUrl","active","state"}]}.
func (engine *Engine) ProfilesJSON() (value string, err error) {
	defer recoverPanic(&err)
	err = engine.act(func(ctx context.Context) error {
		snapshot, listErr := engine.service.ListProfiles(ctx)
		if listErr != nil {
			return listErr
		}
		states, statesErr := engine.service.ProfileStates(ctx, snapshot.Profiles)
		if statesErr != nil {
			return statesErr
		}
		list := profileList{Version: 1, Profiles: make([]profileEntry, 0, len(snapshot.Profiles))}
		for _, item := range snapshot.Profiles {
			list.Profiles = append(list.Profiles, profileEntry{
				ID: item.ID, Name: item.Name, ControlURL: item.ControlURL,
				Active: item.ID == snapshot.ActiveProfileID, State: states[item.ID],
			})
		}
		encoded, marshalErr := json.Marshal(list)
		value = string(encoded)
		return marshalErr
	})
	return value, err
}

// AddAccount adds a profile for the active profile's server, pins the same
// key on it and makes it active, so the next Login signs another account in
// as a new Device; the previous profile keeps its Device (switch back with
// ActivateProfile). name may be empty for "<name> 2". It returns the new
// profile's ID.
func (engine *Engine) AddAccount(name string) (id string, err error) {
	defer recoverPanic(&err)
	err = engine.act(func(ctx context.Context) error {
		created, _, addErr := engine.service.AddAccount(ctx, strings.TrimSpace(name))
		id = created.ID
		return addErr
	})
	return id, err
}

// RemoveProfile removes a profile that is not active. Core removes its
// Device first with the profile's own keys, unless local is set (for a
// server that is gone, or keys Core refuses). It returns what became of the
// Device: removed, already_removed, none, pending (an approval link that
// must not be used now), left (local); or, with no error, RemoveRefused
// (Core refused the keys, nothing removed), RemoveActive, RemoveBusy or
// RemoveIncomplete. It may take up to a minute (Core answers twice for a
// profile switched away mid node-key rotation): call it off the main thread.
func (engine *Engine) RemoveProfile(id string, local bool) (outcome string, err error) {
	defer recoverPanic(&err)
	err = engine.actFor(removeProfileTimeout, func(ctx context.Context) error {
		removal, removeErr := engine.service.RemoveProfile(ctx, strings.TrimSpace(id), local)
		var mapErr error
		outcome, mapErr = removalOutcome(removal, removeErr)
		return mapErr
	})
	return outcome, err
}

// signOutOutcome is what the app is told about a sign-out.
func signOutOutcome(result daemon.LogoutResult, err error) (string, error) {
	switch {
	case err == nil && result.State == daemon.LogoutSignedOut:
		return SignOutDone, nil
	case err == nil && result.State == daemon.LogoutNotRegistered:
		return SignOutNoDevice, nil
	case err == nil && result.State == daemon.LogoutCompleted:
		return SignOutRemoved, nil
	case err == nil:
		return "", fmt.Errorf("sign-out ended in an unknown state %q", result.State)
	case errors.Is(err, daemon.ErrSignOutUnsupported):
		return SignOutUnsupported, nil
	case errors.Is(err, daemon.ErrSignOutNotPermitted):
		return SignOutNotPermitted, nil
	}
	return "", err
}

// removalOutcome is what the app is told about a profile removal.
func removalOutcome(removal daemon.ProfileRemoval, err error) (string, error) {
	switch {
	case err == nil:
		return removal.Device, nil
	case errors.Is(err, daemon.ErrProfileRemoval) && errors.Is(err, controlplane.ErrDeviceNotAuthorized):
		return RemoveRefused, nil
	case errors.Is(err, profile.ErrActive):
		return RemoveActive, nil
	case errors.Is(err, daemon.ErrProfileRemoving):
		return RemoveBusy, nil
	case errors.Is(err, daemon.ErrProfileStillListed):
		return RemoveIncomplete + ":" + removal.Device, nil
	}
	return "", err
}
