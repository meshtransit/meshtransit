package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/identity"
	"meshtransit.net/client/internal/profile"
)

// What became of a removed profile's Device (meshctl profile remove).
const (
	// ProfileDeviceRemoved: Core removed the Device with these keys now.
	ProfileDeviceRemoved = "removed"
	// ProfileDeviceAlreadyRemoved: Core proved the Device was already
	// removed (revoked elsewhere, or its Network deleted).
	ProfileDeviceAlreadyRemoved = "already_removed"
	// ProfileDeviceNone: the profile held no Device (never enrolled).
	ProfileDeviceNone = "none"
	// ProfileDevicePending: the profile only waited for a browser approval;
	// approving that link now would make a Device nothing holds.
	ProfileDevicePending = "pending"
	// ProfileDeviceLeft: --local dropped the keys without asking Core; a
	// Device, if Core still has one, is left for an administrator to remove.
	ProfileDeviceLeft = "left"

	// profileLogoutTimeout bounds Core's answer while the registration gate
	// is held.
	profileLogoutTimeout = 20 * time.Second
)

var (
	// ErrProfileRemoval means the profile was not removed: Core did not
	// remove its Device, or its local state could not be deleted.
	ErrProfileRemoval = errors.New("daemon: profile removal failed")
	// ErrProfileRemoving means the profile is being removed: it cannot be
	// made active, or removed a second time, meanwhile.
	ErrProfileRemoving = errors.New("daemon: the profile is being removed")
	// ErrProfileStillListed means the profile's Device was dealt with and its
	// keys deleted, but the profile entry could not be removed: removing it
	// again finishes. The removal returned with it says what became of the
	// Device.
	ErrProfileStillListed = errors.New("daemon: the profile is still listed")
	// ErrProfileActivated means the profile became the active one while it
	// was being removed: it stays as a profile (a backstop; ActivateProfile
	// refuses a profile being removed).
	ErrProfileActivated = errors.New("daemon: the profile became active while it was being removed")
)

// ProfileRemoval reports RemoveProfile.
type ProfileRemoval struct {
	Profile profile.Profile
	// Device is ProfileDeviceRemoved, ProfileDeviceAlreadyRemoved,
	// ProfileDeviceNone, ProfileDevicePending or ProfileDeviceLeft.
	Device string
}

// RemoveProfile deletes an inactive profile and its keys (docs/device-
// logout-design.md §7). A profile that holds a Device, signed in or signed
// out, first has Core remove it with that profile's own keys
// (Logout{keep_device:false}); only a removal Core proved lets the keys go.
// local skips Core: for a Device Core no longer knows, or a server that is
// gone. The active profile is refused (profile.ErrActive).
func (s *Service) RemoveProfile(ctx context.Context, id string, local bool) (ProfileRemoval, error) {
	if s.gateway {
		return ProfileRemoval{}, ErrGatewayProfiles
	}
	unmark, err := s.markRemoving(id)
	if err != nil {
		return ProfileRemoval{}, err
	}
	defer unmark()
	// The gate keeps a login, sign-out or key rotation from writing this
	// profile's identity while it is removed.
	release, err := s.acquireRegistration(ctx)
	if err != nil {
		return ProfileRemoval{}, err
	}
	defer release()
	target, err := s.inactiveProfile(id)
	if err != nil {
		return ProfileRemoval{}, err
	}

	device, err := s.removeProfileDevice(ctx, target, local)
	if err != nil {
		return ProfileRemoval{}, err
	}
	// Persist even if the caller goes away: Core may already have removed
	// the Device, and the keys must not outlive it.
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), credentialsTimeout)
	defer cancel()
	// The keys go first: a profile left without them shows as untrusted and
	// removing it again finishes, while keys left without a profile would
	// still be loaded (MigrateAll) and could not be removed.
	if err := s.identities.Delete(persistCtx, target.ID); err != nil && !errors.Is(err, identity.ErrNotFound) {
		return ProfileRemoval{}, fmt.Errorf("%w: its keys were not deleted (run it again): %w", ErrProfileRemoval,
			err)
	}
	if _, err := s.profiles.Remove(persistCtx, target.ID); err != nil {
		// What became of the Device stays known: a retry finds no keys.
		return ProfileRemoval{Profile: target, Device: device}, s.profileRemovalFailed(target.ID, device, err)
	}

	return ProfileRemoval{Profile: target, Device: device}, nil
}

// markRemoving reserves id for one removal; ActivateProfile refuses it until
// the returned func runs.
func (s *Service) markRemoving(id string) (func(), error) {
	s.removingMu.Lock()
	defer s.removingMu.Unlock()
	if _, removing := s.removingProfiles[id]; removing {
		return nil, ErrProfileRemoving
	}
	// Checked under the same lock ActivateProfile holds: id is not active
	// now, and cannot become active until the removal ends.
	if _, err := s.inactiveProfile(id); err != nil {
		return nil, err
	}
	if s.removingProfiles == nil {
		s.removingProfiles = map[string]struct{}{}
	}
	s.removingProfiles[id] = struct{}{}

	return func() {
		s.removingMu.Lock()
		delete(s.removingProfiles, id)
		s.removingMu.Unlock()
	}, nil
}

// inactiveProfile finds id among the profiles and refuses the active one.
func (s *Service) inactiveProfile(id string) (profile.Profile, error) {
	snapshot := s.profiles.Snapshot()
	for _, item := range snapshot.Profiles {
		if item.ID != id {
			continue
		}
		if snapshot.ActiveProfileID == id {
			return profile.Profile{}, profile.ErrActive
		}
		return item, nil
	}

	return profile.Profile{}, profile.ErrNotFound
}

// removeProfileDevice asks Core to remove the profile's Device, unless the
// profile holds none or local skips Core, and reports what became of it.
func (s *Service) removeProfileDevice(ctx context.Context, target profile.Profile, local bool) (string, error) {
	record, err := s.identities.Get(ctx, target.ID)
	switch {
	case errors.Is(err, identity.ErrNotFound):
		return ProfileDeviceNone, nil
	case err != nil && local:
		// An unreadable record cannot be sent to Core; --local drops it.
		return ProfileDeviceLeft, nil
	case err != nil:
		return "", fmt.Errorf("%w: reading the profile's keys: %w; meshctl profile remove --local drops them",
			ErrProfileRemoval, err)
	case local:
		return ProfileDeviceLeft, nil
	case record.IsRegistered() || record.SignedOut():
		// A Device, even one signing back in (a pending approval of a
		// signed-out Device).
		return s.logoutProfileDevice(ctx, target, record)
	case record.HasPendingAuth():
		// A first sign-in waiting for approval holds no Device yet, but a
		// Device renewing its expiry (meshctl login) waits the same way:
		// Core tells them apart.
		device, err := s.logoutProfileDevice(ctx, target, record)
		if errors.Is(err, controlplane.ErrDeviceNotAuthorized) {
			return ProfileDevicePending, nil
		}
		return device, err
	}

	return ProfileDeviceNone, nil
}

// logoutProfileDevice has Core remove the Device with the profile's keys.
// A profile switched away during a node-key rotation may have had its new
// node key committed: a refusal of the current key is retried with it.
// Staged machine keys need no retry: only a gateway stages them, and a
// gateway removes no profile.
func (s *Service) logoutProfileDevice(ctx context.Context, target profile.Profile, record identity.Record) (string,
	error,
) {
	material := record.Material()
	defer clearIdentityMaterial(material)
	pendingNode := record.PendingNodePrivateKey()
	defer clear(pendingNode)
	options := controlplane.RegisterOptions{
		Hostname:          s.hostname,
		Version:           "meshd/" + s.build.Version,
		PinnedFingerprint: record.ControlKeyFingerprint(),
	}
	nodeKeys := [][]byte{material.NodePrivateKey}
	if len(pendingNode) > 0 {
		nodeKeys = append(nodeKeys, pendingNode)
	}
	var logoutErr error
	for _, nodeKey := range nodeKeys {
		protocolMaterial := toProtocolMaterial(identity.Material{
			MachinePrivateKey: material.MachinePrivateKey,
			NodePrivateKey:    nodeKey,
			ControlPublicKey:  material.ControlPublicKey,
		})
		callCtx, cancel := context.WithTimeout(ctx, profileLogoutTimeout)
		logoutErr = s.prober.Logout(callCtx, target.ControlURL, protocolMaterial, options)
		cancel()
		clearProtocolMaterial(protocolMaterial)
		switch {
		case logoutErr == nil:
			return ProfileDeviceRemoved, nil
		case errors.Is(logoutErr, controlplane.ErrDeviceRemoved):
			return ProfileDeviceAlreadyRemoved, nil
		case !errors.Is(logoutErr, controlplane.ErrDeviceNotAuthorized):
			// Only a refused key is worth another try.
			return "", fmt.Errorf("%w: %w", ErrProfileRemoval, logoutErr)
		}
	}
	// A refusal is ambiguous (the Device may still hold its address), so the
	// keys stay, as for logout (TD-CLI-100).
	return "", fmt.Errorf("%w: %w", ErrProfileRemoval, logoutErr)
}

// profileRemovalFailed reports a profile entry that could not be removed
// after its keys were. Its keys are gone, so it shows as untrusted, and
// removing it again finishes.
func (s *Service) profileRemovalFailed(id, device string, err error) error {
	if errors.Is(err, profile.ErrActive) {
		// markRemoving makes this unreachable; the session loop must not
		// keep a profile without keys: let it notice.
		s.signalControlSync()
		return fmt.Errorf("%w: %s", ErrProfileActivated, id)
	}

	// A retry finds no keys and reports no Device: say now what became of it.
	return fmt.Errorf("%w: %w: its keys are deleted (device: %s) but the entry was not removed (run it again): %w",
		ErrProfileRemoval, ErrProfileStillListed, device, err)
}
