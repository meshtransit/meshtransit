package daemon

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/identity"
)

const (
	// ControlSessionDown means meshd was taken off the network (`meshctl
	// down`, or briefly while logging out): no control session, data plane or
	// DNS, while the profile stays registered.
	ControlSessionDown = "down"

	// ConnectionDown and ConnectionUp are the wanted states Down and Up report.
	ConnectionDown = "down"
	ConnectionUp   = "up"
	// LogoutCompleted reports that Core ended the Device, or had already, and
	// the profile now holds new unregistered keys.
	LogoutCompleted = "logged_out"
	// LogoutNotRegistered reports that the active profile had no Device.
	LogoutNotRegistered = "not_registered"
	// LogoutSignedOut reports that Core signed the Device out and kept it:
	// the profile keeps its keys, and meshctl login signs it back in.
	LogoutSignedOut = "signed_out"

	// runtimeStopTimeout bounds how long Down and Logout wait for the session
	// loop to stop the runtime.
	runtimeStopTimeout = 10 * time.Second
	runtimeStopPoll    = 50 * time.Millisecond
	credentialsTimeout = 5 * time.Second
)

var (
	// ErrLogout indicates that Core could not log the Device out.
	ErrLogout = errors.New("daemon: logout failed")
	// ErrSignOutUnsupported means the server only removes Devices: signing
	// out needs logout --remove there. Nothing was changed.
	ErrSignOutUnsupported = errors.New("daemon: this server removes the device when it signs out")
	// ErrSignedOutNeedsSignIn means an enrollment key was given for a
	// signed-out Device: only its owner signing in brings it back.
	ErrSignedOutNeedsSignIn = errors.New("daemon: this device is signed out; sign in without a key")
	// ErrSignOutNotPermitted means the Device cannot sign out (a Workspace
	// Device): remove it, or ask an administrator.
	ErrSignOutNotPermitted = errors.New("daemon: this device cannot sign out")
	// ErrControlSessionBusy means the session loop did not stop the runtime
	// in time (it was finishing other control work); retrying succeeds.
	ErrControlSessionBusy = errors.New("daemon: the control session is still stopping")
)

// ConnectionChange reports a Down or Up request.
type ConnectionChange struct {
	State   string
	Changed bool
}

// LogoutResult reports a Logout request.
type LogoutResult struct {
	ProfileID string
	State     string
	// AlreadyRemoved means Core proved the Device was already removed with
	// these keys (revoked elsewhere, or its Network deleted); only the local
	// keys were replaced.
	AlreadyRemoved bool
}

// Down takes meshd off the network and keeps it off, across restarts, until
// Up: it stops the control session, data plane and DNS without ending the
// Device. It returns once the runtime has stopped.
func (s *Service) Down(ctx context.Context) (ConnectionChange, error) {
	acknowledged := s.downAcks.Load()
	changed, err := s.profiles.SetDisconnected(ctx, true)
	if err != nil {
		return ConnectionChange{}, fmt.Errorf("saving the disconnected preference: %w", err)
	}
	s.signalControlSync()
	if err := s.waitForControlSessionDown(ctx, acknowledged); err != nil {
		return ConnectionChange{}, fmt.Errorf("disconnecting: %w", err)
	}

	return ConnectionChange{State: ConnectionDown, Changed: changed}, nil
}

// Up clears a Down; the session loop connects the active profile again.
func (s *Service) Up(ctx context.Context) (ConnectionChange, error) {
	changed, err := s.profiles.SetDisconnected(ctx, false)
	if err != nil {
		return ConnectionChange{}, fmt.Errorf("saving the connected preference: %w", err)
	}
	// Already wanted but waiting to retry a failed runtime (on a phone, the
	// VPN interface was not there yet): try now rather than after the
	// backoff. A running session is never restarted by a repeated Up.
	if changed || s.runtimePending.Load() {
		s.signalControlSync()
	}

	return ConnectionChange{State: ConnectionUp, Changed: changed}, nil
}

// Logout ends the active profile's Device in Core (mtcp-v1 §6.5) and gives
// the profile new unregistered keys, so `meshctl up` enrolls a new Device.
func (s *Service) Logout(ctx context.Context) (LogoutResult, error) {
	return s.logout(ctx, false)
}

// SignOut signs the active profile's Device out and keeps it (schema 283):
// the profile keeps its keys but is no longer registered, so meshd stays off
// the network until `meshctl login` signs the same Device back in. A server
// without device.signout1 answers ErrSignOutUnsupported and nothing changes.
func (s *Service) SignOut(ctx context.Context) (LogoutResult, error) {
	return s.logout(ctx, true)
}

// logout runs Logout or SignOut. The map stream stops first: its session
// uses the same machine key and would replace the logout session. It stops
// before taking the registration gate, which the session loop may need to
// finish a pending node-key rotation on its way to the down state.
func (s *Service) logout(ctx context.Context, keep bool) (LogoutResult, error) {
	if s.gateway {
		return LogoutResult{}, ErrGatewayLogout
	}
	// Nothing to stop or tell Core when the profile holds no Device; the
	// check repeats under the gate. A signed-out Device is still one:
	// removing it goes to Core, signing it out again changes nothing.
	if profileID, registered, signedOut, err := s.activeRegistration(ctx); err != nil {
		return LogoutResult{}, err
	} else if signedOut && keep {
		return LogoutResult{ProfileID: profileID, State: LogoutSignedOut}, nil
	} else if !registered && !signedOut && !s.mayHoldDevice(profileID) {
		return LogoutResult{ProfileID: profileID, State: LogoutNotRegistered}, nil
	}
	s.loggingOut.Store(true)
	defer func() {
		s.loggingOut.Store(false)
		s.signalControlSync()
	}()
	acknowledged := s.downAcks.Load()
	s.signalControlSync()
	if err := s.waitForControlSessionDown(ctx, acknowledged); err != nil {
		return LogoutResult{}, fmt.Errorf("stopping the control session before logout: %w", err)
	}

	release, err := s.acquireRegistration(ctx)
	if err != nil {
		return LogoutResult{}, err
	}
	defer release()

	active, err := s.profiles.Active(ctx)
	if err != nil {
		return LogoutResult{}, err
	}
	record, err := s.identities.Get(ctx, active.ID)
	if errors.Is(err, identity.ErrNotFound) {
		return LogoutResult{ProfileID: active.ID, State: LogoutNotRegistered}, nil
	}
	if err != nil {
		return LogoutResult{}, fmt.Errorf("reading identity: %w", err)
	}
	if record.SignedOut() && keep {
		return LogoutResult{ProfileID: active.ID, State: LogoutSignedOut}, nil
	}
	// Keys neither registered nor signed out may still hold a Device after
	// a stopped sign-in or an expiry: Core is asked then, and its refusal
	// means none (S4b §4.3).
	unconfirmed := !record.IsRegistered() && !record.SignedOut()
	if unconfirmed && !s.mayHoldDevice(active.ID) {
		return LogoutResult{ProfileID: active.ID, State: LogoutNotRegistered}, nil
	}

	identityMaterial := record.Material()
	defer clearIdentityMaterial(identityMaterial)
	protocolMaterial := toProtocolMaterial(identityMaterial)
	defer clearProtocolMaterial(protocolMaterial)
	options := controlplane.RegisterOptions{
		Hostname:          s.hostname,
		Version:           "meshd/" + s.build.Version,
		PinnedFingerprint: record.ControlKeyFingerprint(),
	}
	call := s.prober.Logout
	if keep {
		call = s.prober.SignOut
	}
	logoutErr := call(ctx, active.ControlURL, protocolMaterial, options)
	switch {
	case keep && logoutErr == nil:
		// Signed out and kept: the keys stay, so signing in again brings the
		// same Device back; unregistered, so meshd stays off the network.
		if _, err := s.identities.SetSignedOut(context.WithoutCancel(ctx), active.ID); err != nil {
			return LogoutResult{}, fmt.Errorf("%w: the device is signed out but the profile was not updated: %w",
				ErrLogout, err)
		}
		return LogoutResult{ProfileID: active.ID, State: LogoutSignedOut}, nil
	case errors.Is(logoutErr, controlplane.ErrSignOutUnsupported):
		return LogoutResult{}, fmt.Errorf("%w: %w", ErrSignOutUnsupported, logoutErr)
	case errors.Is(logoutErr, controlplane.ErrSignOutNotPermitted):
		return LogoutResult{}, fmt.Errorf("%w: %w", ErrSignOutNotPermitted, logoutErr)
	case errors.Is(logoutErr, controlplane.ErrDeviceNotAuthorized) && unconfirmed:
		// Keys that were never confirmed hold no Device Core accepts.
		return LogoutResult{ProfileID: active.ID, State: LogoutNotRegistered}, nil
	case errors.Is(logoutErr, controlplane.ErrDeviceNotAuthorized):
		// A refusal is ambiguous (the Device may still hold its address), so
		// the keys stay and the user is told (TD-CLI-100).
		return LogoutResult{}, fmt.Errorf("%w: Core does not accept this device's keys, so they are kept; "+
			"sign in again with meshctl login, or ask an administrator to remove the device: %w", ErrLogout, logoutErr)
	}
	// Only a removal Core proved for exactly these keys lets the profile drop
	// them. Asked to keep it, Core may remove it instead (an ephemeral
	// Device): that is a removal now, not an earlier one.
	alreadyRemoved := errors.Is(logoutErr, controlplane.ErrDeviceRemoved) && !keep
	if keep && errors.Is(logoutErr, controlplane.ErrDeviceRemoved) {
		logoutErr = nil
	}
	if logoutErr != nil && !alreadyRemoved {
		return LogoutResult{}, fmt.Errorf("%w: %w", ErrLogout, logoutErr)
	}
	if err := s.replaceCredentials(context.WithoutCancel(ctx), active.ID); err != nil {
		// Core no longer knows the Device; logging out again finishes here.
		return LogoutResult{}, fmt.Errorf("%w: the Device is removed but its local keys were not reset: %w",
			ErrLogout, err)
	}

	return LogoutResult{ProfileID: active.ID, State: LogoutCompleted, AlreadyRemoved: alreadyRemoved}, nil
}

// activeRegistration reports the active profile and whether it holds a
// registered Device.
func (s *Service) activeRegistration(ctx context.Context) (string, bool, bool, error) {
	active, err := s.profiles.Active(ctx)
	if err != nil {
		return "", false, false, err
	}
	record, err := s.identities.Get(ctx, active.ID)
	if errors.Is(err, identity.ErrNotFound) {
		return active.ID, false, false, nil
	}
	if err != nil {
		return "", false, false, fmt.Errorf("reading identity: %w", err)
	}

	return active.ID, record.IsRegistered(), record.SignedOut(), nil
}

// replaceCredentials gives the profile new machine and node keys: Core keeps
// the old ones revoked for ever.
func (s *Service) replaceCredentials(ctx context.Context, profileID string) error {
	machine, err := controlplane.GenerateNodePrivateKey() // the same clamped X25519 form
	if err != nil {
		return fmt.Errorf("generating a machine key: %w", err)
	}
	defer clear(machine)
	node, err := controlplane.GenerateNodePrivateKey()
	if err != nil {
		return fmt.Errorf("generating a node key: %w", err)
	}
	defer clear(node)
	persistCtx, cancel := context.WithTimeout(ctx, credentialsTimeout)
	defer cancel()
	if _, err := s.identities.ReplaceCredentials(persistCtx, profileID, machine, node); err != nil {
		return fmt.Errorf("replacing the profile keys: %w", err)
	}
	s.displayDeviceRemoved(profileID)

	return nil
}

// revokedCredentialsWait bounds how long the session loop waits for a login or
// rotation holding the registration gate; Core answers REVOKED again on the
// next connect, so a skipped replacement is only delayed.
const revokedCredentialsWait = 5 * time.Second

// replaceRevokedCredentials gives the profile new keys after Core revoked its
// Device, but only while the profile still holds the keys the revoked session
// used: a login, rotation or logout that changed them since keeps its keys.
func (s *Service) replaceRevokedCredentials(ctx context.Context, profileID string, sessionKeys [32]byte) (bool, error) {
	gateCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revokedCredentialsWait)
	defer cancel()
	release, err := s.acquireRegistration(gateCtx)
	if err != nil {
		return false, fmt.Errorf("waiting for the registration gate: %w", err)
	}
	defer release()
	record, err := s.identities.Get(gateCtx, profileID)
	if err != nil {
		return false, fmt.Errorf("reading identity: %w", err)
	}
	material := record.Material()
	current := credentialDigest(material)
	clearIdentityMaterial(material)
	if subtle.ConstantTimeCompare(current[:], sessionKeys[:]) != 1 {
		return false, nil
	}
	if err := s.replaceCredentials(gateCtx, profileID); err != nil {
		return false, err
	}
	if s.logger != nil {
		s.logger.Info("the Device was revoked; the profile has new keys and must log in again",
			"profile_id", profileID)
	}

	return true, nil
}

// credentialDigest names a profile's machine and node keys without keeping
// them.
func credentialDigest(material identity.Material) [32]byte {
	digest := sha256.New()
	digest.Write([]byte("meshd-credentials-v1\x00"))
	digest.Write(material.MachinePrivateKey)
	digest.Write([]byte{0})
	digest.Write(material.NodePrivateKey)
	var sum [32]byte
	copy(sum[:], digest.Sum(nil))

	return sum
}

// heldDown reports whether the session loop must keep the runtime stopped.
func (s *Service) heldDown() bool {
	return s.loggingOut.Load() || s.profiles.Snapshot().Disconnected
}

// waitForControlSessionDown waits until the session loop has stopped the
// runtime and acknowledged the down state after acknowledged, so a down
// reported before the caller signalled does not count.
func (s *Service) waitForControlSessionDown(ctx context.Context, acknowledged uint64) error {
	waitCtx, cancel := context.WithTimeout(ctx, runtimeStopTimeout)
	defer cancel()
	ticker := time.NewTicker(runtimeStopPoll)
	defer ticker.Stop()
	for {
		if s.downAcks.Load() > acknowledged {
			return nil
		}
		select {
		case <-waitCtx.Done():
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("waiting for the control session to stop: %w", err)
			}
			return ErrControlSessionBusy
		case <-ticker.C:
		}
	}
}
