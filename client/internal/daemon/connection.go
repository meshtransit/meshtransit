package daemon

import (
	"context"
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

	// runtimeStopTimeout bounds how long Down and Logout wait for the session
	// loop to stop the runtime.
	runtimeStopTimeout = 10 * time.Second
	runtimeStopPoll    = 50 * time.Millisecond
	credentialsTimeout = 5 * time.Second
)

var (
	// ErrLogout indicates that Core could not log the Device out.
	ErrLogout = errors.New("daemon: logout failed")
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
	// AlreadyRemoved means Core no longer knew the Device (revoked or removed
	// elsewhere); only the local keys were replaced.
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
	if changed {
		s.signalControlSync()
	}

	return ConnectionChange{State: ConnectionUp, Changed: changed}, nil
}

// Logout ends the active profile's Device in Core (mtcp-v1 §6.5) and gives
// the profile new unregistered keys, so `meshctl up` enrolls a new Device.
// The map stream stops first: its session uses the same machine key and
// would replace the logout session. It stops before Logout takes the
// registration gate, which the session loop may need to finish a pending
// node-key rotation on its way to the down state.
func (s *Service) Logout(ctx context.Context) (LogoutResult, error) {
	// Nothing to stop or tell Core when the profile holds no Device; the
	// check repeats under the gate.
	if profileID, registered, err := s.activeRegistration(ctx); err != nil {
		return LogoutResult{}, err
	} else if !registered {
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
	if !record.IsRegistered() {
		return LogoutResult{ProfileID: active.ID, State: LogoutNotRegistered}, nil
	}

	identityMaterial := record.Material()
	defer clearIdentityMaterial(identityMaterial)
	protocolMaterial := toProtocolMaterial(identityMaterial)
	defer clearProtocolMaterial(protocolMaterial)
	logoutErr := s.prober.Logout(ctx, active.ControlURL, protocolMaterial, controlplane.RegisterOptions{
		Hostname:          s.hostname,
		Version:           "meshd/" + s.build.Version,
		PinnedFingerprint: record.ControlKeyFingerprint(),
	})
	alreadyRemoved := errors.Is(logoutErr, controlplane.ErrDeviceNotAuthorized)
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
func (s *Service) activeRegistration(ctx context.Context) (string, bool, error) {
	active, err := s.profiles.Active(ctx)
	if err != nil {
		return "", false, err
	}
	record, err := s.identities.Get(ctx, active.ID)
	if errors.Is(err, identity.ErrNotFound) {
		return active.ID, false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("reading identity: %w", err)
	}

	return active.ID, record.IsRegistered(), nil
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
		return fmt.Errorf("replacing the profile keys after logout: %w", err)
	}

	return nil
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
