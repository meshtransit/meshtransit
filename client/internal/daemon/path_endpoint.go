package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/pathdiscovery"
)

const maxQueuedPathObservations = 128

var errPathEndpointControllerInactive = errors.New(
	"daemon: path endpoint controller is inactive",
)

type preferredEndpointDataPlane interface {
	SetPreferredEndpoint(uint64, uint64, netip.AddrPort) error
	RestorePreferredEndpoint(uint64, uint64) error
}

type pathSelectionEngine interface {
	Activate(
		networkmap.Snapshot,
		pathdiscovery.ProbeGeneration,
	) (pathdiscovery.PathSelectionResult, error)
	Deactivate() pathdiscovery.PathSelectionResult
	Observe(
		pathdiscovery.PathObservation,
	) (pathdiscovery.PathSelectionResult, error)
	Expire(time.Time) (pathdiscovery.PathSelectionResult, error)
}

type pathEndpointCommandKind uint8

const (
	pathEndpointPause pathEndpointCommandKind = iota + 1
	pathEndpointActivate
	pathEndpointDeactivate
)

type pathEndpointCommand struct {
	kind       pathEndpointCommandKind
	snapshot   networkmap.Snapshot
	generation pathdiscovery.ProbeGeneration
	result     chan error
}

// pathEndpointController serializes authenticated observations, exact expiry,
// and endpoint updates independently from the control-stream callback.
type pathEndpointController struct {
	selector    pathSelectionEngine
	dataPlane   preferredEndpointDataPlane
	dataPlaneMu *sync.Mutex
	telemetry   *pathdiscovery.ProbeTelemetry
	clock       func() time.Time
	stopSession context.CancelFunc

	observations chan pathdiscovery.PathObservation
	commands     chan pathEndpointCommand
	done         chan struct{}
	cancel       context.CancelFunc
	workers      sync.WaitGroup
	closeOnce    sync.Once
	errorOnce    sync.Once
	errorMu      sync.Mutex
	err          error
}

func newPathEndpointController(
	ctx context.Context,
	selector pathSelectionEngine,
	dataPlane preferredEndpointDataPlane,
	dataPlaneMu *sync.Mutex,
	telemetry *pathdiscovery.ProbeTelemetry,
	clock func() time.Time,
	stopSession context.CancelFunc,
) (*pathEndpointController, error) {
	if ctx == nil || selector == nil || dataPlane == nil || dataPlaneMu == nil ||
		telemetry == nil || clock == nil || stopSession == nil {
		return nil, errors.New("daemon: path endpoint dependencies are invalid")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	workerCtx, cancel := context.WithCancel(ctx)
	controller := &pathEndpointController{
		selector:     selector,
		dataPlane:    dataPlane,
		dataPlaneMu:  dataPlaneMu,
		telemetry:    telemetry,
		clock:        clock,
		stopSession:  stopSession,
		observations: make(chan pathdiscovery.PathObservation, maxQueuedPathObservations),
		commands:     make(chan pathEndpointCommand),
		done:         make(chan struct{}),
		cancel:       cancel,
	}
	controller.workers.Go(func() { controller.run(workerCtx) })

	return controller, nil
}

// ObservePath queues one authenticated proof without blocking the probe
// runtime. Saturation drops proof, never tunnel traffic or endpoint authority.
func (c *pathEndpointController) ObservePath(
	observation pathdiscovery.PathObservation,
) {
	if c == nil {
		return
	}
	select {
	case <-c.done:
		return
	default:
	}
	select {
	case c.observations <- observation:
		c.telemetry.RecordObservationQueued()
	default:
		c.telemetry.RecordObservationDropped()
	}
}

func (c *pathEndpointController) Pause(ctx context.Context) error {
	return c.command(ctx, pathEndpointCommand{kind: pathEndpointPause})
}

func (c *pathEndpointController) Activate(
	ctx context.Context,
	snapshot networkmap.Snapshot,
	generation pathdiscovery.ProbeGeneration,
) error {
	return c.command(ctx, pathEndpointCommand{
		kind:       pathEndpointActivate,
		snapshot:   snapshot,
		generation: generation,
	})
}

func (c *pathEndpointController) Deactivate(ctx context.Context) error {
	return c.command(ctx, pathEndpointCommand{kind: pathEndpointDeactivate})
}

func (c *pathEndpointController) command(
	ctx context.Context,
	command pathEndpointCommand,
) error {
	if c == nil {
		return errPathEndpointControllerInactive
	}
	if ctx == nil {
		return errors.New("daemon: path endpoint command context is required")
	}
	command.result = make(chan error, 1)
	select {
	case c.commands <- command:
	case <-c.done:
		return c.terminalError()
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-command.result:
		return err
	case <-c.done:
		return c.terminalError()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *pathEndpointController) Close() {
	if c == nil {
		return
	}
	c.closeOnce.Do(func() {
		c.cancel()
		c.workers.Wait()
	})
}

func (c *pathEndpointController) Err() error {
	if c == nil {
		return nil
	}
	c.errorMu.Lock()
	defer c.errorMu.Unlock()

	return c.err
}

func (c *pathEndpointController) terminalError() error {
	if err := c.Err(); err != nil {
		return err
	}

	return errPathEndpointControllerInactive
}

func (c *pathEndpointController) run(ctx context.Context) {
	defer close(c.done)
	defer c.selector.Deactivate()
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	var timerChannel <-chan time.Time
	paused := true
	generation := pathdiscovery.ProbeGeneration{}

	for {
		select {
		case command := <-c.commands:
			var err error
			paused, generation, timerChannel, err = c.handleCommand(
				command,
				paused,
				generation,
				timer,
			)
			command.result <- err
			if err != nil {
				c.fail(err)

				return
			}

			continue
		default:
		}

		select {
		case <-ctx.Done():
			return
		case command := <-c.commands:
			var err error
			paused, generation, timerChannel, err = c.handleCommand(
				command,
				paused,
				generation,
				timer,
			)
			command.result <- err
			if err != nil {
				c.fail(err)

				return
			}
		case observation := <-c.observations:
			if paused {
				continue
			}
			result, err := c.selector.Observe(observation)
			if err != nil {
				c.telemetry.RecordObservationRejected()
			} else {
				c.telemetry.RecordObservationAccepted()
				err = c.applyChanges(generation, result.Changes)
			}
			if err != nil {
				c.fail(fmt.Errorf("processing authenticated path: %w", err))

				return
			}
			timerChannel = resetPathEndpointTimer(
				timer,
				result.ExpiresAt,
				c.clock(),
			)
		case <-timerChannel:
			result, err := c.selector.Expire(c.clock())
			if err == nil {
				c.telemetry.RecordDirectExpiry(countRetiredPaths(result.Changes))
				err = c.applyChanges(generation, result.Changes)
			}
			if err != nil {
				c.fail(fmt.Errorf("expiring authenticated path: %w", err))

				return
			}
			timerChannel = resetPathEndpointTimer(
				timer,
				result.ExpiresAt,
				c.clock(),
			)
		}
	}
}

func (c *pathEndpointController) handleCommand(
	command pathEndpointCommand,
	paused bool,
	generation pathdiscovery.ProbeGeneration,
	timer *time.Timer,
) (bool, pathdiscovery.ProbeGeneration, <-chan time.Time, error) {
	switch command.kind {
	case pathEndpointPause:
		stopPathEndpointTimer(timer)
		drainPathObservations(c.observations)

		return true, generation, nil, nil
	case pathEndpointActivate:
		result, err := c.selector.Activate(command.snapshot, command.generation)
		if err == nil {
			activation := result.Activation
			c.telemetry.RecordActivationPreserved(activation.SelectionsPreserved)
			c.telemetry.RecordActivationRetired(activation.SelectionsRetired)
			c.telemetry.RecordAuthorityPeerSetChange(activation.PeerSetChanges)
			c.telemetry.RecordAuthorityNodeKeyChange(activation.NodeKeyChanges)
			c.telemetry.RecordAuthorityDiscoveryKeyChange(activation.DiscoveryKeyChanges)
			c.telemetry.RecordAuthorityEndpointChange(activation.EndpointSetChanges)
			if activation.SocketChanged {
				c.telemetry.RecordSocketChange()
			}
			err = c.applyActivationChanges(
				command.generation,
				changesForMapPeers(command.snapshot, result.Changes),
			)
		}
		if err != nil {
			return paused, generation, nil, fmt.Errorf(
				"activating path selector: %w",
				err,
			)
		}

		return false, command.generation, resetPathEndpointTimer(
			timer,
			result.ExpiresAt,
			c.clock(),
		), nil
	case pathEndpointDeactivate:
		c.selector.Deactivate()
		stopPathEndpointTimer(timer)
		drainPathObservations(c.observations)

		return true, pathdiscovery.ProbeGeneration{}, nil, nil
	default:
		return paused, generation, nil, errors.New(
			"daemon: path endpoint command is invalid",
		)
	}
}

// changesForMapPeers drops retired selections of peers the activated map no
// longer contains. Applying that map already removed their WireGuard state, so
// there is no endpoint left to restore; restoring one would fail and stop the
// session of a Device that still has other peers.
func changesForMapPeers(
	snapshot networkmap.Snapshot,
	changes []pathdiscovery.PathChange,
) []pathdiscovery.PathChange {
	present := make(map[uint64]struct{}, len(snapshot.Peers))
	for _, peer := range snapshot.Peers {
		present[peer.ID] = struct{}{}
	}
	kept := make([]pathdiscovery.PathChange, 0, len(changes))
	for _, change := range changes {
		if _, found := present[change.PeerID]; !found && !change.Current.IsValid() {
			continue
		}
		kept = append(kept, change)
	}

	return kept
}

func countRetiredPaths(changes []pathdiscovery.PathChange) uint64 {
	var retired uint64
	for _, change := range changes {
		if change.Previous.IsValid() && !change.Current.IsValid() {
			retired++
		}
	}

	return retired
}

func (c *pathEndpointController) applyChanges(
	generation pathdiscovery.ProbeGeneration,
	changes []pathdiscovery.PathChange,
) error {
	return c.applyChangesWithRetiredGeneration(generation, changes, false)
}

func (c *pathEndpointController) applyActivationChanges(
	generation pathdiscovery.ProbeGeneration,
	changes []pathdiscovery.PathChange,
) error {
	return c.applyChangesWithRetiredGeneration(generation, changes, true)
}

func (c *pathEndpointController) applyChangesWithRetiredGeneration(
	generation pathdiscovery.ProbeGeneration,
	changes []pathdiscovery.PathChange,
	allowRetired bool,
) error {
	if len(changes) == 0 {
		return nil
	}
	if !generation.IsValid() {
		return errors.New("daemon: path endpoint generation is invalid")
	}
	c.dataPlaneMu.Lock()
	defer c.dataPlaneMu.Unlock()
	for _, change := range changes {
		if change.PeerID == 0 {
			return errors.New("daemon: path endpoint change has no peer")
		}
		if change.Current.IsValid() {
			if change.Current.Generation != generation {
				return errors.New("daemon: selected path generation changed")
			}
			if err := c.dataPlane.SetPreferredEndpoint(
				generation.MapRevision,
				change.PeerID,
				change.Current.RemoteEndpoint,
			); err != nil {
				return err
			}

			continue
		}
		if change.Previous.Generation != generation &&
			(!allowRetired || !validRetiredPathGeneration(
				change.Previous.Generation,
				generation,
			)) {
			return errors.New("daemon: expired path generation changed")
		}
		err := c.dataPlane.RestorePreferredEndpoint(
			generation.MapRevision,
			change.PeerID,
		)
		// A peer without a map endpoint (offline, or not yet reported after
		// Core came back) has nothing to return to: the map applied before
		// this activation already set its WireGuard state.
		if err != nil && (!allowRetired || !errors.Is(err, dataplane.ErrPeerEndpointUnavailable)) {
			return err
		}
	}

	return nil
}

func validRetiredPathGeneration(
	retired pathdiscovery.ProbeGeneration,
	active pathdiscovery.ProbeGeneration,
) bool {
	if !retired.IsValid() || !active.IsValid() || retired == active ||
		retired.Scope != active.Scope ||
		retired.MapRevision > active.MapRevision ||
		retired.Socket.Generation > active.Socket.Generation {
		return false
	}
	if retired.Socket.Generation == active.Socket.Generation &&
		retired.Socket.Port != active.Socket.Port {
		return false
	}

	return true
}

func (c *pathEndpointController) fail(err error) {
	if err == nil {
		return
	}
	c.errorOnce.Do(func() {
		c.errorMu.Lock()
		c.err = err
		c.errorMu.Unlock()
		c.stopSession()
	})
}

func resetPathEndpointTimer(
	timer *time.Timer,
	deadline time.Time,
	now time.Time,
) <-chan time.Time {
	stopPathEndpointTimer(timer)
	if deadline.IsZero() {
		return nil
	}
	delay := deadline.Sub(now)
	if delay < 0 {
		delay = 0
	}
	timer.Reset(delay)

	return timer.C
}

func stopPathEndpointTimer(timer *time.Timer) {
	if timer == nil || timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}

func drainPathObservations(
	observations <-chan pathdiscovery.PathObservation,
) {
	for {
		select {
		case <-observations:
		default:
			return
		}
	}
}
