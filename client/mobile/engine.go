// Package mobile embeds the MeshTransit client runtime in an Android or iOS
// app (ADR-052). gomobile binds it: the app constructs an Engine with its
// platform implementations (TUN, key store, log), then drives registration,
// connection and status through the Engine's methods.
//
// The Engine runs the same daemon runtime as meshd: profiles, control-plane
// trust and registration, the map stream and the encrypted packet path. Only
// the host integration differs: the TUN comes from the platform VPN API, and
// there is no local API socket, no network helper and no service manager.
//
// Every exported method may be called from any platform thread. Methods that
// talk to Core are bounded by actionTimeout; Start returns at once and the
// runtime runs until Stop or Close.
package mobile

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"meshtransit.net/client/internal/daemon"
	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/identity"
	"meshtransit.net/client/internal/mtcpclient"
	"meshtransit.net/client/internal/profile"
	"meshtransit.net/client/internal/secretstore"
	"meshtransit.net/client/internal/underlay"
	"meshtransit.net/client/internal/version"
)

// APIVersion versions this package's API and its status JSON. The apps check
// it; a change that removes or renames anything increments it.
const APIVersion = 1

const (
	actionTimeout = 30 * time.Second
	stopTimeout   = 10 * time.Second
	stateDirMode  = 0o700
)

var (
	// errEngineRunning reports Start on an Engine that is already running.
	errEngineRunning = errors.New("mobile: engine already running")
	// errEngineClosed reports a call on a closed Engine.
	errEngineClosed = errors.New("mobile: engine closed")
	// errPlatform reports a missing or invalid platform implementation.
	errPlatform = errors.New("mobile: invalid platform implementation")
	// errStopTimeout reports a runtime that did not stop within stopTimeout.
	errStopTimeout = errors.New("mobile: engine did not stop in time")
	// errProtectRefused reports a socket the platform did not protect.
	errProtectRefused = errors.New("mobile: the platform refused to protect a socket")
	// errProtectorInUse reports a SocketProtector another Engine installed.
	errProtectorInUse = errors.New("mobile: another engine's socket protector is installed")
	// errNoProtector reports Start on Android without a SocketProtector.
	errNoProtector = errors.New("mobile: Android needs a socket protector before Start")
	// errPanic reports a panic recovered at the API boundary.
	errPanic = errors.New("mobile: internal error")
)

// requireProtector is set where the platform VPN captures the app's own
// sockets unless each is protected (Android); Start needs a SocketProtector
// there. Tests change it.
var requireProtector = runtime.GOOS == "android"

// ClientVersion returns the client build version.
func ClientVersion() string { return version.Current().Version }

// Engine is one embedded client runtime.
type Engine struct {
	service    *daemon.Service
	serve      func(context.Context) error // service.Run; tests replace it
	profiles   *profile.Store
	identities *identity.Store
	logger     *slog.Logger
	logs       *asyncLog // nil without a log sink
	hosts      *hostAddressList
	network    chan struct{}
	// routeSettings is the subnet route settings file in the state
	// directory (SetSubnetRoutes).
	routeSettings string
	// stopWait bounds how long Stop and Close wait for the runtime.
	stopWait time.Duration

	// lifecycle serializes Start, Stop and Close, including Stop's wait.
	lifecycle sync.Mutex
	// access is held shared by every call that uses the stores and
	// exclusively by Close while it closes them; it guards closed.
	access sync.RWMutex
	closed bool

	mu  sync.Mutex // guards run
	run *runtimeRun
}

// runtimeRun is one Start of the runtime: its goroutine clears it from the
// Engine and closes done when the runtime returns, for any reason.
type runtimeRun struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// NewEngine opens the Engine's stores in config.StateDir and builds the
// runtime around the platform's TUN, key store and log sink (logs may be
// nil). It starts nothing; call Start.
func NewEngine(config *Config, tun TunProvider, keys KeyStore, logs LogSink) (engine *Engine, err error) {
	var queue *asyncLog
	// Runs after recoverPanic, so a recovered panic also stops the queue.
	defer func() {
		if err != nil {
			engine = nil
			if queue != nil {
				queue.close()
			}
		}
	}()
	defer recoverPanic(&err)
	resolved, err := config.validated()
	if err != nil {
		return nil, err
	}
	if tun == nil || keys == nil {
		return nil, fmt.Errorf("%w: TUN provider and key store are required", errPlatform)
	}
	if err := os.MkdirAll(resolved.StateDir, stateDirMode); err != nil {
		return nil, fmt.Errorf("mobile: create state directory: %w", err)
	}
	if logs != nil {
		queue = newAsyncLog(logs)
	}
	return build(resolved, tun, keys, queue)
}

func build(resolved Config, tun TunProvider, keys KeyStore, queue *asyncLog) (*Engine, error) {
	logger := newLogger(queue)
	profiles, identities, err := openStores(resolved.StateDir, keys)
	if err != nil {
		return nil, err
	}
	hosts := &hostAddressList{}
	routeSettings := filepath.Join(resolved.StateDir, routeSettingsFile)
	packets, err := dataplane.NewWireGuardWithObserver(
		newPlatformTUN(tun, DefaultMTU, logger.With("component", "tun"), routeSettings, hosts),
		uint16(resolved.ListenPort), //nolint:gosec // validated to 1024-65535
		nil,
	)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("mobile: create data plane: %w", err), closeStores(profiles, identities))
	}
	packets.SetLogger(logger.With("component", "data_plane"))
	packets.SetHostAddressSource(hosts.load)
	network := make(chan struct{}, 1)
	service, err := daemon.New(profiles, identities, version.Current(), mtcpclient.New(), daemon.Options{
		Hostname:       hostnameFor(resolved.DeviceName),
		DataPlane:      packets,
		Logger:         logger.With("component", "daemon"),
		NetworkChanges: network,
		// Core sends the Sites the rules grant; the device installs them
		// only once the person accepts subnet routes (SetSubnetRoutes).
		EnableSubnetRoutes: true,
	})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("mobile: create runtime: %w", err), closeStores(profiles, identities))
	}
	return &Engine{
		service: service, serve: service.Run, profiles: profiles, identities: identities, logger: logger, logs: queue,
		network: network, stopWait: stopTimeout, hosts: hosts, routeSettings: routeSettings,
	}, nil
}

// openStores opens the profile store and the identity store sealed with the
// platform's envelope key, which is wiped from this memory once copied.
func openStores(stateDir string, keys KeyStore) (*profile.Store, *identity.Store, error) {
	key, err := keys.EnvelopeKey()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: envelope key: %w", errPlatform, err)
	}
	protector, err := secretstore.New(key)
	clear(key)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: envelope key must be %d bytes", errPlatform, secretstore.KeySize)
	}
	profiles, err := profile.Open(stateDir)
	if err != nil {
		return nil, nil, errors.Join(fmt.Errorf("mobile: open profiles: %w", err), protector.Close())
	}
	identities, err := identity.Open(stateDir, protector)
	if err != nil {
		return nil, nil, errors.Join(fmt.Errorf("mobile: open identities: %w", err), protector.Close(),
			profiles.Close())
	}
	ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
	defer cancel()
	if err := identities.MigrateAll(ctx); err != nil {
		return nil, nil, errors.Join(fmt.Errorf("mobile: migrate identities: %w", err),
			closeStores(profiles, identities))
	}
	return profiles, identities, nil
}

func closeStores(profiles *profile.Store, identities *identity.Store) error {
	return errors.Join(identities.Close(), profiles.Close())
}

// Start runs the runtime in the background until Stop or Close. It fails
// while a previous run has not stopped yet.
func (engine *Engine) Start() (err error) {
	defer recoverPanic(&err)
	if engine == nil {
		return errEngineClosed
	}
	engine.lifecycle.Lock()
	defer engine.lifecycle.Unlock()
	engine.access.RLock()
	closed := engine.closed
	engine.access.RUnlock()
	if closed {
		return errEngineClosed
	}
	if requireProtector && !protects(engine) {
		// Unprotected, the packet path would loop through the app's own VPN.
		return errNoProtector
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if engine.run != nil {
		return errEngineRunning
	}
	// A network change seen while stopped is stale: the run reads the
	// network afresh.
	select {
	case <-engine.network:
	default:
	}
	ctx, cancel := context.WithCancel(context.Background())
	run := &runtimeRun{cancel: cancel, done: make(chan struct{})}
	engine.run = run
	go engine.runtime(ctx, run)
	return nil
}

// runtime runs the daemon until ctx ends or it fails, then clears run.
func (engine *Engine) runtime(ctx context.Context, run *runtimeRun) {
	defer close(run.done)
	defer func() {
		engine.mu.Lock()
		if engine.run == run {
			engine.run = nil
		}
		engine.mu.Unlock()
		run.cancel()
	}()
	defer func() {
		if recovered := recover(); recovered != nil {
			engine.logger.Error("runtime panicked", "type", fmt.Sprintf("%T", recovered))
		}
	}()
	if err := engine.serve(ctx); err != nil && !errors.Is(err, context.Canceled) {
		engine.logger.Error("runtime stopped", "error", err)
	}
}

// Stop stops the runtime and waits for it to release the TUN and its
// sockets. Stop on a stopped Engine does nothing. If the runtime does not
// stop within stopTimeout, Stop fails and the Engine stays running; Stop again waits
// again.
func (engine *Engine) Stop() (err error) {
	defer recoverPanic(&err)
	if engine == nil {
		return nil
	}
	engine.lifecycle.Lock()
	defer engine.lifecycle.Unlock()
	return engine.stopLocked()
}

// stopLocked cancels the current run and waits for it. lifecycle is held.
func (engine *Engine) stopLocked() error {
	engine.mu.Lock()
	run := engine.run
	engine.mu.Unlock()
	if run == nil {
		return nil
	}
	run.cancel()
	timer := time.NewTimer(engine.stopWait)
	defer timer.Stop()
	select {
	case <-run.done:
		return nil
	case <-timer.C:
		return errStopTimeout
	}
}

// Close stops the runtime, waits for calls in progress and closes the
// stores. The Engine cannot be used afterwards. If the runtime does not stop
// in time, Close fails and leaves the Engine open, so it can be retried.
func (engine *Engine) Close() (err error) {
	defer recoverPanic(&err)
	if engine == nil {
		return nil
	}
	engine.lifecycle.Lock()
	defer engine.lifecycle.Unlock()
	engine.access.Lock()
	defer engine.access.Unlock()
	if engine.closed {
		return nil
	}
	if err := engine.stopLocked(); err != nil {
		return err
	}
	engine.closed = true
	releaseProtector(engine)
	err = closeStores(engine.profiles, engine.identities)
	if engine.logs != nil {
		engine.logs.close()
	}
	return err
}

// SetSocketProtector installs protector for every socket the runtime
// opens; nil removes it. Call it before Start: a socket opened before would
// stay unprotected. The protector is process-wide, as the platform VPN is,
// and Close removes it.
func (engine *Engine) SetSocketProtector(protector SocketProtector) (err error) {
	defer recoverPanic(&err)
	if engine == nil {
		return errEngineClosed
	}
	engine.lifecycle.Lock()
	defer engine.lifecycle.Unlock()
	engine.access.RLock()
	defer engine.access.RUnlock()
	if engine.closed {
		return errEngineClosed
	}
	if engine.Running() {
		return errEngineRunning
	}
	if protector == nil {
		releaseProtector(engine)
		return nil
	}
	return installProtector(engine, func(fd uintptr) error {
		if !protector.Protect(int(fd)) {
			return errProtectRefused
		}
		return nil
	})
}

// protectorOwner is the Engine whose SocketProtector is installed: the
// protector is process-wide, and one Engine must not replace or remove
// another's.
var protectorOwner struct {
	sync.Mutex
	engine *Engine
}

func installProtector(engine *Engine, protect underlay.Protector) error {
	protectorOwner.Lock()
	defer protectorOwner.Unlock()
	if protectorOwner.engine != nil && protectorOwner.engine != engine {
		return errProtectorInUse
	}
	underlay.SetProtector(protect)
	protectorOwner.engine = engine
	return nil
}

func releaseProtector(engine *Engine) {
	protectorOwner.Lock()
	defer protectorOwner.Unlock()
	if protectorOwner.engine == engine {
		underlay.SetProtector(nil)
		protectorOwner.engine = nil
	}
}

func protects(engine *Engine) bool {
	protectorOwner.Lock()
	defer protectorOwner.Unlock()
	return protectorOwner.engine == engine
}

// Running reports whether the runtime runs.
func (engine *Engine) Running() bool {
	if engine == nil {
		return false
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	return engine.run != nil
}

// NetworkChanged tells the runtime the device's network changed (Wi-Fi to
// cellular, a new address): it refreshes endpoints and paths. It never
// blocks; changes arriving together count once.
func (engine *Engine) NetworkChanged() {
	if engine == nil {
		return
	}
	select {
	case engine.network <- struct{}{}:
	default:
	}
}

// SetHostAddresses tells the runtime the device's addresses on its
// networks, other than the app's own VPN: a comma-separated list of IP
// addresses, each optionally with its prefix length. Mobile platforms do not
// let apps list network interfaces, so the app reports them whenever a
// network changes, then calls NetworkChanged. It never blocks.
func (engine *Engine) SetHostAddresses(addresses string) (err error) {
	defer recoverPanic(&err)
	if engine == nil {
		return errEngineClosed
	}
	parsed, networks, err := parseHostAddresses(addresses)
	if err != nil {
		return err
	}
	engine.hosts.current.Store(&parsed)
	engine.hosts.networks.Store(&networks)
	return nil
}

// StatusJSON returns the current status as the versioned JSON of status.
func (engine *Engine) StatusJSON() (value string, err error) {
	defer recoverPanic(&err)
	err = engine.act(func(ctx context.Context) error {
		current, statusErr := engine.service.Status(ctx)
		if statusErr != nil {
			return statusErr
		}
		reported := newStatus(engine.Running(), current)
		// An unreadable settings file admits nothing: shown as off.
		settings, _ := loadRouteSettings(engine.routeSettings)
		reported.SubnetRoutes.Accepted = settings.AcceptRoutes
		value, statusErr = reported.marshal()
		return statusErr
	})
	return value, err
}

// CreateProfile stores a profile for one Core at controlURL and returns its
// ID; the first profile becomes active.
func (engine *Engine) CreateProfile(name, controlURL string) (id string, err error) {
	defer recoverPanic(&err)
	err = engine.act(func(ctx context.Context) error {
		created, createErr := engine.service.CreateProfile(ctx, profile.CreateInput{Name: name, ControlURL: controlURL})
		id = created.ID
		return createErr
	})
	return id, err
}

// ActivateProfile selects the profile the runtime connects with.
func (engine *Engine) ActivateProfile(id string) (err error) {
	defer recoverPanic(&err)
	return engine.act(func(ctx context.Context) error {
		_, activateErr := engine.service.ActivateProfile(ctx, strings.TrimSpace(id))
		return activateErr
	})
}

// ProbeControl reaches the active profile's Core and returns the
// fingerprint of the key it proves, for the person to compare with the one
// their administrator gave them before TrustControl. It is the ck= form
// install commands and enrollment links carry, when the protocol has one;
// TrustControl takes either form.
func (engine *Engine) ProbeControl() (fingerprint string, err error) {
	defer recoverPanic(&err)
	err = engine.act(func(ctx context.Context) error {
		probe, probeErr := engine.service.ProbeControl(ctx)
		fingerprint = probe.LinkFingerprint
		if fingerprint == "" {
			fingerprint = probe.KeyFingerprint
		}
		return probeErr
	})
	return fingerprint, err
}

// TrustControl pins the active profile's Core after it proves the key whose
// fingerprint the person confirmed, and creates the Device's keys.
func (engine *Engine) TrustControl(fingerprint string) (err error) {
	defer recoverPanic(&err)
	return engine.act(func(ctx context.Context) error {
		_, trustErr := engine.service.TrustControl(ctx, strings.TrimSpace(fingerprint))
		return trustErr
	})
}

// Login registers the Device. With an enrollment key it registers directly
// and returns ""; without one it returns the URL the person opens in a
// browser to approve the Device, after which the app calls CompleteLogin.
func (engine *Engine) Login(enrollmentKey string) (authURL string, err error) {
	defer recoverPanic(&err)
	err = engine.act(func(ctx context.Context) error {
		login, loginErr := engine.service.StartLogin(ctx, strings.TrimSpace(enrollmentKey))
		authURL = login.AuthURL
		return loginErr
	})
	return authURL, err
}

// CompleteLogin checks whether the person approved the Device in the
// browser registration Login started. It waits a few seconds for Core and
// returns false while the approval is still pending; the app calls it again.
func (engine *Engine) CompleteLogin() (registered bool, err error) {
	defer recoverPanic(&err)
	err = engine.act(func(ctx context.Context) error {
		_, loginErr := engine.service.CompleteLogin(ctx)
		if errors.Is(loginErr, daemon.ErrAuthorizationPending) {
			return nil
		}
		registered = loginErr == nil
		return loginErr
	})
	return registered, err
}

// Up connects the active profile and keeps it connected across restarts.
func (engine *Engine) Up() (err error) {
	defer recoverPanic(&err)
	return engine.act(func(ctx context.Context) error {
		_, upErr := engine.service.Up(ctx)
		return upErr
	})
}

// Down disconnects the active profile and keeps it off until Up.
func (engine *Engine) Down() (err error) {
	defer recoverPanic(&err)
	return engine.act(func(ctx context.Context) error {
		_, downErr := engine.service.Down(ctx)
		return downErr
	})
}

// Logout removes the Device from Core and replaces its local keys.
func (engine *Engine) Logout() (err error) {
	defer recoverPanic(&err)
	return engine.act(func(ctx context.Context) error {
		_, logoutErr := engine.service.Logout(ctx)
		return logoutErr
	})
}

// act runs one bounded daemon action while holding access shared, so Close
// waits for it before closing the stores.
func (engine *Engine) act(action func(context.Context) error) error {
	if engine == nil {
		return errEngineClosed
	}
	engine.access.RLock()
	defer engine.access.RUnlock()
	if engine.closed {
		return errEngineClosed
	}
	ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
	defer cancel()
	return action(ctx)
}

// recoverPanic turns a panic below the API boundary into an error, so a bug
// fails one call instead of the app. The panic value is not passed on: it
// may hold data the app must not see.
func recoverPanic(err *error) {
	if recovered := recover(); recovered != nil {
		*err = errPanic
	}
}
