package meshgw

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"

	"meshtransit.net/client/internal/daemon"
	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/identity"
	"meshtransit.net/client/internal/k8sstate"
	"meshtransit.net/client/internal/mtcpclient"
	"meshtransit.net/client/internal/profile"
	"meshtransit.net/client/internal/secretstore"
	"meshtransit.net/client/internal/version"
)

const (
	// MTU is the gateway's TUN MTU: the smallest every mesh path carries.
	MTU = 1280

	probeInterval      = 2 * time.Second
	enrollTimeout      = 30 * time.Second
	migrateTimeout     = 30 * time.Second
	enrollRetryFirst   = 5 * time.Second
	enrollRetryLongest = time.Minute
	shutdownTimeout    = 10 * time.Second
)

// Run runs one gateway replica until ctx ends or it must stop: its state is
// rebuilt from its Secret, mirrored back on every write, and the Device is
// enrolled without a person (k8s-gateway-plan §4.4). It then takes kubectl
// on the Device's mesh addresses (§0).
func Run(ctx context.Context, cfg Config, logger *slog.Logger) (err error) {
	ctx, fail := context.WithCancelCause(ctx)
	defer fail(nil)

	mirror, err := restoreState(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer mirror.Close()
	profiles, identities, err := openStores(ctx, cfg, mirror, fail)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, identities.Close(), profiles.Close()) }()

	stacks := NewStacks(MTU, logger.With("component", "stacks"))
	defer func() { err = errors.Join(err, stacks.Close()) }()
	service, err := newRuntime(cfg, stacks, profiles, identities, logger)
	if err != nil {
		return err
	}
	forwarder := &KubeAPIForwarder{
		Stacks:         stacks,
		Port:           uint16(cfg.KubeAPIPort), //nolint:gosec // validated 1-65535
		Backend:        cfg.KubeAPIBackend,
		MaxConnections: DefaultMaxKubeAPIConnections,
		PeerAt:         service.PeerAt,
		Logger:         logger.With("component", "kube_api"),
	}
	stopProbes, err := startProbes(ctx, cfg, service, stacks, forwarder, logger)
	if err != nil {
		return err
	}
	// The probes stop first, reporting not ready while the rest shuts down.
	defer func() { err = errors.Join(err, stopProbes()) }()

	if cfg.JoinKeyFile != "" {
		// A K1 gateway: join once, then settle and rotate the keys at every
		// start, before the map stream (mtcp-v1 §6.6–6.8).
		if err := joinUntilDone(ctx, service, cfg, enrollRetryFirst, logger); err != nil {
			return err
		}
		if err := prepareKeysUntilDone(ctx, service, enrollRetryFirst, logger); err != nil {
			return err
		}
		logger.Info("gateway joined its cluster", "hostname", cfg.Hostname)
		return serve(ctx, service, forwarder)
	}
	if err := enrollUntilDone(ctx, service, cfg, enrollRetryFirst, logger); err != nil {
		return err
	}
	logger.Info("gateway enrolled", "hostname", cfg.Hostname)
	return serve(ctx, service, forwarder)
}

// restoreState opens the replica's state Secret and rebuilds the state
// directory from it.
func restoreState(ctx context.Context, cfg Config, logger *slog.Logger) (*k8sstate.Mirror, error) {
	kube, err := k8sstate.InClusterConfig(cfg.StateSecret)
	if err != nil {
		return nil, fmt.Errorf("meshgw: %w", err)
	}
	mirror, err := k8sstate.Open(ctx, kube)
	if err != nil {
		return nil, fmt.Errorf("meshgw: %w", err)
	}
	report, err := k8sstate.Restore(cfg.StateDir, mirror.Data())
	if err != nil {
		mirror.Close()
		return nil, fmt.Errorf("meshgw: %w", err)
	}
	if len(report.RemovedIdentities) > 0 {
		logger.Warn("identity records the state Secret lacks were removed", "records", report.RemovedIdentities)
	}
	if len(report.SkippedKeys) > 0 {
		logger.Warn("state Secret keys from a newer version were skipped", "keys", report.SkippedKeys)
	}
	return mirror, nil
}

// newRuntime builds the data plane over the stacks and the daemon over it.
func newRuntime(cfg Config, stacks *Stacks, profiles *profile.Store, identities *identity.Store,
	logger *slog.Logger,
) (*daemon.Service, error) {
	packets, err := dataplane.NewWireGuardWithObserver(stacks, uint16(cfg.ListenPort), nil) //nolint:gosec // validated 1024-65535
	if err != nil {
		return nil, fmt.Errorf("meshgw: creating the data plane: %w", err)
	}
	packets.SetLogger(logger.With("component", "data_plane"))
	// A pod address may repeat in another cluster with the same CIDR, so
	// the gateway offers peers no host address, only STUN and relays.
	packets.SetHostAddressSource(noHostAddresses)
	control := mtcpclient.New()
	if cfg.JoinKeyFile != "" {
		control = mtcpclient.NewGateway()
	}
	service, err := daemon.New(profiles, identities, version.Current(), control, daemon.Options{
		Hostname:  cfg.Hostname,
		DataPlane: packets,
		Logger:    logger.With("component", "daemon"),
		Gateway:   cfg.JoinKeyFile != "",
	})
	if err != nil {
		return nil, fmt.Errorf("meshgw: creating the runtime: %w", err)
	}
	return service, nil
}

// startProbes serves the probes and polls the status for them; the returned
// function stops both and waits for the poller.
func startProbes(ctx context.Context, cfg Config, service *daemon.Service, stacks *Stacks,
	forwarder *KubeAPIForwarder, logger *slog.Logger,
) (func() error, error) {
	probes := NewProbes(service.Status, probeInterval,
		Counter{
			Name: "meshgw_dropped_packets_total", Help: "Packets dropped between the stack and the data plane.",
			Value: stacks.Dropped,
		},
		Counter{
			Name: "meshgw_kube_api_connections_total", Help: "kubectl connections carried.",
			Value: forwarder.Total,
		},
	)
	// K0 serves kubectl: a replica not listening for it is not ready.
	probes.Require("kube API not listening", forwarder.Listening)
	server, err := serveProbes(ctx, cfg.ProbeAddress, probes.Handler(), logger)
	if err != nil {
		return nil, err
	}
	pollCtx, stopPoll := context.WithCancel(ctx)
	polled := make(chan struct{})
	go func() {
		defer close(polled)
		probes.Poll(pollCtx)
	}()
	return func() error {
		stopPoll()
		<-polled
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancel()
		return server.Shutdown(shutdown)
	}, nil
}

// runner is the daemon's run loop as serve sees it.
type runner interface {
	Run(context.Context) error
}

// serve runs the daemon and the kubectl forwarder until ctx ends or the
// gateway must stop, and returns why it stopped. The forwarder stops with
// the daemon, whichever way the daemon stops.
func serve(ctx context.Context, service runner, forwarder *KubeAPIForwarder) error {
	forwarderCtx, stopForwarder := context.WithCancel(ctx)
	defer stopForwarder()
	forwarded := make(chan struct{})
	go func() {
		defer close(forwarded)
		_ = forwarder.Run(forwarderCtx)
	}()
	err := service.Run(ctx)
	stopForwarder()
	<-forwarded
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	if cause := context.Cause(ctx); !errors.Is(cause, context.Canceled) {
		return cause
	}
	return nil
}

// openStores opens the stores over the restored directory, each mirroring
// its writes into the Secret. A conflict on the Secret means a second
// replica uses this identity: the gateway stops rather than share a Device.
func openStores(ctx context.Context, cfg Config, mirror *k8sstate.Mirror, fail context.CancelCauseFunc,
) (*profile.Store, *identity.Store, error) {
	key, err := ReadEnvelopeKey(cfg.EnvelopeKeyFile)
	if err != nil {
		return nil, nil, err
	}
	protector, err := secretstore.New(key)
	clear(key)
	if err != nil {
		return nil, nil, fmt.Errorf("meshgw: the envelope key: %w", err)
	}
	profiles, err := profile.Open(cfg.StateDir,
		profile.WithPersistHook(stopOnConflict(mirror.Hook(k8sstate.ProfileKeyPrefix), fail)))
	if err != nil {
		return nil, nil, errors.Join(fmt.Errorf("meshgw: opening profiles: %w", err), protector.Close())
	}
	identities, err := identity.Open(cfg.StateDir, protector,
		identity.WithPersistHook(stopOnConflict(mirror.Hook(k8sstate.IdentityKeyPrefix), fail)))
	if err != nil {
		return nil, nil, errors.Join(fmt.Errorf("meshgw: opening identities: %w", err), protector.Close(),
			profiles.Close())
	}
	migrate, cancel := context.WithTimeout(ctx, migrateTimeout)
	defer cancel()
	if err := identities.MigrateAll(migrate); err != nil {
		return nil, nil, errors.Join(fmt.Errorf("meshgw: migrating identities: %w", err), identities.Close(),
			profiles.Close())
	}
	return profiles, identities, nil
}

// stopOnConflict passes writes to hook and stops the gateway, through fail,
// once the Secret shows another writer.
func stopOnConflict(hook func(context.Context, string, []byte) error, fail context.CancelCauseFunc,
) func(context.Context, string, []byte) error {
	return func(ctx context.Context, name string, data []byte) error {
		err := hook(ctx, name, data)
		if errors.Is(err, k8sstate.ErrConflict) {
			fail(err)
		}
		return err
	}
}

// enrollUntilDone enrolls, retrying failures that may pass, such as Core
// being unreachable. A permanent failure stops the gateway at once: the pod
// then restarts, visibly, instead of waiting unready.
func enrollUntilDone(ctx context.Context, service controller, cfg Config, wait time.Duration,
	logger *slog.Logger,
) error {
	for {
		attempt, cancel := context.WithTimeout(ctx, enrollTimeout)
		err := Enroll(attempt, service, cfg)
		cancel()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		if permanent(err) {
			return err
		}
		logger.Warn("enrolling failed; trying again", "error", err, "retry_in", wait)
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-time.After(wait):
		}
		wait = min(2*wait, enrollRetryLongest)
	}
}

func serveProbes(ctx context.Context, address string, handler http.Handler, logger *slog.Logger,
) (*http.Server, error) {
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("meshgw: listening for probes on %s: %w", address, err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("probe server stopped", "error", err)
		}
	}()
	return server, nil
}

func noHostAddresses() []netip.Addr { return nil }
