// Command meshd runs the unprivileged MeshTransit coordination daemon.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"meshtransit.net/client/internal/cloudaddr"
	"meshtransit.net/client/internal/config"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/daemon"
	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/flowlog"
	"meshtransit.net/client/internal/identity"
	"meshtransit.net/client/internal/localapi"
	"meshtransit.net/client/internal/mtcpclient"
	"meshtransit.net/client/internal/netwatch"
	"meshtransit.net/client/internal/portmap"
	"meshtransit.net/client/internal/profile"
	"meshtransit.net/client/internal/servicemanager"
	"meshtransit.net/client/internal/socket"
	"meshtransit.net/client/internal/version"
)

const identityMigrationTimeout = 30 * time.Second

func main() {
	os.Exit(entry(os.Args[1:]))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runContext(context.Background(), args, stdout, stderr)
}

// runContext runs meshd until parent is cancelled (the Windows service
// manager stopping it) or the process receives an interrupt.
func runContext(parent context.Context, args []string, stdout, stderr io.Writer) int {
	cfg, err := config.Parse(args, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshd: %v\n", err)

		return 2
	}
	if cfg.ShowVersion {
		_, _ = fmt.Fprintln(stdout, version.String())

		return 0
	}

	logger := newLogger(stderr, cfg.LogLevel)
	notifier, err := servicemanager.New()
	if err != nil {
		logger.Error("creating service-manager notifier failed", "error", err)

		return 1
	}
	profiles, err := profile.Open(cfg.StateDir)
	if err != nil {
		logger.Error("opening profile store failed", "error", err)

		return 1
	}
	defer func() {
		if closeErr := profiles.Close(); closeErr != nil {
			logger.Error("closing profile store failed", "error", closeErr)
		}
	}()
	protector, err := loadIdentityProtector(cfg.IdentityKeyPath, cfg.StateDir, logger)
	if err != nil {
		logger.Error("loading identity envelope key failed", "error", err)

		return 1
	}
	identities, err := identity.Open(cfg.StateDir, protector)
	if err != nil {
		closeErr := protector.Close()
		logger.Error("opening identity store failed", "error", errors.Join(err, closeErr))

		return 1
	}
	defer func() {
		if closeErr := identities.Close(); closeErr != nil {
			logger.Error("closing identity store failed", "error", closeErr)
		}
	}()
	migrationContext, cancelMigration := context.WithTimeout(
		context.Background(),
		identityMigrationTimeout,
	)
	err = identities.MigrateAll(migrationContext)
	cancelMigration()
	if err != nil {
		logger.Error("migrating identity records failed", "error", err)

		return 1
	}
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "mesh-node"
	}
	daemonOptions := daemon.Options{
		Hostname:           hostname,
		Logger:             logger,
		AdvertiseEndpoints: cfg.AdvertiseEndpoints,
	}
	var flowReporter *flowlog.Reporter
	if cfg.EnableFlowLogs {
		flowReporter, err = flowlog.New(flowlog.Config{
			BaseURL:  cfg.FlowLogURL,
			Interval: cfg.FlowLogInterval,
			Timeout:  cfg.FlowLogTimeout,
			Logger:   logger,
		})
		if err != nil {
			logger.Error("creating flow log reporter failed", "error", err)

			return 1
		}
	}
	opener, netAdminClient, err := platformNetwork(cfg)
	if err != nil {
		logger.Error("preparing host networking failed", "error", err)

		return 1
	}
	daemonOptions.EnableDeviceAliases = cfg.EnableDeviceAliases
	daemonOptions.EnableSubnetRoutes = cfg.EnableSubnetRoutes
	daemonOptions.EnableSubnetRouter = cfg.EnableSubnetRouter
	daemonOptions.EnableExitNode = cfg.EnableExitNode
	daemonOptions.EnableExits = cfg.EnableExits
	daemonOptions.ExitPinsDir = cfg.StateDir
	daemonOptions.RouteSettingsPath = cfg.RouteSettingsFile
	if runtime.GOOS == "linux" {
		// Written by the package's postinst before it restarts meshd.
		daemonOptions.RestartMarkerPath = "/run/meshd/restart-expected"
	}
	if cfg.EnableDataPlane {
		engine, err := dataplane.NewWireGuardWithObserver(
			opener,
			cfg.WireGuardListenPort,
			flowReporter,
		)
		if err != nil {
			logger.Error("creating encrypted data plane failed", "error", err)

			return 1
		}
		engine.SetLogger(logger.With("component", "data_plane"))
		switch cfg.LazyPeers {
		case "off":
			engine.SetLazyPeers(dataplane.LazyPeersOff)
		case "always":
			engine.SetLazyPeers(dataplane.LazyPeersAlways)
			logger.Warn("TEST ONLY: every map installs its peers on demand")
		}
		if cfg.TestPolicyDrift {
			engine.SetPolicyDriftTest(true)
			logger.Warn("TEST ONLY: the packet filter enforces one rule fewer than control sends")
		}
		daemonOptions.DataPlane = engine
		if cfg.PortMapping == "auto" {
			daemonOptions.PortMapper = portmap.New(portmap.Options{Logger: logger.With("component", "port_mapping")})
		}
		if cfg.CloudMetadata == "auto" {
			watcher := cloudaddr.NewWatcher(cloudaddr.WatcherOptions{Logger: logger.With("component", "cloud_metadata")})
			if watcher.Platform() != cloudaddr.PlatformNone {
				daemonOptions.CloudAddresses = watcher
				logger.Info("cloud instance recognised", "platform", string(watcher.Platform()))
			}
		}
		logger.Info(
			"encrypted data plane enabled",
			append(networkLogAttrs(cfg), "listen_port", cfg.WireGuardListenPort)...,
		)
		if flowReporter != nil {
			logger.Info(
				"header-only flow logging enabled",
				"origin", cfg.FlowLogURL,
				"interval", cfg.FlowLogInterval,
			)
		}
	}
	if cfg.EnableDNS {
		dnsManager, err := platformDNS(netAdminClient, logger)
		if err != nil {
			logger.Error("setting up MeshTransit DNS failed", "error", err)

			return 1
		}
		daemonOptions.DNS = dnsManager
		logger.Info("MeshTransit DNS enabled", networkLogAttrs(cfg)...)
	}
	var networkMonitor *netwatch.Monitor
	if cfg.EnableDataPlane {
		networkMonitor, err = netwatch.New(netwatch.Options{
			Logger:             logger,
			ExcludedInterfaces: ownInterfaces,
		})
		if err != nil {
			logger.Warn(
				"host network monitor unavailable",
				"error", err,
				"fallback", "periodic endpoint refresh",
			)
		} else {
			daemonOptions.NetworkChanges = networkMonitor.Events()
		}
	}
	control := mtcpclient.New()
	service, err := daemon.New(
		profiles,
		identities,
		version.Current(),
		control,
		daemonOptions,
	)
	if err != nil {
		logger.Error("creating daemon service failed", "error", err)

		return 1
	}
	apiOptions, err := localAPIOptions(cfg)
	if err != nil {
		logger.Error("preparing local api authorization failed", "error", err)

		return 1
	}
	server, err := localapi.New(service, logger, apiOptions)
	if err != nil {
		logger.Error("creating local api failed", "error", err)

		return 1
	}
	listener, err := socket.Listen(cfg.SocketPath)
	if err != nil {
		logger.Error("opening local socket failed", "error", err, "path", cfg.SocketPath)

		return 1
	}
	defer func() {
		if closeErr := listener.Close(); closeErr != nil {
			logger.Error("closing local socket failed", "error", closeErr)
		}
	}()

	// A signal, or the service manager ending parent, stops the service:
	// the context then ends with controlplane.ErrStopping, so a subnet router
	// tells Core it is going away. Ending for another reason (a component
	// stopped) is no announcement.
	ctx, cancel := context.WithCancelCause(parent)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-signals:
			cancel(controlplane.ErrStopping)
		case <-parent.Done():
			cancel(controlplane.ErrStopping)
		case <-ctx.Done():
		}
	}()
	stop := func() {
		signal.Stop(signals)
		cancel(nil)
	}
	defer stop()
	if err := notifier.Ready(ctx); err != nil {
		logger.Error("reporting service readiness failed", "error", err)

		return 1
	}
	defer func() {
		notifyContext, cancelNotify := context.WithTimeout(context.Background(), time.Second)
		defer cancelNotify()
		if notifyErr := notifier.Stopping(notifyContext); notifyErr != nil {
			logger.Warn("reporting service shutdown failed", "error", notifyErr)
		}
	}()

	logger.Info("meshd started", "socket", cfg.SocketPath, "version", version.Version)
	serverResult := make(chan error, 1)
	syncResult := make(chan error, 1)
	go func() { serverResult <- server.Serve(ctx, listener) }()
	go func() { syncResult <- service.Run(ctx) }()
	var networkResult chan error
	if networkMonitor != nil {
		networkResult = make(chan error, 1)
		go func() { networkResult <- networkMonitor.Run(ctx) }()
	}
	var flowResult chan error
	if flowReporter != nil {
		flowResult = make(chan error, 1)
		go func() { flowResult <- flowReporter.Run(ctx) }()
	}

	var serverErr error
	var syncErr error
	var networkErr error
	serverFinished := false
	syncFinished := false
	networkFinished := false
	select {
	case serverErr = <-serverResult:
		serverFinished = true
	case syncErr = <-syncResult:
		syncFinished = true
	case networkErr = <-networkResult:
		networkFinished = true
	case <-ctx.Done():
	}
	stop()
	if !serverFinished {
		serverErr = <-serverResult
	}
	if !syncFinished {
		syncErr = <-syncResult
	}
	if networkResult != nil && !networkFinished {
		networkErr = <-networkResult
	}
	var flowErr error
	if flowResult != nil {
		flowErr = <-flowResult
	}
	if errors.Is(serverErr, context.Canceled) {
		serverErr = nil
	}
	if errors.Is(syncErr, context.Canceled) {
		syncErr = nil
	}
	if errors.Is(networkErr, context.Canceled) {
		networkErr = nil
	}
	if errors.Is(flowErr, context.Canceled) {
		flowErr = nil
	}
	if err := errors.Join(serverErr, syncErr, networkErr, flowErr); err != nil {
		logger.Error("meshd stopped unexpectedly", "error", err)

		return 1
	}
	logger.Info("meshd stopped")

	return 0
}

func newLogger(writer io.Writer, levelName string) *slog.Logger {
	level := slog.LevelInfo
	switch levelName {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	return slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{Level: level}))
}
