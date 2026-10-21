package main

import (
	"errors"
	"log/slog"
	"meshtransit.net/core/internal/domain/captivewindow"
	"time"

	mtcpadapter "meshtransit.net/core/internal/adapter/mtcp"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/enrollment/registration/intake"
	"meshtransit.net/core/internal/platform/clientip"
	"meshtransit.net/core/internal/platform/config"
)

var errInvalidMTCPComposition = errors.New("invalid MTCP composition")

var (
	_ mtcpadapter.DeviceLogout = (*control.DeviceLogoutService)(nil)
	_ mtcpadapter.MapStreams   = (*mapsession.StreamService)(nil)
	_ mtcpMapSessions          = (*mapsession.Service)(nil)
)

// mtcpCapabilities lists what this Core serves (mtcp-v1 §13). Device alias
// grants are offered only where the deployment projects them. map.large1:
// maps of up to the configured peer limit go only to clients that declare it;
// the others get at most 256 peers. relay.zones2: relay tickets for more than
// 31 shares (MTT2), offered once every relay takes them. routes.subnet.v1 and
// router.subnet.v1: subnet routes, when the deployment routes subnets;
// router.health1: routers report their Sites' health with them;
// routes.selection1: nodes report the router they use for each Site.
func mtcpCapabilities(deviceAliases, relayZones, subnetRoutes bool) []string {
	capabilities := []string{"map.zstd", "disco.v2", "relay.mtrp1", "dns.split", "stats.path1", "nat.report1", "map.large1"}
	if deviceAliases {
		capabilities = append(capabilities, "device-alias.v1")
	}
	if relayZones {
		capabilities = append(capabilities, "relay.zones2")
	}
	if subnetRoutes {
		capabilities = append(capabilities, "routes.subnet.v1", "router.subnet.v1", "router.health1",
			"routes.selection1")
	}
	return capabilities
}

// exitCapabilities are the exit node capabilities (mtcp-v1 §7.7), offered
// when the deployment has exit nodes: routes.exit.v1 for nodes that use
// Exit Pools, router.exit.v1 for exit nodes.
func exitCapabilities(exitNodes bool) []string {
	if !exitNodes {
		return nil
	}
	return []string{"routes.exit.v1", "router.exit.v1"}
}

// captiveCapabilities offers captive.audit1, nodes reporting the captive
// portal windows root opened (exit node design §17.12), when Core records
// them.
func captiveCapabilities(recorder captivewindow.Recorder) []string {
	if recorder == nil {
		return nil
	}
	return []string{"captive.audit1"}
}

// mtcpDependencies are the application services MTCP sessions use. The
// browser fields are nil when browser registration is off.
type mtcpDependencies struct {
	streams        mtcpadapter.MapStreams
	sessions       mtcpMapSessions
	registrations  mtcpadapter.Registrations
	logout         mtcpadapter.DeviceLogout
	paths          mtcpadapter.PathRecorder         // optional
	connectivity   mtcpadapter.ConnectivityRecorder // optional
	routeOffers    mtcpadapter.RouteOffers          // optional
	exitOffers     mtcpadapter.ExitOffers           // optional
	captiveWindows captivewindow.Recorder           // optional: offers captive.audit1
	browser        *browserControlServices
	origin         string
	guard          mtcpadapter.TimestampGuard
	logger         *slog.Logger
	relayZones     bool           // offer relay.zones2 (MESHTRANSIT_RELAY_TICKET_ZONES_V2)
	subnetRoutes   bool           // offer subnet routes (MESHTRANSIT_SUBNET_ROUTES_ENABLED)
	exitNodes      bool           // offer exit nodes (MESHTRANSIT_EXIT_NODES_ENABLED)
	dnsSuffix      dnsname.Suffix // MESHTRANSIT_DNS_SUFFIX; zero: the default
}

// mtcpMapSessions is mapsession.Service: endpoints and snapshot opening.
type mtcpMapSessions interface {
	mtcpadapter.EndpointObserver
	mtcpadapter.Snapshots
}

// mtcpApprovalTTL is how long a node waits for a browser approval; the
// approval itself may outlive it, and mtcp-v1 §6.2 caps the wait at 10 min.
const mtcpApprovalTTL = 10 * time.Minute

// controlKeyExpiryWarning is how early the control role warns that its key
// expires (MESHTRANSIT_CONTROL_MTCP_KEY_NOT_AFTER).
const controlKeyExpiryWarning = 60 * 24 * time.Hour

// composeMTCP builds the MTCP v1 server the control listener routes to.
func composeMTCP(
	controlConfig config.ControlConfig,
	deps mtcpDependencies,
) (*mtcpadapter.Server, *mtcpadapter.Metrics, error) {
	if deps.streams == nil || deps.sessions == nil || deps.registrations == nil || deps.logout == nil ||
		deps.guard == nil ||
		deps.logger == nil || (deps.browser != nil && deps.origin == "") {
		return nil, nil, errInvalidMTCPComposition
	}
	logger := deps.logger
	material, err := controlConfig.NoisePrivateKeyFile.Read()
	if err != nil {
		return nil, nil, errors.Join(errInvalidMTCPComposition, err)
	}
	private, err := mtcpadapter.ParseControlKey(material)
	if err != nil {
		return nil, nil, errors.Join(errInvalidMTCPComposition, err)
	}
	keys := []mtcpadapter.ControlKey{{Private: private, NotAfter: controlConfig.MTCP.KeyNotAfter}}
	if controlConfig.NextNoisePrivateKeyFile != nil {
		// During a rotation Core announces the next key to every session
		// (KeyUpdate) and answers handshakes made with it (mtcp-v1 §11).
		nextMaterial, err := controlConfig.NextNoisePrivateKeyFile.Read()
		if err != nil {
			return nil, nil, errors.Join(errInvalidMTCPComposition, err)
		}
		next, err := mtcpadapter.ParseControlKey(nextMaterial)
		if err != nil {
			return nil, nil, errors.Join(errInvalidMTCPComposition, err)
		}
		keys = append(keys, mtcpadapter.ControlKey{Private: next, NotAfter: controlConfig.MTCP.NextKeyNotAfter})
		logger.Info("control key rotation in progress: next key announced",
			"next_not_after", controlConfig.MTCP.NextKeyNotAfter)
	}
	// Past the expiry nodes refuse the key and the control role no longer
	// starts, so warn while there is time to rotate it.
	if remaining := time.Until(controlConfig.MTCP.KeyNotAfter); remaining < controlKeyExpiryWarning {
		logger.Warn("control key expires soon; rotate it", "not_after", controlConfig.MTCP.KeyNotAfter,
			"remaining_hours", int(remaining.Hours()))
	}
	clients, err := clientip.NewResolver(controlConfig.MTCP.TrustedProxyPrefixes())
	if err != nil {
		return nil, nil, errors.Join(errInvalidMTCPComposition, err)
	}
	metrics := mtcpadapter.NewMetrics()
	applicationOptions := mtcpadapter.ApplicationOptions{
		Streams: deps.streams, Endpoints: deps.sessions, Snapshots: deps.sessions, ControlKeys: keys,
		Logger: logger, Registrations: deps.registrations, RegistrationIDs: intake.PublicRegistrationIDGenerator{},
		Logout: deps.logout, Paths: deps.paths, Connectivity: deps.connectivity, RouteOffers: deps.routeOffers, ExitOffers: deps.exitOffers,
		CaptiveWindows:         deps.captiveWindows,
		Metrics:                metrics,
		DeniedEndpointPrefixes: controlConfig.MTCP.DeniedEndpointPrefixes(),
		DNSSuffix:              deps.dnsSuffix,
	}
	if deps.browser != nil {
		applicationOptions.BrowserIssuer = deps.browser.issuer
		applicationOptions.BrowserApproval = deps.browser.completion
		applicationOptions.ApprovalOrigin = deps.origin
		applicationOptions.ApprovalTTL = min(browserRegistrationTTL, mtcpApprovalTTL)
	}
	application, err := mtcpadapter.NewApplication(applicationOptions)
	if err != nil {
		return nil, nil, errors.Join(errInvalidMTCPComposition, err)
	}
	server, err := mtcpadapter.NewServer(mtcpadapter.Options{
		Keys:      keys,
		ClientIPs: clients,
		Handler:   application,
		Guard:     deps.guard,
		Capabilities: append(append(mtcpCapabilities(controlConfig.Map.EnableDeviceAliases, deps.relayZones,
			deps.subnetRoutes), exitCapabilities(deps.exitNodes)...), captiveCapabilities(deps.captiveWindows)...),
		Logger:         logger,
		Metrics:        metrics,
		HandshakeRate:  controlConfig.MTCP.HandshakeRate,
		HandshakeBurst: controlConfig.MTCP.HandshakeBurst,
		// Sessions that serve no Device yet, and how long they may last.
		UnauthenticatedPerSource: controlConfig.MTCP.UnauthenticatedPerSource,
		UnprovenLimit:            controlConfig.MTCP.UnprovenLifetime,
		// MTCP connections count against the listener's connection bound.
		MaxSessions: controlConfig.MaxSessions,
		DrainWindow: controlConfig.DrainWindow,
	})
	if err != nil {
		return nil, nil, errors.Join(errInvalidMTCPComposition, err)
	}
	return server, metrics, nil
}

// composeDeviceLogout builds the logout service MTCP sessions use, bounded
// like the other control-path statements.
func composeDeviceLogout(mapConfig config.ControlMapConfig, runtime *postgresadapter.Pool) (*control.DeviceLogoutService,
	error) {
	store, err := postgresadapter.NewDeviceLogoutStore(runtime, postgresadapter.AccountSessionOptions{
		StatementTimeout: mapConfig.StatementTimeout, IdleTimeout: mapConfig.TransactionIdleLimit,
	})
	if err != nil {
		return nil, errors.Join(errInvalidMTCPComposition, err)
	}
	service, err := control.NewDeviceLogoutService(store)
	if err != nil {
		return nil, errors.Join(errInvalidMTCPComposition, err)
	}
	return service, nil
}
