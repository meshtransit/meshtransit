package main

import (
	"errors"
	"log/slog"
	"time"

	mtcpadapter "meshtransit.net/core/internal/adapter/mtcp"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/control/mapsession"
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
// grants are offered only where the deployment projects them.
func mtcpCapabilities(deviceAliases bool) []string {
	capabilities := []string{"map.zstd", "disco.v2", "relay.mtrp1", "dns.split", "stats.path1", "nat.report1"}
	if deviceAliases {
		capabilities = append(capabilities, "device-alias.v1")
	}
	return capabilities
}

// composeMTCP builds the MTCP v1 server that shares the control listener
// and control key with TS2021. It returns nil when MTCP is off.
// mtcpDependencies are the application services MTCP sessions use. The
// browser fields are nil when browser registration is off.
type mtcpDependencies struct {
	streams       mtcpadapter.MapStreams
	sessions      mtcpMapSessions
	registrations mtcpadapter.Registrations
	logout        mtcpadapter.DeviceLogout
	browser       *browserControlServices
	origin        string
	guard         mtcpadapter.TimestampGuard
	logger        *slog.Logger
}

// mtcpMapSessions is mapsession.Service: endpoints and snapshot opening.
type mtcpMapSessions interface {
	mtcpadapter.EndpointObserver
	mtcpadapter.Snapshots
}

// mtcpApprovalTTL is how long a node waits for a browser approval; the
// approval itself may outlive it, and mtcp-v1 §6.2 caps the wait at 10 min.
const mtcpApprovalTTL = 10 * time.Minute

func composeMTCP(
	controlConfig config.ControlConfig,
	deps mtcpDependencies,
) (*mtcpadapter.Server, *mtcpadapter.Metrics, error) {
	if controlConfig.MTCP == nil {
		return nil, nil, nil
	}
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
	clients, err := clientip.NewResolver(controlConfig.MTCP.TrustedProxyPrefixes())
	if err != nil {
		return nil, nil, errors.Join(errInvalidMTCPComposition, err)
	}
	applicationOptions := mtcpadapter.ApplicationOptions{
		Streams: deps.streams, Endpoints: deps.sessions, Snapshots: deps.sessions, ControlKeys: keys,
		Logger: logger, Registrations: deps.registrations, RegistrationIDs: intake.PublicRegistrationIDGenerator{},
		Logout: deps.logout,
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
	metrics := mtcpadapter.NewMetrics()
	server, err := mtcpadapter.NewServer(mtcpadapter.Options{
		Keys:         keys,
		ClientIPs:    clients,
		Handler:      application,
		Guard:        deps.guard,
		Capabilities: mtcpCapabilities(controlConfig.Map.EnableDeviceAliases),
		Logger:       logger,
		Metrics:      metrics,
		// MTCP connections count against the listener's connection bound.
		MaxSessions: controlConfig.MaxSessions,
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
