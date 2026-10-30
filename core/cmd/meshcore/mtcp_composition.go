package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"meshtransit.net/core/internal/domain/captivewindow"

	mtcpadapter "meshtransit.net/core/internal/adapter/mtcp"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/enrollment/registration/intake"
	"meshtransit.net/core/internal/domain/kubecluster"
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
// session.proof1: a node may prove its node key as its first record, and a
// Kubernetes gateway must (mtcp-v1 §6.7).
func mtcpCapabilities(deviceAliases, relayZones, subnetRoutes bool) []string {
	capabilities := []string{"map.zstd", "disco.v2", "relay.mtrp1", "dns.split", "stats.path1", "nat.report1", "map.large1",
		"session.proof1"}
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

// dnsCapabilities offers dns.forward1, forward DNS zones in maps (DNS design
// D1 §4.1), dns.records1, names and every zone kind (D2 §4.1), and
// dns.root1, the root zone with DNS digests and resolver health (D1b §3.2),
// when the deployment has them.
func dnsCapabilities(dnsZones bool) []string {
	if !dnsZones {
		return nil
	}
	return []string{"dns.forward1", "dns.records1", "dns.root1"}
}

// kubernetesCapabilities offers gateway.kube.v1, a Kubernetes gateway's
// peers' Kubernetes access in its map (mtcp-v1 §7.8), only where maps are
// built from the shared inventory: no other read computes it, so a gateway
// is told the deployment lacks it instead of finding its peers without
// access (K1a3 §13.10).
func kubernetesCapabilities(sharedInventory bool) []string {
	if !sharedInventory {
		return nil
	}
	return []string{"gateway.kube.v1"}
}

// kubeCertCapabilities offers gateway.cert1, gateways' replica
// certificates (mtcp-v1 §6.9), whenever Core queues them: whether a worker
// signs now is answered per request (a3 §14 R-H2).
func kubeCertCapabilities(certificates mtcpadapter.KubeCertificates) []string {
	if certificates == nil {
		return nil
	}
	return []string{mtcpadapter.CapabilityKubeCert}
}

// kubernetesClusterCapabilities offers kube.ca1, the Kubernetes clusters a
// node may reach and their roots in its map (mtcp-v1 §7.11), when schema
// 244 was granted at startup.
func kubernetesClusterCapabilities(offered bool) []string {
	if !offered {
		return nil
	}
	return []string{mtcpadapter.CapabilityKubeCA}
}

// kubeAuditCapabilities offers gateway.audit1, gateways' type A
// operations recorded before they are forwarded (mtcp-v1 §6.10), when
// schema 245 was granted at startup.
func kubeAuditCapabilities(audit *kubeAudit) []string {
	if audit == nil {
		return nil
	}
	return []string{mtcpadapter.CapabilityKubeAudit}
}

// gatewayTokenCapabilities offers gateway.token1, a gateway's pod token on
// every session (mtcp-v1 §6.7), when schema 246 was granted at startup.
func gatewayTokenCapabilities(tokens *mtcpadapter.GatewayTokens) []string {
	if tokens == nil {
		return nil
	}
	return []string{mtcpadapter.CapabilityGatewayToken}
}

// composeGatewayTokens holds gateways to their pod token on every session,
// against the trust their rotations read (schema 246).
func composeGatewayTokens(timestamps *postgresadapter.MTCPTimestampStore, trust kubecluster.MachineKeyRotations,
	mode kubecluster.GatewayTokenMode,
) *mtcpadapter.GatewayTokens {
	return &mtcpadapter.GatewayTokens{Guard: mtcpTimestampGuard{store: timestamps}, Trust: trust, Mode: mode}
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
	// gatewayKeyEvents records Kubernetes gateways' stale or contested keys.
	gatewayKeyEvents mtcpadapter.GatewayKeyRecorder
	logger           *slog.Logger
	relayZones       bool // offer relay.zones2 (MESHTRANSIT_RELAY_TICKET_ZONES_V2)
	subnetRoutes     bool // offer subnet routes (MESHTRANSIT_SUBNET_ROUTES_ENABLED)
	exitNodes        bool // offer exit nodes (MESHTRANSIT_EXIT_NODES_ENABLED)
	dnsZones         bool // offer dns.forward1 (MESHTRANSIT_DNS_ZONES_ENABLED)
	kubernetesAccess bool // offer gateway.kube.v1 (shared inventory)
	// kubernetesClusters offers kube.ca1 (Kubernetes join, shared
	// inventory, schema 244 granted at startup).
	kubernetesClusters bool
	dnsSuffix          dnsname.Suffix // MESHTRANSIT_DNS_SUFFIX; zero: the default
	// dnsInfrastructure are the deployment's own host names a root zone
	// leaves to a node's network (MESHTRANSIT_DNS_PROTECTED_NAMES, the
	// Console and identity hosts).
	dnsInfrastructure []string
	// clusterJoins, when set, accepts Kubernetes cluster joins
	// (MESHTRANSIT_KUBERNETES_JOIN).
	clusterJoins mtcpadapter.ClusterJoins
	// gatewayKeys moves Kubernetes gateways to new machine keys.
	gatewayKeys kubecluster.MachineKeyRotations
	// gatewayTokens, when set, holds gateways to their pod token on every
	// session (gateway.token1, schema 246).
	gatewayTokens *mtcpadapter.GatewayTokens
	// gatewayPresence says whether a gateway's stream may rotate its keys.
	gatewayPresence mapsession.GatewayPresenceStore
	// kubeCertificates, when set, queues gateways' certificate requests
	// (gateway.cert1).
	kubeCertificates mtcpadapter.KubeCertificates
	// kubeAudit, when set, records gateways' operations (gateway.audit1).
	kubeAudit *kubeAudit
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
		DNSInfrastructureNames: deps.dnsInfrastructure,
	}
	if deps.browser != nil {
		applicationOptions.BrowserIssuer = deps.browser.issuer
		applicationOptions.BrowserApproval = deps.browser.completion
		applicationOptions.ApprovalOrigin = deps.origin
		applicationOptions.ApprovalTTL = min(browserRegistrationTTL, mtcpApprovalTTL)
	}
	applicationOptions.MachineKeyRotations = deps.gatewayKeys
	applicationOptions.GatewayPresence = deps.gatewayPresence
	applicationOptions.KubeCertificates = deps.kubeCertificates
	if deps.kubeAudit != nil {
		applicationOptions.KubeAudit = deps.kubeAudit.intents
		applicationOptions.KubeAuditReports = deps.kubeAudit.reports
		applicationOptions.KubeAuditLimits = deps.kubeAudit.limits
	}
	if deps.clusterJoins != nil {
		applicationOptions.ClusterJoins = deps.clusterJoins
		applicationOptions.ClusterJoinSecrets = kubecluster.SystemSecrets{}
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
			deps.subnetRoutes), exitCapabilities(deps.exitNodes)...), append(captiveCapabilities(deps.captiveWindows),
			append(append(dnsCapabilities(deps.dnsZones), kubernetesCapabilities(deps.kubernetesAccess)...),
				append(append(kubeCertCapabilities(deps.kubeCertificates),
					kubernetesClusterCapabilities(deps.kubernetesClusters)...),
					append(kubeAuditCapabilities(deps.kubeAudit), gatewayTokenCapabilities(deps.gatewayTokens)...)...)...)...)...),
		Logger:         logger,
		Metrics:        metrics,
		HandshakeRate:  controlConfig.MTCP.HandshakeRate,
		HandshakeBurst: controlConfig.MTCP.HandshakeBurst,
		// Sessions that serve no Device yet, and how long they may last.
		UnauthenticatedPerSource: controlConfig.MTCP.UnauthenticatedPerSource,
		UnprovenLimit:            controlConfig.MTCP.UnprovenLifetime,
		// MTCP connections count against the listener's connection bound.
		MaxSessions:   controlConfig.MaxSessions,
		DrainWindow:   controlConfig.DrainWindow,
		GatewayKeys:   deps.gatewayKeyEvents,
		GatewayTokens: deps.gatewayTokens,
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

// The map stream service takes resolver health reports (mtcp-v1 §8.6): the
// MTCP adapter finds it by this interface, and drops the reports without it.
var _ mtcpadapter.DNSHealthStreams = (*mapsession.StreamService)(nil)

// mtcpTimestampGuard gives the MTCP server schema 226's answers in its own
// terms.
type mtcpTimestampGuard struct {
	store *postgresadapter.MTCPTimestampStore
}

func (guard mtcpTimestampGuard) AcceptTimestamp(ctx context.Context, machineFingerprint [32]byte, nodeKey []byte,
	timestampMS int64) (mtcpadapter.TimestampCheck, error) {
	check, err := guard.store.AcceptTimestamp(ctx, machineFingerprint, nodeKey, timestampMS)
	if err != nil {
		return mtcpadapter.TimestampCheck{}, err
	}
	return timestampCheck(check), nil
}

// timestampCheck is the store's answer in the server's terms.
func timestampCheck(check postgresadapter.MTCPTimestampCheck) mtcpadapter.TimestampCheck {
	machine := mtcpadapter.MachineUnbound
	switch check.MachineState {
	case "current":
		machine = mtcpadapter.MachineCurrent
	case "retired":
		machine = mtcpadapter.MachineRetired
	}
	return mtcpadapter.TimestampCheck{Accepted: check.Accepted, Gateway: check.Gateway, Machine: machine,
		NodeCurrent: check.NodeCurrent}
}

func (guard mtcpTimestampGuard) CommitGatewayTimestamp(ctx context.Context, machineFingerprint [32]byte,
	nodeKey []byte, timestampMS int64) (bool, error) {
	return guard.store.CommitGatewayTimestamp(ctx, machineFingerprint, nodeKey, timestampMS)
}

// AcceptTimestampV3 is AcceptTimestamp with schema 246's ratchet.
func (guard mtcpTimestampGuard) AcceptTimestampV3(ctx context.Context, machineFingerprint [32]byte,
	nodeKey []byte, timestampMS int64) (mtcpadapter.TimestampCheck, error) {
	check, err := guard.store.AcceptTimestampV3(ctx, machineFingerprint, nodeKey, timestampMS)
	if err != nil {
		return mtcpadapter.TimestampCheck{}, err
	}
	answer := timestampCheck(check)
	answer.TokenRatcheted = check.TokenRatcheted
	return answer, nil
}

func (guard mtcpTimestampGuard) CommitGatewayTimestampV2(ctx context.Context, machineFingerprint [32]byte,
	nodeKey []byte, timestampMS int64, tokenProven bool, mode kubecluster.GatewayTokenMode,
) (kubecluster.GatewayTimestampResult, bool, error) {
	commit, err := guard.store.CommitGatewayTimestampV2(ctx, machineFingerprint, nodeKey, timestampMS, tokenProven,
		mode)
	return commit.Result, commit.Ratcheted, err
}

// AcceptTimestampV4 is AcceptTimestampV3 with schema 253's suspensions.
func (guard mtcpTimestampGuard) AcceptTimestampV4(ctx context.Context, machineFingerprint [32]byte,
	nodeKey []byte, timestampMS int64) (mtcpadapter.TimestampCheck, error) {
	check, err := guard.store.AcceptTimestampV4(ctx, machineFingerprint, nodeKey, timestampMS)
	if err != nil {
		return mtcpadapter.TimestampCheck{}, err
	}
	answer := timestampCheck(check)
	answer.TokenRatcheted = check.TokenRatcheted
	answer.SuspendedUntil = check.SuspendedUntil
	return answer, nil
}

func (guard mtcpTimestampGuard) CommitGatewayTimestampV3(ctx context.Context, machineFingerprint [32]byte,
	nodeKey []byte, timestampMS int64, tokenProven bool, mode kubecluster.GatewayTokenMode,
) (kubecluster.GatewayTimestampResult, bool, time.Time, error) {
	commit, err := guard.store.CommitGatewayTimestampV3(ctx, machineFingerprint, nodeKey, timestampMS,
		tokenProven, mode)
	return commit.Result, commit.Ratcheted, commit.SuspendedUntil, err
}

func (guard mtcpTimestampGuard) ReadRatchetSuspension(ctx context.Context, machineFingerprint [32]byte,
	nodeKey []byte) (time.Time, error) {
	return guard.store.ReadRatchetSuspension(ctx, machineFingerprint, nodeKey)
}

func (guard mtcpTimestampGuard) RatchetGatewayToken(ctx context.Context, machineFingerprint [32]byte,
	nodeKey []byte) (bool, error) {
	return guard.store.RatchetGatewayToken(ctx, machineFingerprint, nodeKey)
}
