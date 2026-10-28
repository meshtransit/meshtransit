package mtcp

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/captivewindow"
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
	"meshtransit.net/shared/policydigest"
)

// MapStreams runs authorized map streams and stores enforcement evidence
// (mapsession.StreamService).
type MapStreams interface {
	Serve(ctx context.Context, machine control.AuthenticatedMachine, request mapsession.Request,
		sink mapsession.StreamSink) error
	ReportEnforcement(ctx context.Context, machine control.AuthenticatedMachine,
		report mapsession.ClientEnforcement) error
}

// EndpointObserver records a node's endpoints for its live map session
// and flushes a change Core deferred (mapsession.Service).
type EndpointObserver interface {
	ObserveSessionEndpoints(ctx context.Context, snapshot mapsession.Snapshot, set node.EndpointSet,
		preferredRelay int, hasPreferredRelay bool) (mapsession.EndpointAnnouncement, error)
	FlushSessionEndpoints(ctx context.Context, snapshot mapsession.Snapshot) (mapsession.EndpointAnnouncement, error)
}

// Snapshots opens the authoritative snapshot of a machine and node key
// (mapsession.Service). A successful open proves the node key is the
// Device's current key.
type Snapshots interface {
	Open(ctx context.Context, machine control.AuthenticatedMachine, request mapsession.Request) (mapsession.Snapshot, error)
}

// ApplicationOptions configures an Application. Registration fields may be
// nil: requests they would serve are answered UNSUPPORTED.
type ApplicationOptions struct {
	Streams     MapStreams
	Endpoints   EndpointObserver
	Snapshots   Snapshots
	ControlKeys []ControlKey
	Logger      *slog.Logger

	Registrations   Registrations
	RegistrationIDs RegistrationIDs
	BrowserIssuer   BrowserIssuer
	BrowserApproval BrowserApproval
	// ClusterJoins, when set with ClusterJoinSecrets, accepts Kubernetes
	// cluster joins (MESHTRANSIT_KUBERNETES_JOIN); without it they are
	// refused.
	ClusterJoins       ClusterJoins
	ClusterJoinSecrets ClusterJoinSecrets
	// MachineKeyRotations, when set, moves Kubernetes gateways to new
	// machine keys (mtcp-v1 §6.8).
	MachineKeyRotations kubecluster.MachineKeyRotations
	// GatewayPresence says whether a Kubernetes gateway's stream may rotate
	// its keys (K1a1 plan §16.12); without it gateways rotate none.
	GatewayPresence mapsession.GatewayPresenceStore
	// KubeCertificates, when set, answers gateway.cert1 requests (mtcp-v1
	// §6.9).
	KubeCertificates KubeCertificates
	Logout           DeviceLogout
	Paths            PathRecorder
	Connectivity     ConnectivityRecorder
	// RouteOffers, when set, stores the subnets Devices offer to forward.
	RouteOffers RouteOffers
	// ExitOffers, when set, stores whether Devices offer to be exit nodes.
	ExitOffers ExitOffers
	// CaptiveWindows, when set, records the captive portal windows Devices
	// report (captive.audit1).
	CaptiveWindows captivewindow.Recorder
	// ApprovalOrigin is the https origin of approval URLs; ApprovalTTL is
	// how long an approval stays open.
	ApprovalOrigin string
	ApprovalTTL    time.Duration
	// Metrics, when set, counts map stream ends.
	Metrics *Metrics
	// DeniedEndpointPrefixes are ranges, such as Core's own addresses,
	// that are dropped from every endpoint report.
	DeniedEndpointPrefixes []netip.Prefix
	// DNSSuffix is the deployment's DNS suffix maps name Devices and shares
	// under; the zero value is dnsname.DefaultSuffix.
	DNSSuffix dnsname.Suffix
	// DNSInfrastructureNames are the host names of the deployment's own
	// services a root zone leaves to a node's network (TD-CLI-70); at most
	// MaximumDNSInfrastructureNames are sent.
	DNSInfrastructureNames []string
}

// Application turns established sessions into registrations and map
// streams.
type Application struct {
	options       ApplicationOptions
	now           func() time.Time
	poll          time.Duration // how often a pending approval is checked
	endpointTimer func(time.Duration, func()) endpointTimer
	// enforcementTimer starts the enforcement pacing's timer; tests
	// replace it as they do endpointTimer.
	enforcementTimer func(time.Duration, func()) endpointTimer
	// routeOfferTimer starts the route offer pacing's timer.
	routeOfferTimer func(time.Duration, func()) endpointTimer
	// routeHealthTimer starts the route health pacing's timer.
	routeHealthTimer func(time.Duration, func()) endpointTimer
	// routeSelectionTimer starts the route selection pacing's timer.
	routeSelectionTimer func(time.Duration, func()) endpointTimer
	// gatewayClaimWait bounds how long a gateway's rotation waits for its
	// stream to claim the presence; gatewayCheckTimeout bounds asking Redis.
	gatewayClaimWait    time.Duration
	gatewayCheckTimeout time.Duration
}

// NewApplication validates its dependencies.
func NewApplication(options ApplicationOptions) (*Application, error) {
	if options.Streams == nil || options.Endpoints == nil || options.Snapshots == nil ||
		len(options.ControlKeys) == 0 || options.Logger == nil ||
		(options.Registrations != nil) != (options.RegistrationIDs != nil) ||
		(options.BrowserIssuer != nil) != (options.BrowserApproval != nil) ||
		(options.ClusterJoins != nil) != (options.ClusterJoinSecrets != nil) {
		return nil, ErrInvalidServer
	}
	if options.BrowserIssuer != nil && (options.ApprovalOrigin == "" || options.ApprovalTTL <= 0 ||
		options.ApprovalTTL > maxApprovalTTL) {
		return nil, ErrInvalidServer
	}
	if !validDeniedEndpointPrefixes(options.DeniedEndpointPrefixes) {
		return nil, ErrInvalidServer
	}
	options.DeniedEndpointPrefixes = slices.Clone(options.DeniedEndpointPrefixes)
	if options.DNSSuffix == (dnsname.Suffix{}) {
		options.DNSSuffix = dnsname.Default()
	}
	if !options.DNSSuffix.IsValid() {
		return nil, ErrInvalidServer
	}
	return &Application{options: options, now: time.Now, poll: approvalPollInterval,
		endpointTimer: realEndpointTimer, enforcementTimer: realEndpointTimer, routeOfferTimer: realEndpointTimer,
		routeHealthTimer: realEndpointTimer, routeSelectionTimer: realEndpointTimer,
		gatewayClaimWait: gatewayClaimWait, gatewayCheckTimeout: gatewayCheckTimeout}, nil
}

// Open implements SessionHandler.
func (application *Application) Open(session *Session) Conversation {
	sink := newMapSink(session, session.Supports("device-alias.v1"), application.options.ControlKeys,
		application.now)
	sink.deniedEndpoints = application.options.DeniedEndpointPrefixes
	sink.suffix = application.options.DNSSuffix
	sink.infrastructure = application.options.DNSInfrastructureNames
	sink.logger, sink.metrics = application.options.Logger, application.options.Metrics
	proven, _ := session.ProvenNodeKey()
	return &conversation{application: application, session: session, sink: sink, provenNodeKey: proven,
		wake: make(chan struct{}, 1), approvals: make(chan approval, 1), claimed: make(chan struct{}),
		identity: newRateBudget(identityBurst, identityRate), browser: newRateBudget(browserBurst, browserRate),
		resync:            newRateBudget(resyncBurst, resyncRate),
		enforcementPacing: enforcementPacing{budget: newRateBudget(enforcementBurst, enforcementRate)},
		routeOfferPacing:  routeOfferPacing{budget: newRateBudget(routeOfferBurst, routeOfferRate)},
		routeHealthPacing: routeHealthPacing{budget: newRateBudget(routeHealthBurst, routeHealthRate)},
		routeSelectionPacing: latestPacing[routeSelectionReport]{
			budget: newRateBudget(routeSelectionBurst, routeSelectionRate),
		}}
}

type conversation struct {
	application *Application
	session     *Session
	sink        *mapSink

	// endpointPacing keeps and paces this session's endpoint reports.
	endpointPacing endpointPacing
	lastPaths      time.Time   // when the last PathStatsReport was stored
	lastCaptive    time.Time   // when the last CaptiveWindowReport was taken
	lastDNSHealth  time.Time   // when the last DnsHealthReport was taken
	dnsRoot        atomic.Bool // the session gets the root zone (Request.DNSRoot)
	// identity, browser and resync are the session's budgets for
	// RegisterRequest and RotateNodeKey, browser approval URLs and
	// MapResync (rate_budget.go); Receive is serial, so they need no lock.
	identity rateBudget
	browser  rateBudget
	resync   rateBudget
	// enforcementPacing paces EnforcementReports.
	enforcementPacing enforcementPacing
	// routeOfferPacing paces the offers of HostinfoReports.
	routeOfferPacing routeOfferPacing
	// routeHealthPacing paces RouteHealthReports.
	routeHealthPacing routeHealthPacing
	// routeSelectionPacing paces RouteSelectionReports.
	routeSelectionPacing latestPacing[routeSelectionReport]
	// lastConnectivity is the connectivity last stored for this session.
	// Only a store claimed by endpointPacing reads and writes it, without
	// the lock: busy runs one store at a time, and claiming and finishing
	// under the pacing lock order the stores one after another.
	lastConnectivity *distribution.Connectivity
	// lastConnectivityGeneration is the session generation it was stored for.
	lastConnectivityGeneration int64

	mu         sync.Mutex
	nodeKey    node.Key // the key the map stream serves; zero until known
	hostname   node.Hostname
	disco      node.DiscoveryKey  // proven at registration or rotation in this session
	generation uint64             // advances with every authorization
	restart    context.CancelFunc // ends the running stream when the key changes

	// provenNodeKey is the node key this session proved it holds: by a
	// NodeKeyProof, or in the registration or rotation that authorized it
	// (mtcp-v1 §6.4, §6.7). joinedGateway: the session completed a
	// Kubernetes cluster join, so its Device is a gateway.
	provenNodeKey node.Key
	joinedGateway bool
	// claim is the presence lease the current stream of a Kubernetes
	// gateway holds, set by its Serve before its first snapshot; claimed
	// is closed then. A starting stream clears claim and, once closed,
	// replaces claimed (K1a1 plan §16.12).
	claim      node.PresenceLease
	claimScope network.Scope
	claimed    chan struct{}
	// keepPresence: the session stopped the stream to rotate the gateway's
	// machine key and ends the lease itself once the rotation is decided.
	keepPresence bool

	// kubeCertPending: a certificate request of the session waits on its
	// goroutine (kubeCertWork); a second one is told to retry (a3 §3).
	// The goroutine runs under kubeCertCtx, which Run cancels before it
	// joins the work; kubeCertClosed then refuses new work (review a3b Go
	// H1). kubeCertMu guards the three.
	kubeCertPending atomic.Bool
	kubeCertWork    sync.WaitGroup
	kubeCertMu      sync.Mutex
	kubeCertClosed  bool
	kubeCertCtx     context.Context
	kubeCertCancel  context.CancelFunc

	wake      chan struct{} // the node key changed
	approvals chan approval // the latest pending browser approval

	// The approval watcher runs only once a browser approval is pending:
	// most sessions never have one, and an idle watcher would cost every
	// session a goroutine and a ticker.
	approvalMu      sync.Mutex
	approvalParent  context.Context // Run's context, once Run started
	approvalPending bool            // an approval arrived before Run started
	approvalCancel  context.CancelFunc
	approvalDone    chan struct{}
	approvalStopped bool
}

// Run serves the map stream of the node key the session currently has: the
// ClientHello's, or the one a registration or rotation authorized. A
// stream that ends because the Device is not authorized leaves the session
// open for a new registration (mtcp-v1 §5, §10).
func (conversation *conversation) Run(ctx context.Context) error {
	if conversation.session.OpenedBy() != sharedmtcp.MessageRegisterRequest {
		if hello := conversation.session.Hello().GetNodeKey(); len(hello) == key.Size {
			conversation.mu.Lock()
			conversation.nodeKey = node.Key(hello)
			conversation.mu.Unlock()
		}
	}
	conversation.watchApprovalsWithin(ctx)
	defer conversation.stopApprovals()
	// A certificate request's wait ends with the conversation: cancelled,
	// then joined, before Run returns.
	defer conversation.closeKubeCerts()
	defer conversation.stopEndpointPacing()
	defer conversation.stopEnforcementPacing()
	defer conversation.stopRouteOfferPacing()
	defer conversation.stopRouteHealthPacing()
	defer conversation.stopRouteSelectionPacing()
	for {
		nodeKey, generation, streamCtx, cancel := conversation.startStream(ctx)
		if nodeKey.IsValid() {
			err := conversation.serve(streamCtx, nodeKey, generation)
			cancel()
			conversation.endClaim()
			if ctx.Err() != nil {
				return nil
			}
			if conversation.currentGeneration() != generation {
				continue // a registration or rotation restarted the stream
			}
			conversation.streamEnded(err)
			if conversation.gatewayPresenceLost(err) {
				return err
			}
			if lifecycle := lifecycleFor(err); lifecycle != nil {
				_ = conversation.session.Send(sharedmtcp.MessageLifecycle, lifecycle)
			}
			if !needsRegistration(err) {
				return err
			}
			conversation.clearKey(nodeKey)
		} else {
			cancel()
		}
		select {
		case <-conversation.wake:
		case <-ctx.Done():
			return nil
		}
	}
}

func (conversation *conversation) startStream(ctx context.Context) (node.Key, uint64, context.Context,
	context.CancelFunc) {
	conversation.mu.Lock()
	defer conversation.mu.Unlock()
	conversation.session.streaming.Store(true)
	streamCtx, cancel := context.WithCancel(ctx)
	conversation.restart = cancel
	conversation.claim = node.PresenceLease{}
	select {
	case <-conversation.claimed:
		conversation.claimed = make(chan struct{})
	default:
	}
	return conversation.nodeKey, conversation.generation, streamCtx, cancel
}

// authenticatedMachine is the session's machine key, with the node key it
// proved when it serves a Kubernetes gateway: stores then mark it for the
// database (schema 226). Other Devices need no mark, and cost no extra
// statement.
func (conversation *conversation) authenticatedMachine() (control.AuthenticatedMachine, error) {
	machine, err := control.NewAuthenticatedMachine(node.MachineKey(conversation.session.Machine()))
	if err != nil {
		return control.AuthenticatedMachine{}, err
	}
	conversation.mu.Lock()
	proven, gateway := conversation.provenNodeKey, conversation.session.IsGateway() || conversation.joinedGateway
	conversation.mu.Unlock()
	if !gateway {
		return machine, nil
	}
	return machine.WithProvenNodeKey(proven).AsKubernetesGateway(), nil
}

// prove records a node key the session proved in a registration or
// rotation; gateway marks a completed cluster join.
func (conversation *conversation) prove(nodeKey node.Key, gateway bool) {
	conversation.mu.Lock()
	defer conversation.mu.Unlock()
	conversation.provenNodeKey = nodeKey
	conversation.joinedGateway = conversation.joinedGateway || gateway
}

// isGateway reports whether the session serves a Kubernetes gateway.
func (conversation *conversation) isGateway() bool {
	conversation.mu.Lock()
	defer conversation.mu.Unlock()
	return conversation.session.IsGateway() || conversation.joinedGateway
}

func (conversation *conversation) currentGeneration() uint64 {
	conversation.mu.Lock()
	defer conversation.mu.Unlock()
	return conversation.generation
}

func (conversation *conversation) serve(ctx context.Context, nodeKey node.Key, generation uint64) error {
	machine, err := conversation.authenticatedMachine()
	if err != nil {
		return err
	}
	request, err := mapsession.NewRequest(nodeKey)
	if err == nil && conversation.session.Supports("device-alias.v1") {
		request, err = request.WithDeviceAliasVersion(1)
	}
	if err != nil {
		return mapsession.ErrUnauthorized
	}
	if conversation.session.Supports("map.large1") {
		request = request.WithLargeMap()
	}
	if conversation.session.Supports("relay.zones2") {
		request = request.WithRelayZones()
	}
	if conversation.session.Supports("routes.subnet.v1") {
		request = request.WithRoutes()
	}
	if conversation.session.Supports("router.subnet.v1") {
		request = request.WithRouter()
	}
	if conversation.session.Supports("routes.exit.v1") {
		request = request.WithExits()
	}
	if conversation.session.Supports("router.exit.v1") {
		request = request.WithExitRouter()
	}
	if conversation.session.Supports("dns.forward1") && conversation.session.Supports("dns.split") {
		request = request.WithDNSForward()
		if conversation.session.Supports("dns.records1") {
			request = request.WithDNSRecords()
		}
		if conversation.session.Supports("dns.root1") {
			request = request.WithDNSRoot()
		}
	}
	// What the session reports on DNS counts only where it gets the root
	// zone (mtcp-v1 §8.4, §8.6).
	conversation.dnsRoot.Store(request.DNSRoot())
	conversation.sink.reportDNS(request.DNSRoot())
	_, gateway := machine.KubernetesGateway()
	if gateway && conversation.session.Supports("gateway.kube.v1") {
		request = request.WithKubernetes()
		conversation.sink.confirmFreshness()
	}
	var sink mapsession.StreamSink = conversation.sink
	if gateway {
		sink = &gatewayStreamSink{mapSink: conversation.sink, conversation: conversation, generation: generation}
	}
	return conversation.application.options.Streams.Serve(ctx, machine, request, sink)
}

func (conversation *conversation) provenDisco() node.DiscoveryKey {
	conversation.mu.Lock()
	defer conversation.mu.Unlock()
	return conversation.disco
}

func (conversation *conversation) currentKey() node.Key {
	conversation.mu.Lock()
	defer conversation.mu.Unlock()
	return conversation.nodeKey
}

func (conversation *conversation) clearKey(nodeKey node.Key) {
	conversation.mu.Lock()
	defer conversation.mu.Unlock()
	if conversation.nodeKey == nodeKey {
		conversation.nodeKey = node.Key{}
	}
}

// authorize switches the session to an authorized node key: the running
// stream ends and the next one starts with RegisterResponse{authorized}.
func (conversation *conversation) authorize(nodeKey node.Key, disco node.DiscoveryKey, hostname node.Hostname,
	announce bool) {
	if announce {
		conversation.sink.announce()
	}
	conversation.mu.Lock()
	conversation.nodeKey, conversation.disco, conversation.hostname = nodeKey, disco, hostname
	conversation.generation++
	if conversation.restart != nil {
		conversation.restart()
	}
	conversation.mu.Unlock()
	select {
	case conversation.wake <- struct{}{}:
	default:
	}
	conversation.forgetRouteOffer()
	if nodeKey.IsValid() {
		// An offer reported before the Device was known is stored now.
		go conversation.flushRouteOffer()
	}
}

// streamEnded counts why a stream ended and warns when Core, not the
// Device, ended it (overload or a failing store), so it is never silent.
// Only the bounded reason is logged: errors may carry identifiers.
func (conversation *conversation) streamEnded(err error) {
	reason := streamEndReason(err)
	conversation.application.options.Metrics.streamEnded(reason)
	switch reason {
	case "unavailable", "discontinuity", "other":
		conversation.application.options.Logger.Warn("map stream ended by control", "reason", reason)
	}
}

// streamEndReason maps a stream end to its bounded metric label.
func streamEndReason(err error) string {
	switch {
	case errors.Is(err, mapsession.ErrSuspended):
		return "suspended"
	case errors.Is(err, mapsession.ErrRevoked):
		return "revoked"
	case errors.Is(err, mapsession.ErrUnauthorized), errors.Is(err, mapsession.ErrAuthorizationExpired):
		return "unauthorized"
	case errors.Is(err, mapsession.ErrPresenceConflict):
		return "presence_conflict"
	case errors.Is(err, mapsession.ErrPresenceChurn):
		return "presence_churn"
	case errors.Is(err, mapsession.ErrStreamWrite):
		return "write_failed"
	case errors.Is(err, mapsession.ErrStreamDiscontinuity):
		return "discontinuity"
	case errors.Is(err, mapsession.ErrStreamUnavailable):
		return "unavailable"
	default:
		return "other"
	}
}

// needsRegistration reports a stream end the node can repair on the same
// session by registering. Revoked keys never come back, so a revoked Device
// cannot.
func needsRegistration(err error) bool {
	if errors.Is(err, mapsession.ErrRevoked) {
		return false
	}
	return errors.Is(err, mapsession.ErrUnauthorized) || errors.Is(err, mapsession.ErrAuthorizationExpired)
}

// presenceChurnWait is the wait for a presence churn refusal that names
// none; Core's window is a minute.
const presenceChurnWait = time.Minute

// lifecycleFor maps how a map stream ended. Core never tells a node to erase
// its keys from an ambiguous cause: only a revocation proven for exactly the
// session's keys (schema 161) ends as REVOKED; any other unauthorized key ends
// as EXPIRED, which asks the node to register again and keeps its keys.
func lifecycleFor(err error) *mtcpv1.Lifecycle {
	switch {
	case errors.Is(err, mapsession.ErrSuspended):
		return nil // the sink already sent SUSPENDED
	case errors.Is(err, mapsession.ErrRevoked):
		return &mtcpv1.Lifecycle{State: mtcpv1.Lifecycle_REVOKED, Reason: "the Device was revoked"}
	case errors.Is(err, mapsession.ErrAuthorizationExpired), errors.Is(err, mapsession.ErrUnauthorized):
		return &mtcpv1.Lifecycle{State: mtcpv1.Lifecycle_EXPIRED, Reason: "the Device is not authorized"}
	case errors.Is(err, mapsession.ErrPresenceConflict):
		return &mtcpv1.Lifecycle{State: mtcpv1.Lifecycle_RECONNECT, Reason: "another session is ending",
			RetryAfterMs: 2000}
	case errors.Is(err, mapsession.ErrPresenceChurn):
		// Two processes share this machine key and keep taking the session
		// from each other; each waits out the window.
		var churn *mapsession.PresenceChurnError
		wait := presenceChurnWait
		if errors.As(err, &churn) {
			wait = churn.RetryAfter
		}
		return &mtcpv1.Lifecycle{State: mtcpv1.Lifecycle_RECONNECT,
			Reason: "this Device's key is in use by another session", RetryAfterMs: retryAfterMS(wait)}
	default:
		return &mtcpv1.Lifecycle{State: mtcpv1.Lifecycle_RECONNECT, Reason: "the map stream ended",
			RetryAfterMs: 1000}
	}
}

// Receive handles what a node sends on the session.
func (conversation *conversation) Receive(ctx context.Context, _ sharedmtcp.MessageType, message proto.Message) error {
	switch m := message.(type) {
	case *mtcpv1.MapAck:
		conversation.sink.ack(m.GetView())
	case *mtcpv1.MapResync:
		// Each one costs a whole map. A node over the limit does not follow
		// the protocol; it reconnects and gets a fresh snapshot then.
		if wait, ok := conversation.resync.spend(conversation.application.now(), 1); !ok {
			conversation.application.options.Metrics.limited(limitResync)
			conversation.session.endOverloaded("too many map resyncs", wait)
			return errSessionLimited
		}
		return conversation.sink.resync(ctx, m.GetView())
	case *mtcpv1.Pong:
		conversation.sink.pong(m.GetNonce())
	case *mtcpv1.EnforcementReport:
		conversation.reportEnforcement(m)
	case *mtcpv1.EndpointReport:
		return conversation.endpoints(m)
	case *mtcpv1.PathStatsReport:
		return conversation.paths(ctx, m)
	case *mtcpv1.HostinfoReport:
		return conversation.hostinfo(m)
	case *mtcpv1.HealthReport:
		// Accepted; nothing reads it yet.
	case *mtcpv1.RouteHealthReport:
		return conversation.routeHealth(m)
	case *mtcpv1.RouteSelectionReport:
		return conversation.routeSelection(m)
	case *mtcpv1.CaptiveWindowReport:
		return conversation.captiveWindows(ctx, m)
	case *mtcpv1.DnsHealthReport:
		return conversation.dnsHealth(ctx, m)
	case *mtcpv1.RegisterRequest:
		if wait, ok := conversation.identity.spend(conversation.application.now(), 1); !ok {
			conversation.application.options.Metrics.limited(limitIdentity)
			return conversation.sendError(mtcpv1.Error_OVERLOADED, "too many registration requests", retryAfterMS(wait))
		}
		return conversation.register(ctx, m)
	case *mtcpv1.RotateNodeKey:
		if wait, ok := conversation.identity.spend(conversation.application.now(), 1); !ok {
			conversation.application.options.Metrics.limited(limitIdentity)
			return conversation.sendError(mtcpv1.Error_OVERLOADED, "too many rotation requests", retryAfterMS(wait))
		}
		return conversation.rotate(ctx, m)
	case *mtcpv1.RotateMachineKey:
		if wait, ok := conversation.identity.spend(conversation.application.now(), 1); !ok {
			conversation.application.options.Metrics.limited(limitIdentity)
			return conversation.sendError(mtcpv1.Error_OVERLOADED, "too many rotation requests", retryAfterMS(wait))
		}
		return conversation.rotateMachineKey(ctx, m)
	case *mtcpv1.Logout:
		return conversation.logout(ctx)
	case *mtcpv1.KubeCertRequest:
		return conversation.kubeCert(ctx, m)
	default:
		return Violation(mtcpv1.Error_INVALID, "unexpected message")
	}
	return nil
}

// enforcement stores evidence the node sent while nodeKey was its key. A
// report kept by the pacing is dropped if the key changed meanwhile: it
// describes the filter of a map the new key never had.
func (conversation *conversation) enforcement(ctx context.Context, report *mtcpv1.EnforcementReport,
	nodeKey node.Key) {
	if !nodeKey.IsValid() || nodeKey != conversation.currentKey() || len(report.GetDigest()) != 32 ||
		report.GetAppliedMs() <= 0 {
		return
	}
	filter, err := mapsession.NewFilterDigest(policydigest.Digest(report.GetDigest()), int(report.GetGrants()))
	if err != nil {
		return
	}
	// A router's route digest (mtcp-v1 §8.4); a malformed one is not
	// stored, the policy digest still is.
	var routes mapsession.RouteDigest
	if len(report.GetRouteDigest()) == 32 {
		routes, _ = mapsession.NewRouteDigest(policydigest.Digest(report.GetRouteDigest()), int(report.GetRouteEntries()))
	}
	machine, err := conversation.authenticatedMachine()
	if err != nil {
		return
	}
	dns, reason := conversation.dnsEvidence(report)
	if err := conversation.application.options.Streams.ReportEnforcement(ctx, machine, mapsession.ClientEnforcement{
		NodeKey: nodeKey, Filter: filter, AppliedAt: time.UnixMilli(report.GetAppliedMs()), Routes: routes,
		DNS: dns, DNSReason: reason,
	}); err != nil {
		conversation.application.options.Logger.DebugContext(ctx, "mtcp enforcement report not stored", "error", err)
	}
}

// maxReportedEndpoints bounds an EndpointReport, and endpointReportInterval
// is the shortest interval between stored reports of a session: a sooner
// one is kept and stored when it ends (mtcp-v1 §8.1).
const (
	maxReportedEndpoints   = 32
	endpointReportInterval = time.Second
)

func (conversation *conversation) endpoints(report *mtcpv1.EndpointReport) error {
	if len(report.GetEndpoints()) > maxReportedEndpoints || len(report.GetDiscoKey()) != 32 {
		return Violation(mtcpv1.Error_INVALID, "invalid endpoint report")
	}
	snapshot, ok := conversation.sink.snapshot()
	if !ok {
		return nil // no map yet; the node reports again within its interval
	}
	disco, err := node.NewDiscoveryKey([32]byte(report.GetDiscoKey()))
	if err != nil {
		return Violation(mtcpv1.Error_INVALID, "invalid disco key")
	}
	if proven := conversation.provenDisco(); proven.IsValid() && proven != disco {
		// mtcp-v1 §8.1: another disco key than the one the node proved.
		return conversation.sendError(mtcpv1.Error_INVALID, "the disco key is not the Device's", 0)
	}
	filter := newEndpointFilter(snapshot.RelayDirectory(), conversation.application.options.DeniedEndpointPrefixes)
	endpoints := make([]node.Endpoint, 0, len(report.GetEndpoints()))
	for _, reported := range report.GetEndpoints() {
		source, known := endpointSource(reported.GetKind())
		if !known {
			continue // unknown kinds are ignored (mtcp-v1 §12)
		}
		address, ok := netip.AddrFromSlice(reported.GetIp())
		if !ok || reported.GetPort() == 0 || reported.GetPort() > 65535 {
			return Violation(mtcpv1.Error_INVALID, "invalid endpoint")
		}
		port := uint16(reported.GetPort()) //nolint:gosec // G115: checked to be 1–65535 above
		endpoint, err := node.NewEndpoint(netip.AddrPortFrom(address.Unmap(), port), source)
		if err != nil || !filter.allows(endpoint.Address().Addr(), snapshot.Addresses()) {
			continue // well formed but not distributed (loopback, overlay, a relay…)
		}
		endpoints = append(endpoints, endpoint)
	}
	set, err := node.NewEndpointSet(disco, endpoints)
	if err != nil {
		return Violation(mtcpv1.Error_INVALID, "invalid endpoint report")
	}
	conversation.report(endpointReport{snapshot: snapshot, set: set, relay: int(report.GetPreferredRelay()),
		report: report})
	return nil
}

func endpointSource(kind mtcpv1.Endpoint_Kind) (node.EndpointSource, bool) {
	switch kind {
	case mtcpv1.Endpoint_HOST:
		return node.EndpointSourceLocal, true
	case mtcpv1.Endpoint_SERVER_REFLEXIVE:
		return node.EndpointSourceSTUN, true
	case mtcpv1.Endpoint_PORT_MAPPED:
		return node.EndpointSourcePortMapped, true
	case mtcpv1.Endpoint_STATIC:
		return node.EndpointSourceConfigured, true
	default:
		return node.EndpointSourceUnknown, false
	}
}
