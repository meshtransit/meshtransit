package mtcp

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/control/mapsession"
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
	Logout          DeviceLogout
	Paths           PathRecorder
	Connectivity    ConnectivityRecorder
	// ApprovalOrigin is the https origin of approval URLs; ApprovalTTL is
	// how long an approval stays open.
	ApprovalOrigin string
	ApprovalTTL    time.Duration
	// Metrics, when set, counts map stream ends.
	Metrics *Metrics
	// DeniedEndpointPrefixes are ranges, such as Core's own addresses,
	// that are dropped from every endpoint report.
	DeniedEndpointPrefixes []netip.Prefix
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
}

// NewApplication validates its dependencies.
func NewApplication(options ApplicationOptions) (*Application, error) {
	if options.Streams == nil || options.Endpoints == nil || options.Snapshots == nil ||
		len(options.ControlKeys) == 0 || options.Logger == nil ||
		(options.Registrations != nil) != (options.RegistrationIDs != nil) ||
		(options.BrowserIssuer != nil) != (options.BrowserApproval != nil) {
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
	return &Application{options: options, now: time.Now, poll: approvalPollInterval,
		endpointTimer: realEndpointTimer, enforcementTimer: realEndpointTimer}, nil
}

// Open implements SessionHandler.
func (application *Application) Open(session *Session) Conversation {
	sink := newMapSink(session, session.Supports("device-alias.v1"), application.options.ControlKeys,
		application.now)
	sink.deniedEndpoints = application.options.DeniedEndpointPrefixes
	return &conversation{application: application, session: session, sink: sink,
		wake: make(chan struct{}, 1), approvals: make(chan approval, 1),
		identity: newRateBudget(identityBurst, identityRate), browser: newRateBudget(browserBurst, browserRate),
		resync:            newRateBudget(resyncBurst, resyncRate),
		enforcementPacing: enforcementPacing{budget: newRateBudget(enforcementBurst, enforcementRate)}}
}

type conversation struct {
	application *Application
	session     *Session
	sink        *mapSink

	// endpointPacing keeps and paces this session's endpoint reports.
	endpointPacing endpointPacing
	lastPaths      time.Time // when the last PathStatsReport was stored
	// identity, browser and resync are the session's budgets for
	// RegisterRequest and RotateNodeKey, browser approval URLs and
	// MapResync (rate_budget.go); Receive is serial, so they need no lock.
	identity rateBudget
	browser  rateBudget
	resync   rateBudget
	// enforcementPacing paces EnforcementReports.
	enforcementPacing enforcementPacing
	// lastConnectivity is the connectivity last stored for this session.
	// Only a store claimed by endpointPacing reads and writes it, without
	// the lock: busy runs one store at a time, and claiming and finishing
	// under the pacing lock order the stores one after another.
	lastConnectivity *distribution.Connectivity

	mu         sync.Mutex
	nodeKey    node.Key // the key the map stream serves; zero until known
	hostname   node.Hostname
	disco      node.DiscoveryKey  // proven at registration or rotation in this session
	generation uint64             // advances with every authorization
	restart    context.CancelFunc // ends the running stream when the key changes

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
	defer conversation.stopEndpointPacing()
	defer conversation.stopEnforcementPacing()
	for {
		nodeKey, generation, streamCtx, cancel := conversation.startStream(ctx)
		if nodeKey.IsValid() {
			err := conversation.serve(streamCtx, nodeKey)
			cancel()
			if ctx.Err() != nil {
				return nil
			}
			if conversation.currentGeneration() != generation {
				continue // a registration or rotation restarted the stream
			}
			conversation.streamEnded(err)
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
	streamCtx, cancel := context.WithCancel(ctx)
	conversation.restart = cancel
	return conversation.nodeKey, conversation.generation, streamCtx, cancel
}

func (conversation *conversation) currentGeneration() uint64 {
	conversation.mu.Lock()
	defer conversation.mu.Unlock()
	return conversation.generation
}

func (conversation *conversation) serve(ctx context.Context, nodeKey node.Key) error {
	machine, err := control.NewAuthenticatedMachine(node.MachineKey(conversation.session.Machine()))
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
	return conversation.application.options.Streams.Serve(ctx, machine, request, conversation.sink)
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
	case *mtcpv1.HostinfoReport, *mtcpv1.HealthReport:
		// Accepted; nothing reads them yet.
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
	case *mtcpv1.Logout:
		return conversation.logout(ctx)
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
	machine, err := control.NewAuthenticatedMachine(node.MachineKey(conversation.session.Machine()))
	if err != nil {
		return
	}
	if err := conversation.application.options.Streams.ReportEnforcement(ctx, machine, mapsession.ClientEnforcement{
		NodeKey: nodeKey, Filter: filter, AppliedAt: time.UnixMilli(report.GetAppliedMs()),
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
