package mtcp

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"time"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
	sharedmtcp "meshtransit.net/shared/mtcp"
	"meshtransit.net/shared/policydigest"
)

// requestCapabilityVersion fills mapsession.Request's legacy compatibility
// field; nothing outside the TS2021 adapter reads it.
const requestCapabilityVersion = 1

// MapStreams runs authorized map streams and stores enforcement evidence
// (mapsession.StreamService).
type MapStreams interface {
	Serve(ctx context.Context, machine control.AuthenticatedMachine, request mapsession.Request,
		sink mapsession.StreamSink) error
	ReportEnforcement(ctx context.Context, machine control.AuthenticatedMachine,
		report mapsession.ClientEnforcement) error
}

// EndpointObserver records a node's endpoints for its live map session
// (mapsession.Service).
type EndpointObserver interface {
	ObserveSessionEndpoints(ctx context.Context, snapshot mapsession.Snapshot, set node.EndpointSet,
		preferredRelay int, hasPreferredRelay bool) error
}

// Application turns established sessions into map streams. Registration
// over MTCP comes in a later step; until then an unregistered node waits.
type Application struct {
	streams     MapStreams
	endpoints   EndpointObserver
	controlKeys []ControlKey
	logger      *slog.Logger
	now         func() time.Time
}

// NewApplication validates its dependencies.
func NewApplication(streams MapStreams, endpoints EndpointObserver, controlKeys []ControlKey,
	logger *slog.Logger) (*Application, error) {
	if streams == nil || endpoints == nil || len(controlKeys) == 0 || logger == nil {
		return nil, ErrInvalidServer
	}
	return &Application{streams: streams, endpoints: endpoints, controlKeys: controlKeys, logger: logger,
		now: time.Now}, nil
}

// Open implements SessionHandler.
func (application *Application) Open(session *Session) Conversation {
	return &conversation{application: application, session: session,
		sink: newMapSink(session, session.Supports("device-alias.v1"), application.controlKeys, application.now)}
}

type conversation struct {
	application *Application
	session     *Session
	sink        *mapSink

	lastEndpoints time.Time // when the last EndpointReport was accepted; Receive is serial
}

// Run serves the map stream of a registered node and maps how it ended to
// a Lifecycle message (mtcp-v1 §10).
func (conversation *conversation) Run(ctx context.Context) error {
	nodeKey := conversation.session.Hello().GetNodeKey()
	if len(nodeKey) == 0 {
		<-ctx.Done() // registration over MTCP is not served yet
		return nil
	}
	machine, err := control.NewAuthenticatedMachine(node.MachineKey(conversation.session.Machine()))
	if err != nil {
		return err
	}
	request, err := mapsession.NewRequest(node.Key(nodeKey), requestCapabilityVersion)
	if err == nil && conversation.session.Supports("device-alias.v1") {
		request, err = request.WithDeviceAliasVersion(1)
	}
	if err != nil {
		return Violation(mtcpv1.Error_INVALID, "invalid node key")
	}
	err = conversation.application.streams.Serve(ctx, machine, request, conversation.sink)
	if ctx.Err() != nil {
		return nil
	}
	lifecycle := lifecycleFor(err)
	if lifecycle != nil {
		_ = conversation.session.Send(sharedmtcp.MessageLifecycle, lifecycle)
	}
	return err
}

// lifecycleFor maps how a map stream ended. Core never tells a node to erase
// its keys from an ambiguous cause: an unauthorized key ends as EXPIRED,
// which asks the node to register again; REVOKED comes with registration.
func lifecycleFor(err error) *mtcpv1.Lifecycle {
	switch {
	case errors.Is(err, mapsession.ErrSuspended):
		return nil // the sink already sent SUSPENDED
	case errors.Is(err, mapsession.ErrAuthorizationExpired), errors.Is(err, mapsession.ErrUnauthorized):
		return &mtcpv1.Lifecycle{State: mtcpv1.Lifecycle_EXPIRED, Reason: "the Device is not authorized"}
	case errors.Is(err, mapsession.ErrPresenceConflict):
		return &mtcpv1.Lifecycle{State: mtcpv1.Lifecycle_RECONNECT, Reason: "another session is ending",
			RetryAfterMs: 2000}
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
		return conversation.sink.resync(ctx, m.GetView())
	case *mtcpv1.Pong:
		conversation.sink.pong(m.GetNonce())
	case *mtcpv1.EnforcementReport:
		conversation.enforcement(ctx, m)
	case *mtcpv1.EndpointReport:
		return conversation.endpoints(ctx, m)
	case *mtcpv1.HostinfoReport, *mtcpv1.HealthReport, *mtcpv1.PathStatsReport:
		// Accepted; Console views for these come later (P4f).
	case *mtcpv1.RegisterRequest, *mtcpv1.RotateNodeKey, *mtcpv1.Logout:
		_ = conversation.session.Send(sharedmtcp.MessageError, &mtcpv1.Error{Code: mtcpv1.Error_UNSUPPORTED,
			Message: "registration over MTCP is not available yet"})
	default:
		return Violation(mtcpv1.Error_INVALID, "unexpected message")
	}
	return nil
}

func (conversation *conversation) enforcement(ctx context.Context, report *mtcpv1.EnforcementReport) {
	nodeKey := conversation.session.Hello().GetNodeKey()
	if len(nodeKey) != 32 || len(report.GetDigest()) != 32 || report.GetAppliedMs() <= 0 {
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
	if err := conversation.application.streams.ReportEnforcement(ctx, machine, mapsession.ClientEnforcement{
		NodeKey: node.Key(nodeKey), Filter: filter, AppliedAt: time.UnixMilli(report.GetAppliedMs()),
	}); err != nil {
		conversation.application.logger.DebugContext(ctx, "mtcp enforcement report not stored", "error", err)
	}
}

// maxReportedEndpoints bounds an EndpointReport, and endpointReportInterval
// is the shortest interval between accepted reports (mtcp-v1 §8.1).
const (
	maxReportedEndpoints   = 32
	endpointReportInterval = time.Second
)

func (conversation *conversation) endpoints(ctx context.Context, report *mtcpv1.EndpointReport) error {
	if len(report.GetEndpoints()) > maxReportedEndpoints || len(report.GetDiscoKey()) != 32 {
		return Violation(mtcpv1.Error_INVALID, "invalid endpoint report")
	}
	snapshot, ok := conversation.sink.snapshot()
	if !ok {
		return nil // no map yet; the node reports again within its interval
	}
	now := conversation.application.now()
	if now.Sub(conversation.lastEndpoints) < endpointReportInterval {
		return nil // faster than allowed: dropped
	}
	disco, err := node.NewDiscoveryKey([32]byte(report.GetDiscoKey()))
	if err != nil {
		return Violation(mtcpv1.Error_INVALID, "invalid disco key")
	}
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
		if err != nil {
			continue // well formed but not distributable (loopback, link-local, multicast…)
		}
		endpoints = append(endpoints, endpoint)
	}
	set, err := node.NewEndpointSet(disco, endpoints)
	if err != nil {
		return Violation(mtcpv1.Error_INVALID, "invalid endpoint report")
	}
	conversation.lastEndpoints = now
	relay := int(report.GetPreferredRelay())
	if err := conversation.application.endpoints.ObserveSessionEndpoints(ctx, snapshot, set, relay, true); err != nil {
		conversation.application.logger.DebugContext(ctx, "mtcp endpoint report not stored", "error", err)
	}
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
