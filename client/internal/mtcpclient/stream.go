package mtcpclient

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

const (
	minReconnectDelay = time.Second
	maxReconnectDelay = 60 * time.Second
	// reconnectResetAfter restarts the backoff after a session that lasted
	// this long with a map (mtcp-v1 §5).
	reconnectResetAfter = 60 * time.Second
	// endpointReportInterval spaces EndpointReports (mtcp-v1 §8.1).
	endpointReportInterval = time.Second
	// enforcementHeartbeat keeps enforcement evidence fresh while nothing
	// changes (mtcp-v1 §8.4).
	enforcementHeartbeat = 5 * time.Minute
	// routeHealthHeartbeat repeats a router's Site health while it serves
	// any (mtcp-v1 §8.3); Core takes a set older than 30 s as unknown.
	routeHealthHeartbeat = 10 * time.Second
	// routeSelectionHeartbeat repeats a consumer's Site routers while it
	// reaches any (mtcp-v1 §8.3); Core takes a set older than 3 minutes as
	// unknown.
	routeSelectionHeartbeat = time.Minute
	discoKeyPrefix          = "discokey:"
)

// errSessionEnded reports a session that ended without a permanent cause;
// the stream reconnects.
var errSessionEnded = errors.New("mtcp: session ended")

// StreamNetmap keeps a map stream for the profile until ctx ends or a
// permanent cause (pinned key changed, Device revoked, expired or
// suspended, invalid map, consumer failure). Every reconnect verifies the
// pinned control key and starts from a fresh snapshot.
func (c *Client) StreamNetmap(ctx context.Context, controlURL string, material controlplane.KeyMaterial,
	options controlplane.NetmapOptions, handler controlplane.NetmapHandler,
) error {
	if handler == nil {
		return errors.New("mtcp: map handler is required")
	}
	keys, err := c.openKeys(material)
	if err != nil {
		return err
	}
	origin, err := c.origin(controlURL)
	if err != nil {
		return err
	}
	disco, err := parseDiscoKey(options.PeerProbePublicKey)
	if err != nil {
		return err
	}
	reports := newReportBox(controlplane.EndpointUpdate{
		Candidates:     options.Candidates,
		PreferredRelay: options.PreferredRelay, HasPreferredRelay: options.HasPreferredRelay,
	})
	streamCtx, cancel := context.WithCancel(ctx)
	var forwarders sync.WaitGroup
	forwarders.Go(func() {
		reports.forward(streamCtx, options.EndpointUpdates, options.EnforcementReports, options.PathStats,
			options.HostOffers, options.RouteHealth, options.ExitHealth, options.RouteSelection, options.ExitSelection)
	})
	defer func() {
		cancel()
		forwarders.Wait()
	}()
	stream := &netmapStream{
		client: c, origin: origin, keys: keys, options: options, handler: handler,
		disco: disco, reports: reports,
	}
	if len(options.NextControlKey) != 0 {
		raw, err := controlplane.ParseControlPublicKey(options.NextControlKey)
		if err != nil {
			return err
		}
		next := key.ControlPublic(raw)
		stream.next = &next
	}
	return stream.run(streamCtx)
}

func parseDiscoKey(text string) (key.DiscoPublic, error) {
	encoded, found := strings.CutPrefix(text, discoKeyPrefix)
	raw, err := hex.DecodeString(encoded)
	if !found || err != nil || len(raw) != key.Size || strings.ToLower(encoded) != encoded {
		return key.DiscoPublic{}, fmt.Errorf("%w: peer probe key is required", controlplane.ErrInvalidMaterial)
	}
	return key.DiscoPublic(raw), nil
}

// reportBox holds the latest endpoint set and enforcement report across
// sessions; changed wakes the session that sends them.
type reportBox struct {
	mu          sync.Mutex
	endpoints   controlplane.EndpointUpdate
	enforcement *controlplane.EnforcementReport
	paths       *controlplane.PathStatsReport // sent once, then cleared
	// advertised is the latest offer; nil until the host's settings are read.
	advertised *controlplane.HostOffer
	// routeHealth is the latest Site health; nil until it is measured.
	routeHealth []controlplane.RouteSiteHealth
	// exitHealth is the latest exit health; nil until it is measured.
	exitHealth *controlplane.RouteExitHealth
	// routeSelection is the latest Site routers; nil until the first map.
	routeSelection []controlplane.RouteSiteSelection
	// exitSelection is the latest exit node used; nil until the first map.
	exitSelection *controlplane.RouteExitSelection
	changed       chan struct{}
}

func newReportBox(initial controlplane.EndpointUpdate) *reportBox {
	return &reportBox{endpoints: initial, changed: make(chan struct{}, 1)}
}

func (box *reportBox) forward(ctx context.Context, endpoints <-chan controlplane.EndpointUpdate,
	enforcement <-chan controlplane.EnforcementReport, paths <-chan controlplane.PathStatsReport,
	advertised <-chan controlplane.HostOffer, routeHealth <-chan []controlplane.RouteSiteHealth,
	exitHealth <-chan controlplane.RouteExitHealth,
	routeSelection <-chan []controlplane.RouteSiteSelection, exitSelection <-chan controlplane.RouteExitSelection,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case update, ok := <-endpoints:
			if !ok {
				endpoints = nil
				continue
			}
			box.mu.Lock()
			box.endpoints = update
			box.mu.Unlock()
		case report, ok := <-enforcement:
			if !ok {
				enforcement = nil
				continue
			}
			box.mu.Lock()
			box.enforcement = &report
			box.mu.Unlock()
		case report, ok := <-paths:
			if !ok {
				paths = nil
				continue
			}
			box.mu.Lock()
			box.paths = &report
			box.mu.Unlock()
		case offer, ok := <-advertised:
			if !ok {
				advertised = nil
				continue
			}
			box.mu.Lock()
			offer.Prefixes = slices.Clone(offer.Prefixes)
			box.advertised = &offer
			box.mu.Unlock()
		case health, ok := <-routeHealth:
			if !ok {
				routeHealth = nil
				continue
			}
			box.mu.Lock()
			box.routeHealth = append([]controlplane.RouteSiteHealth{}, health...)
			box.mu.Unlock()
		case health, ok := <-exitHealth:
			if !ok {
				exitHealth = nil
				continue
			}
			box.mu.Lock()
			box.exitHealth = &health
			box.mu.Unlock()
		case selection, ok := <-routeSelection:
			if !ok {
				routeSelection = nil
				continue
			}
			box.mu.Lock()
			box.routeSelection = append([]controlplane.RouteSiteSelection{}, selection...)
			box.mu.Unlock()
		case selection, ok := <-exitSelection:
			if !ok {
				exitSelection = nil
				continue
			}
			box.mu.Lock()
			box.exitSelection = &selection
			box.mu.Unlock()
		}
		select {
		case box.changed <- struct{}{}:
		default:
		}
	}
}

func (box *reportBox) latest() (controlplane.EndpointUpdate, *controlplane.EnforcementReport) {
	box.mu.Lock()
	defer box.mu.Unlock()
	return box.endpoints, box.enforcement
}

// offer returns the latest offer, nil before the settings were read.
func (box *reportBox) offer() *controlplane.HostOffer {
	box.mu.Lock()
	defer box.mu.Unlock()
	if box.advertised == nil {
		return nil
	}
	offer := *box.advertised
	offer.Prefixes = slices.Clone(offer.Prefixes)
	return &offer
}

// health returns the latest Site health, nil before it was measured.
// exit returns the latest exit health, nil before it was measured.
func (box *reportBox) exit() *controlplane.RouteExitHealth {
	box.mu.Lock()
	defer box.mu.Unlock()
	if box.exitHealth == nil {
		return nil
	}
	health := *box.exitHealth
	return &health
}

func (box *reportBox) health() []controlplane.RouteSiteHealth {
	box.mu.Lock()
	defer box.mu.Unlock()
	return slices.Clone(box.routeHealth)
}

// selection returns the latest Site routers, nil before the first map.
func (box *reportBox) selection() []controlplane.RouteSiteSelection {
	box.mu.Lock()
	defer box.mu.Unlock()
	return slices.Clone(box.routeSelection)
}

// exitChoice returns the latest exit node used, nil before the first map.
func (box *reportBox) exitChoice() *controlplane.RouteExitSelection {
	box.mu.Lock()
	defer box.mu.Unlock()
	if box.exitSelection == nil {
		return nil
	}
	selection := *box.exitSelection
	return &selection
}

// takePaths returns the pending path report, once.
func (box *reportBox) takePaths() *controlplane.PathStatsReport {
	box.mu.Lock()
	defer box.mu.Unlock()
	report := box.paths
	box.paths = nil
	return report
}

type netmapStream struct {
	client   *Client
	origin   *url.URL
	keys     profileKeys
	options  controlplane.NetmapOptions
	handler  controlplane.NetmapHandler
	disco    key.DiscoPublic
	reports  *reportBox
	revision uint64
	last     *networkmap.Snapshot // last delivered, with Revision zeroed
	// next is the staged next control key (mtcp-v1 §11), or nil.
	next *key.ControlPublic
	// connected is whether the current session has a usable map (reported
	// through NetmapOptions.ConnectionChanged).
	connected bool
}

// setConnected reports a change of the control connection.
func (stream *netmapStream) setConnected(connected bool) {
	if stream.connected == connected {
		return
	}
	stream.connected = connected
	if notify := stream.options.ConnectionChanged; notify != nil {
		notify(connected)
	}
}

// run reconnects with jittered exponential backoff until a permanent cause.
func (stream *netmapStream) run(ctx context.Context) error {
	backoff := minReconnectDelay
	for {
		started := time.Now()
		mapped, retryAfter, err := stream.session(ctx)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if permanentStreamError(err) {
			// The daemon decides what follows (a suspended Device waits to
			// be resumed); Core's wait goes with the error.
			return controlplane.WithRetryAfter(err, retryAfter)
		}
		stream.setConnected(false)
		if mapped && time.Since(started) >= reconnectResetAfter {
			backoff = minReconnectDelay
		}
		delay := max(jittered(backoff), min(retryAfter, controlplane.MaxRetryAfter))
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		backoff = min(2*backoff, maxReconnectDelay)
	}
}

func permanentStreamError(err error) bool {
	return errors.Is(err, controlplane.ErrInvalidMaterial) || errors.Is(err, controlplane.ErrInvalidFingerprint) ||
		errors.Is(err, controlplane.ErrControlKeyChanged) || errors.Is(err, controlplane.ErrControlKeyRotated) ||
		errors.Is(err, controlplane.ErrNetmapRejected) ||
		errors.Is(err, controlplane.ErrNetmapInvalid) || errors.Is(err, controlplane.ErrNetmapAuthorityRevoked) ||
		errors.Is(err, controlplane.ErrNetmapAuthorityPaused) || errors.Is(err, controlplane.ErrNetmapConsumer) ||
		errors.Is(err, networkmap.ErrInvalid) || errors.Is(err, errUnknownKey) ||
		// The origin does not serve MTCP: the caller may use another protocol.
		errors.Is(err, ErrUnavailable)
}

func jittered(base time.Duration) time.Duration {
	half := base / 2
	if half <= 0 {
		return base
	}
	random, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(half)))
	if err != nil {
		return half
	}
	return half + time.Duration(random.Int64())
}

// incoming is one message or the end of the session's reader.
type incoming struct {
	message proto.Message
	err     error
}

// session runs one session. It reports whether a map arrived and how long
// Core asked the node to wait before reconnecting.
func (stream *netmapStream) session(ctx context.Context) (bool, time.Duration, error) {
	c := stream.client
	if err := c.checkPinned(ctx, stream.origin, stream.keys.control, stream.options.PinnedFingerprint); err != nil {
		if errors.Is(err, controlplane.ErrControlKeyChanged) && stream.next != nil &&
			c.offersControlKey(ctx, stream.origin, *stream.next) {
			// Offline through the rotation: Core dropped the old key, and
			// the next one was announced over an authenticated session.
			return false, 0, controlplane.ErrControlKeyRotated
		}
		return false, 0, err
	}
	nodePublic := stream.keys.node.Public()
	// map.large1: this client applies maps of up to 10,000 peers, alias
	// peers and policy rules, with two DNS records per shared Device; Core
	// limits a client without it to the earlier bounds (256 peers).
	// relay.zones2: it hands relays MTT2 tickets for more than 31 shares.
	capabilities := []string{
		"map.zstd", "relay.mtrp1", "dns.split", "stats.path1", "nat.report1", "map.large1", "relay.zones2",
	}
	if stream.options.EnableDeviceAliases {
		capabilities = append(capabilities, "device-alias.v1")
	}
	if stream.options.EnableSubnetRoutes {
		capabilities = append(capabilities, "routes.subnet.v1", "routes.selection1")
	}
	if stream.options.EnableSubnetRouter {
		capabilities = append(capabilities, "router.subnet.v1", "router.health1")
	}
	if stream.options.EnableExits {
		capabilities = append(capabilities, "routes.exit.v1")
		if !stream.options.EnableSubnetRoutes {
			capabilities = append(capabilities, "routes.selection1")
		}
	}
	if stream.options.EnableExitNode {
		capabilities = append(capabilities, "router.exit.v1")
		if !stream.options.EnableSubnetRouter {
			capabilities = append(capabilities, "router.health1")
		}
	}
	s, err := c.open(ctx, stream.origin, sessionOptions{
		machine: stream.keys.machine, control: stream.keys.control,
		nodeKey: nodePublic[:], capabilities: capabilities, version: stream.options.Version,
	})
	if err != nil {
		return false, controlplane.RetryAfterOf(err), err
	}
	defer s.close()
	if err := s.send(sharedmtcp.MessagePing, &mtcpv1.Ping{}); err != nil {
		return false, 0, errors.Join(errSessionEnded, err)
	}
	inbox := make(chan incoming, 16)
	stop := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			_, message, err := s.receive()
			select {
			case inbox <- incoming{message: message, err: err}:
			case <-stop:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	defer func() {
		close(stop)
		s.close()
		<-readerDone
	}()
	state := newMapState(stream.options.EnableSubnetRoutes)
	state.takesServed = stream.options.EnableSubnetRouter
	state.takesServedExits = stream.options.EnableExitNode
	state.takesExits = stream.options.EnableExits
	run := &sessionRun{stream: stream, s: s, state: state, controlTime: time.UnixMilli(s.reply.GetServerTimeMs())}
	return run.loop(ctx, inbox)
}

// sessionRun is the state of one session.
type sessionRun struct {
	stream      *netmapStream
	s           *session
	state       *mapState
	controlTime time.Time
	mapped      bool
	resyncing   bool
	lastSent    time.Time // when the last EndpointReport left
	sentReport  bool
	enforced    *controlplane.EnforcementReport
	// offered is the offer sent in this session; nil before the first.
	offered *controlplane.HostOffer
	// healthSent is the Site health sent in this session and healthSentAt
	// when; nil before the first.
	healthSent   []controlplane.RouteSiteHealth
	healthSentAt time.Time
	// exitSent is the exit health sent in this session; nil before.
	exitSent *controlplane.RouteExitHealth
	// selectionSent is the Site routers sent in this session and
	// selectionSentAt when; nil before the first.
	selectionSent   []controlplane.RouteSiteSelection
	selectionSentAt time.Time
	// exitSelectionSent is the exit node sent with them; nil before.
	exitSelectionSent *controlplane.RouteExitSelection
	// unacked counts applied deltas not acknowledged yet, ackView is the
	// latest applied view and ackTimer acknowledges it (mtcp-v1 §7.2).
	unacked  int
	ackView  *mtcpv1.View
	ackTimer *time.Timer
}

// A node acknowledges a snapshot at once, and deltas once ackBatch of them
// are unacknowledged or ackDelay after the first, whichever comes first
// (mtcp-v1 §7.2): fewer acks than one per message, while Core's window of
// 8 never stalls.
const (
	ackBatch = 4
	ackDelay = time.Second
)

func (run *sessionRun) loop(ctx context.Context, inbox <-chan incoming) (bool, time.Duration, error) {
	keepalive := time.NewTicker(run.s.keepalive)
	defer keepalive.Stop()
	heartbeat := time.NewTicker(enforcementHeartbeat)
	defer heartbeat.Stop()
	healthBeat := time.NewTicker(routeHealthHeartbeat)
	defer healthBeat.Stop()
	selectionBeat := time.NewTicker(routeSelectionHeartbeat)
	defer selectionBeat.Stop()
	endpointTimer := time.NewTimer(time.Hour)
	endpointTimer.Stop()
	defer endpointTimer.Stop()
	run.ackTimer = time.NewTimer(time.Hour)
	run.ackTimer.Stop()
	defer run.ackTimer.Stop()
	for {
		// The end of ctx goes first: a stopping router announces it before
		// handling anything else.
		if ctx.Err() != nil {
			return run.stopped(ctx)
		}
		select {
		case <-ctx.Done():
			return run.stopped(ctx)
		case in := <-inbox:
			if in.err != nil {
				return run.mapped, 0, errors.Join(errSessionEnded, in.err)
			}
			retryAfter, err := run.handle(ctx, in.message)
			if err != nil {
				return run.mapped, retryAfter, err
			}
		case <-run.stream.reports.changed:
			if err := run.sendReports(endpointTimer); err != nil {
				return run.mapped, 0, err
			}
		case <-endpointTimer.C:
			if err := run.sendReports(endpointTimer); err != nil {
				return run.mapped, 0, err
			}
		case <-heartbeat.C:
			run.enforced = nil // resend the current evidence
			if err := run.sendReports(endpointTimer); err != nil {
				return run.mapped, 0, err
			}
		case <-healthBeat.C:
			if err := run.sendRouteHealth(); err != nil {
				return run.mapped, 0, err
			}
		case <-selectionBeat.C:
			if err := run.sendRouteSelection(); err != nil {
				return run.mapped, 0, err
			}
		case <-keepalive.C:
			if err := run.s.send(sharedmtcp.MessagePing, &mtcpv1.Ping{}); err != nil {
				return run.mapped, 0, errors.Join(errSessionEnded, err)
			}
		case <-run.ackTimer.C:
			if err := run.acknowledge(); err != nil {
				return run.mapped, 0, err
			}
		}
	}
}

// handle applies one message from Core.
func (run *sessionRun) handle(ctx context.Context, message proto.Message) (time.Duration, error) {
	switch m := message.(type) {
	case *mtcpv1.KeyUpdate:
		return 0, run.keyUpdate(ctx, m)
	case *mtcpv1.MapSnapshot:
		if err := run.state.applySnapshot(m); err != nil {
			return 0, err
		}
		run.resyncing = false
		return 0, run.mapChanged(ctx, m.GetView(), true)
	case *mtcpv1.MapDelta:
		if run.resyncing {
			return 0, nil // waiting for the snapshot that answers the resync
		}
		if err := run.state.applyDelta(m); err != nil {
			if !errors.Is(err, errMapGap) {
				return 0, err
			}
			run.resyncing = true
			view := &mtcpv1.View{Epoch: run.state.epoch, Seq: run.state.seq}
			return 0, run.send(sharedmtcp.MessageMapResync, &mtcpv1.MapResync{View: view})
		}
		return 0, run.mapChanged(ctx, m.GetView(), false)
	case *mtcpv1.RelayTicket:
		if err := run.state.setTicket(m); err != nil {
			return 0, err
		}
		return 0, run.deliver(ctx)
	case *mtcpv1.Lifecycle:
		return lifecycleOutcome(m)
	case *mtcpv1.Error:
		return errorOutcome(m)
	}
	return 0, nil // other messages (Pong, RegisterResponse, Notice) need nothing
}

func (run *sessionRun) keyUpdate(ctx context.Context, update *mtcpv1.KeyUpdate) error {
	listed := false
	var other *key.ControlPublic
	for _, control := range update.GetControlKeys() {
		raw := control.GetKey()
		if string(raw) == string(run.s.control[:]) {
			listed = true
			continue
		}
		if len(raw) == key.Size && other == nil {
			announced := key.ControlPublic(raw)
			other = &announced
		}
	}
	stream := run.stream
	if !listed {
		if stream.next != nil && other != nil && *other == *stream.next {
			return controlplane.ErrControlKeyRotated
		}
		return controlplane.ErrControlKeyChanged
	}
	if !sameControlKey(other, stream.next) && stream.options.ControlKeysChanged != nil {
		var encoded []byte
		if other != nil {
			encoded = controlplane.EncodeControlPublicKey(*other)
		}
		if err := stream.options.ControlKeysChanged(ctx, encoded); err != nil {
			return fmt.Errorf("mtcp: storing the next control key: %w", err)
		}
		stream.next = other
	}
	if err := run.state.setKeys(update); err != nil {
		return err
	}
	if err := run.send(sharedmtcp.MessagePong, &mtcpv1.Pong{Nonce: update.GetNonce()}); err != nil {
		return err
	}
	if run.state.ready {
		return run.deliver(ctx)
	}
	return nil
}

// acknowledge sends a MapAck for the latest applied view, if one is
// unacknowledged.
func (run *sessionRun) acknowledge() error {
	if run.unacked == 0 || run.ackView == nil {
		return nil
	}
	run.ackTimer.Stop()
	run.unacked = 0
	return run.send(sharedmtcp.MessageMapAck, &mtcpv1.MapAck{View: run.ackView})
}

// mapChanged delivers the view, acknowledges it now or soon, and after the
// first map of the session sends the node's reports.
func (run *sessionRun) mapChanged(ctx context.Context, view *mtcpv1.View, snapshot bool) error {
	run.ackView = view
	run.unacked++
	switch {
	case snapshot || run.unacked >= ackBatch:
		if err := run.acknowledge(); err != nil {
			return err
		}
	case run.unacked == 1:
		run.ackTimer.Reset(ackDelay)
	}
	if !run.mapped {
		run.mapped = true
		// The first report follows the first map, even without candidates:
		// Core learns this session's disco key from it, which the self
		// entry and the relay grant need (mtcp-v1 §8.1).
		if err := run.sendReports(nil); err != nil {
			return err
		}
	}
	return run.deliver(ctx)
}

// deliver hands a changed product snapshot to the daemon, once the map's
// self entry carries this session's disco key: until Core has applied the
// first EndpointReport it may name none, or the previous session's.
func (run *sessionRun) deliver(ctx context.Context) error {
	stream := run.stream
	if !bytes.Equal(run.state.self.GetDiscoKey(), stream.disco[:]) {
		return nil
	}
	snapshot, err := run.state.build(snapshotInput{
		revision: stream.revision + 1, controlTime: run.controlTime,
		now: time.Now(),
	})
	if err != nil {
		return err
	}
	compare := snapshot
	compare.Revision = 0
	if stream.last != nil && reflect.DeepEqual(*stream.last, compare) {
		stream.setConnected(true) // usable again, the map already applied
		return nil
	}
	if err := stream.handler(ctx, snapshot); err != nil {
		return fmt.Errorf("%w: %w", controlplane.ErrNetmapConsumer, err)
	}
	stream.revision++
	stream.last = &compare
	stream.setConnected(true)
	return nil
}

// sendReports sends the current endpoint set (at most once per interval)
// and new enforcement evidence, once the session has a map.
func (run *sessionRun) sendReports(timer *time.Timer) error {
	if !run.mapped {
		return nil
	}
	endpoints, enforcement := run.stream.reports.latest()
	if wait := endpointReportInterval - time.Since(run.lastSent); run.sentReport && wait > 0 {
		if timer != nil {
			timer.Reset(wait)
		}
	} else {
		if err := run.send(sharedmtcp.MessageEndpointReport, run.endpointReport(endpoints)); err != nil {
			return err
		}
		run.lastSent, run.sentReport = time.Now(), true
	}
	if enforcement != nil && (run.enforced == nil || *run.enforced != *enforcement) {
		report := &mtcpv1.EnforcementReport{
			View:   &mtcpv1.View{Epoch: run.state.epoch, Seq: run.state.seq},
			Digest: enforcement.Digest[:], Grants: uint32(max(enforcement.Grants, 0)), //nolint:gosec // G115: bounded by the rule limit
			AppliedMs: enforcement.AppliedAt.UnixMilli(),
		}
		if run.stream.options.EnableSubnetRouter {
			// Always 32 bytes, also for an empty set (mtcp-v1 §8.4).
			report.RouteDigest = enforcement.RouteDigest[:]
			report.RouteEntries = uint32(max(enforcement.RouteEntries, 0)) //nolint:gosec // G115: at most 4,096
		}
		if err := run.send(sharedmtcp.MessageEnforcementReport, report); err != nil {
			return err
		}
		copied := *enforcement
		run.enforced = &copied
	}
	if err := run.sendOffer(); err != nil {
		return err
	}
	if err := run.sendRouteHealth(); err != nil {
		return err
	}
	if err := run.sendRouteSelection(); err != nil {
		return err
	}
	if run.supports("stats.path1") {
		if paths := run.stream.reports.takePaths(); paths != nil {
			if err := run.send(sharedmtcp.MessagePathStatsReport, pathStatsMessage(*paths)); err != nil {
				return err
			}
		}
	}
	return nil
}

// sendOffer sends what the host offers (mtcp-v1 §8.2), the subnets it
// forwards to and whether it may be an exit node, once per session and
// whenever it changes, always the whole offer.
func (run *sessionRun) sendOffer() error {
	options := run.stream.options
	if !options.EnableSubnetRouter && !options.EnableExitNode {
		return nil
	}
	offer := run.stream.reports.offer()
	if offer == nil || (run.offered != nil && run.offered.Equal(*offer)) {
		return nil
	}
	hostinfo := &mtcpv1.Hostinfo{
		Hostname: options.Hostname, Os: runtime.GOOS, Arch: runtime.GOARCH,
		ClientVersion: options.Version, ExitOffered: options.EnableExitNode && offer.Exit,
	}
	if options.EnableSubnetRouter {
		for _, prefix := range offer.Prefixes {
			hostinfo.AdvertisedPrefixes = append(hostinfo.AdvertisedPrefixes, sharedmtcp.AppendPrefix(prefix))
		}
	}
	if err := run.send(sharedmtcp.MessageHostinfoReport, &mtcpv1.HostinfoReport{Hostinfo: hostinfo}); err != nil {
		return err
	}
	run.offered = offer
	return nil
}

// sendRouteHealth sends the served Sites' health and the served Exit Pool's
// (mtcp-v1 §8.3) when either changed, and again every routeHealthHeartbeat
// while not empty. A router waits for its Sites to be measured.
func (run *sessionRun) sendRouteHealth() error {
	options := run.stream.options
	takesExit := options.EnableExitNode && run.supports("router.exit.v1")
	if !run.mapped || (!options.EnableSubnetRouter && !takesExit) || !run.supports("router.health1") {
		return nil
	}
	health := run.stream.reports.health()
	if options.EnableSubnetRouter && health == nil {
		return nil
	}
	if !options.EnableSubnetRouter || !run.supports("router.subnet.v1") {
		health = []controlplane.RouteSiteHealth{}
	}
	var exit *controlplane.RouteExitHealth
	if takesExit {
		if exit = run.stream.reports.exit(); exit == nil && !options.EnableSubnetRouter {
			return nil
		}
		if exit != nil && exit.Ref == "" {
			exit = nil
		}
		// An exit node that never served a pool has nothing to withdraw.
		if !options.EnableSubnetRouter && exit == nil && run.exitSent == nil {
			return nil
		}
	}
	changed := run.healthSent == nil || !slices.Equal(run.healthSent, health) || !equalExitHealth(run.exitSent, exit)
	if !changed && ((len(health) == 0 && exit == nil) ||
		time.Since(run.healthSentAt) < routeHealthHeartbeat-time.Second) {
		return nil
	}
	report := &mtcpv1.RouteHealthReport{
		Sites: make([]*mtcpv1.RouteHealthReport_SiteHealth, 0, len(health)),
		Exit:  exitHealthMessage(exit),
	}
	for _, site := range health {
		report.Sites = append(report.Sites, &mtcpv1.RouteHealthReport_SiteHealth{
			SiteRef: site.Ref, State: routeHealthState(site.State), Code: site.Code,
		})
	}
	if err := run.send(sharedmtcp.MessageRouteHealthReport, report); err != nil {
		return err
	}
	run.healthSent, run.healthSentAt, run.exitSent = health, time.Now(), exit
	return nil
}

func equalExitHealth(first, second *controlplane.RouteExitHealth) bool {
	if first == nil || second == nil {
		return first == second
	}
	return *first == *second
}

// exitHealthMessage encodes an exit node's health; nil when it serves none.
func exitHealthMessage(exit *controlplane.RouteExitHealth) *mtcpv1.RouteHealthReport_ExitHealth {
	if exit == nil {
		return nil
	}
	families := mtcpv1.ExitCandidate_FAMILIES_UNSPECIFIED
	switch exit.Families {
	case controlplane.ExitFamiliesV4:
		families = mtcpv1.ExitCandidate_V4
	case controlplane.ExitFamiliesV6:
		families = mtcpv1.ExitCandidate_V6
	case controlplane.ExitFamiliesBoth:
		families = mtcpv1.ExitCandidate_BOTH
	}
	return &mtcpv1.RouteHealthReport_ExitHealth{
		PoolRef: exit.Ref, State: routeHealthState(exit.State),
		Code: exit.Code, Families: families,
	}
}

// sendGoingAway tells Core that this router stops serving every Site it
// served in this session: a last RouteHealthReport with each FAILED as
// going_away (design §6.2), so Core elects another router at once instead of
// waiting for its silence. Not while a restart is expected, and best effort:
// the session ends either way.
func (run *sessionRun) sendGoingAway() {
	options := run.stream.options
	if !run.mapped || (!options.EnableSubnetRouter && !options.EnableExitNode) || !run.supports("router.health1") ||
		(len(run.healthSent) == 0 && run.exitSent == nil) ||
		options.AnnounceGoingAway == nil || !options.AnnounceGoingAway() {
		return
	}
	report := &mtcpv1.RouteHealthReport{Sites: make([]*mtcpv1.RouteHealthReport_SiteHealth, 0, len(run.healthSent))}
	if run.exitSent != nil {
		going := *run.exitSent
		going.State, going.Code = controlplane.RouteHealthFailed, goingAwayCode
		report.Exit = exitHealthMessage(&going)
	}
	for _, site := range run.healthSent {
		report.Sites = append(report.Sites, &mtcpv1.RouteHealthReport_SiteHealth{
			SiteRef: site.Ref, State: mtcpv1.RouteHealthReport_SiteHealth_FAILED, Code: goingAwayCode,
		})
	}
	_ = run.send(sharedmtcp.MessageRouteHealthReport, report)
}

// sendRouteSelection sends the router of each Site (mtcp-v1 §8.3) and the
// exit node used (§7.7) when they changed, and again every
// routeSelectionHeartbeat while not empty.
func (run *sessionRun) sendRouteSelection() error {
	sites := run.stream.options.EnableSubnetRoutes
	exits := run.stream.options.EnableExits && run.supports("routes.exit.v1")
	if !run.mapped || (!sites && !exits) || !run.supports("routes.selection1") {
		return nil
	}
	var selection []controlplane.RouteSiteSelection
	if sites {
		if selection = run.stream.reports.selection(); selection == nil {
			return nil
		}
	}
	var exit *controlplane.RouteExitSelection
	if exits {
		if exit = run.stream.reports.exitChoice(); exit == nil {
			return nil
		}
	}
	unchanged := !run.selectionSentAt.IsZero() && slices.Equal(run.selectionSent, selection) &&
		equalExitSelection(run.exitSelectionSent, exit)
	empty := len(selection) == 0 && (exit == nil || exit.Pool == "")
	if unchanged && (empty || time.Since(run.selectionSentAt) < routeSelectionHeartbeat-time.Second) {
		return nil
	}
	report := &mtcpv1.RouteSelectionReport{
		Sites: make([]*mtcpv1.RouteSelectionReport_SiteSelection, 0, len(selection)),
	}
	for _, site := range selection {
		report.Sites = append(report.Sites, &mtcpv1.RouteSelectionReport_SiteSelection{
			SiteRef: site.Ref, Router: site.Router, Reason: routeSelectionReason(site.Reason),
		})
	}
	if exit != nil && exit.Pool != "" {
		report.Exit = &mtcpv1.RouteSelectionReport_ExitSelection{
			PoolRef: exit.Pool, ExitNode: exit.ExitNode, Reason: exitSelectionReason(exit.Reason),
		}
	}
	if err := run.send(sharedmtcp.MessageRouteSelectionReport, report); err != nil {
		return err
	}
	run.selectionSent, run.selectionSentAt, run.exitSelectionSent = selection, time.Now(), exit
	return nil
}

func equalExitSelection(first, second *controlplane.RouteExitSelection) bool {
	if first == nil || second == nil {
		return first == second
	}
	return *first == *second
}

func exitSelectionReason(reason controlplane.RouteSelectionReason) mtcpv1.RouteSelectionReport_ExitSelection_Reason {
	switch reason {
	case controlplane.RouteSelectionPrimary:
		return mtcpv1.RouteSelectionReport_ExitSelection_PRIMARY
	case controlplane.RouteSelectionLocalFailover:
		return mtcpv1.RouteSelectionReport_ExitSelection_LOCAL_FAILOVER
	case controlplane.RouteSelectionSticky:
		return mtcpv1.RouteSelectionReport_ExitSelection_STICKY
	case controlplane.RouteSelectionNone:
		return mtcpv1.RouteSelectionReport_ExitSelection_NONE
	}
	return mtcpv1.RouteSelectionReport_ExitSelection_REASON_UNSPECIFIED
}

func routeSelectionReason(reason controlplane.RouteSelectionReason) mtcpv1.RouteSelectionReport_SiteSelection_Reason {
	switch reason {
	case controlplane.RouteSelectionPrimary:
		return mtcpv1.RouteSelectionReport_SiteSelection_PRIMARY
	case controlplane.RouteSelectionLocalFailover:
		return mtcpv1.RouteSelectionReport_SiteSelection_LOCAL_FAILOVER
	case controlplane.RouteSelectionNone:
		return mtcpv1.RouteSelectionReport_SiteSelection_NONE
	}
	return mtcpv1.RouteSelectionReport_SiteSelection_REASON_UNSPECIFIED
}

// goingAwayCode is the health code of a router that stops.
const goingAwayCode = "going_away"

// goingAwayWait bounds the last report's write: on a dead connection the
// service must still stop well within its stop timeout. The session's close
// ends a write still running.
const goingAwayWait = 2 * time.Second

// stopped ends the session once ctx ended, first telling Core when the
// service stops.
func (run *sessionRun) stopped(ctx context.Context) (bool, time.Duration, error) {
	if errors.Is(context.Cause(ctx), controlplane.ErrStopping) {
		sent := make(chan struct{})
		go func() {
			defer close(sent)
			run.sendGoingAway()
		}()
		select {
		case <-sent:
		case <-time.After(goingAwayWait):
		}
	}
	return run.mapped, 0, ctx.Err()
}

func routeHealthState(state controlplane.RouteHealthState) mtcpv1.RouteHealthReport_SiteHealth_State {
	switch state {
	case controlplane.RouteHealthOK:
		return mtcpv1.RouteHealthReport_SiteHealth_OK
	case controlplane.RouteHealthDegraded:
		return mtcpv1.RouteHealthReport_SiteHealth_DEGRADED
	case controlplane.RouteHealthFailed:
		return mtcpv1.RouteHealthReport_SiteHealth_FAILED
	}
	return mtcpv1.RouteHealthReport_SiteHealth_STATE_UNSPECIFIED
}

func (run *sessionRun) supports(capability string) bool {
	return slices.Contains(run.s.reply.GetCapabilities(), capability)
}

// pathStatsMessage encodes one interval (mtcp-v1 §8.3).
func pathStatsMessage(report controlplane.PathStatsReport) *mtcpv1.PathStatsReport {
	seconds := min(max(report.Interval/time.Second, 0), 24*60*60)
	message := &mtcpv1.PathStatsReport{
		IntervalStartMs: report.IntervalStart.UnixMilli(),
		IntervalS:       uint32(seconds),
	}
	for _, peer := range report.Peers {
		entry := &mtcpv1.PeerPathStats{
			DeviceId: peer.DeviceID, DirectTxBytes: peer.DirectTxBytes,
			DirectRxBytes: peer.DirectRxBytes, RelayTxBytes: peer.RelayTxBytes, RelayRxBytes: peer.RelayRxBytes,
		}
		switch peer.Path {
		case controlplane.PathDirect:
			entry.Technique = mtcpv1.PeerPathStats_DIRECT
		case controlplane.PathRelay:
			entry.Technique = mtcpv1.PeerPathStats_RELAY
			entry.RelayRegion = uint32(max(peer.RelayRegion, 0)) //nolint:gosec // G115: region IDs are small
			switch peer.RelayReason {
			case controlplane.RelayBootstrap:
				entry.RelayReason = mtcpv1.PeerPathStats_BOOTSTRAP
			case controlplane.RelayNoCandidates:
				entry.RelayReason = mtcpv1.PeerPathStats_NO_CANDIDATES
			case controlplane.RelayNoResponse:
				entry.RelayReason = mtcpv1.PeerPathStats_NO_RESPONSE
			}
		}
		message.Peers = append(message.Peers, entry)
	}
	return message
}

func (run *sessionRun) endpointReport(update controlplane.EndpointUpdate) *mtcpv1.EndpointReport {
	report := &mtcpv1.EndpointReport{DiscoKey: run.stream.disco[:], ObservedMs: time.Now().UnixMilli()}
	if update.HasPreferredRelay && update.PreferredRelay > 0 {
		report.PreferredRelay = uint32(update.PreferredRelay) //nolint:gosec // G115: region IDs are small
	}
	for _, candidate := range update.Candidates.Candidates() {
		kind, ok := endpointKind(candidate.Source())
		if !ok || len(report.Endpoints) == 32 {
			continue
		}
		address := candidate.Endpoint()
		report.Endpoints = append(report.Endpoints, &mtcpv1.Endpoint{
			Ip:   address.Addr().Unmap().AsSlice(),
			Port: uint32(address.Port()), Kind: kind,
		})
	}
	if run.supports("nat.report1") {
		addConnectivity(report, update)
	}
	return report
}

// addConnectivity fills the NAT classification, IPv6 reachability (from the
// whole candidate set, before the endpoint cap) and port mapping state.
func addConnectivity(report *mtcpv1.EndpointReport, update controlplane.EndpointUpdate) {
	connectivity := update.Connectivity
	if connectivity.NATKnown {
		report.Nat = &mtcpv1.NatInfo{
			Mapping: uint32(connectivity.NAT.Mapping), Filtering: uint32(connectivity.NAT.Filtering),
			Allocation: uint32(connectivity.NAT.Allocation), SequentialStep: uint32(connectivity.NATStep),
		}
		if !connectivity.NATObservedAt.IsZero() {
			report.NatObservedMs = connectivity.NATObservedAt.UnixMilli()
		}
	}
	for _, candidate := range update.Candidates.Candidates() {
		address := candidate.Endpoint().Addr()
		if !address.Is6() || address.IsPrivate() {
			continue
		}
		switch candidate.Source() {
		case pathdiscovery.SourceHost, pathdiscovery.SourceConfigured:
			report.Ipv6Global = true
		case pathdiscovery.SourceServerReflexive:
			report.Ipv6Global, report.Ipv6Stun = true, true
		}
	}
	if mapping := connectivity.PortMapping; mapping.State != "" {
		report.PortMapping = &mtcpv1.PortMapping{
			Protocol: portMappingProtocols[mapping.Protocol], State: portMappingStates[mapping.State],
		}
		if !mapping.ExpiresAt.IsZero() {
			report.PortMapping.ExpiresMs = mapping.ExpiresAt.UnixMilli()
		}
	}
}

// Port mapping codes of MTCP PortMapping; anything else is 0 (unknown).
var (
	portMappingProtocols = map[string]uint32{"pcp": 1, "nat-pmp": 2, "upnp": 3}
	portMappingStates    = map[string]uint32{
		"off": 1, "idle": 2, "searching": 2, "mapped": 3, "double_nat": 4, "unavailable": 5, "failed": 6,
	}
)

func endpointKind(source pathdiscovery.Source) (mtcpv1.Endpoint_Kind, bool) {
	switch source {
	case pathdiscovery.SourceHost:
		return mtcpv1.Endpoint_HOST, true
	case pathdiscovery.SourceServerReflexive:
		return mtcpv1.Endpoint_SERVER_REFLEXIVE, true
	case pathdiscovery.SourcePortMapping:
		return mtcpv1.Endpoint_PORT_MAPPED, true
	case pathdiscovery.SourceConfigured:
		return mtcpv1.Endpoint_STATIC, true
	default:
		return mtcpv1.Endpoint_KIND_UNSPECIFIED, false
	}
}

func (run *sessionRun) send(t sharedmtcp.MessageType, message proto.Message) error {
	if err := run.s.send(t, message); err != nil {
		return errors.Join(errSessionEnded, err)
	}
	return nil
}

// lifecycleOutcome maps a Lifecycle (mtcp-v1 §10).
func lifecycleOutcome(lifecycle *mtcpv1.Lifecycle) (time.Duration, error) {
	retry := time.Duration(lifecycle.GetRetryAfterMs()) * time.Millisecond
	switch lifecycle.GetState() {
	case mtcpv1.Lifecycle_SUSPENDED:
		return retry, controlplane.ErrNetmapAuthorityPaused
	case mtcpv1.Lifecycle_EXPIRED:
		return retry, fmt.Errorf("%w: %w", controlplane.ErrNetmapRejected, controlplane.ErrNodeKeyExpired)
	case mtcpv1.Lifecycle_REVOKED, mtcpv1.Lifecycle_LOGGED_OUT:
		return retry, controlplane.ErrNetmapAuthorityRevoked
	case mtcpv1.Lifecycle_RECONNECT:
		return retry, errSessionEnded
	default:
		return 0, nil // ACTIVE and REAUTH_REQUIRED change nothing yet
	}
}

// errorOutcome maps an Error from Core during a map stream.
func errorOutcome(failure *mtcpv1.Error) (time.Duration, error) {
	retry := time.Duration(failure.GetRetryAfterMs()) * time.Millisecond
	switch failure.GetCode() {
	case mtcpv1.Error_INVALID, mtcpv1.Error_UNSUPPORTED:
		if failure.GetFatal() {
			return retry, fmt.Errorf("%w: %s", controlplane.ErrNetmapRejected, boundedText(failure.GetMessage()))
		}
		return 0, nil // a refused report; the stream goes on
	case mtcpv1.Error_NOT_AUTHORIZED, mtcpv1.Error_NOT_PERMITTED:
		if failure.GetFatal() {
			return retry, fmt.Errorf("%w: %s", controlplane.ErrNetmapRejected, boundedText(failure.GetMessage()))
		}
		return 0, nil
	default:
		if failure.GetFatal() {
			return retry, errSessionEnded
		}
		return 0, nil
	}
}

func sameControlKey(left, right *key.ControlPublic) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}
