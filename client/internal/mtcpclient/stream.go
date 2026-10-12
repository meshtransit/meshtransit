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
	discoKeyPrefix       = "discokey:"
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
		reports.forward(streamCtx, options.EndpointUpdates, options.EnforcementReports, options.PathStats)
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
	changed     chan struct{}
}

func newReportBox(initial controlplane.EndpointUpdate) *reportBox {
	return &reportBox{endpoints: initial, changed: make(chan struct{}, 1)}
}

func (box *reportBox) forward(ctx context.Context, endpoints <-chan controlplane.EndpointUpdate,
	enforcement <-chan controlplane.EnforcementReport, paths <-chan controlplane.PathStatsReport,
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
			return err
		}
		stream.setConnected(false)
		if mapped && time.Since(started) >= reconnectResetAfter {
			backoff = minReconnectDelay
		}
		delay := max(jittered(backoff), retryAfter)
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
	capabilities := []string{"map.zstd", "relay.mtrp1", "dns.split", "stats.path1", "nat.report1", "map.large1"}
	if stream.options.EnableDeviceAliases {
		capabilities = append(capabilities, "device-alias.v1")
	}
	s, err := c.open(ctx, stream.origin, sessionOptions{
		machine: stream.keys.machine, control: stream.keys.control,
		nodeKey: nodePublic[:], capabilities: capabilities, version: stream.options.Version,
	})
	if err != nil {
		return false, 0, err
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
	run := &sessionRun{stream: stream, s: s, state: newMapState(), controlTime: time.UnixMilli(s.reply.GetServerTimeMs())}
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
}

func (run *sessionRun) loop(ctx context.Context, inbox <-chan incoming) (bool, time.Duration, error) {
	keepalive := time.NewTicker(run.s.keepalive)
	defer keepalive.Stop()
	heartbeat := time.NewTicker(enforcementHeartbeat)
	defer heartbeat.Stop()
	endpointTimer := time.NewTimer(time.Hour)
	endpointTimer.Stop()
	defer endpointTimer.Stop()
	for {
		select {
		case <-ctx.Done():
			return run.mapped, 0, ctx.Err()
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
		case <-keepalive.C:
			if err := run.s.send(sharedmtcp.MessagePing, &mtcpv1.Ping{}); err != nil {
				return run.mapped, 0, errors.Join(errSessionEnded, err)
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
		return 0, run.mapChanged(ctx, m.GetView())
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
		return 0, run.mapChanged(ctx, m.GetView())
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

// mapChanged delivers the view, acknowledges it, and after the first map
// of the session sends the node's reports.
func (run *sessionRun) mapChanged(ctx context.Context, view *mtcpv1.View) error {
	if err := run.send(sharedmtcp.MessageMapAck, &mtcpv1.MapAck{View: view}); err != nil {
		return err
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
		if err := run.send(sharedmtcp.MessageEnforcementReport, report); err != nil {
			return err
		}
		copied := *enforcement
		run.enforced = &copied
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
