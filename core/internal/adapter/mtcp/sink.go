package mtcp

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/dnsname"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// ackTimeout bounds how long a full acknowledgement window may stay full
// before the stream ends; the node then reconnects and gets a snapshot.
const ackTimeout = 60 * time.Second

var errAckTimeout = errors.New("mtcp: map acknowledgement window stayed full")

// mapSink delivers map stream frames as MTCP messages (mtcp-v1 §7, §9, §11).
// The stream service calls it serially; MapAck and MapResync arrive from the
// session reader, so every method takes mu.
type mapSink struct {
	session     *Session
	aliases     bool
	controlKeys []*mtcpv1.KeyUpdate_ControlKey
	// deniedEndpoints are the operator's ranges never sent as endpoints.
	deniedEndpoints []netip.Prefix
	// suffix is the deployment's DNS suffix the map names Devices under.
	suffix dnsname.Suffix
	// infrastructure are the deployment's own host names a root zone
	// leaves to the node's network.
	infrastructure []string
	// logger and metrics, when set, report names a map left out.
	logger  *slog.Logger
	metrics *Metrics
	now     func() time.Time

	mu         sync.Mutex
	epoch, seq uint64
	acked      uint64
	ackSignal  chan struct{}
	current    mapsession.Snapshot
	hasCurrent bool
	peerIDs    map[int64]string // numeric ID to device ID of the peers the node holds
	signing    [][]byte         // signing keys last sent in a KeyUpdate
	keysSent   bool
	keyNonce   []byte
	ticket     []byte
	relayMap   []byte
	// dnsDigest identifies the DNS configuration the node holds: with DNS
	// names a map's DNS reaches a megabyte, too much to keep per session.
	dnsDigest [sha256.Size]byte
	// dnsResolvers are the resolvers of the DNS configuration the node
	// holds, the only ones its health reports may name. The map is
	// replaced, never changed, so a reader may keep it outside mu.
	dnsResolvers map[netip.AddrPort]struct{}
	// dnsEvidence is set for a session that reports the DNS it applied
	// (dns.root1); sentDNS is then the DNS digest of the configuration the
	// node holds.
	dnsEvidence bool
	sentDNS     mapsession.DNSDigest
	routes      *mtcpv1.RouteConfig  // the routes the node holds; nil: none
	served      *mtcpv1.ServedRoutes // the Sites the node serves; nil: none
	exits       *mtcpv1.ExitConfig   // the Exit Pools the node holds; nil: none
	exitServed  *mtcpv1.ServedExits  // the Exit Pool the node serves; nil: none
	// kubeClusters is what the node holds of its Kubernetes clusters, for a
	// session that negotiated kube.ca1 (§7.11).
	kubeClusters kubeClusterState
	authorized   bool // a registration awaits its RegisterResponse
	// fresh is set for a Kubernetes gateway's session that negotiated
	// gateway.kube.v1: it is told when its map is current (MapFresh,
	// mtcp-v1 §7.9).
	fresh bool
	// authoritySeq is the seq of the epoch's last snapshot or authority
	// delta, authorityAsOf this host's clock before its authority was read,
	// and authorityFresh whether it may be confirmed: its map carries the
	// peers' Kubernetes access (K1a3 Q8) and only its own Network.
	// freshSent is the authority seq whose acknowledgement was confirmed.
	authoritySeq   uint64
	authorityAsOf  time.Time
	authorityFresh bool
	freshSent      uint64
	// freshPending: a goroutine is about to confirm an acknowledgement.
	freshPending bool
}

func newMapSink(session *Session, aliases bool, controlKeys []ControlKey, now func() time.Time) *mapSink {
	keys := make([]*mtcpv1.KeyUpdate_ControlKey, 0, len(controlKeys))
	for _, controlKey := range controlKeys {
		public := controlKey.Private.Public()
		keys = append(keys, &mtcpv1.KeyUpdate_ControlKey{Key: public[:], NotAfterMs: controlKey.NotAfter.UnixMilli()})
	}
	return &mapSink{session: session, aliases: aliases, controlKeys: keys, now: now, suffix: dnsname.Default(),
		ackSignal: make(chan struct{}, 1), peerIDs: make(map[int64]string)}
}

var _ mapsession.StreamSink = (*mapSink)(nil)

// SendSnapshot replaces the node's state with a new epoch.
func (sink *mapSink) SendSnapshot(ctx context.Context, snapshot mapsession.Snapshot) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.sendSnapshotLocked(ctx, snapshot)
}

func (sink *mapSink) sendSnapshotLocked(_ context.Context, snapshot mapsession.Snapshot) error {
	grant, err := splitGrant(snapshot.RelayGrant())
	if err != nil {
		return err
	}
	if sink.authorized {
		if err := sink.session.Send(sharedmtcp.MessageRegisterResponse, authorizedResponse(snapshot)); err != nil {
			return err
		}
		sink.authorized = false
	}
	if err := sink.sendKeysLocked(grant); err != nil {
		return err
	}
	epoch := max(sink.epoch+1, uint64(sink.now().UnixMilli()))
	names, err := sink.names(snapshot)
	if err != nil {
		return err
	}
	message, err := encodeNamedSnapshot(snapshot, &mtcpv1.View{Epoch: epoch, Seq: 1}, sink.aliases,
		sink.deniedEndpoints, names)
	if err != nil {
		return err
	}
	message.Dns = withInfrastructure(message.Dns, sink.infrastructure)
	kubeClusters, kubeCounts := sink.kubeClusters, kubeClusterCounts{}
	if sink.session.Supports(CapabilityKubeCA) {
		message.KubernetesClusters, kubeClusters, kubeCounts = sink.kubeClusters.encodeKubernetesClusters(snapshot,
			sink.suffix, true)
	}
	if err := sink.session.Send(sharedmtcp.MessageMapSnapshot, message); err != nil {
		return err
	}
	sink.kubeClusters = kubeClusters
	sink.metrics.kubernetesClustersSent(kubeCounts)
	if sink.dnsDigest, err = dnsDigest(message.GetDns()); err != nil {
		return err
	}
	sink.adoptDNSLocked(message.GetDns())
	if !proto.Equal(sink.routes, message.GetRoutes()) || !proto.Equal(sink.served, message.GetServed()) {
		sink.metrics.routesSent(message.GetRoutes(), snapshot.Routes().Omitted())
	}
	sink.routes, sink.served = message.GetRoutes(), message.GetServed()
	if !proto.Equal(sink.exitServed, message.GetServedExits()) {
		sink.metrics.servedExitsSent(snapshot.Routes().DNSRelayTargetsDropped())
	}
	sink.exits, sink.exitServed = message.GetExits(), message.GetServedExits()
	// A map was authorized for this session: it serves a Device now.
	sink.session.proveDevice()
	sink.epoch, sink.seq, sink.acked = epoch, 1, 0
	sink.freshSent = 0
	sink.adoptLocked(snapshot, grant)
	sink.noteAuthorityLocked(snapshot)
	return sink.sendTicketLocked(grant)
}

// noteAuthorityLocked records that the message just sent, at seq, carries
// snapshot's authority.
func (sink *mapSink) noteAuthorityLocked(snapshot mapsession.Snapshot) {
	sink.authoritySeq, sink.authorityAsOf = sink.seq, snapshot.ReadAtLocal()
	sink.authorityFresh = snapshot.Kubernetes().Computed() && len(snapshot.SharingScopes()) == 0
}

// ConfirmFresh implements mapsession.FreshMapSink: a gateway that
// acknowledged current's authority hears that it still stood at asOf.
func (sink *mapSink) ConfirmFresh(_ context.Context, current mapsession.Snapshot, asOf time.Time) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if !sink.confirmableLocked() || sink.current.NetworkRevision() != current.NetworkRevision() {
		return nil
	}
	return sink.sendFreshLocked(asOf)
}

// confirmableLocked reports whether the node holds and acknowledged an
// authority a MapFresh may confirm.
func (sink *mapSink) confirmableLocked() bool {
	return sink.fresh && sink.hasCurrent && sink.authorityFresh && sink.acked >= sink.authoritySeq
}

// sendFreshLocked confirms the epoch's last authority as of asOf.
func (sink *mapSink) sendFreshLocked(asOf time.Time) error {
	if err := sink.session.Send(sharedmtcp.MessageMapFresh, &mtcpv1.MapFresh{
		View:             &mtcpv1.View{Epoch: sink.epoch, Seq: sink.authoritySeq},
		NetworkRevisions: networkRevisions(sink.current), AsOfMs: asOf.UnixMilli(),
		AgeMs: max(sink.now().Sub(asOf).Milliseconds(), 0),
	}); err != nil {
		return err
	}
	sink.freshSent = sink.authoritySeq
	return nil
}

// confirmFreshness makes the sink tell a Kubernetes gateway when its map is
// current (mtcp-v1 §7.9).
func (sink *mapSink) confirmFreshness() {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.fresh = true
}

// announce makes the next snapshot start with RegisterResponse{authorized}:
// the first map of a new registration carries the facts the response
// reports (mtcp-v1 §6.2).
func (sink *mapSink) announce() {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.authorized = true
}

func authorizedResponse(snapshot mapsession.Snapshot) *mtcpv1.RegisterResponse {
	authorized := &mtcpv1.RegisterResponse_Authorized{
		DeviceId: snapshot.NodeID().String(), NetworkId: snapshot.Scope().NetworkID().String(),
	}
	for _, prefix := range snapshot.Addresses() {
		authorized.Addresses = append(authorized.Addresses, prefix.Addr().AsSlice())
	}
	if expiry := snapshot.KeyExpiry(); !expiry.IsZero() {
		authorized.KeyExpiryMs = expiry.UnixMilli()
	}
	return &mtcpv1.RegisterResponse{Outcome: &mtcpv1.RegisterResponse_Authorized_{Authorized: authorized}}
}

// SendAuthorityDelta sends the change to the next Network revision.
func (sink *mapSink) SendAuthorityDelta(ctx context.Context, delta mapsession.AuthorityDelta) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	snapshot := delta.Snapshot()
	removed := make([]string, 0, len(delta.RemovedPeerNumericIDs()))
	for _, numericID := range delta.RemovedPeerNumericIDs() {
		deviceID, known := sink.peerIDs[numericID]
		if !known {
			return sink.sendSnapshotLocked(ctx, snapshot) // the node's state is not what we think
		}
		removed = append(removed, deviceID)
	}
	names, err := sink.names(snapshot)
	if err != nil {
		return err
	}
	message, grant, err := sink.deltaLocked(snapshot, delta.SelfChanged(), delta.ChangedPeers(), names)
	if err != nil {
		return err
	}
	message.PeersRemove = removed
	if message.PacketFilter, err = encodePacketFilter(snapshot); err != nil {
		return err
	}
	// DNS is sent only when it changed; an absent one means "unchanged".
	dns := withInfrastructure(encodeDeviceDNS(snapshot, names), sink.infrastructure)
	digest, err := dnsDigest(dns)
	if err != nil {
		return err
	}
	if digest != sink.dnsDigest {
		message.Dns = dns
	}
	// So are routes; a present, empty message clears them (mtcp-v1 §7.6).
	filter := newEndpointFilter(snapshot.RelayDirectory(), sink.deniedEndpoints)
	routes, served := encodeRoutes(snapshot.Routes(), filter), encodeServed(snapshot.Routes(), filter)
	if !proto.Equal(routes, sink.routes) {
		message.Routes = cmp.Or(routes, &mtcpv1.RouteConfig{})
	}
	if !proto.Equal(served, sink.served) {
		message.Served = cmp.Or(served, &mtcpv1.ServedRoutes{})
	}
	// Exit Pools likewise (mtcp-v1 §7.7).
	exits := encodeExits(snapshot)
	exitServed, err := encodeServedExits(snapshot)
	if err != nil {
		return err
	}
	if !proto.Equal(exits, sink.exits) {
		message.Exits = cmp.Or(exits, &mtcpv1.ExitConfig{})
	}
	if !proto.Equal(exitServed, sink.exitServed) {
		message.ServedExits = cmp.Or(exitServed, &mtcpv1.ServedExits{})
	}
	// Kubernetes clusters when they changed (§7.11); a delta without a
	// current map goes as a snapshot, which encodes them itself.
	kubeClusters, kubeCounts := sink.kubeClusters, kubeClusterCounts{}
	if sink.hasCurrent && sink.session.Supports(CapabilityKubeCA) {
		message.KubernetesClusters, kubeClusters, kubeCounts = sink.kubeClusters.encodeKubernetesClusters(snapshot,
			sink.suffix, false)
	}
	sent := sink.hasCurrent
	if err := sink.sendDeltaLocked(ctx, message, snapshot, grant); err != nil {
		return err
	}
	if sent {
		sink.kubeClusters = kubeClusters
		sink.metrics.kubernetesClustersSent(kubeCounts)
	}
	sink.noteAuthorityLocked(snapshot)
	if message.Dns != nil {
		sink.dnsDigest = digest
		sink.adoptDNSLocked(message.Dns)
	}
	if message.Routes != nil {
		sink.routes = routes
		sink.metrics.routesSent(routes, snapshot.Routes().Omitted())
	}
	if message.Served != nil {
		sink.served = served
	}
	if message.Exits != nil {
		sink.exits = exits
	}
	if message.ServedExits != nil {
		sink.exitServed = exitServed
		sink.metrics.servedExitsSent(snapshot.Routes().DNSRelayTargetsDropped())
	}
	return nil
}

// SendConnectivityDelta sends changed endpoints and presence as full peer
// replacements, so withdrawn endpoints cannot linger.
func (sink *mapSink) SendConnectivityDelta(ctx context.Context, delta mapsession.ConnectivityDelta) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	names, err := sink.peerNames(delta.Snapshot())
	if err != nil {
		return err
	}
	message, grant, err := sink.deltaLocked(delta.Snapshot(), delta.SelfChanged(), delta.ChangedPeers(), names)
	if err != nil {
		return err
	}
	return sink.sendDeltaLocked(ctx, message, delta.Snapshot(), grant)
}

func (sink *mapSink) deltaLocked(snapshot mapsession.Snapshot, selfChanged bool,
	changed []mapsession.PeerCandidate, names mapsession.DNSView) (*mtcpv1.MapDelta, grantParts, error) {
	grant, err := splitGrant(snapshot.RelayGrant())
	if err != nil {
		return nil, grantParts{}, err
	}
	message := &mtcpv1.MapDelta{NetworkRevisions: networkRevisions(snapshot)}
	filter := newEndpointFilter(snapshot.RelayDirectory(), sink.deniedEndpoints)
	if selfChanged {
		if message.Self, err = encodeSelf(snapshot, filter, names); err != nil {
			return nil, grantParts{}, err
		}
	}
	if message.PeersUpsert, err = encodePeers(snapshot, changed, sink.aliases, filter, names); err != nil {
		return nil, grantParts{}, err
	}
	if !bytes.Equal(grant.relayMap, sink.relayMap) {
		message.RelayMap = grant.relayMap
	}
	return message, grant, nil
}

func (sink *mapSink) sendDeltaLocked(ctx context.Context, message *mtcpv1.MapDelta, snapshot mapsession.Snapshot,
	grant grantParts) error {
	if !sink.hasCurrent {
		return sink.sendSnapshotLocked(ctx, snapshot)
	}
	if err := sink.sendKeysLocked(grant); err != nil {
		return err
	}
	if err := sink.waitWindowLocked(ctx); err != nil {
		return err
	}
	message.View = &mtcpv1.View{Epoch: sink.epoch, Seq: sink.seq + 1}
	if err := sink.session.Send(sharedmtcp.MessageMapDelta, message); err != nil {
		return err
	}
	sink.seq++
	sink.adoptLocked(snapshot, grant)
	return sink.sendTicketLocked(grant)
}

// SendAuthorityPause tells a suspended node to remove peers and keep its
// keys; the session then ends and the node retries (mtcp-v1 §10).
func (sink *mapSink) SendAuthorityPause(context.Context, mapsession.Snapshot) error {
	sink.revokeFreshness()
	return sink.session.Send(sharedmtcp.MessageLifecycle, &mtcpv1.Lifecycle{
		State: mtcpv1.Lifecycle_SUSPENDED, Reason: "the Device is suspended", RetryAfterMs: 3000,
	})
}

// SendAuthorityWithdrawal sends nothing: the stream returns the cause next,
// and the conversation turns it into the matching Lifecycle.
func (sink *mapSink) SendAuthorityWithdrawal(context.Context, mapsession.Snapshot) error {
	sink.revokeFreshness()
	return nil
}

// revokeFreshness stops confirming the map: its authority was paused or
// withdrawn.
func (sink *mapSink) revokeFreshness() {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.authorityFresh = false
}

// SendRelayGrant delivers a renewed grant: keys, relay map and ticket.
func (sink *mapSink) SendRelayGrant(ctx context.Context, snapshot mapsession.Snapshot) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	grant, err := splitGrant(snapshot.RelayGrant())
	if err != nil {
		return err
	}
	if !bytes.Equal(grant.relayMap, sink.relayMap) && sink.hasCurrent {
		return sink.sendDeltaLocked(ctx, &mtcpv1.MapDelta{RelayMap: grant.relayMap,
			NetworkRevisions: networkRevisions(snapshot)}, snapshot, grant)
	}
	if err := sink.sendKeysLocked(grant); err != nil {
		return err
	}
	return sink.sendTicketLocked(grant)
}

// SendKeepAlive sends a Ping.
func (sink *mapSink) SendKeepAlive(context.Context) error {
	return sink.session.Send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
}

var _ mapsession.DNSDigestSink = (*mapSink)(nil)

// reportDNS records whether the session reports the DNS it applied.
func (sink *mapSink) reportDNS(on bool) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.dnsEvidence = on
}

// SentDNSDigest returns the DNS digest of the configuration the node holds,
// for a session that reports the DNS it applied; the zero value otherwise.
func (sink *mapSink) SentDNSDigest() mapsession.DNSDigest {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.sentDNS
}

// adoptDNSLocked records the DNS configuration just sent: its resolvers, and
// its DNS digest when the session reports what it applied. A digest that
// cannot be computed is counted and left zero: the Device then shows no DNS
// comparison rather than losing its map.
func (sink *mapSink) adoptDNSLocked(config *mtcpv1.DnsConfig) {
	sink.dnsResolvers = resolversOf(config)
	sink.sentDNS = mapsession.DNSDigest{}
	if !sink.dnsEvidence {
		return
	}
	digest, err := digestDNSConfig(config)
	if err != nil {
		sink.metrics.namesDegraded(namesDNSDigestFailed, 1)
		return
	}
	sink.sentDNS = digest.WithZones(suffixesOf(config))
}

// sentResolvers returns the resolvers of the DNS configuration the node
// holds, and whether it holds a map.
func (sink *mapSink) sentResolvers() (map[netip.AddrPort]struct{}, bool) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.dnsResolvers, sink.hasCurrent
}

// dnsDigest hashes a DNS configuration's deterministic encoding.
func dnsDigest(config *mtcpv1.DnsConfig) ([sha256.Size]byte, error) {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(config)
	if err != nil {
		return [sha256.Size]byte{}, errors.Join(ErrMapEncoding, err)
	}
	return sha256.Sum256(encoded), nil
}

// peerNames computes the names a connectivity delta gives peers: without
// the names an administrator set, which only the DNS configuration carries.
func (sink *mapSink) peerNames(snapshot mapsession.Snapshot) (mapsession.DNSView, error) {
	names, err := snapshot.DNSPeerNames(sink.suffix)
	if err != nil {
		return mapsession.DNSView{}, errors.Join(ErrMapEncoding, err)
	}
	return names, nil
}

// names computes the map's names and reports any it left out.
func (sink *mapSink) names(snapshot mapsession.Snapshot) (mapsession.DNSView, error) {
	names, err := dnsView(snapshot, sink.suffix)
	if err != nil {
		return mapsession.DNSView{}, err
	}
	if names.Unnamed() > 0 || names.Dropped() > 0 || names.OverBudget() > 0 {
		sink.metrics.namesDegraded(namesUnlabeled, names.Unnamed())
		sink.metrics.namesDegraded(namesDropped, names.Dropped())
		sink.metrics.namesDegraded(namesOverBudget, names.OverBudget())
		if sink.logger != nil {
			sink.logger.Debug("map names degraded", "unlabeled_devices", names.Unnamed(),
				"dropped_records", names.Dropped(), "over_route_budget", names.OverBudget())
		}
	}
	return names, nil
}

func (sink *mapSink) adoptLocked(snapshot mapsession.Snapshot, grant grantParts) {
	sink.current, sink.hasCurrent = snapshot, true
	sink.session.deviceKeyExpiry.Store(snapshot.KeyExpiry().UnixMilli())
	clear(sink.peerIDs)
	for _, peer := range snapshot.AuthorizedPeers() {
		sink.peerIDs[peer.NumericNodeID()] = peer.NodeID().String()
	}
	sink.relayMap = grant.relayMap
}

// sendKeysLocked sends a KeyUpdate before the first map message and whenever
// the signing keys change (mtcp-v1 §11).
func (sink *mapSink) sendKeysLocked(grant grantParts) error {
	signing := make([][]byte, 0, len(grant.signingKeys))
	for _, signingKey := range grant.signingKeys {
		signing = append(signing, signingKey.GetKey())
	}
	if sink.keysSent && equalKeys(signing, sink.signing) {
		return nil
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	if err := sink.session.Send(sharedmtcp.MessageKeyUpdate, &mtcpv1.KeyUpdate{
		ControlKeys: sink.controlKeys, SigningKeys: grant.signingKeys, Nonce: nonce,
	}); err != nil {
		return err
	}
	sink.keysSent, sink.signing, sink.keyNonce = true, signing, nonce
	return nil
}

func (sink *mapSink) sendTicketLocked(grant grantParts) error {
	if grant.ticket == nil || bytes.Equal(grant.ticket.GetTicket(), sink.ticket) {
		return nil
	}
	if err := sink.session.Send(sharedmtcp.MessageRelayTicket, grant.ticket); err != nil {
		return err
	}
	sink.ticket = grant.ticket.GetTicket()
	return nil
}

// waitWindowLocked blocks, releasing mu, while maxUnackedMap messages of the
// current epoch are unacknowledged (mtcp-v1 §7.2).
func (sink *mapSink) waitWindowLocked(ctx context.Context) error {
	deadline := time.NewTimer(ackTimeout)
	defer deadline.Stop()
	for sink.seq-sink.acked >= maxUnackedMap {
		sink.mu.Unlock()
		select {
		case <-sink.ackSignal:
		case <-ctx.Done():
			sink.mu.Lock()
			return ctx.Err()
		case <-deadline.C:
			sink.mu.Lock()
			return errAckTimeout
		}
		sink.mu.Lock()
	}
	return nil
}

// ack records a MapAck of the current epoch.
func (sink *mapSink) ack(view *mtcpv1.View) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if view.GetEpoch() != sink.epoch || view.GetSeq() <= sink.acked || view.GetSeq() > sink.seq {
		return
	}
	sink.acked = view.GetSeq()
	select {
	case sink.ackSignal <- struct{}{}:
	default:
	}
	// A gateway hears at once that the authority it just applied is
	// current as of its read (K1a3 §13.3). The session's reader never
	// writes: another goroutine sends it.
	if sink.confirmableLocked() && sink.freshSent != sink.authoritySeq && !sink.freshPending {
		sink.freshPending = true
		go sink.confirmAcknowledged()
	}
}

// confirmAcknowledged sends the MapFresh an acknowledgement earned, unless
// a newer authority awaits its own meanwhile. A failed send ends the
// session through its writer, which reports it.
func (sink *mapSink) confirmAcknowledged() {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.freshPending = false
	if sink.confirmableLocked() && sink.freshSent != sink.authoritySeq {
		_ = sink.sendFreshLocked(sink.authorityAsOf)
	}
}

// resync answers a MapResync with a fresh snapshot of the current state,
// unless a newer epoch was already sent.
func (sink *mapSink) resync(ctx context.Context, view *mtcpv1.View) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if !sink.hasCurrent || view.GetEpoch() < sink.epoch && view.GetEpoch() != 0 {
		return nil
	}
	return sink.sendSnapshotLocked(ctx, sink.current)
}

// pong reports whether a Pong acknowledges the last KeyUpdate.
func (sink *mapSink) pong(nonce []byte) bool {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return len(nonce) > 0 && bytes.Equal(nonce, sink.keyNonce)
}

// snapshot returns the state the node holds, if any.
func (sink *mapSink) snapshot() (mapsession.Snapshot, bool) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.current, sink.hasCurrent
}

func equalKeys(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}
