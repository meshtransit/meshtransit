package mtcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
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
	now         func() time.Time

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
}

func newMapSink(session *Session, aliases bool, controlKeys []ControlKey, now func() time.Time) *mapSink {
	keys := make([]*mtcpv1.KeyUpdate_ControlKey, 0, len(controlKeys))
	for _, controlKey := range controlKeys {
		public := controlKey.Private.Public()
		keys = append(keys, &mtcpv1.KeyUpdate_ControlKey{Key: public[:], NotAfterMs: controlKey.NotAfter.UnixMilli()})
	}
	return &mapSink{session: session, aliases: aliases, controlKeys: keys, now: now,
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
	if err := sink.sendKeysLocked(grant); err != nil {
		return err
	}
	epoch := max(sink.epoch+1, uint64(sink.now().UnixMilli()))
	message, err := encodeSnapshot(snapshot, &mtcpv1.View{Epoch: epoch, Seq: 1}, sink.aliases)
	if err != nil {
		return err
	}
	if err := sink.session.Send(sharedmtcp.MessageMapSnapshot, message); err != nil {
		return err
	}
	sink.epoch, sink.seq, sink.acked = epoch, 1, 0
	sink.adoptLocked(snapshot, grant)
	return sink.sendTicketLocked(grant)
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
	message, grant, err := sink.deltaLocked(snapshot, delta.SelfChanged(), delta.ChangedPeers())
	if err != nil {
		return err
	}
	message.PeersRemove = removed
	if message.PacketFilter, err = encodePacketFilter(snapshot); err != nil {
		return err
	}
	if message.Dns, err = encodeDNS(snapshot); err != nil {
		return err
	}
	return sink.sendDeltaLocked(ctx, message, snapshot, grant)
}

// SendConnectivityDelta sends changed endpoints and presence as full peer
// replacements, so withdrawn endpoints cannot linger.
func (sink *mapSink) SendConnectivityDelta(ctx context.Context, delta mapsession.ConnectivityDelta) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	message, grant, err := sink.deltaLocked(delta.Snapshot(), delta.SelfChanged(), delta.ChangedPeers())
	if err != nil {
		return err
	}
	return sink.sendDeltaLocked(ctx, message, delta.Snapshot(), grant)
}

func (sink *mapSink) deltaLocked(snapshot mapsession.Snapshot, selfChanged bool,
	changed []mapsession.PeerCandidate) (*mtcpv1.MapDelta, grantParts, error) {
	grant, err := splitGrant(snapshot.RelayGrant())
	if err != nil {
		return nil, grantParts{}, err
	}
	message := &mtcpv1.MapDelta{NetworkRevisions: networkRevisions(snapshot)}
	if selfChanged {
		if message.Self, err = encodeSelf(snapshot); err != nil {
			return nil, grantParts{}, err
		}
	}
	if message.PeersUpsert, err = encodePeers(snapshot, changed, sink.aliases); err != nil {
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
	return sink.session.Send(sharedmtcp.MessageLifecycle, &mtcpv1.Lifecycle{
		State: mtcpv1.Lifecycle_SUSPENDED, Reason: "the Device is suspended", RetryAfterMs: 3000,
	})
}

// SendAuthorityWithdrawal sends nothing: the stream returns the cause next,
// and the conversation turns it into the matching Lifecycle.
func (sink *mapSink) SendAuthorityWithdrawal(context.Context, mapsession.Snapshot) error { return nil }

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

func (sink *mapSink) adoptLocked(snapshot mapsession.Snapshot, grant grantParts) {
	sink.current, sink.hasCurrent = snapshot, true
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
