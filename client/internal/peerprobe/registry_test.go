package peerprobe

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/shared/disco"
	"meshtransit.net/shared/key"
)

func TestRegistryBridgesAuthenticatedPingAndPong(t *testing.T) {
	t.Parallel()

	local, remote, registry, snapshot, generation := testRegistry(t)
	remoteChannel := testPeerChannel(t, remote, local)
	transaction := testTransaction(generation, snapshot.Peers[0])
	packet, err := registry.SealPing(transaction, 24)
	if err != nil {
		t.Fatalf("SealPing() error = %v", err)
	}
	message, err := remoteChannel.Open(packet)
	if err != nil {
		t.Fatalf("remote Open(ping) error = %v", err)
	}
	ping, ok := message.(disco.Ping)
	if !ok || ping.TxID != disco.TxID(transaction.ID) ||
		ping.Node != testNodeKey(t, snapshot.Self.PublicKey) || ping.Padding != 24 {
		t.Fatalf("remote Open(ping) = %#v", message)
	}

	observedLocal := netip.MustParseAddrPort("198.51.100.15:41641")
	pongPacket, err := remoteChannel.Seal(disco.Pong{
		TxID:     ping.TxID,
		Observed: observedLocal,
	})
	if err != nil {
		t.Fatalf("remote Seal(pong) error = %v", err)
	}
	opened, err := registry.Open(pongPacket, transaction.Endpoint, generation, time.Unix(1_000, 0))
	if err != nil {
		t.Fatalf("Open(pong) error = %v", err)
	}
	pong, ok := opened.(IncomingPong)
	replyValue := pong.AuthenticatedReply()
	if !ok || replyValue.ID != transaction.ID ||
		replyValue.PeerID != transaction.PeerID ||
		replyValue.Generation != generation ||
		replyValue.Source != transaction.Endpoint ||
		replyValue.ObservedLocalEndpoint != observedLocal {
		t.Fatalf("Open(pong) = %#v", opened)
	}

	remotePingID := disco.TxID{12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	remotePingPacket, err := remoteChannel.Seal(disco.Ping{
		TxID: remotePingID,
		Node: testNodeKey(t, snapshot.Peers[0].PublicKey),
	})
	if err != nil {
		t.Fatalf("remote Seal(ping) error = %v", err)
	}
	opened, err = registry.Open(remotePingPacket, transaction.Endpoint, generation, time.Unix(1_000, 0))
	if err != nil {
		t.Fatalf("Open(ping) error = %v", err)
	}
	incomingPing, ok := opened.(IncomingPing)
	if !ok || incomingPing.ID() != pathdiscovery.ProbeID(remotePingID) ||
		incomingPing.PeerID() != transaction.PeerID ||
		incomingPing.Generation() != generation ||
		incomingPing.Source() != transaction.Endpoint {
		t.Fatalf("Open(ping) = %#v", opened)
	}
	replyPacket, err := registry.SealPong(incomingPing)
	if err != nil {
		t.Fatalf("SealPong() error = %v", err)
	}
	message, err = remoteChannel.Open(replyPacket)
	if err != nil {
		t.Fatalf("remote Open(pong) error = %v", err)
	}
	reply, ok := message.(disco.Pong)
	if !ok || reply.TxID != remotePingID || reply.Observed != transaction.Endpoint {
		t.Fatalf("remote Open(pong) = %#v", message)
	}
}

func TestRegistryRejectsUnauthorizedInputs(t *testing.T) {
	t.Parallel()

	local, remote, registry, snapshot, generation := testRegistry(t)
	remoteChannel := testPeerChannel(t, remote, local)
	transaction := testTransaction(generation, snapshot.Peers[0])

	wrongEndpoint := transaction
	wrongEndpoint.Endpoint = netip.MustParseAddrPort("203.0.113.99:41641")
	if _, err := registry.SealPing(wrongEndpoint, 0); !errors.Is(err, ErrInvalidProbe) {
		t.Fatalf("SealPing(wrong endpoint) error = %v, want ErrInvalidProbe", err)
	}
	wrongGeneration := transaction
	wrongGeneration.Generation.MapRevision++
	if _, err := registry.SealPing(wrongGeneration, 0); !errors.Is(err, ErrInvalidGeneration) {
		t.Fatalf("SealPing(wrong generation) error = %v, want ErrInvalidGeneration", err)
	}

	badNodePacket, err := remoteChannel.Seal(disco.Ping{
		TxID: disco.TxID{1},
		Node: testNodeKey(t, testNodeKeyText(0x77)),
	})
	if err != nil {
		t.Fatalf("remote Seal(bad node) error = %v", err)
	}
	if _, err := registry.Open(badNodePacket, transaction.Endpoint, generation, time.Unix(1_000, 0)); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("Open(bad node) error = %v, want ErrInvalidPacket", err)
	}

	validPacket, err := remoteChannel.Seal(disco.Pong{
		TxID:     disco.TxID{1},
		Observed: netip.MustParseAddrPort("198.51.100.20:41641"),
	})
	if err != nil {
		t.Fatalf("remote Seal(valid) error = %v", err)
	}
	tampered := bytes.Clone(validPacket)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := registry.Open(tampered, transaction.Endpoint, generation, time.Unix(1_000, 0)); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("Open(tampered) error = %v, want ErrInvalidPacket", err)
	}

	unknown := testIdentity(t)
	unknownChannel := testPeerChannel(t, unknown, local)
	unknownPacket, err := unknownChannel.Seal(disco.Pong{
		TxID:     disco.TxID{1},
		Observed: netip.MustParseAddrPort("198.51.100.21:41641"),
	})
	if err != nil {
		t.Fatalf("unknown Seal() error = %v", err)
	}
	if _, err := registry.Open(unknownPacket, transaction.Endpoint, generation, time.Unix(1_000, 0)); !errors.Is(err, ErrUnknownPeer) {
		t.Fatalf("Open(unknown) error = %v, want ErrUnknownPeer", err)
	}
}

func TestRegistryReplacementIsAtomic(t *testing.T) {
	t.Parallel()

	_, _, registry, snapshot, generation := testRegistry(t)

	invalid := cloneTestSnapshot(snapshot)
	invalid.Revision++
	duplicate := invalid.Peers[0]
	duplicate.ID++
	duplicate.PublicKey = testNodeKeyText(0x33)
	invalid.Peers = append(invalid.Peers, duplicate)
	invalidGeneration := generation
	invalidGeneration.MapRevision = invalid.Revision
	if _, err := registry.Replace(invalid, invalidGeneration, time.Unix(1_000, 0)); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("Replace(duplicate discovery key) error = %v, want ErrInvalidSnapshot", err)
	}
	if _, err := registry.SealPing(testTransaction(generation, snapshot.Peers[0]), 0); err != nil {
		t.Fatalf("SealPing() after failed replacement error = %v", err)
	}

	newRemote := testIdentity(t)
	replacement := cloneTestSnapshot(snapshot)
	replacement.Revision++
	replacement.Peers[0].ID++
	replacement.Peers[0].PublicKey = testNodeKeyText(0x44)
	newRemotePublic := newRemote.Public()
	replacement.Peers[0].DiscoveryKey = MapDiscoveryKey(newRemotePublic)
	replacement.Peers[0].Endpoints = []netip.AddrPort{
		netip.MustParseAddrPort("203.0.113.44:41641"),
	}
	replacementGeneration := generation
	replacementGeneration.MapRevision = replacement.Revision
	if count, err := registry.Replace(replacement, replacementGeneration, time.Unix(1_000, 0)); err != nil || count != 1 {
		t.Fatalf("Replace(valid) = %d, %v, want 1", count, err)
	}
	if _, err := registry.SealPing(testTransaction(generation, snapshot.Peers[0]), 0); !errors.Is(err, ErrInvalidGeneration) {
		t.Fatalf("SealPing(old generation) error = %v, want ErrInvalidGeneration", err)
	}

	stale := cloneTestSnapshot(snapshot)
	if _, err := registry.Replace(stale, generation, time.Unix(1_000, 0)); !errors.Is(err, ErrInvalidGeneration) {
		t.Fatalf("Replace(stale) error = %v, want ErrInvalidGeneration", err)
	}
	if count := registry.Len(); count != 1 {
		t.Fatalf("Len() after stale replacement = %d, want 1", count)
	}
}

func TestRegistryDeactivateRetainsGenerationFloor(t *testing.T) {
	t.Parallel()

	_, _, registry, snapshot, generation := testRegistry(t)
	if removed := registry.Deactivate(); removed != 1 {
		t.Fatalf("Deactivate() = %d, want 1", removed)
	}
	if count := registry.Len(); count != 0 {
		t.Fatalf("Len() after Deactivate = %d, want 0", count)
	}
	if _, err := registry.SealPing(
		testTransaction(generation, snapshot.Peers[0]),
		0,
	); !errors.Is(err, ErrInactive) {
		t.Fatalf("SealPing() after Deactivate error = %v, want ErrInactive", err)
	}

	stale := cloneTestSnapshot(snapshot)
	stale.Revision--
	staleGeneration := generation
	staleGeneration.MapRevision = stale.Revision
	if _, err := registry.Replace(stale, staleGeneration, time.Unix(1_000, 0)); !errors.Is(err, ErrInvalidGeneration) {
		t.Fatalf("Replace(stale) error = %v, want ErrInvalidGeneration", err)
	}
	if count, err := registry.Replace(snapshot, generation, time.Unix(1_000, 0)); err != nil || count != 1 {
		t.Fatalf("Replace(current) = %d, %v, want 1", count, err)
	}
}

func TestRegistryValidatesSessionAndPeerMap(t *testing.T) {
	t.Parallel()

	_, _, registry, snapshot, generation := testRegistry(t)
	tests := []struct {
		name   string
		mutate func(*networkmap.Snapshot)
	}{
		{
			name: "session discovery key",
			mutate: func(candidate *networkmap.Snapshot) {
				candidate.Self.DiscoveryKey = testDiscoveryKeyText(0x55)
			},
		},
		{
			name: "unauthorized peer",
			mutate: func(candidate *networkmap.Snapshot) {
				candidate.Peers[0].MachineAuthorized = false
			},
		},
		{
			name: "expired peer",
			mutate: func(candidate *networkmap.Snapshot) {
				candidate.Peers[0].Expired = true
			},
		},
		{
			name: "duplicate peer id",
			mutate: func(candidate *networkmap.Snapshot) {
				candidate.Peers[0].ID = candidate.Self.ID
			},
		},
		{
			name: "unsafe endpoint",
			mutate: func(candidate *networkmap.Snapshot) {
				candidate.Peers[0].Endpoints[0] = netip.MustParseAddrPort("127.0.0.1:41641")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneTestSnapshot(snapshot)
			candidate.Revision++
			test.mutate(&candidate)
			candidateGeneration := generation
			candidateGeneration.MapRevision = candidate.Revision
			if _, err := registry.Replace(candidate, candidateGeneration, time.Unix(1_000, 0)); !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("Replace() error = %v, want ErrInvalidSnapshot", err)
			}
		})
	}

	withoutDiscovery := cloneTestSnapshot(snapshot)
	withoutDiscovery.Revision++
	withoutDiscovery.Peers[0].DiscoveryKey = ""
	withoutGeneration := generation
	withoutGeneration.MapRevision = withoutDiscovery.Revision
	if count, err := registry.Replace(withoutDiscovery, withoutGeneration, time.Unix(1_000, 0)); err != nil || count != 0 {
		t.Fatalf("Replace(no peer discovery key) = %d, %v, want 0", count, err)
	}

	registry.Close()
	registry.Close()
	if _, err := registry.Replace(snapshot, generation, time.Unix(1_000, 0)); !errors.Is(err, ErrInactive) {
		t.Fatalf("Replace() after Close error = %v, want ErrInactive", err)
	}
	if _, err := registry.SealPong(IncomingPing{}); !errors.Is(err, ErrInvalidProbe) {
		t.Fatalf("SealPong() after Close error = %v, want ErrInvalidProbe", err)
	}
}

func TestRegistryConcurrentReplacementAndPacketUse(t *testing.T) {
	t.Parallel()

	local, remote, registry, snapshot, generation := testRegistry(t)
	remoteChannel := testPeerChannel(t, remote, local)
	transaction := testTransaction(generation, snapshot.Peers[0])
	pongPacket, err := remoteChannel.Seal(disco.Pong{
		TxID:     disco.TxID(transaction.ID),
		Observed: netip.MustParseAddrPort("198.51.100.30:41641"),
	})
	if err != nil {
		t.Fatalf("remote Seal(pong) error = %v", err)
	}

	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			<-start
			for range 32 {
				if _, err := registry.SealPing(transaction, 0); err != nil &&
					!errors.Is(err, ErrInvalidGeneration) {
					t.Errorf("SealPing() concurrent error = %v", err)

					return
				}
				if _, err := registry.Open(pongPacket, transaction.Endpoint, generation, time.Unix(1_000, 0)); err != nil &&
					!errors.Is(err, ErrInvalidGeneration) {
					t.Errorf("Open() concurrent error = %v", err)

					return
				}
			}
		})
	}
	replacement := cloneTestSnapshot(snapshot)
	replacement.Revision++
	replacementGeneration := generation
	replacementGeneration.MapRevision = replacement.Revision
	close(start)
	count, err := registry.Replace(replacement, replacementGeneration, time.Unix(1_000, 0))
	workers.Wait()
	if err != nil || count != 1 {
		t.Fatalf("Replace() = %d, %v, want 1", count, err)
	}
}

func testRegistry(
	t *testing.T,
) (key.DiscoPrivate, key.DiscoPrivate, *Registry, networkmap.Snapshot, pathdiscovery.ProbeGeneration) {
	t.Helper()

	local := testIdentity(t)
	remote := testIdentity(t)
	localPublic := local.Public()
	remotePublic := remote.Public()
	endpoint := netip.MustParseAddrPort("203.0.113.10:41641")
	snapshot := networkmap.Snapshot{
		Revision: 7,
		Self: networkmap.Node{
			ID:                1,
			PublicKey:         testNodeKeyText(0x11),
			DiscoveryKey:      MapDiscoveryKey(localPublic),
			MachineAuthorized: true,
		},
		Peers: []networkmap.Node{{
			ID:                2,
			PublicKey:         testNodeKeyText(0x22),
			DiscoveryKey:      MapDiscoveryKey(remotePublic),
			Endpoints:         []netip.AddrPort{endpoint},
			MachineAuthorized: true,
		}},
	}
	generation := pathdiscovery.ProbeGeneration{
		Scope:       9,
		MapRevision: snapshot.Revision,
		Socket: pathdiscovery.Socket{
			Port:       41641,
			Generation: 3,
		},
	}
	registry, err := NewRegistry(local)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	if count, err := registry.Replace(snapshot, generation, time.Unix(1_000, 0)); err != nil || count != 1 {
		t.Fatalf("Replace() = %d, %v, want 1", count, err)
	}
	t.Cleanup(registry.Close)

	return local, remote, registry, snapshot, generation
}

func testIdentity(t *testing.T) key.DiscoPrivate {
	t.Helper()

	identity, err := key.NewDiscoPrivate()
	if err != nil {
		t.Fatalf("NewDiscoPrivate() error = %v", err)
	}

	return identity
}

// testWire is the remote side of a disco v2 channel.
type testWire struct{ key *disco.PeerKey }

func (w *testWire) Seal(message disco.Message) ([]byte, error) {
	return w.key.Seal(nil, message, rand.Reader)
}

func (w *testWire) Open(packet []byte) (disco.Message, error) { return w.key.Open(packet) }

func testPeerChannel(
	t *testing.T,
	from key.DiscoPrivate,
	to key.DiscoPrivate,
) *testWire {
	t.Helper()

	peer, err := disco.NewPeerKey(from, to.Public())
	if err != nil {
		t.Fatalf("NewPeerKey() error = %v", err)
	}

	return &testWire{key: peer}
}

func testTransaction(
	generation pathdiscovery.ProbeGeneration,
	peer networkmap.Node,
) pathdiscovery.ProbeTransaction {
	startedAt := time.Unix(1_000, 0)

	return pathdiscovery.ProbeTransaction{
		ID:         pathdiscovery.ProbeID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		PeerID:     peer.ID,
		Generation: generation,
		Endpoint:   peer.Endpoints[0],
		StartedAt:  startedAt,
		Deadline:   startedAt.Add(5 * time.Second),
	}
}

func testNodeKey(t *testing.T, text string) key.NodePublic {
	t.Helper()

	raw, err := parseMapKey(text, mapNodeKeyPrefix)
	if err != nil {
		t.Fatalf("parseMapKey() error = %v", err)
	}

	return key.NodePublic(raw)
}

func testNodeKeyText(value byte) string {
	return "nodekey:" + strings.Repeat(fmtHexByte(value), 32)
}

func testDiscoveryKeyText(value byte) string {
	return "discokey:" + strings.Repeat(fmtHexByte(value), 32)
}

func fmtHexByte(value byte) string {
	const digits = "0123456789abcdef"

	return string([]byte{digits[value>>4], digits[value&0x0f]})
}

func cloneTestSnapshot(snapshot networkmap.Snapshot) networkmap.Snapshot {
	clone := snapshot
	clone.Peers = append([]networkmap.Node{}, snapshot.Peers...)
	for index := range clone.Peers {
		clone.Peers[index].Endpoints = append(
			[]netip.AddrPort{},
			snapshot.Peers[index].Endpoints...,
		)
	}

	return clone
}
