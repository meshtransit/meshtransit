package pathdiscovery

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestProbeManagerCompletesExactAuthenticatedReply(t *testing.T) {
	t.Parallel()

	manager := testProbeManager(4, 2)
	generation := testProbeGeneration(1)
	if removed, err := manager.Activate(generation); err != nil || removed != 0 {
		t.Fatalf("Activate() = %d, %v", removed, err)
	}
	startedAt := time.Unix(100, 0)
	remote := netip.MustParseAddrPort("203.0.113.10:41641")
	transaction, err := manager.Start(startedAt, 7, remote)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if transaction.ID.IsZero() || transaction.PeerID != 7 ||
		transaction.Generation != generation || transaction.Endpoint != remote ||
		transaction.StartedAt != startedAt ||
		transaction.Deadline != startedAt.Add(defaultProbeLifetime) {
		t.Fatalf("Start() transaction = %#v", transaction)
	}

	observedLocal := netip.MustParseAddrPort("198.51.100.20:41641")
	observation, err := manager.Complete(startedAt.Add(25*time.Millisecond), AuthenticatedProbeReply{
		ID:                    transaction.ID,
		PeerID:                transaction.PeerID,
		Generation:            transaction.Generation,
		Source:                transaction.Endpoint,
		ObservedLocalEndpoint: observedLocal,
	})
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if observation.PeerID != transaction.PeerID ||
		observation.Generation != generation || observation.RemoteEndpoint != remote ||
		observation.ObservedLocalEndpoint != observedLocal ||
		observation.RoundTrip != 25*time.Millisecond ||
		observation.ObservedAt != startedAt.Add(25*time.Millisecond) {
		t.Fatalf("Complete() observation = %#v", observation)
	}
	if _, err := manager.Complete(startedAt.Add(30*time.Millisecond), AuthenticatedProbeReply{
		ID:                    transaction.ID,
		PeerID:                transaction.PeerID,
		Generation:            transaction.Generation,
		Source:                transaction.Endpoint,
		ObservedLocalEndpoint: observedLocal,
	}); !errors.Is(err, ErrPeerProbeNotFound) {
		t.Fatalf("Complete(replay) error = %v, want ErrPeerProbeNotFound", err)
	}
}

func TestProbeManagerConsumesMismatchedAuthenticatedReply(t *testing.T) {
	t.Parallel()

	startedAt := time.Unix(200, 0)
	remote := netip.MustParseAddrPort("203.0.113.20:41641")
	observedLocal := netip.MustParseAddrPort("198.51.100.30:41641")
	tests := []struct {
		name   string
		mutate func(*AuthenticatedProbeReply)
	}{
		{name: "peer", mutate: func(reply *AuthenticatedProbeReply) { reply.PeerID++ }},
		{name: "scope", mutate: func(reply *AuthenticatedProbeReply) { reply.Generation.Scope++ }},
		{name: "map", mutate: func(reply *AuthenticatedProbeReply) { reply.Generation.MapRevision++ }},
		{name: "socket", mutate: func(reply *AuthenticatedProbeReply) { reply.Generation.Socket.Generation++ }},
		{name: "source", mutate: func(reply *AuthenticatedProbeReply) {
			reply.Source = netip.MustParseAddrPort("203.0.113.21:41641")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			manager := testProbeManager(4, 2)
			if _, err := manager.Activate(testProbeGeneration(1)); err != nil {
				t.Fatalf("Activate() error = %v", err)
			}
			transaction, err := manager.Start(startedAt, 9, remote)
			if err != nil {
				t.Fatalf("Start() error = %v", err)
			}
			reply := AuthenticatedProbeReply{
				ID:                    transaction.ID,
				PeerID:                transaction.PeerID,
				Generation:            transaction.Generation,
				Source:                transaction.Endpoint,
				ObservedLocalEndpoint: observedLocal,
			}
			test.mutate(&reply)
			if _, err := manager.Complete(startedAt.Add(time.Millisecond), reply); !errors.Is(err, ErrPeerProbeMismatch) {
				t.Fatalf("Complete() error = %v, want ErrPeerProbeMismatch", err)
			}
			reply.PeerID = transaction.PeerID
			reply.Generation = transaction.Generation
			reply.Source = transaction.Endpoint
			if _, err := manager.Complete(startedAt.Add(2*time.Millisecond), reply); !errors.Is(err, ErrPeerProbeNotFound) {
				t.Fatalf("Complete(after mismatch) error = %v, want ErrPeerProbeNotFound", err)
			}
		})
	}
}

func TestProbeManagerExpiresTransactions(t *testing.T) {
	t.Parallel()

	startedAt := time.Unix(300, 0)
	remote := netip.MustParseAddrPort("203.0.113.30:41641")
	observedLocal := netip.MustParseAddrPort("198.51.100.40:41641")
	manager := testProbeManager(2, 1)
	if _, err := manager.Activate(testProbeGeneration(1)); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	first, err := manager.Start(startedAt, 10, remote)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if _, err := manager.Complete(first.Deadline, AuthenticatedProbeReply{
		ID:                    first.ID,
		PeerID:                first.PeerID,
		Generation:            first.Generation,
		Source:                first.Endpoint,
		ObservedLocalEndpoint: observedLocal,
	}); !errors.Is(err, ErrPeerProbeExpired) {
		t.Fatalf("Complete(at deadline) error = %v, want ErrPeerProbeExpired", err)
	}

	second, err := manager.Start(startedAt, 11, remote)
	if err != nil {
		t.Fatalf("second Start() error = %v", err)
	}
	removed, err := manager.Expire(second.Deadline)
	if err != nil || removed != 1 {
		t.Fatalf("Expire() = %d, %v, want 1", removed, err)
	}
	if _, err := manager.Complete(second.Deadline, AuthenticatedProbeReply{
		ID:                    second.ID,
		PeerID:                second.PeerID,
		Generation:            second.Generation,
		Source:                second.Endpoint,
		ObservedLocalEndpoint: observedLocal,
	}); !errors.Is(err, ErrPeerProbeNotFound) {
		t.Fatalf("Complete(expired) error = %v, want ErrPeerProbeNotFound", err)
	}
}

func TestProbeManagerCancelsExactTransaction(t *testing.T) {
	t.Parallel()

	manager := testProbeManager(2, 1)
	generation := testProbeGeneration(1)
	if _, err := manager.Activate(generation); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	now := time.Unix(350, 0)
	transaction, err := manager.Start(
		now,
		10,
		netip.MustParseAddrPort("203.0.113.35:41641"),
	)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	mismatch := transaction
	mismatch.PeerID++
	if manager.Cancel(mismatch) {
		t.Fatal("Cancel(mismatch) = true")
	}
	if !manager.Cancel(transaction) {
		t.Fatal("Cancel(exact) = false")
	}
	if manager.Cancel(transaction) {
		t.Fatal("Cancel(replay) = true")
	}
	if _, err := manager.Complete(now.Add(time.Millisecond), AuthenticatedProbeReply{
		ID:                    transaction.ID,
		PeerID:                transaction.PeerID,
		Generation:            transaction.Generation,
		Source:                transaction.Endpoint,
		ObservedLocalEndpoint: netip.MustParseAddrPort("198.51.100.35:41641"),
	}); !errors.Is(err, ErrPeerProbeNotFound) {
		t.Fatalf("Complete(cancelled) error = %v, want ErrPeerProbeNotFound", err)
	}
}

func TestProbeManagerEnforcesResourceLimits(t *testing.T) {
	t.Parallel()

	manager := testProbeManager(2, 1)
	if _, err := manager.Activate(testProbeGeneration(1)); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	now := time.Unix(400, 0)
	remote := netip.MustParseAddrPort("203.0.113.40:41641")
	if _, err := manager.Start(now, 1, remote); err != nil {
		t.Fatalf("Start(peer 1) error = %v", err)
	}
	if _, err := manager.Start(now, 1, remote); !errors.Is(err, ErrPeerProbeCapacity) {
		t.Fatalf("Start(peer 1 duplicate) error = %v, want ErrPeerProbeCapacity", err)
	}
	if _, err := manager.Start(now, 2, remote); err != nil {
		t.Fatalf("Start(peer 2) error = %v", err)
	}
	if _, err := manager.Start(now, 3, remote); !errors.Is(err, ErrPeerProbeCapacity) {
		t.Fatalf("Start(global limit) error = %v, want ErrPeerProbeCapacity", err)
	}
	if _, err := manager.Start(now.Add(defaultProbeLifetime), 3, remote); err != nil {
		t.Fatalf("Start(after opportunistic expiry) error = %v", err)
	}
}

func TestProbeManagerGenerationChangesInvalidateTransactions(t *testing.T) {
	t.Parallel()

	manager := testProbeManager(4, 2)
	firstGeneration := testProbeGeneration(1)
	if _, err := manager.Activate(firstGeneration); err != nil {
		t.Fatalf("Activate(first) error = %v", err)
	}
	now := time.Unix(500, 0)
	transaction, err := manager.Start(now, 12, netip.MustParseAddrPort("203.0.113.50:41641"))
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	secondGeneration := testProbeGeneration(2)
	if removed, err := manager.Activate(secondGeneration); err != nil || removed != 1 {
		t.Fatalf("Activate(second) = %d, %v, want 1", removed, err)
	}
	if removed, err := manager.Activate(secondGeneration); err != nil || removed != 0 {
		t.Fatalf("Activate(same) = %d, %v, want 0", removed, err)
	}
	if _, err := manager.Complete(now.Add(time.Millisecond), AuthenticatedProbeReply{
		ID:                    transaction.ID,
		PeerID:                transaction.PeerID,
		Generation:            transaction.Generation,
		Source:                transaction.Endpoint,
		ObservedLocalEndpoint: netip.MustParseAddrPort("198.51.100.50:41641"),
	}); !errors.Is(err, ErrPeerProbeNotFound) {
		t.Fatalf("Complete(old generation) error = %v, want ErrPeerProbeNotFound", err)
	}
	if _, err := manager.Start(now, 13, transaction.Endpoint); err != nil {
		t.Fatalf("Start(second generation) error = %v", err)
	}
	if removed, err := manager.Activate(ProbeGeneration{}); !errors.Is(err, ErrInvalidPeerProbe) || removed != 1 {
		t.Fatalf("Activate(invalid) = %d, %v, want one removal and invalid", removed, err)
	}
	if _, err := manager.Start(now, 14, transaction.Endpoint); !errors.Is(err, ErrPeerProbeInactive) {
		t.Fatalf("Start(inactive) error = %v, want ErrPeerProbeInactive", err)
	}
}

func TestProbeManagerValidatesInputsAndEntropy(t *testing.T) {
	t.Parallel()

	now := time.Unix(600, 0)
	remote := netip.MustParseAddrPort("203.0.113.60:41641")
	manager := testProbeManager(4, 2)
	if _, err := manager.Start(now, 1, remote); !errors.Is(err, ErrPeerProbeInactive) {
		t.Fatalf("Start(inactive) error = %v, want ErrPeerProbeInactive", err)
	}
	if _, err := manager.Activate(testProbeGeneration(1)); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	if _, err := manager.Start(time.Time{}, 1, remote); !errors.Is(err, ErrInvalidPeerProbe) {
		t.Fatalf("Start(zero time) error = %v, want ErrInvalidPeerProbe", err)
	}
	if _, err := manager.Start(now, 0, remote); !errors.Is(err, ErrInvalidPeerProbe) {
		t.Fatalf("Start(zero peer) error = %v, want ErrInvalidPeerProbe", err)
	}
	if _, err := manager.Start(now, 1, netip.MustParseAddrPort("127.0.0.1:41641")); !errors.Is(err, ErrInvalidPeerProbe) {
		t.Fatalf("Start(unsafe endpoint) error = %v, want ErrInvalidPeerProbe", err)
	}

	entropyManager := newProbeManager(probeErrorReader{}, defaultProbeLifetime, 4, 2)
	if _, err := entropyManager.Activate(testProbeGeneration(1)); err != nil {
		t.Fatalf("entropy Activate() error = %v", err)
	}
	if _, err := entropyManager.Start(now, 1, remote); !errors.Is(err, ErrPeerProbeEntropy) {
		t.Fatalf("Start(entropy failure) error = %v, want ErrPeerProbeEntropy", err)
	}
	zeroManager := newProbeManager(bytes.NewReader(make([]byte, probeIDSize*maxProbeIDAttempts)), defaultProbeLifetime, 4, 2)
	if _, err := zeroManager.Activate(testProbeGeneration(1)); err != nil {
		t.Fatalf("zero Activate() error = %v", err)
	}
	if _, err := zeroManager.Start(now, 1, remote); !errors.Is(err, ErrPeerProbeEntropy) {
		t.Fatalf("Start(zero ids) error = %v, want ErrPeerProbeEntropy", err)
	}
	collisionBytes := bytes.Repeat([]byte{1}, probeIDSize*(maxProbeIDAttempts+1))
	collisionManager := newProbeManager(
		bytes.NewReader(collisionBytes),
		defaultProbeLifetime,
		4,
		2,
	)
	if _, err := collisionManager.Activate(testProbeGeneration(1)); err != nil {
		t.Fatalf("collision Activate() error = %v", err)
	}
	if _, err := collisionManager.Start(now, 1, remote); err != nil {
		t.Fatalf("collision first Start() error = %v", err)
	}
	if _, err := collisionManager.Start(now, 2, remote); !errors.Is(err, ErrPeerProbeEntropy) {
		t.Fatalf("Start(colliding ids) error = %v, want ErrPeerProbeEntropy", err)
	}

	invalidReply := AuthenticatedProbeReply{}
	if _, err := manager.Complete(now, invalidReply); !errors.Is(err, ErrInvalidPeerProbe) {
		t.Fatalf("Complete(invalid) error = %v, want ErrInvalidPeerProbe", err)
	}
	if _, err := manager.Expire(time.Time{}); !errors.Is(err, ErrInvalidPeerProbe) {
		t.Fatalf("Expire(zero time) error = %v, want ErrInvalidPeerProbe", err)
	}
}

func TestProbeManagerConcurrentLifecycle(t *testing.T) {
	t.Parallel()

	manager := NewProbeManager()
	generation := testProbeGeneration(1)
	if _, err := manager.Activate(generation); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	now := time.Unix(700, 0)
	remote := netip.MustParseAddrPort("203.0.113.70:41641")
	observedLocal := netip.MustParseAddrPort("198.51.100.70:41641")
	transactions := make(chan ProbeTransaction, 128)
	var starters sync.WaitGroup
	for peerID := uint64(1); peerID <= 128; peerID++ {
		starters.Go(func() {
			transaction, err := manager.Start(now, peerID, remote)
			if err != nil {
				t.Errorf("Start(%d) error = %v", peerID, err)

				return
			}
			transactions <- transaction
		})
	}
	starters.Wait()
	close(transactions)

	var completers sync.WaitGroup
	for transaction := range transactions {
		completers.Go(func() {
			if _, err := manager.Complete(now.Add(time.Millisecond), AuthenticatedProbeReply{
				ID:                    transaction.ID,
				PeerID:                transaction.PeerID,
				Generation:            transaction.Generation,
				Source:                transaction.Endpoint,
				ObservedLocalEndpoint: observedLocal,
			}); err != nil {
				t.Errorf("Complete(%d) error = %v", transaction.PeerID, err)
			}
		})
	}
	completers.Wait()
	if removed := manager.Deactivate(); removed != 0 {
		t.Fatalf("Deactivate() removed = %d, want 0", removed)
	}
}

func FuzzProbeManagerComplete(f *testing.F) {
	f.Add([]byte{}, uint64(1), uint64(1), uint64(1), uint16(41641))
	f.Add(make([]byte, probeIDSize), uint64(0), uint64(0), uint64(0), uint16(0))

	f.Fuzz(func(
		t *testing.T,
		rawID []byte,
		peerID uint64,
		scope uint64,
		mapRevision uint64,
		port uint16,
	) {
		manager := testProbeManager(4, 2)
		activeGeneration := testProbeGeneration(1)
		if _, err := manager.Activate(activeGeneration); err != nil {
			t.Fatalf("Activate() error = %v", err)
		}
		transaction, err := manager.Start(
			time.Unix(800, 0),
			1,
			netip.MustParseAddrPort("203.0.113.80:41641"),
		)
		if err != nil {
			t.Fatalf("Start() error = %v", err)
		}
		id := transaction.ID
		if len(rawID) != 0 {
			clear(id[:])
			copy(id[:], rawID)
		}
		generation := ProbeGeneration{
			Scope:       scope,
			MapRevision: mapRevision,
			Socket:      Socket{Port: port, Generation: scope},
		}
		_, _ = manager.Complete(time.Unix(800, 0), AuthenticatedProbeReply{
			ID:                    id,
			PeerID:                peerID,
			Generation:            generation,
			Source:                netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, 80}), port),
			ObservedLocalEndpoint: netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, 80}), port),
		})
	})
}

func testProbeManager(maxPending, maxPerPeer int) *ProbeManager {
	random := make([]byte, probeIDSize*64)
	for index := range random {
		random[index] = byte(index/probeIDSize + 1)
	}

	return newProbeManager(bytes.NewReader(random), defaultProbeLifetime, maxPending, maxPerPeer)
}

func testProbeGeneration(sequence uint64) ProbeGeneration {
	return ProbeGeneration{
		Scope:       sequence,
		MapRevision: sequence,
		Socket: Socket{
			Port:       41641,
			Generation: sequence,
		},
	}
}

type probeErrorReader struct{}

func (probeErrorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
