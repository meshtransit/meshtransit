package disco

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"

	"golang.org/x/crypto/nacl/box"
	upstreamdisco "tailscale.com/disco"
)

func TestPeerSealPingCompatibility(t *testing.T) {
	t.Parallel()

	sender := mustIdentity(t)
	recipient := mustIdentity(t)
	peer, err := sender.Peer(recipient.public)
	if err != nil {
		t.Fatalf("Peer() error = %v", err)
	}
	t.Cleanup(peer.Close)
	transactionID := TransactionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	nodeKey := mustNodeKey(t)
	packet, err := peer.Seal(Ping{
		ID:      transactionID,
		NodeKey: nodeKey,
		Padding: 32,
	})
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if !upstreamdisco.LooksLikeDiscoWrapper(packet) {
		t.Fatal("Seal() packet does not match compatibility wrapper")
	}
	source, ok := upstreamdisco.Source(packet)
	if !ok {
		t.Fatal("compatibility Source() rejected packet")
	}
	var sourceKey [keySize]byte
	copy(sourceKey[:], source)
	var nonce [nonceSize]byte
	copy(nonce[:], packet[len(magic)+keySize:wrapperHeaderSize])
	var shared [keySize]byte
	box.Precompute(&shared, &sourceKey, &recipient.private)
	plaintext, ok := box.OpenAfterPrecomputation(
		nil,
		packet[wrapperHeaderSize:],
		&nonce,
		&shared,
	)
	clear(shared[:])
	if !ok {
		t.Fatal("compatibility key failed to open packet")
	}
	decoded, err := upstreamdisco.Parse(plaintext)
	if err != nil {
		t.Fatalf("compatibility Parse() error = %v", err)
	}
	ping, ok := decoded.(*upstreamdisco.Ping)
	if !ok || ping.TxID != [transactionSize]byte(transactionID) ||
		ping.NodeKey.String() != nodeKey.String() || ping.Padding != 32 {
		t.Fatalf("compatibility Parse() = %#v", decoded)
	}
}

func TestPeerOpenPongCompatibility(t *testing.T) {
	t.Parallel()

	sender := mustIdentity(t)
	recipient := mustIdentity(t)
	peer, err := recipient.Peer(sender.public)
	if err != nil {
		t.Fatalf("Peer() error = %v", err)
	}
	t.Cleanup(peer.Close)
	transactionID := TransactionID{12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	source := netip.MustParseAddrPort("203.0.113.80:41641")
	payload := (&upstreamdisco.Pong{
		TxID: [transactionSize]byte(transactionID),
		Src:  source,
	}).AppendMarshal(nil)
	packet := compatibilityPacket(t, sender, recipient.public, payload)

	decoded, err := peer.Open(packet)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	pong, ok := decoded.(Pong)
	if !ok || pong.ID != transactionID || pong.Source != source {
		t.Fatalf("Open() = %#v", decoded)
	}
}

func TestSourceIsUntrustedUntilOpen(t *testing.T) {
	t.Parallel()

	sender := mustIdentity(t)
	recipient := mustIdentity(t)
	peer, err := sender.Peer(recipient.public)
	if err != nil {
		t.Fatalf("Peer() error = %v", err)
	}
	t.Cleanup(peer.Close)
	packet, err := peer.Seal(Ping{
		ID:      TransactionID{1},
		NodeKey: mustNodeKey(t),
	})
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	source, err := Source(packet)
	if err != nil || source != sender.public {
		t.Fatalf("Source() = %#v, %v", source, err)
	}
	if !LooksLikePacket(packet) {
		t.Fatal("LooksLikePacket() = false")
	}
}

func TestPeerRejectsUnauthenticatedPackets(t *testing.T) {
	t.Parallel()

	sender := mustIdentity(t)
	recipient := mustIdentity(t)
	senderPeer, err := sender.Peer(recipient.public)
	if err != nil {
		t.Fatalf("sender Peer() error = %v", err)
	}
	t.Cleanup(senderPeer.Close)
	recipientPeer, err := recipient.Peer(sender.public)
	if err != nil {
		t.Fatalf("recipient Peer() error = %v", err)
	}
	t.Cleanup(recipientPeer.Close)
	packet, err := senderPeer.Seal(Ping{
		ID:      TransactionID{1},
		NodeKey: mustNodeKey(t),
	})
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	tampered := bytes.Clone(packet)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := recipientPeer.Open(tampered); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("Open(tampered) error = %v, want ErrAuthentication", err)
	}

	third := mustIdentity(t)
	thirdPeer, err := third.Peer(sender.public)
	if err != nil {
		t.Fatalf("third Peer() error = %v", err)
	}
	t.Cleanup(thirdPeer.Close)
	if _, err := thirdPeer.Open(packet); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("Open(wrong recipient) error = %v, want ErrAuthentication", err)
	}

	wrongSender := bytes.Clone(packet)
	copy(wrongSender[len(magic):len(magic)+keySize], third.public.raw[:])
	if _, err := recipientPeer.Open(wrongSender); !errors.Is(err, ErrUnexpectedPeer) {
		t.Fatalf("Open(wrong sender) error = %v, want ErrUnexpectedPeer", err)
	}

	wrongMagic := bytes.Clone(packet)
	wrongMagic[0] ^= 0xff
	if _, err := recipientPeer.Open(wrongMagic); !errors.Is(err, ErrNotPacket) {
		t.Fatalf("Open(wrong magic) error = %v, want ErrNotPacket", err)
	}
	if _, err := recipientPeer.Open(packet[:len(magic)+keySize]); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Open(truncated) error = %v, want ErrMalformed", err)
	}
	oversized := append(bytes.Clone(packet), make([]byte, maxPacketSize)...)
	if _, err := recipientPeer.Open(oversized); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Open(oversized) error = %v, want ErrMalformed", err)
	}
}

func TestPeerReportsNonceFailureAndClosure(t *testing.T) {
	t.Parallel()

	sender := mustIdentity(t)
	recipient := mustIdentity(t)
	peer, err := sender.Peer(recipient.public)
	if err != nil {
		t.Fatalf("Peer() error = %v", err)
	}
	peer.mu.Lock()
	peer.random = errorReader{}
	peer.mu.Unlock()
	if _, err := peer.Seal(Ping{
		ID:      TransactionID{1},
		NodeKey: mustNodeKey(t),
	}); err == nil {
		t.Fatal("Seal() random error = nil")
	}
	peer.Close()
	if _, err := peer.Open([]byte(magic)); !errors.Is(err, ErrNotPacket) {
		t.Fatalf("Open() after Close error = %v, want ErrNotPacket for non-packet", err)
	}
}

func FuzzPeerOpen(f *testing.F) {
	sender, err := NewIdentity()
	if err != nil {
		f.Fatalf("NewIdentity() sender error = %v", err)
	}
	defer sender.Close()
	recipient, err := NewIdentity()
	if err != nil {
		f.Fatalf("NewIdentity() recipient error = %v", err)
	}
	defer recipient.Close()
	senderPeer, err := sender.Peer(recipient.public)
	if err != nil {
		f.Fatalf("Peer() sender error = %v", err)
	}
	defer senderPeer.Close()
	recipientPeer, err := recipient.Peer(sender.public)
	if err != nil {
		f.Fatalf("Peer() recipient error = %v", err)
	}
	defer recipientPeer.Close()
	valid, err := senderPeer.Seal(Ping{
		ID:      TransactionID{1},
		NodeKey: NodeKey{raw: [keySize]byte{0: 1}},
	})
	if err != nil {
		f.Fatalf("Seal() error = %v", err)
	}
	f.Add(valid)
	f.Add([]byte(magic))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, packet []byte) {
		_, _ = recipientPeer.Open(packet)
	})
}

func compatibilityPacket(
	t *testing.T,
	sender *Identity,
	recipient PublicKey,
	payload []byte,
) []byte {
	t.Helper()

	var nonce [nonceSize]byte
	nonce[0] = 1
	var shared [keySize]byte
	box.Precompute(&shared, &recipient.raw, &sender.private)
	packet := make([]byte, 0, maxPacketSize)
	packet = append(packet, upstreamdisco.Magic...)
	packet = append(packet, sender.public.raw[:]...)
	packet = append(packet, nonce[:]...)
	packet = box.SealAfterPrecomputation(packet, payload, &nonce, &shared)
	clear(shared[:])

	return packet
}
