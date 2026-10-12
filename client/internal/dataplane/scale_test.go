package dataplane

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
	"time"

	"meshtransit.net/client/internal/networkmap"
)

// scalePeers returns count peers with fresh keys and contiguous overlay
// addresses after 100.64.0.10.
func scalePeers(t testing.TB, template networkmap.Node, start, count int) []networkmap.Node {
	t.Helper()
	peers := make([]networkmap.Node, 0, count)
	for index := start; index < start+count; index++ {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey() error = %v", err)
		}
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], 100<<24|64<<16|uint32(10+index)) //nolint:gosec // index < 2^20
		prefix := netip.PrefixFrom(netip.AddrFrom4(raw), 32)
		peer := template
		peer.ID = uint64(100 + index) //nolint:gosec // index is non-negative
		peer.PublicKey = "nodekey:" + hex.EncodeToString(key.PublicKey().Bytes())
		peer.Addresses = []netip.Prefix{prefix}
		peer.AllowedIPs = []netip.Prefix{prefix}
		peers = append(peers, peer)
	}
	return peers
}

// TestWireGuardEngineAppliesTenThousandPeers: a map at the peer limit
// applies, installs a handful of aggregated routes, and one joining peer
// changes one peer in the device.
func TestWireGuardEngineAppliesTenThousandPeers(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test")
	}
	t.Parallel()
	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Peers = scalePeers(t, snapshot.Peers[0], 0, maxWireGuardPeers-1)
	snapshot.Policy = nil
	opener := &wireGuardTUNOpener{}
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(opener, 41641, &fakeWireGuardFactory{device: device}, nil)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	started := time.Now()
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply(%d peers) error = %v", len(snapshot.Peers), err)
	}
	t.Logf("first Apply of %d peers: %v", len(snapshot.Peers), time.Since(started))
	if routes := len(opener.config.Routes); routes == 0 || routes > 32 {
		t.Fatalf("installed %d routes for contiguous peers", routes)
	}

	snapshot.Revision++
	snapshot.Peers = append(snapshot.Peers, scalePeers(t, snapshot.Peers[0], maxWireGuardPeers, 1)...)
	started = time.Now()
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply(+1 peer) error = %v", err)
	}
	t.Logf("Apply of one joining peer among %d: %v", len(snapshot.Peers), time.Since(started))
	if keys := strings.Count(device.configuration, "public_key="); keys != 1 {
		t.Fatalf("one joining peer rewrote %d peers", keys)
	}

	snapshot.Revision++
	snapshot.Peers = append(snapshot.Peers, scalePeers(t, snapshot.Peers[0], maxWireGuardPeers+1, 1)...)
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err == nil {
		t.Fatal("a map over the peer limit applied")
	}
}
