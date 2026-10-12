package dataplane

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// TestPeerDiffKeepsSessionsOnARealDevice applies wireGuardPeerDiff to a real
// wireguard-go device: the device ends with exactly the planned peers, and a
// peer that did not change keeps its session.
func TestPeerDiffKeepsSessionsOnARealDevice(t *testing.T) {
	t.Parallel()
	binds := bindtest.NewChannelBinds()
	tunA, tunB := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	logger := &device.Logger{Verbosef: device.DiscardLogf, Errorf: device.DiscardLogf}
	deviceA := newEndpointAuthorityDevice(tunA.TUN(), binds[0], logger)
	deviceB := newEndpointAuthorityDevice(tunB.TUN(), binds[1], logger)
	t.Cleanup(deviceA.Close)
	t.Cleanup(deviceB.Close)

	keyA, keyB := testWireGuardKey(t, 0x11), testWireGuardKey(t, 0x22)
	keyC, keyD := testWireGuardKey(t, 0x33), testWireGuardKey(t, 0x44)
	addressA, addressB := netip.MustParseAddr("10.9.0.1"), netip.MustParseAddr("10.9.0.2")
	plan := func(id uint64, key device.NoisePrivateKey, endpoint, address string) wireGuardPeerPlan {
		var public [32]byte
		copy(public[:], publicKeyFor(t, key))
		return wireGuardPeerPlan{
			id: id, key: public, baseEndpoint: endpoint, basePath: peerPathDirect,
			allowedIPs: []netip.Prefix{netip.MustParsePrefix(address)},
		}
	}
	peerB := plan(2, keyB, "127.0.0.1:1", "10.9.0.2/32")
	peerC := plan(3, keyC, "", "10.9.0.3/32")
	peerD := plan(4, keyD, "", "10.9.0.4/32")

	// B first, so A's first handshake finds B keyed.
	configureEndpointAuthorityPeer(t, deviceB, keyB, keyA, "127.0.0.1:2", addressA)
	var initial bytes.Buffer
	fmt.Fprintf(&initial, "private_key=%s\nreplace_peers=true\n", hex.EncodeToString(keyA[:]))
	installed := map[uint64]wireGuardPeerState{}
	for _, peer := range []wireGuardPeerPlan{peerB, peerC} {
		writeWireGuardPeerConfiguration(&initial, peer)
		installed[peer.id] = wireGuardPeerState{
			key: peer.key, baseEndpoint: peer.baseEndpoint, basePath: peer.basePath, allowedIPs: peer.allowedIPs,
		}
	}
	if err := deviceA.IpcSetOperation(&initial); err != nil {
		t.Fatalf("initial configuration: %v", err)
	}
	for _, target := range []*device.Device{deviceA, deviceB} {
		if err := target.Up(); err != nil {
			t.Fatal(err)
		}
	}
	exchangeEndpointAuthorityPing(t, tunA, tunB, addressA, addressB)
	handshakeBefore := peerHandshake(t, deviceA, peerB.key)
	if handshakeBefore == "" || handshakeBefore == "0" {
		t.Fatalf("no session with B before the diff (handshake %q)", handshakeBefore)
	}

	diff, preserved, resets := wireGuardPeerDiff(installed, []wireGuardPeerPlan{peerB, peerD})
	if _, kept := preserved[peerB.id]; !kept || len(resets) != 0 {
		t.Fatalf("diff preserved %v, reset %v", preserved, resets)
	}
	if err := deviceA.IpcSetOperation(bytes.NewReader(diff)); err != nil {
		t.Fatalf("diff configuration: %v\n%s", err, diff)
	}

	keys := installedPeerKeys(t, deviceA)
	want := []string{hex.EncodeToString(peerB.key[:]), hex.EncodeToString(peerD.key[:])}
	slices.Sort(want)
	if !slices.Equal(keys, want) {
		t.Fatalf("installed peers = %v, want %v", keys, want)
	}
	if after := peerHandshake(t, deviceA, peerB.key); after != handshakeBefore {
		t.Fatalf("B's session was reset: handshake %q, then %q", handshakeBefore, after)
	}
	exchangeEndpointAuthorityPing(t, tunA, tunB, addressA, addressB)
}

// installedPeerKeys lists the device's peer public keys in hex, sorted.
func installedPeerKeys(t *testing.T, target *device.Device) []string {
	t.Helper()
	state, err := target.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, line := range strings.Split(state, "\n") {
		if value, found := strings.CutPrefix(line, "public_key="); found {
			keys = append(keys, value)
		}
	}
	slices.Sort(keys)
	return keys
}

// peerHandshake returns the peer's last_handshake_time_sec.
func peerHandshake(t *testing.T, target *device.Device, key [32]byte) string {
	t.Helper()
	state, err := target.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	inPeer := false
	for _, line := range strings.Split(state, "\n") {
		if value, found := strings.CutPrefix(line, "public_key="); found {
			inPeer = value == hex.EncodeToString(key[:])
			continue
		}
		if value, found := strings.CutPrefix(line, "last_handshake_time_sec="); found && inPeer {
			return value
		}
	}
	return ""
}
