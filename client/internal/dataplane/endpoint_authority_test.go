package dataplane

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// TestConfiguredEndpointSurvivesPacketsFromAnotherPath reproduces relay-driven
// roaming: every authenticated packet the channel bind delivers carries a
// different source endpoint than the one meshd configured, as relayed packets
// do after a direct promotion. The configured endpoint must stay authoritative.
func TestConfiguredEndpointSurvivesPacketsFromAnotherPath(t *testing.T) {
	t.Parallel()
	binds := bindtest.NewChannelBinds()
	tunA, tunB := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	logger := &device.Logger{Verbosef: device.DiscardLogf, Errorf: device.DiscardLogf}
	deviceA := newEndpointAuthorityDevice(tunA.TUN(), binds[0], logger)
	deviceB := newEndpointAuthorityDevice(tunB.TUN(), binds[1], logger)
	t.Cleanup(deviceA.Close)
	t.Cleanup(deviceB.Close)

	keyA, keyB := testWireGuardKey(t, 0x11), testWireGuardKey(t, 0x22)
	addressA, addressB := netip.MustParseAddr("10.9.0.1"), netip.MustParseAddr("10.9.0.2")
	// Channel endpoint 1 is A's configured path to B; B's packets arrive at A
	// tagged as endpoint 3, which roaming would adopt.
	configureEndpointAuthorityPeer(t, deviceA, keyA, keyB, "127.0.0.1:1", addressB)
	configureEndpointAuthorityPeer(t, deviceB, keyB, keyA, "127.0.0.1:2", addressA)
	for _, target := range []*device.Device{deviceA, deviceB} {
		if err := target.Up(); err != nil {
			t.Fatal(err)
		}
	}

	exchangeEndpointAuthorityPing(t, tunA, tunB, addressA, addressB)
	exchangeEndpointAuthorityPing(t, tunB, tunA, addressB, addressA)

	if got := installedPeerEndpoint(t, deviceA); got != "127.0.0.1:1" {
		t.Fatalf("peer endpoint = %q after packets from another path, want configured 127.0.0.1:1", got)
	}
}

// TestPeerWithoutConfiguredEndpointStillLearnsFromPackets keeps the existing
// behavior for peers meshd has no endpoint for: their first authenticated
// packet supplies the only known return path.
func TestPeerWithoutConfiguredEndpointStillLearnsFromPackets(t *testing.T) {
	t.Parallel()
	binds := bindtest.NewChannelBinds()
	tunA, tunB := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	logger := &device.Logger{Verbosef: device.DiscardLogf, Errorf: device.DiscardLogf}
	deviceA := newEndpointAuthorityDevice(tunA.TUN(), binds[0], logger)
	deviceB := newEndpointAuthorityDevice(tunB.TUN(), binds[1], logger)
	t.Cleanup(deviceA.Close)
	t.Cleanup(deviceB.Close)

	keyA, keyB := testWireGuardKey(t, 0x33), testWireGuardKey(t, 0x44)
	addressA, addressB := netip.MustParseAddr("10.9.1.1"), netip.MustParseAddr("10.9.1.2")
	configureEndpointAuthorityPeer(t, deviceA, keyA, keyB, "", addressB)
	configureEndpointAuthorityPeer(t, deviceB, keyB, keyA, "127.0.0.1:2", addressA)
	for _, target := range []*device.Device{deviceA, deviceB} {
		if err := target.Up(); err != nil {
			t.Fatal(err)
		}
	}

	exchangeEndpointAuthorityPing(t, tunB, tunA, addressB, addressA)

	if got := installedPeerEndpoint(t, deviceA); got != "127.0.0.1:3" {
		t.Fatalf("peer endpoint = %q, want the learned packet source 127.0.0.1:3", got)
	}
}

func testWireGuardKey(t *testing.T, seed byte) device.NoisePrivateKey {
	t.Helper()
	var key device.NoisePrivateKey
	for index := range key {
		key[index] = seed + byte(index)
	}
	// Clamp as Curve25519 requires so the derived public key is valid.
	key[0] &= 248
	key[31] = (key[31] & 127) | 64

	return key
}

func configureEndpointAuthorityPeer(
	t *testing.T,
	target *device.Device,
	private device.NoisePrivateKey,
	peerPrivate device.NoisePrivateKey,
	endpoint string,
	peerAddress netip.Addr,
) {
	t.Helper()
	peerPublic := publicKeyFor(t, peerPrivate)
	var configuration bytes.Buffer
	fmt.Fprintf(&configuration, "private_key=%s\n", hex.EncodeToString(private[:]))
	fmt.Fprintf(&configuration, "public_key=%s\n", hex.EncodeToString(peerPublic))
	if endpoint != "" {
		fmt.Fprintf(&configuration, "endpoint=%s\n", endpoint)
	}
	fmt.Fprintf(&configuration, "allowed_ip=%s/32\n", peerAddress)
	if err := configureWithEndpointAuthority(target, &configuration); err != nil {
		t.Fatal(err)
	}
}

func publicKeyFor(t *testing.T, private device.NoisePrivateKey) []byte {
	t.Helper()
	public, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}

	return public
}

func exchangeEndpointAuthorityPing(
	t *testing.T,
	from, to *tuntest.ChannelTUN,
	source, destination netip.Addr,
) {
	t.Helper()
	packet := tuntest.Ping(destination, source)
	deadline := time.After(5 * time.Second)
	for {
		from.Outbound <- packet
		select {
		case received := <-to.Inbound:
			if bytes.Equal(received, packet) {
				return
			}
		case <-time.After(100 * time.Millisecond):
			continue
		case <-deadline:
			t.Fatalf("ping %s -> %s was not delivered", source, destination)
		}
	}
}

func installedPeerEndpoint(t *testing.T, target *device.Device) string {
	t.Helper()
	state, err := target.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(state, "\n") {
		if value, found := strings.CutPrefix(line, "endpoint="); found {
			return value
		}
	}

	return ""
}
