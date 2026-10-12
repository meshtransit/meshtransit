package dataplane

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/client/internal/relay"
)

func TestWireGuardEngineApply(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	opener := &wireGuardTUNOpener{}
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(opener, 41641, &fakeWireGuardFactory{device: device}, nil)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	state, err := engine.Apply(t.Context(), snapshot, privateKey)
	if err != nil || state != StateEncrypted {
		t.Fatalf("Apply() = %q, %v", state, err)
	}
	if opener.calls != 1 || device.upCalls != 1 || device.configureCalls != 1 {
		t.Fatalf(
			"calls open=%d up=%d configure=%d",
			opener.calls,
			device.upCalls,
			device.configureCalls,
		)
	}
	if !slices.Equal(opener.config.Addresses, snapshot.Self.Addresses) ||
		!slices.Equal(opener.config.Routes, snapshot.Peers[0].Addresses) {
		t.Fatalf("helper config = %#v, want signed host prefixes", opener.config)
	}
	for _, expected := range []string{
		"listen_port=41641",
		"endpoint=203.0.113.20:41641",
		"persistent_keepalive_interval=25",
		"allowed_ip=100.64.0.4/32",
	} {
		if !strings.Contains(device.configuration, expected) {
			t.Fatalf("configuration is missing %q", expected)
		}
	}
	if state, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil || state != StateEncrypted {
		t.Fatalf("repeat Apply() = %q, %v", state, err)
	}
	if opener.calls != 1 || device.configureCalls != 1 {
		t.Fatalf("repeat calls open=%d configure=%d", opener.calls, device.configureCalls)
	}
	if err := engine.Close(); err != nil || device.closeCalls != 1 {
		t.Fatalf("Close() error=%v calls=%d", err, device.closeCalls)
	}
}

func TestWireGuardEngineTogglesKeepaliveWithSelectedPath(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot = addTestRelay(snapshot)
	direct := snapshot.Peers[0].Endpoints[0]
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(
		&wireGuardTUNOpener{},
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !strings.Contains(device.configurations[0], "persistent_keepalive_interval=0") {
		t.Fatalf("relay configuration = %q, want disabled keepalive", device.configurations[0])
	}
	if err := engine.SetPreferredEndpoint(snapshot.Revision, snapshot.Peers[0].ID, direct); err != nil {
		t.Fatalf("SetPreferredEndpoint() error = %v", err)
	}
	if !strings.Contains(device.configurations[1], "persistent_keepalive_interval=25") {
		t.Fatalf("direct configuration = %q, want enabled keepalive", device.configurations[1])
	}
	if err := engine.RestorePreferredEndpoint(snapshot.Revision, snapshot.Peers[0].ID); err != nil {
		t.Fatalf("RestorePreferredEndpoint() error = %v", err)
	}
	if !strings.Contains(device.configurations[2], "persistent_keepalive_interval=0") {
		t.Fatalf("restored relay configuration = %q, want disabled keepalive", device.configurations[2])
	}
}

func TestWireGuardEngineRetainsPresenceTransportWithoutPeers(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot = addTestRelay(snapshot)
	opener := &wireGuardTUNOpener{}
	device := &fakeWireGuardDevice{
		discoverySocket: pathdiscovery.Socket{Port: 41641, Generation: 1},
	}
	engine, err := newWireGuardEngine(
		opener,
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply(peer map) error = %v", err)
	}

	peerless := snapshot
	peerless.Revision++
	peerless.Peers = nil
	peerless.Policy = nil
	state, err := engine.Apply(t.Context(), peerless, privateKey)
	if err != nil || state != StateIdle {
		t.Fatalf("Apply(peerless map) = %q, %v", state, err)
	}
	if engine.device == nil || engine.DiscoverySocket() != device.discoverySocket {
		t.Fatalf("peerless presence transport = %#v", engine.DiscoverySocket())
	}
	if paths := engine.PeerPaths(); !paths.Available || paths.PeerCount != 0 {
		t.Fatalf("peerless paths = %#v", paths)
	}
	if opener.calls != 1 || opener.updateCalls != 1 || device.closeCalls != 0 ||
		device.upCalls != 1 || device.relayUpdateCalls != 1 || len(device.relayPeers) != 0 {
		t.Fatalf(
			"peerless transition calls open=%d update=%d close=%d up=%d relay=%d peers=%d",
			opener.calls,
			opener.updateCalls,
			device.closeCalls,
			device.upCalls,
			device.relayUpdateCalls,
			len(device.relayPeers),
		)
	}
	if len(opener.config.Routes) != 0 || !slices.Equal(opener.config.Addresses, peerless.Self.Addresses) {
		t.Fatalf("peerless helper config = %#v", opener.config)
	}
	if device.configuration != "replace_peers=true\n" {
		t.Fatalf("peerless wireguard update restarted the bind: %q", device.configuration)
	}

	peerless.Revision++
	if state, err := engine.Apply(t.Context(), peerless, privateKey); err != nil || state != StateIdle {
		t.Fatalf("repeat Apply(peerless map) = %q, %v", state, err)
	}
	if opener.calls != 1 || opener.updateCalls != 1 || device.closeCalls != 0 ||
		device.configureCalls != 2 || device.relayUpdateCalls != 1 {
		t.Fatalf(
			"repeat peerless calls open=%d update=%d close=%d configure=%d relay=%d",
			opener.calls,
			opener.updateCalls,
			device.closeCalls,
			device.configureCalls,
			device.relayUpdateCalls,
		)
	}
	snapshot.Revision = peerless.Revision + 1
	if state, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil ||
		state != StateEncryptedRelay {
		t.Fatalf("Apply(restored peer map) = %q, %v", state, err)
	}
	if opener.calls != 1 || opener.updateCalls != 2 || device.closeCalls != 0 ||
		device.configureCalls != 3 || device.relayUpdateCalls != 2 || len(device.relayPeers) != 1 {
		t.Fatalf(
			"restored transition calls open=%d update=%d close=%d configure=%d relay=%d peers=%d",
			opener.calls,
			opener.updateCalls,
			device.closeCalls,
			device.configureCalls,
			device.relayUpdateCalls,
			len(device.relayPeers),
		)
	}
	for _, forbidden := range []string{"private_key=", "listen_port="} {
		if strings.Contains(device.configuration, forbidden) {
			t.Fatalf("restored wireguard update contains %q: %q", forbidden, device.configuration)
		}
	}

	if err := engine.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestWireGuardEngineBoundsRepeatedPeerlessTransitions(t *testing.T) {
	t.Parallel()

	privateKey, peerMap := testWireGuardSnapshot(t)
	peerMap = addTestRelay(peerMap)
	peerlessMap := peerMap
	peerlessMap.Peers = nil
	peerlessMap.Policy = nil
	opener := &wireGuardTUNOpener{}
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(
		opener,
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), peerMap, privateKey); err != nil {
		t.Fatalf("initial Apply() error = %v", err)
	}
	const cycles = 100
	for cycle := range cycles {
		peerlessMap.Revision = uint64(cycle*2 + 2)
		if state, err := engine.Apply(t.Context(), peerlessMap, privateKey); err != nil ||
			state != StateIdle {
			t.Fatalf("cycle %d peerless Apply() = %q, %v", cycle, state, err)
		}
		peerMap.Revision = uint64(cycle*2 + 3)
		if state, err := engine.Apply(t.Context(), peerMap, privateKey); err != nil ||
			state != StateEncryptedRelay {
			t.Fatalf("cycle %d peer Apply() = %q, %v", cycle, state, err)
		}
	}
	if opener.calls != 1 || opener.updateCalls != cycles*2 || device.closeCalls != 0 ||
		device.upCalls != 1 || device.configureCalls != cycles*2+1 ||
		device.relayUpdateCalls != cycles*2 {
		t.Fatalf(
			"repeated transitions open=%d update=%d close=%d up=%d configure=%d relay=%d",
			opener.calls,
			opener.updateCalls,
			device.closeCalls,
			device.upCalls,
			device.configureCalls,
			device.relayUpdateCalls,
		)
	}
}

func TestWireGuardEngineApplyDualStack(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	selfIPv6 := netip.MustParsePrefix("fd07:d4de:9d87::f/128")
	peerIPv6 := netip.MustParsePrefix("fd07:d4de:9d87::5/128")
	snapshot.Self.Addresses = append(snapshot.Self.Addresses, selfIPv6)
	snapshot.Peers[0].Addresses = append(snapshot.Peers[0].Addresses, peerIPv6)
	snapshot.Peers[0].AllowedIPs = append(snapshot.Peers[0].AllowedIPs, peerIPv6)
	opener := &wireGuardTUNOpener{}
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(
		opener,
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })

	if !slices.Equal(opener.config.Addresses, snapshot.Self.Addresses) ||
		!slices.Equal(opener.config.Routes, snapshot.Peers[0].Addresses) {
		t.Fatalf("dual-stack helper config = %#v", opener.config)
	}
	for _, expected := range []string{
		"allowed_ip=100.64.0.4/32",
		"allowed_ip=fd07:d4de:9d87::5/128",
	} {
		if !strings.Contains(device.configuration, expected) {
			t.Fatalf("configuration is missing %q", expected)
		}
	}
}

func TestWireGuardEngineAppliesAndRestoresAuthenticatedPeerEndpoint(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	base := snapshot.Peers[0].Endpoints[0]
	preferred := netip.MustParseAddrPort("192.168.1.20:41641")
	snapshot.Peers[0].Endpoints = append(snapshot.Peers[0].Endpoints, preferred)
	opener := &wireGuardTUNOpener{}
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(
		opener,
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if err := engine.SetPreferredEndpoint(snapshot.Revision, snapshot.Peers[0].ID, preferred); err != nil {
		t.Fatalf("SetPreferredEndpoint() error = %v", err)
	}
	if device.configureCalls != 2 || len(device.configurations) != 2 {
		t.Fatalf("configure calls = %d, configurations=%d", device.configureCalls, len(device.configurations))
	}
	update := device.configurations[1]
	for _, expected := range []string{
		"public_key=",
		"update_only=true",
		"endpoint=" + preferred.String(),
	} {
		if !strings.Contains(update, expected) {
			t.Fatalf("incremental configuration is missing %q: %q", expected, update)
		}
	}
	for _, forbidden := range []string{"private_key=", "replace_peers=", "allowed_ip="} {
		if strings.Contains(update, forbidden) {
			t.Fatalf("incremental configuration contains %q: %q", forbidden, update)
		}
	}
	if err := engine.SetPreferredEndpoint(snapshot.Revision, snapshot.Peers[0].ID, preferred); err != nil {
		t.Fatalf("repeat SetPreferredEndpoint() error = %v", err)
	}
	if device.configureCalls != 3 || !strings.Contains(
		device.configurations[2],
		"endpoint="+preferred.String(),
	) {
		t.Fatalf("reassert preferred endpoint configuration = %q", device.configuration)
	}
	if err := engine.RestorePreferredEndpoint(snapshot.Revision, snapshot.Peers[0].ID); err != nil {
		t.Fatalf("RestorePreferredEndpoint() error = %v", err)
	}
	if device.configureCalls != 4 || !strings.Contains(
		device.configurations[3],
		"endpoint="+base.String(),
	) {
		t.Fatalf("restore configuration = %q", device.configuration)
	}
	if opener.calls != 1 || device.upCalls != 1 || device.closeCalls != 0 {
		t.Fatalf(
			"endpoint updates recreated tunnel: open=%d up=%d close=%d",
			opener.calls,
			device.upCalls,
			device.closeCalls,
		)
	}
}

func TestWireGuardEngineRejectsUnauthorizedOrStalePeerEndpoint(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(
		&wireGuardTUNOpener{},
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if err := engine.SetPreferredEndpoint(
		snapshot.Revision+1,
		snapshot.Peers[0].ID,
		snapshot.Peers[0].Endpoints[0],
	); !errors.Is(err, ErrPeerEndpointGeneration) {
		t.Fatalf("stale SetPreferredEndpoint() error = %v", err)
	}
	if err := engine.SetPreferredEndpoint(
		snapshot.Revision,
		snapshot.Peers[0].ID,
		netip.MustParseAddrPort("127.0.0.1:41641"),
	); !errors.Is(err, ErrPeerEndpointUnauthorized) {
		t.Fatalf("unauthorized SetPreferredEndpoint() error = %v", err)
	}
	if err := engine.RestorePreferredEndpoint(snapshot.Revision, snapshot.Peers[0].ID+1); !errors.Is(
		err,
		ErrPeerEndpointUnavailable,
	) {
		t.Fatalf("unknown RestorePreferredEndpoint() error = %v", err)
	}
	if device.configureCalls != 1 {
		t.Fatalf("rejected updates changed device, configure calls = %d", device.configureCalls)
	}
}

func TestWireGuardEngineEquivalentMapRevisionPreservesPreferredEndpoint(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	preferred := netip.MustParseAddrPort("192.168.1.21:41641")
	snapshot.Peers[0].Endpoints = append(snapshot.Peers[0].Endpoints, preferred)
	opener := &wireGuardTUNOpener{}
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(
		opener,
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if err := engine.SetPreferredEndpoint(snapshot.Revision, snapshot.Peers[0].ID, preferred); err != nil {
		t.Fatalf("SetPreferredEndpoint() error = %v", err)
	}
	snapshot.Revision++
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply(new revision) error = %v", err)
	}
	if device.configureCalls != 2 {
		t.Fatalf("equivalent revision configure calls = %d, want 2", device.configureCalls)
	}
	if paths := engine.PeerPaths(); paths.DirectCount != 1 || paths.RelayCount != 0 {
		t.Fatalf("equivalent revision PeerPaths() = %#v, want direct", paths)
	}
	if err := engine.RestorePreferredEndpoint(snapshot.Revision, snapshot.Peers[0].ID); err != nil {
		t.Fatalf("RestorePreferredEndpoint() error = %v", err)
	}
	if device.configureCalls != 3 {
		t.Fatalf("restored base configure calls = %d, want 3", device.configureCalls)
	}
	if opener.calls != 1 || device.upCalls != 1 || device.closeCalls != 0 {
		t.Fatalf(
			"map revision reset recreated tunnel: open=%d up=%d close=%d",
			opener.calls,
			device.upCalls,
			device.closeCalls,
		)
	}
}

func TestWireGuardEngineRelayBaseChangePreservesPreferredEndpoint(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot = addTestRelay(snapshot)
	snapshot.Relays[2] = testRelayRegion(2, "relay-2.example.com")
	preferred := snapshot.Peers[0].Endpoints[0]
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(
		&wireGuardTUNOpener{},
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if err := engine.SetPreferredEndpoint(
		snapshot.Revision,
		snapshot.Peers[0].ID,
		preferred,
	); err != nil {
		t.Fatalf("SetPreferredEndpoint() error = %v", err)
	}

	snapshot.Revision++
	snapshot.Peers[0].HomeRelay = 2
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply(relay base change) error = %v", err)
	}
	paths := engine.PeerPaths()
	if device.configureCalls != 2 || paths.DirectCount != 1 ||
		paths.RelayCount != 0 || paths.RelayFallbackCount != 0 {
		t.Fatalf(
			"relay base change configure=%d paths=%#v, want preserved direct path",
			device.configureCalls,
			paths,
		)
	}

	peerKey, err := parseNodePublicKey(snapshot.Peers[0].PublicKey)
	if err != nil {
		t.Fatalf("parseNodePublicKey() error = %v", err)
	}
	wantRelay := formatRelayEndpoint(2, relay.Key(peerKey))
	if err := engine.RestorePreferredEndpoint(
		snapshot.Revision,
		snapshot.Peers[0].ID,
	); err != nil {
		t.Fatalf("RestorePreferredEndpoint() error = %v", err)
	}
	if device.configureCalls != 3 ||
		!strings.Contains(device.configurations[2], "endpoint="+wantRelay+"\n") {
		t.Fatalf("restored relay configuration = %q", device.configuration)
	}
}

func TestWireGuardEngineNewEquivalentRevisionPreservesSocket(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	opener := &wireGuardTUNOpener{}
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(
		opener,
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	oldRevision := snapshot.Revision
	snapshot.Revision++
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply(new revision) error = %v", err)
	}
	if device.configureCalls != 1 || opener.calls != 1 || device.upCalls != 1 ||
		device.closeCalls != 0 {
		t.Fatalf(
			"equivalent revision changed tunnel: configure=%d open=%d up=%d close=%d",
			device.configureCalls,
			opener.calls,
			device.upCalls,
			device.closeCalls,
		)
	}
	if err := engine.SetPreferredEndpoint(
		oldRevision,
		snapshot.Peers[0].ID,
		snapshot.Peers[0].Endpoints[0],
	); !errors.Is(err, ErrPeerEndpointGeneration) {
		t.Fatalf("old-revision SetPreferredEndpoint() error = %v", err)
	}
	if err := engine.SetPreferredEndpoint(
		snapshot.Revision,
		snapshot.Peers[0].ID,
		snapshot.Peers[0].Endpoints[0],
	); err != nil {
		t.Fatalf("current-revision SetPreferredEndpoint() error = %v", err)
	}
}

func TestWireGuardEngineEndpointAuthorityChangePreservesPeerSession(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot = addTestRelay(snapshot)
	opener := &wireGuardTUNOpener{}
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(
		opener,
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	oldEndpoint := snapshot.Peers[0].Endpoints[0]
	newEndpoint := netip.MustParseAddrPort("198.51.100.44:41641")
	snapshot.Revision++
	snapshot.Peers[0].Endpoints = []netip.AddrPort{newEndpoint}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply(authority change) error = %v", err)
	}
	if device.configureCalls != 1 {
		t.Fatalf(
			"authority change replaced peer session: configure calls = %d",
			device.configureCalls,
		)
	}
	if opener.calls != 1 || device.upCalls != 1 || device.closeCalls != 0 {
		t.Fatalf(
			"authority change recreated tunnel: open=%d up=%d close=%d",
			opener.calls,
			device.upCalls,
			device.closeCalls,
		)
	}
	if err := engine.SetPreferredEndpoint(
		snapshot.Revision,
		snapshot.Peers[0].ID,
		oldEndpoint,
	); err != nil {
		// A public endpoint the map no longer lists stays usable once the
		// path controller has authenticated proof for it (disco-v2 §4.1).
		t.Fatalf("removed endpoint SetPreferredEndpoint() error = %v", err)
	}
	if err := engine.SetPreferredEndpoint(
		snapshot.Revision,
		snapshot.Peers[0].ID,
		newEndpoint,
	); err != nil {
		t.Fatalf("new endpoint SetPreferredEndpoint() error = %v", err)
	}
}

func TestWireGuardEngineEndpointAuthorityChangeResetsSelectedPath(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot = addTestRelay(snapshot)
	preferred := snapshot.Peers[0].Endpoints[0]
	opener := &wireGuardTUNOpener{}
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(
		opener,
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if err := engine.SetPreferredEndpoint(snapshot.Revision, snapshot.Peers[0].ID, preferred); err != nil {
		t.Fatalf("SetPreferredEndpoint() error = %v", err)
	}
	snapshot.Revision++
	snapshot.Peers[0].Endpoints = []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.45:41641"),
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply(authority change) error = %v", err)
	}
	if device.configureCalls != 3 || !strings.Contains(
		device.configurations[2],
		"update_only=true",
	) || strings.Contains(device.configurations[2], "replace_peers=true") {
		t.Fatalf("authority change configuration = %q", device.configuration)
	}
	paths := engine.PeerPaths()
	if paths.RelayCount != 1 || paths.DirectCount != 0 {
		t.Fatalf("PeerPaths() = %#v, want relay reset", paths)
	}
	if opener.calls != 1 || device.upCalls != 1 || device.closeCalls != 0 {
		t.Fatalf(
			"authority change recreated tunnel: open=%d up=%d close=%d",
			opener.calls,
			device.upCalls,
			device.closeCalls,
		)
	}
}

func TestWireGuardEngineDiscoveryIdentityChangeResetsPeerSession(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Peers[0].DiscoveryKey = "discokey:" + strings.Repeat("11", 32)
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(
		&wireGuardTUNOpener{},
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	snapshot.Revision++
	snapshot.Peers[0].DiscoveryKey = "discokey:" + strings.Repeat("22", 32)
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply(discovery identity change) error = %v", err)
	}
	if device.configureCalls != 2 {
		t.Fatalf(
			"discovery identity change configure calls = %d, want 2",
			device.configureCalls,
		)
	}
	reset := device.configurations[1]
	if strings.Count(reset, "public_key=") != 2 ||
		!strings.Contains(reset, "remove=true") ||
		!strings.Contains(reset, "replace_allowed_ips=true") ||
		strings.Contains(reset, "replace_peers=true") {
		t.Fatalf("discovery identity change configuration = %q", reset)
	}
	preferred := snapshot.Peers[0].Endpoints[0]
	if err := engine.SetPreferredEndpoint(
		snapshot.Revision,
		snapshot.Peers[0].ID,
		preferred,
	); err != nil {
		t.Fatalf("SetPreferredEndpoint() error = %v", err)
	}
	if device.configureCalls != 3 {
		t.Fatalf("authenticated path configure calls = %d, want 3", device.configureCalls)
	}
	readinessReset := device.configurations[2]
	if strings.Count(readinessReset, "public_key=") != 2 ||
		!strings.Contains(readinessReset, "remove=true") ||
		!strings.Contains(readinessReset, "endpoint="+preferred.String()) ||
		strings.Contains(readinessReset, "update_only=true") {
		t.Fatalf("authenticated path configuration = %q", readinessReset)
	}
	if err := engine.SetPreferredEndpoint(
		snapshot.Revision,
		snapshot.Peers[0].ID,
		preferred,
	); err != nil {
		t.Fatalf("SetPreferredEndpoint(reassert) error = %v", err)
	}
	if device.configureCalls != 4 ||
		!strings.Contains(device.configurations[3], "update_only=true") ||
		strings.Contains(device.configurations[3], "remove=true") {
		t.Fatalf("authenticated path reassertion = %q", device.configurations[3])
	}
}

func TestWireGuardEngineClosesWhenPeerSessionResetFails(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Peers[0].DiscoveryKey = "discokey:" + strings.Repeat("11", 32)
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(
		&wireGuardTUNOpener{},
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	device.configureErr = errors.New("test peer reset failure")
	snapshot.Revision++
	snapshot.Peers[0].DiscoveryKey = "discokey:" + strings.Repeat("22", 32)
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err == nil {
		t.Fatal("Apply(discovery identity change) error = nil")
	}
	if device.configureCalls != 2 || device.closeCalls != 1 || engine.device != nil ||
		engine.appliedRevision != 0 {
		t.Fatalf(
			"failed peer reset calls=%d close=%d device=%#v revision=%d",
			device.configureCalls,
			device.closeCalls,
			engine.device,
			engine.appliedRevision,
		)
	}
}

func TestWireGuardEngineClosesWhenReadinessSessionResetFails(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Peers[0].DiscoveryKey = "discokey:" + strings.Repeat("11", 32)
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(
		&wireGuardTUNOpener{},
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	snapshot.Revision++
	snapshot.Peers[0].DiscoveryKey = "discokey:" + strings.Repeat("22", 32)
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply(discovery identity change) error = %v", err)
	}
	device.configureErr = errors.New("test readiness reset failure")
	if err := engine.SetPreferredEndpoint(
		snapshot.Revision,
		snapshot.Peers[0].ID,
		snapshot.Peers[0].Endpoints[0],
	); err == nil {
		t.Fatal("SetPreferredEndpoint() error = nil")
	}
	if device.configureCalls != 3 || device.closeCalls != 1 || engine.device != nil ||
		engine.appliedRevision != 0 {
		t.Fatalf(
			"failed readiness reset calls=%d close=%d device=%#v revision=%d",
			device.configureCalls,
			device.closeCalls,
			engine.device,
			engine.appliedRevision,
		)
	}
}

func TestWireGuardEngineClosesWhenEndpointAuthorityResetFails(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	preferred := netip.MustParseAddrPort("192.168.1.23:41641")
	snapshot.Peers[0].Endpoints = append(snapshot.Peers[0].Endpoints, preferred)
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(
		&wireGuardTUNOpener{},
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if err := engine.SetPreferredEndpoint(snapshot.Revision, snapshot.Peers[0].ID, preferred); err != nil {
		t.Fatalf("SetPreferredEndpoint() error = %v", err)
	}
	device.configureErr = errors.New("test reset failure")
	snapshot.Revision++
	snapshot.Peers[0].Endpoints = snapshot.Peers[0].Endpoints[:1]
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err == nil {
		t.Fatal("Apply(authority change) error = nil")
	}
	if device.configureCalls != 3 || device.closeCalls != 1 || engine.device != nil ||
		engine.appliedRevision != 0 {
		t.Fatalf(
			"failed revision reset calls=%d close=%d device=%#v revision=%d",
			device.configureCalls,
			device.closeCalls,
			engine.device,
			engine.appliedRevision,
		)
	}
}

func TestWireGuardEngineClosesAfterPeerEndpointConfigureFailure(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	preferred := netip.MustParseAddrPort("192.168.1.22:41641")
	snapshot.Peers[0].Endpoints = append(snapshot.Peers[0].Endpoints, preferred)
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(
		&wireGuardTUNOpener{},
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	device.configureErr = errors.New("test update failure")
	if err := engine.SetPreferredEndpoint(snapshot.Revision, snapshot.Peers[0].ID, preferred); err == nil {
		t.Fatal("SetPreferredEndpoint() error = nil")
	}
	if device.closeCalls != 1 || engine.device != nil || engine.appliedRevision != 0 {
		t.Fatalf(
			"failed update close calls=%d device=%#v revision=%d",
			device.closeCalls,
			engine.device,
			engine.appliedRevision,
		)
	}
}

func TestWireGuardEngineReplacesSignedRoutesInPlace(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	opener := &wireGuardTUNOpener{}
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(
		opener,
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if state, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil || state != StateEncrypted {
		t.Fatalf("initial Apply() = %q, %v", state, err)
	}

	newRoute := netip.MustParsePrefix("100.64.0.5/32")
	snapshot.Peers[0].Addresses = []netip.Prefix{newRoute}
	snapshot.Peers[0].AllowedIPs = []netip.Prefix{newRoute}
	snapshot.Policy[0].Sources[0].Prefix = newRoute
	if state, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil || state != StateEncrypted {
		t.Fatalf("changed Apply() = %q, %v", state, err)
	}
	if opener.calls != 1 || opener.updateCalls != 1 || device.closeCalls != 0 ||
		device.upCalls != 1 {
		t.Fatalf(
			"changed calls open=%d update=%d close=%d up=%d",
			opener.calls,
			opener.updateCalls,
			device.closeCalls,
			device.upCalls,
		)
	}
	if !slices.Equal(opener.config.Routes, []netip.Prefix{newRoute}) {
		t.Fatalf("changed helper routes = %#v", opener.config.Routes)
	}
}

func TestWireGuardEngineFailsClosedWhenRouteReplacementFails(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	opener := &wireGuardTUNOpener{}
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(
		opener,
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("initial Apply() error = %v", err)
	}
	opener.updateErr = errors.New("injected route failure")
	snapshot.Revision++
	snapshot.Peers = nil
	snapshot.Policy = nil
	state, err := engine.Apply(t.Context(), snapshot, privateKey)
	if err == nil || state != StateFailed {
		t.Fatalf("Apply() = %q, %v, want failed", state, err)
	}
	if opener.calls != 1 || opener.updateCalls != 1 || device.closeCalls != 1 ||
		engine.device != nil {
		t.Fatalf(
			"failed transition open=%d update=%d close=%d device=%#v",
			opener.calls,
			opener.updateCalls,
			device.closeCalls,
			engine.device,
		)
	}
}

func TestWireGuardEngineWaitsForEndpoint(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Peers[0].Endpoints = nil
	opener := &wireGuardTUNOpener{}
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(
		opener,
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	state, err := engine.Apply(t.Context(), snapshot, privateKey)
	if err != nil || state != StateWaitingEndpoint || opener.calls != 1 {
		t.Fatalf("Apply() = %q, %v, opens=%d", state, err, opener.calls)
	}
	if device.upCalls != 1 || device.configureCalls != 1 {
		t.Fatalf(
			"device calls up=%d configure=%d",
			device.upCalls,
			device.configureCalls,
		)
	}
	if strings.Contains(device.configuration, "endpoint=") {
		t.Fatalf("pending configuration contains endpoint: %q", device.configuration)
	}
	if !strings.Contains(device.configuration, "allowed_ip=100.64.0.4/32") {
		t.Fatalf("pending configuration is missing peer route: %q", device.configuration)
	}
}

func TestWireGuardEngineDiscoversOnActiveDevice(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Peers[0].Endpoints = nil
	server := netip.MustParseAddrPort("192.0.2.10:3478")
	candidate, err := pathdiscovery.NewCandidate(
		netip.MustParseAddrPort("198.51.100.20:41641"),
		pathdiscovery.SourceServerReflexive,
	)
	if err != nil {
		t.Fatalf("NewCandidate() error = %v", err)
	}
	candidates, err := pathdiscovery.NewSet([]pathdiscovery.Candidate{candidate})
	if err != nil {
		t.Fatalf("NewSet() error = %v", err)
	}
	device := &fakeWireGuardDevice{
		discoverySocket: pathdiscovery.Socket{Port: 41641, Generation: 3},
		discoveryResult: pathdiscovery.DiscoveryResult{
			Scope:      7,
			Socket:     pathdiscovery.Socket{Port: 41641, Generation: 3},
			Candidates: candidates,
		},
	}
	engine, err := newWireGuardEngine(
		&wireGuardTUNOpener{},
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	engine.hostAddresses = func() ([]netip.Addr, error) { return nil, nil }
	if got := engine.DiscoverySocket(); got != device.discoverySocket {
		t.Fatalf("DiscoverySocket() = %#v, want %#v", got, device.discoverySocket)
	}

	result, err := engine.DiscoverEndpoints(t.Context(), 7, []netip.AddrPort{server})
	if err != nil {
		t.Fatalf("DiscoverEndpoints() error = %v", err)
	}
	if result.Scope != 7 || !result.Candidates.Equal(candidates) {
		t.Fatalf("DiscoverEndpoints() = %#v", result)
	}
	if device.discoveryScope != 7 || !slices.Equal(device.discoveryServers, []netip.AddrPort{server}) {
		t.Fatalf(
			"device discovery scope=%d servers=%v",
			device.discoveryScope,
			device.discoveryServers,
		)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := engine.DiscoverySocket(); got.IsOpen() {
		t.Fatalf("DiscoverySocket() after Close = %#v", got)
	}
}

func TestWireGuardEngineRejectsDiscoveryWithoutActiveDevice(t *testing.T) {
	t.Parallel()

	engine, err := newWireGuardEngine(
		&wireGuardTUNOpener{},
		41641,
		&fakeWireGuardFactory{},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.DiscoverEndpoints(
		t.Context(),
		1,
		[]netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:3478")},
	); err == nil {
		t.Fatal("DiscoverEndpoints() error = nil")
	}
}

func TestWireGuardEngineExposesSharedPeerProbeTransport(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	device := &fakeWireGuardDevice{
		discoverySocket: pathdiscovery.Socket{Port: 41641, Generation: 4},
	}
	engine, err := newWireGuardEngine(
		&wireGuardTUNOpener{},
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	handler := &recordingDatagramHandler{}
	if err := engine.SetPeerProbeHandler(handler); err != nil {
		t.Fatalf("SetPeerProbeHandler() error = %v", err)
	}
	packet := []byte{1, 2, 3}
	destination := netip.MustParseAddrPort("203.0.113.40:41641")
	socket, err := engine.SendDatagram(packet, destination)
	if err != nil {
		t.Fatalf("SendDatagram() error = %v", err)
	}
	if socket != device.discoverySocket || engine.Socket() != device.discoverySocket ||
		device.peerHandler != handler || device.peerDestination != destination ||
		!slices.Equal(device.peerPacket, packet) {
		t.Fatalf(
			"peer transport socket=%#v handler=%#v destination=%v packet=%v",
			socket,
			device.peerHandler,
			device.peerDestination,
			device.peerPacket,
		)
	}
	if err := engine.SetPeerProbeHandler(nil); err != nil || device.peerHandler != nil {
		t.Fatalf("SetPeerProbeHandler(nil) error=%v handler=%#v", err, device.peerHandler)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := engine.SetPeerProbeHandler(nil); err != nil {
		t.Fatalf("SetPeerProbeHandler(nil) after Close error = %v", err)
	}
	if _, err := engine.SendDatagram(packet, destination); err == nil {
		t.Fatal("SendDatagram() after Close error = nil")
	}
}

func TestWireGuardEnginePublishesHostCandidateWhenSTUNIsUnavailable(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Peers[0].Endpoints = nil
	socket := pathdiscovery.Socket{Port: 41641, Generation: 4}
	device := &fakeWireGuardDevice{
		discoverySocket: socket,
		discoveryErr:    pathdiscovery.ErrNoSTUNResponse,
	}
	engine, err := newWireGuardEngine(
		&wireGuardTUNOpener{},
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	engine.hostAddresses = func() ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("192.168.1.20"),
			snapshot.Self.Addresses[0].Addr(),
		}, nil
	}

	result, err := engine.DiscoverEndpoints(
		t.Context(),
		9,
		[]netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:3478")},
	)
	if err != nil {
		t.Fatalf("DiscoverEndpoints() error = %v", err)
	}
	want := netip.MustParseAddrPort("192.168.1.20:41641")
	got := result.Candidates.Candidates()
	if result.Scope != 9 || result.Socket != socket || len(got) != 1 ||
		got[0].Endpoint() != want || got[0].Source() != pathdiscovery.SourceHost {
		t.Fatalf("DiscoverEndpoints() = %#v, candidates %#v", result, got)
	}
}

func TestWireGuardEnginePublishesHostCandidateWithoutSTUNServer(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Peers[0].Endpoints = nil
	socket := pathdiscovery.Socket{Port: 41641, Generation: 5}
	device := &fakeWireGuardDevice{discoverySocket: socket}
	engine, err := newWireGuardEngine(
		&wireGuardTUNOpener{},
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	engine.hostAddresses = func() ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.168.1.21")}, nil
	}

	result, err := engine.DiscoverEndpoints(t.Context(), 10, nil)
	if err != nil {
		t.Fatalf("DiscoverEndpoints() error = %v", err)
	}
	if got := result.Candidates.Endpoints(); !slices.Equal(got, []netip.AddrPort{
		netip.MustParseAddrPort("192.168.1.21:41641"),
	}) {
		t.Fatalf("DiscoverEndpoints() candidates = %v", got)
	}
	if device.discoveryCalls != 0 {
		t.Fatalf("device discovery calls = %d, want 0", device.discoveryCalls)
	}
}

func TestWireGuardEngineAcceptsNarrowPolicy(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Policy[0].Protocols = []uint8{6}
	snapshot.Policy[0].Destinations[0].PortFrom = 18080
	snapshot.Policy[0].Destinations[0].PortTo = 18080
	opener := &wireGuardTUNOpener{}
	engine, err := newWireGuardEngine(
		opener,
		41641,
		&fakeWireGuardFactory{},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	state, err := engine.Apply(t.Context(), snapshot, privateKey)
	if err != nil || state != StateEncrypted || opener.calls != 1 {
		t.Fatalf("Apply() = %q, %v, opens=%d", state, err, opener.calls)
	}
}

func TestWireGuardEngineStartsForOutboundOnlyNode(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Policy = []networkmap.Rule{}
	opener := &wireGuardTUNOpener{}
	engine, err := newWireGuardEngine(
		opener,
		41641,
		&fakeWireGuardFactory{},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	state, err := engine.Apply(t.Context(), snapshot, privateKey)
	if err != nil || state != StateEncrypted || opener.calls != 1 {
		t.Fatalf("Apply() = %q, %v, opens=%d", state, err, opener.calls)
	}
}

func TestNodePrivateKeyFormattingIsRedacted(t *testing.T) {
	t.Parallel()

	key := NodePrivateKey{1, 2, 3}
	if strings.Contains(key.String(), "1") || strings.Contains(key.GoString(), "1") {
		t.Fatal("node private key formatting disclosed key bytes")
	}
}

func TestWireGuardEngineUsesRelayBeforeAuthenticatedDirectPath(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot = addTestRelay(snapshot)
	opener := &wireGuardTUNOpener{}
	device := &fakeWireGuardDevice{}
	factory := &fakeWireGuardFactory{device: device}
	engine, err := newWireGuardEngine(opener, 41641, factory, nil)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	state, err := engine.Apply(t.Context(), snapshot, privateKey)
	if err != nil || state != StateEncryptedRelay {
		t.Fatalf("Apply() = %q, %v", state, err)
	}
	peerKey, err := parseNodePublicKey(snapshot.Peers[0].PublicKey)
	if err != nil {
		t.Fatalf("parseNodePublicKey() error = %v", err)
	}
	relayEndpoint := formatRelayEndpoint(1, relay.Key(peerKey))
	if !strings.Contains(device.configuration, "endpoint="+relayEndpoint+"\n") {
		t.Fatalf("initial configuration = %q, want relay endpoint", device.configuration)
	}
	directEndpoint := snapshot.Peers[0].Endpoints[0]
	if strings.Contains(device.configuration, "endpoint="+directEndpoint.String()+"\n") {
		t.Fatalf("initial configuration selected unproven direct endpoint: %q", device.configuration)
	}
	if factory.relayFingerprint == ([32]byte{}) {
		t.Fatal("factory did not receive relay authority")
	}
	if paths := engine.PeerPaths(); !paths.Available || paths.PeerCount != 1 ||
		paths.RelayCount != 1 || paths.DirectCount != 0 || paths.PendingCount != 0 {
		t.Fatalf("initial PeerPaths() = %#v, want one relay path", paths)
	}

	if err := engine.SetPreferredEndpoint(
		snapshot.Revision,
		snapshot.Peers[0].ID,
		directEndpoint,
	); err != nil {
		t.Fatalf("SetPreferredEndpoint() error = %v", err)
	}
	if !strings.Contains(device.configuration, "endpoint="+directEndpoint.String()+"\n") {
		t.Fatalf("preferred configuration = %q", device.configuration)
	}
	if paths := engine.PeerPaths(); paths.DirectCount != 1 ||
		paths.RelayCount != 0 || paths.PendingCount != 0 {
		t.Fatalf("preferred PeerPaths() = %#v, want one direct path", paths)
	}
	if err := engine.RestorePreferredEndpoint(
		snapshot.Revision,
		snapshot.Peers[0].ID,
	); err != nil {
		t.Fatalf("RestorePreferredEndpoint() error = %v", err)
	}
	if !strings.Contains(device.configuration, "endpoint="+relayEndpoint+"\n") {
		t.Fatalf("restored configuration = %q", device.configuration)
	}
	if paths := engine.PeerPaths(); paths.RelayCount != 1 ||
		paths.DirectCount != 0 || paths.PendingCount != 0 {
		t.Fatalf("restored PeerPaths() = %#v, want one relay path", paths)
	}
}

func TestWireGuardEngineReportsRelayFirstPromotionTiming(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot = addTestRelay(snapshot)
	now := time.Date(2026, time.September, 27, 14, 0, 0, 0, time.UTC)
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(
		&wireGuardTUNOpener{},
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	engine.clock = func() time.Time { return now }
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	paths := engine.PeerPaths()
	if paths.RelayBootstrapCount != 1 || paths.DirectPromotionCount != 0 ||
		paths.RelayFallbackCount != 0 || paths.LastDirectPromotion != 0 ||
		paths.MaxDirectPromotion != 0 {
		t.Fatalf("initial PeerPaths() = %#v", paths)
	}

	now = now.Add(250 * time.Millisecond)
	if err := engine.SetPreferredEndpoint(
		snapshot.Revision,
		snapshot.Peers[0].ID,
		snapshot.Peers[0].Endpoints[0],
	); err != nil {
		t.Fatalf("SetPreferredEndpoint() error = %v", err)
	}
	paths = engine.PeerPaths()
	if paths.DirectPromotionCount != 1 ||
		paths.LastDirectPromotion != 250*time.Millisecond ||
		paths.MaxDirectPromotion != 250*time.Millisecond {
		t.Fatalf("promoted PeerPaths() = %#v", paths)
	}
	snapshot.Revision++
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply(equivalent revision) error = %v", err)
	}
	paths = engine.PeerPaths()
	if paths.DirectCount != 1 || paths.RelayCount != 0 ||
		paths.DirectPromotionCount != 1 || paths.RelayFallbackCount != 0 ||
		device.configureCalls != 2 {
		t.Fatalf("equivalent revision PeerPaths() = %#v, configure calls = %d", paths, device.configureCalls)
	}
	if err := engine.SetPreferredEndpoint(
		snapshot.Revision,
		snapshot.Peers[0].ID,
		snapshot.Peers[0].Endpoints[0],
	); err != nil {
		t.Fatalf("repeated SetPreferredEndpoint() error = %v", err)
	}
	paths = engine.PeerPaths()
	if paths.DirectPromotionCount != 1 ||
		paths.LastDirectPromotion != 250*time.Millisecond ||
		paths.MaxDirectPromotion != 250*time.Millisecond {
		t.Fatalf("reasserted PeerPaths() = %#v", paths)
	}

	now = now.Add(500 * time.Millisecond)
	if err := engine.RestorePreferredEndpoint(
		snapshot.Revision,
		snapshot.Peers[0].ID,
	); err != nil {
		t.Fatalf("RestorePreferredEndpoint() error = %v", err)
	}
	paths = engine.PeerPaths()
	if paths.RelayFallbackCount != 1 {
		t.Fatalf("fallback PeerPaths() = %#v", paths)
	}

	now = now.Add(200 * time.Millisecond)
	if err := engine.SetPreferredEndpoint(
		snapshot.Revision,
		snapshot.Peers[0].ID,
		snapshot.Peers[0].Endpoints[0],
	); err != nil {
		t.Fatalf("second SetPreferredEndpoint() error = %v", err)
	}
	paths = engine.PeerPaths()
	if paths.DirectPromotionCount != 2 ||
		paths.LastDirectPromotion != 200*time.Millisecond ||
		paths.MaxDirectPromotion != 250*time.Millisecond {
		t.Fatalf("re-promoted PeerPaths() = %#v", paths)
	}
}

func TestWireGuardEnginePeerPathsUnavailableAfterClose(t *testing.T) {
	t.Parallel()

	engine := &WireGuardEngine{
		device: &fakeWireGuardDevice{},
		peers: map[uint64]wireGuardPeerState{
			1: {currentEndpoint: "not-an-endpoint", currentPath: peerPathPending},
		},
	}
	paths := engine.PeerPaths()
	if !paths.Available || paths.PeerCount != 1 || paths.PendingCount != 1 {
		t.Fatalf("PeerPaths() = %#v, want one pending path", paths)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if paths := engine.PeerPaths(); paths != (PeerPathSnapshot{}) {
		t.Fatalf("PeerPaths() after Close = %#v, want unavailable", paths)
	}
}

func TestWireGuardEnginePreparesAuthorizedRelayBeforeSelection(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot = addTestRelay(snapshot)
	snapshot.Relays[2] = testRelayRegion(2, "relay-2.example.com")
	now := time.Now()
	device := &fakeWireGuardDevice{relayHealth: relay.HealthSnapshot{
		Available:  true,
		HomeRegion: 1,
		Regions: []relay.RegionHealth{{
			RegionID:      1,
			Connected:     true,
			LastConnected: now,
			LastActivity:  now,
		}},
	}}
	factory := &fakeWireGuardFactory{device: device}
	engine, err := newWireGuardEngine(
		&wireGuardTUNOpener{},
		41641,
		factory,
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !slices.Equal(factory.relayRegions, []int{1, 2}) {
		t.Fatalf("relay authority regions = %v, want [1 2]", factory.relayRegions)
	}
	health := engine.RelayHealth()
	if !health.Available || health.HomeRegion != 1 || len(health.Regions) != 1 {
		t.Fatalf("RelayHealth() = %#v", health)
	}
	health.Regions[0].Connected = false
	if !engine.RelayHealth().Regions[0].Connected {
		t.Fatal("RelayHealth() returned mutable device state")
	}
	// The device's relay failures reach the engine's long-lived channel,
	// and repeated failures coalesce into one pending signal.
	if device.relayFailureHook == nil || !device.hookBeforeUp {
		t.Fatal("Apply() did not install the relay failure hook before Up")
	}
	device.relayFailureHook()
	device.relayFailureHook()
	select {
	case <-engine.RelayFailures():
	default:
		t.Fatal("relay failure did not reach RelayFailures()")
	}
	select {
	case <-engine.RelayFailures():
		t.Fatal("relay failures did not coalesce")
	default:
	}
	if err := engine.PrepareRelayRegion(2); err != nil {
		t.Fatalf("PrepareRelayRegion() error = %v", err)
	}
	if !slices.Equal(device.preparedRelays, []int{2}) {
		t.Fatalf("prepared relay regions = %v", device.preparedRelays)
	}
}

func TestWireGuardEngineFallsBackToDirectWithoutUsableRelay(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Relays = map[int]networkmap.RelayRegion{
		1: {
			ID: 1,
			Nodes: []networkmap.RelayNode{{
				Name:      "stun-only",
				HostName:  "relay.example.com",
				STUNOnly:  true,
				RelayPort: 443,
			}},
		},
	}
	snapshot.Self.HomeRelay = 1
	snapshot.Peers[0].HomeRelay = 1
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(
		&wireGuardTUNOpener{},
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	state, err := engine.Apply(t.Context(), snapshot, privateKey)
	if err != nil || state != StateEncrypted {
		t.Fatalf("Apply() = %q, %v", state, err)
	}
	if !strings.Contains(
		device.configuration,
		"endpoint="+snapshot.Peers[0].Endpoints[0].String()+"\n",
	) {
		t.Fatalf("configuration = %q, want direct endpoint", device.configuration)
	}
}

func TestWireGuardEngineSelectsDeterministicRelayFallback(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Relays = map[int]networkmap.RelayRegion{
		2: testRelayRegion(2, "relay-2.example.com"),
		1: testRelayRegion(1, "relay-1.example.com"),
	}
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(
		&wireGuardTUNOpener{},
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	state, err := engine.Apply(t.Context(), snapshot, privateKey)
	if err != nil || state != StateEncryptedRelay {
		t.Fatalf("Apply() = %q, %v", state, err)
	}
	peerKey, err := parseNodePublicKey(snapshot.Peers[0].PublicKey)
	if err != nil {
		t.Fatalf("parseNodePublicKey() error = %v", err)
	}
	wantEndpoint := formatRelayEndpoint(1, relay.Key(peerKey))
	if !strings.Contains(device.configuration, "endpoint="+wantEndpoint+"\n") {
		t.Fatalf("configuration = %q, want %q", device.configuration, wantEndpoint)
	}
}

func TestWireGuardEngineReopensOnRelayAuthorityChange(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot = addTestRelay(snapshot)
	opener := &wireGuardTUNOpener{}
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(
		opener,
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("first Apply() error = %v", err)
	}
	snapshot.Revision++
	region := snapshot.Relays[1]
	region.Nodes[0].HostName = "relay-2.example.com"
	snapshot.Relays[1] = region
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("second Apply() error = %v", err)
	}
	if opener.calls != 2 || device.closeCalls != 1 || device.upCalls != 2 {
		t.Fatalf(
			"authority change calls open=%d close=%d up=%d, want 2/1/2",
			opener.calls,
			device.closeCalls,
			device.upCalls,
		)
	}
}

func TestWireGuardEngineMovesHomeRelayWithoutReopening(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot = addTestRelay(snapshot)
	snapshot.Relays[2] = testRelayRegion(2, "relay-2.example.com")
	opener := &wireGuardTUNOpener{}
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(opener, 41641, &fakeWireGuardFactory{device: device}, nil)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("first Apply() error = %v", err)
	}
	snapshot.Revision++
	snapshot.Self.HomeRelay = 2
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("second Apply() error = %v", err)
	}
	if opener.calls != 1 || device.closeCalls != 0 || device.upCalls != 1 {
		t.Fatalf("home change calls open=%d close=%d up=%d, want 1/0/1", opener.calls, device.closeCalls, device.upCalls)
	}
	if device.relayUpdateCalls != 1 || device.relayHome != 2 {
		t.Fatalf("relay authority updates = %d home %d, want 1 and 2", device.relayUpdateCalls, device.relayHome)
	}
}

func addTestRelay(snapshot networkmap.Snapshot) networkmap.Snapshot {
	snapshot.Self.HomeRelay = 1
	snapshot.Peers[0].HomeRelay = 1
	snapshot.Relays = map[int]networkmap.RelayRegion{
		1: {
			ID:   1,
			Code: "test",
			Name: "Test Relay",
			Nodes: []networkmap.RelayNode{{
				Name:      "relay-1",
				HostName:  "relay.example.com",
				RelayPort: 443,
				UDPPort:   3479,
				RelayKey:  [32]byte{0x01},
			}},
		},
	}

	return snapshot
}

func testRelayRegion(id int, hostName string) networkmap.RelayRegion {
	return networkmap.RelayRegion{
		ID:   id,
		Code: fmt.Sprintf("test-%d", id),
		Name: fmt.Sprintf("Test Relay %d", id),
		Nodes: []networkmap.RelayNode{{
			Name:      fmt.Sprintf("relay-%d", id),
			HostName:  hostName,
			RelayPort: 443,
			UDPPort:   3479,
			RelayKey:  sha256.Sum256([]byte(hostName)),
		}},
	}
}

func testWireGuardSnapshot(t *testing.T) (NodePrivateKey, networkmap.Snapshot) {
	t.Helper()

	privateKey := NodePrivateKey{}
	for index := range privateKey {
		privateKey[index] = byte(index + 1)
	}
	peerPrivate := make([]byte, 32)
	for index := range peerPrivate {
		peerPrivate[index] = byte(index + 33)
	}
	curve := ecdh.X25519()
	self, err := curve.NewPrivateKey(privateKey[:])
	if err != nil {
		t.Fatalf("NewPrivateKey(self) error = %v", err)
	}
	peer, err := curve.NewPrivateKey(peerPrivate)
	if err != nil {
		t.Fatalf("NewPrivateKey(peer) error = %v", err)
	}
	publicText := func(value []byte) string {
		return "nodekey:" + hex.EncodeToString(value)
	}
	selfAddress := netip.MustParsePrefix("100.64.0.3/32")
	peerAddress := netip.MustParsePrefix("100.64.0.4/32")

	return privateKey, networkmap.Snapshot{
		Revision: 1,
		Self: networkmap.Node{
			ID:        1,
			PublicKey: publicText(self.PublicKey().Bytes()),
			Addresses: []netip.Prefix{selfAddress},
		},
		Peers: []networkmap.Node{{
			ID:                2,
			PublicKey:         publicText(peer.PublicKey().Bytes()),
			Addresses:         []netip.Prefix{peerAddress},
			AllowedIPs:        []netip.Prefix{peerAddress},
			Endpoints:         []netip.AddrPort{netip.MustParseAddrPort("203.0.113.20:41641")},
			MachineAuthorized: true,
		}},
		Policy: []networkmap.Rule{{
			Sources: []networkmap.Selector{{
				Kind:   networkmap.SelectorPrefix,
				Prefix: peerAddress,
			}},
			Destinations: []networkmap.Destination{{
				Selector: networkmap.Selector{
					Kind:   networkmap.SelectorPrefix,
					Prefix: selfAddress,
				},
				PortFrom: 0,
				PortTo:   65535,
			}},
		}},
	}
}

type wireGuardTUNOpener struct {
	calls       int
	updateCalls int
	updateErr   error
	config      netadmin.TUNConfig
}

func (o *wireGuardTUNOpener) ConfigureTUNRoutes(
	_ context.Context,
	config netadmin.TUNConfig,
) error {
	o.updateCalls++
	if o.updateErr != nil {
		return o.updateErr
	}
	o.config = netadmin.TUNConfig{
		Addresses: append([]netip.Prefix{}, config.Addresses...),
		Routes:    append([]netip.Prefix{}, config.Routes...),
	}

	return nil
}

func (o *wireGuardTUNOpener) OpenTUN(
	_ context.Context,
	config netadmin.TUNConfig,
) (netadmin.TUN, error) {
	o.calls++
	o.config = netadmin.TUNConfig{
		Addresses: append([]netip.Prefix{}, config.Addresses...),
		Routes:    append([]netip.Prefix{}, config.Routes...),
	}
	file, err := os.Open(os.DevNull)
	if err != nil {
		return netadmin.TUN{}, err
	}

	return netadmin.TUN{
		File:      file,
		Name:      "mesh0",
		MTU:       1280,
		Addresses: append([]netip.Prefix{}, config.Addresses...),
		Routes:    append([]netip.Prefix{}, config.Routes...),
	}, nil
}

type fakeWireGuardFactory struct {
	device           *fakeWireGuardDevice
	relayFingerprint [32]byte
	relayRegions     []int
}

func (f *fakeWireGuardFactory) New(
	_ context.Context,
	_ netadmin.TUN,
	_ *policyFilter,
	_ PacketObserver,
	relayConfig *relay.Config,
) (wireGuardDevice, error) {
	if relayConfig != nil {
		f.relayFingerprint = relay.Fingerprint(*relayConfig)
		f.relayRegions = f.relayRegions[:0]
		for regionID := range relayConfig.Regions {
			f.relayRegions = append(f.relayRegions, regionID)
		}
		slices.Sort(f.relayRegions)
	} else {
		f.relayFingerprint = [32]byte{}
		f.relayRegions = nil
	}
	if f.device == nil {
		f.device = &fakeWireGuardDevice{}
	}

	return f.device, nil
}

type fakeWireGuardDevice struct {
	relayFailureHook func()
	hookBeforeUp     bool
	configuration    string
	configurations   []string
	configureErr     error
	configureCalls   int
	upCalls          int
	closeCalls       int
	discoveryScope   uint64
	discoveryServers []netip.AddrPort
	discoverySocket  pathdiscovery.Socket
	discoveryResult  pathdiscovery.DiscoveryResult
	discoveryErr     error
	discoveryCalls   int
	peerHandler      pathdiscovery.DatagramHandler
	peerPacket       []byte
	peerDestination  netip.AddrPort
	relayHealth      relay.HealthSnapshot
	preparedRelays   []int
	relayPeers       []relay.Peer
	relayHome        int
	relayUpdateCalls int
	relayUpdateErr   error
}

func (d *fakeWireGuardDevice) Configure(configuration io.Reader) error {
	d.configureCalls++
	encoded, err := io.ReadAll(configuration)
	if err != nil {
		return err
	}
	d.configuration = string(encoded)
	d.configurations = append(d.configurations, d.configuration)

	return d.configureErr
}

func (d *fakeWireGuardDevice) Up() error {
	d.upCalls++
	d.hookBeforeUp = d.relayFailureHook != nil

	return nil
}

func (d *fakeWireGuardDevice) Close() { d.closeCalls++ }

func (d *fakeWireGuardDevice) DiscoverySocket() pathdiscovery.Socket {
	return d.discoverySocket
}

func (d *fakeWireGuardDevice) DiscoverEndpoints(
	_ context.Context,
	scope uint64,
	servers []netip.AddrPort,
) (pathdiscovery.DiscoveryResult, error) {
	d.discoveryCalls++
	d.discoveryScope = scope
	d.discoveryServers = append([]netip.AddrPort(nil), servers...)

	return d.discoveryResult, d.discoveryErr
}

func (d *fakeWireGuardDevice) Socket() pathdiscovery.Socket {
	return d.discoverySocket
}

func (d *fakeWireGuardDevice) SendDatagram(
	packet []byte,
	destination netip.AddrPort,
) (pathdiscovery.Socket, error) {
	d.peerPacket = append([]byte(nil), packet...)
	d.peerDestination = destination

	return d.discoverySocket, nil
}

func (d *fakeWireGuardDevice) SetPeerProbeHandler(
	handler pathdiscovery.DatagramHandler,
) {
	d.peerHandler = handler
}

func (d *fakeWireGuardDevice) RelayHealth() relay.HealthSnapshot {
	health := d.relayHealth
	health.Regions = append([]relay.RegionHealth(nil), d.relayHealth.Regions...)

	return health
}

func (d *fakeWireGuardDevice) SetRelayFailureHook(hook func()) {
	d.relayFailureHook = hook
}

func (d *fakeWireGuardDevice) PrepareRelayRegion(regionID int) error {
	d.preparedRelays = append(d.preparedRelays, regionID)

	return nil
}

func (d *fakeWireGuardDevice) ReplaceRelayAuthority(homeRegion int, peers []relay.Peer) error {
	d.relayUpdateCalls++
	d.relayHome = homeRegion
	d.relayPeers = append([]relay.Peer(nil), peers...)

	return d.relayUpdateErr
}

// TestWireGuardEngineInstallsAggregatedPeerRoutes: contiguous peer addresses
// become one route, and the route covers no address that is not a peer.
func TestWireGuardEngineInstallsAggregatedPeerRoutes(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	curve := ecdh.X25519()
	for index, address := range []string{"100.64.0.5/32", "100.64.0.6/32", "100.64.0.7/32"} {
		key, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey() error = %v", err)
		}
		prefix := netip.MustParsePrefix(address)
		peer := snapshot.Peers[0]
		peer.ID = uint64(10 + index)
		peer.PublicKey = "nodekey:" + hex.EncodeToString(key.PublicKey().Bytes())
		peer.Addresses = []netip.Prefix{prefix}
		peer.AllowedIPs = []netip.Prefix{prefix}
		snapshot.Peers = append(snapshot.Peers, peer)
	}
	opener := &wireGuardTUNOpener{}
	engine, err := newWireGuardEngine(opener, 41641, &fakeWireGuardFactory{device: &fakeWireGuardDevice{}}, nil)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if state, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil || state != StateEncrypted {
		t.Fatalf("Apply() = %q, %v", state, err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("100.64.0.4/30")}
	if !slices.Equal(opener.config.Routes, want) {
		t.Fatalf("helper routes = %v, want %v", opener.config.Routes, want)
	}
}
