package dataplane

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/packetmeta"
)

// testExitRules let the peer 100.64.0.4 reach TCP 443 on the Internet.
func testExitRules() []networkmap.Rule {
	return []networkmap.Rule{{
		Sources: []networkmap.Selector{{Kind: networkmap.SelectorPrefix, Prefix: netip.MustParsePrefix("100.64.0.4/32")}},
		Destinations: []networkmap.Destination{
			{
				Selector: networkmap.Selector{Kind: networkmap.SelectorPrefix, Prefix: netip.MustParsePrefix("0.0.0.0/0")},
				PortFrom: 443, PortTo: 443,
			},
			{
				Selector: networkmap.Selector{Kind: networkmap.SelectorPrefix, Prefix: netip.MustParsePrefix("::/0")},
				PortFrom: 443, PortTo: 443,
			},
		},
		Protocols: []uint8{packetmeta.ProtocolTCP},
	}}
}

func TestPolicyFilterForwardsToTheInternetAsAnExitNode(t *testing.T) {
	t.Parallel()
	filter := newPolicyFilter()
	filter.UpdateNetwork(testRouterSnapshot())
	peer, public, lan := [4]byte{100, 64, 0, 4}, [4]byte{8, 8, 8, 8}, [4]byte{10, 99, 0, 1}
	own := [4]byte{45, 76, 10, 10}
	toInternet := testIPv4TransportPacket(peer, public, 40000, 443, packetmeta.ProtocolTCP, 0x02)
	if filter.Allow(PacketInbound, toInternet) {
		t.Fatal("the Internet was reached before the helper forwarded as an exit node")
	}
	filter.SetExitInstalled(testExitRules(), []netip.Addr{netip.AddrFrom4(own)}, 2)
	if !filter.Allow(PacketInbound, toInternet) {
		t.Fatal("an allowed packet to the Internet was denied")
	}
	for name, packet := range map[string][]byte{
		"another port":       testIPv4TransportPacket(peer, public, 40000, 80, packetmeta.ProtocolTCP, 0x02),
		"a LAN address":      testIPv4TransportPacket(peer, lan, 40000, 443, packetmeta.ProtocolTCP, 0x02),
		"cloud metadata":     testIPv4TransportPacket(peer, [4]byte{169, 254, 169, 254}, 40000, 443, packetmeta.ProtocolTCP, 0x02),
		"its own public":     testIPv4TransportPacket(peer, own, 40000, 443, packetmeta.ProtocolTCP, 0x02),
		"another consumer":   testIPv4TransportPacket([4]byte{100, 64, 0, 9}, public, 40000, 443, packetmeta.ProtocolTCP, 0x02),
		"the mesh itself":    testIPv4TransportPacket(peer, [4]byte{100, 64, 0, 3}, 40000, 443, packetmeta.ProtocolTCP, 0x02),
		"a served Site port": testIPv4TransportPacket(peer, [4]byte{10, 35, 0, 4}, 40000, 22, packetmeta.ProtocolTCP, 0x02),
	} {
		if filter.Allow(PacketInbound, packet) {
			t.Errorf("%s was forwarded", name)
		}
	}
	// The Internet answers the consumer; a LAN host never speaks to it.
	if !filter.Allow(PacketOutbound, reverseTestPacket(toInternet)) {
		t.Fatal("the Internet's answer was denied")
	}
	if filter.Allow(PacketOutbound, testIPv4TransportPacket(lan, peer, 443, 40000, packetmeta.ProtocolTCP, 0x12)) {
		t.Fatal("a LAN host reached the mesh through the exit node")
	}
	filter.SetExitInstalled(nil, nil, 0)
	if filter.Allow(PacketInbound, toInternet) {
		t.Fatal("the Internet was reached after the exit node stopped")
	}
}

func TestExitFilterBoundsItsConsumers(t *testing.T) {
	t.Parallel()
	exit := exitFilter{maxConsumers: 1, consumers: map[netip.Addr]time.Time{}}
	now := time.Date(2026, time.October, 20, 12, 0, 0, 0, time.UTC)
	first, second := netip.MustParseAddr("100.64.0.4"), netip.MustParseAddr("100.64.0.5")
	if !exit.admitConsumer(first, now) || exit.admitConsumer(second, now) || !exit.admitConsumer(first, now) {
		t.Fatal("the consumer limit is not enforced")
	}
	if !exit.admitConsumer(second, now.Add(exitConsumerIdle+time.Second)) {
		t.Fatal("an idle consumer still counts")
	}
}

type exitTUNOpener struct {
	wireGuardTUNOpener
	mu       sync.Mutex
	requests []netadmin.ExitRequest
	refused  string
}

func (o *exitTUNOpener) SetServedExit(_ context.Context, request netadmin.ExitRequest) (netadmin.ExitServing, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.requests = append(o.requests, request)
	if !request.Serve {
		return netadmin.ExitServing{}, nil
	}
	if o.refused != "" {
		return netadmin.ExitServing{Refused: o.refused}, nil
	}
	return netadmin.ExitServing{
		Serving: true, ConntrackPerConsumer: min(request.ConntrackPerConsumer, 4096),
		MaxConsumers: 8,
	}, nil
}

func (o *exitTUNOpener) sent() []netadmin.ExitRequest {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]netadmin.ExitRequest{}, o.requests...)
}

func TestWireGuardEngineServesTheExitPoolThroughTheHelper(t *testing.T) {
	t.Parallel()
	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.ServedExits = []networkmap.ServedExit{{
		Ref: "p-main", ConntrackPerConsumer: 16384,
		Rules: testExitRules(),
	}}
	opener := &exitTUNOpener{}
	engine, err := newWireGuardEngine(opener, 41641, &fakeWireGuardFactory{device: &fakeWireGuardDevice{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the exit node to serve", func() bool { return engine.ExitNode().Serving })
	if requests := opener.sent(); len(requests) != 1 || !requests[0].Serve || requests[0].ConntrackPerConsumer != 16384 {
		t.Fatalf("requests = %+v", requests)
	}
	if status := engine.ExitNode(); status.Pool != "p-main" || status.ConntrackPerConsumer != 4096 ||
		status.MaxConsumers != 8 || status.Error != "" {
		t.Fatalf("ExitNode() = %+v", status)
	}
	snapshot.Revision++
	snapshot.ServedExits = nil
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the exit node to stop", func() bool { return !engine.ExitNode().Serving })
	if requests := opener.sent(); len(requests) != 2 || requests[1].Serve {
		t.Fatalf("requests = %+v", requests)
	}
}

func TestWireGuardEngineReportsAnExitNodeTheHostRefuses(t *testing.T) {
	t.Parallel()
	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.ServedExits = []networkmap.ServedExit{{Ref: "p-main", ConntrackPerConsumer: 16384, Rules: testExitRules()}}
	opener := &exitTUNOpener{refused: netadmin.ExitRefusedOff}
	engine, err := newWireGuardEngine(opener, 41641, &fakeWireGuardFactory{device: &fakeWireGuardDevice{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the refusal", func() bool { return engine.ExitNode().Refused == netadmin.ExitRefusedOff })
	engine.filter.mu.Lock()
	active := engine.filter.exit.active
	engine.filter.mu.Unlock()
	if active {
		t.Fatal("the filter admits exit traffic the host refuses")
	}
}

// checkingExitOpener also answers the health check with the exit node's
// forwarding.
type checkingExitOpener struct {
	exitTUNOpener
}

func (o *checkingExitOpener) CheckServedRoutes(context.Context) (netadmin.ServedHealth, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	health := netadmin.ServedHealth{}
	if len(o.requests) != 0 && o.requests[len(o.requests)-1].Serve && o.refused == "" {
		health.Exit = netadmin.ExitServing{Serving: true, ConntrackPerConsumer: 4096, MaxConsumers: 8}
	} else if o.refused != "" {
		health.Exit = netadmin.ExitServing{Refused: o.refused}
	}
	return health, nil
}

func TestWireGuardEngineMeasuresTheServedExitPool(t *testing.T) {
	t.Parallel()
	for _, refused := range []string{"", netadmin.ExitRefusedOff} {
		privateKey, snapshot := testWireGuardSnapshot(t)
		snapshot.ServedExits = []networkmap.ServedExit{{Ref: "p-main", ConntrackPerConsumer: 16384, Rules: testExitRules()}}
		opener := &checkingExitOpener{exitTUNOpener{refused: refused}}
		engine, err := newWireGuardEngine(opener, 41641, &fakeWireGuardFactory{device: &fakeWireGuardDevice{}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		want := ExitHealth{State: SiteHealthOK, Code: SiteCodeOK}
		if refused != "" {
			want = ExitHealth{State: SiteHealthFailed, Code: ExitCodeNotOffered}
		}
		if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "the pool's health", func() bool {
			health := engine.ExitNode().Health
			return health != nil && *health == want
		})
		// The pool gone ends the measurement.
		snapshot.Revision++
		snapshot.ServedExits = nil
		if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "the health to clear", func() bool { return engine.ExitNode().Health == nil })
		_ = engine.Close()
	}
}

// The host's public addresses, as peers see them, are no Internet for its
// consumers: sent to the helper and refused by layer 1. Private ones are not
// sent.
func TestWireGuardEngineLeavesItsPublicAddressesOut(t *testing.T) {
	t.Parallel()
	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.ServedExits = []networkmap.ServedExit{{Ref: "p-main", ConntrackPerConsumer: 16384, Rules: testExitRules()}}
	opener := &exitTUNOpener{}
	engine, err := newWireGuardEngine(opener, 41641, &fakeWireGuardFactory{device: &fakeWireGuardDevice{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the exit node to serve", func() bool { return engine.ExitNode().Serving })
	public := netip.MustParseAddr("34.1.2.3")
	engine.SetExitPublicAddresses([]netip.Addr{public, netip.MustParseAddr("192.168.1.20"), public})
	waitFor(t, "the public address to reach the helper", func() bool {
		requests := opener.sent()
		last := requests[len(requests)-1]
		return len(last.Excluded) == 1 && last.Excluded[0] == netip.PrefixFrom(public, 32)
	})
	waitFor(t, "layer 1 to refuse it", func() bool {
		return !engine.filter.Allow(PacketInbound,
			testIPv4TransportPacket([4]byte{100, 64, 0, 4}, public.As4(), 40000, 443, packetmeta.ProtocolTCP, 0x02))
	})
	count := len(opener.sent())
	engine.SetExitPublicAddresses([]netip.Addr{public})
	if len(opener.sent()) != count {
		t.Fatal("an unchanged public address was sent again")
	}
}
