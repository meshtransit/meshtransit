package portmap

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// natpmpGateway is a NAT-PMP server (RFC 6886) for tests.
type natpmpGateway struct {
	epoch    uint32
	external netip.Addr
	port     uint16 // external port granted; zero grants the suggested one
	result   uint16 // result code for mapping requests
	deleted  []uint16
}

func (g *natpmpGateway) handle(request []byte, to netip.AddrPort) []datagram {
	if to != netip.AddrPortFrom(testGateway.Addr, gatewayPort) || len(request) < 2 || request[0] != 0 {
		return nil
	}
	switch request[1] {
	case natpmpOpExternal:
		reply := make([]byte, 12)
		reply[1] = natpmpResponseBit | natpmpOpExternal
		binary.BigEndian.PutUint32(reply[4:8], g.epoch)
		external := g.external.As4()
		copy(reply[8:12], external[:])

		return []datagram{fromGateway(reply)}
	case natpmpOpMapUDP:
		internal := binary.BigEndian.Uint16(request[4:6])
		suggested := binary.BigEndian.Uint16(request[6:8])
		lifetime := binary.BigEndian.Uint32(request[8:12])
		reply := make([]byte, 16)
		reply[1] = natpmpResponseBit | natpmpOpMapUDP
		binary.BigEndian.PutUint16(reply[2:4], g.result)
		binary.BigEndian.PutUint32(reply[4:8], g.epoch)
		binary.BigEndian.PutUint16(reply[8:10], internal)
		if lifetime == 0 {
			g.deleted = append(g.deleted, internal)
		} else {
			granted := suggested
			if g.port != 0 {
				granted = g.port
			}
			binary.BigEndian.PutUint16(reply[10:12], granted)
		}
		binary.BigEndian.PutUint32(reply[12:16], lifetime)
		// A stray reply for another port comes first; the client skips it.
		stray := append([]byte(nil), reply...)
		binary.BigEndian.PutUint16(stray[8:10], internal+1)

		return []datagram{fromGateway(stray), fromGateway(reply)}
	}

	return nil
}

func TestNATPMPMapsChecksAndRemoves(t *testing.T) {
	t.Parallel()
	clock := newFixedClock()
	gateway := &natpmpGateway{epoch: 1000, external: testExternal, port: 40001}
	network := &fakeNet{handler: gateway.handle}
	c := natpmpClient{listen: network.listen, clock: clock.Now}

	mapping, err := c.mapPort(context.Background(), testGateway, 41641, nil)
	if err != nil {
		t.Fatal(err)
	}
	if mapping.External != netip.AddrPortFrom(testExternal, 40001) || mapping.Lifetime != DefaultLifetime ||
		mapping.Protocol != ProtocolNATPMP || !mapping.PublicExternal() {
		t.Fatalf("mapping %+v", mapping)
	}
	// A renewal asks for the external port it already holds.
	gateway.port = 0
	renewed, err := c.mapPort(context.Background(), testGateway, 41641, &mapping)
	if err != nil || renewed.External.Port() != 40001 {
		t.Fatalf("renewal %+v %v", renewed, err)
	}

	clock.Advance(100 * time.Second)
	gateway.epoch = 1100
	if held, err := c.check(context.Background(), mapping); err != nil || !held {
		t.Fatalf("check after 100 s: %v %v", held, err)
	}
	gateway.epoch = 5 // the gateway restarted and forgot its mappings
	if held, _ := c.check(context.Background(), mapping); held {
		t.Fatal("a restarted gateway still holds the mapping")
	}

	if err := c.unmap(context.Background(), mapping); err != nil {
		t.Fatal(err)
	}
	if len(gateway.deleted) != 1 || gateway.deleted[0] != 41641 {
		t.Fatalf("deleted %v", gateway.deleted)
	}
}

func TestNATPMPErrors(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		result uint16
		want   error
	}{
		"refused":     {result: 2, want: ErrRefused},
		"old version": {result: natpmpResultBadVersion, want: ErrUnsupported},
	} {
		gateway := &natpmpGateway{epoch: 1, external: testExternal, result: test.result}
		network := &fakeNet{handler: gateway.handle}
		c := natpmpClient{listen: network.listen, clock: time.Now}
		if _, err := c.mapPort(context.Background(), testGateway, 41641, nil); !errors.Is(err, test.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Silence, or replies from another address, mean no NAT-PMP there.
	foreign := &fakeNet{handler: func([]byte, netip.AddrPort) []datagram {
		reply := make([]byte, 12)
		reply[1] = natpmpResponseBit
		return []datagram{{payload: reply, from: netip.MustParseAddrPort("192.168.1.66:5351")}}
	}}
	c := natpmpClient{listen: foreign.listen, clock: time.Now}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.mapPort(ctx, testGateway, 41641, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("foreign replies: %v", err)
	}
}

func TestEpochConsistent(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		previous, current uint32
		elapsed           time.Duration
		want              bool
	}{
		{1000, 1100, 100 * time.Second, true},
		{1000, 1092, 100 * time.Second, true}, // within 1/16 + 2 s
		{1000, 1080, 100 * time.Second, false},
		{1000, 1300, 100 * time.Second, false}, // the gateway's clock ran away
		{1000, 998, time.Second, false},
		{1000, 1000, time.Second, true},
	} {
		if got := epochConsistent(test.previous, test.current, test.elapsed); got != test.want {
			t.Errorf("%d → %d after %s: %v", test.previous, test.current, test.elapsed, got)
		}
	}
}

func FuzzParseNATPMP(f *testing.F) {
	f.Add([]byte{0, 128, 0, 0, 0, 0, 0, 1, 203, 0, 113, 7})
	f.Add([]byte{0, 129, 0, 0, 0, 0, 0, 1, 0xa2, 0xa9, 0x9c, 0x41, 0, 0, 0x1c, 0x20})
	f.Fuzz(func(t *testing.T, b []byte) {
		if external, ok, err := parseNATPMPExternal(b); ok && err == nil && !external.external.Is4() {
			t.Fatal("non-IPv4 external address")
		}
		_, _, _ = parseNATPMPMap(b)
	})
}
