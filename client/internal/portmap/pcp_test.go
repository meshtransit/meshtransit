package portmap

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"
)

// pcpGateway is a PCP server (RFC 6887) for tests. It checks every request
// field a real server checks.
type pcpGateway struct {
	t        *testing.T
	epoch    uint32
	external netip.AddrPort
	result   uint8
	natpmp   bool // answer like a NAT-PMP-only gateway
	nonces   [][12]byte
	deleted  int
}

func (g *pcpGateway) handle(request []byte, to netip.AddrPort) []datagram {
	if to != netip.AddrPortFrom(testGateway.Addr, gatewayPort) {
		return nil
	}
	if g.natpmp {
		return []datagram{fromGateway([]byte{0, 128 | request[1], 0, natpmpResultBadVersion, 0, 0, 0, 1})}
	}
	if len(request) < pcpHeaderLen || request[0] != pcpVersion {
		g.t.Errorf("malformed pcp request % x", request)
		return nil
	}
	if client := netip.AddrFrom16([16]byte(request[8:24])); client.Unmap() != testGateway.Local || !client.Is4In6() {
		g.t.Errorf("pcp client address %s", client)
	}
	reply := make([]byte, pcpHeaderLen, pcpHeaderLen+pcpMapLen)
	reply[0], reply[1], reply[3] = pcpVersion, pcpResponseBit|request[1], g.result
	binary.BigEndian.PutUint32(reply[8:12], g.epoch)
	if request[1] == pcpOpAnnounce {
		return []datagram{fromGateway(reply)}
	}
	if request[1] != pcpOpMap || len(request) != pcpHeaderLen+pcpMapLen {
		g.t.Errorf("unexpected pcp request % x", request)
		return nil
	}
	payload := request[pcpHeaderLen:]
	if payload[12] != pcpProtocolUDP {
		g.t.Errorf("pcp protocol %d", payload[12])
	}
	lifetime := binary.BigEndian.Uint32(request[4:8])
	g.nonces = append(g.nonces, [12]byte(payload[0:12]))
	if lifetime == 0 {
		g.deleted++
	} else if g.result == pcpResultSuccess {
		binary.BigEndian.PutUint32(reply[4:8], lifetime)
	}
	response := slices.Concat(reply, payload)
	if g.result == pcpResultSuccess && lifetime != 0 && g.external.IsValid() {
		binary.BigEndian.PutUint16(response[pcpHeaderLen+18:], g.external.Port())
		external := g.external.Addr().As16()
		copy(response[pcpHeaderLen+20:], external[:])
	}
	// A reply carrying another nonce comes first; the client skips it.
	stray := append([]byte(nil), response...)
	stray[pcpHeaderLen] ^= 0xff

	return []datagram{fromGateway(stray), fromGateway(response)}
}

func TestPCPMapsRenewsChecksAndRemoves(t *testing.T) {
	t.Parallel()
	clock := newFixedClock()
	gateway := &pcpGateway{t: t, epoch: 500, external: netip.AddrPortFrom(testExternal, 50000)}
	network := &fakeNet{handler: gateway.handle}
	c := pcpClient{listen: network.listen, clock: clock.Now}

	mapping, err := c.mapPort(context.Background(), testGateway, 41641, nil)
	if err != nil {
		t.Fatal(err)
	}
	if mapping.External != gateway.external || mapping.Lifetime != DefaultLifetime || mapping.Protocol != ProtocolPCP {
		t.Fatalf("mapping %+v", mapping)
	}
	if _, err := c.mapPort(context.Background(), testGateway, 41641, &mapping); err != nil {
		t.Fatal(err)
	}
	if len(gateway.nonces) != 2 || gateway.nonces[0] != gateway.nonces[1] {
		t.Fatal("a renewal must reuse the mapping nonce")
	}

	clock.Advance(time.Minute)
	gateway.epoch = 560
	if held, err := c.check(context.Background(), mapping); err != nil || !held {
		t.Fatalf("check: %v %v", held, err)
	}
	gateway.epoch = 3
	if held, _ := c.check(context.Background(), mapping); held {
		t.Fatal("a restarted gateway still holds the mapping")
	}
	if err := c.unmap(context.Background(), mapping); err != nil || gateway.deleted != 1 {
		t.Fatalf("unmap: %v (deleted %d)", err, gateway.deleted)
	}
}

func TestPCPErrors(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		gateway pcpGateway
		want    error
	}{
		"nat-pmp only":     {gateway: pcpGateway{natpmp: true}, want: ErrUnsupported},
		"address mismatch": {gateway: pcpGateway{result: pcpResultMismatch}, want: ErrRefused},
		"not authorized":   {gateway: pcpGateway{result: 2}, want: ErrRefused},
		"no external":      {gateway: pcpGateway{}, want: ErrInvalidResponse},
	} {
		gateway := test.gateway
		gateway.t = t
		network := &fakeNet{handler: gateway.handle}
		c := pcpClient{listen: network.listen, clock: time.Now}
		if _, err := c.mapPort(context.Background(), testGateway, 41641, nil); !errors.Is(err, test.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func FuzzParsePCPResponse(f *testing.F) {
	seed := make([]byte, pcpHeaderLen+pcpMapLen)
	seed[0], seed[1] = pcpVersion, pcpResponseBit|pcpOpMap
	f.Add(seed)
	f.Add([]byte{0, 129, 0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, opcode := range []uint8{pcpOpAnnounce, pcpOpMap} {
			response, ok, err := parsePCPResponse(b, opcode)
			if ok && err == nil && opcode == pcpOpMap && !response.hasPayload {
				t.Fatal("successful map response without payload")
			}
		}
	})
}
