package portmap

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"meshtransit.net/test/natlab"
)

// servePCP runs a PCP MAP server on the home router of node: requests become
// explicit mappings on the lab NAT, as on a real router.
func servePCP(t *testing.T, lab *natlab.Lab, node natlab.HomeNode) {
	t.Helper()
	gateway, err := lab.Net.NewHost("gateway", node.LAN, natlab.HomeGateway)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := gateway.Listen(gatewayPort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	started := time.Now()
	go func() {
		buffer := make([]byte, maxDatagram)
		for {
			n, source, err := conn.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			request := buffer[:n]
			if n != pcpHeaderLen+pcpMapLen || request[0] != pcpVersion || request[1] != pcpOpMap {
				continue
			}
			client := netip.AddrFrom16([16]byte(request[8:24])).Unmap()
			if client != source.Addr() {
				continue // a real server answers ADDRESS_MISMATCH
			}
			lifetime := binary.BigEndian.Uint32(request[4:8])
			payload := request[pcpHeaderLen:]
			internal := netip.AddrPortFrom(client, binary.BigEndian.Uint16(payload[16:18]))
			reply := make([]byte, pcpHeaderLen, pcpHeaderLen+pcpMapLen)
			reply[0], reply[1] = pcpVersion, pcpResponseBit|pcpOpMap
			binary.BigEndian.PutUint32(reply[8:12], uint32(time.Since(started)/time.Second)) //nolint:gosec // G115: test epoch
			reply = append(reply, payload...)
			if lifetime == 0 {
				node.Router.RemovePortMapping(internal)
			} else {
				external, err := node.Router.AddPortMapping(internal, binary.BigEndian.Uint16(payload[18:20]),
					time.Duration(lifetime)*time.Second)
				if err != nil {
					reply[3] = 8 // NO_RESOURCES
				} else {
					binary.BigEndian.PutUint32(reply[4:8], lifetime)
					binary.BigEndian.PutUint16(reply[pcpHeaderLen+18:], external.Port())
					address := external.Addr().As16()
					copy(reply[pcpHeaderLen+20:], address[:])
				}
			}
			_, _ = conn.WriteToUDPAddrPort(reply, source)
		}
	}()
}

// received reports whether conn receives a datagram within a short wait.
func received(t *testing.T, conn *natlab.Conn) bool {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	_, _, err := conn.ReadFromUDPAddrPort(buffer)

	return err == nil
}

// TestMapperOpensASymmetricNAT maps the packet port through a symmetric NAT
// with the real PCP client: before the mapping, nothing from the Internet
// reaches the host; with it, any Internet host does; after the mapper stops,
// the gateway has removed it again.
func TestMapperOpensASymmetricNAT(t *testing.T) {
	t.Parallel()
	lab, err := natlab.NewLab(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lab.Close)
	node, err := lab.AddHomeNode("home", natlab.SymmetricRandom)
	if err != nil {
		t.Fatal(err)
	}
	servePCP(t, lab, node)
	packets, err := node.Host.Listen(41641)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packets.Close() })
	internet, err := lab.Net.NewHost("peer", lab.Net.Internet, netip.MustParseAddr("198.51.100.200"))
	if err != nil {
		t.Fatal(err)
	}
	peer, err := internet.Listen(7000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })

	if _, err := peer.WriteToUDPAddrPort([]byte("x"), netip.AddrPortFrom(node.Router.External(), 41641)); err != nil {
		t.Fatal(err)
	}
	if received(t, packets) {
		t.Fatal("the symmetric NAT let an unsolicited packet in")
	}

	var nextPort atomic.Uint32
	nextPort.Store(50000)
	mapper := New(Options{
		Gateway: func() (Gateway, error) { return Gateway{Addr: natlab.HomeGateway, Local: natlab.LANHost}, nil },
		Listen: func(context.Context, netip.Addr) (PacketConn, error) {
			return node.Host.Listen(uint16(nextPort.Add(1))) //nolint:gosec // G115: test ports stay below 65535
		},
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		mapper.Run(ctx)
	}()
	mapper.SetPort(41641)
	deadline := time.Now().Add(5 * time.Second)
	for mapper.Status().State != StateMapped {
		if time.Now().After(deadline) {
			t.Fatalf("no mapping: %+v", mapper.Status())
		}
		time.Sleep(5 * time.Millisecond)
	}
	external, ok := mapper.Candidate()
	if !ok || external.Addr() != node.Router.External() || mapper.Status().Protocol != ProtocolPCP {
		t.Fatalf("candidate %s %v, status %+v", external, ok, mapper.Status())
	}
	if _, err := peer.WriteToUDPAddrPort([]byte("x"), external); err != nil {
		t.Fatal(err)
	}
	if !received(t, packets) {
		t.Fatal("the mapped endpoint is not reachable from the Internet")
	}

	cancel()
	<-done
	if _, err := peer.WriteToUDPAddrPort([]byte("x"), external); err != nil {
		t.Fatal(err)
	}
	if received(t, packets) {
		t.Fatal("the mapping survived the mapper")
	}
}
