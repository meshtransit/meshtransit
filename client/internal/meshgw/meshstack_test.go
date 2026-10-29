package meshgw

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// The gateway's stack keeps its own TCP sizes, not gVisor's 1 MiB
// (TD-CLI-82).
func TestMeshStackBufferSizes(t *testing.T) {
	t.Parallel()
	stack, err := newMeshStack([]netip.Addr{gatewayAddr}, netstackMTU, DefaultTCPBuffers())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stack.Close() }()
	var receive tcpip.TCPReceiveBufferSizeRangeOption
	var send tcpip.TCPSendBufferSizeRangeOption
	var moderate tcpip.TCPModerateReceiveBufferOption
	for _, option := range []tcpip.GettableTransportProtocolOption{&receive, &send, &moderate} {
		if err := stack.stack.TransportProtocolOption(tcp.ProtocolNumber, option); err != nil {
			t.Fatal(err)
		}
	}
	if receive.Max != tcpReceiveBuffer || receive.Default != tcpReceiveBuffer || send.Max != tcpSendBuffer ||
		send.Default != tcpSendBuffer || bool(moderate) {
		t.Fatalf("receive %+v, send %+v, moderate %t", receive, send, moderate)
	}
}

// A cluster's sizes reach the stack, and sizes out of bounds are refused
// (K1c Q88).
func TestMeshStackConfiguredBuffers(t *testing.T) {
	t.Parallel()
	buffers := TCPBuffers{Receive: 1 << 20, Send: 512 << 10}
	stack, err := newMeshStack([]netip.Addr{gatewayAddr}, netstackMTU, buffers)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stack.Close() }()
	var receive tcpip.TCPReceiveBufferSizeRangeOption
	var send tcpip.TCPSendBufferSizeRangeOption
	for _, option := range []tcpip.GettableTransportProtocolOption{&receive, &send} {
		if err := stack.stack.TransportProtocolOption(tcp.ProtocolNumber, option); err != nil {
			t.Fatal(err)
		}
	}
	if receive.Max != buffers.Receive || send.Max != buffers.Send || stack.receive != buffers.Receive {
		t.Fatalf("receive %+v, send %+v, listener %d", receive, send, stack.receive)
	}
	for _, bad := range []TCPBuffers{{}, {Receive: 1 << 20}, {Receive: 8 << 20, Send: 96 << 10}} {
		if _, err := newMeshStack([]netip.Addr{gatewayAddr}, netstackMTU, bad); err == nil {
			t.Errorf("%+v taken", bad)
		}
	}
}

// An accepted connection probes an idle peer.
func TestMeshStackKeepAlive(t *testing.T) {
	t.Parallel()
	stack, err := newMeshStack([]netip.Addr{gatewayAddr}, netstackMTU, DefaultTCPBuffers())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stack.Close() }()
	var queue waiter.Queue
	endpoint, tcpErr := stack.stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &queue)
	if tcpErr != nil {
		t.Fatal(tcpErr)
	}
	defer endpoint.Close()
	keepAlive(endpoint)
	var idle tcpip.KeepaliveIdleOption
	var interval tcpip.KeepaliveIntervalOption
	_ = endpoint.GetSockOpt(&idle)
	_ = endpoint.GetSockOpt(&interval)
	count, _ := endpoint.GetSockOptInt(tcpip.KeepaliveCountOption)
	if !endpoint.SocketOptions().GetKeepAlive() || time.Duration(idle) != keepaliveIdle ||
		time.Duration(interval) != keepaliveInterval || count != keepaliveCount {
		t.Fatalf("keepalive %t, idle %s, interval %s, count %d", endpoint.SocketOptions().GetKeepAlive(),
			time.Duration(idle), time.Duration(interval), count)
	}
}

// The stack carries a connection both ways through the data plane's TUN,
// and its listener stops on Close.
func TestMeshStackCarriesAConnection(t *testing.T) {
	t.Parallel()
	stacks := newTestStacks(t)
	clientDevice, clientNet := newClient(t)
	w := newWire(t, clientDevice)
	w.attach(openTUN(t, stacks, gatewayConfig(gatewayAddr)))
	current, _ := stacks.Current()
	listener, err := current.Net.ListenTCPAddrPort(netip.AddrPortFrom(gatewayAddr, 443))
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		defer func() { _ = conn.Close() }()
		got, _ := io.ReadAll(conn)
		accepted <- got
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn, err := clientNet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(gatewayAddr, 443))
	if err != nil {
		t.Fatal(err)
	}
	sent := bytes.Repeat([]byte("mesh"), 200_000) // past the receive buffer
	if _, err := conn.Write(sent); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	select {
	case got := <-accepted:
		if !bytes.Equal(got, sent) {
			t.Fatalf("got %d bytes, sent %d", len(got), len(sent))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("nothing accepted")
	}
	_ = listener.Close()
	_ = listener.Close() // twice is fine
	if _, err := listener.Accept(); err == nil {
		t.Fatal("accepted after close")
	}
}

// DialUDPAddrPort sends datagrams from the stack, for tests.
func (s *meshStack) DialUDPAddrPort(local, remote netip.AddrPort) (net.Conn, error) {
	var localFull *tcpip.FullAddress
	protocol := tcpip.NetworkProtocolNumber(ipv4.ProtocolNumber)
	if remote.Addr().Is6() {
		protocol = ipv6.ProtocolNumber
	}
	if local.IsValid() {
		localFull = &tcpip.FullAddress{
			NIC: nicID, Addr: tcpip.AddrFromSlice(local.Addr().AsSlice()),
			Port: local.Port(),
		}
	}
	remoteFull := &tcpip.FullAddress{
		NIC: nicID, Addr: tcpip.AddrFromSlice(remote.Addr().AsSlice()),
		Port: remote.Port(),
	}
	return gonet.DialUDP(s.stack, localFull, remoteFull, protocol)
}

// An accepted connection holds keepalive and the stack's buffer sizes;
// found among the stack's endpoints, so Accept dropping keepAlive fails it.
func TestMeshStackAcceptedEndpoint(t *testing.T) {
	t.Parallel()
	stacks := newTestStacks(t)
	clientDevice, clientNet := newClient(t)
	w := newWire(t, clientDevice)
	w.attach(openTUN(t, stacks, gatewayConfig(gatewayAddr)))
	current, _ := stacks.Current()
	listener, err := current.Net.ListenTCPAddrPort(netip.AddrPortFrom(gatewayAddr, 443))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := listener.Accept()
		accepted <- conn
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, err := clientNet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(gatewayAddr, 443))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	conn := <-accepted
	if conn == nil {
		t.Fatal("nothing accepted")
	}
	defer func() { _ = conn.Close() }()
	found := false
	for _, registered := range current.Net.stack.RegisteredEndpoints() {
		endpoint, ok := registered.(tcpip.Endpoint)
		if !ok {
			continue
		}
		info, ok := endpoint.Info().(*stack.TransportEndpointInfo)
		if !ok {
			continue
		}
		if info.ID.RemoteAddress.String() != clientAddr.String() {
			continue
		}
		found = true
		options := endpoint.SocketOptions()
		if !options.GetKeepAlive() || options.GetReceiveBufferSize() != tcpReceiveBuffer ||
			options.GetSendBufferSize() != tcpSendBuffer {
			t.Fatalf("keepalive %t, receive %d, send %d", options.GetKeepAlive(), options.GetReceiveBufferSize(),
				options.GetSendBufferSize())
		}
	}
	if !found {
		t.Fatal("the accepted endpoint was not found")
	}
}

// Closing the listener wakes an Accept waiting on it.
func TestMeshStackCloseWakesAccept(t *testing.T) {
	t.Parallel()
	stack, err := newMeshStack([]netip.Addr{gatewayAddr}, netstackMTU, DefaultTCPBuffers())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stack.Close() }()
	listener, err := stack.ListenTCPAddrPort(netip.AddrPortFrom(gatewayAddr, 443))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	_ = listener.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Accept never woke")
	}
}

// A closed stack reads and writes os.ErrClosed; a packet that is not IP is
// refused, the batch's others still taken.
func TestMeshStackReadWrite(t *testing.T) {
	t.Parallel()
	stack, err := newMeshStack([]netip.Addr{gatewayAddr}, netstackMTU, DefaultTCPBuffers())
	if err != nil {
		t.Fatal(err)
	}
	if n, err := stack.Write([][]byte{{0x00, 1, 2}, echoRequest(clientAddr, gatewayAddr)}, 0); !errors.Is(err, errNotIP) ||
		n != 2 {
		t.Fatalf("not IP: %d, %v", n, err)
	}
	// The echo after the bad packet went in: its reply comes out.
	replied := make(chan int, 1)
	go func() {
		sizes := []int{0}
		if _, err := stack.Read([][]byte{make([]byte, netstackMTU)}, sizes, 0); err == nil {
			replied <- sizes[0]
		}
	}()
	select {
	case size := <-replied:
		if size != header.IPv4MinimumSize+header.ICMPv4MinimumSize {
			t.Fatalf("a reply of %d bytes", size)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no echo reply")
	}
	_ = stack.Close()
	if _, err := stack.Read([][]byte{make([]byte, netstackMTU)}, []int{0}, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Read after close: %v", err)
	}
	if _, err := stack.Write([][]byte{{0x45}}, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Write after close: %v", err)
	}
}

// echoRequest is an ICMPv4 echo request from source to target.
func echoRequest(source, target netip.Addr) []byte {
	packet := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize)
	ip := header.IPv4(packet)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)), TTL: 64,
		Protocol: uint8(header.ICMPv4ProtocolNumber), SrcAddr: tcpip.AddrFrom4(source.As4()),
		DstAddr: tcpip.AddrFrom4(target.As4()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	echo := header.ICMPv4(packet[header.IPv4MinimumSize:])
	echo.SetType(header.ICMPv4Echo)
	echo.SetIdent(1)
	echo.SetSequence(1)
	echo.SetChecksum(^checksum.Checksum(echo, 0))
	return packet
}
