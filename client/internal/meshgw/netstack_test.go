package meshgw

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

const (
	// netstackMTU is the gateway's planned MTU (k8s-gateway-plan §4.4).
	netstackMTU = 1280
	// pumpOffset leaves headroom in front of each packet, as the data plane
	// does when it reads the TUN.
	pumpOffset = 16
)

var (
	listenerAddr = netip.MustParseAddr("100.64.0.1")
	dialerAddr   = netip.MustParseAddr("100.64.0.2")
)

// Two netstacks joined packet for packet carry a TCP stream both ways and
// close it half at a time: the server reads the whole request to the
// client's FIN, then answers over the half-closed connection and closes its
// own side. The gateway's forwarder rests on exactly this.
func TestNetstackCarriesTCPBetweenTwoStacks(t *testing.T) {
	t.Parallel()
	listenerNet, dialerNet := joinedNetstacks(t)

	listener, err := listenerNet.ListenTCPAddrPort(netip.AddrPortFrom(listenerAddr, 443))
	if err != nil {
		t.Fatalf("ListenTCPAddrPort() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	served := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			served <- err
			return
		}
		defer func() { _ = conn.Close() }()
		request, err := io.ReadAll(conn)
		if err == nil {
			_, err = conn.Write(request)
		}
		if err == nil {
			tcp, ok := conn.(*gonet.TCPConn)
			if !ok {
				err = fmt.Errorf("accepted a %T, want *gonet.TCPConn", conn)
			} else {
				err = tcp.CloseWrite()
			}
		}
		served <- err
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	conn, err := dialerNet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(listenerAddr, 443))
	if err != nil {
		t.Fatalf("DialContextTCPAddrPort() error = %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}

	sent := make([]byte, 256<<10)
	if _, err := rand.Read(sent); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	if _, err := conn.Write(sent); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite() error = %v", err)
	}
	received, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if !bytes.Equal(received, sent) {
		t.Fatalf("echoed %d bytes, want the %d sent", len(received), len(sent))
	}
	if err := <-served; err != nil {
		t.Fatalf("server error = %v", err)
	}
}

// A port with no listener answers with a reset, so a forwarder learns at
// once that the target is down instead of waiting out its dial timeout.
func TestNetstackRefusesAClosedPort(t *testing.T) {
	t.Parallel()
	_, dialerNet := joinedNetstacks(t)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	started := time.Now()
	conn, err := dialerNet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(listenerAddr, 443))
	if err == nil {
		_ = conn.Close()
		t.Fatal("DialContextTCPAddrPort() to a closed port succeeded")
	}
	// gonet keeps only the text of gVisor's errors, so the text is all a
	// caller can tell a refusal by.
	var opErr *net.OpError
	refused := (&tcpip.ErrConnectionRefused{}).String()
	if !errors.As(err, &opErr) || opErr.Err.Error() != refused {
		t.Fatalf("DialContextTCPAddrPort() error = %v, want %q", err, refused)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("refusal took %s", elapsed)
	}
}

// joinedNetstacks returns the stacks at listenerAddr and dialerAddr with
// every packet one sends moved into the other, as the data plane would after
// decrypting it, until the test ends.
func joinedNetstacks(t *testing.T) (listener, dialer *netstack.Net) {
	t.Helper()
	listenerTUN, listener := newNetstack(t, listenerAddr)
	dialerTUN, dialer := newNetstack(t, dialerAddr)
	var pumps sync.WaitGroup
	pumps.Add(2)
	go func() { defer pumps.Done(); pump(t, listenerTUN, dialerTUN) }()
	go func() { defer pumps.Done(); pump(t, dialerTUN, listenerTUN) }()
	t.Cleanup(func() {
		_ = listenerTUN.Close()
		_ = dialerTUN.Close()
		pumps.Wait()
	})
	return listener, dialer
}

func newNetstack(t *testing.T, addr netip.Addr) (tun.Device, *netstack.Net) {
	t.Helper()
	device, network, err := netstack.CreateNetTUN([]netip.Addr{addr}, nil, netstackMTU)
	if err != nil {
		t.Fatalf("CreateNetTUN(%s) error = %v", addr, err)
	}
	return device, network
}

// pump runs until from is closed. A packet longer than the MTU fails the
// test, because the stack would have cut it short without a word.
func pump(t *testing.T, from, to tun.Device) {
	batch := from.BatchSize()
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, pumpOffset+netstackMTU+1)
	}
	sizes := make([]int, batch)
	for {
		n, err := from.Read(bufs, sizes, pumpOffset)
		if errors.Is(err, os.ErrClosed) {
			return
		}
		if err != nil {
			t.Errorf("Read() error = %v", err)
			return
		}
		packets := make([][]byte, n)
		for i := range n {
			if sizes[i] > netstackMTU {
				t.Errorf("read a %d-byte packet, over the %d-byte MTU", sizes[i], netstackMTU)
				return
			}
			packets[i] = bufs[i][:pumpOffset+sizes[i]]
		}
		if _, err := to.Write(packets, pumpOffset); err != nil {
			t.Errorf("Write() error = %v", err)
			return
		}
	}
}
