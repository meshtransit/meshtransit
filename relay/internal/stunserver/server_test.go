package stunserver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"meshtransit.net/shared/disco"
	"meshtransit.net/shared/netcheck"
	"meshtransit.net/shared/stun"
)

func startServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	s, err := Listen(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return s
}

// TestNetcheckAgainstRelaySTUN classifies a loopback client with the relay's
// STUN server: no NAT, and a change-port answer proves at most
// address-dependent filtering (the server has no alternate address).
func TestNetcheckAgainstRelaySTUN(t *testing.T) {
	t.Parallel()
	s := startServer(t, Config{
		Primary: "127.0.0.1:0", AltPort: "127.0.0.1:0",
		PublicAddr: netip.MustParseAddr("127.0.0.1"),
	})
	primary, alt := s.Ports()
	if alt == 0 {
		t.Fatal("alternate port not bound")
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	prober := netcheck.NewProber(conn, netcheck.Config{ProbeTimeout: 300 * time.Millisecond, Retransmit: 50 * time.Millisecond})
	var wg sync.WaitGroup
	wg.Go(func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if err == nil {
				prober.HandleResponse(buf[:n], from)
			}
		}
	})
	t.Cleanup(func() {
		_ = conn.Close()
		wg.Wait()
	})
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatal("UDP socket without a UDP address")
	}
	local := addr.AddrPort()
	report, err := prober.Run(context.Background(),
		[]netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), primary)},
		[]netip.AddrPort{local})
	if err != nil {
		t.Fatal(err)
	}
	if report.NAT.Filtering != disco.FilteringAddressDependent || report.Mapped != local {
		t.Fatalf("report = %+v", report)
	}
}

func TestSTUNServerRejectsAndLimits(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	results := map[string]int{}
	s := startServer(t, Config{
		Primary: "127.0.0.1:0", PublicAddr: netip.MustParseAddr("127.0.0.1"), SourceRate: 2,
		Metrics: func(r string) { mu.Lock(); results[r]++; mu.Unlock() },
	})
	primary, _ := s.Ports()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	dst := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), primary)
	send := func(b []byte) { _, _ = conn.WriteToUDPAddrPort(b, dst) }

	send([]byte("not stun"))
	send(stun.AppendBindingRequest(nil, stun.TxID{1}, stun.ChangeRequest{Port: true})) // no alternate port
	for i := range 4 {
		send(stun.AppendBindingRequest(nil, stun.TxID{byte(i + 10)}, stun.ChangeRequest{}))
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		done := results["invalid"] == 1 && results["change_unsupported"] == 1 && results["answered"] == 1 && results["rate_limited"] == 3
		snapshot := map[string]int{}
		for k, v := range results {
			snapshot[k] = v
		}
		mu.Unlock()
		if done {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("results = %v", snapshot)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
