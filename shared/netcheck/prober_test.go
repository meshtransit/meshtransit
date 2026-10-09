package netcheck_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"go.uber.org/goleak"

	"meshtransit.net/shared/disco"
	"meshtransit.net/shared/netcheck"
	"meshtransit.net/shared/stun"
	"meshtransit.net/test/natlab"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

var fast = netcheck.Config{ProbeTimeout: 100 * time.Millisecond, Retransmit: 20 * time.Millisecond, Budget: 2 * time.Second}

// probe classifies a host placed behind profile p in a fresh lab.
func probe(t *testing.T, p natlab.Profile) netcheck.Report {
	t.Helper()
	lab, err := natlab.NewLab(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lab.Close)
	host, err := lab.AddNode("node", p)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := host.Listen(41641)
	if err != nil {
		t.Fatal(err)
	}
	prober := netcheck.NewProber(conn, fast)
	go readLoop(conn, prober)
	t.Cleanup(func() { _ = conn.Close() })
	r, err := prober.Run(context.Background(), lab.STUN(), conn.LocalAddrPorts())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return r
}

func readLoop(conn *natlab.Conn, p *netcheck.Prober) {
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err == nil {
			p.HandleResponse(buf[:n], from)
		}
	}
}

func TestProberClassifiesProfiles(t *testing.T) {
	t.Parallel()
	tests := []struct {
		profile natlab.Profile
		want    disco.NATInfo
	}{
		{natlab.Public, disco.NATInfo{Mapping: disco.MappingNone, Filtering: disco.FilteringEndpointIndependent, Allocation: disco.AllocationPreserving}},
		{natlab.FullCone, disco.NATInfo{Mapping: disco.MappingEndpointIndependent, Filtering: disco.FilteringEndpointIndependent, Allocation: disco.AllocationPreserving}},
		{natlab.RestrictedCone, disco.NATInfo{Mapping: disco.MappingEndpointIndependent, Filtering: disco.FilteringAddressDependent, Allocation: disco.AllocationPreserving}},
		{natlab.PortRestrictedCone, disco.NATInfo{Mapping: disco.MappingEndpointIndependent, Filtering: disco.FilteringAddressAndPortDependent, Allocation: disco.AllocationPreserving}},
		{natlab.SymmetricSequential, disco.NATInfo{Mapping: disco.MappingAddressAndPortDependent, Filtering: disco.FilteringAddressAndPortDependent, Allocation: disco.AllocationSequential}},
		{natlab.SymmetricRandom, disco.NATInfo{Mapping: disco.MappingAddressAndPortDependent, Filtering: disco.FilteringAddressAndPortDependent, Allocation: disco.AllocationRandom}},
		{natlab.DoubleNAT, disco.NATInfo{Mapping: disco.MappingEndpointIndependent, Filtering: disco.FilteringAddressAndPortDependent, Allocation: disco.AllocationRandom}},
		{natlab.CGNATSymmetric, disco.NATInfo{Mapping: disco.MappingAddressAndPortDependent, Filtering: disco.FilteringAddressAndPortDependent, Allocation: disco.AllocationRandom}},
	}
	for _, tt := range tests {
		t.Run(tt.profile.Name, func(t *testing.T) {
			t.Parallel()
			r := probe(t, tt.profile)
			if r.NAT != tt.want {
				t.Fatalf("NAT = %+v, want %+v (observations %v)", r.NAT, tt.want, r.Observations)
			}
			if tt.want.Allocation == disco.AllocationSequential && r.Step != 1 {
				t.Fatalf("step = %d, want 1", r.Step)
			}
		})
	}
}

func TestProberAddressDependentMapping(t *testing.T) {
	t.Parallel()
	p := natlab.Profile{Name: "adm-adf", NATs: []natlab.NATConfig{{
		Mapping: disco.MappingAddressDependent, Filtering: disco.FilteringAddressDependent, Allocation: disco.AllocationRandom,
	}}}
	r := probe(t, p)
	if r.NAT.Mapping != disco.MappingAddressDependent || r.NAT.Filtering != disco.FilteringAddressDependent {
		t.Fatalf("NAT = %+v", r.NAT)
	}
}

func TestProberNoServers(t *testing.T) {
	t.Parallel()
	lab, err := natlab.NewLab(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lab.Close()
	host, err := lab.AddNode("node", natlab.PortRestrictedCone)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := host.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	prober := netcheck.NewProber(conn, fast)
	go readLoop(conn, prober)
	dead := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.99:3478"), netip.MustParseAddrPort("[2001:db8::1]:3478")}
	_, err = prober.Run(context.Background(), dead, conn.LocalAddrPorts())
	if !errors.Is(err, netcheck.ErrNoResponse) || !errors.Is(err, natlab.ErrNoRoute) {
		t.Fatalf("Run error = %v, want ErrNoResponse joined with ErrNoRoute", err)
	}
}

// recordingWriter captures requests so tests can forge responses.
type recordingWriter struct{ sent chan []byte }

func (w recordingWriter) WriteToUDPAddrPort(b []byte, _ netip.AddrPort) (int, error) {
	select {
	case w.sent <- append([]byte(nil), b...):
	default:
	}
	return len(b), nil
}

func TestHandleResponseRejectsWrongSource(t *testing.T) {
	t.Parallel()
	w := recordingWriter{sent: make(chan []byte, 16)}
	p := netcheck.NewProber(w, fast)
	server := netip.MustParseAddrPort("203.0.113.1:3478")
	done := make(chan error, 1)
	go func() {
		_, err := p.Run(context.Background(), []netip.AddrPort{server}, nil)
		done <- err
	}()
	req, err := stun.Parse(<-w.sent)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := stun.AppendBindingSuccess(nil, req.TxID, netip.MustParseAddrPort("198.51.100.1:1"), netip.AddrPort{}, netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	if !p.HandleResponse(resp, netip.MustParseAddrPort("203.0.113.66:3478")) {
		t.Fatal("STUN packet not consumed")
	}
	if p.HandleResponse([]byte("not stun at all, just some bytes"), server) {
		t.Fatal("non-STUN packet consumed")
	}
	if err := <-done; !errors.Is(err, netcheck.ErrNoResponse) {
		t.Fatalf("spoofed source accepted: Run error = %v", err)
	}
}

func TestHandleResponseIgnoresLookalikes(t *testing.T) {
	t.Parallel()
	p := netcheck.NewProber(recordingWriter{sent: make(chan []byte, 1)}, fast)
	// Passes stun.Is (cookie at bytes 4..8) but is not a STUN message, as a
	// WireGuard packet with an unlucky receiver index would be.
	pkt := make([]byte, 32)
	pkt[0] = 4
	copy(pkt[4:8], []byte{0x21, 0x12, 0xa4, 0x42})
	if !stun.Is(pkt) {
		t.Fatal("test packet does not pass stun.Is")
	}
	if p.HandleResponse(pkt, netip.MustParseAddrPort("198.51.100.1:1")) {
		t.Fatal("non-STUN lookalike consumed")
	}
}

func TestRunCancelled(t *testing.T) {
	t.Parallel()
	p := netcheck.NewProber(recordingWriter{sent: make(chan []byte, 16)}, fast)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := p.Run(ctx, []netip.AddrPort{netip.MustParseAddrPort("203.0.113.1:3478")}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
}

func TestProberSendsSoftware(t *testing.T) {
	t.Parallel()
	w := recordingWriter{sent: make(chan []byte, 16)}
	cfg := fast
	cfg.Software = "compat-value"
	p := netcheck.NewProber(w, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = p.Run(ctx, []netip.AddrPort{netip.MustParseAddrPort("203.0.113.1:3478")}, nil)
	}()
	req, err := stun.Parse(<-w.sent)
	cancel()
	<-done
	if err != nil || req.Software != "compat-value" {
		t.Fatalf("request = %+v, %v", req, err)
	}
}
