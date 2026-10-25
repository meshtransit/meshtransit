package underlay

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Once the system resolver failed the client, its names are asked of
// resolved's upstreams directly for a while, never of a server in the mesh.
func TestUpstreamResolverAsksResolvedUpstreamsWhenBypassing(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	go answerA(server, [4]byte{203, 0, 113, 7})
	path := filepath.Join(t.TempDir(), "resolv.conf")
	content := "# resolved\nnameserver 100.64.0.9\nnameserver 192.0.2.53\nnameserver 127.0.0.1\nnameserver fe80::1%eth0\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	local, ok := server.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("local address %T", server.LocalAddr())
	}
	previousPath, previousPort := upstreamResolvers, upstreamPort
	upstreamResolvers, upstreamPort = path, uint16(local.Port) //nolint:gosec // G115: a port
	t.Cleanup(func() { upstreamResolvers, upstreamPort = previousPath, previousPort })
	if got := readUpstreams(path); len(got) != 1 || got[0].Addr() != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("upstreams = %v, want only 127.0.0.1", got)
	}
	bypassUntil.Store(time.Now().Add(time.Minute).UnixNano())
	t.Cleanup(func() { bypassUntil.Store(0) })
	addresses, err := upstreamResolver.LookupHost(t.Context(), "control.example.test")
	if err != nil || len(addresses) != 1 || addresses[0] != "203.0.113.7" {
		t.Fatalf("LookupHost() = %v, %v", addresses, err)
	}
	// Bound off the exit routes (a meshd restarting under the kill
	// switch), the upstreams are asked at once, never resolved's stub.
	bypassUntil.Store(0)
	SetExitChosen(true)
	t.Cleanup(func() { SetExitChosen(false) })
	if !usesUpstreamsNow() {
		t.Fatal("a client whose settings name a pool asked the system resolver first")
	}
	SetExitChosen(false)
	// A root zone takes every name, its resolvers may filter Core's name:
	// meshd asks the network's resolvers (DNS design D1b §5.8).
	SetRootZone(true)
	t.Cleanup(func() { SetRootZone(false) })
	if !usesUpstreamsNow() || !RootZone() {
		t.Fatal("a root zone left meshd's own names to the system resolver")
	}
	SetRootZone(false)
	if usesUpstreamsNow() {
		t.Fatal("a client neither bound nor bypassing skipped the system resolver")
	}
	if got := readUpstreams(filepath.Join(t.TempDir(), "absent")); got != nil {
		t.Fatalf("upstreams without the file = %v", got)
	}
}

// answerA answers every A question with address until the socket closes.
func answerA(server *net.UDPConn, address [4]byte) {
	buffer := make([]byte, 1500)
	for {
		count, remote, err := server.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return
		}
		var query dnsmessage.Message
		if query.Unpack(buffer[:count]) != nil || len(query.Questions) != 1 {
			continue
		}
		response := dnsmessage.Message{
			Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionAvailable: true}, Questions: query.Questions,
		}
		if query.Questions[0].Type == dnsmessage.TypeA {
			response.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Name: query.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30,
				},
				Body: &dnsmessage.AResource{A: address},
			}}
		}
		if packed, err := response.Pack(); err == nil {
			_, _ = server.WriteToUDPAddrPort(packed, remote)
		}
	}
}

// A system resolver that answers SERVFAIL, or does not answer, starts the
// bypass, and the next lookup asks the upstreams; one that answers keeps
// the client on it.
func TestSystemResolverStartsTheBypassOnFailure(t *testing.T) {
	t.Cleanup(func() { bypassUntil.Store(0) })
	upstream := listenUDP(t)
	go answerA(upstream, [4]byte{203, 0, 113, 8})
	useUpstream(t, upstream)

	servfail := listenUDP(t)
	go answerRcode(servfail, dnsmessage.RCodeServerFailure)
	silent := listenUDP(t)
	answering := listenUDP(t)
	go answerA(answering, [4]byte{203, 0, 113, 9})
	for name, test := range map[string]struct {
		server *net.UDPConn
		bypass bool
	}{
		"answer":   {answering, false},
		"servfail": {servfail, true},
		"silent":   {silent, true},
	} {
		bypassUntil.Store(0)
		_, _ = lookupThrough(t, test.server.LocalAddr().String())
		if bypassing := bypassUntil.Load() > time.Now().UnixNano(); bypassing != test.bypass {
			t.Errorf("%s: bypassing = %t, want %t", name, bypassing, test.bypass)
		}
	}

	// Bypassing, the next lookup goes to the upstream, whichever server the
	// resolver asked for.
	bypassUntil.Store(time.Now().Add(time.Minute).UnixNano())
	addresses, err := lookupThrough(t, silent.LocalAddr().String())
	if err != nil || len(addresses) != 1 || addresses[0] != "203.0.113.8" {
		t.Fatalf("LookupHost() while bypassing = %v, %v; want the upstream's answer", addresses, err)
	}
}

func listenUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

// useUpstream makes server the only resolved upstream for the test.
func useUpstream(t *testing.T, server *net.UDPConn) {
	t.Helper()
	local, ok := server.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("local address %T", server.LocalAddr())
	}
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte("nameserver 127.0.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousPath, previousPort := upstreamResolvers, upstreamPort
	upstreamResolvers, upstreamPort = path, uint16(local.Port) //nolint:gosec // G115: a port
	t.Cleanup(func() { upstreamResolvers, upstreamPort = previousPath, previousPort })
}

// lookupThrough looks up a name with the system resolver at address, as
// the client's own dials do.
func lookupThrough(t *testing.T, address string) ([]string, error) {
	t.Helper()
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialResolver(ctx, network, address)
	}}
	ctx, cancel := context.WithTimeout(t.Context(), 1500*time.Millisecond)
	defer cancel()
	return resolver.LookupHost(ctx, "control.example.test.")
}

// answerRcode answers every question with rcode until the socket closes.
func answerRcode(server *net.UDPConn, rcode dnsmessage.RCode) {
	buffer := make([]byte, 1500)
	for {
		count, remote, err := server.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return
		}
		var query dnsmessage.Message
		if query.Unpack(buffer[:count]) != nil {
			continue
		}
		response := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: query.ID, Response: true, RCode: rcode},
			Questions: query.Questions,
		}
		if packed, err := response.Pack(); err == nil {
			_, _ = server.WriteToUDPAddrPort(packed, remote)
		}
	}
}

// The system resolver's socket stays a PacketConn through the watch: Go's
// resolver frames its query by the connection's type, and a UDP socket it
// takes for a stream gets each query with a TCP length prefix, which no
// server answers. Every lookup then timed out to the bypass, and forever in
// a pod, which has no resolved upstreams to bypass to.
func TestSystemResolverLooksUpOverUDP(t *testing.T) {
	t.Cleanup(func() { bypassUntil.Store(0) })
	bypassUntil.Store(0)
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	go answerA(server, [4]byte{203, 0, 113, 9})
	address := server.LocalAddr().String()

	conn, err := dialResolver(t.Context(), "udp", address)
	if err != nil {
		t.Fatalf("dialResolver() error = %v", err)
	}
	if _, ok := conn.(net.PacketConn); !ok {
		t.Fatalf("dialResolver() gave a %T, not a PacketConn", conn)
	}
	_ = conn.Close()

	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialResolver(ctx, network, address)
	}}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	addresses, err := resolver.LookupHost(ctx, "control.example.test.")
	if err != nil || len(addresses) != 1 || addresses[0] != "203.0.113.9" {
		t.Fatalf("LookupHost() = %v, %v", addresses, err)
	}
	if bypassUntil.Load() > time.Now().UnixNano() {
		t.Fatal("a lookup the system resolver answered started the bypass")
	}
}
