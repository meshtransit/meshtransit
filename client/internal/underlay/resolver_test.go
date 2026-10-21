package underlay

import (
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
	content := "# resolved\nnameserver 100.64.0.9\nnameserver 127.0.0.1\nnameserver fe80::1%eth0\n"
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
// bypass; one that answers keeps the client on it.
func TestWatchedConnStartsTheBypassOnFailure(t *testing.T) {
	t.Cleanup(func() { bypassUntil.Store(0) })
	for name, test := range map[string]struct {
		response []byte
		bypass   bool
	}{
		"answer":   {[]byte{0, 1, 0x81, 0x80}, false},
		"servfail": {[]byte{0, 1, 0x81, 0x82}, true},
	} {
		bypassUntil.Store(0)
		client, server := net.Pipe()
		go func() { _, _ = server.Write(test.response); _ = server.Close() }()
		buffer := make([]byte, 16)
		_, _ = (&watchedConn{Conn: client}).Read(buffer)
		_ = client.Close()
		if bypassing := bypassUntil.Load() > time.Now().UnixNano(); bypassing != test.bypass {
			t.Errorf("%s: bypassing = %t", name, bypassing)
		}
	}
	bypassUntil.Store(0)
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	_, _ = (&watchedConn{Conn: client}).Read(make([]byte, 16))
	_ = client.Close()
	if bypassUntil.Load() <= time.Now().UnixNano() {
		t.Error("a timeout did not start the bypass")
	}
}
