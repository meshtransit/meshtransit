package derp

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/client/internal/relay"
)

func TestDialRejectsNonUpgradeResponse(t *testing.T) {
	t.Parallel()

	requestHost := make(chan string, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requestHost <- request.Host
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	var dialNetwork string
	var dialAddress string
	dialer := &Dialer{
		dialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialNetwork = network
			dialAddress = address
			var networkDialer net.Dialer

			return networkDialer.DialContext(ctx, network, server.Listener.Addr().String())
		},
		rootCAs: roots,
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, err := dialer.Dial(ctx, relay.Key{1}, relay.Region{
		ID: 1,
		Nodes: []relay.Node{{
			Name:     "relay",
			HostName: server.Certificate().DNSNames[0],
			IPv4:     "192.0.2.1",
			IPv6:     "none",
			Port:     443,
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "status 204") {
		t.Fatalf("Dial() error = %v", err)
	}
	if dialNetwork != "tcp4" || dialAddress != "192.0.2.1:443" {
		t.Fatalf("dial target = %s %s, want tcp4 192.0.2.1:443", dialNetwork, dialAddress)
	}
	if got, want := <-requestHost, server.Certificate().DNSNames[0]+":443"; got != want {
		t.Fatalf("HTTP authority = %q, want %q", got, want)
	}
}

func TestDialRejectsOversizedUpgradeResponse(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(
		response http.ResponseWriter,
		_ *http.Request,
	) {
		hijacker, ok := response.(http.Hijacker)
		if !ok {
			t.Error("test server cannot hijack connection")

			return
		}
		connection, _, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("Hijack() error = %v", err)

			return
		}
		defer func() { _ = connection.Close() }()
		_, _ = io.WriteString(
			connection,
			"HTTP/1.1 101 Switching Protocols\r\n"+
				"Upgrade: DERP\r\n"+
				"Connection: Upgrade\r\n"+
				"X-Padding: "+strings.Repeat("a", 40<<10)+"\r\n\r\n",
		)
	}))
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	dialer := &Dialer{
		dialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var networkDialer net.Dialer

			return networkDialer.DialContext(ctx, network, server.Listener.Addr().String())
		},
		rootCAs: roots,
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, err := dialer.Dial(ctx, relay.Key{1}, relay.Region{
		ID: 1,
		Nodes: []relay.Node{{
			Name:     "relay",
			HostName: server.Certificate().DNSNames[0],
			IPv4:     "192.0.2.1",
			IPv6:     "none",
			Port:     443,
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "upgrade response exceeds limit") {
		t.Fatalf("Dial() error = %v", err)
	}
}

func TestTLSConfigVerifiesAlternateCertificateName(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	certificate := server.Certificate()
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	dialer := &Dialer{rootCAs: roots}
	config, err := dialer.tlsConfig(relay.Node{
		HostName: "front.invalid",
		CertName: certificate.DNSNames[0],
	})
	if err != nil {
		t.Fatalf("tlsConfig() error = %v", err)
	}
	if config.VerifyConnection == nil {
		t.Fatal("tlsConfig() did not install alternate-name verification")
	}
	if err := config.VerifyConnection(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{certificate},
	}); err != nil {
		t.Fatalf("VerifyConnection() error = %v", err)
	}
}

func TestTLSConfigVerifiesPinnedCertificate(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	certificate := server.Certificate()
	digest := sha256.Sum256(certificate.Raw)
	dialer := &Dialer{}
	config, err := dialer.tlsConfig(relay.Node{
		HostName: certificate.DNSNames[0],
		CertName: certificatePinLabel + hex.EncodeToString(digest[:]),
	})
	if err != nil {
		t.Fatalf("tlsConfig() error = %v", err)
	}
	if err := config.VerifyConnection(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{certificate},
	}); err != nil {
		t.Fatalf("VerifyConnection() error = %v", err)
	}
	wrongDigest := digest
	wrongDigest[0] ^= 0xff
	verifier := pinnedCertificateVerifier(certificate.DNSNames[0], wrongDigest)
	if err := verifier(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{certificate},
	}); err == nil {
		t.Fatal("pinned verifier accepted wrong certificate")
	}
}

func TestTLSConfigRejectsMalformedPin(t *testing.T) {
	t.Parallel()

	dialer := &Dialer{}
	_, err := dialer.tlsConfig(relay.Node{
		HostName: "relay.example.com",
		CertName: certificatePinLabel + "01",
	})
	if err == nil {
		t.Fatal("tlsConfig() error = nil")
	}
}

func TestHeaderContainsToken(t *testing.T) {
	t.Parallel()

	if !headerContainsToken("keep-alive, Upgrade", "upgrade") {
		t.Fatal("headerContainsToken() = false")
	}
	if headerContainsToken("keep-alive", "upgrade") {
		t.Fatal("headerContainsToken() = true")
	}
}

func TestDialHonorsCancellation(t *testing.T) {
	t.Parallel()

	dialer := &Dialer{
		dialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()

			return nil, ctx.Err()
		},
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := dialer.Dial(ctx, relay.Key{1}, relay.Region{
		ID: 1,
		Nodes: []relay.Node{{
			Name:     "relay",
			HostName: "relay.example.com",
			Port:     443,
		}},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Dial() error = %v, want context.Canceled", err)
	}
}

func TestRelayDialCandidates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		node relay.Node
		want []dialCandidate
	}{
		{
			name: "dual stack literals prefer ipv6",
			node: relay.Node{
				HostName: "relay.example.com",
				IPv4:     "192.0.2.1",
				IPv6:     "2001:db8::1",
				Port:     443,
			},
			want: []dialCandidate{
				{network: "tcp6", address: "[2001:db8::1]:443"},
				{network: "tcp4", address: "192.0.2.1:443"},
			},
		},
		{
			name: "ipv6 only",
			node: relay.Node{
				HostName: "relay.example.com",
				IPv4:     "none",
				IPv6:     "2001:db8::1",
				Port:     8443,
			},
			want: []dialCandidate{{network: "tcp6", address: "[2001:db8::1]:8443"}},
		},
		{
			name: "dns ipv4 only",
			node: relay.Node{
				HostName: "relay.example.com",
				IPv6:     "none",
				Port:     443,
			},
			want: []dialCandidate{{network: "tcp4", address: "relay.example.com:443"}},
		},
		{
			name: "literal hostname selects its family",
			node: relay.Node{
				HostName: "192.0.2.2",
				Port:     443,
			},
			want: []dialCandidate{{network: "tcp4", address: "192.0.2.2:443"}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := relayDialCandidates(test.node)
			if err != nil {
				t.Fatalf("relayDialCandidates() error = %v", err)
			}
			if len(got) != len(test.want) {
				t.Fatalf("relayDialCandidates() = %#v, want %#v", got, test.want)
			}
			for index := range got {
				if got[index] != test.want[index] {
					t.Fatalf("relayDialCandidates()[%d] = %#v, want %#v", index, got[index], test.want[index])
				}
			}
		})
	}
}

func TestRelayDialCandidatesRejectInvalidAuthority(t *testing.T) {
	t.Parallel()

	for _, node := range []relay.Node{
		{HostName: "relay.example.com", IPv4: "2001:db8::1", Port: 443},
		{HostName: "relay.example.com", IPv6: "fe80::1", Port: 443},
		{HostName: "relay.example.com", IPv4: "127.0.0.1", Port: 443},
		{HostName: "relay.example.com", IPv4: "invalid", Port: 443},
		{HostName: "relay.example.com", IPv4: "none", IPv6: "none", Port: 443},
	} {
		if _, err := relayDialCandidates(node); err == nil {
			t.Fatalf("relayDialCandidates(%+v) error = nil", node)
		}
	}
}

func TestDialNodeTCPFallsBackImmediatelyAfterIPv6Failure(t *testing.T) {
	t.Parallel()

	winner, peer := net.Pipe()
	t.Cleanup(func() {
		_ = winner.Close()
		_ = peer.Close()
	})
	var networks []string
	dialer := &Dialer{
		dialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
			networks = append(networks, network)
			if network == "tcp6" {
				return nil, errors.New("ipv6 unavailable")
			}

			return winner, nil
		},
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	conn, err := dialer.dialNodeTCP(ctx, relay.Node{
		HostName: "relay.example.com",
		IPv4:     "192.0.2.1",
		IPv6:     "2001:db8::1",
		Port:     443,
	})
	if err != nil {
		t.Fatalf("dialNodeTCP() error = %v", err)
	}
	if conn != winner {
		t.Fatal("dialNodeTCP() returned the wrong connection")
	}
	if len(networks) != 2 || networks[0] != "tcp6" || networks[1] != "tcp4" {
		t.Fatalf("dial order = %v, want [tcp6 tcp4]", networks)
	}
}

func TestRaceDialCandidatesStaggersFallbackAndClosesLoser(t *testing.T) {
	t.Parallel()

	preferredStarted := make(chan struct{})
	fallbackStarted := make(chan struct{})
	loserPeer := make(chan net.Conn, 1)
	winnerPeer := make(chan net.Conn, 1)
	dialer := &Dialer{
		dialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if network == "tcp6" {
				close(preferredStarted)
				<-ctx.Done()
				conn, peer := net.Pipe()
				loserPeer <- peer

				return conn, nil
			}
			close(fallbackStarted)
			conn, peer := net.Pipe()
			winnerPeer <- peer

			return conn, nil
		},
	}
	fallbackReady := make(chan time.Time)
	type outcome struct {
		conn net.Conn
		err  error
	}
	result := make(chan outcome, 1)
	go func() {
		conn, err := dialer.raceDialCandidates(t.Context(), []dialCandidate{
			{network: "tcp6", address: "[2001:db8::1]:443"},
			{network: "tcp4", address: "192.0.2.1:443"},
		}, fallbackReady)
		result <- outcome{conn: conn, err: err}
	}()

	<-preferredStarted
	select {
	case <-fallbackStarted:
		t.Fatal("fallback started before its delay elapsed")
	default:
	}
	fallbackReady <- time.Now()
	got := <-result
	if got.err != nil {
		t.Fatalf("raceDialCandidates() error = %v", got.err)
	}
	_ = got.conn.Close()
	_ = (<-winnerPeer).Close()

	peer := <-loserPeer
	defer func() { _ = peer.Close() }()
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		if errors.Is(err, io.ErrClosedPipe) {
			return
		}
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("losing connection remained open")
	} else {
		var netError net.Error
		if errors.As(err, &netError) && netError.Timeout() {
			t.Fatal("losing connection was not closed")
		}
	}
}
