package derp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshd/internal/relay"
	"go4.org/mem"
	protocol "tailscale.com/derp"
	"tailscale.com/types/key"
)

func TestDialFailsOverAfterNodeSessionTimeout(t *testing.T) {
	t.Parallel()

	server := newAuthenticatedRelayServer(t, nil)
	stalledClient, stalledServer := net.Pipe()
	t.Cleanup(func() {
		_ = stalledClient.Close()
		_ = stalledServer.Close()
	})
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	attempted := make([]string, 0, 2)
	dialer := &Dialer{
		dialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			attempted = append(attempted, address)
			if address == "192.0.2.1:443" {
				return stalledClient, nil
			}
			var networkDialer net.Dialer

			return networkDialer.DialContext(ctx, network, server.Listener.Addr().String())
		},
		rootCAs:            roots,
		nodeSessionTimeout: 50 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	started := time.Now()
	client, err := dialer.Dial(ctx, relay.Key{1}, relay.Region{
		ID: 1,
		Nodes: []relay.Node{
			{
				Name:     "stalled",
				HostName: server.Certificate().DNSNames[0],
				IPv4:     "192.0.2.1",
				IPv6:     "none",
				Port:     443,
			},
			{
				Name:     "healthy",
				HostName: server.Certificate().DNSNames[0],
				IPv4:     "192.0.2.2",
				IPv6:     "none",
				Port:     443,
			},
		},
	})
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if want := []string{"192.0.2.1:443", "192.0.2.2:443"}; !slices.Equal(attempted, want) {
		t.Fatalf("dial attempts = %v, want %v", attempted, want)
	}
	if elapsed := time.Since(started); elapsed >= 500*time.Millisecond {
		t.Fatalf("Dial() failover took %v", elapsed)
	}
}

func TestDialTimesOutMissingServerGreeting(t *testing.T) {
	t.Parallel()

	server := newHijackedTLSServer(t, func(
		connection net.Conn,
		readWriter *bufio.ReadWriter,
	) error {
		if err := writeUpgradeResponse(readWriter); err != nil {
			return err
		}
		_, err := connection.Read(make([]byte, 1))
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
			return nil
		}

		return err
	})
	dialer := testServerDialer(server)
	dialer.nodeSessionTimeout = 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, err := dialer.Dial(ctx, relay.Key{1}, testServerRegion(server))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Dial() error = %v, want context deadline exceeded", err)
	}
}

func TestClientRejectsAdversarialServerFrames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		frameType protocol.FrameType
		frameSize uint32
	}{
		{
			name:      "unknown frame",
			frameType: protocol.FrameType(0xff),
		},
		{
			name:      "oversized encrypted packet",
			frameType: protocol.FrameRecvPacket,
			frameSize: protocol.KeyLen + relay.MaxPacketSize + 1,
		},
		{
			name:      "short ping",
			frameType: protocol.FramePing,
			frameSize: 7,
		},
		{
			name:      "oversized health state",
			frameType: protocol.FrameHealth,
			frameSize: maxHealthFrameSize + 1,
		},
		{
			name:      "repeated greeting",
			frameType: protocol.FrameServerKey,
			frameSize: uint32(len(protocol.Magic) + protocol.KeyLen),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newAuthenticatedRelayServer(t, func(readWriter *bufio.ReadWriter) error {
				if err := protocol.WriteFrameHeader(
					readWriter.Writer,
					test.frameType,
					test.frameSize,
				); err != nil {
					return err
				}

				return readWriter.Flush()
			})
			client, err := testServerDialer(server).Dial(
				t.Context(),
				relay.Key{1},
				testServerRegion(server),
			)
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			t.Cleanup(func() { _ = client.Close() })

			received := make(chan error, 1)
			go func() {
				_, err := client.Receive()
				received <- err
			}()
			select {
			case err := <-received:
				if err == nil || !strings.Contains(err.Error(), "inbound frame") {
					t.Fatalf("Receive() error = %v", err)
				}
			case <-time.After(250 * time.Millisecond):
				_ = client.Close()
				t.Fatal("Receive() did not reject adversarial frame")
			}
		})
	}
}

func TestClientAcceptsBoundedKeepAlive(t *testing.T) {
	t.Parallel()

	server := newAuthenticatedRelayServer(t, func(readWriter *bufio.ReadWriter) error {
		return protocol.WriteFrame(readWriter.Writer, protocol.FrameKeepAlive, nil)
	})
	client, err := testServerDialer(server).Dial(
		t.Context(),
		relay.Key{1},
		testServerRegion(server),
	)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	event, err := client.Receive()
	if err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if event.Kind != relay.ReceiveActivity || event.Source != (relay.Key{}) ||
		len(event.Data) != 0 {
		t.Fatalf("Receive() = %#v", event)
	}
}

func TestClientRedactsUnhealthyServerDetail(t *testing.T) {
	t.Parallel()

	const privateDetail = "internal relay diagnostic"
	server := newAuthenticatedRelayServer(t, func(readWriter *bufio.ReadWriter) error {
		return protocol.WriteFrame(
			readWriter.Writer,
			protocol.FrameHealth,
			[]byte(privateDetail),
		)
	})
	client, err := testServerDialer(server).Dial(
		t.Context(),
		relay.Key{1},
		testServerRegion(server),
	)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	_, err = client.Receive()
	if err == nil || !strings.Contains(err.Error(), "server reports unhealthy") {
		t.Fatalf("Receive() error = %v", err)
	}
	if strings.Contains(err.Error(), privateDetail) {
		t.Fatalf("Receive() exposed server detail: %v", err)
	}
}

func FuzzServerFrameReader(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{byte(protocol.FrameServerKey), 0, 0, 0, 40})
	f.Add([]byte{byte(protocol.FrameServerKey), 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0xff, 0, 0, 0, 0})

	f.Fuzz(func(t *testing.T, input []byte) {
		reader := newServerFrameReader(bytes.NewReader(input))
		_, _ = io.Copy(io.Discard, reader)
	})
}

func newAuthenticatedRelayServer(
	t *testing.T,
	afterAuthentication func(*bufio.ReadWriter) error,
) *httptest.Server {
	t.Helper()

	serverPrivate := key.NewNode()

	return newHijackedTLSServer(t, func(
		connection net.Conn,
		readWriter *bufio.ReadWriter,
	) error {
		if err := writeUpgradeResponse(readWriter); err != nil {
			return err
		}
		greeting := append([]byte(protocol.Magic), serverPrivate.Public().AppendTo(nil)...)
		if err := protocol.WriteFrame(
			readWriter.Writer,
			protocol.FrameServerKey,
			greeting,
		); err != nil {
			return err
		}
		frameType, frameSize, err := protocol.ReadFrameHeader(readWriter.Reader)
		if err != nil {
			return fmt.Errorf("reading client authentication header: %w", err)
		}
		if frameType != protocol.FrameClientInfo || frameSize < protocol.KeyLen ||
			frameSize > 256<<10 {
			return errors.New("client authentication frame is invalid")
		}
		rawClientKey := make([]byte, protocol.KeyLen)
		if _, err := io.ReadFull(readWriter.Reader, rawClientKey); err != nil {
			return fmt.Errorf("reading client public key: %w", err)
		}
		if _, err := io.CopyN(
			io.Discard,
			readWriter.Reader,
			int64(frameSize-protocol.KeyLen),
		); err != nil {
			return fmt.Errorf("reading client authentication body: %w", err)
		}
		clientPublic := key.NodePublicFromRaw32(mem.B(rawClientKey))
		serverInfo := serverPrivate.SealTo(clientPublic, []byte(`{"version":2}`))
		if err := protocol.WriteFrame(
			readWriter.Writer,
			protocol.FrameServerInfo,
			serverInfo,
		); err != nil {
			return err
		}
		if afterAuthentication != nil {
			if err := afterAuthentication(readWriter); err != nil {
				return err
			}
		}
		_, err = connection.Read(make([]byte, 1))
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
			return nil
		}

		return err
	})
}

func newHijackedTLSServer(
	t *testing.T,
	serve func(net.Conn, *bufio.ReadWriter) error,
) *httptest.Server {
	t.Helper()

	done := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(
		response http.ResponseWriter,
		_ *http.Request,
	) {
		defer close(done)
		hijacker, ok := response.(http.Hijacker)
		if !ok {
			t.Error("test server cannot hijack connection")

			return
		}
		connection, readWriter, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("Hijack() error = %v", err)

			return
		}
		defer func() { _ = connection.Close() }()
		if err := serve(connection, readWriter); err != nil {
			t.Errorf("adversarial relay server error = %v", err)
		}
	}))
	t.Cleanup(func() {
		server.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("adversarial relay server did not stop")
		}
	})

	return server
}

func writeUpgradeResponse(readWriter *bufio.ReadWriter) error {
	if _, err := readWriter.WriteString(
		"HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: DERP\r\n" +
			"Connection: Upgrade\r\n\r\n",
	); err != nil {
		return err
	}

	return readWriter.Flush()
}

func testServerDialer(server *httptest.Server) *Dialer {
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())

	return &Dialer{
		dialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var networkDialer net.Dialer

			return networkDialer.DialContext(ctx, network, server.Listener.Addr().String())
		},
		rootCAs: roots,
	}
}

func testServerRegion(server *httptest.Server) relay.Region {
	return relay.Region{
		ID: 1,
		Nodes: []relay.Node{{
			Name:     "relay",
			HostName: server.Certificate().DNSNames[0],
			IPv4:     "192.0.2.1",
			IPv6:     "none",
			Port:     443,
		}},
	}
}
