package netadmin

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"meshtransit.net/client/internal/socket"
)

// kernelNamingCreator hands out pipes named like macOS utun interfaces.
type kernelNamingCreator struct {
	mu     sync.Mutex
	writer *os.File
}

func (c *kernelNamingCreator) pipeWriter() *os.File {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writer
}

func (c *kernelNamingCreator) Open(name string, _ int, _ uint32, _, _ []netip.Prefix) (*os.File, string, error) {
	if name != "" {
		return nil, "", errors.New("macOS helper passed a fixed interface name")
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, "", err
	}
	c.mu.Lock()
	c.writer = writer
	c.mu.Unlock()
	return reader, "utun7", nil
}

func (c *kernelNamingCreator) ReplaceRoutes(name string, _, _ []netip.Prefix) error {
	if name != "utun7" {
		return errors.New("routes replaced on the wrong interface")
	}
	return nil
}

func startDarwinServer(t *testing.T, creator tunCreator) string {
	t.Helper()
	server, err := newServer(ServerOptions{
		AllowedUID:      uint32(os.Geteuid()), //nolint:gosec // uids are non-negative
		MTU:             1280,
		AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		Logger:          slog.New(slog.DiscardHandler),
	}, creator)
	if err != nil {
		t.Fatalf("newServer() error = %v", err)
	}
	// macOS limits socket paths to 104 bytes; t.TempDir is too deep.
	directory, err := os.MkdirTemp("/tmp", "netadmin") //nolint:usetesting // see above
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "n.sock")
	listener, err := socket.ListenPacket(path)
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		<-result
	})
	return path
}

func TestDarwinOpenTUNPassesTheDescriptorAndKernelName(t *testing.T) {
	t.Parallel()
	creator := &kernelNamingCreator{}
	path := startDarwinServer(t, creator)
	client, err := NewClient(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	config := TUNConfig{
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")},
		Routes:    []netip.Prefix{netip.MustParsePrefix("100.64.0.4/32")},
	}
	tun, err := client.OpenTUN(t.Context(), config)
	if err != nil {
		t.Fatalf("OpenTUN() error = %v", err)
	}
	t.Cleanup(func() { _ = tun.File.Close() })
	if tun.Name != "utun7" {
		t.Fatalf("tun name = %q, want utun7", tun.Name)
	}
	if _, err := creator.pipeWriter().Write([]byte("packet")); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 6)
	if _, err := tun.File.Read(payload); err != nil || string(payload) != "packet" {
		t.Fatalf("read through passed descriptor = %q, %v", payload, err)
	}
	config.Routes = append(config.Routes, netip.MustParsePrefix("100.64.0.5/32"))
	if err := client.ConfigureTUNRoutes(t.Context(), config); err != nil {
		t.Fatalf("ConfigureTUNRoutes() error = %v", err)
	}
}

// rawExchange sends one hand-made message and returns the response payload.
func rawExchange(t *testing.T, path string, message []byte, file *os.File) response {
	t.Helper()
	connection, err := (&net.Dialer{}).DialContext(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		t.Fatalf("dialed %T", connection)
	}
	var control []byte
	if file != nil {
		control = unix.UnixRights(int(file.Fd()))
	}
	if _, _, err := unixConnection.WriteMsgUnix(message, control, nil); err != nil {
		t.Fatal(err)
	}
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	payload, descriptors, err := readResponseFrame(unixConnection)
	closeDescriptors(descriptors)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	value := response{}
	if err := decodeMessage(payload, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestDarwinServerRejectsBadFraming(t *testing.T) {
	t.Parallel()
	path := startDarwinServer(t, &kernelNamingCreator{})
	request, err := encodeMessage(request{Version: protocolVersion, Operation: operationResetDNS})
	if err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })

	oversized := make([]byte, frameHeaderBytes)
	binary.BigEndian.PutUint32(oversized, maxMessageBytes+1)
	for name, test := range map[string]struct {
		message []byte
		file    *os.File
	}{
		"descriptor on a request": {message: frame(request), file: reader},
		"oversized length":        {message: oversized},
		"bytes past the frame":    {message: append(frame(request), '{')},
	} {
		if got := rawExchange(t, path, test.message, test.file); got.OK || got.Code != "invalid_request" {
			t.Errorf("%s: response = %+v, want invalid_request", name, got)
		}
	}
}

func TestValidInterfaceNameAcceptsKernelTunnels(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]bool{
		"utun0": true, "utun9999": true, "utun": false, "utun10000": false, "utunx": false,
		"mesh0": true, "eth0": false,
	} {
		if got := validInterfaceName(name); got != want {
			t.Errorf("validInterfaceName(%q) = %v, want %v", name, got, want)
		}
	}
	if validConfiguredInterfaceName("utun3") || !validConfiguredInterfaceName("") {
		t.Error("macOS helper must leave interface names to the kernel")
	}
}
