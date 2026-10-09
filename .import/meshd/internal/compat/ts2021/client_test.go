package ts2021

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"tailscale.com/control/controlbase"
	"tailscale.com/control/controlhttp/controlhttpcommon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestClient_Probe(t *testing.T) {
	t.Parallel()

	serverKey := key.NewMachine().Public()
	client := newWithHTTPClient(&http.Client{
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.Method != http.MethodGet {
				t.Fatalf("method = %q, want GET", request.Method)
			}
			if got, expected := request.URL.String(), "https://control.example.com/base/key?v=142"; got != expected {
				t.Fatalf("url = %q, want %q", got, expected)
			}
			if got, expected := request.Header.Get("User-Agent"), "meshd"; got != expected {
				t.Fatalf("User-Agent = %q, want %q", got, expected)
			}

			body := `{"legacyPublicKey":"mkey:0000000000000000000000000000000000000000000000000000000000000000","publicKey":"` + serverKey.String() + `"}`

			return jsonResponse(http.StatusOK, body), nil
		}),
	})

	result, err := client.Probe(t.Context(), "https://control.example.com/base/")
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if got, expected := result.Protocol, "ts2021"; got != expected {
		t.Fatalf("Protocol = %q, want %q", got, expected)
	}
	if got, expected := result.Capability, 142; got != expected {
		t.Fatalf("Capability = %d, want %d", got, expected)
	}
	if !strings.HasPrefix(result.KeyFingerprint, "sha256:") || len(result.KeyFingerprint) != 71 {
		t.Fatalf("KeyFingerprint = %q, want sha256 plus 64 hex characters", result.KeyFingerprint)
	}
	if !result.NoiseEstablished || result.NoiseVersion != 142 {
		t.Fatalf("noise result = %#v, want established version 142", result)
	}
}

func TestNoiseHandshake(t *testing.T) {
	t.Parallel()

	controlKey := key.NewMachine()
	clientConnection, serverConnection := net.Pipe()
	serverResult := make(chan error, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	go runNoiseTestServer(ctx, serverConnection, controlKey, serverResult)

	keyURL, err := url.Parse("https://control.example.com/key?v=142")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "control.example.com:443" {
			t.Fatalf("dial target = %s %s, want tcp control.example.com:443", network, address)
		}

		return clientConnection, nil
	}

	version, err := noiseHandshake(ctx, keyURL, controlKey.Public(), dial)
	if err != nil {
		t.Fatalf("noiseHandshake() error = %v", err)
	}
	if got, expected := version, int(tailcfg.CurrentCapabilityVersion); got != expected {
		t.Fatalf("noise version = %d, want %d", got, expected)
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("test server error = %v", err)
	}
}

func TestEarlyPayloadConn(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		wire []byte
		want []byte
	}{
		{
			name: "ordinary http2 bytes are replayed",
			wire: []byte("HTTP/2 response bytes"),
			want: []byte("HTTP/2 response bytes"),
		},
		{
			name: "early payload is stripped",
			wire: earlyPayloadWire([]byte("challenge"), []byte("HTTP/2 response bytes")),
			want: []byte("HTTP/2 response bytes"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			clientConnection, serverConnection := net.Pipe()
			writerResult := make(chan error, 1)
			go func() {
				_, writeErr := serverConnection.Write(test.wire)
				writerResult <- errors.Join(writeErr, serverConnection.Close())
			}()

			got, err := io.ReadAll(newEarlyPayloadConn(clientConnection))
			_ = clientConnection.Close()
			if err != nil {
				t.Fatalf("ReadAll() error = %v", err)
			}
			if err := <-writerResult; err != nil {
				t.Fatalf("writer error = %v", err)
			}
			if !bytes.Equal(got, test.want) {
				t.Fatalf("payload = %q, want %q", got, test.want)
			}
		})
	}
}

func TestEarlyPayloadConn_RejectsOversizedPayload(t *testing.T) {
	t.Parallel()

	header := make([]byte, earlyPayloadHeaderLen)
	copy(header, earlyPayloadMagic)
	binary.BigEndian.PutUint32(header[len(earlyPayloadMagic):], maxEarlyPayloadBytes+1)
	clientConnection, serverConnection := net.Pipe()
	writerResult := make(chan error, 1)
	go func() {
		_, writeErr := serverConnection.Write(header)
		writerResult <- errors.Join(writeErr, serverConnection.Close())
	}()

	_, err := newEarlyPayloadConn(clientConnection).Read(make([]byte, 1))
	_ = clientConnection.Close()
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Read() error = %v, want size-limit error", err)
	}
	if err := <-writerResult; err != nil {
		t.Fatalf("writer error = %v", err)
	}
}

func earlyPayloadWire(early, body []byte) []byte {
	encoded := make([]byte, earlyPayloadHeaderLen, earlyPayloadHeaderLen+len(early)+len(body))
	copy(encoded, earlyPayloadMagic)
	binary.BigEndian.PutUint32(
		encoded[len(earlyPayloadMagic):],
		uint32(len(early)), //nolint:gosec // The helper is used only with bounded test fixtures.
	)
	encoded = append(encoded, early...)
	encoded = append(encoded, body...)

	return encoded
}

func TestClient_ProbeValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		controlURL     string
		responseStatus int
		responseBody   string
	}{
		{
			name:       "plain http",
			controlURL: "http://control.example.com",
		},
		{
			name:       "nonstandard port",
			controlURL: "https://control.example.com:8443",
		},
		{
			name:           "redirect",
			controlURL:     "https://control.example.com",
			responseStatus: http.StatusFound,
			responseBody:   `{}`,
		},
		{
			name:           "zero public key",
			controlURL:     "https://control.example.com",
			responseStatus: http.StatusOK,
			responseBody:   `{"publicKey":"mkey:0000000000000000000000000000000000000000000000000000000000000000"}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			client := newWithHTTPClient(&http.Client{
				Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
					if test.responseStatus == 0 {
						t.Fatal("transport called for an invalid control url")
					}

					return jsonResponse(test.responseStatus, test.responseBody), nil
				}),
			})
			if _, err := client.Probe(t.Context(), test.controlURL); err == nil {
				t.Fatal("Probe() error = nil, want validation error")
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(strings.NewReader(body)),
	}
}

var _ http.RoundTripper = roundTripFunc(nil)

func runNoiseTestServer(
	ctx context.Context,
	connection net.Conn,
	controlKey key.MachinePrivate,
	result chan<- error,
) {
	defer func() { _ = connection.Close() }()

	reader := bufio.NewReader(connection)
	request, err := http.ReadRequest(reader)
	if err != nil {
		result <- fmt.Errorf("reading upgrade request: %w", err)

		return
	}
	if request.Method != http.MethodPost || request.URL.Path != "/ts2021" {
		result <- fmt.Errorf("unexpected upgrade request %s %s", request.Method, request.URL.Path)

		return
	}
	initial, err := base64.StdEncoding.DecodeString(
		request.Header.Get(controlhttpcommon.HandshakeHeaderName),
	)
	if err != nil {
		result <- fmt.Errorf("decoding handshake header: %w", err)

		return
	}
	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Connection: upgrade\r\n" +
		"Upgrade: " + controlhttpcommon.UpgradeHeaderValue + "\r\n\r\n"
	if _, err := io.WriteString(connection, response); err != nil {
		result <- fmt.Errorf("writing upgrade response: %w", err)

		return
	}

	secureConnection, err := controlbase.Server(ctx, connection, controlKey, initial)
	if err != nil {
		result <- fmt.Errorf("completing server noise handshake: %w", err)

		return
	}
	_, readErr := io.Copy(io.Discard, secureConnection)
	closeErr := secureConnection.Close()
	if readErr != nil && !errors.Is(readErr, net.ErrClosed) {
		result <- fmt.Errorf("waiting for client close: %w", readErr)

		return
	}
	result <- closeErr
}
