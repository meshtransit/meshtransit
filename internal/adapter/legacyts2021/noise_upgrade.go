package legacyts2021

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"tailscale.com/control/controlbase"

	"github.com/meshtransit/meshtransit/internal/control"
	"github.com/meshtransit/meshtransit/internal/node"
)

const (
	noiseHandshakeHeader    = "X-Tailscale-Handshake"
	noiseUpgradeProtocol    = "tailscale-control-protocol"
	maxNoiseInitiationBytes = 4 << 10
)

func (server *ControlServer) serveNoiseUpgrade(
	response http.ResponseWriter,
	request *http.Request,
) {
	setResponseHeaders(response)
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		http.Error(response, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if err := validateNoiseUpgradeRequest(request); err != nil {
		http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	initial, err := decodeNoiseInitiation(request.Header.Values(noiseHandshakeHeader))
	if err != nil {
		http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	defer clear(initial)
	if !server.beginSession() {
		http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	defer server.endSession()

	hijacker, ok := response.(http.Hijacker)
	if !ok {
		http.Error(response, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	connection, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	if !server.trackConnection(connection) {
		_ = connection.Close()
		return
	}
	defer server.finishConnection(connection)
	defer func() { _ = connection.Close() }()

	if err := writeUpgradeResponse(buffered); err != nil {
		server.logRejectedSession(request.Context(), "upgrade_response_failure")
		return
	}
	handshakeCtx, cancel := context.WithTimeout(request.Context(), server.handshakeTimeout)
	defer cancel()
	secureConnection, err := controlbase.Server(
		handshakeCtx,
		&bufferedReadConn{Conn: connection, reader: buffered.Reader},
		server.privateKey.value,
		initial,
	)
	if err != nil {
		server.logRejectedSession(request.Context(), "noise_handshake_failure")
		return
	}
	defer func() { _ = secureConnection.Close() }()
	if err := secureConnection.SetDeadline(time.Time{}); err != nil {
		server.logRejectedSession(request.Context(), "noise_deadline_failure")
		return
	}
	if secureConnection.ProtocolVersion() != supportedCapabilityVersion {
		server.logRejectedSession(request.Context(), "unsupported_capability")
		return
	}
	machine, err := authenticatedMachineFromNoise(secureConnection)
	if err != nil {
		server.logRejectedSession(request.Context(), "noise_identity_failure")
		return
	}
	handler, err := server.sessions.Handler(machine)
	if err != nil || handler == nil {
		server.logRejectedSession(request.Context(), "session_handler_failure")
		return
	}
	server.http2Server.ServeConn(secureConnection, &http2.ServeConnOpts{
		Context: request.Context(),
		BaseConfig: &http.Server{
			ReadHeaderTimeout: server.handshakeTimeout,
			MaxHeaderBytes:    maxControlHeaderBytes,
		},
		Handler: handler,
	})
}

func validateNoiseUpgradeRequest(request *http.Request) error {
	if request.URL.RawQuery != "" || !headerContainsToken(request.Header.Values("Connection"), "upgrade") ||
		len(request.Header.Values("Upgrade")) != 1 ||
		!strings.EqualFold(request.Header.Get("Upgrade"), noiseUpgradeProtocol) {
		return ErrInvalidControlServer
	}
	return nil
}

func decodeNoiseInitiation(values []string) ([]byte, error) {
	if len(values) != 1 || values[0] == "" ||
		len(values[0]) > base64.StdEncoding.EncodedLen(maxNoiseInitiationBytes) {
		return nil, ErrInvalidControlServer
	}
	initial, err := base64.StdEncoding.Strict().DecodeString(values[0])
	if err != nil || len(initial) == 0 || len(initial) > maxNoiseInitiationBytes {
		clear(initial)
		return nil, ErrInvalidControlServer
	}
	return initial, nil
}

func writeUpgradeResponse(buffered *bufio.ReadWriter) error {
	if buffered == nil {
		return ErrInvalidControlServer
	}
	if _, err := buffered.WriteString(
		"HTTP/1.1 101 Switching Protocols\r\n" +
			"Connection: upgrade\r\n" +
			"Upgrade: " + noiseUpgradeProtocol + "\r\n\r\n",
	); err != nil {
		return err
	}
	return buffered.Flush()
}

func authenticatedMachineFromNoise(connection *controlbase.Conn) (control.AuthenticatedMachine, error) {
	if connection == nil {
		return control.AuthenticatedMachine{}, ErrInvalidControlServer
	}
	encoded, err := connection.Peer().MarshalText()
	defer clear(encoded)
	if err != nil || len(encoded) != len("mkey:")+64 ||
		!bytes.HasPrefix(encoded, []byte("mkey:")) {
		return control.AuthenticatedMachine{}, ErrInvalidControlServer
	}
	var raw [32]byte
	if _, err := hex.Decode(raw[:], encoded[len("mkey:"):]); err != nil {
		return control.AuthenticatedMachine{}, ErrInvalidControlServer
	}
	machineKey, err := node.NewMachineKey(raw)
	clear(raw[:])
	if err != nil {
		return control.AuthenticatedMachine{}, ErrInvalidControlServer
	}
	return control.NewAuthenticatedMachine(machineKey)
}

func (server *ControlServer) logRejectedSession(ctx context.Context, code string) {
	server.logger.DebugContext(ctx, "control session rejected", "error_code", code)
}

func headerContainsToken(values []string, token string) bool {
	for _, value := range values {
		for part := range strings.SplitSeq(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

type bufferedReadConn struct {
	net.Conn
	reader *bufio.Reader
}

func (connection *bufferedReadConn) Read(buffer []byte) (int, error) {
	return connection.reader.Read(buffer)
}
