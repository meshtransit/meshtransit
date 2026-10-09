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

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/node"
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
		server.telemetry.recordSessionAttempt(sessionAttemptInvalidRequest)
		response.Header().Set("Allow", http.MethodPost)
		http.Error(response, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if err := validateNoiseUpgradeRequest(request); err != nil {
		server.telemetry.recordSessionAttempt(sessionAttemptInvalidRequest)
		http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	initial, err := decodeNoiseInitiation(request.Header.Values(noiseHandshakeHeader))
	if err != nil {
		server.telemetry.recordSessionAttempt(sessionAttemptInvalidRequest)
		http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	defer clear(initial)
	admission := server.beginSession()
	if admission != sessionAdmissionAccepted {
		result := sessionAttemptShutdown
		if admission == sessionAdmissionCapacity {
			result = sessionAttemptCapacity
		}
		server.rejectSession(request.Context(), result)
		http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	defer server.endSession()

	hijacker, ok := response.(http.Hijacker)
	if !ok {
		server.rejectSession(request.Context(), sessionAttemptTransportFailure)
		http.Error(response, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	connection, buffered, err := hijacker.Hijack()
	if err != nil {
		server.rejectSession(request.Context(), sessionAttemptTransportFailure)
		return
	}
	if !server.trackConnection(connection) {
		server.rejectSession(request.Context(), sessionAttemptShutdown)
		_ = connection.Close()
		return
	}
	defer server.finishConnection(connection)
	defer func() { _ = connection.Close() }()

	if err := writeUpgradeResponse(buffered); err != nil {
		server.rejectSession(request.Context(), sessionAttemptTransportFailure)
		return
	}
	handshakeCtx, cancel := context.WithTimeout(request.Context(), server.handshakeTimeout)
	defer cancel()
	handshakeStarted := time.Now()
	secureConnection, err := controlbase.Server(
		handshakeCtx,
		&bufferedReadConn{Conn: connection, reader: buffered.Reader},
		server.privateKey.value,
		initial,
	)
	server.telemetry.recordHandshake(time.Since(handshakeStarted), err == nil)
	if err != nil {
		server.rejectSession(request.Context(), sessionAttemptHandshakeFailure)
		return
	}
	defer func() { _ = secureConnection.Close() }()
	if secureConnection.ProtocolVersion() != supportedCapabilityVersion {
		server.rejectSession(request.Context(), sessionAttemptCapabilityFailure)
		return
	}
	if err := secureConnection.SetDeadline(time.Time{}); err != nil {
		server.rejectSession(request.Context(), sessionAttemptTransportFailure)
		return
	}
	machine, err := authenticatedMachineFromNoise(secureConnection)
	if err != nil {
		server.rejectSession(request.Context(), sessionAttemptIdentityFailure)
		return
	}
	handler, err := server.sessions.Handler(machine)
	if err != nil || handler == nil {
		server.rejectSession(request.Context(), sessionAttemptHandlerFailure)
		return
	}
	server.telemetry.recordSessionAttempt(sessionAttemptEstablished)
	sessionStarted := server.telemetry.authenticatedSessionOpened()
	defer server.telemetry.authenticatedSessionClosed(sessionStarted)
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

func (server *ControlServer) rejectSession(ctx context.Context, result sessionAttemptResult) {
	server.telemetry.recordSessionAttempt(result)
	server.logger.DebugContext(ctx, "control session rejected", "error_code", result.label())
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
