package legacyts2021

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"tailscale.com/control/controlbase"
	"tailscale.com/types/key"

	"github.com/meshtransit/meshtransit/core/internal/control"
)

func TestControlServerBindsNoisePeerToHTTP2Session(t *testing.T) {
	t.Parallel()

	machines := make(chan control.AuthenticatedMachine, 1)
	factory := &recordingAuthenticatedHandlerFactory{
		machines: machines,
		handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodGet || request.URL.Path != "/session" {
				http.NotFound(response, request)
				return
			}
			response.WriteHeader(http.StatusNoContent)
		}),
	}
	server := newControlServerFixture(t, factory)
	clientKey := key.NewMachine()
	initial, continueHandshake, err := controlbase.ClientDeferred(
		clientKey,
		server.privateKey.value.Public(),
		uint16(supportedCapabilityVersion),
	)
	if err != nil {
		t.Fatalf("controlbase.ClientDeferred() error = %v", err)
	}
	defer clear(initial)

	clientConnection, serverConnection := net.Pipe()
	upgradeRequest := newNoiseUpgradeRequestWithInitial(t, initial)
	hijacker := newPipeHijacker(serverConnection)
	handlerDone := make(chan struct{})
	var handlers sync.WaitGroup
	handlers.Go(func() {
		defer close(handlerDone)
		server.ServeHTTP(hijacker, upgradeRequest)
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	reader := bufio.NewReader(clientConnection)
	upgradeResponse, err := http.ReadResponse(reader, upgradeRequest)
	if err != nil {
		_ = clientConnection.Close()
		t.Fatalf("http.ReadResponse() error = %v", err)
	}
	if upgradeResponse.StatusCode != http.StatusSwitchingProtocols {
		_ = clientConnection.Close()
		t.Fatalf("upgrade status = %d, want 101", upgradeResponse.StatusCode)
	}
	defer func() { _ = upgradeResponse.Body.Close() }()
	secureConnection, err := continueHandshake(
		ctx,
		&bufferedReadConn{Conn: clientConnection, reader: reader},
	)
	if err != nil {
		_ = clientConnection.Close()
		t.Fatalf("continueHandshake() error = %v", err)
	}
	if err := secureConnection.SetDeadline(time.Time{}); err != nil {
		_ = secureConnection.Close()
		t.Fatalf("secure connection SetDeadline() error = %v", err)
	}

	var dialed atomic.Bool
	transport := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(
			_ context.Context,
			network string,
			address string,
			_ *tls.Config,
		) (net.Conn, error) {
			if network != "tcp" || address != "control.example:80" || dialed.Swap(true) {
				return nil, errors.New("unexpected HTTP/2 dial")
			}
			return secureConnection, nil
		},
	}
	sessionRequest, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"http://control.example/session",
		nil,
	)
	if err != nil {
		t.Fatalf("http.NewRequestWithContext() error = %v", err)
	}
	sessionResponse, err := transport.RoundTrip(sessionRequest)
	if err != nil {
		_ = secureConnection.Close()
		t.Fatalf("HTTP/2 RoundTrip() error = %v", err)
	}
	if sessionResponse.StatusCode != http.StatusNoContent {
		_ = sessionResponse.Body.Close()
		_ = secureConnection.Close()
		t.Fatalf("session status = %d, want 204", sessionResponse.StatusCode)
	}
	if err := sessionResponse.Body.Close(); err != nil {
		t.Fatalf("session response close error = %v", err)
	}

	var machine control.AuthenticatedMachine
	select {
	case machine = <-machines:
	case <-ctx.Done():
		t.Fatalf("authenticated machine unavailable: %v", ctx.Err())
	}
	registrationRequest, err := DecodeCredentialRegistration(
		strings.NewReader(validRegistrationRequestJSON),
		parseRegistrationID(t),
	)
	if err != nil {
		t.Fatalf("DecodeCredentialRegistration() error = %v", err)
	}
	bound, err := machine.BindRegistration(registrationRequest)
	if err != nil {
		t.Fatalf("AuthenticatedMachine.BindRegistration() error = %v", err)
	}
	clientPublic, err := clientKey.Public().MarshalText()
	if err != nil {
		t.Fatalf("MachinePublic.MarshalText() error = %v", err)
	}
	defer clear(clientPublic)
	var wantMachineKey [32]byte
	if _, err := hex.Decode(wantMachineKey[:], clientPublic[len("mkey:"):]); err != nil {
		t.Fatalf("hex.Decode(machine key) error = %v", err)
	}
	if bound.Identity.MachineKey().Bytes() != wantMachineKey {
		t.Fatal("Noise peer identity was not bound to the authenticated handler")
	}

	transport.CloseIdleConnections()
	_ = secureConnection.Close()
	select {
	case <-handlerDone:
	case <-ctx.Done():
		t.Fatalf("control session did not stop: %v", ctx.Err())
	}
	handlers.Wait()
	metrics := gatherControlMetrics(t, server.telemetry)
	for _, value := range []string{
		`meshtransit_control_session_attempts_total{result="established"} 1`,
		`meshtransit_control_noise_handshake_duration_seconds_count{result="success"} 1`,
		`meshtransit_control_session_slots_active 0`,
		`meshtransit_control_authenticated_sessions_active 0`,
	} {
		if !strings.Contains(metrics, value) {
			t.Fatalf("established session metrics missing %q: %s", value, metrics)
		}
	}
}

func TestControlServerRejectsUnsupportedNoiseCapability(t *testing.T) {
	t.Parallel()

	machines := make(chan control.AuthenticatedMachine, 1)
	server := newControlServerFixture(t, &recordingAuthenticatedHandlerFactory{
		machines: machines,
		handler:  http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
	})
	clientKey := key.NewMachine()
	initial, continueHandshake, err := controlbase.ClientDeferred(
		clientKey,
		server.privateKey.value.Public(),
		uint16(supportedCapabilityVersion-1),
	)
	if err != nil {
		t.Fatalf("controlbase.ClientDeferred() error = %v", err)
	}
	defer clear(initial)

	clientConnection, serverConnection := net.Pipe()
	upgradeRequest := newNoiseUpgradeRequestWithInitial(t, initial)
	handlerDone := make(chan struct{})
	var handlers sync.WaitGroup
	handlers.Go(func() {
		defer close(handlerDone)
		server.ServeHTTP(newPipeHijacker(serverConnection), upgradeRequest)
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	reader := bufio.NewReader(clientConnection)
	upgradeResponse, err := http.ReadResponse(reader, upgradeRequest)
	if err != nil {
		_ = clientConnection.Close()
		t.Fatalf("http.ReadResponse() error = %v", err)
	}
	defer func() { _ = upgradeResponse.Body.Close() }()
	if upgradeResponse.StatusCode != http.StatusSwitchingProtocols {
		_ = clientConnection.Close()
		t.Fatalf("upgrade status = %d, want 101", upgradeResponse.StatusCode)
	}
	secureConnection, handshakeErr := continueHandshake(
		ctx,
		&bufferedReadConn{Conn: clientConnection, reader: reader},
	)
	if handshakeErr == nil {
		_ = secureConnection.Close()
	} else {
		_ = clientConnection.Close()
	}
	select {
	case <-handlerDone:
	case <-ctx.Done():
		t.Fatalf("unsupported session did not stop: %v", ctx.Err())
	}
	handlers.Wait()
	select {
	case <-machines:
		t.Fatal("unsupported capability reached authenticated session handler")
	default:
	}
	metrics := gatherControlMetrics(t, server.telemetry)
	if !strings.Contains(
		metrics,
		`meshtransit_control_session_attempts_total{result="capability_failure"} 1`,
	) {
		t.Fatalf("unsupported capability metrics missing bounded result: %s", metrics)
	}
}
