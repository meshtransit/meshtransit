//go:build integration

package protocoltest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"tailscale.com/control/controlbase"
	"tailscale.com/types/key"
)

const (
	testCapabilityVersion = 142
	testOperationTimeout  = 10 * time.Second
	testResponseLimit     = 64 << 10
	noiseUpgradeProtocol  = "tailscale-control-protocol"
	noiseHandshakeHeader  = "X-Tailscale-Handshake"
)

type session struct {
	connection *http2.ClientConn
}

func (session *session) Close() error {
	if session == nil || session.connection == nil {
		return nil
	}
	return session.connection.Close()
}

func (client *Client) discoverControlKey(ctx context.Context) (key.MachinePublic, error) {
	operationCtx, cancel := context.WithTimeout(ctx, testOperationTimeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: testOperationTimeout, KeepAlive: -1}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, client.controlAddress)
		},
		TLSClientConfig:       client.tlsConfig.Clone(),
		TLSHandshakeTimeout:   testOperationTimeout,
		ResponseHeaderTimeout: testOperationTimeout,
		DisableKeepAlives:     true,
	}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("protocol test: redirect rejected")
		},
	}
	request, err := http.NewRequestWithContext(
		operationCtx,
		http.MethodGet,
		"https://"+client.tlsServerName+"/key?v=142",
		nil,
	)
	if err != nil {
		return key.MachinePublic{}, fmt.Errorf("build control-key request: %w", err)
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return key.MachinePublic{}, fmt.Errorf("request control key: %w", err)
	}
	body, err := readResponse(response)
	if err != nil {
		return key.MachinePublic{}, fmt.Errorf("read control-key response: %w", err)
	}
	defer clear(body)
	if response.StatusCode != http.StatusOK || !isJSON(response.Header.Get("Content-Type")) {
		return key.MachinePublic{}, ErrInvalidClient
	}
	var document struct {
		PublicKey string `json:"publicKey"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return key.MachinePublic{}, fmt.Errorf("decode control key: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return key.MachinePublic{}, ErrInvalidClient
	}
	var publicKey key.MachinePublic
	if err := publicKey.UnmarshalText([]byte(document.PublicKey)); err != nil || publicKey.IsZero() {
		return key.MachinePublic{}, ErrInvalidClient
	}
	return publicKey, nil
}

func (client *Client) openSession(
	ctx context.Context,
	controlKey key.MachinePublic,
) (*session, error) {
	operationCtx, cancel := context.WithTimeout(ctx, testOperationTimeout)
	defer cancel()
	initial, continueHandshake, err := controlbase.ClientDeferred(
		client.machineKey,
		controlKey,
		testCapabilityVersion,
	)
	if err != nil {
		return nil, fmt.Errorf("begin authenticated handshake: %w", err)
	}
	defer clear(initial)

	outer, err := client.dialTLS(operationCtx)
	if err != nil {
		return nil, err
	}
	owned := false
	defer func() {
		if !owned {
			_ = outer.Close()
		}
	}()
	request, err := http.NewRequestWithContext(
		operationCtx,
		http.MethodPost,
		"https://"+client.tlsServerName+"/ts2021",
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("build authenticated upgrade request: %w", err)
	}
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", noiseUpgradeProtocol)
	request.Header.Set(noiseHandshakeHeader, base64.StdEncoding.EncodeToString(initial))
	if err := request.Write(outer); err != nil {
		return nil, fmt.Errorf("write authenticated upgrade request: %w", err)
	}
	reader := bufio.NewReaderSize(outer, testResponseLimit)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, fmt.Errorf("read authenticated upgrade response: %w", err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols ||
		!headerContainsToken(response.Header.Values("Connection"), "upgrade") ||
		!strings.EqualFold(response.Header.Get("Upgrade"), noiseUpgradeProtocol) {
		_ = response.Body.Close()
		return nil, ErrInvalidClient
	}
	secure, err := continueHandshake(
		operationCtx,
		&bufferedConnection{Conn: outer, reader: reader},
	)
	if err != nil {
		_ = response.Body.Close()
		return nil, fmt.Errorf("finish authenticated handshake: %w", err)
	}
	// For a 101 response the body aliases outer. The authenticated connection
	// now owns that socket, so replace the alias before satisfying body closure.
	response.Body = http.NoBody
	if err := response.Body.Close(); err != nil {
		_ = secure.Close()
		return nil, fmt.Errorf("close authenticated upgrade response: %w", err)
	}
	if err := secure.SetDeadline(time.Time{}); err != nil {
		_ = secure.Close()
		return nil, fmt.Errorf("clear authenticated session deadline: %w", err)
	}
	http2Transport := &http2.Transport{
		AllowHTTP:                  true,
		StrictMaxConcurrentStreams: true,
		ReadIdleTimeout:            2 * time.Second,
		PingTimeout:                time.Second,
		WriteByteTimeout:           2 * time.Second,
		MaxHeaderListSize:          32 << 10,
	}
	connection, err := http2Transport.NewClientConn(secure)
	if err != nil {
		_ = secure.Close()
		return nil, fmt.Errorf("start authenticated HTTP/2 session: %w", err)
	}
	owned = true
	return &session{connection: connection}, nil
}

func (client *Client) dialTLS(ctx context.Context) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: testOperationTimeout, KeepAlive: -1}
	raw, err := dialer.DialContext(ctx, "tcp", client.controlAddress)
	if err != nil {
		return nil, fmt.Errorf("dial control origin: %w", err)
	}
	connection := tls.Client(raw, client.tlsConfig.Clone())
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("bound control origin connection: %w", err)
		}
	}
	if err := connection.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("authenticate control origin: %w", err)
	}
	return connection, nil
}

func readResponse(response *http.Response) ([]byte, error) {
	if response == nil || response.Body == nil {
		return nil, ErrInvalidClient
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, testResponseLimit+1))
	closeErr := response.Body.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		clear(body)
		return nil, err
	}
	if len(body) > testResponseLimit {
		clear(body)
		return nil, ErrInvalidClient
	}
	return body, nil
}

func isJSON(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/json"
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

type bufferedConnection struct {
	net.Conn
	reader *bufio.Reader
}

func (connection *bufferedConnection) Read(buffer []byte) (int, error) {
	return connection.reader.Read(buffer)
}
