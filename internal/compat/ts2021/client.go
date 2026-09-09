// Package ts2021 isolates compatibility with the encrypted control protocol.
package ts2021

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailscale.com/control/controlbase"
	"tailscale.com/control/controlhttp/controlhttpcommon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	maxKeyResponseBytes   = 64 << 10
	maxUpgradeReadBytes   = 64 << 10
	maxEarlyPayloadBytes  = 64 << 10
	requestTimeout        = 15 * time.Second
	earlyPayloadMagic     = "\xff\xff\xffTS"
	earlyPayloadHeaderLen = 9
)

// Result contains non-secret compatibility facts about a control server.
type Result struct {
	Protocol         string
	Capability       int
	KeyFingerprint   string
	NoiseEstablished bool
	NoiseVersion     int
}

// Client performs bounded HTTPS compatibility probes.
type Client struct {
	httpClient *http.Client
	handshake  func(context.Context, *url.URL, key.MachinePublic) (int, error)
}

// New creates a client that uses system trust roots, TLS 1.2 or newer, port
// 443 only, and refuses redirects.
func New() *Client {
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		panic("ts2021: net/http default transport has an unexpected type")
	}
	transport := defaultTransport.Clone()
	transport.DisableCompression = true
	transport.ForceAttemptHTTP2 = true
	transport.MaxResponseHeaderBytes = maxKeyResponseBytes
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	return &Client{
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   requestTimeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		handshake: strictNoiseHandshake,
	}
}

func newWithHTTPClient(httpClient *http.Client) *Client {
	return &Client{
		httpClient: httpClient,
		handshake: func(_ context.Context, _ *url.URL, _ key.MachinePublic) (int, error) {
			return int(tailcfg.CurrentCapabilityVersion), nil
		},
	}
}

// Probe fetches and validates the control server key for capability 142. It
// returns only a SHA-256 fingerprint and never exposes the raw key.
func (c *Client) Probe(ctx context.Context, controlURL string) (Result, error) {
	if c == nil || c.httpClient == nil || c.handshake == nil {
		return Result{}, errors.New("ts2021: client is not initialized")
	}

	discovered, err := c.discoverControlKey(ctx, controlURL)
	if err != nil {
		return Result{}, err
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	noiseVersion, err := c.handshake(handshakeCtx, discovered.endpoint, discovered.publicKey)
	if err != nil {
		return Result{}, fmt.Errorf("ts2021: noise handshake failed: %w", err)
	}

	return Result{
		Protocol:         "ts2021",
		Capability:       int(tailcfg.CurrentCapabilityVersion),
		KeyFingerprint:   discovered.fingerprint,
		NoiseEstablished: true,
		NoiseVersion:     noiseVersion,
	}, nil
}

type discoveredControlKey struct {
	endpoint    *url.URL
	publicKey   key.MachinePublic
	fingerprint string
}

func (c *Client) discoverControlKey(
	ctx context.Context,
	controlURL string,
) (discoveredControlKey, error) {
	if c == nil || c.httpClient == nil {
		return discoveredControlKey{}, errors.New("ts2021: client is not initialized")
	}

	endpoint, err := keyEndpoint(controlURL)
	if err != nil {
		return discoveredControlKey{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return discoveredControlKey{}, fmt.Errorf("ts2021: creating key request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "meshd")

	response, err := c.httpClient.Do(request)
	if err != nil {
		return discoveredControlKey{}, fmt.Errorf("ts2021: fetching control key: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return discoveredControlKey{}, fmt.Errorf(
			"ts2021: control key endpoint returned http %d",
			response.StatusCode,
		)
	}
	if err := validateJSONContentType(response.Header.Get("Content-Type")); err != nil {
		return discoveredControlKey{}, err
	}
	if response.ContentLength > maxKeyResponseBytes {
		return discoveredControlKey{}, fmt.Errorf(
			"ts2021: control key response exceeds %d bytes",
			maxKeyResponseBytes,
		)
	}

	encoded, err := io.ReadAll(io.LimitReader(response.Body, maxKeyResponseBytes+1))
	if err != nil {
		return discoveredControlKey{}, fmt.Errorf("ts2021: reading control key response: %w", err)
	}
	if len(encoded) > maxKeyResponseBytes {
		return discoveredControlKey{}, fmt.Errorf(
			"ts2021: control key response exceeds %d bytes",
			maxKeyResponseBytes,
		)
	}

	keyResponse := tailcfg.OverTLSPublicKeyResponse{}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if err := decoder.Decode(&keyResponse); err != nil {
		return discoveredControlKey{}, fmt.Errorf("ts2021: decoding control key response: %w", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return discoveredControlKey{}, err
	}
	if keyResponse.PublicKey.IsZero() {
		return discoveredControlKey{}, errors.New("ts2021: control server returned a zero noise key")
	}
	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		return discoveredControlKey{}, fmt.Errorf("ts2021: parsing validated key endpoint: %w", err)
	}

	return discoveredControlKey{
		endpoint:    endpointURL,
		publicKey:   keyResponse.PublicKey,
		fingerprint: controlKeyFingerprint(keyResponse.PublicKey),
	}, nil
}

func controlKeyFingerprint(publicKey key.MachinePublic) string {
	publicText, err := publicKey.MarshalText()
	if err != nil {
		panic("ts2021: machine public key failed to marshal")
	}
	digest := sha256.Sum256(publicText)

	return "sha256:" + hex.EncodeToString(digest[:])
}

func keyEndpoint(controlURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(controlURL))
	if err != nil {
		return "", fmt.Errorf("ts2021: parsing control url: %w", err)
	}
	if parsed.Opaque != "" || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return "", errors.New("ts2021: control url must be an absolute https url")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" {
		return "", errors.New("ts2021: control url contains unsupported components")
	}
	if port := parsed.Port(); port != "" && port != "443" {
		return "", errors.New("ts2021: control url must use port 443")
	}

	parsed.Path = path.Join("/", parsed.Path, "key")
	query := parsed.Query()
	query.Set("v", strconv.Itoa(int(tailcfg.CurrentCapabilityVersion)))
	parsed.RawQuery = query.Encode()

	return parsed.String(), nil
}

func validateJSONContentType(contentType string) error {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" {
		return fmt.Errorf("ts2021: unexpected control key content type %q", contentType)
	}

	return nil
}

func ensureEOF(decoder *json.Decoder) error {
	var extra struct{}
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("ts2021: control key response contains multiple json values")
	}

	return fmt.Errorf("ts2021: validating control key response: %w", err)
}

func strictNoiseHandshake(
	ctx context.Context,
	keyURL *url.URL,
	controlKey key.MachinePublic,
) (int, error) {
	machineKey := key.NewMachine()
	connection, err := strictBaseNoiseConnection(ctx, keyURL, machineKey, controlKey)
	if err != nil {
		return 0, err
	}
	defer func() { _ = connection.Close() }()

	return connection.ProtocolVersion(), nil
}

type dialFunc func(context.Context, string, string) (net.Conn, error)

func noiseHandshake(
	ctx context.Context,
	keyURL *url.URL,
	controlKey key.MachinePublic,
	dial dialFunc,
) (int, error) {
	machineKey := key.NewMachine()
	connection, err := openNoiseConnection(ctx, keyURL, machineKey, controlKey, dial)
	if err != nil {
		return 0, err
	}
	defer func() { _ = connection.Close() }()

	return connection.ProtocolVersion(), nil
}

func strictBaseNoiseConnection(
	ctx context.Context,
	keyURL *url.URL,
	machineKey key.MachinePrivate,
	controlKey key.MachinePublic,
) (*controlbase.Conn, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: requestTimeout},
		Config: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: keyURL.Hostname(),
			NextProtos: []string{"http/1.1"},
		},
	}
	connection, err := openNoiseConnection(
		ctx,
		keyURL,
		machineKey,
		controlKey,
		dialer.DialContext,
	)
	if err != nil {
		return nil, err
	}

	return connection, nil
}

func openNoiseConnection(
	ctx context.Context,
	keyURL *url.URL,
	machineKey key.MachinePrivate,
	controlKey key.MachinePublic,
	dial dialFunc,
) (*controlbase.Conn, error) {
	initial, continueHandshake, err := controlbase.ClientDeferred(
		machineKey,
		controlKey,
		uint16(tailcfg.CurrentCapabilityVersion),
	)
	if err != nil {
		return nil, fmt.Errorf("creating noise initiation: %w", err)
	}
	if dial == nil {
		return nil, errors.New("noise dialer is required")
	}

	address := net.JoinHostPort(keyURL.Hostname(), "443")
	connection, err := dial(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("dialing tls control endpoint: %w", err)
	}
	isOwned := true
	defer func() {
		if isOwned {
			_ = connection.Close()
		}
	}()

	if deadline, exists := ctx.Deadline(); exists {
		if err := connection.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("setting control deadline: %w", err)
		}
	}

	upgradeURL := &url.URL{
		Scheme: "https",
		Host:   keyURL.Host,
		Path:   path.Join("/", path.Dir(keyURL.Path), "ts2021"),
	}
	request := &http.Request{
		Method: http.MethodPost,
		URL:    upgradeURL,
		Host:   keyURL.Host,
		Header: http.Header{
			"Accept":                              []string{"*/*"},
			"Connection":                          []string{"upgrade"},
			"Upgrade":                             []string{controlhttpcommon.UpgradeHeaderValue},
			"User-Agent":                          []string{"meshd"},
			controlhttpcommon.HandshakeHeaderName: []string{base64.StdEncoding.EncodeToString(initial)},
		},
	}
	if err := request.Write(connection); err != nil {
		return nil, fmt.Errorf("writing control upgrade request: %w", err)
	}

	limitedReader := &upgradeReader{
		reader:    connection,
		remaining: maxUpgradeReadBytes,
		isLimited: true,
	}
	reader := bufio.NewReader(limitedReader)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, fmt.Errorf("reading control upgrade response: %w", err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		_ = response.Body.Close()

		return nil, fmt.Errorf("control upgrade returned http %d", response.StatusCode)
	}
	if !headerContainsToken(response.Header.Values("Connection"), "upgrade") {
		_ = response.Body.Close()

		return nil, errors.New("control upgrade response omitted connection upgrade")
	}
	if !strings.EqualFold(response.Header.Get("Upgrade"), controlhttpcommon.UpgradeHeaderValue) {
		_ = response.Body.Close()

		return nil, errors.New("control upgrade response selected an unexpected protocol")
	}
	limitedReader.disableLimit()

	noiseConnection, err := continueHandshake(ctx, &bufferedConn{
		Conn:   connection,
		reader: reader,
	})
	if err != nil {
		return nil, fmt.Errorf("completing noise handshake: %w", err)
	}
	if err := noiseConnection.SetDeadline(time.Time{}); err != nil {
		_ = noiseConnection.Close()

		return nil, fmt.Errorf("clearing control deadline: %w", err)
	}
	isOwned = false

	return noiseConnection, nil
}

type upgradeReader struct {
	reader    io.Reader
	remaining int64
	isLimited bool
}

func (r *upgradeReader) Read(buffer []byte) (int, error) {
	if !r.isLimited {
		return r.reader.Read(buffer)
	}
	if r.remaining <= 0 {
		return 0, errors.New("control upgrade response headers exceed limit")
	}
	if int64(len(buffer)) > r.remaining {
		buffer = buffer[:r.remaining]
	}
	n, err := r.reader.Read(buffer)
	r.remaining -= int64(n)

	return n, err
}

func (r *upgradeReader) disableLimit() { r.isLimited = false }

// earlyPayloadConn strips the optional bounded server preface that precedes
// HTTP/2. Registration does not consume its challenge payload.
type earlyPayloadConn struct {
	net.Conn
	once   sync.Once
	reader io.Reader
	err    error
}

func newEarlyPayloadConn(connection net.Conn) *earlyPayloadConn {
	return &earlyPayloadConn{Conn: connection}
}

func (c *earlyPayloadConn) Read(buffer []byte) (int, error) {
	c.once.Do(c.readPreface)
	if c.err != nil {
		return 0, c.err
	}

	return c.reader.Read(buffer)
}

func (c *earlyPayloadConn) readPreface() {
	var header [earlyPayloadHeaderLen]byte
	if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
		c.err = fmt.Errorf("reading control http/2 preface: %w", err)

		return
	}
	if string(header[:len(earlyPayloadMagic)]) != earlyPayloadMagic {
		c.reader = io.MultiReader(bytes.NewReader(header[:]), c.Conn)

		return
	}
	payloadLength := int64(binary.BigEndian.Uint32(header[len(earlyPayloadMagic):]))
	if payloadLength > maxEarlyPayloadBytes {
		c.err = fmt.Errorf("control early payload exceeds %d bytes", maxEarlyPayloadBytes)

		return
	}
	if _, err := io.CopyN(io.Discard, c.Conn, payloadLength); err != nil {
		c.err = fmt.Errorf("reading control early payload: %w", err)

		return
	}
	c.reader = c.Conn
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(buffer []byte) (int, error) {
	return c.reader.Read(buffer)
}

func headerContainsToken(values []string, target string) bool {
	for _, value := range values {
		for token := range strings.SplitSeq(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), target) {
				return true
			}
		}
	}

	return false
}
