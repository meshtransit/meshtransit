// Package routeagent implements the mutually authenticated Private Endpoint
// gateway protocol. It accepts only exact idempotent desired-state commands.
package routeagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/sharing/endpointpublication"
)

const (
	maximumCommandBytes  = 64 * 1024
	maximumResponseBytes = 4 * 1024
)

var (
	// ErrInvalidClient reports unsafe transport configuration.
	ErrInvalidClient = errors.New("route agent: invalid client")
	// ErrUnavailable conceals transport details from the reconciliation domain.
	ErrUnavailable = errors.New("route agent: unavailable")
	// ErrRejected reports a non-authoritative or mismatched acknowledgement.
	ErrRejected = errors.New("route agent: command rejected")
)

// Options contains one exact TLS origin and client identity.
type Options struct {
	Origin            string
	ServerCA          []byte
	ClientCertificate []byte
	ClientPrivateKey  []byte
	Timeout           time.Duration
}

type doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client applies and removes route generations through a fixed mTLS origin.
type Client struct {
	origin    *url.URL
	client    doer
	transport *http.Transport
	timeout   time.Duration
}

// New validates all trust material and constructs an isolated no-proxy client.
func New(options Options) (*Client, error) {
	origin, err := parseOrigin(options.Origin)
	if err != nil || options.Timeout < 100*time.Millisecond || options.Timeout > 30*time.Second {
		return nil, ErrInvalidClient
	}
	roots := x509.NewCertPool()
	if len(options.ServerCA) == 0 || !roots.AppendCertsFromPEM(options.ServerCA) {
		return nil, ErrInvalidClient
	}
	certificate, err := tls.X509KeyPair(options.ClientCertificate, options.ClientPrivateKey)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, ErrInvalidClient
	}
	dialer := &net.Dialer{Timeout: options.Timeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true,
		DisableCompression: true, MaxIdleConns: 8, MaxIdleConnsPerHost: 4, MaxConnsPerHost: 8,
		IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: options.Timeout,
		ResponseHeaderTimeout: options.Timeout, MaxResponseHeaderBytes: 16 * 1024,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{certificate},
			ServerName: origin.Hostname(),
		},
	}
	client := &http.Client{
		Transport: transport, Timeout: options.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &Client{origin: origin, client: client, transport: transport, timeout: options.Timeout}, nil
}

// Apply makes the exact route generation active or confirms it is already active.
func (client *Client) Apply(ctx context.Context, route endpointpublication.Route, hash [sha256.Size]byte) error {
	canonical, err := route.Hash()
	if err != nil || canonical != hash {
		return ErrInvalidClient
	}
	return client.command(ctx, http.MethodPut, route.EndpointID, route.EndpointGeneration, route, hash)
}

// Withdraw removes the exact route generation or confirms it is already absent.
func (client *Client) Withdraw(ctx context.Context, command endpointpublication.Withdrawal, hash [sha256.Size]byte) error {
	canonical, err := command.Hash()
	if err != nil || canonical != hash {
		return ErrInvalidClient
	}
	return client.command(ctx, http.MethodDelete, command.EndpointID, command.EndpointGeneration, command, hash)
}

func (client *Client) command(
	ctx context.Context,
	method string,
	endpointID string,
	generation int64,
	payload any,
	hash [sha256.Size]byte,
) error {
	if ctx == nil || client == nil || client.origin == nil || client.client == nil ||
		(method != http.MethodPut && method != http.MethodDelete) || generation <= 0 ||
		hash == ([sha256.Size]byte{}) {
		return ErrInvalidClient
	}
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumCommandBytes {
		return ErrInvalidClient
	}
	commandURL := *client.origin
	commandURL.Path = "/v1/private-endpoint-routes/" + endpointID
	request, err := http.NewRequestWithContext(ctx, method, commandURL.String(), bytes.NewReader(encoded))
	if err != nil {
		return ErrInvalidClient
	}
	hashText := hex.EncodeToString(hash[:])
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-MeshTransit-Route-SHA256", hashText)
	request.Header.Set("X-MeshTransit-Endpoint-Generation", strconv.FormatInt(generation, 10))
	operation := "apply"
	if method == http.MethodDelete {
		operation = "withdraw"
	}
	request.Header.Set("X-MeshTransit-Operation", operation)
	request.Header.Set("Idempotency-Key", endpointID+":"+strconv.FormatInt(generation, 10)+":"+hashText)

	response, err := client.client.Do(request)
	if err != nil {
		return errors.Join(ErrUnavailable, ctx.Err())
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(body) > maximumResponseBytes {
		return errors.Join(ErrUnavailable, ctx.Err())
	}
	if response.StatusCode != http.StatusNoContent || len(body) != 0 ||
		response.Header.Get("X-MeshTransit-Route-SHA256") != hashText ||
		response.Header.Get("X-MeshTransit-Endpoint-Generation") != strconv.FormatInt(generation, 10) ||
		response.Header.Get("X-MeshTransit-Operation") != operation {
		return ErrRejected
	}
	return nil
}

// CloseIdleConnections releases pooled transport resources after workers join.
func (client *Client) CloseIdleConnections() {
	if client != nil && client.transport != nil {
		client.transport.CloseIdleConnections()
	}
}

func parseOrigin(value string) (*url.URL, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return nil, ErrInvalidClient
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" || parsed.RawPath != "" {
		return nil, ErrInvalidClient
	}
	if parsed.Hostname() == "" {
		return nil, ErrInvalidClient
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return nil, ErrInvalidClient
	}
	if port := parsed.Port(); port != "" {
		value, portErr := strconv.ParseUint(port, 10, 16)
		if portErr != nil || value == 0 {
			return nil, ErrInvalidClient
		}
	}
	return parsed, nil
}
