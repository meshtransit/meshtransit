//go:build integration

// Package protocoltest provides bounded black-box clients for integration
// testing the legacy control protocol adapter.
package protocoltest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"

	"tailscale.com/types/key"
)

const (
	maxCredentialLength = 1024
	maxServerNameLength = 253
	maxHostnameLength   = 253
)

var (
	// ErrInvalidClient reports malformed test client configuration.
	ErrInvalidClient = errors.New("protocol test: invalid client")
	// ErrRegistration reports a failed or rejected black-box registration.
	ErrRegistration = errors.New("protocol test: registration failed")
	// ErrMap reports a failed or rejected black-box map exchange.
	ErrMap = errors.New("protocol test: map exchange failed")
)

// Options contains one synthetic control origin and its trust material.
type Options struct {
	ControlAddress string
	TLSServerName  string
	RootCAPEM      []byte
	Hostname       string
}

// Identity is the raw public identity generated for one test client.
type Identity struct {
	MachineKey [32]byte
	NodeKey    [32]byte
}

// Client performs one bounded registration exchange per call and retains only
// the synthetic machine and Node private keys needed to exercise replay.
type Client struct {
	controlAddress string
	tlsServerName  string
	hostname       string
	tlsConfig      *tls.Config
	machineKey     key.MachinePrivate
	nodeKey        key.NodePrivate
	identity       Identity
}

// NewClient validates a synthetic origin, builds an isolated trust store, and
// generates fresh client identity without starting goroutines or dialing I/O.
func NewClient(options Options) (*Client, error) {
	if !validOptions(options) {
		return nil, ErrInvalidClient
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(options.RootCAPEM) {
		return nil, ErrInvalidClient
	}
	machineKey := key.NewMachine()
	machinePublic, err := rawMachinePublic(machineKey.Public())
	if err != nil {
		return nil, ErrInvalidClient
	}
	nodeKey := key.NewNode()
	nodePublic, err := rawNodePublic(nodeKey.Public())
	if err != nil {
		return nil, ErrInvalidClient
	}
	return &Client{
		controlAddress: options.ControlAddress,
		tlsServerName:  options.TLSServerName,
		hostname:       options.Hostname,
		tlsConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
			ServerName: options.TLSServerName,
			NextProtos: []string{"http/1.1"},
		},
		machineKey: machineKey,
		nodeKey:    nodeKey,
		identity: Identity{
			MachineKey: machinePublic,
			NodeKey:    nodePublic,
		},
	}, nil
}

// Identity returns a copy of the public identity used by registration calls.
func (client *Client) Identity() Identity {
	if client == nil {
		return Identity{}
	}
	return client.identity
}

// Register discovers the control key, establishes a fresh authenticated
// session, and submits one credential registration request.
func (client *Client) Register(ctx context.Context, credential string) (resultErr error) {
	if ctx == nil || client == nil || client.tlsConfig == nil ||
		len(credential) == 0 || len(credential) > maxCredentialLength ||
		strings.ContainsAny(credential, "\x00\r\n") {
		return ErrInvalidClient
	}
	controlKey, err := client.discoverControlKey(ctx)
	if err != nil {
		return errors.Join(ErrRegistration, err)
	}
	session, err := client.openSession(ctx, controlKey)
	if err != nil {
		return errors.Join(ErrRegistration, err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, session.Close())
	}()
	if err := client.register(ctx, session, credential); err != nil {
		return errors.Join(ErrRegistration, err)
	}
	return nil
}

// FetchFullMap discovers the control key, establishes a fresh authenticated
// session, and fetches one complete fail-closed map snapshot.
func (client *Client) FetchFullMap(ctx context.Context) (_ FullMap, resultErr error) {
	if ctx == nil || client == nil || client.tlsConfig == nil {
		return FullMap{}, ErrInvalidClient
	}
	controlKey, err := client.discoverControlKey(ctx)
	if err != nil {
		return FullMap{}, errors.Join(ErrMap, err)
	}
	session, err := client.openSession(ctx, controlKey)
	if err != nil {
		return FullMap{}, errors.Join(ErrMap, err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, session.Close())
	}()
	result, err := client.fetchFullMap(ctx, session)
	if err != nil {
		return FullMap{}, errors.Join(ErrMap, err)
	}
	return result, nil
}

// FetchInitialStreamMap opens a streaming request, validates its first full
// snapshot, then closes both the HTTP/2 stream and authenticated session.
func (client *Client) FetchInitialStreamMap(ctx context.Context) (_ FullMap, resultErr error) {
	if ctx == nil || client == nil || client.tlsConfig == nil {
		return FullMap{}, ErrInvalidClient
	}
	controlKey, err := client.discoverControlKey(ctx)
	if err != nil {
		return FullMap{}, errors.Join(ErrMap, err)
	}
	session, err := client.openSession(ctx, controlKey)
	if err != nil {
		return FullMap{}, errors.Join(ErrMap, err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, session.Close())
	}()
	result, err := client.fetchInitialStreamMap(ctx, session)
	if err != nil {
		return FullMap{}, errors.Join(ErrMap, err)
	}
	return result, nil
}

func validOptions(options Options) bool {
	host, port, err := net.SplitHostPort(options.ControlAddress)
	if err != nil || host == "" || port == "" {
		return false
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 || len(options.RootCAPEM) == 0 {
		return false
	}
	return validBoundedName(options.TLSServerName, maxServerNameLength) &&
		validBoundedName(options.Hostname, maxHostnameLength)
}

func validBoundedName(value string, limit int) bool {
	return len(value) > 0 && len(value) <= limit && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n/\\")
}

func rawMachinePublic(publicKey key.MachinePublic) ([32]byte, error) {
	encoded, err := publicKey.MarshalText()
	if err != nil {
		return [32]byte{}, err
	}
	defer clear(encoded)
	return decodeTypedPublicKey(encoded, "mkey:")
}

func rawNodePublic(publicKey key.NodePublic) ([32]byte, error) {
	encoded, err := publicKey.MarshalText()
	if err != nil {
		return [32]byte{}, err
	}
	defer clear(encoded)
	return decodeTypedPublicKey(encoded, "nodekey:")
}

func decodeTypedPublicKey(encoded []byte, prefix string) ([32]byte, error) {
	if len(encoded) != len(prefix)+64 || !strings.HasPrefix(string(encoded), prefix) {
		return [32]byte{}, ErrInvalidClient
	}
	var raw [32]byte
	if _, err := hex.Decode(raw[:], encoded[len(prefix):]); err != nil {
		return [32]byte{}, err
	}
	if raw == ([32]byte{}) {
		return [32]byte{}, ErrInvalidClient
	}
	return raw, nil
}
