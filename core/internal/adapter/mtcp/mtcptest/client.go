// Package mtcptest is a test-only MTCP v1 node (docs/protocol/mtcp-v1.md)
// for black-box tests of a running Core control process. It dials the
// control listener over TLS with a pinned test root, pins the control key
// from the key document on first use, registers with an enrollment key,
// reads map streams into comparable values and sends endpoint reports.
//
// Production code must never import this package: it keeps synthetic
// private keys in memory, trusts the key document without a ck= fingerprint
// and fails on anything unexpected instead of recovering like meshd.
package mtcptest

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"meshtransit.net/shared/key"
)

const (
	maxCredentialLength = 1024
	maxServerNameLength = 253
	maxHostnameLength   = 253
)

var (
	// ErrInvalidClient reports malformed test client configuration or input.
	ErrInvalidClient = errors.New("mtcptest: invalid client")
	// ErrSession reports a failed key discovery, upgrade or handshake.
	ErrSession = errors.New("mtcptest: session failed")
	// ErrRegistration reports a failed or rejected registration.
	ErrRegistration = errors.New("mtcptest: registration failed")
	// ErrMap reports a failed, ended or malformed map stream.
	ErrMap = errors.New("mtcptest: map stream failed")
)

// Options contains one synthetic control origin and its trust material.
type Options struct {
	ControlAddress string // host:port the TLS connection dials
	TLSServerName  string // the control host the certificate names
	RootCAPEM      []byte
	Hostname       string
}

// Identity is the raw public identity generated for one test client.
type Identity struct {
	MachineKey [32]byte
	NodeKey    [32]byte
}

// Connectivity is the synthetic endpoint report the client sends. Every
// endpoint is reported as server-reflexive (STUN).
type Connectivity struct {
	DiscoveryKey [32]byte
	Endpoints    []netip.AddrPort
}

// ControlKey is a control key pinned from the key document.
type ControlKey struct {
	Public   [32]byte
	NotAfter time.Time
}

// Client is one synthetic node installation: a machine key, a node key and
// a disco key that survive every session, so registration can be replayed.
// Calls are bounded by their contexts and may run one at a time; Identity,
// Connectivity and PinnedControlKey are safe at any time.
type Client struct {
	controlAddress string
	serverName     string
	hostname       string
	tlsConfig      *tls.Config
	machine        key.MachinePrivate
	node           key.NodePrivate
	disco          key.DiscoPrivate
	identity       Identity

	mu            sync.Mutex
	connectivity  Connectivity
	control       ControlKey // zero until the key document was read
	lastTimestamp int64      // the last ClientHello timestamp, in Unix ms
}

// SetControlAddress makes later dials go to address, as a load balancer
// might place a reconnecting node on another replica.
func (client *Client) SetControlAddress(address string) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.controlAddress = address
}

func (client *Client) address() string {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.controlAddress
}

// NewClient validates a synthetic origin, builds an isolated trust store and
// generates fresh keys without dialing.
func NewClient(options Options) (*Client, error) {
	if !validOptions(options) {
		return nil, ErrInvalidClient
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(options.RootCAPEM) {
		return nil, ErrInvalidClient
	}
	machine, err := key.NewMachinePrivate(nil)
	if err != nil {
		return nil, errors.Join(ErrInvalidClient, err)
	}
	node, err := newNodePrivate()
	if err != nil {
		return nil, errors.Join(ErrInvalidClient, err)
	}
	disco, err := key.NewDiscoPrivate()
	if err != nil {
		return nil, errors.Join(ErrInvalidClient, err)
	}
	return &Client{
		controlAddress: options.ControlAddress,
		serverName:     options.TLSServerName,
		hostname:       options.Hostname,
		tlsConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
			ServerName: options.TLSServerName,
			NextProtos: []string{"http/1.1"},
		},
		machine:  machine,
		node:     node,
		disco:    disco,
		identity: Identity{MachineKey: machine.Public(), NodeKey: node.Public()},
		connectivity: Connectivity{
			DiscoveryKey: disco.Public(),
			// Not a relay's address, which Core never distributes.
			Endpoints: []netip.AddrPort{netip.MustParseAddrPort("198.51.100.10:41641")},
		},
	}, nil
}

// newNodePrivate draws a node key; X25519 accepts any non-zero scalar.
func newNodePrivate() (key.NodePrivate, error) {
	var raw [key.Size]byte
	defer clear(raw[:])
	if _, err := rand.Read(raw[:]); err != nil {
		return key.NodePrivate{}, err
	}
	return key.NodePrivateFromBytes(raw[:])
}

// Identity returns a copy of the public identity used by every session.
func (client *Client) Identity() Identity {
	if client == nil {
		return Identity{}
	}
	return client.identity
}

// Connectivity returns a caller-owned copy of the synthetic endpoint report.
func (client *Client) Connectivity() Connectivity {
	if client == nil {
		return Connectivity{}
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	return Connectivity{
		DiscoveryKey: client.connectivity.DiscoveryKey,
		Endpoints:    slices.Clone(client.connectivity.Endpoints),
	}
}

// PinnedControlKey returns the control key pinned from the key document,
// or the zero value before the first session.
func (client *Client) PinnedControlKey() ControlKey {
	if client == nil {
		return ControlKey{}
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.control
}

// UpdateEndpoint replaces the endpoint that later reports carry. Core
// distributes only global unicast endpoints (mtcp-v1 §8.1).
func (client *Client) UpdateEndpoint(endpoint netip.AddrPort) error {
	if client == nil || !endpoint.IsValid() || endpoint.Port() == 0 ||
		endpoint.Addr().Zone() != "" || endpoint.Addr() != endpoint.Addr().Unmap() ||
		!endpoint.Addr().IsGlobalUnicast() {
		return ErrInvalidClient
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	client.connectivity.Endpoints = []netip.AddrPort{endpoint}
	return nil
}

// nextTimestamp returns a ClientHello timestamp strictly greater than the
// previous one, as Core requires per machine key (mtcp-v1 §3).
func (client *Client) nextTimestamp() int64 {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.lastTimestamp = max(time.Now().UnixMilli(), client.lastTimestamp+1)
	return client.lastTimestamp
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

func validCredential(credential string) bool {
	return len(credential) > 0 && len(credential) <= maxCredentialLength &&
		!strings.ContainsAny(credential, "\x00\r\n")
}
