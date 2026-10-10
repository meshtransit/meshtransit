// Package mtcpclient is meshd's MTCP v1 control client (docs/protocol/
// mtcp-v1.md). It serves the daemon's protocol-neutral contract
// (controlplane) over sessions authenticated by the profile's machine key
// and pinned control key.
package mtcpclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

const (
	// Protocol names MTCP v1 in probe results.
	Protocol         = "mtcp"
	requestTimeout   = 15 * time.Second
	maxKeyDocument   = 4 << 10
	userAgent        = "meshd"
	controlHTTPSPort = "443"
)

var (
	// ErrUnavailable reports that the control origin does not serve MTCP.
	ErrUnavailable = errors.New("mtcp: control origin does not serve MTCP")
	errNotReady    = errors.New("mtcp: client is not initialized")
)

// Client opens MTCP sessions to control origins. It is safe for concurrent
// use; it holds no per-profile state.
type Client struct {
	httpClient *http.Client
	dialTLS    func(ctx context.Context, address string, config *tls.Config) (net.Conn, error)
	tlsConfig  *tls.Config
	port       string // the only origin port accepted; 443 outside tests
	now        func() time.Time
}

// New returns a client that uses system trust roots, TLS 1.2 or newer,
// HTTPS on port 443 only, no proxy and no redirects.
func New() *Client {
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		panic("mtcp: net/http default transport has an unexpected type")
	}
	transport := defaultTransport.Clone()
	transport.DisableCompression = true
	transport.Proxy = nil
	transport.MaxResponseHeaderBytes = maxKeyDocument
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	transport.TLSClientConfig = tlsConfig.Clone()
	return &Client{
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   requestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		dialTLS:   dialTLS,
		tlsConfig: tlsConfig,
		port:      controlHTTPSPort,
		now:       time.Now,
	}
}

func dialTLS(ctx context.Context, address string, config *tls.Config) (net.Conn, error) {
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: requestTimeout}, Config: config}
	return dialer.DialContext(ctx, "tcp", address)
}

// origin validates a control URL: absolute https, no credentials, query,
// fragment or path parameters, and the client's port.
func (c *Client) origin(controlURL string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(controlURL))
	if err != nil {
		return nil, fmt.Errorf("mtcp: parsing control url: %w", err)
	}
	if parsed.Opaque != "" || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" ||
		(parsed.Path != "" && parsed.Path != "/") {
		return nil, errors.New("mtcp: control url must be an https origin")
	}
	if port := parsed.Port(); port != "" && port != c.port {
		return nil, fmt.Errorf("mtcp: control url must use port %s", c.port)
	}
	return &url.URL{Scheme: "https", Host: net.JoinHostPort(parsed.Hostname(), c.port)}, nil
}

// controlKey is one key of the key document (mtcp-v1 §2.1).
type controlKey struct {
	Key      key.ControlPublic
	NotAfter time.Time
}

// fetchKeys reads the control key document.
func (c *Client) fetchKeys(ctx context.Context, origin *url.URL) ([]controlKey, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin.String()+sharedmtcp.KeyPath, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", userAgent)
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", controlplane.ErrRegistrationTemporary, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusNotFound {
		return nil, ErrUnavailable
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: key document answered http %d", controlplane.ErrRegistrationTemporary,
			response.StatusCode)
	}
	if mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type")); err != nil ||
		mediaType != "application/json" {
		return nil, ErrUnavailable
	}
	var document struct {
		Version int `json:"version"`
		Keys    []struct {
			Key      key.ControlPublic `json:"key"`
			NotAfter time.Time         `json:"not_after"`
		} `json:"keys"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxKeyDocument))
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("mtcp: key document: %w", err)
	}
	if document.Version != 1 || len(document.Keys) == 0 || len(document.Keys) > 2 {
		return nil, errors.New("mtcp: key document is not version 1 with one or two keys")
	}
	now := c.now()
	keys := make([]controlKey, 0, len(document.Keys))
	for _, entry := range document.Keys {
		if entry.Key.IsZero() || !entry.NotAfter.After(now) {
			continue // an expired key is never used
		}
		keys = append(keys, controlKey{Key: entry.Key, NotAfter: entry.NotAfter})
	}
	if len(keys) == 0 {
		return nil, errors.New("mtcp: every control key has expired")
	}
	return keys, nil
}

// pinnedKey returns the key of the document that matches pin: a control
// key fingerprint ("sha256:…", as profiles store it) or an enrollment link
// fingerprint (ck=, mtcp-v1 §2.1).
func pinnedKey(keys []controlKey, pin string) (key.ControlPublic, string, error) {
	for _, candidate := range keys {
		fingerprint := controlplane.ControlKeyFingerprint(candidate.Key)
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(pin)), "sha256:") {
			if canonical, err := controlplane.VerifyFingerprint(pin, fingerprint); err == nil {
				return candidate.Key, canonical, nil
			} else if errors.Is(err, controlplane.ErrInvalidFingerprint) {
				return key.ControlPublic{}, "", err
			}
			continue
		}
		if sharedmtcp.FingerprintMatches(candidate.Key, strings.ToLower(strings.TrimSpace(pin))) {
			return candidate.Key, fingerprint, nil
		}
	}
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(pin)), "sha256:") && len(strings.TrimSpace(pin)) != 32 {
		return key.ControlPublic{}, "", controlplane.ErrInvalidFingerprint
	}
	return key.ControlPublic{}, "", controlplane.ErrFingerprintMismatch
}

// Probe proves that the origin serves MTCP with a key it can use: a session
// with a throwaway machine key answers a Ping.
func (c *Client) Probe(ctx context.Context, controlURL string) (controlplane.Result, error) {
	if c == nil || c.httpClient == nil {
		return controlplane.Result{}, errNotReady
	}
	origin, err := c.origin(controlURL)
	if err != nil {
		return controlplane.Result{}, err
	}
	keys, err := c.fetchKeys(ctx, origin)
	if err != nil {
		return controlplane.Result{}, err
	}
	machine, err := key.NewMachinePrivate(nil)
	if err != nil {
		return controlplane.Result{}, err
	}
	if err := c.ping(ctx, origin, machine, keys[0].Key); err != nil {
		return controlplane.Result{}, err
	}
	return controlplane.Result{
		Protocol: Protocol, Capability: sharedmtcp.Version,
		KeyFingerprint:   controlplane.ControlKeyFingerprint(keys[0].Key),
		NoiseEstablished: true, NoiseVersion: sharedmtcp.Version,
	}, nil
}

// BootstrapTrust finds the control key that matches the operator's pin,
// proves the origin holds it, and creates fresh machine and node keys.
func (c *Client) BootstrapTrust(ctx context.Context, controlURL, expectedFingerprint string) (
	controlplane.TrustResult, error,
) {
	if c == nil || c.httpClient == nil {
		return controlplane.TrustResult{}, errNotReady
	}
	origin, err := c.origin(controlURL)
	if err != nil {
		return controlplane.TrustResult{}, err
	}
	keys, err := c.fetchKeys(ctx, origin)
	if err != nil {
		return controlplane.TrustResult{}, err
	}
	control, fingerprint, err := pinnedKey(keys, expectedFingerprint)
	if err != nil {
		return controlplane.TrustResult{}, err
	}
	machineText, err := controlplane.GenerateNodePrivateKey() // the same clamped X25519 form
	if err != nil {
		return controlplane.TrustResult{}, err
	}
	nodeText, err := controlplane.GenerateNodePrivateKey()
	if err != nil {
		return controlplane.TrustResult{}, err
	}
	material := controlplane.KeyMaterial{
		MachinePrivateKey: machineText, NodePrivateKey: nodeText,
		ControlPublicKey: controlplane.EncodeControlPublicKey(control),
	}
	opened, err := c.openKeys(material)
	if err != nil {
		return controlplane.TrustResult{}, err
	}
	if err := c.ping(ctx, origin, opened.machine, control); err != nil {
		return controlplane.TrustResult{}, err
	}
	return controlplane.TrustResult{Fingerprint: fingerprint, Material: material}, nil
}

// VerifyTrust checks that the origin still offers the profile's control key
// and that it matches the pin, then proves possession with a session.
func (c *Client) VerifyTrust(ctx context.Context, controlURL string, material controlplane.KeyMaterial,
	pinnedFingerprint string,
) error {
	keys, err := c.openKeys(material)
	if err != nil {
		return err
	}
	origin, err := c.origin(controlURL)
	if err != nil {
		return err
	}
	if err := c.checkPinned(ctx, origin, keys.control, pinnedFingerprint); err != nil {
		return err
	}
	return c.ping(ctx, origin, keys.machine, keys.control)
}

// checkPinned verifies that the document still lists the profile's control
// key and that the key matches the stored pin.
func (c *Client) checkPinned(ctx context.Context, origin *url.URL, control key.ControlPublic, pin string) error {
	if pin != "" {
		if _, err := controlplane.VerifyFingerprint(pin, controlplane.ControlKeyFingerprint(control)); err != nil {
			return controlplane.ErrControlKeyChanged
		}
	}
	keys, err := c.fetchKeys(ctx, origin)
	if err != nil {
		return err
	}
	for _, candidate := range keys {
		if candidate.Key == control {
			return nil
		}
	}
	return controlplane.ErrControlKeyChanged
}

// profileKeys are a profile's keys decoded for one operation.
type profileKeys struct {
	machine key.MachinePrivate
	node    key.NodePrivate
	control key.ControlPublic
}

func (c *Client) openKeys(material controlplane.KeyMaterial) (profileKeys, error) {
	if c == nil || c.httpClient == nil {
		return profileKeys{}, errNotReady
	}
	machineRaw, err := controlplane.ParsePrivateKey(material.MachinePrivateKey)
	if err != nil {
		return profileKeys{}, err
	}
	defer clear(machineRaw[:])
	nodeRaw, err := controlplane.ParsePrivateKey(material.NodePrivateKey)
	if err != nil {
		return profileKeys{}, err
	}
	defer clear(nodeRaw[:])
	controlRaw, err := controlplane.ParseControlPublicKey(material.ControlPublicKey)
	if err != nil {
		return profileKeys{}, err
	}
	machine, err := key.MachinePrivateFromBytes(machineRaw[:])
	if err != nil {
		return profileKeys{}, controlplane.ErrInvalidMaterial
	}
	nodeKey, err := key.NodePrivateFromBytes(nodeRaw[:])
	if err != nil {
		return profileKeys{}, controlplane.ErrInvalidMaterial
	}
	return profileKeys{machine: machine, node: nodeKey, control: key.ControlPublic(controlRaw)}, nil
}
