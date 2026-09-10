// Package derp isolates the pinned relay wire protocol from product code.
package derp

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/meshtransit/meshd/internal/relay"
	"go4.org/mem"
	protocol "tailscale.com/derp"
	"tailscale.com/derp/derpconst"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const (
	relayPath           = "/derp"
	writeTimeout        = 5 * time.Second
	nodeDialTimeout     = 1500 * time.Millisecond
	familyFallbackDelay = 200 * time.Millisecond
	maxErrorBody        = 4096
	certificatePinLabel = "sha256-raw:"
)

type dialContextFunc func(context.Context, string, string) (net.Conn, error)

type dialCandidate struct {
	network string
	address string
}

type dialResult struct {
	conn net.Conn
	err  error
}

// Dialer opens TLS-only relay sessions without environment proxies or redirects.
type Dialer struct {
	dialContext dialContextFunc
	rootCAs     *x509.CertPool
}

// Client adapts the pinned protocol client to the product relay contract.
type Client struct {
	protocol *protocol.Client
	conn     net.Conn
	writeMu  sync.Mutex
	close    sync.Once
}

var (
	_ relay.Dialer = (*Dialer)(nil)
	_ relay.Client = (*Client)(nil)
)

// NewDialer creates a strict system-root TLS relay dialer.
func NewDialer() *Dialer {
	networkDialer := &net.Dialer{
		KeepAlive: 30 * time.Second,
	}

	return &Dialer{dialContext: networkDialer.DialContext}
}

// Dial tries the control-authorized relay nodes in their signed order.
func (d *Dialer) Dial(
	ctx context.Context,
	privateKey relay.Key,
	region relay.Region,
) (relay.Client, error) {
	if d == nil || d.dialContext == nil {
		return nil, errors.New("relay protocol: dialer is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if privateKey == (relay.Key{}) || region.ID <= 0 || len(region.Nodes) == 0 {
		return nil, errors.New("relay protocol: connection authority is invalid")
	}

	var firstErr error
	for _, node := range region.Nodes {
		client, err := d.dialNode(ctx, privateKey, node)
		if err == nil {
			return client, nil
		}
		if firstErr == nil {
			firstErr = err
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if firstErr == nil {
		firstErr = errors.New("no relay node is available")
	}

	return nil, fmt.Errorf("relay protocol: connecting to region %d: %w", region.ID, firstErr)
}

func (d *Dialer) dialNode(
	ctx context.Context,
	privateKey relay.Key,
	node relay.Node,
) (*Client, error) {
	if node.HostName == "" || node.Port == 0 {
		return nil, errors.New("relay protocol: node endpoint is invalid")
	}
	authority := net.JoinHostPort(node.HostName, fmt.Sprint(node.Port))
	tcpConn, err := d.dialNodeTCP(ctx, node)
	if err != nil {
		return nil, fmt.Errorf("dialing relay node: %w", err)
	}
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = tcpConn.Close()
	})
	defer func() {
		if !stopCancellation() {
			_ = tcpConn.Close()
		}
	}()

	tlsConfig, err := d.tlsConfig(node)
	if err != nil {
		_ = tcpConn.Close()

		return nil, err
	}
	tlsConn := tls.Client(tcpConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()

		return nil, fmt.Errorf("verifying relay tls: %w", err)
	}
	buffer := bufio.NewReadWriter(bufio.NewReader(tlsConn), bufio.NewWriter(tlsConn))
	requestURL := &url.URL{
		Scheme: "https",
		Host:   authority,
		Path:   relayPath,
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		_ = tlsConn.Close()

		return nil, fmt.Errorf("creating relay upgrade request: %w", err)
	}
	request.Header.Set("Upgrade", "DERP")
	request.Header.Set("Connection", "Upgrade")
	if err := request.Write(buffer); err != nil {
		_ = tlsConn.Close()

		return nil, fmt.Errorf("writing relay upgrade request: %w", err)
	}
	if err := buffer.Flush(); err != nil {
		_ = tlsConn.Close()

		return nil, fmt.Errorf("flushing relay upgrade request: %w", err)
	}
	response, err := http.ReadResponse(buffer.Reader, request)
	if err != nil {
		_ = tlsConn.Close()

		return nil, fmt.Errorf("reading relay upgrade response: %w", err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols ||
		!strings.EqualFold(response.Header.Get("Upgrade"), "DERP") ||
		!headerContainsToken(response.Header.Get("Connection"), "upgrade") {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxErrorBody))
		_ = response.Body.Close()
		_ = tlsConn.Close()

		return nil, fmt.Errorf("relay protocol: upgrade rejected with status %d", response.StatusCode)
	}

	var encodedPrivate [64]byte
	hex.Encode(encodedPrivate[:], privateKey[:])
	protocolKey, err := key.ParseNodePrivateUntyped(mem.B(encodedPrivate[:]))
	clear(encodedPrivate[:])
	if err != nil {
		_ = tlsConn.Close()

		return nil, errors.New("relay protocol: private identity encoding is invalid")
	}
	protocolClient, err := protocol.NewClient(
		protocolKey,
		tlsConn,
		buffer,
		logger.Discard,
		protocol.CanAckPings(true),
		protocol.AppName("meshd"),
	)
	if err != nil {
		_ = tlsConn.Close()

		return nil, fmt.Errorf("authenticating relay session: %w", err)
	}
	message, err := protocolClient.Recv()
	if err != nil {
		_ = tlsConn.Close()

		return nil, fmt.Errorf("confirming relay session: %w", err)
	}
	if _, ok := message.(protocol.ServerInfoMessage); !ok {
		_ = tlsConn.Close()

		return nil, errors.New("relay protocol: server confirmation is missing")
	}
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		_ = tlsConn.Close()

		return nil, fmt.Errorf("clearing relay session deadline: %w", err)
	}

	return &Client{protocol: protocolClient, conn: tlsConn}, nil
}

func (d *Dialer) dialNodeTCP(ctx context.Context, node relay.Node) (net.Conn, error) {
	candidates, err := relayDialCandidates(node)
	if err != nil {
		return nil, err
	}
	dialCtx, cancel := context.WithTimeout(ctx, nodeDialTimeout)
	defer cancel()
	if len(candidates) == 1 {
		return d.raceDialCandidates(dialCtx, candidates, nil)
	}

	timer := time.NewTimer(familyFallbackDelay)
	defer timer.Stop()

	return d.raceDialCandidates(dialCtx, candidates, timer.C)
}

// raceDialCandidates starts the preferred family immediately. The fallback
// starts when the preferred attempt fails or fallbackReady fires, whichever is
// first. Every started attempt is joined before the function returns.
func (d *Dialer) raceDialCandidates(
	ctx context.Context,
	candidates []dialCandidate,
	fallbackReady <-chan time.Time,
) (net.Conn, error) {
	if len(candidates) == 0 || len(candidates) > 2 {
		return nil, errors.New("relay protocol: dial candidate set is invalid")
	}
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan dialResult, len(candidates))
	start := func(candidate dialCandidate) {
		go func() {
			conn, err := d.dialContext(dialCtx, candidate.network, candidate.address)
			if conn == nil && err == nil {
				err = errors.New("relay protocol: dial returned an empty connection")
			}
			results <- dialResult{conn: conn, err: err}
		}()
	}

	start(candidates[0])
	next := 1
	pending := 1
	var failures []error
	closePending := func(count int) {
		for range count {
			result := <-results
			if result.conn != nil {
				_ = result.conn.Close()
			}
		}
	}
	for {
		select {
		case result := <-results:
			pending--
			if result.err == nil {
				if err := ctx.Err(); err != nil {
					_ = result.conn.Close()
					cancel()
					closePending(pending)

					return nil, err
				}
				cancel()
				closePending(pending)

				return result.conn, nil
			}
			if result.conn != nil {
				_ = result.conn.Close()
			}
			failures = append(failures, result.err)
			if next < len(candidates) {
				start(candidates[next])
				next++
				pending++
				fallbackReady = nil
			}
			if pending == 0 {
				return nil, errors.Join(failures...)
			}
		case <-fallbackReady:
			fallbackReady = nil
			if next < len(candidates) {
				start(candidates[next])
				next++
				pending++
			}
		case <-ctx.Done():
			cancel()
			closePending(pending)

			return nil, ctx.Err()
		}
	}
}

func relayDialCandidates(node relay.Node) ([]dialCandidate, error) {
	candidates := make([]dialCandidate, 0, 2)
	for _, family := range []struct {
		network string
		rawIP   string
		is4     bool
	}{
		{network: "tcp6", rawIP: node.IPv6},
		{network: "tcp4", rawIP: node.IPv4, is4: true},
	} {
		candidate, enabled, err := relayDialCandidate(node, family.network, family.rawIP, family.is4)
		if err != nil {
			return nil, err
		}
		if enabled {
			candidates = append(candidates, candidate)
		}
	}
	if len(candidates) == 0 {
		return nil, errors.New("relay protocol: both address families are disabled")
	}

	return candidates, nil
}

func relayDialCandidate(
	node relay.Node,
	network string,
	rawIP string,
	wantIPv4 bool,
) (dialCandidate, bool, error) {
	if rawIP == "none" {
		return dialCandidate{}, false, nil
	}
	host := node.HostName
	if rawIP != "" {
		address, err := netip.ParseAddr(rawIP)
		wrongFamily := (wantIPv4 && !address.Is4()) || (!wantIPv4 && !address.Is6())
		if err != nil || wrongFamily || address.Is4In6() || address.Zone() != "" ||
			address != address.Unmap() || !address.IsGlobalUnicast() ||
			address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() ||
			address.IsLinkLocalUnicast() {
			return dialCandidate{}, false, errors.New(
				"relay protocol: explicit node address is invalid",
			)
		}
		host = address.String()
	} else if address, err := netip.ParseAddr(host); err == nil {
		if (wantIPv4 && !address.Is4()) || (!wantIPv4 && !address.Is6()) {
			return dialCandidate{}, false, nil
		}
		host = address.String()
	}

	return dialCandidate{
		network: network,
		address: net.JoinHostPort(host, fmt.Sprint(node.Port)),
	}, true, nil
}

// Send writes one encrypted WireGuard packet to a relay-addressed peer.
func (c *Client) Send(destination relay.Key, packet []byte) error {
	if c == nil || c.protocol == nil || c.conn == nil {
		return errors.New("relay protocol: client is closed")
	}
	if destination == (relay.Key{}) || len(packet) == 0 {
		return errors.New("relay protocol: outbound packet is invalid")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return fmt.Errorf("setting relay write deadline: %w", err)
	}
	defer func() { _ = c.conn.SetWriteDeadline(time.Time{}) }()
	publicKey := key.NodePublicFromRaw32(mem.B(destination[:]))
	if err := c.protocol.Send(publicKey, packet); err != nil {
		return fmt.Errorf("sending relay frame: %w", err)
	}

	return nil
}

// Receive returns encrypted peer packets and authenticated relay activity.
func (c *Client) Receive() (relay.ReceiveEvent, error) {
	if c == nil || c.protocol == nil || c.conn == nil {
		return relay.ReceiveEvent{}, errors.New("relay protocol: client is closed")
	}
	for {
		message, err := c.protocol.Recv()
		if err != nil {
			return relay.ReceiveEvent{}, fmt.Errorf("receiving relay frame: %w", err)
		}
		switch message := message.(type) {
		case protocol.ReceivedPacket:
			rawSource := message.Source.AppendTo(nil)
			if len(rawSource) != len(relay.Key{}) {
				return relay.ReceiveEvent{}, errors.New(
					"relay protocol: source identity size is invalid",
				)
			}
			var source relay.Key
			copy(source[:], rawSource)

			return relay.ReceiveEvent{
				Kind:   relay.ReceivePacket,
				Source: source,
				Data:   append([]byte{}, message.Data...),
			}, nil
		case protocol.PingMessage:
			if err := c.sendPong([8]byte(message)); err != nil {
				return relay.ReceiveEvent{}, err
			}

			return relay.ReceiveEvent{Kind: relay.ReceiveActivity}, nil
		case protocol.ServerRestartingMessage:
			return relay.ReceiveEvent{}, errors.New("relay protocol: server is restarting")
		case protocol.HealthMessage:
			if message.Problem != "" {
				return relay.ReceiveEvent{}, errors.New("relay protocol: server reports unhealthy")
			}

			return relay.ReceiveEvent{Kind: relay.ReceiveActivity}, nil
		case protocol.ServerInfoMessage, protocol.PongMessage,
			protocol.KeepAliveMessage,
			protocol.PeerGoneMessage, protocol.PeerPresentMessage:
			return relay.ReceiveEvent{Kind: relay.ReceiveActivity}, nil
		default:
			continue
		}
	}
}

// Close terminates the connection and unblocks Receive.
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	var closeErr error
	c.close.Do(func() {
		closeErr = c.conn.Close()
	})

	return closeErr
}

func (c *Client) sendPong(value [8]byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return fmt.Errorf("setting relay pong deadline: %w", err)
	}
	defer func() { _ = c.conn.SetWriteDeadline(time.Time{}) }()
	if err := c.protocol.SendPong(value); err != nil {
		return fmt.Errorf("sending relay pong: %w", err)
	}

	return nil
}

func (d *Dialer) tlsConfig(node relay.Node) (*tls.Config, error) {
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: node.HostName,
		RootCAs:    d.rootCAs,
	}
	if node.CertName == "" || node.CertName == node.HostName {
		return config, nil
	}
	if hashText, ok := strings.CutPrefix(node.CertName, certificatePinLabel); ok {
		digest, err := hex.DecodeString(hashText)
		if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != hashText {
			return nil, errors.New("relay protocol: certificate pin is invalid")
		}
		// #nosec G402 -- normal verification is replaced by an exact control-signed
		// certificate pin plus hostname and validity checks below.
		config.InsecureSkipVerify = true
		config.VerifyConnection = pinnedCertificateVerifier(node.HostName, [32]byte(digest))

		return config, nil
	}
	// #nosec G402 -- domain-fronting keeps the signed SNI while the hook performs
	// the complete x509 chain verification against the signed certificate name.
	config.InsecureSkipVerify = true
	config.VerifyConnection = namedCertificateVerifier(node.CertName, d.rootCAs)

	return config, nil
}

func pinnedCertificateVerifier(
	hostName string,
	expected [sha256.Size]byte,
) func(tls.ConnectionState) error {
	return func(state tls.ConnectionState) error {
		certificates := nonMetaCertificates(state.PeerCertificates)
		if len(certificates) != 1 {
			return errors.New("relay protocol: pinned certificate set is invalid")
		}
		certificate := certificates[0]
		actual := sha256.Sum256(certificate.Raw)
		if subtle.ConstantTimeCompare(actual[:], expected[:]) != 1 {
			return errors.New("relay protocol: certificate pin mismatch")
		}
		if err := certificate.VerifyHostname(hostName); err != nil {
			return fmt.Errorf("relay protocol: certificate hostname mismatch: %w", err)
		}
		now := time.Now()
		if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
			return errors.New("relay protocol: pinned certificate is outside its validity period")
		}

		return nil
	}
}

func namedCertificateVerifier(
	certificateName string,
	roots *x509.CertPool,
) func(tls.ConnectionState) error {
	return func(state tls.ConnectionState) error {
		certificates := nonMetaCertificates(state.PeerCertificates)
		if len(certificates) == 0 {
			return errors.New("relay protocol: certificate is missing")
		}
		intermediates := x509.NewCertPool()
		for _, certificate := range certificates[1:] {
			intermediates.AddCert(certificate)
		}
		_, err := certificates[0].Verify(x509.VerifyOptions{
			DNSName:       certificateName,
			Roots:         roots,
			Intermediates: intermediates,
		})
		if err != nil {
			return fmt.Errorf("relay protocol: certificate verification failed: %w", err)
		}

		return nil
	}
}

func nonMetaCertificates(certificates []*x509.Certificate) []*x509.Certificate {
	result := make([]*x509.Certificate, 0, len(certificates))
	for _, certificate := range certificates {
		if certificate == nil || strings.HasPrefix(
			certificate.Subject.CommonName,
			derpconst.MetaCertCommonNamePrefix,
		) {
			continue
		}
		result = append(result, certificate)
	}

	return result
}

func headerContainsToken(value, token string) bool {
	for item := range strings.SplitSeq(value, ",") {
		if strings.EqualFold(strings.TrimSpace(item), token) {
			return true
		}
	}

	return false
}
