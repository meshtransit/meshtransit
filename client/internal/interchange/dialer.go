// Package interchange is the node side of MTRP v1: it reaches Interchange
// relays over UDP, TLS or WebSocket, proves the node's disco key and ticket,
// and carries WireGuard packets to peers through routes (docs/protocol/
// mtrp-v1.md). It implements the protocol-neutral relay.Dialer and
// relay.Client.
package interchange

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"meshtransit.net/client/internal/relay"
	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

// Dial schedule (MTRP §1, §4.1).
const (
	tlsHeadStart     = 300 * time.Millisecond
	udpRetryInterval = time.Second
	udpAttempts      = 5
	streamHandshake  = 10 * time.Second
)

var (
	// ErrNoCredentials reports that no ticket is available yet.
	ErrNoCredentials = errors.New("interchange: no relay ticket")
	errNoKey         = errors.New("interchange: relay node has no key")
)

// Credentials supplies the disco key and the ticket Core issued for it.
// RelayCredentials reports false while no usable ticket exists.
type Credentials interface {
	RelayCredentials() (disco key.DiscoPrivate, ticket []byte, ok bool)
}

// ZoneCredentials is implemented by credentials whose tickets may be MTT2:
// RelayTicketZones returns the zone list ticket commits to, and
// RelayFallbackTicket the MTT1 ticket to use with a relay that does not
// answer it, or nil.
type ZoneCredentials interface {
	RelayTicketZones(ticket []byte) []byte
	RelayFallbackTicket(ticket []byte) []byte
}

// Dialer reaches a relay region. It implements relay.Dialer.
type Dialer struct {
	credentials Credentials
	now         func() time.Time
	random      io.Reader
	resolve     func(ctx context.Context, host string) ([]netip.Addr, error)
	dialUDP     func(context.Context, endpoint) (transport, error)
	dialTLS     func(context.Context, endpoint) (transport, error)
	dialWS      func(context.Context, endpoint) (transport, error)

	lastTimestamp atomic.Int64 // ClientHello timestamps strictly increase (§4)

	cookiesMu sync.Mutex
	cookies   map[key.RelayPublic][mtrp.MACSize]byte
}

// NewDialer returns a dialer presenting creds.
func NewDialer(creds Credentials) *Dialer {
	return &Dialer{
		credentials: creds,
		now:         time.Now,
		random:      rand.Reader,
		resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		dialUDP: dialUDP,
		dialTLS: dialTLS,
		dialWS:  dialWebSocket,
		cookies: make(map[key.RelayPublic][mtrp.MACSize]byte),
	}
}

// Dial connects to the first reachable node of region. The node private key
// argument is unused: an Interchange session proves the disco key instead.
func (d *Dialer) Dial(ctx context.Context, _ relay.Key, region relay.Region) (relay.Client, error) {
	var failures []error
	for _, node := range region.Nodes {
		client, err := d.dialNode(ctx, node)
		if err == nil {
			return client, nil
		}
		if ctx.Err() != nil || errors.Is(err, ErrNoCredentials) {
			return nil, err
		}
		failures = append(failures, fmt.Errorf("node %s: %w", node.Name, err))
	}
	if len(failures) == 0 {
		return nil, errors.New("interchange: region has no nodes")
	}
	return nil, errors.Join(failures...)
}

type dialResult struct {
	kind   TransportKind
	client *Client
	err    error
}

// dialNode races the transports: UDP first, TLS after a head start, and
// WebSocket when TLS cannot connect. The first session wins.
func (d *Dialer) dialNode(ctx context.Context, node relay.Node) (*Client, error) {
	if node.RelayKey == ([32]byte{}) {
		return nil, errNoKey
	}
	if _, _, ok := d.credentials.RelayCredentials(); !ok {
		return nil, ErrNoCredentials
	}
	e, err := d.endpoint(ctx, node)
	if err != nil {
		return nil, err
	}
	relayKey := key.RelayPublic(node.RelayKey)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan dialResult, 3)
	attempt := func(kind TransportKind, dial func(context.Context, endpoint) (transport, error)) {
		t, err := dial(ctx, e)
		if err != nil {
			results <- dialResult{kind: kind, err: err}
			return
		}
		c, err := d.handshake(ctx, t, relayKey)
		if err != nil {
			_ = t.close()
		}
		results <- dialResult{kind: kind, client: c, err: err}
	}
	running := 0
	if e.udpPort != 0 {
		running++
		go attempt(TransportUDP, d.dialUDP)
	}
	var tlsStart <-chan time.Time
	if e.tlsPort != 0 {
		if running == 0 {
			running++
			go attempt(TransportTLS, d.dialTLS)
		} else {
			timer := time.NewTimer(tlsHeadStart)
			defer timer.Stop()
			tlsStart = timer.C
		}
	}
	var failures []error
	wsTried := false
	for running > 0 || tlsStart != nil {
		select {
		case <-tlsStart:
			tlsStart = nil
			running++
			go attempt(TransportTLS, d.dialTLS)
		case r := <-results:
			running--
			if r.err == nil {
				cancel()
				go drain(results, running) // close late winners
				return r.client, nil
			}
			failures = append(failures, r.err)
			// TLS failed: only HTTP(S) may get through, so try WebSocket
			// now, while UDP may still be retrying.
			if !wsTried && r.kind == TransportTLS {
				wsTried = true
				running++
				go attempt(TransportWebSocket, d.dialWS)
			}
		case <-ctx.Done():
			go drain(results, running)
			return nil, ctx.Err()
		}
	}
	return nil, errors.Join(failures...)
}

func drain(results <-chan dialResult, n int) {
	for range n {
		if r := <-results; r.client != nil {
			_ = r.client.Close()
		}
	}
}

// endpoint picks the node's address: IPv4, then IPv6, then DNS.
func (d *Dialer) endpoint(ctx context.Context, node relay.Node) (endpoint, error) {
	e := endpoint{host: node.HostName, udpPort: node.UDPPort, tlsPort: node.Port}
	for _, text := range []string{node.IPv4, node.IPv6} {
		if text == "" {
			continue
		}
		if addr, err := netip.ParseAddr(text); err == nil {
			e.addr = addr.Unmap()
			return e, nil
		}
	}
	if node.HostName == "" {
		return endpoint{}, errors.New("interchange: relay node has no address")
	}
	addrs, err := d.resolve(ctx, node.HostName)
	if err != nil || len(addrs) == 0 {
		return endpoint{}, fmt.Errorf("interchange: resolve %s: %w", node.HostName, err)
	}
	e.addr = addrs[0].Unmap()
	return e, nil
}

// handshake runs MTRP §4 on t. UDP retries with a fresh INIT (new
// ephemeral key and timestamp), and answers a COOKIE with a new INIT that
// carries mac2. Streams try once.
func (d *Dialer) handshake(ctx context.Context, t transport, relayKey key.RelayPublic) (*Client, error) {
	stream := t.kind() != TransportUDP
	attempts, wait := udpAttempts, udpRetryInterval
	if stream {
		attempts, wait = 1, streamHandshake
	}
	frames := startPump(t)
	handedOff := false
	defer func() {
		if !handedOff {
			frames.close() // the caller closes t, which ends the reader
		}
	}()
	// A relay that does not take MTT2 drops its INIT unanswered: with an
	// MTT1 fallback, every other attempt (and a stream's second one) uses
	// it. A relay that does take MTT2 receives it later as TICKET_UPDATE.
	source, zoned := d.credentials.(ZoneCredentials)
	if _, ticket, ok := d.credentials.RelayCredentials(); ok && zoned && stream && source.RelayFallbackTicket(ticket) != nil {
		attempts = 2
	}
	var lastErr error
	for attempt := range attempts {
		disco, ticket, ok := d.credentials.RelayCredentials()
		if !ok {
			return nil, ErrNoCredentials
		}
		if zoned && attempt%2 == 1 {
			if fallback := source.RelayFallbackTicket(ticket); fallback != nil {
				ticket = fallback
			}
		}
		var index [4]byte
		if _, err := io.ReadFull(d.random, index[:]); err != nil {
			return nil, err
		}
		cfg := mtrp.ClientConfig{
			Disco: disco, Relay: relayKey, PadUDP: !stream, Random: d.random,
			Index: binary.BigEndian.Uint32(index[:]) | 1,
			Hello: mtrp.ClientHello{TimestampMS: d.timestamp(), Ticket: ticket, Caps: mtrp.CapWebSocket},
		}
		if cookie, ok := d.cookie(relayKey); ok && !stream {
			cfg.Cookie = &cookie
		}
		hs, init, err := mtrp.StartClientHandshake(cfg)
		if err != nil {
			return nil, err
		}
		if err := t.send(init); err != nil {
			return nil, err
		}
		outcome, retry, err := d.await(ctx, hs, frames, wait, relayKey)
		if outcome != nil {
			handedOff = true
			return newClient(t, frames, outcome.session, outcome.hello, disco.Public(), ticket, d.credentials, d.now), nil
		}
		if !retry {
			return nil, err
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("interchange: no handshake response")
	}
	return nil, lastErr
}

type handshakeOutcome struct {
	session *mtrp.Session
	hello   mtrp.ServerHello
}

// await waits for the RESPONSE (or a COOKIE) to one INIT. retry reports
// whether a new INIT should be sent.
func (d *Dialer) await(ctx context.Context, hs *mtrp.ClientHandshake, frames *pump,
	wait time.Duration, relayKey key.RelayPublic,
) (*handshakeOutcome, bool, error) {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case <-timer.C:
			return nil, true, errors.New("interchange: handshake timed out")
		case frame, ok := <-frames.frames:
			if !ok {
				return nil, false, <-frames.err
			}
			typ, err := mtrp.PeekType(frame)
			if err != nil {
				continue
			}
			switch typ {
			case mtrp.TypeResponse:
				session, hello, err := hs.Finish(frame)
				if err != nil {
					continue // spoofed or stale RESPONSE
				}
				return &handshakeOutcome{session: session, hello: hello}, false, nil
			case mtrp.TypeCookie:
				cookie, err := hs.OpenCookie(frame)
				if err != nil {
					continue
				}
				d.cookiesMu.Lock()
				d.cookies[relayKey] = cookie
				d.cookiesMu.Unlock()
				return nil, true, errors.New("interchange: relay under load, retrying with cookie")
			default:
			}
		}
	}
}

func (d *Dialer) cookie(relayKey key.RelayPublic) ([mtrp.MACSize]byte, bool) {
	d.cookiesMu.Lock()
	defer d.cookiesMu.Unlock()
	c, ok := d.cookies[relayKey]
	return c, ok
}

// timestamp returns the current time in milliseconds, strictly greater than
// any timestamp this dialer used before.
func (d *Dialer) timestamp() int64 {
	for {
		last := d.lastTimestamp.Load()
		next := max(d.now().UnixMilli(), last+1)
		if d.lastTimestamp.CompareAndSwap(last, next) {
			return next
		}
	}
}

var _ relay.Dialer = (*Dialer)(nil)
