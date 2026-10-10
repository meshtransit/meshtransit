// Command meshrelay-load measures a relay under load over UDP: it opens
// pairs of sessions with test tickets, has one side of each pair send DATA
// to the other at a fixed rate, and reports delivery, added latency and
// throughput. It also reports the handshake amplification factor (bytes the
// relay sends for each byte of a client INIT before the client is bound).
//
// The relay must trust the test signing key the tickets are signed with:
//
//	meshrelay genkey --out relay.key
//	meshrelay serve --key-file relay.key --trusted-signing-keys mtsign:<test key> \
//	  --udp 127.0.0.1:3479 --stun ''
//	meshrelay-load -relay 127.0.0.1:3479 -relay-key mtrelay:… \
//	  -signing-seed-file test-signing.seed -pairs 200 -rate 200 -duration 30s
//
// Latency is measured with the sender's and receiver's shared clock, so run
// the tool on one host. A relay admits 10 handshakes per second per source
// address; -sources spreads clients over several local addresses.
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

// sourceHandshakeRate stays under the relay's per-source handshake limit.
const sourceHandshakeRate = 9

// keepaliveInterval keeps sessions well inside the relay's idle timeout.
const keepaliveInterval = 10 * time.Second

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "meshrelay-load:", err)
		os.Exit(1)
	}
}

type config struct {
	relay    netip.AddrPort
	relayKey key.RelayPublic
	signer   key.SigningPrivate
	sources  []netip.Addr
	pairs    int
	rate     int
	size     int
	duration time.Duration
}

func parse(args []string) (config, error) {
	fs := flag.NewFlagSet("meshrelay-load", flag.ContinueOnError)
	relay := fs.String("relay", "127.0.0.1:3479", "relay UDP address")
	relayKey := fs.String("relay-key", "", "relay public key (mtrelay:…)")
	seedFile := fs.String("signing-seed-file", "", "file with the 32-byte seed of the test signing key the relay trusts")
	sources := fs.String("sources", "", "comma-separated local addresses to send from (default: any)")
	pairs := fs.Int("pairs", 50, "session pairs (each pair is two clients)")
	rate := fs.Int("rate", 100, "DATA packets per second sent by each pair")
	size := fs.Int("size", 1200, "DATA payload bytes (16–1400)")
	duration := fs.Duration("duration", 20*time.Second, "how long to send")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	cfg := config{pairs: *pairs, rate: *rate, size: *size, duration: *duration}
	var err error
	if cfg.relay, err = netip.ParseAddrPort(*relay); err != nil {
		return config{}, fmt.Errorf("-relay: %w", err)
	}
	if cfg.relayKey, err = key.ParseRelayPublic(*relayKey); err != nil {
		return config{}, fmt.Errorf("-relay-key: %w", err)
	}
	seed, err := os.ReadFile(*seedFile)
	if err != nil {
		return config{}, fmt.Errorf("-signing-seed-file: %w", err)
	}
	cfg.signer, err = key.SigningPrivateFromSeed(seed)
	clear(seed)
	if err != nil {
		return config{}, fmt.Errorf("-signing-seed-file: %w", err)
	}
	for _, text := range strings.Split(*sources, ",") {
		if text = strings.TrimSpace(text); text == "" {
			continue
		}
		address, err := netip.ParseAddr(text)
		if err != nil {
			return config{}, fmt.Errorf("-sources: %w", err)
		}
		cfg.sources = append(cfg.sources, address)
	}
	if len(cfg.sources) == 0 {
		cfg.sources = []netip.Addr{{}}
	}
	if cfg.pairs < 1 || cfg.pairs > 50_000 || cfg.rate < 1 || cfg.rate > 100_000 || cfg.size < 16 || cfg.size > 1400 ||
		cfg.duration <= 0 {
		return config{}, errors.New("-pairs, -rate, -size or -duration out of range")
	}
	return cfg, nil
}

// client is one relay session over its own UDP socket.
type client struct {
	conn    *net.UDPConn
	relay   netip.AddrPort
	session *mtrp.Session
	node    key.NodePublic
}

func (c *client) send(b []byte) error {
	_, err := c.conn.WriteToUDPAddrPort(b, c.relay)
	return err
}

func (c *client) recv(deadline time.Time) ([]byte, error) {
	_ = c.conn.SetReadDeadline(deadline)
	buf := make([]byte, 2048)
	n, _, err := c.conn.ReadFromUDPAddrPort(buf)
	return buf[:n], err
}

func (c *client) control(m mtrp.ControlMessage) error {
	payload, err := mtrp.AppendControlMessage(nil, m)
	if err != nil {
		return err
	}
	frame, err := c.session.SealControl(nil, payload)
	if err != nil {
		return err
	}
	return c.send(frame)
}

func (c *client) expect(want mtrp.ControlType) (mtrp.ControlMessage, error) {
	deadline := time.Now().Add(5 * time.Second)
	for {
		frame, err := c.recv(deadline)
		if err != nil {
			return mtrp.ControlMessage{}, err
		}
		payload, err := c.session.OpenControl(nil, frame)
		if err != nil {
			continue // a DATA frame or a stray datagram
		}
		m, err := mtrp.ParseControlMessage(payload)
		if err == nil && m.Type == want {
			return m, nil
		}
	}
}

// handshakeBytes records the sizes of one handshake for the amplification
// factor.
type handshakeBytes struct{ sent, received int }

func connect(cfg config, source netip.Addr, id uint32) (*client, handshakeBytes, error) {
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(source, 0)))
	if err != nil {
		return nil, handshakeBytes{}, err
	}
	disco, err := key.NewDiscoPrivate()
	if err != nil {
		_ = conn.Close()
		return nil, handshakeBytes{}, err
	}
	var node key.NodePublic
	binary.BigEndian.PutUint32(node[:4], id)
	node[4] = 0x7e
	now := time.Now()
	var ticketID [16]byte
	if _, err := io.ReadFull(rand.Reader, ticketID[:]); err != nil {
		_ = conn.Close()
		return nil, handshakeBytes{}, err
	}
	ticket, err := mtrp.Ticket{
		ID: ticketID, IssuedAtMS: now.UnixMilli(), NotAfterMS: now.Add(14 * time.Minute).UnixMilli(),
		Node: node, Disco: disco.Public(), Deployment: [16]byte{0x7e},
		Zones: []mtrp.Zone{{Kind: mtrp.ZoneNetwork, ID: [16]byte{0x7e}}},
	}.Sign(cfg.signer)
	if err != nil {
		_ = conn.Close()
		return nil, handshakeBytes{}, err
	}
	handshake, init, err := mtrp.StartClientHandshake(mtrp.ClientConfig{
		Disco: disco, Relay: cfg.relayKey, Index: id, PadUDP: true,
		Hello: mtrp.ClientHello{TimestampMS: now.UnixMilli(), Ticket: ticket},
	})
	if err != nil {
		_ = conn.Close()
		return nil, handshakeBytes{}, err
	}
	c := &client{conn: conn, relay: cfg.relay, node: node}
	if err := c.send(init); err != nil {
		_ = conn.Close()
		return nil, handshakeBytes{}, err
	}
	reply, err := c.recv(time.Now().Add(5 * time.Second))
	if err != nil {
		_ = conn.Close()
		return nil, handshakeBytes{}, fmt.Errorf("handshake reply: %w", err)
	}
	if c.session, _, err = handshake.Finish(reply); err != nil {
		_ = conn.Close()
		return nil, handshakeBytes{}, err
	}
	if err := c.control(mtrp.ControlMessage{Type: mtrp.ControlKeepalive}); err != nil {
		_ = conn.Close()
		return nil, handshakeBytes{}, err
	}
	if _, err := c.expect(mtrp.ControlKeepalive); err != nil {
		_ = conn.Close()
		return nil, handshakeBytes{}, fmt.Errorf("keepalive: %w", err)
	}
	return c, handshakeBytes{sent: len(init), received: len(reply)}, nil
}

// pair is a sender and a receiver joined by a route.
type pair struct {
	from, to *client
	route    uint32
}

func openPair(cfg config, source netip.Addr, n int) (pair, []handshakeBytes, error) {
	a, hsA, err := connect(cfg, source, uint32(2*n+1)) //nolint:gosec // G115: n is bounded by -pairs
	if err != nil {
		return pair{}, nil, err
	}
	b, hsB, err := connect(cfg, source, uint32(2*n+2)) //nolint:gosec // G115: n is bounded by -pairs
	if err != nil {
		_ = a.conn.Close()
		return pair{}, nil, err
	}
	if err := a.control(mtrp.ControlMessage{Type: mtrp.ControlRouteOpen, Request: 1, Peer: b.node}); err != nil {
		closePair(pair{from: a, to: b})
		return pair{}, nil, err
	}
	if _, err := b.expect(mtrp.ControlRouteIncoming); err != nil {
		closePair(pair{from: a, to: b})
		return pair{}, nil, fmt.Errorf("route incoming: %w", err)
	}
	ok, err := a.expect(mtrp.ControlRouteOK)
	if err != nil {
		closePair(pair{from: a, to: b})
		return pair{}, nil, fmt.Errorf("route ok: %w", err)
	}
	return pair{from: a, to: b, route: ok.Route}, []handshakeBytes{hsA, hsB}, nil
}

func keepAlive(pairs []pair) {
	for _, p := range pairs {
		_ = p.from.control(mtrp.ControlMessage{Type: mtrp.ControlKeepalive})
		_ = p.to.control(mtrp.ControlMessage{Type: mtrp.ControlKeepalive})
	}
}

func closePair(p pair) {
	_ = p.from.conn.Close()
	_ = p.to.conn.Close()
}

// stats aggregates one run.
type stats struct {
	sent, received, bytes atomic.Int64
	mu                    sync.Mutex
	latencies             []time.Duration
}

func (s *stats) record(latency time.Duration) {
	s.mu.Lock()
	if len(s.latencies) < 1_000_000 {
		s.latencies = append(s.latencies, latency)
	}
	s.mu.Unlock()
}

func send(ctx context.Context, p pair, cfg config, s *stats) {
	interval := time.Second / time.Duration(cfg.rate)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	keepalive := time.NewTicker(keepaliveInterval)
	defer keepalive.Stop()
	payload := make([]byte, cfg.size)
	var frame []byte
	for sequence := uint64(0); ; sequence++ {
		select {
		case <-ctx.Done():
			return
		case <-keepalive.C:
			_ = p.from.control(mtrp.ControlMessage{Type: mtrp.ControlKeepalive})
			_ = p.to.control(mtrp.ControlMessage{Type: mtrp.ControlKeepalive})
		case <-ticker.C:
			binary.BigEndian.PutUint64(payload[0:8], uint64(time.Now().UnixNano()))
			binary.BigEndian.PutUint64(payload[8:16], sequence)
			var err error
			frame, err = mtrp.AppendData(frame[:0], p.from.session.RemoteIndex(), p.route, payload)
			if err != nil || p.from.send(frame) != nil {
				continue
			}
			s.sent.Add(1)
		}
	}
}

func receive(p pair, s *stats, until time.Time) {
	for {
		frame, err := p.to.recv(until)
		if err != nil {
			return
		}
		data, err := mtrp.ParseData(frame)
		if err != nil || len(data.Payload) < 16 {
			continue
		}
		sentAt := int64(binary.BigEndian.Uint64(data.Payload[0:8])) //nolint:gosec // G115: written from UnixNano
		s.received.Add(1)
		s.bytes.Add(int64(len(frame)))
		s.record(time.Duration(time.Now().UnixNano() - sentAt))
	}
}

func run(args []string, out io.Writer) error {
	cfg, err := parse(args)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Open pairs, spreading handshakes over the sources within each
	// source's handshake budget.
	var (
		pairs      []pair
		handshakes []handshakeBytes
		failures   int
	)
	interval := time.Second / time.Duration(sourceHandshakeRate*len(cfg.sources)) * 2 // two handshakes per pair
	started, lastKeepalive := time.Now(), time.Now()
	for n := range cfg.pairs {
		if ctx.Err() != nil {
			break
		}
		// Opening many pairs takes minutes; keep the open ones from idling
		// out (the relay closes a silent session after 90 s).
		if time.Since(lastKeepalive) > keepaliveInterval {
			keepAlive(pairs)
			lastKeepalive = time.Now()
		}
		p, hs, err := openPair(cfg, cfg.sources[n%len(cfg.sources)], n)
		if err != nil {
			failures++
			if failures <= 3 {
				_, _ = fmt.Fprintln(out, "pair failed:", err)
			}
		} else {
			pairs, handshakes = append(pairs, p), append(handshakes, hs...)
		}
		time.Sleep(interval)
	}
	defer func() {
		for _, p := range pairs {
			closePair(p)
		}
	}()
	_, _ = fmt.Fprintf(out, "opened %d of %d pairs (%d sessions) in %v; %d failed\n", len(pairs), cfg.pairs, 2*len(pairs),
		time.Since(started).Round(time.Millisecond), failures)
	if len(pairs) == 0 {
		return errors.New("no pair could be opened")
	}
	reportAmplification(out, handshakes)

	var s stats
	sendCtx, cancel := context.WithTimeout(ctx, cfg.duration)
	defer cancel()
	until := time.Now().Add(cfg.duration + 2*time.Second)
	var wg sync.WaitGroup
	for _, p := range pairs {
		wg.Go(func() { receive(p, &s, until) })
		wg.Go(func() { send(sendCtx, p, cfg, &s) })
	}
	wg.Wait()
	report(out, cfg, &s)
	return nil
}

func reportAmplification(out io.Writer, handshakes []handshakeBytes) {
	var sent, received int
	for _, hs := range handshakes {
		sent, received = sent+hs.sent, received+hs.received
	}
	_, _ = fmt.Fprintf(out, "handshake amplification: %.2f (%d B INIT → %d B reply on average)\n",
		float64(received)/float64(sent), sent/len(handshakes), received/len(handshakes))
}

func report(out io.Writer, cfg config, s *stats) {
	sent, received := s.sent.Load(), s.received.Load()
	loss := 0.0
	if sent > 0 {
		loss = 100 * float64(sent-received) / float64(sent)
	}
	seconds := cfg.duration.Seconds()
	_, _ = fmt.Fprintf(out, "sent %d, delivered %d (%.3f%% lost); %.0f packets/s, %.1f Mbit/s delivered\n",
		sent, received, loss, float64(received)/seconds, float64(s.bytes.Load())*8/seconds/1e6)
	s.mu.Lock()
	latencies := slices.Clone(s.latencies)
	s.mu.Unlock()
	if len(latencies) == 0 {
		return
	}
	slices.Sort(latencies)
	at := func(q float64) time.Duration { return latencies[min(len(latencies)-1, int(q*float64(len(latencies))))] }
	_, _ = fmt.Fprintf(out, "one-way latency through the relay: p50 %v, p99 %v, p99.9 %v, max %v\n",
		at(0.50).Round(time.Microsecond), at(0.99).Round(time.Microsecond), at(0.999).Round(time.Microsecond),
		latencies[len(latencies)-1].Round(time.Microsecond))
}
