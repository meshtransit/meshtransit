package netcheck

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"sync"
	"time"

	"meshtransit.net/shared/disco"
	"meshtransit.net/shared/stun"
)

// Defaults from nat-classification §2.
const (
	DefaultProbeTimeout = time.Second
	DefaultRetransmit   = 200 * time.Millisecond
	DefaultBudget       = 3 * time.Second
	// MaxServers bounds the servers one run contacts.
	MaxServers = 4
	// maxPending bounds outstanding transactions, so stray responses can
	// never grow the table.
	maxPending = 2 * MaxServers * 2
)

// ErrNoResponse reports that no STUN server answered.
var ErrNoResponse = errors.New("netcheck: no STUN server answered")

// errBusy reports a full transaction table.
var errBusy = errors.New("netcheck: too many outstanding probes")

// PacketWriter sends datagrams from the socket being classified. It is
// satisfied by *net.UDPConn and by test networks.
type PacketWriter interface {
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error)
}

// Config tunes a Prober. Zero fields take the defaults.
type Config struct {
	ProbeTimeout time.Duration // wait for one probe, including its retransmission
	Retransmit   time.Duration // delay before the single retransmission
	Budget       time.Duration // bound on a whole Run
	Random       io.Reader     // transaction IDs; crypto/rand when nil; read under a lock
	Software     string        // optional STUN SOFTWARE attribute for servers that require one
	Now          func() time.Time
}

// Report is the result of one classification run.
type Report struct {
	NAT          disco.NATInfo
	Step         uint16         // median port step for sequential allocation
	Mapped       netip.AddrPort // public endpoint seen by the first server
	Observations []Observation  // in probe order
	At           time.Time
}

// Current returns the classification, or unknown when the report is older
// than MaxReportAge (§4).
func (r Report) Current(now time.Time) disco.NATInfo {
	if r.At.IsZero() || now.Sub(r.At) > MaxReportAge || now.Before(r.At) {
		return disco.NATInfo{}
	}
	return r.NAT
}

// Prober classifies the NAT in front of a socket it does not own: Run writes
// STUN requests through the PacketWriter, and the socket's read loop hands
// every inbound STUN packet to HandleResponse.
//
// A Prober is safe for concurrent use; Run calls are serialised.
type Prober struct {
	conn PacketWriter
	cfg  Config

	run     chan struct{} // one-slot semaphore: one Run at a time
	mu      sync.Mutex    // guards pending and reads from cfg.Random
	pending map[stun.TxID]*transaction
}

type transaction struct {
	expect netip.AddrPort // the only source a valid response may come from
	done   chan response  // buffered 1; written at most once under Prober.mu
}

type response struct {
	msg  stun.Message
	from netip.AddrPort
}

// NewProber returns a Prober writing through conn.
func NewProber(conn PacketWriter, cfg Config) *Prober {
	if cfg.ProbeTimeout <= 0 {
		cfg.ProbeTimeout = DefaultProbeTimeout
	}
	if cfg.Retransmit <= 0 || cfg.Retransmit >= cfg.ProbeTimeout {
		cfg.Retransmit = min(DefaultRetransmit, cfg.ProbeTimeout/2)
	}
	if cfg.Budget <= 0 {
		cfg.Budget = DefaultBudget
	}
	if cfg.Random == nil {
		cfg.Random = rand.Reader
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Prober{conn: conn, cfg: cfg, run: make(chan struct{}, 1), pending: make(map[stun.TxID]*transaction)}
}

// HandleResponse consumes an inbound packet. It reports whether the packet
// parsed as STUN, in which case the caller must not process it further. Responses
// that match no outstanding probe, or arrive from an unexpected source, are
// dropped.
func (p *Prober) HandleResponse(pkt []byte, from netip.AddrPort) bool {
	if !stun.Is(pkt) {
		return false
	}
	msg, err := stun.Parse(pkt)
	if err != nil {
		// stun.Is is a weak test (a WireGuard packet can pass it), so only
		// packets that parse as STUN are consumed.
		return false
	}
	if msg.Type != stun.TypeBindingSuccess {
		return true
	}
	from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
	p.mu.Lock()
	defer p.mu.Unlock()
	tx, ok := p.pending[msg.TxID]
	if !ok || from != tx.expect {
		// A server that ignores CHANGE-REQUEST answers from its primary
		// address; accepting that would misreport filtering as open.
		return true
	}
	delete(p.pending, msg.TxID)
	tx.done <- response{msg: msg, from: from}
	return true
}

// Run classifies the NAT using servers, in preference order (at most
// MaxServers are used). local lists the socket's own addresses.
func (p *Prober) Run(ctx context.Context, servers, local []netip.AddrPort) (Report, error) {
	select {
	case p.run <- struct{}{}:
		defer func() { <-p.run }()
	case <-ctx.Done():
		return Report{}, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Budget)
	defer cancel()

	servers, local = normalize(servers), normalize(local)
	r := &run{p: p, ctx: ctx, failed: make(map[netip.Addr]bool)}
	primary, first, err := r.firstAnswer(servers)
	if err != nil {
		return Report{At: p.cfg.Now()}, err
	}
	filtering := r.filtering(primary, first)
	r.mappingProbes(primary, first, servers)

	mapping := ClassifyMapping(local, r.obs)
	ports := make([]uint16, 0, len(r.obs))
	for _, o := range r.obs {
		ports = append(ports, o.Mapped.Port())
	}
	var localPort uint16
	if len(local) > 0 {
		localPort = local[0].Port()
	}
	alloc, step := ClassifyAllocation(mapping, localPort, ports)
	return Report{
		NAT:          disco.NATInfo{Mapping: mapping, Filtering: filtering, Allocation: alloc},
		Step:         step,
		Mapped:       first.XORMapped,
		Observations: r.obs,
		At:           p.cfg.Now(),
	}, nil
}

// run holds the state of one Run.
type run struct {
	p      *Prober
	ctx    context.Context
	obs    []Observation
	failed map[netip.Addr]bool // servers that did not answer; not retried
}

// firstAnswer finds the first server that answers a plain Binding request.
func (r *run) firstAnswer(servers []netip.AddrPort) (netip.AddrPort, stun.Message, error) {
	var errs []error
	for i, s := range servers {
		if i == MaxServers {
			break
		}
		msg, ok, err := r.p.transact(r.ctx, s, s, stun.ChangeRequest{})
		switch {
		case r.ctx.Err() != nil:
			return netip.AddrPort{}, stun.Message{}, errors.Join(ErrNoResponse, r.ctx.Err())
		case ok:
			r.obs = append(r.obs, Observation{Server: s, Mapped: msg.XORMapped})
			return s, msg, nil
		case err != nil:
			errs = append(errs, err) // e.g. no route to this family; try the next server
		}
		r.failed[s.Addr()] = true
	}
	return netip.AddrPort{}, stun.Message{}, errors.Join(append([]error{ErrNoResponse}, errs...)...)
}

// filtering runs the RFC 5780 probes against the first server. It must run
// before any packet is sent to the server's alternate port, otherwise that
// packet would open the filter the change-port probe is measuring.
func (r *run) filtering(server netip.AddrPort, first stun.Message) disco.Filtering {
	other := first.OtherAddress
	if !other.IsValid() || other.Port() == server.Port() {
		return disco.FilteringUnknown
	}
	changePortFrom := netip.AddrPortFrom(server.Addr(), other.Port())
	both, port := ProbeNotTried, ProbeNotTried
	var wg sync.WaitGroup
	if other.Addr() != server.Addr() {
		wg.Go(func() { both = r.p.probe(r.ctx, server, other, stun.ChangeRequest{IP: true, Port: true}) })
	}
	wg.Go(func() { port = r.p.probe(r.ctx, server, changePortFrom, stun.ChangeRequest{Port: true}) })
	wg.Wait()
	return ClassifyFiltering(both, port)
}

// mappingProbes contacts the remaining destinations one at a time, so the
// NAT creates mappings in a known order: the first server's alternate port,
// then each further server and its alternate port.
func (r *run) mappingProbes(primary netip.AddrPort, first stun.Message, servers []netip.AddrPort) {
	r.observe(alternate(primary, first))
	used := 1
	for _, s := range servers {
		if used == MaxServers || r.ctx.Err() != nil {
			return
		}
		if s.Addr() == primary.Addr() || r.failed[s.Addr()] {
			continue
		}
		used++
		if msg, ok := r.observe(s); ok {
			r.observe(alternate(s, msg))
		}
	}
}

func (r *run) observe(dst netip.AddrPort) (stun.Message, bool) {
	if !dst.IsValid() {
		return stun.Message{}, false
	}
	msg, ok, err := r.p.transact(r.ctx, dst, dst, stun.ChangeRequest{})
	if err != nil || !ok {
		return stun.Message{}, false
	}
	r.obs = append(r.obs, Observation{Server: dst, Mapped: msg.XORMapped})
	return msg, true
}

// normalize unmaps IPv4-mapped IPv6 addresses, so they compare equal to the
// sources the socket reports, and drops duplicates.
func normalize(servers []netip.AddrPort) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(servers))
	for _, s := range servers {
		s = netip.AddrPortFrom(s.Addr().Unmap(), s.Port())
		if s.IsValid() && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// alternate returns the server's primary IP with its alternate port.
func alternate(server netip.AddrPort, msg stun.Message) netip.AddrPort {
	if !msg.OtherAddress.IsValid() || msg.OtherAddress.Port() == server.Port() {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(server.Addr(), msg.OtherAddress.Port())
}

// probe reports ProbeLost only for a genuine timeout: a send error or a
// cancelled run says nothing about the NAT and yields ProbeNotTried.
func (p *Prober) probe(ctx context.Context, dst, expect netip.AddrPort, change stun.ChangeRequest) Probe {
	_, ok, err := p.transact(ctx, dst, expect, change)
	switch {
	case ok:
		return ProbeReceived
	case err != nil:
		return ProbeNotTried
	default:
		return ProbeLost
	}
}

// transact sends one Binding request to dst, retransmits it once, and waits
// for a response from expect. ok is false and err nil when the probe timed
// out; err is set when it could not be sent or ctx ended.
func (p *Prober) transact(ctx context.Context, dst, expect netip.AddrPort, change stun.ChangeRequest) (stun.Message, bool, error) {
	tx := &transaction{expect: expect, done: make(chan response, 1)}
	id, err := p.register(tx)
	if err != nil {
		return stun.Message{}, false, err
	}
	defer p.unregister(id)

	req, err := stun.AppendRequest(make([]byte, 0, 64+len(p.cfg.Software)), id, stun.Request{Change: change, Software: p.cfg.Software})
	if err != nil {
		return stun.Message{}, false, fmt.Errorf("netcheck: encode probe: %w", err)
	}
	if _, err := p.conn.WriteToUDPAddrPort(req, dst); err != nil {
		return stun.Message{}, false, fmt.Errorf("netcheck: send probe: %w", err)
	}
	retransmit := time.NewTimer(p.cfg.Retransmit)
	defer retransmit.Stop()
	deadline := time.NewTimer(p.cfg.ProbeTimeout)
	defer deadline.Stop()
	for {
		select {
		case resp := <-tx.done:
			return resp.msg, true, nil
		case <-retransmit.C:
			// A lost retransmission is just another lost packet.
			_, _ = p.conn.WriteToUDPAddrPort(req, dst)
		case <-deadline.C:
			return stun.Message{}, false, nil
		case <-ctx.Done():
			return stun.Message{}, false, ctx.Err()
		}
	}
}

// register draws a transaction ID and records tx under it. Drawing under
// p.mu keeps a caller-supplied, non-concurrent Config.Random safe.
func (p *Prober) register(tx *transaction) (stun.TxID, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var id stun.TxID
	if len(p.pending) >= maxPending {
		return id, errBusy
	}
	if _, err := io.ReadFull(p.cfg.Random, id[:]); err != nil {
		return id, fmt.Errorf("netcheck: transaction id: %w", err)
	}
	if _, dup := p.pending[id]; dup {
		return id, errors.New("netcheck: duplicate transaction id")
	}
	p.pending[id] = tx
	return id, nil
}

func (p *Prober) unregister(id stun.TxID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.pending, id)
}
