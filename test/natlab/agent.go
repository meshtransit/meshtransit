package natlab

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"meshtransit.net/shared/disco"
	"meshtransit.net/shared/key"
	"meshtransit.net/shared/netcheck"
)

// Agent defaults.
const (
	DefaultPingInterval     = 10 * time.Millisecond
	DefaultBirthdaySockets  = 256
	DefaultSprayPerInterval = 64
	predictionWindow        = 256
	maxCandidates           = 64
	pingLifetime            = time.Second
	birthdayRefreshTicks    = 50
	eventQueue              = 4096
	minProbePort            = 1024
)

// Technique says how a direct path was found, from least to most effort.
type Technique uint8

// Techniques.
const (
	TechniqueNone          Technique = iota // no direct path; traffic stays relayed
	TechniqueDirect                         // an advertised endpoint answered
	TechniquePeerReflexive                  // the peer's packets revealed a new endpoint
	TechniquePrediction                     // probing predicted ports of a sequential allocator
	TechniqueBirthday                       // random probing against many hard-side mappings
)

func (t Technique) String() string {
	switch t {
	case TechniqueDirect:
		return "direct"
	case TechniquePeerReflexive:
		return "peer-reflexive"
	case TechniquePrediction:
		return "prediction"
	case TechniqueBirthday:
		return "birthday"
	default:
		return "relay"
	}
}

// AgentConfig configures a reference traversal agent.
type AgentConfig struct {
	Host  *Host
	Disco key.DiscoPrivate
	Node  key.NodePublic
	STUN  []netip.AddrPort
	Seed  uint64 // seeds probe port choices
	// Prober tunes netcheck; lab defaults are much shorter than production.
	Prober           netcheck.Config
	PingInterval     time.Duration
	BirthdaySockets  int
	SprayPerInterval int
}

// Result is the path an agent confirmed: it sent a PING to Remote from
// Local and received the matching PONG.
type Result struct {
	Local     netip.AddrPort
	Remote    netip.AddrPort
	Technique Technique
	Elapsed   time.Duration
}

// Agent is a reference implementation of disco v2 path discovery over natlab
// sockets. It is test infrastructure: it shows which techniques find a path
// for which NAT pairs, and it exercises the shared codecs end to end.
//
// Probe, Introduce, Offer and Accept must run before Run; Run owns the agent
// state until it returns. Close releases sockets and goroutines.
type Agent struct {
	cfg    AgentConfig
	rng    *mrand.Rand
	prober *netcheck.Prober
	report netcheck.Report
	guard  disco.ReplayGuard
	seq    uint64
	peer   *peer

	mu        sync.Mutex // guards conns
	conns     []*Conn    // conns[0] is the main socket
	events    chan inbound
	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup

	// Run state, owned by the Run goroutine.
	cands       map[candidate]Technique
	pending     map[disco.TxID]sentPing
	spray       Technique // TechniquePrediction or TechniqueBirthday when spraying
	sprayNext   int
	ticks       int
	result      Result
	resultConn  int
	established chan struct{}
}

type peer struct {
	key       *disco.PeerKey
	node      key.NodePublic
	nat       disco.NATInfo
	endpoints []netip.AddrPort
	reflexive netip.AddrPort // server-reflexive endpoint, if advertised
}

type candidate struct {
	conn int
	addr netip.AddrPort
}

// anyConn marks a PING sent from every extra socket.
const anyConn = -1

type sentPing struct {
	conn      int            // anyConn for birthday pings
	to        netip.AddrPort // invalid for spray and birthday pings
	technique Technique
	at        time.Time
}

type inbound struct {
	conn int
	from netip.AddrPort
	data []byte
}

// NewAgent opens the agent's main socket on cfg.Host.
func NewAgent(cfg AgentConfig) (*Agent, error) {
	if cfg.Host == nil || cfg.Disco.IsZero() || cfg.Node.IsZero() {
		return nil, errors.New("natlab: agent needs a host, a disco key and a node key")
	}
	if cfg.PingInterval <= 0 {
		cfg.PingInterval = DefaultPingInterval
	}
	if cfg.BirthdaySockets <= 0 {
		cfg.BirthdaySockets = DefaultBirthdaySockets
	}
	if cfg.SprayPerInterval <= 0 {
		cfg.SprayPerInterval = DefaultSprayPerInterval
	}
	if cfg.Prober.ProbeTimeout == 0 {
		cfg.Prober = netcheck.Config{ProbeTimeout: 100 * time.Millisecond, Retransmit: 20 * time.Millisecond, Budget: time.Second}
	}
	main, err := cfg.Host.Listen(0)
	if err != nil {
		return nil, err
	}
	a := &Agent{
		cfg:         cfg,
		rng:         mrand.New(mrand.NewPCG(cfg.Seed, ^cfg.Seed)), //nolint:gosec // reproducible probe ports, not secrets
		prober:      netcheck.NewProber(main, cfg.Prober),
		events:      make(chan inbound, eventQueue),
		done:        make(chan struct{}),
		cands:       make(map[candidate]Technique),
		pending:     make(map[disco.TxID]sentPing),
		established: make(chan struct{}),
	}
	a.addConn(main)
	return a, nil
}

// Probe classifies the agent's NAT.
func (a *Agent) Probe(ctx context.Context) (netcheck.Report, error) {
	r, err := a.prober.Run(ctx, a.cfg.STUN, a.conn(0).LocalAddrPorts())
	if err != nil {
		return netcheck.Report{}, err
	}
	a.report = r
	return r, nil
}

// Introduce sets the peer's keys, as the control plane's map would.
func (a *Agent) Introduce(peerDisco key.DiscoPublic, peerNode key.NodePublic) error {
	k, err := disco.NewPeerKey(a.cfg.Disco, peerDisco)
	if err != nil {
		return err
	}
	a.peer = &peer{key: k, node: peerNode}
	return nil
}

// Offer returns a sealed CALL_ME_MAYBE listing the agent's endpoints. In a
// deployment it travels through the relay.
func (a *Agent) Offer() ([]byte, error) {
	if a.peer == nil {
		return nil, errors.New("natlab: offer before introduce")
	}
	var eps []disco.Endpoint
	for _, ap := range a.conn(0).LocalAddrPorts() {
		eps = append(eps, disco.Endpoint{Kind: disco.EndpointHost, Addr: ap})
	}
	if m := a.report.Mapped; m.IsValid() && !slices.ContainsFunc(eps, func(e disco.Endpoint) bool { return e.Addr == m }) {
		eps = append(eps, disco.Endpoint{Kind: disco.EndpointServerReflex, Addr: m})
	}
	a.seq++
	cmm := disco.CallMeMaybe{Seq: a.seq, SentAt: time.Now().UnixMilli(), NAT: a.report.NAT, Endpoints: eps}
	return a.peer.key.Seal(nil, cmm, rand.Reader)
}

// Accept verifies and records the peer's CALL_ME_MAYBE.
func (a *Agent) Accept(offer []byte) error {
	if a.peer == nil {
		return errors.New("natlab: accept before introduce")
	}
	msg, err := a.peer.key.Open(offer)
	if err != nil {
		return err
	}
	cmm, ok := msg.(disco.CallMeMaybe)
	if !ok {
		return fmt.Errorf("natlab: offer is %T, not a call-me-maybe", msg)
	}
	if err := a.guard.Accept(a.peer.key.Peer(), cmm); err != nil {
		return err
	}
	a.peer.nat = cmm.NAT
	a.peer.endpoints = a.peer.endpoints[:0]
	for _, e := range cmm.Endpoints {
		a.peer.endpoints = append(a.peer.endpoints, e.Addr)
		a.cands[candidate{conn: 0, addr: e.Addr}] = TechniqueDirect
		if e.Kind == disco.EndpointServerReflex {
			a.peer.reflexive = e.Addr
		}
	}
	return nil
}

// Established is closed once Run has confirmed a path.
func (a *Agent) Established() <-chan struct{} { return a.established }

// Run probes and answers until ctx is done and returns the confirmed path,
// whose Technique is TechniqueNone when no direct path was found. It keeps
// answering the peer after confirming, so the peer can confirm too.
func (a *Agent) Run(ctx context.Context) (Result, error) {
	if a.peer == nil || len(a.peer.endpoints) == 0 {
		return Result{}, errors.New("natlab: run before accept")
	}
	start := time.Now()
	if err := a.chooseRole(); err != nil {
		return Result{}, err
	}
	ticker := time.NewTicker(a.cfg.PingInterval)
	defer ticker.Stop()
	a.tick(start)
	for {
		select {
		case <-ctx.Done():
			return a.result, nil
		case ev := <-a.events:
			a.handle(ev, start)
		case now := <-ticker.C:
			a.tick(now)
		}
	}
}

// Close stops the agent's goroutines and releases its sockets.
func (a *Agent) Close() {
	a.closeOnce.Do(func() {
		close(a.done)
		a.mu.Lock()
		conns := slices.Clone(a.conns)
		a.mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
		a.wg.Wait()
	})
}

func (a *Agent) conn(i int) *Conn {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.conns[i]
}

func (a *Agent) addConn(c *Conn) int {
	a.mu.Lock()
	i := len(a.conns)
	a.conns = append(a.conns, c)
	a.mu.Unlock()
	a.wg.Go(func() { a.read(i, c) })
	return i
}

// read forwards datagrams from one socket to the Run loop. STUN answers on
// the main socket go to the prober.
func (a *Agent) read(i int, c *Conn) {
	buf := make([]byte, 2048)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			continue
		}
		if i == 0 && a.prober.HandleResponse(buf[:n], from) {
			continue
		}
		select {
		case a.events <- inbound{conn: i, from: from, data: bytes.Clone(buf[:n])}:
		case <-a.done:
			return
		default: // queue full: drop, as a socket would
		}
	}
}
