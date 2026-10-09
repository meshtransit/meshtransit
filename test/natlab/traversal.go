package natlab

import (
	"context"
	"crypto/rand"
	"errors"
	"net/netip"
	"slices"
	"time"

	"meshtransit.net/shared/disco"
)

// chooseRole picks the extra technique for this NAT pair:
//
//   - easy mapping with port-restricted filtering facing a hard peer: spray
//     probes at the peer's address, predicted ports first when the peer
//     allocates sequentially;
//   - hard mapping with random allocation facing a port-restricted easy
//     peer: open many sockets so that some spray probe hits one of their
//     mappings (the birthday paradox).
//
// Other pairs need nothing beyond pinging candidates and answering with
// peer-reflexive learning.
func (a *Agent) chooseRole() error {
	self, other := a.report.NAT, a.peer.nat
	strictFilter := func(f disco.Filtering) bool {
		return f != disco.FilteringEndpointIndependent && f != disco.FilteringAddressDependent
	}
	switch {
	case self.Mapping.Easy() && other.Mapping.Hard() && strictFilter(self.Filtering) && a.peer.reflexive.IsValid():
		a.spray = TechniqueBirthday
		if other.Allocation == disco.AllocationSequential {
			a.spray = TechniquePrediction
		}
	case self.Mapping.Hard() && other.Mapping.Easy() && strictFilter(other.Filtering) &&
		self.Allocation != disco.AllocationSequential && a.peer.reflexive.IsValid():
		for range a.cfg.BirthdaySockets {
			c, err := a.cfg.Host.Listen(0)
			if err != nil {
				return err
			}
			a.addConn(c)
		}
	}
	return nil
}

func (a *Agent) tick(now time.Time) {
	a.ticks++
	for id, p := range a.pending {
		if now.Sub(p.at) > pingLifetime {
			delete(a.pending, id)
		}
	}
	if a.result.Technique != TechniqueNone {
		a.ping(now, a.resultConn, a.result.Remote, a.result.Technique) // keepalive
		return
	}
	for c, t := range a.cands {
		a.ping(now, c.conn, c.addr, t)
	}
	if n := a.connCount(); n > 1 && (a.ticks == 1 || a.ticks%birthdayRefreshTicks == 0) {
		a.birthdayPings(now, n)
	}
	if a.spray != TechniqueNone {
		a.sprayPings(now)
	}
}

// birthdayPings sends one PING from every extra socket to the peer's
// reflexive endpoint, creating a mapping (and filter permit) per socket.
func (a *Agent) birthdayPings(now time.Time, conns int) {
	pkt, id, ok := a.sealPing(now)
	if !ok {
		return
	}
	a.pending[id] = sentPing{conn: anyConn, technique: TechniqueBirthday, at: now}
	for i := 1; i < conns; i++ {
		_, _ = a.conn(i).WriteToUDPAddrPort(pkt, a.peer.reflexive)
	}
}

// sprayPings sends one shared PING to the next batch of ports on the peer's
// reflexive address.
func (a *Agent) sprayPings(now time.Time) {
	pkt, id, ok := a.sealPing(now)
	if !ok {
		return
	}
	a.pending[id] = sentPing{conn: 0, technique: a.spray, at: now}
	base := a.peer.reflexive
	main := a.conn(0)
	for range a.cfg.SprayPerInterval {
		var port uint16
		if a.spray == TechniquePrediction {
			a.sprayNext = a.sprayNext%predictionWindow + 1
			port = base.Port() + uint16(a.sprayNext) //nolint:gosec // sprayNext ≤ predictionWindow; wraps by design
		} else {
			port = minProbePort + uint16(a.rng.UintN(1<<16-minProbePort)) //nolint:gosec // < 2^16 by construction
		}
		if port < minProbePort {
			continue
		}
		_, _ = main.WriteToUDPAddrPort(pkt, netip.AddrPortFrom(base.Addr(), port))
	}
}

func (a *Agent) ping(now time.Time, conn int, to netip.AddrPort, t Technique) {
	pkt, id, ok := a.sealPing(now)
	if !ok {
		return
	}
	a.pending[id] = sentPing{conn: conn, to: to, technique: t, at: now}
	_, _ = a.conn(conn).WriteToUDPAddrPort(pkt, to)
}

func (a *Agent) sealPing(now time.Time) ([]byte, disco.TxID, bool) {
	var id disco.TxID
	if _, err := rand.Read(id[:]); err != nil {
		return nil, id, false
	}
	pkt, err := a.peer.key.Seal(nil, disco.Ping{TxID: id, Node: a.cfg.Node, SentAt: now.UnixMilli()}, rand.Reader)
	return pkt, id, err == nil
}

func (a *Agent) handle(ev inbound, start time.Time) {
	if !disco.LooksLikeDisco(ev.data) {
		return
	}
	msg, err := a.peer.key.Open(ev.data)
	if err != nil {
		return // forged, corrupted or from someone else: never answer
	}
	switch m := msg.(type) {
	case disco.Ping:
		if m.Node != a.peer.node {
			return
		}
		a.learn(ev)
		pong, err := a.peer.key.Seal(nil, disco.Pong{TxID: m.TxID, Observed: ev.from, Echo: m.SentAt}, rand.Reader)
		if err == nil {
			_, _ = a.conn(ev.conn).WriteToUDPAddrPort(pong, ev.from)
		}
	case disco.Pong:
		sent, ok := a.pending[m.TxID]
		if !ok || (sent.conn >= 0 && sent.conn != ev.conn) || (sent.to.IsValid() && sent.to != ev.from) {
			return
		}
		if a.result.Technique == TechniqueNone {
			a.result = Result{
				Local:     a.conn(ev.conn).LocalAddrPort(),
				Remote:    ev.from,
				Technique: sent.technique,
				Elapsed:   time.Since(start),
			}
			a.resultConn = ev.conn
			close(a.established)
		}
	}
}

// learn records the source of a PING as a candidate (peer-reflexive
// learning), bounded so that a flood cannot grow the table.
func (a *Agent) learn(ev inbound) {
	c := candidate{conn: ev.conn, addr: ev.from}
	if _, ok := a.cands[c]; ok || len(a.cands) >= maxCandidates {
		return
	}
	switch {
	case ev.conn != 0:
		a.cands[c] = TechniqueBirthday
	case a.spray != TechniqueNone:
		a.cands[c] = a.spray
	case slices.Contains(a.peer.endpoints, ev.from):
		a.cands[c] = TechniqueDirect
	default:
		a.cands[c] = TechniquePeerReflexive
	}
}

func (a *Agent) connCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.conns)
}

// Pair runs a full exchange between two agents: both classify their NAT,
// swap offers and probe until both confirm a path or timeout passes.
func Pair(ctx context.Context, a, b *Agent, timeout time.Duration) (Result, Result, error) {
	for _, ag := range []*Agent{a, b} {
		if _, err := ag.Probe(ctx); err != nil {
			return Result{}, Result{}, err
		}
	}
	if err := exchange(a, b); err != nil {
		return Result{}, Result{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type out struct {
		r   Result
		err error
	}
	results := [2]chan out{make(chan out, 1), make(chan out, 1)}
	for i, ag := range []*Agent{a, b} {
		go func() {
			r, err := ag.Run(ctx)
			results[i] <- out{r, err}
		}()
	}
	go func() {
		// Stop early once both sides have confirmed a path.
		for _, ag := range []*Agent{a, b} {
			select {
			case <-ag.Established():
			case <-ctx.Done():
				return
			}
		}
		cancel()
	}()
	ra, rb := <-results[0], <-results[1]
	return ra.r, rb.r, errors.Join(ra.err, rb.err)
}

func exchange(a, b *Agent) error {
	offerA, err := a.Offer()
	if err != nil {
		return err
	}
	offerB, err := b.Offer()
	if err != nil {
		return err
	}
	return errors.Join(b.Accept(offerA), a.Accept(offerB))
}
