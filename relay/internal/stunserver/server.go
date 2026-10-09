// Package stunserver answers STUN Binding requests (RFC 8489) with the RFC
// 5780 attributes that let nodes classify their NAT
// (docs/protocol/nat-classification.md): RESPONSE-ORIGIN, OTHER-ADDRESS and
// CHANGE-REQUEST handling on an alternate port and, when configured, an
// alternate address.
package stunserver

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"meshtransit.net/relay/internal/ratelimit"
	"meshtransit.net/relay/internal/udp"
	"meshtransit.net/shared/stun"
)

// Defaults bound the reflection a STUN server offers: a response is a few
// dozen bytes larger than the smallest request.
const (
	DefaultGlobalRate = 20_000 // responses per second
	DefaultSourceRate = 20     // responses per second per source address
	maxSources        = 1 << 16
)

// Config describes the sockets and public addresses of the server.
type Config struct {
	// Listen addresses: the primary socket and the alternate-port socket.
	// With an alternate address, AltAddrListen and AltBothListen are the
	// sockets on that address.
	Primary, AltPort          string
	AltAddrListen, AltBoth    string
	PublicAddr, PublicAltAddr netip.Addr // as clients reach them; PublicAltAddr optional
	GlobalRate, SourceRate    float64
	Now                       func() time.Time
	Metrics                   func(result string)
}

// Server is a running STUN server.
type Server struct {
	cfg Config
	// sockets[addr][port]: addr 0 primary, 1 alternate; port 0 primary, 1 alternate.
	sockets [2][2]*udp.Listener
	ports   [2]uint16

	global  *ratelimit.Shared
	sources *ratelimit.SourceLimiter
}

// Listen opens the sockets. PublicAddr is required for RFC 5780 attributes;
// without it the server answers plain Binding requests only.
func Listen(cfg Config) (*Server, error) {
	if cfg.Primary == "" {
		return nil, errors.New("stunserver: primary listen address is required")
	}
	if cfg.GlobalRate <= 0 {
		cfg.GlobalRate = DefaultGlobalRate
	}
	if cfg.SourceRate <= 0 {
		cfg.SourceRate = DefaultSourceRate
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Metrics == nil {
		cfg.Metrics = func(string) {}
	}
	s := &Server{
		cfg:     cfg,
		global:  ratelimit.NewShared(cfg.GlobalRate, cfg.GlobalRate),
		sources: ratelimit.NewSourceLimiter(cfg.SourceRate, cfg.SourceRate, maxSources, cfg.Now),
	}
	open := func(addr string, a, p int) error {
		if addr == "" {
			return nil
		}
		l, err := udp.Listen(addr, stun.MaxMessageSize)
		if err != nil {
			s.Close()
			return err
		}
		s.sockets[a][p] = l
		s.ports[p] = l.LocalAddr().Port()
		return nil
	}
	for _, o := range []struct {
		addr string
		a, p int
	}{{cfg.Primary, 0, 0}, {cfg.AltPort, 0, 1}, {cfg.AltAddrListen, 1, 0}, {cfg.AltBoth, 1, 1}} {
		if err := open(o.addr, o.a, o.p); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Serve answers requests on every socket until ctx is done.
func (s *Server) Serve(ctx context.Context) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error
	for a := range 2 {
		for p := range 2 {
			l := s.sockets[a][p]
			if l == nil {
				continue
			}
			wg.Go(func() {
				err := l.Serve(ctx, 1, func(frame []byte, from netip.AddrPort) { s.answer(a, p, frame, from) })
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			})
		}
	}
	wg.Wait()
	return errors.Join(errs...)
}

// Close closes every socket.
func (s *Server) Close() {
	for a := range 2 {
		for p := range 2 {
			if l := s.sockets[a][p]; l != nil {
				_ = l.Close()
			}
		}
	}
}

// Ports returns the bound primary and alternate ports (alternate 0 if none).
func (s *Server) Ports() (primary, alternate uint16) { return s.ports[0], s.ports[1] }

func (s *Server) answer(a, p int, frame []byte, from netip.AddrPort) {
	req, err := stun.Parse(frame)
	if err != nil || req.Type != stun.TypeBindingRequest {
		s.cfg.Metrics("invalid")
		return
	}
	if !s.allow(from.Addr()) {
		s.cfg.Metrics("rate_limited")
		return
	}
	ra, rp := a, p
	if req.Change.IP {
		ra = 1 - a
	}
	if req.Change.Port {
		rp = 1 - p
	}
	out := s.sockets[ra][rp]
	if out == nil {
		// Answering from the receiving socket would misreport filtering.
		s.cfg.Metrics("change_unsupported")
		return
	}
	var origin, other netip.AddrPort
	if pub := s.publicAddr(ra); pub.IsValid() {
		origin = netip.AddrPortFrom(pub, s.ports[rp])
	}
	if pub, port := s.publicAddr(1-a), s.ports[1-p]; port != 0 {
		if !pub.IsValid() {
			pub = s.publicAddr(a) // alternate port only: same address
		}
		if pub.IsValid() {
			other = netip.AddrPortFrom(pub, port)
		}
	}
	var buf [stun.MaxMessageSize]byte
	resp, err := stun.AppendBindingSuccess(buf[:0], req.TxID, from, origin, other)
	if err != nil {
		return
	}
	if _, err := out.WriteToUDPAddrPort(resp, from); err == nil {
		s.cfg.Metrics("answered")
	}
}

func (s *Server) publicAddr(a int) netip.Addr {
	if a == 0 {
		return s.cfg.PublicAddr
	}
	if s.sockets[1][0] == nil && s.sockets[1][1] == nil {
		return netip.Addr{}
	}
	return s.cfg.PublicAltAddr
}

// allow applies the per-source (IPv6: per /64) and global rate limits.
func (s *Server) allow(src netip.Addr) bool {
	return s.sources.Allow(src) && s.global.Allow(s.cfg.Now())
}
