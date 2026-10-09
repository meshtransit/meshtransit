package natlab

import (
	"errors"
	"net"
	"net/netip"
	"sync"

	"meshtransit.net/shared/stun"
)

// STUNServer is an RFC 5780 STUN server on a host with one or two addresses:
// it answers Binding requests on two ports, honours CHANGE-REQUEST and
// reports RESPONSE-ORIGIN and OTHER-ADDRESS. With one address it can change
// only the port and never answers a change-IP request.
type STUNServer struct {
	primary, alternate netip.Addr // alternate is invalid with one address
	conns              [2]*Conn   // primary port, alternate port
	wg                 sync.WaitGroup
}

// NewSTUNServer starts a server on h listening on port and altPort.
func NewSTUNServer(h *Host, port, altPort uint16) (*STUNServer, error) {
	s := &STUNServer{primary: h.addrs[0]}
	for _, a := range h.addrs[1:] {
		if a.Is4() == s.primary.Is4() {
			s.alternate = a
			break
		}
	}
	for i, p := range []uint16{port, altPort} {
		c, err := h.Listen(p)
		if err != nil {
			s.Close()
			return nil, err
		}
		s.conns[i] = c
	}
	for i := range s.conns {
		s.wg.Go(func() { s.serve(i) })
	}
	return s, nil
}

// Addr returns the primary endpoint clients should query.
func (s *STUNServer) Addr() netip.AddrPort {
	return netip.AddrPortFrom(s.primary, s.conns[0].port)
}

// Close stops the server and waits for its goroutines.
func (s *STUNServer) Close() {
	for _, c := range s.conns {
		if c != nil {
			_ = c.Close()
		}
	}
	s.wg.Wait()
}

func (s *STUNServer) serve(i int) {
	buf := make([]byte, stun.MaxMessageSize)
	for {
		p, err := s.conns[i].readPacket()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			continue
		}
		s.answer(i, p, buf)
	}
}

func (s *STUNServer) answer(i int, p packet, buf []byte) {
	req, err := stun.Parse(p.payload)
	if err != nil || req.Type != stun.TypeBindingRequest {
		return
	}
	fromIP := p.dst.Addr()
	if req.Change.IP {
		if !s.alternate.IsValid() {
			return // cannot honour it; answering from here would mislead the client
		}
		fromIP = s.other(fromIP)
	}
	conn := s.conns[i]
	if req.Change.Port {
		conn = s.conns[1-i]
	}
	otherIP := s.primary
	if s.alternate.IsValid() {
		otherIP = s.other(p.dst.Addr())
	}
	resp, err := stun.AppendBindingSuccess(buf[:0], req.TxID, p.src,
		netip.AddrPortFrom(fromIP, conn.port),
		netip.AddrPortFrom(otherIP, s.conns[1-i].port))
	if err != nil {
		return
	}
	_, _ = conn.writeFrom(fromIP, resp, p.src)
}

func (s *STUNServer) other(a netip.Addr) netip.Addr {
	if a == s.primary {
		return s.alternate
	}
	return s.primary
}
