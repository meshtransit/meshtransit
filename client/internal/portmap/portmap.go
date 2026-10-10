// Package portmap asks the local Internet gateway to forward the WireGuard
// UDP port, so peers behind hard NATs can reach this node directly.
//
// It speaks PCP (RFC 6887), NAT-PMP (RFC 6886) and UPnP IGD (WANIPConnection
// v1/v2, WANPPPConnection v1), in that order, and only ever to the IPv4
// default gateway: requests go to the gateway address, and replies from any
// other source are ignored. A mapping is renewed at half its lifetime and
// removed when the mapper stops.
package portmap

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Protocol names the mapping protocol that produced a mapping.
type Protocol string

// Mapping protocols, in the order the mapper tries them.
const (
	ProtocolPCP    Protocol = "pcp"
	ProtocolNATPMP Protocol = "nat-pmp"
	ProtocolUPnP   Protocol = "upnp"
)

// DefaultLifetime is the mapping lifetime requested from the gateway.
const DefaultLifetime = 2 * time.Hour

// Errors shared by the protocol clients.
var (
	// ErrUnsupported means the gateway does not speak the protocol; the mapper
	// tries the next one.
	ErrUnsupported = errors.New("portmap: protocol not supported by the gateway")
	// ErrRefused means the gateway speaks the protocol but refused the request.
	ErrRefused = errors.New("portmap: gateway refused the mapping")
	// ErrNoGateway means there is no IPv4 default gateway.
	ErrNoGateway = errors.New("portmap: no IPv4 default gateway")
	// ErrInvalidResponse means a reply failed validation.
	ErrInvalidResponse = errors.New("portmap: invalid gateway response")
)

// Gateway is the IPv4 default gateway and the local address that faces it.
type Gateway struct {
	Addr  netip.Addr // the gateway's address
	Local netip.Addr // this host's address on the gateway's link
}

// Valid reports whether both addresses are IPv4 and usable.
func (g Gateway) Valid() bool {
	return g.Addr.Is4() && g.Local.Is4() && !g.Addr.IsUnspecified() && !g.Local.IsUnspecified() &&
		!g.Addr.IsMulticast() && g.Addr != g.Local
}

// translating reports whether the gateway can be a NAT this host sits
// behind: both addresses private, shared (100.64.0.0/10) or link-local.
func (g Gateway) translating() bool {
	inside := func(addr netip.Addr) bool {
		return addr.IsPrivate() || addr.IsLinkLocalUnicast() || sharedAddressSpace.Contains(addr)
	}

	return g.Valid() && inside(g.Addr) && inside(g.Local)
}

// Mapping is one UDP port mapping held on the gateway.
type Mapping struct {
	Protocol Protocol
	Gateway  Gateway
	Internal uint16         // the local UDP port
	External netip.AddrPort // the address and port peers can reach
	Lifetime time.Duration  // granted lifetime; zero means until removed
	Obtained time.Time

	// epoch is the gateway's epoch at Obtained (PCP and NAT-PMP).
	epoch uint32
	// nonce identifies a PCP mapping across renewals.
	nonce [12]byte
	// control is the UPnP control endpoint the mapping was made through.
	control upnpControl
}

// renewAt is when the mapping should be renewed: half its lifetime. A
// permanent mapping is refreshed hourly.
func (m Mapping) renewAt() time.Time {
	if m.Lifetime <= 0 {
		return m.Obtained.Add(time.Hour)
	}

	return m.Obtained.Add(m.Lifetime / 2)
}

// PublicExternal reports whether the external address is reachable from the
// Internet. A private or shared external address means another NAT sits
// beyond the gateway, so the mapping alone does not help peers.
func (m Mapping) PublicExternal() bool {
	return isPublicIPv4(m.External.Addr())
}

var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

func isPublicIPv4(addr netip.Addr) bool {
	return addr.Is4() && addr.IsGlobalUnicast() && !addr.IsPrivate() && !sharedAddressSpace.Contains(addr)
}

// PacketConn is the subset of *net.UDPConn the protocol clients use.
type PacketConn interface {
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error)
	ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

// ListenFunc opens a UDP socket on local with an ephemeral port.
type ListenFunc func(ctx context.Context, local netip.Addr) (PacketConn, error)

// client is one mapping protocol.
type client interface {
	protocol() Protocol
	// mapPort creates or renews a mapping of internal on gw. previous is the
	// mapping being renewed, or nil.
	mapPort(ctx context.Context, gw Gateway, internal uint16, previous *Mapping) (Mapping, error)
	// unmap removes a mapping. It is best effort.
	unmap(ctx context.Context, m Mapping) error
	// check reports whether the gateway still holds m, for gateways that can
	// tell (PCP and NAT-PMP epochs). It returns true when it cannot tell.
	check(ctx context.Context, m Mapping) (bool, error)
}

// Retransmission for PCP and NAT-PMP: 250 ms doubling, four attempts
// (RFC 6886 §3.1 starts at 250 ms; the RFCs allow longer, the mapper retries).
const (
	initialRetransmit = 250 * time.Millisecond
	maxAttempts       = 4
	maxDatagram       = 1100 // RFC 6887 §7: messages are at most 1100 bytes
	gatewayPort       = 5351
)

// exchange sends request to the gateway's port 5351 and returns the first
// reply from that address that accept takes. Replies from other sources and
// replies accept rejects are skipped.
func exchange(
	ctx context.Context,
	listen ListenFunc,
	gw Gateway,
	request []byte,
	accept func([]byte) (bool, error),
) error {
	conn, err := listen(ctx, gw.Local)
	if err != nil {
		return fmt.Errorf("portmap: opening socket: %w", err)
	}
	defer func() { _ = conn.Close() }()
	// Cancelling ctx ends a pending read at once.
	defer context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })()
	destination := netip.AddrPortFrom(gw.Addr, gatewayPort)
	buffer := make([]byte, maxDatagram)
	wait := initialRetransmit
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := conn.WriteToUDPAddrPort(request, destination); err != nil {
			return fmt.Errorf("portmap: sending request: %w", err)
		}
		deadline := time.Now().Add(wait)
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			return fmt.Errorf("portmap: setting deadline: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return err // cancelled before the deadline was set
		}
		for {
			n, source, err := conn.ReadFromUDPAddrPort(buffer)
			if err != nil {
				break // timeout: retransmit
			}
			if source.Addr().Unmap() != gw.Addr || source.Port() != gatewayPort {
				continue
			}
			done, err := accept(buffer[:n])
			if err != nil {
				return err
			}
			if done {
				return nil
			}
		}
		wait *= 2
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	return ErrUnsupported // no answer: nothing speaks the protocol there
}
