package pathdiscovery

import (
	"context"
	"errors"
	"net/netip"
	"slices"

	"meshtransit.net/shared/netcheck"
	"meshtransit.net/shared/stun"
)

// NATReport is one NAT classification bound to the socket generation it
// describes.
type NATReport struct {
	Socket Socket
	Report netcheck.Report
}

// NATClassifier classifies the NAT in front of the shared encrypted packet
// socket (docs/protocol/nat-classification.md). It sends STUN through the
// transport and receives answers as a DatagramHandler, so the result describes
// the mapping that WireGuard traffic actually uses.
type NATClassifier struct {
	transport DatagramTransport
	prober    *netcheck.Prober
}

var _ DatagramHandler = (*NATClassifier)(nil)

// NewNATClassifier constructs a classifier over the shared transport.
func NewNATClassifier(transport DatagramTransport, config netcheck.Config) (*NATClassifier, error) {
	if transport == nil {
		return nil, errors.New("pathdiscovery: datagram transport is required")
	}

	return &NATClassifier{
		transport: transport,
		prober:    netcheck.NewProber(transportWriter{transport}, config),
	}, nil
}

// MatchesDatagram implements DatagramHandler.
func (c *NATClassifier) MatchesDatagram(packet []byte) bool { return stun.Is(packet) }

// HandleDatagram implements DatagramHandler. Answers to transactions the
// classifier did not send are ignored.
func (c *NATClassifier) HandleDatagram(packet []byte, source netip.AddrPort, _ Socket) {
	if c != nil {
		c.prober.HandleResponse(packet, source)
	}
}

// Classify runs one bounded classification against servers. local lists the
// socket's own addresses, used to recognise a host without NAT.
func (c *NATClassifier) Classify(
	ctx context.Context,
	servers []netip.AddrPort,
	local []netip.AddrPort,
) (NATReport, error) {
	if c == nil {
		return NATReport{}, ErrTransportClosed
	}
	socket := c.transport.Socket()
	if !socket.IsOpen() {
		return NATReport{}, ErrTransportClosed
	}
	report, err := c.prober.Run(ctx, servers, local)
	if err != nil {
		return NATReport{}, err
	}
	if c.transport.Socket() != socket {
		return NATReport{}, ErrSocketChanged
	}

	return NATReport{Socket: socket, Report: report}, nil
}

// NATServers orders relay STUN endpoints for classification: IPv4 first
// (the family whose NAT matters most), one endpoint per address, in the
// region-spread order of ServersFromRelayMap.
func NATServers(servers []RelayServer) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, min(len(servers), netcheck.MaxServers))
	for _, wantV4 := range []bool{true, false} {
		for _, server := range servers {
			endpoint := server.Endpoint
			if endpoint.Addr().Is4() != wantV4 || len(out) == netcheck.MaxServers {
				continue
			}
			if !slices.ContainsFunc(out, func(e netip.AddrPort) bool { return e.Addr() == endpoint.Addr() }) {
				out = append(out, endpoint)
			}
		}
	}

	return out
}

// transportWriter adapts the shared transport to netcheck.PacketWriter.
type transportWriter struct{ transport DatagramTransport }

func (w transportWriter) WriteToUDPAddrPort(packet []byte, destination netip.AddrPort) (int, error) {
	if _, err := w.transport.SendDatagram(packet, destination); err != nil {
		return 0, err
	}

	return len(packet), nil
}

// JoinHandlers returns a DatagramHandler that offers each packet to every
// handler that matches it. Handlers that share a protocol (such as endpoint
// discovery and NAT classification, both STUN) each ignore transactions they
// did not start.
func JoinHandlers(handlers ...DatagramHandler) DatagramHandler {
	return joinedHandlers(slices.DeleteFunc(slices.Clone(handlers), func(h DatagramHandler) bool { return h == nil }))
}

type joinedHandlers []DatagramHandler

func (j joinedHandlers) MatchesDatagram(packet []byte) bool {
	return slices.ContainsFunc(j, func(h DatagramHandler) bool { return h.MatchesDatagram(packet) })
}

func (j joinedHandlers) HandleDatagram(packet []byte, source netip.AddrPort, socket Socket) {
	for _, h := range j {
		if h.MatchesDatagram(packet) {
			h.HandleDatagram(packet, source, socket)
		}
	}
}
