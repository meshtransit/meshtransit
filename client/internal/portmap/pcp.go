package portmap

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

// PCP (RFC 6887) constants.
const (
	pcpVersion        = 2
	pcpOpAnnounce     = 0
	pcpOpMap          = 1
	pcpResponseBit    = 0x80
	pcpHeaderLen      = 24
	pcpMapLen         = 36
	pcpProtocolUDP    = 17
	pcpResultSuccess  = 0
	pcpResultVersion  = 1
	pcpResultOpcode   = 4
	pcpResultMismatch = 12
)

// pcpClient implements PCP MAP for IPv4.
type pcpClient struct {
	listen ListenFunc
	clock  func() time.Time
}

func (pcpClient) protocol() Protocol { return ProtocolPCP }

// pcpResponse is a parsed PCP response header and, for MAP, its payload.
type pcpResponse struct {
	opcode   uint8
	result   uint8
	lifetime uint32
	epoch    uint32
	nonce    [12]byte
	protocol uint8
	internal uint16
	external netip.AddrPort
	// hasPayload is set when the response carried a MAP payload.
	hasPayload bool
}

func pcpResultError(code uint8) error {
	switch code {
	case pcpResultSuccess:
		return nil
	case pcpResultVersion, pcpResultOpcode:
		return ErrUnsupported
	default:
		return fmt.Errorf("%w: pcp result %d", ErrRefused, code)
	}
}

// pcpRequest builds a request header (RFC 6887 §7.1) and payload.
func pcpRequest(opcode uint8, lifetime uint32, client netip.Addr, payload []byte) []byte {
	request := make([]byte, pcpHeaderLen, pcpHeaderLen+len(payload))
	request[0], request[1] = pcpVersion, opcode
	binary.BigEndian.PutUint32(request[4:8], lifetime)
	address := client.As16() // IPv4 addresses are written IPv4-mapped
	copy(request[8:24], address[:])

	return append(request, payload...)
}

// pcpMapPayload builds a MAP opcode payload (RFC 6887 §11.1).
func pcpMapPayload(nonce [12]byte, internal, suggestedPort uint16, suggestedAddr netip.Addr) []byte {
	payload := make([]byte, pcpMapLen)
	copy(payload[0:12], nonce[:])
	payload[12] = pcpProtocolUDP
	binary.BigEndian.PutUint16(payload[16:18], internal)
	binary.BigEndian.PutUint16(payload[18:20], suggestedPort)
	// No preference is the all-zeros IPv4 address, written IPv4-mapped.
	if !suggestedAddr.Is4() {
		suggestedAddr = netip.IPv4Unspecified()
	}
	mapped := suggestedAddr.As16()
	copy(payload[20:36], mapped[:])

	return payload
}

// parsePCPResponse parses a PCP response for opcode. It returns ok=false for
// datagrams that are not a response to that opcode. A NAT-PMP-only gateway
// answers a PCP request with a NAT-PMP "unsupported version" response
// (RFC 6887 §9), reported as ErrUnsupported.
func parsePCPResponse(b []byte, opcode uint8) (pcpResponse, bool, error) {
	if len(b) >= 4 && b[0] == natpmpVersion {
		if binary.BigEndian.Uint16(b[2:4]) == natpmpResultBadVersion {
			return pcpResponse{}, true, ErrUnsupported
		}

		return pcpResponse{}, false, nil
	}
	if len(b) < pcpHeaderLen || b[1] != pcpResponseBit|opcode {
		return pcpResponse{}, false, nil
	}
	if b[0] != pcpVersion {
		// RFC 6887 §9: a server that does not support version 2 answers with
		// UNSUPP_VERSION and the version it supports.
		if b[3] == pcpResultVersion {
			return pcpResponse{}, true, ErrUnsupported
		}

		return pcpResponse{}, false, nil
	}
	response := pcpResponse{
		opcode:   opcode,
		result:   b[3],
		lifetime: binary.BigEndian.Uint32(b[4:8]),
		epoch:    binary.BigEndian.Uint32(b[8:12]),
	}
	if opcode != pcpOpMap {
		return response, true, pcpResultError(response.result)
	}
	if len(b) < pcpHeaderLen+pcpMapLen {
		if response.result != pcpResultSuccess {
			return response, true, pcpResultError(response.result)
		}

		return pcpResponse{}, true, fmt.Errorf("%w: short pcp map response", ErrInvalidResponse)
	}
	// Error responses repeat the request's payload (RFC 6887 §8.3), so the
	// caller matches nonce, protocol and port for them too.
	payload := b[pcpHeaderLen:]
	response.hasPayload = true
	copy(response.nonce[:], payload[0:12])
	response.protocol = payload[12]
	response.internal = binary.BigEndian.Uint16(payload[16:18])
	external := netip.AddrFrom16([16]byte(payload[20:36])).Unmap()
	response.external = netip.AddrPortFrom(external, binary.BigEndian.Uint16(payload[18:20]))

	return response, true, pcpResultError(response.result)
}

func (c pcpClient) mapRequest(
	ctx context.Context,
	gw Gateway,
	nonce [12]byte,
	internal uint16,
	suggested netip.AddrPort,
	lifetime uint32,
) (pcpResponse, error) {
	request := pcpRequest(pcpOpMap, lifetime, gw.Local,
		pcpMapPayload(nonce, internal, suggested.Port(), suggested.Addr()))
	var result pcpResponse
	err := exchange(ctx, c.listen, gw, request, func(b []byte) (bool, error) {
		parsed, ok, err := parsePCPResponse(b, pcpOpMap)
		if !ok {
			return false, nil
		}
		// RFC 6887 §11.3: match nonce, protocol and internal port.
		if parsed.hasPayload &&
			(parsed.nonce != nonce || parsed.protocol != pcpProtocolUDP || parsed.internal != internal) {
			return false, nil
		}
		if err != nil {
			return true, err
		}
		if !parsed.hasPayload {
			return true, fmt.Errorf("%w: pcp map response without payload", ErrInvalidResponse)
		}
		result = parsed

		return true, nil
	})

	return result, err
}

func (c pcpClient) mapPort(ctx context.Context, gw Gateway, internal uint16, previous *Mapping) (Mapping, error) {
	var nonce [12]byte
	suggested := netip.AddrPortFrom(netip.IPv4Unspecified(), internal)
	if previous != nil && previous.Protocol == ProtocolPCP && previous.Gateway == gw && previous.Internal == internal {
		nonce = previous.nonce
		suggested = previous.External
	} else if _, err := rand.Read(nonce[:]); err != nil {
		return Mapping{}, fmt.Errorf("portmap: pcp nonce: %w", err)
	}
	response, err := c.mapRequest(ctx, gw, nonce, internal, suggested, uint32(DefaultLifetime/time.Second))
	if err != nil {
		return Mapping{}, err
	}
	if response.lifetime == 0 || response.external.Port() == 0 || !response.external.Addr().Is4() ||
		response.external.Addr().IsUnspecified() {
		return Mapping{}, fmt.Errorf("%w: pcp granted no usable mapping", ErrInvalidResponse)
	}

	return Mapping{
		Protocol: ProtocolPCP,
		Gateway:  gw,
		Internal: internal,
		External: response.external,
		Lifetime: time.Duration(response.lifetime) * time.Second,
		Obtained: c.clock(),
		epoch:    response.epoch,
		nonce:    nonce,
	}, nil
}

func (c pcpClient) unmap(ctx context.Context, m Mapping) error {
	// RFC 6887 §15: a MAP with lifetime 0 and the same nonce deletes it.
	_, err := c.mapRequest(ctx, m.Gateway, m.nonce, m.Internal,
		netip.AddrPortFrom(netip.IPv4Unspecified(), 0), 0)

	return err
}

func (c pcpClient) check(ctx context.Context, m Mapping) (bool, error) {
	var epoch uint32
	err := exchange(ctx, c.listen, m.Gateway, pcpRequest(pcpOpAnnounce, 0, m.Gateway.Local, nil),
		func(b []byte) (bool, error) {
			parsed, ok, err := parsePCPResponse(b, pcpOpAnnounce)
			if ok && err == nil {
				epoch = parsed.epoch
			}

			return ok, err
		})
	if err != nil {
		return true, err // cannot tell; renewal at half lifetime still runs
	}

	return epochConsistent(m.epoch, epoch, c.clock().Sub(m.Obtained)), nil
}
