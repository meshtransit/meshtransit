package portmap

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

// NAT-PMP (RFC 6886) opcodes and result codes.
const (
	natpmpVersion          = 0
	natpmpOpExternal       = 0
	natpmpOpMapUDP         = 1
	natpmpResponseBit      = 128
	natpmpResultSuccess    = 0
	natpmpResultBadVersion = 1
	natpmpResultBadOpcode  = 5
)

// natpmpClient implements NAT-PMP.
type natpmpClient struct {
	listen ListenFunc
	clock  func() time.Time
}

func (natpmpClient) protocol() Protocol { return ProtocolNATPMP }

// natpmpExternal is a parsed external address response.
type natpmpExternal struct {
	epoch    uint32
	external netip.Addr
}

// natpmpMap is a parsed mapping response.
type natpmpMap struct {
	epoch    uint32
	internal uint16
	external uint16
	lifetime uint32
}

func natpmpResultError(code uint16) error {
	switch code {
	case natpmpResultSuccess:
		return nil
	case natpmpResultBadVersion, natpmpResultBadOpcode:
		return ErrUnsupported
	default:
		return fmt.Errorf("%w: nat-pmp result %d", ErrRefused, code)
	}
}

// parseNATPMPExternal parses an external address response (RFC 6886 §3.2).
// It returns ok=false for a datagram that is not that response.
func parseNATPMPExternal(b []byte) (natpmpExternal, bool, error) {
	if len(b) < 4 || b[0] != natpmpVersion || b[1] != natpmpResponseBit|natpmpOpExternal {
		return natpmpExternal{}, false, nil
	}
	if err := natpmpResultError(binary.BigEndian.Uint16(b[2:4])); err != nil {
		return natpmpExternal{}, true, err
	}
	if len(b) < 12 {
		return natpmpExternal{}, true, fmt.Errorf("%w: short nat-pmp response", ErrInvalidResponse)
	}

	return natpmpExternal{
		epoch:    binary.BigEndian.Uint32(b[4:8]),
		external: netip.AddrFrom4([4]byte(b[8:12])),
	}, true, nil
}

// parseNATPMPMap parses a UDP mapping response (RFC 6886 §3.3).
func parseNATPMPMap(b []byte) (natpmpMap, bool, error) {
	if len(b) < 4 || b[0] != natpmpVersion || b[1] != natpmpResponseBit|natpmpOpMapUDP {
		return natpmpMap{}, false, nil
	}
	var parsed natpmpMap
	if len(b) >= 16 {
		parsed = natpmpMap{
			epoch:    binary.BigEndian.Uint32(b[4:8]),
			internal: binary.BigEndian.Uint16(b[8:10]),
			external: binary.BigEndian.Uint16(b[10:12]),
			lifetime: binary.BigEndian.Uint32(b[12:16]),
		}
	}
	// Error responses carry the request's internal port when they are full
	// length, so the caller can match them too.
	if err := natpmpResultError(binary.BigEndian.Uint16(b[2:4])); err != nil {
		return parsed, true, err
	}
	if len(b) < 16 {
		return natpmpMap{}, true, fmt.Errorf("%w: short nat-pmp response", ErrInvalidResponse)
	}

	return parsed, true, nil
}

func natpmpMapRequest(internal, suggested uint16, lifetime uint32) []byte {
	request := make([]byte, 12)
	request[0], request[1] = natpmpVersion, natpmpOpMapUDP
	binary.BigEndian.PutUint16(request[4:6], internal)
	binary.BigEndian.PutUint16(request[6:8], suggested)
	binary.BigEndian.PutUint32(request[8:12], lifetime)

	return request
}

func (c natpmpClient) external(ctx context.Context, gw Gateway) (natpmpExternal, error) {
	var result natpmpExternal
	err := exchange(ctx, c.listen, gw, []byte{natpmpVersion, natpmpOpExternal}, func(b []byte) (bool, error) {
		parsed, ok, err := parseNATPMPExternal(b)
		if ok && err == nil {
			result = parsed
		}

		return ok, err
	})

	return result, err
}

func (c natpmpClient) request(ctx context.Context, gw Gateway, internal, suggested uint16, lifetime uint32) (natpmpMap, error) {
	var result natpmpMap
	err := exchange(ctx, c.listen, gw, natpmpMapRequest(internal, suggested, lifetime), func(b []byte) (bool, error) {
		parsed, ok, err := parseNATPMPMap(b)
		if !ok {
			return false, nil
		}
		if parsed.internal != 0 && parsed.internal != internal {
			return false, nil // a reply to another request
		}
		if err != nil {
			return true, err
		}
		result = parsed

		return true, nil
	})

	return result, err
}

func (c natpmpClient) mapPort(ctx context.Context, gw Gateway, internal uint16, previous *Mapping) (Mapping, error) {
	external, err := c.external(ctx, gw)
	if err != nil {
		return Mapping{}, err
	}
	suggested := internal
	if previous != nil && previous.External.IsValid() {
		suggested = previous.External.Port()
	}
	mapped, err := c.request(ctx, gw, internal, suggested, uint32(DefaultLifetime/time.Second))
	if err != nil {
		return Mapping{}, err
	}
	if mapped.external == 0 || mapped.lifetime == 0 || external.external.IsUnspecified() {
		return Mapping{}, fmt.Errorf("%w: nat-pmp granted no mapping", ErrInvalidResponse)
	}

	return Mapping{
		Protocol: ProtocolNATPMP,
		Gateway:  gw,
		Internal: internal,
		External: netip.AddrPortFrom(external.external, mapped.external),
		Lifetime: time.Duration(mapped.lifetime) * time.Second,
		Obtained: c.clock(),
		epoch:    mapped.epoch,
	}, nil
}

func (c natpmpClient) unmap(ctx context.Context, m Mapping) error {
	// RFC 6886 §3.4: lifetime 0 and suggested external port 0 delete it.
	_, err := c.request(ctx, m.Gateway, m.Internal, 0, 0)

	return err
}

func (c natpmpClient) check(ctx context.Context, m Mapping) (bool, error) {
	external, err := c.external(ctx, m.Gateway)
	if err != nil {
		return false, err
	}
	if external.external != m.External.Addr() {
		return false, nil
	}

	return epochConsistent(m.epoch, external.epoch, c.clock().Sub(m.Obtained)), nil
}

// epochConsistent applies RFC 6887 §8.5 (which refines RFC 6886 §3.6): the
// gateway lost its state if its epoch went backwards by more than a second,
// or if the gateway's and the client's elapsed times differ by more than
// 1/16 plus two seconds in either direction.
func epochConsistent(previous, current uint32, elapsed time.Duration) bool {
	server := int64(current) - int64(previous)
	client := int64(elapsed / time.Second)
	if server < -1 {
		return false
	}

	return client+2 >= server-server/16 && server+2 >= client-client/16
}
