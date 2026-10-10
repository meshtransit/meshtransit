package mtcp

import (
	"net/netip"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/shared/policydigest"
)

// Packet filter bounds (mtcp-v1 §7.3).
const (
	MaxFilterRules       = 10000
	MaxFilterRuleSources = 1024
)

// ParsePrefix reads a protobuf Prefix: 4 or 16 raw address bytes and a
// prefix length within the address. The result is masked.
func ParsePrefix(prefix *mtcpv1.Prefix) (netip.Prefix, error) {
	address, ok := netip.AddrFromSlice(prefix.GetIp())
	if !ok || (len(prefix.GetIp()) != 4 && len(prefix.GetIp()) != 16) || int(prefix.GetBits()) > address.BitLen() {
		return netip.Prefix{}, ErrMalformed
	}
	return netip.PrefixFrom(address.Unmap(), int(prefix.GetBits())).Masked(), nil
}

// AppendPrefix encodes a prefix; IPv4 is always 4 bytes.
func AppendPrefix(prefix netip.Prefix) *mtcpv1.Prefix {
	address := prefix.Addr().Unmap()
	return &mtcpv1.Prefix{Ip: address.AsSlice(), Bits: uint32(prefix.Bits())} //nolint:gosec // 0..128
}

// PolicyRules converts a packet filter to the policy digest model (an empty
// port list means every port). Both Core and nodes digest a filter this
// way, so enforcement evidence compares across protocols.
func PolicyRules(filter *mtcpv1.PacketFilter) ([]policydigest.Rule, error) {
	if len(filter.GetRules()) > MaxFilterRules {
		return nil, ErrTooLarge
	}
	rules := make([]policydigest.Rule, 0, len(filter.GetRules()))
	for _, rule := range filter.GetRules() {
		if len(rule.GetSources()) > MaxFilterRuleSources {
			return nil, ErrTooLarge
		}
		converted := policydigest.Rule{}
		for _, source := range rule.GetSources() {
			prefix, err := ParsePrefix(source)
			if err != nil {
				return nil, err
			}
			converted.Sources = append(converted.Sources, policydigest.Selector{Kind: policydigest.KindPrefix, Prefix: prefix})
		}
		for _, destination := range rule.GetDestinations() {
			prefix, err := ParsePrefix(destination.GetPrefix())
			if err != nil {
				return nil, err
			}
			selector := policydigest.Selector{Kind: policydigest.KindPrefix, Prefix: prefix}
			if len(destination.GetPorts()) == 0 {
				converted.Destinations = append(converted.Destinations,
					policydigest.Destination{Selector: selector, PortFrom: 0, PortTo: 65535})
				continue
			}
			for _, ports := range destination.GetPorts() {
				if ports.GetFirst() > ports.GetLast() || ports.GetLast() > 65535 {
					return nil, ErrMalformed
				}
				converted.Destinations = append(converted.Destinations, policydigest.Destination{
					Selector: selector, PortFrom: uint16(ports.GetFirst()), PortTo: uint16(ports.GetLast()), //nolint:gosec // checked
				})
			}
		}
		for _, protocol := range rule.GetProtocols() {
			if protocol > 255 {
				return nil, ErrMalformed
			}
			converted.Protocols = append(converted.Protocols, uint8(protocol))
		}
		rules = append(rules, converted)
	}
	return rules, nil
}

// FilterDigest returns the policy digest v1 of a packet filter.
func FilterDigest(filter *mtcpv1.PacketFilter) (policydigest.Digest, int, error) {
	rules, err := PolicyRules(filter)
	if err != nil {
		return policydigest.Digest{}, 0, err
	}
	return policydigest.Compute(rules)
}
