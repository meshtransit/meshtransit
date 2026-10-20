package dnsconfig

import (
	"fmt"
	"net/netip"
	"slices"

	"golang.org/x/net/dns/dnsmessage"
)

// withoutPrivateAnswers removes from an upstream response every address
// record a consumer may not reach through the exit node (exit node design
// §7.2): A and AAAA records whose address private reports, and SVCB and
// HTTPS records with such an address hint. The exit network's resolver can
// then never tell a consumer the names and addresses inside it. What is
// left keeps its code: a name with no address left answers with no data.
func withoutPrivateAnswers(response []byte, private func(netip.Addr) bool) ([]byte, error) {
	var message dnsmessage.Message
	if err := message.Unpack(response); err != nil {
		return nil, fmt.Errorf("dnsconfig: reading the upstream response: %w", err)
	}
	filtered := false
	keep := func(resources []dnsmessage.Resource) []dnsmessage.Resource {
		return slices.DeleteFunc(resources, func(resource dnsmessage.Resource) bool {
			if privateResource(resource, private) {
				filtered = true
				return true
			}
			return false
		})
	}
	message.Answers = keep(message.Answers)
	message.Authorities = keep(message.Authorities)
	message.Additionals = keep(message.Additionals)
	if !filtered {
		return response, nil
	}
	packed, err := message.Pack()
	if err != nil {
		return nil, fmt.Errorf("dnsconfig: writing the filtered response: %w", err)
	}
	return packed, nil
}

// privateResource reports an address record, or an address hint of a
// service binding, that private reports.
func privateResource(resource dnsmessage.Resource, private func(netip.Addr) bool) bool {
	switch body := resource.Body.(type) {
	case *dnsmessage.AResource:
		return private(netip.AddrFrom4(body.A))
	case *dnsmessage.AAAAResource:
		return private(netip.AddrFrom16(body.AAAA).Unmap())
	case *dnsmessage.SVCBResource:
		return privateHints(body.Params, private)
	case *dnsmessage.HTTPSResource:
		return privateHints(body.Params, private)
	}
	return false
}

func privateHints(params []dnsmessage.SVCParam, private func(netip.Addr) bool) bool {
	for _, param := range params {
		size := 0
		switch param.Key {
		case dnsmessage.SVCParamIPv4Hint:
			size = 4
		case dnsmessage.SVCParamIPv6Hint:
			size = 16
		default:
			continue
		}
		if len(param.Value)%size != 0 {
			return true // malformed: dropped rather than trusted
		}
		for offset := 0; offset < len(param.Value); offset += size {
			address, _ := netip.AddrFromSlice(param.Value[offset : offset+size])
			if private(address.Unmap()) {
				return true
			}
		}
	}
	return false
}
