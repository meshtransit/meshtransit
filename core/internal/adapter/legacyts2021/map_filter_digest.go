package legacyts2021

import (
	"errors"
	"net/netip"

	"tailscale.com/tailcfg"

	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/shared/policydigest"
)

// ErrFilterDigest reports a packet filter the policy digest cannot cover.
var ErrFilterDigest = errors.New("legacyts2021: packet filter digest")

// PacketFilterDigest returns the policy digest v1 of the packet filter that a
// full map or authority delta for snapshot carries, as meshd will compute it
// over the rules it enforces.
func PacketFilterDigest(snapshot mapsession.Snapshot) (mapsession.FilterDigest, error) {
	if !snapshot.IsValid() {
		return mapsession.FilterDigest{}, ErrFilterDigest
	}
	authorized := snapshot.AuthorizedPeers()
	candidates := make(map[node.ID]mapsession.PeerCandidate, len(authorized))
	for _, candidate := range authorized {
		candidates[candidate.NodeID()] = candidate
	}
	filter, err := fullMapPacketFilter(snapshot, candidates)
	if err != nil {
		return mapsession.FilterDigest{}, errors.Join(ErrFilterDigest, err)
	}
	rules, err := digestRules(filter)
	if err != nil {
		return mapsession.FilterDigest{}, err
	}
	digest, grants, err := policydigest.Compute(rules)
	if err != nil {
		return mapsession.FilterDigest{}, errors.Join(ErrFilterDigest, err)
	}
	return mapsession.NewFilterDigest(digest, grants)
}

// digestRules reads back the filter this adapter writes: bare addresses for
// sources and destinations, as meshd parses them.
func digestRules(filter []tailcfg.FilterRule) ([]policydigest.Rule, error) {
	rules := make([]policydigest.Rule, 0, len(filter))
	for _, rule := range filter {
		converted := policydigest.Rule{
			Sources:      make([]policydigest.Selector, 0, len(rule.SrcIPs)),
			Destinations: make([]policydigest.Destination, 0, len(rule.DstPorts)),
			Protocols:    make([]uint8, 0, len(rule.IPProto)),
		}
		for _, source := range rule.SrcIPs {
			selector, err := digestSelector(source)
			if err != nil {
				return nil, err
			}
			converted.Sources = append(converted.Sources, selector)
		}
		for _, destination := range rule.DstPorts {
			selector, err := digestSelector(destination.IP)
			if err != nil || destination.Bits != nil {
				return nil, ErrFilterDigest
			}
			converted.Destinations = append(converted.Destinations, policydigest.Destination{
				Selector: selector, PortFrom: destination.Ports.First, PortTo: destination.Ports.Last,
			})
		}
		for _, protocol := range rule.IPProto {
			if protocol < 0 || protocol > 255 {
				return nil, ErrFilterDigest
			}
			converted.Protocols = append(converted.Protocols, uint8(protocol))
		}
		rules = append(rules, converted)
	}
	return rules, nil
}

func digestSelector(text string) (policydigest.Selector, error) {
	address, err := netip.ParseAddr(text)
	if err != nil {
		return policydigest.Selector{}, ErrFilterDigest
	}
	address = address.Unmap()
	return policydigest.Selector{
		Kind:   policydigest.KindPrefix,
		Prefix: netip.PrefixFrom(address, address.BitLen()),
	}, nil
}
