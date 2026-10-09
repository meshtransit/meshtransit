package ts2021

import (
	"bytes"
	"errors"
	"time"

	"tailscale.com/tailcfg"

	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/shared/mtrp"
)

// interchangeCapability carries the node's relay grant on its own map entry
// until MTCP replaces this adapter (MTRP v1 §9.1).
const interchangeCapability = tailcfg.NodeCapability(mtrp.InterchangeCapability)

var errInterchangeGrant = errors.New("control compatibility: invalid relay grant")

// interchangeGrant is a verified relay grant held across map responses.
type interchangeGrant struct {
	ticket   []byte
	notAfter time.Time
	disco    [32]byte
	relayMap mtrp.RelayMap
}

// parseInterchange reads the grant on the node's own entry. present reports
// whether the entry carried one at all; err reports one that failed
// verification (the caller keeps its previous grant).
func parseInterchange(node *tailcfg.Node, now time.Time) (grant *interchangeGrant, present bool, err error) {
	values := node.CapMap[interchangeCapability]
	if len(values) == 0 {
		return nil, false, nil
	}
	if len(values) != 1 {
		return nil, true, errInterchangeGrant
	}
	decoded, err := mtrp.ParseInterchangeGrant([]byte(values[0]))
	if err != nil {
		return nil, true, errors.Join(errInterchangeGrant, err)
	}
	relayMap, err := decoded.OpenRelayMap(now)
	if err != nil {
		return nil, true, errors.Join(errInterchangeGrant, err)
	}
	ticket, err := mtrp.ParseTicketUnverified(decoded.Ticket)
	if err != nil || !decoded.TicketNotAfter.Equal(ticket.NotAfter()) {
		return nil, true, errors.Join(errInterchangeGrant, err)
	}
	return &interchangeGrant{
		ticket:   bytes.Clone(decoded.Ticket),
		notAfter: ticket.NotAfter(),
		disco:    ticket.Disco,
		relayMap: relayMap,
	}, true, nil
}

// supersedes reports whether a newly received grant replaces held: never
// with an older relay map, and with the same map version only when it is at
// least as fresh (Core re-signs an unchanged map with a later expiry).
func (grant *interchangeGrant) supersedes(held *interchangeGrant) bool {
	if held == nil {
		return true
	}
	if grant.relayMap.Version != held.relayMap.Version {
		return grant.relayMap.Version > held.relayMap.Version
	}
	return !grant.relayMap.ExpiresAt.Before(held.relayMap.ExpiresAt)
}

func (grant *interchangeGrant) equal(other *interchangeGrant) bool {
	if grant == nil || other == nil {
		return grant == other
	}
	return bytes.Equal(grant.ticket, other.ticket) && grant.relayMap.Version == other.relayMap.Version &&
		grant.relayMap.ExpiresAt.Equal(other.relayMap.ExpiresAt)
}

// snapshot returns the product view of the grant and the relay regions of
// its map, which replace any legacy relay directory.
func (grant *interchangeGrant) snapshot() (*networkmap.Interchange, map[int]networkmap.RelayRegion) {
	regions := make(map[int]networkmap.RelayRegion, len(grant.relayMap.Regions))
	for _, r := range grant.relayMap.Regions {
		region := networkmap.RelayRegion{ID: int(r.ID), Code: r.Code, Name: r.Name}
		for _, n := range r.Nodes {
			node := networkmap.RelayNode{
				Name: n.Name, HostName: n.HostName,
				STUNPort: int(n.STUNPort), RelayPort: int(n.TLSPort),
				RelayKey: n.Key, UDPPort: int(n.UDPPort),
			}
			if n.IPv4.IsValid() {
				node.IPv4 = n.IPv4.String()
			}
			if n.IPv6.IsValid() {
				node.IPv6 = n.IPv6.String()
			}
			region.Nodes = append(region.Nodes, node)
		}
		regions[region.ID] = region
	}
	return &networkmap.Interchange{
		Ticket:         bytes.Clone(grant.ticket),
		TicketNotAfter: grant.notAfter,
		TicketDisco:    grant.disco,
		MapVersion:     grant.relayMap.Version,
		MapExpiresAt:   grant.relayMap.ExpiresAt,
	}, regions
}
