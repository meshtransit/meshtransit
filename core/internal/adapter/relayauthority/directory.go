package relayauthority

import (
	"errors"
	"net/netip"

	"meshtransit.net/core/internal/domain/relay"
	"meshtransit.net/shared/mtrp"
)

// Directory derives the control plane's relay directory from the relay map,
// so the regions nodes report and the regions they are given are the same
// (one source of relay topology, MTRP v1 §9.1).
func Directory(m mtrp.RelayMap) (relay.Directory, error) {
	regions := make([]relay.Region, 0, len(m.Regions))
	for _, r := range m.Regions {
		nodes := make([]relay.Node, 0, len(r.Nodes))
		for _, n := range r.Nodes {
			node, err := relay.NewNode(relay.NodeParams{
				Name:      n.Name,
				HostName:  n.HostName,
				IPv4:      addressText(n.IPv4),
				IPv6:      addressText(n.IPv6),
				STUNPort:  int(n.STUNPort),
				RelayPort: int(n.TLSPort),
			})
			if err != nil {
				return relay.Directory{}, errors.Join(ErrInvalidMap, err)
			}
			nodes = append(nodes, node)
		}
		region, err := relay.NewRegion(relay.RegionParams{ID: int(r.ID), Code: r.Code, Name: r.Name, Nodes: nodes})
		if err != nil {
			return relay.Directory{}, errors.Join(ErrInvalidMap, err)
		}
		regions = append(regions, region)
	}
	// The directory revision orders snapshots; map version 0 is still the
	// first published topology.
	directory, err := relay.NewDirectory(relay.DirectoryParams{Revision: max(m.Version, 1), Regions: regions})
	if err != nil {
		return relay.Directory{}, errors.Join(ErrInvalidMap, err)
	}
	return directory, nil
}

func addressText(a netip.Addr) string {
	if !a.IsValid() {
		return "none" // the node has no address in this family
	}
	return a.String()
}
