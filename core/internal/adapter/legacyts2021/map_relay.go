package legacyts2021

import (
	"tailscale.com/tailcfg"

	"github.com/meshtransit/meshtransit/core/internal/domain/relay"
)

func mapRelayDirectory(directory relay.Directory) (*tailcfg.DERPMap, error) {
	if !directory.IsValid() {
		return nil, ErrMapResponse
	}
	regions := directory.Regions()
	result := &tailcfg.DERPMap{
		Regions:            make(map[int]*tailcfg.DERPRegion, len(regions)),
		OmitDefaultRegions: true,
	}
	for _, region := range regions {
		nodes := region.Nodes()
		wireRegion := &tailcfg.DERPRegion{
			RegionID:   region.ID(),
			RegionCode: region.Code(),
			RegionName: region.Name(),
			Nodes:      make([]*tailcfg.DERPNode, 0, len(nodes)),
		}
		for _, node := range nodes {
			wireRegion.Nodes = append(wireRegion.Nodes, &tailcfg.DERPNode{
				Name:     node.Name(),
				RegionID: region.ID(),
				HostName: node.HostName(),
				CertName: node.CertName(),
				IPv4:     node.IPv4(),
				IPv6:     node.IPv6(),
				STUNPort: node.STUNPort(),
				STUNOnly: node.IsSTUNOnly(),
				DERPPort: node.RelayPort(),
			})
		}
		result.Regions[region.ID()] = wireRegion
	}
	return result, nil
}
