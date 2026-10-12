//go:build windows

package portmap

import (
	"fmt"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"meshtransit.net/client/internal/winadapter"
)

// DefaultGateway returns the IPv4 default gateway Windows sends through and
// the source address towards it. Routes on the MeshTransit adapter are
// skipped; Windows removes the routes of interfaces that go down.
func DefaultGateway() (Gateway, error) {
	table, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return Gateway{}, fmt.Errorf("portmap: reading the routing table: %w", err)
	}
	own, _ := winadapter.LUID()
	interfaceMetrics := make(map[winipcfg.LUID]uint32)
	candidates := make([]gatewayCandidate, 0, 2)
	for i := range table {
		row := &table[i]
		if row.DestinationPrefix.PrefixLength != 0 || uint64(row.InterfaceLUID) == own {
			continue
		}
		interfaceMetric, cached := interfaceMetrics[row.InterfaceLUID]
		if !cached {
			ipInterface, err := row.InterfaceLUID.IPInterface(windows.AF_INET)
			if err != nil {
				// The interface went away after the table was read.
				continue
			}
			interfaceMetric = ipInterface.Metric
			interfaceMetrics[row.InterfaceLUID] = interfaceMetric
		}
		candidates = append(candidates, gatewayCandidate{
			nextHop: row.NextHop.Addr(),
			index:   int(row.InterfaceIndex),
			metric:  uint64(row.Metric) + uint64(interfaceMetric),
		})
	}
	gateway, ok := preferredGateway(candidates)
	if !ok {
		return Gateway{}, ErrNoGateway
	}
	local, err := sourceAddressTowards(gateway)
	if err != nil {
		return Gateway{}, err
	}
	result := Gateway{Addr: gateway, Local: local}
	if !result.Valid() {
		return Gateway{}, ErrNoGateway
	}

	return result, nil
}
