package underlay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"meshtransit.net/client/internal/winadapter"
)

// FollowsRoutes reports that the client's own sockets follow the host's
// routing table, subnet routes included: Windows has no per-user routing.
const FollowsRoutes = true

// unicastInterface is IP_UNICAST_IF and IPV6_UNICAST_IF, the same value at
// both levels (ws2ipdef.h).
const unicastInterface = 31

// bindPhysical sends the socket's packets out of the interface of the most
// specific route to destination off the MeshTransit adapter
// (IP_UNICAST_IF), so they take the path the host would use without its
// subnet routes.
func bindPhysical(raw syscall.RawConn, destination netip.Addr) error {
	cached, err := physicalInterfaces.lookup(destination, func(address netip.Addr) (int, error) {
		index, err := physicalInterface(address)
		if err == nil && index == 0 {
			err = errors.New("no physical route")
		}
		return int(index), err
	})
	if err != nil {
		return err
	}
	if cached <= 0 || cached > math.MaxUint32 {
		return errors.New("no physical route")
	}
	index := uint32(cached)
	var bindErr error
	if err := raw.Control(func(fd uintptr) {
		handle := windows.Handle(fd)
		if destination.Is6() {
			bindErr = windows.SetsockoptInt(handle, windows.IPPROTO_IPV6, unicastInterface, int(index))
			return
		}
		// IPv4 takes the index in network byte order. A dual-stack socket
		// sends IPv4 by its IPv6 option too; an IPv4 socket refuses that one.
		var order [4]byte
		binary.BigEndian.PutUint32(order[:], index)
		bindErr = windows.SetsockoptInt(handle, windows.IPPROTO_IP, unicastInterface,
			int(binary.NativeEndian.Uint32(order[:])))
		_ = windows.SetsockoptInt(handle, windows.IPPROTO_IPV6, unicastInterface, int(index))
	}); err != nil {
		return fmt.Errorf("reaching the socket: %w", err)
	}
	if bindErr != nil {
		return fmt.Errorf("binding to interface %d: %w", index, bindErr)
	}
	return nil
}

// physicalInterface returns the interface index of the route Windows would
// pick for destination off the MeshTransit adapter: the most specific route
// on a connected interface, the lowest route plus interface metric breaking a
// tie.
func physicalInterface(destination netip.Addr) (uint32, error) {
	family := winipcfg.AddressFamily(windows.AF_INET)
	if destination.Is6() {
		family = windows.AF_INET6
	}
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return 0, fmt.Errorf("reading routes: %w", err)
	}
	mesh, _ := winadapter.LUID()
	interfaceMetrics := map[winipcfg.LUID]uint32{}
	// metric returns the route's full metric, or false for an interface
	// that is down.
	metric := func(row *winipcfg.MibIPforwardRow2) (uint32, bool) {
		value, known := interfaceMetrics[row.InterfaceLUID]
		if !known {
			ipInterface, err := row.InterfaceLUID.IPInterface(family)
			if err != nil || !ipInterface.Connected {
				return 0, false
			}
			value = ipInterface.Metric
			interfaceMetrics[row.InterfaceLUID] = value
		}
		return row.Metric + value, true
	}
	var best *winipcfg.MibIPforwardRow2
	bestBits, bestMetric := -1, uint32(0)
	for i := range rows {
		row := &rows[i]
		prefix := row.DestinationPrefix.Prefix()
		if uint64(row.InterfaceLUID) == mesh || row.InterfaceIndex == 0 || !prefix.Contains(destination) ||
			prefix.Bits() < bestBits {
			continue
		}
		total, up := metric(row)
		if !up || prefix.Bits() == bestBits && total >= bestMetric {
			continue
		}
		best, bestBits, bestMetric = row, prefix.Bits(), total
	}
	if best == nil {
		return 0, errors.New("no physical route")
	}
	return best.InterfaceIndex, nil
}

// PhysicalIndex returns the interface of the host's route to destination
// off the MeshTransit adapter, 0 for none.
func PhysicalIndex(destination netip.Addr) uint32 {
	index, err := physicalInterface(destination)
	if err != nil {
		return 0
	}
	return index
}

// DirectBlocked is false: Windows sends a bound socket's datagrams with its
// interface's address (strong host model).
func DirectBlocked() bool { return false }

// ReconnectOnExitChange is false: a bound socket sends with its interface's
// address whatever the routes (strong host model).
const ReconnectOnExitChange = false
