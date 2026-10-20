//go:build darwin

package netadmin

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"meshtransit.net/client/internal/hostroute"
	"meshtransit.net/client/internal/routesettings"
)

// maximumLocalRoutes bounds the host routes the checks compare against. A
// host with more is no consumer the checks can keep safe cheaply: it
// installs no routes.
const maximumLocalRoutes = 16384

var errTooManyLocalRoutes = errors.New("too many local routes to check subnet routes against")

// validPlatformRoutedOptions requires the table settings be unset: macOS has
// one routing table and no policy rules, and a Mac does not forward.
func validPlatformRoutedOptions(options RoutedOptions) bool {
	return options.Table == 0 && options.Priority == 0 && options.NftTable == "" && options.StatePath == "" &&
		options.ExitTable == 0 && options.ExitPriority == 0 && options.ExitNftTable == ""
}

type kernelRoutedConfigurer struct{}

// ReplaceRouted installs desired on the utun link in the host's routing
// table and returns what is installed. macOS has no policy routing: meshd
// keeps its own sockets off these routes itself (underlay). It compares
// desired with the kernel's table, not with current, so a route removed
// behind the helper's back is installed again. Resolver pins are host routes
// through the gateway the resolver uses now, installed before the routes
// that contain them and removed after them. A route the kernel refuses is
// reported, not fatal. With nothing desired it clears every marked route.
func (configurer kernelRoutedConfigurer) ReplaceRouted(name string, options RoutedOptions, uid uint32,
	_, desired routedState,
) (routedState, []routesettings.Refusal, error) {
	if len(desired.Routes) == 0 {
		return routedState{}, nil, configurer.Clear(options, uid)
	}
	if !validInterfaceName(name) || name[:4] != "utun" {
		return routedState{}, nil, errors.New("routed route target is invalid")
	}
	link, err := net.InterfaceByName(name)
	if err != nil {
		return routedState{}, nil, fmt.Errorf("finding utun link for routed routes: %w", err)
	}
	table, err := hostroute.Read()
	if err != nil {
		return routedState{}, nil, err
	}
	installed, err := installedRouted(table, link.Index)
	if err != nil {
		return routedState{}, nil, err
	}
	throws, throwRefusals := addPins(table, link.Index, installed.Throws, desired.Throws)
	wanted, refused := withoutUnpinned(desired.Routes, throwRefusals)
	linkGateway := &route.LinkAddr{Index: link.Index}
	for _, prefix := range prefixDifference(installed.Routes, wanted) {
		if err := writeRoute(routedMessage(unix.RTM_DELETE, prefix, linkGateway, 0)); err != nil &&
			!errors.Is(err, unix.ESRCH) {
			return routedState{}, nil, fmt.Errorf("removing routed route: %w", err)
		}
	}
	routes := prefixIntersection(wanted, installed.Routes)
	for _, prefix := range prefixDifference(wanted, installed.Routes) {
		if err := writeRoute(routedMessage(unix.RTM_ADD, prefix, linkGateway, 0)); err != nil {
			refused = append(refused, routesettings.Refusal{Prefix: prefix, Reason: installRefusalReason(err)})
			continue
		}
		routes = append(routes, prefix)
	}
	slices.SortFunc(routes, compareRoutedPrefixes)
	for _, prefix := range prefixDifference(installed.Throws, desired.Throws) {
		if err := writeRoute(routedMessage(unix.RTM_DELETE, prefix, nil, unix.RTF_GATEWAY)); err != nil &&
			!errors.Is(err, unix.ESRCH) {
			return routedState{}, nil, fmt.Errorf("removing resolver pin: %w", err)
		}
	}
	return routedState{Routes: routes, Throws: throws}, refused, nil
}

// installRefusalReason names why the kernel refused a route.
func installRefusalReason(err error) string {
	if errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EADDRNOTAVAIL) {
		return routesettings.ReasonFamilyUnavailable
	}
	return routesettings.ReasonInstallFailed
}

// installedRouted sorts the helper's routes: those on the utun link are
// routed routes, its host routes through a gateway are resolver pins. A pin
// whose gateway is no longer the one the host uses (another Wi-Fi, a new
// DHCP lease), and a route on another link, left by an earlier utun, are
// removed.
func installedRouted(table []hostroute.Route, linkIndex int) (routedState, error) {
	var state routedState
	for _, entry := range table {
		if !entry.Owned() {
			continue
		}
		switch {
		case entry.Index == linkIndex && entry.Flags&unix.RTF_GATEWAY == 0:
			state.Routes = append(state.Routes, entry.Prefix)
		case entry.Flags&unix.RTF_GATEWAY != 0 && entry.Prefix.IsSingleIP() && pinCurrent(table, linkIndex, entry):
			state.Throws = append(state.Throws, entry.Prefix)
		default:
			if err := deleteRoute(entry); err != nil {
				return routedState{}, fmt.Errorf("removing stray routed route: %w", err)
			}
		}
	}
	slices.SortFunc(state.Routes, compareRoutedPrefixes)
	slices.SortFunc(state.Throws, compareRoutedPrefixes)
	return state, nil
}

// pinCurrent reports whether a pin still goes through the gateway the host
// uses for its resolver.
func pinCurrent(table []hostroute.Route, linkIndex int, pin hostroute.Route) bool {
	path, found := hostroute.Physical(table, []int{linkIndex}, pin.Prefix.Addr())
	return found && path.Flags&unix.RTF_GATEWAY != 0 && hostroute.SameGateway(path.Gateway, pin.Gateway)
}

// addPins installs a host route for each desired resolver not yet pinned,
// through the gateway the host uses for it now, and returns the desired pins
// now installed. A resolver with no gateway to pin it to is refused, and so
// then are the routes that contain it.
func addPins(table []hostroute.Route, meshIndex int, installed, desired []netip.Prefix) (
	[]netip.Prefix, []routesettings.Refusal,
) {
	kept := prefixIntersection(desired, installed)
	var refused []routesettings.Refusal
	for _, pin := range prefixDifference(desired, installed) {
		path, found := hostroute.Physical(table, []int{meshIndex}, pin.Addr())
		if !found || path.Flags&unix.RTF_GATEWAY == 0 {
			// A resolver on an attached network needs no pin, as a route
			// containing it is refused as a local conflict; one without a
			// path cannot be kept off the mesh.
			refused = append(refused, routesettings.Refusal{Prefix: pin, Reason: routesettings.ReasonLocalConflict})
			continue
		}
		if err := writeRoute(routedMessage(unix.RTM_ADD, pin, path.Gateway, unix.RTF_GATEWAY)); err != nil {
			refused = append(refused, routesettings.Refusal{Prefix: pin, Reason: installRefusalReason(err)})
			continue
		}
		kept = append(kept, pin)
	}
	slices.SortFunc(kept, compareRoutedPrefixes)
	return kept, refused
}

// Clear removes every route the helper installed, whatever a previous run
// left: the mark on a static route belongs to this helper alone.
func (kernelRoutedConfigurer) Clear(RoutedOptions, uint32) error {
	table, err := hostroute.Read()
	if err != nil {
		return err
	}
	var failures []error
	// Routes go before pins: until they are gone the pins keep resolvers
	// off the mesh.
	for _, pins := range []bool{false, true} {
		for _, entry := range table {
			if !entry.Owned() || (entry.Flags&unix.RTF_GATEWAY != 0) != pins {
				continue
			}
			if err := deleteRoute(entry); err != nil {
				failures = append(failures, fmt.Errorf("removing routed route %s: %w", entry.Prefix, err))
			}
		}
	}
	return errors.Join(failures...)
}

func deleteRoute(entry hostroute.Route) error {
	err := writeRoute(routedMessage(unix.RTM_DELETE, entry.Prefix, entry.Gateway, entry.Flags&unix.RTF_GATEWAY))
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}

// routedMessage builds the RTM_ADD or RTM_DELETE message of one marked
// route: through a link (route add -interface) or, with RTF_GATEWAY, through
// a gateway, which a delete may leave nil.
func routedMessage(messageType int, prefix netip.Prefix, gateway route.Addr, gatewayFlag int) *route.RouteMessage {
	flags := unix.RTF_UP | unix.RTF_STATIC | hostroute.Mark | gatewayFlag
	addresses := []route.Addr{unix.RTAX_DST: routeAddr(prefix.Addr()), unix.RTAX_GATEWAY: gateway}
	if prefix.IsSingleIP() {
		flags |= unix.RTF_HOST
	} else {
		mask := net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())
		maskAddress, _ := netip.AddrFromSlice(mask)
		addresses = append(addresses, routeAddr(maskAddress)) // RTAX_NETMASK
	}
	return &route.RouteMessage{
		Version: unix.RTM_VERSION, Type: messageType, Flags: flags, ID: uintptr(os.Getpid()), Seq: 1,
		Addrs: addresses,
	}
}

// writeRoute sends one message over a routing socket.
func writeRoute(message *route.RouteMessage) error {
	encoded, err := message.Marshal()
	if err != nil {
		return fmt.Errorf("encoding route: %w", err)
	}
	socket, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("opening routing socket: %w", err)
	}
	defer func() { _ = unix.Close(socket) }()
	if _, err := unix.Write(socket, encoded); err != nil {
		return fmt.Errorf("writing route: %w", err)
	}
	return nil
}

type kernelHostRouting struct{}

// LocalRoutes returns the routing table's routes but default routes, those
// on the mesh link, the helper's own and those the kernel cloned; a route
// through no gateway is an attached network.
func (kernelHostRouting) LocalRoutes(meshInterface string) ([]LocalRoute, error) {
	meshIndex := -1
	if link, err := net.InterfaceByName(meshInterface); err == nil {
		meshIndex = link.Index
	}
	table, err := hostroute.Read()
	if err != nil {
		return nil, err
	}
	return localRoutes(table, meshIndex)
}

func localRoutes(table []hostroute.Route, meshIndex int) ([]LocalRoute, error) {
	var local []LocalRoute
	for _, entry := range table {
		prefix := entry.Prefix
		if entry.Index == meshIndex || entry.Marked() || entry.Cloned() || prefix.Bits() == 0 ||
			prefix.Addr().IsLinkLocalUnicast() || prefix.Addr().IsMulticast() {
			continue
		}
		if len(local) == maximumLocalRoutes {
			return nil, errTooManyLocalRoutes
		}
		local = append(local, LocalRoute{Prefix: prefix, Connected: entry.Flags&unix.RTF_GATEWAY == 0})
	}
	return local, nil
}

// resolverFiles hold the system resolvers configd writes for the primary
// network service.
var resolverFiles = []string{"/etc/resolv.conf"}

// Resolvers returns the nameservers of the system resolver file.
func (kernelHostRouting) Resolvers() []netip.Addr { return readResolvers(resolverFiles) }
