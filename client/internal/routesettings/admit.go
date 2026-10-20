package routesettings

import (
	"net/netip"
	"slices"
)

// MaximumRoutes bounds the routed prefixes a node installs; beyond it the
// node installs none (mtcp-v1 §14).
const MaximumRoutes = 4096

// Reasons a route is refused.
const (
	ReasonRoutesOff = "routes_off"
	ReasonMalformed = "not_canonical"
	ReasonTooWide   = "too_wide"
	ReasonReserved  = "reserved_range"
	ReasonPublic    = "public_range"
	ReasonTooMany   = "too_many_routes"
	// ReasonLocalConflict refuses a route that would take over a network
	// the host is attached to or reaches by another path (rule 4).
	ReasonLocalConflict = "local_conflict"
	// ReasonInstallFailed refuses a route the kernel would not take;
	// ReasonFamilyUnavailable one of an address family the host lacks.
	ReasonInstallFailed     = "install_failed"
	ReasonFamilyUnavailable = "family_unavailable"
	minimumIPv4Bits         = 8
	minimumIPv6Bits         = 32
)

// Refusal is one granted route the node does not install, and why.
type Refusal struct {
	Prefix netip.Prefix
	Reason string
}

// meshReserved are the overlay frame's IPv4 ranges and fd00::/48, which
// holds the mesh's self-test address. The rest of the IPv6 frame (fd00::/8)
// is unique local space a Site may use: MeshOverlaps keeps routes off the
// /48s the mesh uses on this node.
var meshReserved = [...]netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("fd00::/48"),
}

// meshBlockBits is the size of the unique local blocks the mesh hands out
// (a Workspace's overlay, a deployment's alias pool): a route may not touch
// the block of any mesh address or overlay route.
const meshBlockBits = 48

// WithoutMesh refuses each route that overlaps the unique local block (/48)
// of a mesh address or overlay route the node holds, or the IPv4 overlay
// route itself: a Site must never take over the mesh's own addresses.
func WithoutMesh(routes, mesh []netip.Prefix) ([]netip.Prefix, []Refusal) {
	blocks := make([]netip.Prefix, 0, len(mesh))
	for _, prefix := range mesh {
		if prefix.Addr().Is6() && prefix.Bits() > meshBlockBits {
			prefix = netip.PrefixFrom(prefix.Addr(), meshBlockBits).Masked()
		}
		blocks = append(blocks, prefix.Masked())
	}
	kept := make([]netip.Prefix, 0, len(routes))
	var refused []Refusal
	for _, route := range routes {
		if slices.ContainsFunc(blocks, route.Overlaps) {
			refused = append(refused, Refusal{Prefix: route, Reason: ReasonReserved})
			continue
		}
		kept = append(kept, route)
	}
	return kept, refused
}

// never lists ranges a route may never touch: loopback, link-local,
// multicast and unspecified addresses (the mesh's own ranges are checked
// apart).
var never = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// private lists the ranges routes may use without accept_public_routes;
// every other range, reserved ones included, is public.
var private = [...]netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// Usable reports why a prefix can never be a subnet route, or "" when it
// can: not canonical (host bits, IPv4-mapped, a zone), a default route or
// shorter than IPv4 /8 or IPv6 /32, or overlapping the IPv4 overlay frame or
// fd00::/48,
// loopback, link-local, multicast or unspecified addresses.
func Usable(prefix netip.Prefix) string {
	if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
		return ReasonMalformed
	}
	minimum := minimumIPv6Bits
	if prefix.Addr().Is4() {
		minimum = minimumIPv4Bits
	}
	if prefix.Bits() < minimum {
		return ReasonTooWide
	}
	for _, reserved := range meshReserved {
		if prefix.Overlaps(reserved) {
			return ReasonReserved
		}
	}
	for _, reserved := range never {
		if prefix.Overlaps(reserved) {
			return ReasonReserved
		}
	}
	return ""
}

// Private reports whether a usable prefix lies inside a private range.
func Private(prefix netip.Prefix) bool {
	return slices.ContainsFunc(private[:], func(outer netip.Prefix) bool {
		return outer.Bits() <= prefix.Bits() && outer.Contains(prefix.Addr())
	})
}

// Admit applies the host's settings to the routes Core grants (mtcp-v1
// §7.6): routes only when accept_routes is on, never one Usable refuses,
// public ranges only with accept_public_routes, and none at all beyond
// MaximumRoutes. It returns the routes to install, canonical, sorted and
// without duplicates, and those refused.
func Admit(settings Settings, granted []netip.Prefix) ([]netip.Prefix, []Refusal) {
	accepted := make([]netip.Prefix, 0, len(granted))
	var refused []Refusal
	for _, prefix := range granted {
		reason := Usable(prefix)
		switch {
		case reason != "":
		case !settings.AcceptRoutes:
			reason = ReasonRoutesOff
		case !Private(prefix) && !settings.AcceptPublicRoutes:
			reason = ReasonPublic
		}
		if reason != "" {
			refused = append(refused, Refusal{Prefix: prefix, Reason: reason})
			continue
		}
		accepted = append(accepted, prefix)
	}
	slices.SortFunc(accepted, comparePrefixes)
	accepted = slices.Compact(accepted)
	if len(accepted) > MaximumRoutes {
		for _, prefix := range accepted {
			refused = append(refused, Refusal{Prefix: prefix, Reason: ReasonTooMany})
		}
		return []netip.Prefix{}, refused
	}
	return accepted, refused
}
