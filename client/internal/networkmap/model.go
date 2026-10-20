// Package networkmap owns the validated, upstream-independent network view.
package networkmap

import (
	"net/netip"
	"time"
)

// Snapshot is an immutable-by-convention network view published atomically.
type Snapshot struct {
	Revision    uint64
	NetworkName string
	ControlTime time.Time
	Self        Node
	Peers       []Node
	Policy      []Rule
	Relays      map[int]RelayRegion
	DNS         *DNSConfig
	Audit       AuditCredentials
	// Interchange is the node's relay grant; when present, Relays come from
	// its signed relay map (MTRP v1 §9.1).
	Interchange *Interchange
	// Routes are the Sites the node may reach (mtcp-v1 §7.6), sorted by
	// reference; nil when the node does not take subnet routes.
	Routes []SiteRoute
	// Served are the Sites the node forwards to as a router (mtcp-v1 §7.6),
	// sorted by reference; nil when the node is not a router.
	Served []ServedSite
	// ServedExits is the Exit Pool the node forwards to the Internet for as
	// an exit node (mtcp-v1 §7.7), at most one; nil when it cannot be one.
	ServedExits []ServedExit
}

// Interchange is a verified relay grant: the ticket this node presents to
// Interchange relays, and the relay map version its regions came from.
type Interchange struct {
	Ticket         []byte
	TicketNotAfter time.Time
	// TicketZones is, for an MTT2 ticket, every zone it commits to
	// (mtrp.EncodeZones); the node hands relays those past the inline ones.
	TicketZones []byte
	// FallbackTicket is the MTT1 ticket for relays that do not take MTT2.
	FallbackTicket []byte
	TicketDisco    [32]byte // the disco key the ticket binds
	MapVersion     uint64
	MapExpiresAt   time.Time
}

// Node contains only the control-plane fields needed by the future data plane.
type Node struct {
	ID                uint64
	StableID          string
	Name              string
	PublicKey         string
	DiscoveryKey      string
	Addresses         []netip.Prefix
	AllowedIPs        []netip.Prefix
	Endpoints         []netip.AddrPort
	HomeRelay         int
	OnlineKnown       bool
	Online            bool
	KeyExpiry         time.Time
	Expired           bool
	MachineAuthorized bool
	Alias             *AliasBinding
}

// SelectorKind identifies one bounded address selector representation.
type SelectorKind string

const (
	SelectorAny        SelectorKind = "any"
	SelectorPrefix     SelectorKind = "prefix"
	SelectorRange      SelectorKind = "range"
	SelectorCapability SelectorKind = "capability"
)

// Selector represents an address wildcard, prefix, inclusive range, or
// capability reference. Only sources may use capability selectors.
type Selector struct {
	Kind       SelectorKind
	Prefix     netip.Prefix
	RangeStart netip.Addr
	RangeEnd   netip.Addr
	Capability string
}

// Destination combines an address selector and inclusive port range.
type Destination struct {
	Selector Selector
	PortFrom uint16
	PortTo   uint16
}

// Rule is one allow rule. An empty Protocols slice means TCP, UDP, and ICMP,
// matching the control protocol; enforcement remains deny-by-default.
type Rule struct {
	Sources      []Selector
	Destinations []Destination
	Protocols    []uint8
}

// RelayRegion is the validated relay topology required by the data plane.
type RelayRegion struct {
	ID    int
	Code  string
	Name  string
	Nodes []RelayNode
	// Preferred marks a Private Interchange region: the home relay while it
	// is reachable (mtrp-v1 §8).
	Preferred bool
}

// RelayNode describes one relay endpoint without test-only transport knobs.
// RelayPort is the TLS port. Interchange nodes also carry their static
// relay key and UDP port.
type RelayNode struct {
	Name      string
	HostName  string
	CertName  string
	IPv4      string
	IPv6      string
	STUNPort  int
	RelayPort int
	STUNOnly  bool
	RelayKey  [32]byte
	UDPPort   int
}

// DNSConfig is the complete, product-owned DNS view for one map revision. A
// nil *DNSConfig means that the control plane did not configure DNS for this
// network. Resolver order is significant.
type DNSConfig struct {
	Resolvers         []DNSResolver
	FallbackResolvers []DNSResolver
	Routes            []DNSRoute
	SearchDomains     []string
	Records           []DNSRecord
}

// DNSResolver is a classic UDP/TCP DNS endpoint. The initial implementation
// deliberately accepts only IP addresses on port 53; URL-based resolvers stay
// outside the trusted network-map model until their transport is implemented.
type DNSResolver struct {
	Address netip.AddrPort
}

// DNSRoute sends one canonical DNS suffix to an ordered resolver set. An empty
// resolver set means the suffix is answered by the local MeshTransit resolver.
type DNSRoute struct {
	Suffix    string
	Resolvers []DNSResolver
}

// DNSRecordType is one supported local DNS record type.
type DNSRecordType string

const (
	DNSRecordA    DNSRecordType = "A"
	DNSRecordAAAA DNSRecordType = "AAAA"
)

// DNSRecord is one validated local address record. Names are lowercase,
// absolute-by-convention, and stored without a trailing dot.
type DNSRecord struct {
	Name    string
	Type    DNSRecordType
	Address netip.Addr
}
