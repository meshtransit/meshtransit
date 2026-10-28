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
	// Exits are the Exit Pools the node may use (mtcp-v1 §7.7), sorted by
	// reference; nil when the node does not take them.
	Exits []ExitPool
	// ExitRoute is the exit node this node sends its Internet traffic to:
	// a local choice among Exits (exit node design §9), never part of
	// Core's map; nil when it uses none.
	ExitRoute *ExitRoute
	// DroppedAliasPeers counts the shared Devices the client left out of
	// this map because their alias could not be used (expired, invalid or
	// colliding); for the log, never for authority.
	DroppedAliasPeers int
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
	// Kubernetes is the peer's access in a Kubernetes gateway's cluster;
	// only a gateway's map has it, never on self or an alias peer.
	Kubernetes *KubernetesAccess
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
	// InfrastructureNames are host names of the deployment's own services
	// a root zone leaves to the host's network (TD-CLI-70).
	InfrastructureNames []string
}

// Empty reports a DNS view with nothing in it, as for a Device of an
// unmanaged Device Group (DNS design D5b): nothing to configure.
func (config *DNSConfig) Empty() bool {
	return config == nil || len(config.Resolvers) == 0 && len(config.FallbackResolvers) == 0 &&
		len(config.Routes) == 0 && len(config.SearchDomains) == 0 && len(config.Records) == 0
}

// DNSResolver is a classic UDP/TCP DNS endpoint: an IP address on port 53,
// or, for a route's resolver (a resolver Device of a forward zone), on port
// 53 or 1024-65535. URL-based resolvers stay outside the trusted network-map
// model until their transport is implemented.
type DNSResolver struct {
	Address netip.AddrPort
}

// DNSRoute sends one canonical DNS suffix to an ordered resolver set. An empty
// resolver set means the suffix is answered by the local MeshTransit resolver,
// unless Unavailable: then it is a forward zone none of whose resolvers can
// be used now (mtcp-v1 §7.3), and its names follow FailOpen. FailOpen asks
// the host's own resolvers (the exit node's forwarder while one is in use)
// when no resolver can answer; otherwise such names are answered SERVFAIL.
type DNSRoute struct {
	Suffix      string
	Resolvers   []DNSResolver
	Unavailable bool
	FailOpen    bool
}

// DNSRecordType is one supported local DNS record type.
type DNSRecordType string

const (
	DNSRecordA    DNSRecordType = "A"
	DNSRecordAAAA DNSRecordType = "AAAA"
	// DNSRecordCNAME points a name at another (MTCP dns.records1).
	DNSRecordCNAME DNSRecordType = "CNAME"
)

// DNSRecord is one validated local record: an address (A, AAAA) or, for a
// CNAME, the Target name. Names are lowercase, absolute-by-convention, and
// stored without a trailing dot.
type DNSRecord struct {
	Name    string
	Type    DNSRecordType
	Address netip.Addr
	Target  string
}
