package dnszone

import (
	"net/netip"
	"slices"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/shared/internet"
)

// Technical ceilings no plan can exceed: they bound maps and the domains a
// host routes to its resolver (at most 256 on every platform, the mesh
// names and search domains included).
const (
	MaximumZonesPerNetwork       = 200
	MaximumResolversPerZone      = 4
	MaximumGroupsPerZone         = 16
	MaximumSearchZonesPerNetwork = 7
	// MaximumConsumersPerResolver is the most Devices one resolver Device
	// serves: it is a peer of each, and a map holds 10,000 peers.
	MaximumConsumersPerResolver = 10000
	// MaximumSearchPosition bounds the order of search domains.
	MaximumSearchPosition = 1000
)

// DNSPort is the port of a resolver on the Internet and the default of a
// resolver Device.
const DNSPort = 53

// minimumHighPort is the first port a resolver Device may use instead of 53
// (an unbound or Pi-hole on 5335, say).
const minimumHighPort = 1024

// Limits are the plan limits of one Workspace; until paid plans set them,
// every Workspace has the ceilings.
type Limits struct {
	ZonesPerNetwork       int
	SearchZonesPerNetwork int
	ConsumersPerResolver  int
}

// DefaultLimits returns the technical ceilings.
func DefaultLimits() Limits {
	return Limits{
		ZonesPerNetwork: MaximumZonesPerNetwork, SearchZonesPerNetwork: MaximumSearchZonesPerNetwork,
		ConsumersPerResolver: MaximumConsumersPerResolver,
	}
}

// Validate keeps every limit within its ceiling.
func (limits Limits) Validate() error {
	if limits.ZonesPerNetwork < 1 || limits.ZonesPerNetwork > MaximumZonesPerNetwork ||
		limits.SearchZonesPerNetwork < 0 || limits.SearchZonesPerNetwork > MaximumSearchZonesPerNetwork ||
		limits.ConsumersPerResolver < 1 || limits.ConsumersPerResolver > MaximumConsumersPerResolver {
		return ErrInvalid
	}
	return nil
}

// ID identifies a zone.
type ID publicid.ID

// ParseID parses a zone's public ID.
func ParseID(value string) (ID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return ID{}, ErrInvalid
	}
	return ID(id), nil
}

// String returns the canonical public ID.
func (id ID) String() string { return publicid.ID(id).String() }

// IsValid reports a UUIDv7 public ID.
func (id ID) IsValid() bool { return publicid.ID(id).IsValid() }

// FailureMode is what a zone's names get when none of its resolvers can be
// used, or none answers.
type FailureMode string

// Failure modes (DNS design D1 §5.3).
const (
	// FailOpen asks the host's own DNS (the exit node's while one is used).
	FailOpen FailureMode = "open"
	// FailClosed answers SERVFAIL, so no name of the zone leaves for another
	// resolver.
	FailClosed FailureMode = "closed"
)

// IsKnown reports a failure mode a zone can store.
func (mode FailureMode) IsKnown() bool { return mode == FailOpen || mode == FailClosed }

// Resolver is one resolver of a zone: a Device of the Network, or an
// address on the Internet; exactly one is set.
type Resolver struct {
	DeviceID node.ID
	Address  netip.Addr
	Port     uint16
}

// IsDevice reports a resolver Device.
func (resolver Resolver) IsDevice() bool { return resolver.DeviceID.IsValid() }

// Validate checks one resolver: a Device on port 53 or 1024-65535, or an
// address on the Internet on port 53.
func (resolver Resolver) Validate() error {
	switch {
	case resolver.IsDevice() && resolver.Address.IsValid():
		return ErrInvalid
	case resolver.IsDevice():
		if resolver.Port != DNSPort && resolver.Port < minimumHighPort {
			return ErrInvalid
		}
	case !resolver.Address.IsValid() || resolver.Address.Zone() != "" || resolver.Port != DNSPort:
		return ErrInvalid
	case !internet.Contains(resolver.Address):
		return ErrResolverNotInternet
	}
	return nil
}

// Definition is what a create or update sends: the whole zone each time.
// Groups empty sends the zone to every Device of the Network. A nil
// SearchPosition keeps the domain out of the search domains.
type Definition struct {
	Domain          string
	FailureMode     FailureMode
	Resolvers       []Resolver
	Groups          []devicegroup.ID
	SearchPosition  *int
	PublicConfirmed bool
}

// Validate checks everything but the domain, which ParseDomain checks.
func (definition Definition) Validate(limits Limits) error {
	if !definition.FailureMode.IsKnown() || len(definition.Resolvers) == 0 ||
		len(definition.Resolvers) > MaximumResolversPerZone || len(definition.Groups) > MaximumGroupsPerZone {
		return ErrInvalid
	}
	for index, resolver := range definition.Resolvers {
		if err := resolver.Validate(); err != nil {
			return err
		}
		if slices.ContainsFunc(definition.Resolvers[:index], func(other Resolver) bool {
			return other.DeviceID == resolver.DeviceID && other.Address == resolver.Address
		}) {
			return ErrInvalid
		}
	}
	for index, group := range definition.Groups {
		if !group.IsValid() || slices.Contains(definition.Groups[:index], group) {
			return ErrInvalid
		}
	}
	if position := definition.SearchPosition; position != nil &&
		(*position < 1 || *position > MaximumSearchPosition || limits.SearchZonesPerNetwork == 0) {
		return ErrInvalid
	}
	return nil
}

// Canonical returns the definition with its groups in a stable order:
// resolvers keep the order the admin chose.
func (definition Definition) Canonical() Definition {
	canonical := definition
	canonical.Resolvers = slices.Clone(definition.Resolvers)
	canonical.Groups = slices.Clone(definition.Groups)
	slices.SortFunc(canonical.Groups, func(left, right devicegroup.ID) int {
		return strings.Compare(left.String(), right.String())
	})
	if definition.SearchPosition != nil {
		position := *definition.SearchPosition
		canonical.SearchPosition = &position
	}
	return canonical
}

// ResolverDevice is what Core knows of a resolver Device, to show why it
// cannot serve.
type ResolverDevice struct {
	Name      string
	State     string
	Ownership string
	ExitNode  bool
}

// Eligible reports a Device that can serve as a resolver: active, owned by
// the Workspace and no exit node.
func (device ResolverDevice) Eligible() bool {
	return device.State == "active" && device.Ownership == "workspace" && !device.ExitNode
}

// ZoneResolver is one stored resolver; Device is set for a resolver Device.
type ZoneResolver struct {
	Resolver
	Device *ResolverDevice
}

// Group is a Device Group a zone is sent to.
type Group struct {
	ID    devicegroup.ID
	Name  string
	State string
}

// Zone is one stored zone.
type Zone struct {
	ID              ID
	Domain          Domain
	FailureMode     FailureMode
	Resolvers       []ZoneResolver
	Groups          []Group
	SearchPosition  *int
	Class           Class
	ListVersion     string
	PublicConfirmed bool
	Deleted         bool
	Version         int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
}
