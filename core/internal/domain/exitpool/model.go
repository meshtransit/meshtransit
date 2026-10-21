package exitpool

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/shared/internet"
)

// Technical ceilings no plan can exceed: they bound maps and client state.
const (
	MaximumPoolsPerNetwork = 64
	MaximumNodesPerPool    = 16
	MaximumProbesPerPool   = 8
	MaximumDNSUpstreams    = 4
)

const (
	// MaximumNameLength bounds a pool name in characters.
	MaximumNameLength = 64
	// MaximumPriority bounds an exit node priority; a smaller number is
	// preferred.
	MaximumPriority = 999
)

// The connections one consumer may hold open through an exit node (design
// §4.3). An exit node's own local limit can only lower it.
const (
	MinimumConntrackPerConsumer = 1024
	DefaultConntrackPerConsumer = 16384
	MaximumConntrackPerConsumer = 262144
)

// Limits are the plan limits of one Workspace; until paid plans set them,
// every Workspace has the ceilings.
type Limits struct {
	PoolsPerNetwork int
	NodesPerPool    int
}

// DefaultLimits are the limits of a Workspace without a plan.
func DefaultLimits() Limits {
	return Limits{PoolsPerNetwork: MaximumPoolsPerNetwork, NodesPerPool: MaximumNodesPerPool}
}

// Validate accepts limits of at least one and at most the ceilings.
func (limits Limits) Validate() error {
	if limits.PoolsPerNetwork < 1 || limits.PoolsPerNetwork > MaximumPoolsPerNetwork ||
		limits.NodesPerPool < 1 || limits.NodesPerPool > MaximumNodesPerPool {
		return ErrInvalid
	}
	return nil
}

// ID identifies one Exit Pool.
type ID publicid.ID

// ParseID validates a canonical pool UUIDv7.
func ParseID(value string) (ID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return ID{}, ErrInvalid
	}
	return ID(id), nil
}

// String returns the canonical public identity.
func (id ID) String() string { return publicid.ID(id).String() }

// IsValid reports whether the identity is a UUIDv7.
func (id ID) IsValid() bool { return publicid.ID(id).IsValid() }

// Probe is one Internet address and TCP port an exit node connects to,
// through its own forwarding path, to check that it reaches the Internet
// (design §8).
type Probe struct {
	Address netip.Addr
	Port    uint16
}

// Definition is the editable part of a pool.
type Definition struct {
	Name string
	// Failback returns to a preferred exit node once it is healthy again.
	// Off by default: changing exit node changes the public address and cuts
	// every connection (design §9).
	Failback bool
	// SMTPAllowed lets consumers open TCP port 25 to the Internet.
	SMTPAllowed          bool
	ConntrackPerConsumer int
	// DNSUpstreams are the resolvers exit nodes forward DNS to, tried in
	// order; empty uses each exit node's own system resolver.
	DNSUpstreams []netip.Addr
	Probes       []Probe
	// Mode is failover or spread; ModeKeep in an update keeps the stored
	// one and in a new pool means failover.
	Mode Mode
	// CaptiveWindows lets consumers' root open captive portal windows, or
	// turns them off; CaptiveKeep in an update keeps the stored one and in
	// a new pool means allowed.
	CaptiveWindows CaptiveWindows
}

// CaptiveWindows is whether consumers of a pool may open captive portal
// windows (exit node design §17.4, C5): Core may only turn them off.
type CaptiveWindows string

const (
	// CaptiveKeep is the setting of an update that keeps the stored one.
	CaptiveKeep CaptiveWindows = ""
	// CaptiveAllowed leaves windows to root on each consumer.
	CaptiveAllowed CaptiveWindows = "allowed"
	// CaptiveOff refuses windows on every consumer of the pool.
	CaptiveOff CaptiveWindows = "off"
)

// IsKnown reports a setting a pool can store.
func (setting CaptiveWindows) IsKnown() bool {
	return setting == CaptiveAllowed || setting == CaptiveOff
}

// Validate accepts a trimmed, bounded name of plain text, a connection
// limit in range, and distinct Internet resolvers and probes within the
// ceilings.
func (definition Definition) Validate(limits Limits) error {
	if err := limits.Validate(); err != nil {
		return err
	}
	name := strings.TrimSpace(definition.Name)
	if name != definition.Name || name == "" || utf8.RuneCountInString(name) > MaximumNameLength || !plainText(name) {
		return ErrInvalid
	}
	if definition.Mode != ModeKeep && !definition.Mode.IsKnown() {
		return ErrInvalid
	}
	if definition.CaptiveWindows != CaptiveKeep && !definition.CaptiveWindows.IsKnown() {
		return ErrInvalid
	}
	if definition.ConntrackPerConsumer < MinimumConntrackPerConsumer ||
		definition.ConntrackPerConsumer > MaximumConntrackPerConsumer {
		return ErrInvalid
	}
	if len(definition.DNSUpstreams) > MaximumDNSUpstreams || len(definition.Probes) > MaximumProbesPerPool {
		return ErrInvalid
	}
	for index, address := range definition.DNSUpstreams {
		if !address.IsValid() || slices.Contains(definition.DNSUpstreams[:index], address) {
			return ErrInvalid
		}
		if !internet.Contains(address) {
			return ErrNotInternet
		}
	}
	for index, probe := range definition.Probes {
		if !probe.Address.IsValid() || probe.Port == 0 || slices.Contains(definition.Probes[:index], probe) {
			return ErrInvalid
		}
		if !internet.Contains(probe.Address) {
			return ErrNotInternet
		}
	}
	return nil
}

// Canonical returns a copy with probes sorted, as stored and sent in maps.
// Resolvers keep their order: exit nodes try them in it.
func (definition Definition) Canonical() Definition {
	definition.DNSUpstreams = slices.Clone(definition.DNSUpstreams)
	definition.Probes = slices.Clone(definition.Probes)
	slices.SortFunc(definition.Probes, func(first, second Probe) int {
		return cmp.Or(first.Address.Compare(second.Address), cmp.Compare(first.Port, second.Port))
	})
	return definition
}

func plainText(value string) bool {
	return utf8.ValidString(value) && !strings.ContainsFunc(value, unicode.IsControl)
}

// NodeState says whether an exit node may be chosen.
type NodeState uint8

const (
	// NodeActive may serve the pool.
	NodeActive NodeState = 1
	// NodeDraining keeps serving but is chosen only when no active exit node
	// can serve.
	NodeDraining NodeState = 2
)

// NodeAssignment makes a Device an exit node of a pool.
type NodeAssignment struct {
	DeviceID node.ID
	Priority int
	State    NodeState
}

// Validate accepts a Device, a priority of 0 to MaximumPriority and a known
// state.
func (assignment NodeAssignment) Validate() error {
	if !assignment.DeviceID.IsValid() || assignment.Priority < 0 || assignment.Priority > MaximumPriority ||
		(assignment.State != NodeActive && assignment.State != NodeDraining) {
		return ErrInvalid
	}
	return nil
}

// Node is one exit node of a pool as stored, with what Core knows of it.
type Node struct {
	NodeAssignment
	DeviceName string
	// Offered reports the Device's own configuration offers to be an exit
	// node (exit_mode); assigning it does not require it, serving does.
	Offered bool
	// Eligible is false while the Device cannot serve: not active, not owned
	// by the Workspace, or not offering to be an exit node.
	Eligible bool
	AddedAt  time.Time
}

// Pool is one Exit Pool as stored.
type Pool struct {
	ID        ID
	Version   int64
	Nodes     []Node
	CreatedAt time.Time
	UpdatedAt time.Time
	Definition
}

// Eligible decides whether a stored exit node can serve its pool: an active
// Device owned by the Workspace whose own configuration offers to be an
// exit node.
func Eligible(deviceState, ownership string, offered bool) bool {
	return deviceState == "active" && ownership == "workspace" && offered
}
