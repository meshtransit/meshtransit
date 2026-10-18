package site

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
)

const (
	// MaximumNameLength bounds a Site name in characters.
	MaximumNameLength = 64
	// MaximumPriority bounds a router priority; a smaller number is preferred.
	MaximumPriority = 999
	// RoutersSupported is how many routers a Site may have until high
	// availability (R2) elects among several.
	RoutersSupported = 1
)

// ID identifies one Site.
type ID publicid.ID

// ParseID validates a canonical Site UUIDv7.
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

// ProbeKind is how a router checks that it reaches its Site.
type ProbeKind uint8

const (
	// ProbeICMP sends an echo request.
	ProbeICMP ProbeKind = 1
	// ProbeTCP opens a connection to a port.
	ProbeTCP ProbeKind = 2
)

// Probe is one address inside the Site that its routers check.
type Probe struct {
	Address netip.Addr
	Kind    ProbeKind
	Port    uint16
}

func (probe Probe) valid(prefixes []netip.Prefix) bool {
	inside := slices.ContainsFunc(prefixes, func(prefix netip.Prefix) bool { return prefix.Contains(probe.Address) })
	switch probe.Kind {
	case ProbeICMP:
		return inside && probe.Port == 0
	case ProbeTCP:
		return inside && probe.Port != 0
	default:
		return false
	}
}

// Definition is the editable part of a Site.
type Definition struct {
	Name       string
	Prefixes   []netip.Prefix
	Masquerade bool
	Failback   bool
	Probes     []Probe
}

// Validate accepts a trimmed, bounded name of plain text, a valid prefix set
// within the plan, and distinct probes inside the Site.
func (definition Definition) Validate(limits Limits, denied []netip.Prefix) error {
	if err := limits.Validate(); err != nil {
		return err
	}
	name := strings.TrimSpace(definition.Name)
	if name != definition.Name || name == "" || utf8.RuneCountInString(name) > MaximumNameLength || !plainText(name) {
		return ErrInvalid
	}
	if err := ValidatePrefixSet(definition.Prefixes, denied, limits.PrefixesPerSite); err != nil {
		return err
	}
	if len(definition.Probes) > limits.ProbesPerSite {
		return ErrInvalid
	}
	for index, probe := range definition.Probes {
		if !probe.valid(definition.Prefixes) || slices.Contains(definition.Probes[:index], probe) {
			return ErrInvalid
		}
	}
	return nil
}

// Canonical returns a copy with prefixes and probes sorted, as stored and
// sent in maps.
func (definition Definition) Canonical() Definition {
	definition.Prefixes = slices.Clone(definition.Prefixes)
	slices.SortFunc(definition.Prefixes, comparePrefixes)
	definition.Probes = slices.Clone(definition.Probes)
	slices.SortFunc(definition.Probes, func(first, second Probe) int {
		return cmp.Or(first.Address.Compare(second.Address), cmp.Compare(first.Kind, second.Kind),
			cmp.Compare(first.Port, second.Port))
	})
	return definition
}

// comparePrefixes orders IPv4 before IPv6, then by address and length.
func comparePrefixes(first, second netip.Prefix) int {
	return cmp.Or(first.Addr().Compare(second.Addr()), cmp.Compare(first.Bits(), second.Bits()))
}

func plainText(value string) bool {
	return utf8.ValidString(value) && !strings.ContainsFunc(value, unicode.IsControl)
}

// RouterState says whether a router may be chosen.
type RouterState uint8

const (
	// RouterActive may serve the Site.
	RouterActive RouterState = 1
	// RouterDraining keeps serving but is chosen only when no active router
	// can serve.
	RouterDraining RouterState = 2
)

// RouterAssignment makes a Device a router of a Site.
type RouterAssignment struct {
	DeviceID node.ID
	Priority int
	State    RouterState
}

// Validate accepts a Device, a priority of 0 to MaximumPriority and a known
// state.
func (assignment RouterAssignment) Validate() error {
	if !assignment.DeviceID.IsValid() || assignment.Priority < 0 || assignment.Priority > MaximumPriority ||
		(assignment.State != RouterActive && assignment.State != RouterDraining) {
		return ErrInvalid
	}
	return nil
}

// Router is one router of a Site as stored, with what Core knows of it.
type Router struct {
	RouterAssignment
	DeviceName string
	// Eligible is false while the Device cannot serve: not active, not
	// owned by the Workspace, or not offering the Site's prefixes.
	Eligible bool
	AddedAt  time.Time
}

// Site is one Site as stored.
type Site struct {
	ID        ID
	Version   int64
	Routers   []Router
	CreatedAt time.Time
	UpdatedAt time.Time
	Definition
}
