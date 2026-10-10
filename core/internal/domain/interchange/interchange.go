// Package interchange models Private Interchange: MeshTransit relays a
// Workspace runs itself and grants to some of its Networks (P5e). Core adds
// a granted relay's region, marked preferred, to those Networks' relay maps,
// and tells the relay which Networks it serves (mtrp-v1 §9.2).
package interchange

import (
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/shared/key"
)

// Limits.
const (
	MaxPerWorkspace = 16
	MaxNetworks     = 256
	maxNameLength   = 64
)

var (
	// ErrInvalid reports an invalid relay, change or result.
	ErrInvalid = errors.New("interchange: invalid Private Interchange")
	// ErrForbidden reports a missing permission.
	ErrForbidden = errors.New("interchange: permission denied")
	// ErrNotFound reports an unknown relay.
	ErrNotFound = errors.New("interchange: not found")
	// ErrVersionConflict reports a change against an older version.
	ErrVersionConflict = errors.New("interchange: version conflict")
	// ErrUnknownNetwork reports a Network outside the Workspace.
	ErrUnknownNetwork = errors.New("interchange: Network is not in the Workspace")
	// ErrLimit reports the per-Workspace limit.
	ErrLimit = errors.New("interchange: limit reached")
	// ErrConflict reports a relay key or region code already in use, by
	// another Private Interchange or by the shared relay map.
	ErrConflict = errors.New("interchange: relay key or region code already in use")
	// ErrUnavailable reports a store failure.
	ErrUnavailable = errors.New("interchange: unavailable")
)

var (
	regionCodePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,15}$`)
	hostNamePattern   = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
)

// Spec is what an owner sets for a relay.
type Spec struct {
	Name       string
	RegionCode string // relay map region code; unique in the deployment
	HostName   string // TLS/WebSocket host name of the relay
	IPv4       netip.Addr
	IPv6       netip.Addr
	RelayKey   key.RelayPublic
	UDPPort    uint16
	TLSPort    uint16 // 0: no TLS/WebSocket fallback
	STUNPort   uint16
	Networks   []network.ID // sorted, distinct
}

// IsValid reports a complete, well-formed spec: public addresses only, at
// least one of them, and the Networks sorted and distinct.
func (spec Spec) IsValid() bool {
	name := strings.TrimSpace(spec.Name)
	switch {
	case name != spec.Name || name == "" || utf8.RuneCountInString(name) > maxNameLength || !utf8.ValidString(name):
		return false
	case !regionCodePattern.MatchString(spec.RegionCode):
		return false
	case len(spec.HostName) > 253 || !hostNamePattern.MatchString(spec.HostName):
		return false
	case !spec.IPv4.IsValid() && !spec.IPv6.IsValid():
		return false
	case spec.IPv4.IsValid() && (!spec.IPv4.Is4() || !publicAddress(spec.IPv4)):
		return false
	case spec.IPv6.IsValid() && (!spec.IPv6.Is6() || spec.IPv6.Is4In6() || !publicAddress(spec.IPv6)):
		return false
	case spec.RelayKey.IsZero() || spec.UDPPort == 0 || spec.STUNPort == 0:
		return false
	case len(spec.Networks) > MaxNetworks:
		return false
	}
	for i, id := range spec.Networks {
		if !id.IsValid() || (i > 0 && compareNetworks(spec.Networks[i-1], id) >= 0) {
			return false
		}
	}
	return true
}

var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

func publicAddress(addr netip.Addr) bool {
	return addr.Zone() == "" && addr.IsGlobalUnicast() && !addr.IsPrivate() && !sharedAddressSpace.Contains(addr)
}

// SortNetworks returns ids sorted and without duplicates.
func SortNetworks(ids []network.ID) []network.ID {
	sorted := slices.Clone(ids)
	slices.SortFunc(sorted, compareNetworks)
	return slices.Compact(sorted)
}

func compareNetworks(a, b network.ID) int {
	return strings.Compare(publicid.ID(a).String(), publicid.ID(b).String())
}

// Interchange is one active relay of a Workspace.
type Interchange struct {
	ID        publicid.ID
	RegionID  uint16 // allocated by Core, 1000–64999
	Spec      Spec
	Version   int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

// IsValid reports a consistent stored relay.
func (interchange Interchange) IsValid() bool {
	return interchange.ID.IsValid() && interchange.RegionID >= 1000 && interchange.RegionID <= 64999 &&
		interchange.Spec.IsValid() && interchange.Version > 0 && !interchange.CreatedAt.IsZero() &&
		!interchange.UpdatedAt.Before(interchange.CreatedAt)
}

// SharedRelays is the shared relay map a Private Interchange must not clash
// with.
type SharedRelays interface {
	// Uses reports whether the shared map uses the region code or relay key.
	Uses(regionCode string, relayKey key.RelayPublic) bool
}

// Directory is every active relay of the deployment, as the control plane
// reads it for relay maps and grants.
type Directory struct {
	// Revision is the time of the latest change of any relay, in seconds;
	// it never decreases, so map versions built from it never go back.
	Revision int64
	Relays   []Interchange // Version, CreatedAt and UpdatedAt are not set
}

// ForNetwork returns the relays granted to id, in region order.
func (directory Directory) ForNetwork(id network.ID) []Interchange {
	var granted []Interchange
	for _, relay := range directory.Relays {
		if _, found := slices.BinarySearchFunc(relay.Spec.Networks, id, compareNetworks); found {
			granted = append(granted, relay)
		}
	}
	return granted
}

// ByKey returns the relay with relayKey.
func (directory Directory) ByKey(relayKey key.RelayPublic) (Interchange, bool) {
	for _, relay := range directory.Relays {
		if relay.Spec.RelayKey == relayKey {
			return relay, true
		}
	}
	return Interchange{}, false
}
