package mtrp

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"time"

	"meshtransit.net/shared/key"
)

// Relay map limits (mtrp-v1 §8).
const (
	MaxRelayRegions        = 128
	MaxRelayNodesPerRegion = 16
	// MaxRelayMapLifetime bounds how long a node may keep using one map.
	MaxRelayMapLifetime = 30 * 24 * time.Hour
)

var (
	regionCodePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,15}$`)
	hostNamePattern   = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
)

// RelayMap lists the Interchange relays nodes may use. Core signs it as a
// DocumentRelayMap; nodes accept only a newer, unexpired map.
type RelayMap struct {
	Version   uint64
	ExpiresAt time.Time
	Regions   []RelayRegion
}

// RelayRegion is a group of relay nodes in one location.
type RelayRegion struct {
	ID    uint16
	Code  string // short lowercase name, e.g. "sgp"
	Name  string // display name
	Nodes []RelayNode
	// Preferred marks a Private Interchange region: nodes use it as their
	// home relay while it is reachable, before shared regions.
	Preferred bool
}

// RelayNode is one relay endpoint.
type RelayNode struct {
	Name        string
	HostName    string // TLS/WebSocket host and ACME name
	IPv4, IPv6  netip.Addr
	Key         key.RelayPublic
	UDPPort     uint16
	TLSPort     uint16
	STUNPort    uint16
	STUNAltPort uint16     // 0: no RFC 5780 alternate port
	STUNAltAddr netip.Addr // invalid: no alternate address
	Weight      uint16     // relative capacity for home-relay selection
}

type relayMapWire struct {
	Version     int          `json:"version"`
	MapVersion  uint64       `json:"map_version"`
	ExpiresAtMS int64        `json:"expires_at_ms"`
	Regions     []regionWire `json:"regions"`
}

type regionWire struct {
	ID        uint16     `json:"id"`
	Code      string     `json:"code"`
	Name      string     `json:"name"`
	Nodes     []nodeWire `json:"nodes"`
	Preferred bool       `json:"preferred,omitempty"`
}

type nodeWire struct {
	Name        string          `json:"name"`
	HostName    string          `json:"host_name"`
	IPv4        string          `json:"ipv4,omitempty"`
	IPv6        string          `json:"ipv6,omitempty"`
	Key         key.RelayPublic `json:"key"`
	UDPPort     uint16          `json:"udp_port"`
	TLSPort     uint16          `json:"tls_port"`
	STUNPort    uint16          `json:"stun_port"`
	STUNAltPort uint16          `json:"stun_alt_port,omitempty"`
	STUNAltAddr string          `json:"stun_alt_addr,omitempty"`
	Weight      uint16          `json:"weight"`
}

// Payload validates m and encodes it as a signed-document payload.
func (m RelayMap) Payload(now time.Time) ([]byte, error) {
	if err := m.validate(now); err != nil {
		return nil, err
	}
	w := relayMapWire{Version: 1, MapVersion: m.Version, ExpiresAtMS: m.ExpiresAt.UnixMilli()}
	for _, r := range m.Regions {
		rw := regionWire{ID: r.ID, Code: r.Code, Name: r.Name, Preferred: r.Preferred}
		for _, n := range r.Nodes {
			rw.Nodes = append(rw.Nodes, nodeWire{
				Name: n.Name, HostName: n.HostName, IPv4: addrString(n.IPv4), IPv6: addrString(n.IPv6),
				Key: n.Key, UDPPort: n.UDPPort, TLSPort: n.TLSPort, STUNPort: n.STUNPort,
				STUNAltPort: n.STUNAltPort, STUNAltAddr: addrString(n.STUNAltAddr), Weight: n.Weight,
			})
		}
		w.Regions = append(w.Regions, rw)
	}
	return json.Marshal(w)
}

// ParseRelayMap decodes and validates a verified payload; maps that expired
// before now are rejected.
func ParseRelayMap(payload []byte, now time.Time) (RelayMap, error) {
	var w relayMapWire
	if err := json.Unmarshal(payload, &w); err != nil {
		return RelayMap{}, fmt.Errorf("%w: %w", ErrDocumentMalformed, err)
	}
	if w.Version != 1 {
		return RelayMap{}, fmt.Errorf("%w: relay map version %d", ErrDocumentMalformed, w.Version)
	}
	m := RelayMap{Version: w.MapVersion, ExpiresAt: time.UnixMilli(w.ExpiresAtMS)}
	for _, rw := range w.Regions {
		r := RelayRegion{ID: rw.ID, Code: rw.Code, Name: rw.Name, Preferred: rw.Preferred}
		for _, nw := range rw.Nodes {
			n := RelayNode{
				Name: nw.Name, HostName: nw.HostName, Key: nw.Key, UDPPort: nw.UDPPort, TLSPort: nw.TLSPort,
				STUNPort: nw.STUNPort, STUNAltPort: nw.STUNAltPort, Weight: nw.Weight,
			}
			var err error
			if n.IPv4, err = parseOptionalAddr(nw.IPv4); err != nil {
				return RelayMap{}, err
			}
			if n.IPv6, err = parseOptionalAddr(nw.IPv6); err != nil {
				return RelayMap{}, err
			}
			if n.STUNAltAddr, err = parseOptionalAddr(nw.STUNAltAddr); err != nil {
				return RelayMap{}, err
			}
			r.Nodes = append(r.Nodes, n)
		}
		m.Regions = append(m.Regions, r)
	}
	if err := m.validate(now); err != nil {
		return RelayMap{}, err
	}
	return m, nil
}

func (m RelayMap) validate(now time.Time) error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrDocumentMalformed}, args...)...)
	}
	if m.Version == 0 {
		return bad("map version must be positive")
	}
	if !m.ExpiresAt.After(now) || m.ExpiresAt.Sub(now) > MaxRelayMapLifetime {
		return bad("relay map expiry out of range")
	}
	if len(m.Regions) == 0 || len(m.Regions) > MaxRelayRegions {
		return bad("1..%d regions required", MaxRelayRegions)
	}
	var keys []key.RelayPublic
	for i, r := range m.Regions {
		if r.ID == 0 || slices.ContainsFunc(m.Regions[:i], func(o RelayRegion) bool { return o.ID == r.ID }) {
			return bad("invalid or duplicate region id %d", r.ID)
		}
		if slices.ContainsFunc(m.Regions[:i], func(o RelayRegion) bool { return o.Code == r.Code }) {
			return bad("duplicate region code %q", r.Code)
		}
		if !regionCodePattern.MatchString(r.Code) || len(r.Name) == 0 || len(r.Name) > 64 {
			return bad("region %d: invalid code or name", r.ID)
		}
		if len(r.Nodes) == 0 || len(r.Nodes) > MaxRelayNodesPerRegion {
			return bad("region %d: 1..%d nodes required", r.ID, MaxRelayNodesPerRegion)
		}
		for _, n := range r.Nodes {
			if err := n.validate(); err != nil {
				return bad("region %d node %q: %v", r.ID, n.Name, err)
			}
			if slices.Contains(keys, n.Key) {
				return bad("duplicate relay key")
			}
			keys = append(keys, n.Key)
		}
	}
	return nil
}

func (n RelayNode) validate() error {
	switch {
	case n.Name == "" || len(n.Name) > 32:
		return fmt.Errorf("name length")
	case !hostNamePattern.MatchString(n.HostName) || len(n.HostName) > 253:
		return fmt.Errorf("host name")
	case n.Key.IsZero():
		return fmt.Errorf("relay key")
	case !n.IPv4.IsValid() && !n.IPv6.IsValid():
		return fmt.Errorf("needs an IPv4 or IPv6 address")
	case n.IPv4.IsValid() && !n.IPv4.Is4(), n.IPv6.IsValid() && !n.IPv6.Is6():
		return fmt.Errorf("address family")
	case n.UDPPort == 0 || n.STUNPort == 0:
		return fmt.Errorf("udp and stun ports required")
	case n.Weight == 0:
		return fmt.Errorf("weight must be positive")
	}
	return nil
}

func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func parseOptionalAddr(s string) (netip.Addr, error) {
	if s == "" {
		return netip.Addr{}, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("%w: address %q", ErrDocumentMalformed, s)
	}
	return a.Unmap(), nil
}
