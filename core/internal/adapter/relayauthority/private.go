package relayauthority

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/interchange"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/relay"
	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

// GrantLifetime is how long a Private Interchange grant is valid; Core
// re-signs it every window and the relay polls every 10 seconds.
const GrantLifetime = 10 * time.Minute

// privateNodeWeight is the weight of a Private Interchange node; the client
// prefers the region by its preferred flag, not by weight.
const privateNodeWeight = 100

// PrivateInterchangeSource reads the deployment's Private Interchange relays.
type PrivateInterchangeSource interface {
	ReadPrivateInterchanges(ctx context.Context) (interchange.Directory, error)
}

// MapVersion combines the shared map's version with the Private
// Interchange revision. Both only grow, so a node never sees an older map
// when relays are added to or removed from its Network.
func MapVersion(shared uint64, privateRevision int64) uint64 {
	return shared<<32 | uint64(uint32(max(privateRevision, 0))) //nolint:gosec // G115: seconds fit 32 bits until 2106
}

// NetworkMap is the relay map of one Network: the shared regions and, marked
// preferred, the Private Interchange regions granted to it. A private relay
// whose region ID, region code or key clashes with the shared map is left
// out (MeshCore refuses such relays when they are added).
func NetworkMap(shared mtrp.RelayMap, granted []interchange.Interchange, privateRevision int64) mtrp.RelayMap {
	m := mtrp.RelayMap{Version: MapVersion(shared.Version, privateRevision), ExpiresAt: shared.ExpiresAt,
		Regions: slices.Clone(shared.Regions)}
	used := func(relay interchange.Interchange) bool {
		for _, region := range m.Regions {
			if region.ID == relay.RegionID || region.Code == relay.Spec.RegionCode {
				return true
			}
			for _, node := range region.Nodes {
				if node.Key == relay.Spec.RelayKey {
					return true
				}
			}
		}
		return false
	}
	for _, relay := range granted {
		if len(m.Regions) >= mtrp.MaxRelayRegions || used(relay) {
			continue
		}
		m.Regions = append(m.Regions, mtrp.RelayRegion{
			ID: relay.RegionID, Code: relay.Spec.RegionCode, Name: relay.Spec.Name, Preferred: true,
			Nodes: []mtrp.RelayNode{{
				Name: relay.Spec.RegionCode, HostName: relay.Spec.HostName, IPv4: relay.Spec.IPv4,
				IPv6: relay.Spec.IPv6, Key: relay.Spec.RelayKey, UDPPort: relay.Spec.UDPPort,
				TLSPort: relay.Spec.TLSPort, STUNPort: relay.Spec.STUNPort, Weight: privateNodeWeight,
			}},
		})
	}
	return m
}

// networkMapKey identifies the content of a Network's map apart from its
// expiry: the combined version and the private regions it carries.
func networkMapKey(shared uint64, privateRevision int64, granted []interchange.Interchange) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d", MapVersion(shared, privateRevision))
	for _, relay := range granted {
		fmt.Fprintf(&b, "/%d", relay.RegionID)
	}
	return b.String()
}

// privateDirectory returns the Private Interchange relays in force; empty
// when none are configured or none could be read yet.
func (p *Publisher) privateDirectory() interchange.Directory {
	if directory := p.private.Load(); directory != nil {
		return *directory
	}
	return interchange.Directory{}
}

// refreshPrivate reads the Private Interchange relays. A failed read keeps
// the previous set: grants and maps stay valid while PostgreSQL recovers.
func (p *Publisher) refreshPrivate(ctx context.Context) {
	if p.opts.Private == nil {
		return
	}
	directory, err := p.opts.Private.ReadPrivateInterchanges(ctx)
	if err != nil {
		p.opts.Metrics.refreshes.WithLabelValues("private_failed").Inc()
		p.opts.Logger.Warn("private interchange read failed", "error", err)
		return
	}
	if previous := p.private.Load(); previous != nil && directory.Revision < previous.Revision {
		return // a replica's read behind ours: keep the newer set
	}
	p.private.Store(&directory)
}

// mapForNetwork returns the signed relay map of a Network for the current
// window and its content key.
func (p *Publisher) mapForNetwork(id network.ID) (*document, string, error) {
	if p.opts.Map == nil {
		return nil, "", ErrNoRelayMap
	}
	directory := p.privateDirectory()
	granted := directory.ForNetwork(id)
	mapKey := networkMapKey(p.opts.Map.Version, directory.Revision, granted)
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()
	if p.cacheWindow.Equal(p.window) {
		if cached, found := p.maps[mapKey]; found {
			return cached, mapKey, nil
		}
	} else {
		p.cacheWindow, p.maps, p.grants = p.window, map[string]*document{}, map[key.RelayPublic]*document{}
	}
	m := NetworkMap(*p.opts.Map, granted, directory.Revision)
	m.ExpiresAt = p.window.Add(MapLifetime)
	signed, err := p.sign(mtrp.DocumentRelayMap, func() ([]byte, error) { return m.Payload(p.window) })
	if err != nil {
		return nil, "", err
	}
	p.maps[mapKey] = signed
	return signed, mapKey, nil
}

// RelayMapCurrent reports whether a grant built on the map with mapKey still
// matches the Network's relays (mapsession uses it to renew grants when a
// Private Interchange is added, changed or removed).
func (p *Publisher) RelayMapCurrent(id network.ID, mapKey string) bool {
	if p.opts.Map == nil {
		return true
	}
	directory := p.privateDirectory()
	return networkMapKey(p.opts.Map.Version, directory.Revision, directory.ForNetwork(id)) == mapKey
}

// DirectoryFor returns the relay directory of a Network: the regions its
// nodes may report as home and relay through, private regions included.
func (p *Publisher) DirectoryFor(id network.ID) (relay.Directory, error) {
	if p.opts.Map == nil {
		return relay.Directory{}, ErrNoRelayMap
	}
	directory := p.privateDirectory()
	return Directory(NetworkMap(*p.opts.Map, directory.ForNetwork(id), directory.Revision))
}

// Uses reports whether the shared relay map uses a region code or relay key,
// for MeshCore to refuse a Private Interchange that would clash.
func (p *Publisher) Uses(regionCode string, relayKey key.RelayPublic) bool {
	if p.opts.Map == nil {
		return false
	}
	for _, region := range p.opts.Map.Regions {
		if region.Code == regionCode {
			return true
		}
		for _, node := range region.Nodes {
			if node.Key == relayKey {
				return true
			}
		}
	}
	return false
}

// sealedGrant returns the current grant of a Private Interchange relay,
// sealed to its key, or false when no Workspace registered the key.
func (p *Publisher) sealedGrant(relayKey key.RelayPublic) ([]byte, bool, error) {
	relay, found := p.privateDirectory().ByKey(relayKey)
	if !found {
		return nil, false, nil
	}
	p.cacheMu.Lock()
	if !p.cacheWindow.Equal(p.window) {
		p.cacheWindow, p.maps, p.grants = p.window, map[string]*document{}, map[key.RelayPublic]*document{}
	}
	signed, cached := p.grants[relayKey]
	if !cached {
		networks := make([][16]byte, len(relay.Spec.Networks))
		for index, id := range relay.Spec.Networks {
			networks[index] = id.Bytes()
		}
		slices.SortFunc(networks, func(a, b [16]byte) int { return bytes.Compare(a[:], b[:]) })
		networks = slices.Compact(networks)
		grant := mtrp.RelayGrant{Relay: relayKey, Sequence: uint64(p.window.UnixMilli()),
			IssuedAt: p.window, ExpiresAt: p.window.Add(GrantLifetime), Networks: networks}
		var err error
		signed, err = p.sign(mtrp.DocumentRelayGrant, grant.Payload)
		if err != nil {
			p.cacheMu.Unlock()
			return nil, true, err
		}
		p.grants[relayKey] = signed
	}
	p.cacheMu.Unlock()
	sealed, err := mtrp.SealRelayGrant(signed.body, relayKey, nil)
	return sealed, true, err
}
