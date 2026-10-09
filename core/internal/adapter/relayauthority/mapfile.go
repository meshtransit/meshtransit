// Package relayauthority makes the control role the Interchange relay
// authority (docs/protocol/mtrp-v1.md §8, §9): it keeps a freshly signed
// relay state and relay map in memory and serves them to relays and nodes.
package relayauthority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	"meshtransit.net/core/internal/adapter/relayfile"
	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

// MapLifetime is how far ahead each signed relay map expires. The map is
// re-signed every refresh, so nodes always hold a map valid for this long.
const MapLifetime = 7 * 24 * time.Hour

const maxMapFileBytes = 256 << 10

// ErrInvalidMap reports an unusable relay map file.
var ErrInvalidMap = errors.New("relayauthority: invalid relay map file")

// mapFile is the operator-maintained relay map: the signed map without its
// expiry, which the authority sets when signing.
type mapFile struct {
	SchemaVersion int              `json:"schema_version"`
	Revision      uint64           `json:"revision"`
	Regions       []mapRegionEntry `json:"regions"`
}

type mapRegionEntry struct {
	ID    uint16         `json:"id"`
	Code  string         `json:"code"`
	Name  string         `json:"name"`
	Nodes []mapNodeEntry `json:"nodes"`
}

type mapNodeEntry struct {
	Name        string          `json:"name"`
	HostName    string          `json:"host_name"`
	IPv4        string          `json:"ipv4"`
	IPv6        string          `json:"ipv6"`
	Key         key.RelayPublic `json:"key"`
	UDPPort     uint16          `json:"udp_port"`
	TLSPort     uint16          `json:"tls_port"`
	STUNPort    uint16          `json:"stun_port"`
	STUNAltPort uint16          `json:"stun_alt_port"`
	STUNAltAddr string          `json:"stun_alt_addr"`
	Weight      uint16          `json:"weight"`
}

// LoadMap reads and validates the relay map file (verified against its
// configured SHA-256).
func LoadMap(ctx context.Context, path string, digest [sha256.Size]byte, now time.Time) (mtrp.RelayMap, error) {
	encoded, err := relayfile.ReadVerified(ctx, path, digest, maxMapFileBytes)
	if err != nil {
		return mtrp.RelayMap{}, errors.Join(ErrInvalidMap, err)
	}
	return decodeMap(encoded, now)
}

func decodeMap(encoded []byte, now time.Time) (mtrp.RelayMap, error) {
	var file mapFile
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return mtrp.RelayMap{}, fmt.Errorf("%w: %w", ErrInvalidMap, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return mtrp.RelayMap{}, fmt.Errorf("%w: trailing data", ErrInvalidMap)
	}
	if file.SchemaVersion != 1 {
		return mtrp.RelayMap{}, fmt.Errorf("%w: schema_version must be 1", ErrInvalidMap)
	}
	m := mtrp.RelayMap{Version: file.Revision}
	for _, r := range file.Regions {
		region := mtrp.RelayRegion{ID: r.ID, Code: r.Code, Name: r.Name}
		for _, n := range r.Nodes {
			node := mtrp.RelayNode{
				Name: n.Name, HostName: n.HostName, Key: n.Key, UDPPort: n.UDPPort, TLSPort: n.TLSPort,
				STUNPort: n.STUNPort, STUNAltPort: n.STUNAltPort, Weight: n.Weight,
			}
			var err error
			if node.IPv4, err = optionalAddr(n.IPv4); err != nil {
				return mtrp.RelayMap{}, err
			}
			if node.IPv6, err = optionalAddr(n.IPv6); err != nil {
				return mtrp.RelayMap{}, err
			}
			if node.STUNAltAddr, err = optionalAddr(n.STUNAltAddr); err != nil {
				return mtrp.RelayMap{}, err
			}
			region.Nodes = append(region.Nodes, node)
		}
		m.Regions = append(m.Regions, region)
	}
	// Validate exactly as nodes will, with the expiry the authority sets.
	m.ExpiresAt = now.Add(MapLifetime)
	if _, err := m.Payload(now); err != nil {
		return mtrp.RelayMap{}, fmt.Errorf("%w: %w", ErrInvalidMap, err)
	}
	return m, nil
}

func optionalAddr(s string) (netip.Addr, error) {
	if s == "" {
		return netip.Addr{}, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("%w: address %q", ErrInvalidMap, s)
	}
	return a.Unmap(), nil
}
