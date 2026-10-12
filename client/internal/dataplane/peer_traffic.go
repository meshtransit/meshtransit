package dataplane

import (
	"bufio"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// PeerPathKind is the path a peer's packets take now.
type PeerPathKind uint8

const (
	// PeerPathUnknown means no path is installed yet.
	PeerPathUnknown PeerPathKind = iota
	// PeerPathDirectUDP sends straight to the peer.
	PeerPathDirectUDP
	// PeerPathRelayed sends through an Interchange relay.
	PeerPathRelayed
)

// PeerPathStat is one installed peer's path and cumulative traffic. It
// carries no endpoint addresses or keys.
type PeerPathStat struct {
	PeerID      uint64
	Path        PeerPathKind
	RelayRegion int       // the relay region when relayed
	RelaySince  time.Time // when the current relayed period began
	RxBytes     uint64
	TxBytes     uint64
}

// trafficReportingDevice reads cumulative per-peer counters.
type trafficReportingDevice interface {
	PeerTraffic() (map[[32]byte]peerTraffic, error)
}

// peerTraffic is one peer's counters; handshake is the unix second of its
// last completed handshake, zero when it never completed one.
type peerTraffic struct{ rx, tx, handshake uint64 }

// parsePeerTraffic reads the public_key, rx_bytes, tx_bytes and
// last_handshake_time_sec lines of a WireGuard UAPI get response.
func parsePeerTraffic(response string) map[[32]byte]peerTraffic {
	traffic := make(map[[32]byte]peerTraffic)
	var current [32]byte
	var have bool
	scanner := bufio.NewScanner(strings.NewReader(response))
	for scanner.Scan() {
		name, value, found := strings.Cut(scanner.Text(), "=")
		if !found {
			continue
		}
		switch name {
		case "public_key":
			raw, err := hex.DecodeString(value)
			have = err == nil && len(raw) == len(current)
			if have {
				copy(current[:], raw)
				traffic[current] = peerTraffic{}
			}
		case "rx_bytes", "tx_bytes", "last_handshake_time_sec":
			if !have {
				continue
			}
			count, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				continue
			}
			entry := traffic[current]
			switch name {
			case "rx_bytes":
				entry.rx = count
			case "tx_bytes":
				entry.tx = count
			default:
				entry.handshake = count
			}
			traffic[current] = entry
		}
	}
	return traffic
}

// relayRegionOf returns the region of a relay endpoint string.
func relayRegionOf(endpoint string) int {
	rest, found := strings.CutPrefix(endpoint, relayEndpointPrefix)
	if !found {
		return 0
	}
	region, _, _ := strings.Cut(rest, ":")
	id, err := strconv.Atoi(region)
	if err != nil || id <= 0 {
		return 0
	}
	return id
}

// PeerPathStats returns every installed peer's path and counters, and the
// counters of lazy peers evicted since, with no path. Counters are zero when
// the device cannot report them. The daemon serializes this
// call with Apply and Close.
func (e *WireGuardEngine) PeerPathStats() []PeerPathStat {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.device == nil {
		return nil
	}
	var traffic map[[32]byte]peerTraffic
	if reporting, ok := e.device.(trafficReportingDevice); ok {
		traffic, _ = reporting.PeerTraffic() // best effort: paths still report
	}
	stats := make([]PeerPathStat, 0, len(e.peers)+len(e.lazyTrafficBase))
	for id, base := range e.lazyTrafficBase {
		if _, installed := e.peers[id]; !installed {
			stats = append(stats, PeerPathStat{PeerID: id, RxBytes: base.rx, TxBytes: base.tx})
		}
	}
	for id, peer := range e.peers {
		stat := PeerPathStat{PeerID: id}
		switch peer.currentPath {
		case peerPathDirect:
			stat.Path = PeerPathDirectUDP
		case peerPathRelay:
			stat.Path, stat.RelayRegion, stat.RelaySince = PeerPathRelayed, relayRegionOf(peer.currentEndpoint),
				peer.relayStartedAt
		}
		if counters, found := traffic[peer.key]; found {
			stat.RxBytes, stat.TxBytes = counters.rx, counters.tx
		}
		base := e.lazyTrafficBase[id]
		stat.RxBytes, stat.TxBytes = stat.RxBytes+base.rx, stat.TxBytes+base.tx
		stats = append(stats, stat)
	}
	return stats
}
