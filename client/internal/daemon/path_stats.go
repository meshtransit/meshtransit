package daemon

import (
	"context"
	"sync"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/networkmap"
)

const (
	// pathStatsSample is how often paths and counters are read; traffic of
	// a sample is attributed to the path in use when it is read.
	pathStatsSample = 10 * time.Second
	// pathStatsSamples make one report interval (mtcp-v1 §8.3: 60 s).
	pathStatsSamples = 6
	// relayBootstrapWindow is how long a relayed path counts as bootstrap.
	relayBootstrapWindow = 30 * time.Second
	maxPathStatsPeers    = 10_000
)

// pathStatsDataPlane reports per-peer paths and cumulative counters.
type pathStatsDataPlane interface {
	PeerPathStats() []dataplane.PeerPathStat
}

type pathPeer struct {
	deviceID     string
	hasEndpoints bool
}

type pathTotals struct {
	path               controlplane.PathKind
	region             int
	reason             controlplane.RelayReason
	directTx, directRx uint64
	relayTx, relayRx   uint64
	lastTx, lastRx     uint64
	counted            bool
}

// pathStatsSampler turns cumulative per-peer counters into per-interval
// path statistics. observe runs from the map callback, sample from the
// sampling loop.
type pathStatsSampler struct {
	mu            sync.Mutex
	peers         map[uint64]pathPeer
	totals        map[uint64]*pathTotals
	intervalStart time.Time
}

func newPathStatsSampler(now time.Time) *pathStatsSampler {
	return &pathStatsSampler{peers: map[uint64]pathPeer{}, totals: map[uint64]*pathTotals{}, intervalStart: now}
}

// observe records which Device each peer ID is and whether it offers
// direct candidates.
func (p *pathStatsSampler) observe(snapshot networkmap.Snapshot) {
	peers := make(map[uint64]pathPeer, len(snapshot.Peers))
	for _, peer := range snapshot.Peers {
		peers[peer.ID] = pathPeer{deviceID: peer.StableID, hasEndpoints: len(peer.Endpoints) > 0}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.peers = peers
	for id := range p.totals {
		if _, found := peers[id]; !found {
			delete(p.totals, id)
		}
	}
}

// sample attributes the traffic since the previous sample to each peer's
// current path.
func (p *pathStatsSampler) sample(stats []dataplane.PeerPathStat, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, stat := range stats {
		peer, known := p.peers[stat.PeerID]
		if !known {
			continue
		}
		totals := p.totals[stat.PeerID]
		if totals == nil {
			totals = &pathTotals{}
			p.totals[stat.PeerID] = totals
		}
		var tx, rx uint64
		if totals.counted && stat.TxBytes >= totals.lastTx && stat.RxBytes >= totals.lastRx {
			tx, rx = stat.TxBytes-totals.lastTx, stat.RxBytes-totals.lastRx
		}
		totals.lastTx, totals.lastRx, totals.counted = stat.TxBytes, stat.RxBytes, true
		totals.path, totals.region, totals.reason = controlplane.PathUnknown, 0, controlplane.RelayReasonNone
		switch stat.Path {
		case dataplane.PeerPathDirectUDP:
			totals.path = controlplane.PathDirect
			totals.directTx += tx
			totals.directRx += rx
		case dataplane.PeerPathRelayed:
			totals.path, totals.region = controlplane.PathRelay, stat.RelayRegion
			totals.relayTx += tx
			totals.relayRx += rx
			switch {
			case !peer.hasEndpoints:
				totals.reason = controlplane.RelayNoCandidates
			case !stat.RelaySince.IsZero() && now.Sub(stat.RelaySince) < relayBootstrapWindow:
				totals.reason = controlplane.RelayBootstrap
			default:
				totals.reason = controlplane.RelayNoResponse
			}
		}
	}
}

// report returns the interval's statistics and starts the next interval.
func (p *pathStatsSampler) report(now time.Time) controlplane.PathStatsReport {
	p.mu.Lock()
	defer p.mu.Unlock()
	report := controlplane.PathStatsReport{IntervalStart: p.intervalStart, Interval: now.Sub(p.intervalStart)}
	for id, totals := range p.totals {
		peer, known := p.peers[id]
		if !known || len(report.Peers) == maxPathStatsPeers {
			continue
		}
		report.Peers = append(report.Peers, controlplane.PeerPathStats{
			DeviceID: peer.deviceID, Path: totals.path, RelayRegion: totals.region, RelayReason: totals.reason,
			DirectTxBytes: totals.directTx, DirectRxBytes: totals.directRx,
			RelayTxBytes: totals.relayTx, RelayRxBytes: totals.relayRx,
		})
		totals.directTx, totals.directRx, totals.relayTx, totals.relayRx = 0, 0, 0, 0
	}
	p.intervalStart = now
	return report
}

// runPathStats samples the data plane and publishes one report per
// interval until ctx ends; a report the stream has not taken is replaced.
func runPathStats(ctx context.Context, sampler *pathStatsSampler, read func() []dataplane.PeerPathStat,
	reports chan controlplane.PathStatsReport, clock func() time.Time,
) {
	ticker := time.NewTicker(pathStatsSample)
	defer ticker.Stop()
	samples := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		sampler.sample(read(), clock())
		samples++
		if samples < pathStatsSamples {
			continue
		}
		samples = 0
		report := sampler.report(clock())
		select {
		case <-reports:
		default:
		}
		select {
		case reports <- report:
		default:
		}
	}
}
