package mtcp

import (
	"cmp"
	"context"
	"slices"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
)

// PathRecorder stores a Device's latest path report for its session
// (redis.Client).
type PathRecorder interface {
	RecordPaths(ctx context.Context, nodeID node.ID, sessionGeneration int64, report distribution.PathReport) error
}

const (
	// maxReportedPathPeers bounds a PathStatsReport (mtcp-v1 §8.3).
	maxReportedPathPeers = 10_000
	// pathReportInterval spaces stored reports; nodes report every minute.
	pathReportInterval = 30 * time.Second
	pathRecordTimeout  = 2 * time.Second
)

// paths stores a PathStatsReport about the peers of the node's current map;
// entries about other Devices are dropped.
func (conversation *conversation) paths(ctx context.Context, report *mtcpv1.PathStatsReport) error {
	recorder := conversation.application.options.Paths
	if recorder == nil {
		return nil
	}
	if len(report.GetPeers()) > maxReportedPathPeers || report.GetIntervalS() == 0 || report.GetIntervalS() > 3600 {
		return Violation(mtcpv1.Error_INVALID, "invalid path statistics")
	}
	snapshot, ok := conversation.sink.snapshot()
	now := conversation.application.now()
	if !ok || now.Sub(conversation.lastPaths) < pathReportInterval {
		return nil
	}
	conversation.lastPaths = now
	type mapPeer struct {
		id       node.ID
		external bool
	}
	known := make(map[string]mapPeer, len(snapshot.AuthorizedPeers()))
	for _, peer := range snapshot.AuthorizedPeers() {
		known[peer.NodeID().String()] = mapPeer{id: peer.NodeID(),
			external: peer.Scope().NetworkID() != snapshot.Scope().NetworkID()}
	}
	directory := snapshot.RelayDirectory()
	stored := distribution.PathReport{ReportedAt: now, Interval: time.Duration(report.GetIntervalS()) * time.Second}
	for _, entry := range report.GetPeers() {
		mapped, found := known[entry.GetDeviceId()]
		if !found {
			continue
		}
		peer := distribution.PeerPath{PeerID: mapped.id, External: mapped.external, Kind: distribution.PathUnknown,
			DirectBytes: saturatingSum(entry.GetDirectTxBytes(), entry.GetDirectRxBytes()),
			RelayBytes:  saturatingSum(entry.GetRelayTxBytes(), entry.GetRelayRxBytes())}
		switch entry.GetTechnique() {
		case mtcpv1.PeerPathStats_DIRECT, mtcpv1.PeerPathStats_PEER_REFLEXIVE, mtcpv1.PeerPathStats_PREDICTION,
			mtcpv1.PeerPathStats_BIRTHDAY:
			peer.Kind = distribution.PathDirect
		case mtcpv1.PeerPathStats_RELAY:
			peer.Kind = distribution.PathRelay
			if region := int(min(entry.GetRelayRegion(), 65535)); region > 0 {
				peer.RelayRegion = region
				if named, found := directory.Region(region); found {
					peer.RelayCode = named.Code()
				}
			}
			peer.RelayReason = relayReason(entry.GetRelayReason())
		}
		stored.Peers = append(stored.Peers, peer)
	}
	// The busiest peers are kept when the report names more.
	slices.SortFunc(stored.Peers, func(a, b distribution.PeerPath) int {
		return cmp.Compare(saturatingSum(b.DirectBytes, b.RelayBytes), saturatingSum(a.DirectBytes, a.RelayBytes))
	})
	if len(stored.Peers) > distribution.MaximumPathPeers {
		stored.Peers = stored.Peers[:distribution.MaximumPathPeers]
	}
	recordCtx, cancel := context.WithTimeout(ctx, pathRecordTimeout)
	defer cancel()
	if err := recorder.RecordPaths(recordCtx, snapshot.NodeID(), snapshot.SessionGeneration(), stored); err != nil {
		conversation.application.options.Logger.DebugContext(ctx, "mtcp path report not stored", "error", err)
	}
	return nil
}

func relayReason(reason mtcpv1.PeerPathStats_RelayReason) distribution.RelayReason {
	switch reason {
	case mtcpv1.PeerPathStats_BOOTSTRAP:
		return distribution.RelayBootstrap
	case mtcpv1.PeerPathStats_NO_CANDIDATES:
		return distribution.RelayNoCandidates
	case mtcpv1.PeerPathStats_NO_RESPONSE:
		return distribution.RelayNoResponse
	default:
		return ""
	}
}

func saturatingSum(a, b uint64) uint64 {
	if a > ^uint64(0)-b {
		return ^uint64(0)
	}
	return a + b
}
