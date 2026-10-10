package mtcp

import (
	"context"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
)

// ConnectivityRecorder stores a Device's latest connectivity report for its
// session (redis.Client).
type ConnectivityRecorder interface {
	RecordConnectivity(ctx context.Context, nodeID node.ID, sessionGeneration int64, report distribution.Connectivity) error
}

// connectivity stores the NAT classification, IPv6 reachability and port
// mapping state of an endpoint report (mtcp-v1 §8.1) when they changed
// since the last one stored in this session. Unknown codes read as unknown.
func (conversation *conversation) connectivity(
	ctx context.Context,
	snapshot mapsession.Snapshot,
	report *mtcpv1.EndpointReport,
	now time.Time,
) {
	recorder := conversation.application.options.Connectivity
	if recorder == nil {
		return
	}
	reported := connectivityOf(report, now)
	if last := conversation.lastConnectivity; last != nil && last.SameAs(reported) {
		return
	}
	recordCtx, cancel := context.WithTimeout(ctx, pathRecordTimeout)
	defer cancel()
	if err := recorder.RecordConnectivity(recordCtx, snapshot.NodeID(), snapshot.SessionGeneration(), reported); err != nil {
		conversation.application.options.Logger.DebugContext(ctx, "mtcp connectivity report not stored", "error", err)
		return
	}
	conversation.lastConnectivity = &reported
}

func connectivityOf(report *mtcpv1.EndpointReport, now time.Time) distribution.Connectivity {
	connectivity := distribution.Connectivity{
		ReportedAt: now, IPv6Global: report.GetIpv6Global() || report.GetIpv6Stun(), IPv6STUN: report.GetIpv6Stun(),
	}
	if nat := report.GetNat(); nat != nil {
		connectivity.NAT = &distribution.NATClass{
			Mapping:        pick(nat.GetMapping(), distribution.NATMappingUnknown, natMappings),
			Filtering:      pick(nat.GetFiltering(), distribution.NATFilteringUnknown, natFilterings),
			Allocation:     pick(nat.GetAllocation(), distribution.NATAllocationUnknown, natAllocations),
			SequentialStep: uint16(min(nat.GetSequentialStep(), 65535)),
			ObservedAt:     plausibleTime(report.GetNatObservedMs(), now),
		}
	}
	if mapping := report.GetPortMapping(); mapping != nil {
		connectivity.PortMapping = &distribution.PortMapping{
			Protocol:  pick(mapping.GetProtocol(), distribution.PortMappingProtocolUnknown, portMappingProtocols),
			State:     pick(mapping.GetState(), distribution.PortMappingUnknown, portMappingStates),
			ExpiresAt: plausibleTime(mapping.GetExpiresMs(), now),
		}
	}
	return connectivity
}

// Codes of mtcp-v1 NatInfo (nat-classification §1) and PortMapping.
var (
	natMappings = []distribution.NATMapping{
		distribution.NATMappingUnknown, distribution.NATMappingNone, distribution.NATMappingEndpointIndependent,
		distribution.NATMappingAddressDependent, distribution.NATMappingAddressAndPortDependent,
	}
	natFilterings = []distribution.NATFiltering{
		distribution.NATFilteringUnknown, distribution.NATFilteringEndpointIndependent,
		distribution.NATFilteringAddressDependent, distribution.NATFilteringAddressAndPortDependent,
	}
	natAllocations = []distribution.NATAllocation{
		distribution.NATAllocationUnknown, distribution.NATAllocationPreserving,
		distribution.NATAllocationSequential, distribution.NATAllocationRandom,
	}
	portMappingProtocols = []distribution.PortMappingProtocol{
		distribution.PortMappingProtocolUnknown, distribution.PortMappingProtocolPCP,
		distribution.PortMappingProtocolNATPMP, distribution.PortMappingProtocolUPnP,
	}
	portMappingStates = []distribution.PortMappingState{
		distribution.PortMappingUnknown, distribution.PortMappingOff, distribution.PortMappingSearching,
		distribution.PortMappingMapped, distribution.PortMappingDoubleNAT, distribution.PortMappingUnavailable,
		distribution.PortMappingFailed,
	}
)

func pick[T any](code uint32, unknown T, values []T) T {
	if int64(code) >= int64(len(values)) {
		return unknown
	}
	return values[code]
}

// plausibleTime reads a node timestamp, dropping values more than 30 days
// away from Core's now: a node clock that far off says nothing useful.
func plausibleTime(ms int64, now time.Time) time.Time {
	if ms <= 0 {
		return time.Time{}
	}
	value := time.UnixMilli(ms).UTC()
	if diff := value.Sub(now); diff > maxNodeClockSkew || diff < -maxNodeClockSkew {
		return time.Time{}
	}
	return value
}

// maxNodeClockSkew bounds node timestamps Core keeps.
const maxNodeClockSkew = 30 * 24 * time.Hour
