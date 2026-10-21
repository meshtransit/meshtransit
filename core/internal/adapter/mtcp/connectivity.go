package mtcp

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
)

// ConnectivityRecorder stores a Device's latest connectivity report, with
// the platform of its session, for its session (redis.Client).
type ConnectivityRecorder interface {
	RecordConnectivity(ctx context.Context, nodeID node.ID, sessionGeneration int64, report distribution.Connectivity,
		platform *distribution.Platform) (bool, error)
}

// connectivity stores the NAT classification, IPv6 reachability, port
// mapping state and public addresses of an endpoint report (mtcp-v1 §8.1),
// with the platform the ClientHello named, when they changed since the
// last one stored for this session generation: a new generation (a key
// rotation, a new login) starts with an empty record. Unknown codes read
// as unknown.
func (conversation *conversation) connectivity(
	ctx context.Context,
	snapshot mapsession.Snapshot,
	report *mtcpv1.EndpointReport,
	set node.EndpointSet,
	now time.Time,
) {
	recorder := conversation.application.options.Connectivity
	if recorder == nil {
		return
	}
	reported := connectivityOf(report, now)
	reported.PublicAddresses = publicAddressesOf(set)
	generation := snapshot.SessionGeneration()
	if last := conversation.lastConnectivity; last != nil && conversation.lastConnectivityGeneration == generation &&
		last.SameAs(reported) {
		return
	}
	recordCtx, cancel := context.WithTimeout(ctx, pathRecordTimeout)
	defer cancel()
	platform := platformOf(conversation.session.Hello().GetClient())
	stored, err := recorder.RecordConnectivity(recordCtx, snapshot.NodeID(), generation, reported, platform)
	if err != nil {
		conversation.application.options.Logger.DebugContext(ctx, "mtcp connectivity report not stored", "error", err)
		return
	}
	if !stored {
		// The delivery record is not this generation's yet: the next report
		// tries again.
		return
	}
	conversation.lastConnectivity, conversation.lastConnectivityGeneration = &reported, generation
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

// publicAddressesOf returns the distinct public addresses of an endpoint
// report, at most distribution.MaximumPublicAddresses, in address order:
// those STUN saw or a gateway mapped, or, when there are none, those of the
// node's own interfaces. Leaving out interface addresses when the Internet
// already saw the node keeps stable IPv6 interface identifiers (which may
// carry the MAC address) out of Device reads.
func publicAddressesOf(set node.EndpointSet) []netip.Addr {
	var reflexive, local []netip.Addr
	for _, endpoint := range set.Endpoints() {
		address := endpoint.Address().Addr()
		if !distribution.IsPublicAddress(address) {
			continue
		}
		if endpoint.Source() == node.EndpointSourceLocal {
			local = append(local, address)
		} else {
			reflexive = append(reflexive, address)
		}
	}
	candidates := reflexive
	if len(candidates) == 0 {
		candidates = local
	}
	var addresses []netip.Addr
	for _, address := range candidates {
		if len(addresses) < distribution.MaximumPublicAddresses && !slices.Contains(addresses, address) {
			addresses = append(addresses, address)
		}
	}
	slices.SortFunc(addresses, netip.Addr.Compare)
	return addresses
}

// platformOf reads the platform a ClientHello names; nil when it names no
// valid one. The handshake bounds every field.
func platformOf(client *mtcpv1.ClientInfo) *distribution.Platform {
	platform := distribution.Platform{
		OS: strings.ToLower(strings.TrimSpace(client.GetOs())), OSVersion: strings.TrimSpace(client.GetOsVersion()),
		Arch: strings.TrimSpace(client.GetArch()), ClientVersion: strings.TrimSpace(client.GetVersion()),
	}
	if !platform.IsValid() {
		return nil
	}
	return &platform
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
