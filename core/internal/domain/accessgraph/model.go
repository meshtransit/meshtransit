// Package accessgraph owns revision-bound authorization explanations derived
// from effective compiled policy. It never owns packet authority.
package accessgraph

import (
	"errors"
	"net/netip"
	"slices"
	"strings"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/devicetag"
	"meshtransit.net/core/internal/domain/exitpool"
	"meshtransit.net/core/internal/domain/identitygroup"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/resource"
	"meshtransit.net/core/internal/domain/sharing"
	"meshtransit.net/core/internal/domain/site"
	"meshtransit.net/shared/internet"
)

const (
	// MaximumExplanationPaths bounds topology disclosed by one explanation.
	MaximumExplanationPaths = 64
	maximumReaderPaths      = MaximumExplanationPaths + 1
)

var (
	// ErrInvalidQuery reports malformed or ambiguous Access Graph input.
	ErrInvalidQuery = errors.New("access graph: invalid query")
	// ErrInvalidSnapshot reports malformed effective-policy evidence.
	ErrInvalidSnapshot = errors.New("access graph: invalid snapshot")
	// ErrForbidden conceals missing policy.explain authority.
	ErrForbidden = errors.New("access graph: forbidden")
	// ErrUnavailable reports an unavailable authoritative dependency.
	ErrUnavailable = errors.New("access graph: unavailable")
)

// QueryParams contains one bounded network.connect explanation question.
type QueryParams struct {
	Scope                         network.Scope
	SourceNodeID                  node.ID
	DestinationNodeID             node.ID
	DestinationResourceID         resource.ID
	DestinationImportedResourceID sharing.ImportedResourceID
	// DestinationAddress asks about an address inside a Site.
	DestinationAddress netip.Addr
	Protocol           policy.Protocol
	DestinationPort    uint16
}

// Query asks whether one Device can initiate an exact packet action toward one
// Device or Resource in the same Network.
type Query struct {
	scope                         network.Scope
	sourceNodeID                  node.ID
	destinationNodeID             node.ID
	destinationResourceID         resource.ID
	destinationImportedResourceID sharing.ImportedResourceID
	destinationAddress            netip.Addr
	protocol                      policy.Protocol
	destinationPort               uint16
}

// NewQuery validates one exact Device-to-Device or Device-to-Resource question.
func NewQuery(params QueryParams) (Query, error) {
	query := Query{
		scope: params.Scope, sourceNodeID: params.SourceNodeID,
		destinationNodeID:             params.DestinationNodeID,
		destinationResourceID:         params.DestinationResourceID,
		destinationImportedResourceID: params.DestinationImportedResourceID,
		destinationAddress:            params.DestinationAddress,
		protocol:                      params.Protocol, destinationPort: params.DestinationPort,
	}
	if !query.IsValid() {
		return Query{}, ErrInvalidQuery
	}
	return query, nil
}

// Scope returns the exact Workspace-qualified Network scope.
func (query Query) Scope() network.Scope { return query.scope }

// SourceNodeID returns the initiating Device identity.
func (query Query) SourceNodeID() node.ID { return query.sourceNodeID }

// DestinationNodeID returns the queried Device, when selected.
func (query Query) DestinationNodeID() node.ID { return query.destinationNodeID }

// DestinationResourceID returns the queried Resource, when selected.
func (query Query) DestinationResourceID() resource.ID { return query.destinationResourceID }

// DestinationImportedResourceID returns the queried Imported Resource, when selected.
func (query Query) DestinationImportedResourceID() sharing.ImportedResourceID {
	return query.destinationImportedResourceID
}

// DestinationAddress returns the queried Site address, when selected.
func (query Query) DestinationAddress() netip.Addr { return query.destinationAddress }

// Protocol returns the exact packet protocol.
func (query Query) Protocol() policy.Protocol { return query.protocol }

// DestinationPort returns the exact TCP/UDP destination port, or zero for ICMP.
func (query Query) DestinationPort() uint16 { return query.destinationPort }

// IsValid reports whether the query is exact-scoped and unambiguous.
func (query Query) IsValid() bool {
	hasDevice := query.destinationNodeID.IsValid()
	hasResource := query.destinationResourceID.IsValid()
	hasImportedResource := query.destinationImportedResourceID.IsValid()
	hasAddress := query.destinationAddress.IsValid()
	if hasAddress && !validSiteAddress(query.destinationAddress) {
		return false
	}
	selectorCount := 0
	for _, selected := range []bool{hasDevice, hasResource, hasImportedResource, hasAddress} {
		if selected {
			selectorCount++
		}
	}
	if !query.scope.IsValid() || !query.sourceNodeID.IsValid() || selectorCount != 1 ||
		!query.protocol.IsValid() || (hasDevice && query.sourceNodeID == query.destinationNodeID) {
		return false
	}
	if query.protocol == policy.ProtocolICMP {
		return query.destinationPort == 0
	}
	return query.destinationPort > 0
}

// validSiteAddress accepts one unicast address a Site can hold.
func validSiteAddress(address netip.Addr) bool {
	return address == address.Unmap() && address.Zone() == "" && !address.IsUnspecified() &&
		!address.IsMulticast() && !address.IsLoopback()
}

// SelectorKind identifies the authoring selector that produced one compiled edge.
type SelectorKind uint8

const (
	// SelectorKindUnknown is the invalid zero value.
	SelectorKindUnknown SelectorKind = iota
	// SelectorKindDevice identifies a directly selected Device.
	SelectorKindDevice
	// SelectorKindResource identifies a directly selected Resource.
	SelectorKindResource
	// SelectorKindResourceGroup identifies a Resource Group member expansion.
	SelectorKindResourceGroup
	// SelectorKindImportedResource identifies a Device shared into the Network
	// through a Trust Contract. Its path names no consumer-side Device.
	SelectorKindImportedResource
	// SelectorKindSite identifies a rule to a Site. Its path names the Site
	// and the prefixes the rule grants, not a Device.
	SelectorKindSite
	// SelectorKindExitPool identifies a rule to an Exit Pool. Its path names
	// the pool, neither a Device nor a prefix.
	SelectorKindExitPool
)

// String returns the stable wire spelling.
func (kind SelectorKind) String() string {
	switch kind {
	case SelectorKindDevice:
		return "device"
	case SelectorKindResource:
		return "resource"
	case SelectorKindResourceGroup:
		return "resource_group"
	case SelectorKindImportedResource:
		return "imported_resource"
	case SelectorKindSite:
		return "site"
	case SelectorKindExitPool:
		return "exit_pool"
	default:
		return ""
	}
}

// PathParams binds one matching compiled edge to its immutable authoring provenance.
type PathParams struct {
	ProjectionID          publication.ProjectionID
	RuleID                policy.RuleID
	SourceNodeID          node.ID
	DestinationNodeID     node.ID
	Protocol              policy.Protocol
	DestinationPortRanges []policy.PortRange
	SelectorKind          SelectorKind
	DestinationResourceID resource.ID
	DestinationGroupID    resource.GroupID
	// DestinationImportedResourceID and TrustContractID are set only for
	// SelectorKindImportedResource, which leaves DestinationNodeID zero.
	DestinationImportedResourceID sharing.ImportedResourceID
	TrustContractID               sharing.ContractID
	// The selectors a group rule matched through, on a Device path: at
	// most one source (Device Group, Identity Group or tag) and at most one
	// destination (Device Group or tag).
	SourceDeviceGroupID      devicegroup.ID
	SourceIdentityGroupID    identitygroup.ID
	SourceTagID              devicetag.ID
	DestinationDeviceGroupID devicegroup.ID
	DestinationTagID         devicetag.ID
	// DestinationSiteID and DestinationPrefixes are set only for
	// SelectorKindSite: the Site and the prefixes of it the rule grants.
	DestinationSiteID   site.ID
	DestinationPrefixes []netip.Prefix
	// DestinationExitPoolID is set only for SelectorKindExitPool.
	DestinationExitPoolID exitpool.ID
}

// Path explains one effective compiled allow edge.
type Path struct {
	projectionID                  publication.ProjectionID
	ruleID                        policy.RuleID
	sourceNodeID                  node.ID
	destinationNodeID             node.ID
	protocol                      policy.Protocol
	destinationPortRanges         []policy.PortRange
	selectorKind                  SelectorKind
	destinationResourceID         resource.ID
	destinationGroupID            resource.GroupID
	destinationImportedResourceID sharing.ImportedResourceID
	trustContractID               sharing.ContractID
	sourceDeviceGroupID           devicegroup.ID
	sourceIdentityGroupID         identitygroup.ID
	sourceTagID                   devicetag.ID
	destinationDeviceGroupID      devicegroup.ID
	destinationTagID              devicetag.ID
	destinationSiteID             site.ID
	destinationPrefixes           []netip.Prefix
	destinationExitPoolID         exitpool.ID
}

// NewPath validates one immutable explanation path.
func NewPath(params PathParams) (Path, error) {
	path := Path{
		projectionID: params.ProjectionID, ruleID: params.RuleID,
		sourceNodeID: params.SourceNodeID, destinationNodeID: params.DestinationNodeID,
		protocol: params.Protocol, destinationPortRanges: slices.Clone(params.DestinationPortRanges),
		selectorKind: params.SelectorKind, destinationResourceID: params.DestinationResourceID,
		destinationGroupID:            params.DestinationGroupID,
		destinationImportedResourceID: params.DestinationImportedResourceID,
		trustContractID:               params.TrustContractID,
		sourceDeviceGroupID:           params.SourceDeviceGroupID,
		sourceIdentityGroupID:         params.SourceIdentityGroupID,
		sourceTagID:                   params.SourceTagID,
		destinationDeviceGroupID:      params.DestinationDeviceGroupID,
		destinationTagID:              params.DestinationTagID,
		destinationSiteID:             params.DestinationSiteID,
		destinationPrefixes:           slices.Clone(params.DestinationPrefixes),
		destinationExitPoolID:         params.DestinationExitPoolID,
	}
	if !path.IsValid() {
		return Path{}, ErrInvalidSnapshot
	}
	return path, nil
}

// ProjectionID returns the immutable compiled-edge identity.
func (path Path) ProjectionID() publication.ProjectionID { return path.projectionID }

// RuleID returns the stable authoring Access Rule identity.
func (path Path) RuleID() policy.RuleID { return path.ruleID }

// SourceNodeID returns the initiating Device identity.
func (path Path) SourceNodeID() node.ID { return path.sourceNodeID }

// DestinationNodeID returns the resolved destination Device identity.
func (path Path) DestinationNodeID() node.ID { return path.destinationNodeID }

// Protocol returns the exact compiled packet protocol.
func (path Path) Protocol() policy.Protocol { return path.protocol }

// DestinationPortRanges returns caller-owned canonical transport intervals.
func (path Path) DestinationPortRanges() []policy.PortRange {
	return slices.Clone(path.destinationPortRanges)
}

// SelectorKind returns the authoring destination selector type.
func (path Path) SelectorKind() SelectorKind { return path.selectorKind }

// DestinationResourceID returns direct or group-member Resource provenance.
func (path Path) DestinationResourceID() resource.ID { return path.destinationResourceID }

// DestinationGroupID returns Resource Group provenance, when present.
func (path Path) DestinationGroupID() resource.GroupID { return path.destinationGroupID }

// DestinationImportedResourceID returns the shared target, when present.
func (path Path) DestinationImportedResourceID() sharing.ImportedResourceID {
	return path.destinationImportedResourceID
}

// TrustContractID returns the contract that carries a shared path, when present.
func (path Path) TrustContractID() sharing.ContractID { return path.trustContractID }

// SourceDeviceGroupID returns the source Device Group of a group rule path.
func (path Path) SourceDeviceGroupID() devicegroup.ID { return path.sourceDeviceGroupID }

// DestinationDeviceGroupID returns the destination Device Group of a group rule path.
func (path Path) DestinationDeviceGroupID() devicegroup.ID { return path.destinationDeviceGroupID }

// SourceIdentityGroupID returns the source Identity Group of a group rule path.
func (path Path) SourceIdentityGroupID() identitygroup.ID { return path.sourceIdentityGroupID }

// SourceTagID returns the source tag of a group rule path.
func (path Path) SourceTagID() devicetag.ID { return path.sourceTagID }

// DestinationTagID returns the destination tag of a group rule path.
func (path Path) DestinationTagID() devicetag.ID { return path.destinationTagID }

// DestinationSiteID returns the Site of a Site path.
func (path Path) DestinationSiteID() site.ID { return path.destinationSiteID }

// DestinationPrefixes returns the prefixes of the Site a Site path grants.
func (path Path) DestinationPrefixes() []netip.Prefix { return slices.Clone(path.destinationPrefixes) }

// DestinationExitPoolID returns the Exit Pool of an exit path.
func (path Path) DestinationExitPoolID() exitpool.ID { return path.destinationExitPoolID }

// IsValid reports whether one path has complete canonical provenance.
func (path Path) IsValid() bool {
	if !path.projectionID.IsValid() || !path.ruleID.IsValid() || !path.sourceNodeID.IsValid() ||
		!path.protocol.IsValid() || len(path.destinationPortRanges) > policy.MaximumPortRangesPerRule {
		return false
	}
	toSite, toExit := path.selectorKind == SelectorKindSite, path.selectorKind == SelectorKindExitPool
	if toSite != path.destinationSiteID.IsValid() || toSite != (len(path.destinationPrefixes) > 0) ||
		!validSitePrefixes(path.destinationPrefixes) || toExit != path.destinationExitPoolID.IsValid() {
		return false
	}
	shared := path.selectorKind == SelectorKindImportedResource
	if toSite || toExit {
		if path.destinationNodeID.IsValid() || path.destinationImportedResourceID.IsValid() ||
			path.trustContractID.IsValid() {
			return false
		}
	} else if shared {
		if path.destinationNodeID.IsValid() || !path.destinationImportedResourceID.IsValid() ||
			!path.trustContractID.IsValid() {
			return false
		}
	} else if !path.destinationNodeID.IsValid() || path.sourceNodeID == path.destinationNodeID ||
		path.destinationImportedResourceID.IsValid() || path.trustContractID.IsValid() {
		return false
	}
	sources := countValid(path.sourceDeviceGroupID.IsValid(), path.sourceIdentityGroupID.IsValid(),
		path.sourceTagID.IsValid())
	destinations := countValid(path.destinationDeviceGroupID.IsValid(), path.destinationTagID.IsValid())
	if sources > 1 || destinations > 1 || (destinations > 0 && path.selectorKind != SelectorKindDevice) ||
		(sources > 0 && path.selectorKind != SelectorKindDevice && !toSite && !toExit) {
		return false
	}
	switch path.selectorKind {
	case SelectorKindDevice, SelectorKindSite, SelectorKindExitPool:
		if path.destinationResourceID.IsValid() || path.destinationGroupID.IsValid() {
			return false
		}
	case SelectorKindResource:
		if !path.destinationResourceID.IsValid() || path.destinationGroupID.IsValid() {
			return false
		}
	case SelectorKindResourceGroup:
		if !path.destinationResourceID.IsValid() || !path.destinationGroupID.IsValid() {
			return false
		}
	case SelectorKindImportedResource:
		if path.destinationResourceID.IsValid() || path.destinationGroupID.IsValid() {
			return false
		}
	default:
		return false
	}
	if path.protocol == policy.ProtocolICMP {
		return len(path.destinationPortRanges) == 0
	}
	if len(path.destinationPortRanges) == 0 {
		return false
	}
	previousLast := uint16(0)
	for index, portRange := range path.destinationPortRanges {
		if portRange.First() == 0 || portRange.Last() < portRange.First() ||
			(index > 0 && (previousLast == ^uint16(0) || portRange.First() <= previousLast+1)) {
			return false
		}
		previousLast = portRange.Last()
	}
	return true
}

// validSitePrefixes accepts the bounded, masked, distinct prefixes of a path.
func validSitePrefixes(prefixes []netip.Prefix) bool {
	if len(prefixes) > site.MaximumPrefixesPerSite {
		return false
	}
	for index, prefix := range prefixes {
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Zone() != "" ||
			slices.Contains(prefixes[:index], prefix) {
			return false
		}
	}
	return true
}

func (path Path) matches(query Query, snapshot Snapshot) bool {
	if path.sourceNodeID != query.sourceNodeID || path.protocol != query.protocol {
		return false
	}
	if path.selectorKind == SelectorKindSite {
		if path.destinationSiteID != snapshot.targetSiteID ||
			!slices.ContainsFunc(path.destinationPrefixes, func(prefix netip.Prefix) bool {
				return prefix.Contains(query.destinationAddress)
			}) {
			return false
		}
	} else if path.selectorKind == SelectorKindExitPool {
		if path.destinationExitPoolID != snapshot.targetExitPoolID || !internet.Contains(query.destinationAddress) {
			return false
		}
	} else if path.selectorKind == SelectorKindImportedResource {
		if path.destinationImportedResourceID != query.destinationImportedResourceID {
			return false
		}
	} else if path.destinationNodeID != snapshot.targetNodeID {
		return false
	}
	if query.protocol == policy.ProtocolICMP {
		return len(path.destinationPortRanges) == 0
	}
	for _, portRange := range path.destinationPortRanges {
		if query.destinationPort >= portRange.First() && query.destinationPort <= portRange.Last() {
			return true
		}
	}
	return false
}

// SnapshotParams contains one repeatable-read effective-policy graph view.
type SnapshotParams struct {
	Scope                 network.Scope
	NetworkRevision       int64
	InventoryRevision     int64
	GroupRevision         int64
	PolicyRevision        int64
	DNSRevision           int64
	RouteRevision         int64
	SharingRevision       int64
	IsolationGeneration   int64
	HasActiveRelease      bool
	ReleaseID             publication.ReleaseID
	CompilerFormatVersion int
	SemanticHash          publication.SemanticHash
	TargetNodeID          node.ID
	// TargetSiteID is the Site holding the queried address, when one does.
	TargetSiteID site.ID
	// TargetExitPoolID is the Exit Pool an Internet address is reached
	// through, when a pool's rules grant it.
	TargetExitPoolID exitpool.ID
	Paths            []Path
	// Source and Target describe the participants inside the explained
	// Network. TargetKind must match the query. Share is set exactly when the
	// target is an existing shared Device.
	Source     Participant
	TargetKind TargetKind
	Target     Participant
	Share      *ShareContext
}

// Snapshot is one exact revision vector plus matching compiled paths.
type Snapshot struct {
	scope                 network.Scope
	networkRevision       int64
	inventoryRevision     int64
	groupRevision         int64
	policyRevision        int64
	dnsRevision           int64
	routeRevision         int64
	sharingRevision       int64
	isolationGeneration   int64
	hasActiveRelease      bool
	releaseID             publication.ReleaseID
	compilerFormatVersion int
	semanticHash          publication.SemanticHash
	targetNodeID          node.ID
	targetSiteID          site.ID
	targetExitPoolID      exitpool.ID
	paths                 []Path
	source                Participant
	targetKind            TargetKind
	target                Participant
	share                 ShareContext
	hasShare              bool
}

// NewSnapshot validates and canonicalizes authoritative explanation evidence.
func NewSnapshot(params SnapshotParams) (Snapshot, error) {
	paths := clonePaths(params.Paths)
	slices.SortFunc(paths, comparePaths)
	snapshot := Snapshot{
		scope: params.Scope, networkRevision: params.NetworkRevision,
		inventoryRevision: params.InventoryRevision, groupRevision: params.GroupRevision,
		policyRevision: params.PolicyRevision, dnsRevision: params.DNSRevision,
		routeRevision: params.RouteRevision, sharingRevision: params.SharingRevision,
		isolationGeneration: params.IsolationGeneration,
		hasActiveRelease:    params.HasActiveRelease, releaseID: params.ReleaseID,
		compilerFormatVersion: params.CompilerFormatVersion, semanticHash: params.SemanticHash,
		targetNodeID: params.TargetNodeID, targetSiteID: params.TargetSiteID,
		targetExitPoolID: params.TargetExitPoolID, paths: paths,
		source: params.Source, targetKind: params.TargetKind, target: params.Target,
	}
	if params.Share != nil {
		snapshot.share, snapshot.hasShare = *params.Share, true
	}
	if !snapshot.IsValid() {
		return Snapshot{}, ErrInvalidSnapshot
	}
	return snapshot, nil
}

// IsValid reports whether the snapshot is complete and internally consistent.
func (snapshot Snapshot) IsValid() bool {
	if !snapshot.scope.IsValid() || snapshot.networkRevision <= 0 || snapshot.inventoryRevision <= 0 ||
		snapshot.groupRevision <= 0 || snapshot.policyRevision <= 0 || snapshot.dnsRevision <= 0 ||
		snapshot.routeRevision <= 0 || snapshot.sharingRevision <= 0 ||
		snapshot.isolationGeneration <= 0 || snapshot.networkRevision < snapshot.inventoryRevision ||
		snapshot.networkRevision < snapshot.groupRevision || snapshot.networkRevision < snapshot.policyRevision ||
		snapshot.networkRevision < snapshot.dnsRevision || snapshot.networkRevision < snapshot.routeRevision ||
		snapshot.networkRevision < snapshot.sharingRevision || len(snapshot.paths) > maximumReaderPaths {
		return false
	}
	if snapshot.hasActiveRelease {
		if snapshot.policyRevision <= 1 || !snapshot.releaseID.IsValid() || snapshot.compilerFormatVersion <= 0 ||
			snapshot.compilerFormatVersion > publication.MaximumCompilerFormatVersion ||
			!snapshot.semanticHash.IsValid() {
			return false
		}
	} else if snapshot.policyRevision != 1 || snapshot.releaseID.IsValid() || snapshot.compilerFormatVersion != 0 ||
		snapshot.semanticHash.IsValid() || len(snapshot.paths) > 0 {
		return false
	}
	if !snapshot.validContext() {
		return false
	}
	shared := snapshot.targetKind == TargetKindImportedResource
	toSite, toExit := snapshot.targetKind == TargetKindSite, snapshot.targetKind == TargetKindExitPool
	if len(snapshot.paths) > 0 && !shared && !toSite && !toExit && !snapshot.targetNodeID.IsValid() {
		return false
	}
	projectionIDs := make(map[publication.ProjectionID]struct{}, len(snapshot.paths))
	for index, path := range snapshot.paths {
		_, duplicateProjection := projectionIDs[path.projectionID]
		if !path.IsValid() || duplicateProjection ||
			(path.selectorKind == SelectorKindImportedResource) != shared ||
			(path.selectorKind == SelectorKindSite) != toSite ||
			(toSite && path.destinationSiteID != snapshot.targetSiteID) ||
			(path.selectorKind == SelectorKindExitPool) != toExit ||
			(toExit && path.destinationExitPoolID != snapshot.targetExitPoolID) ||
			(shared && path.trustContractID != snapshot.share.contractID) ||
			(index > 0 && comparePaths(snapshot.paths[index-1], path) >= 0) {
			return false
		}
		projectionIDs[path.projectionID] = struct{}{}
	}
	return true
}

// validContext checks participants and share against each other and against
// the paths: a path exists only while the source, the target and any share
// are usable now.
func (snapshot Snapshot) validContext() bool {
	if !snapshot.source.IsValid() || !snapshot.target.IsValid() ||
		snapshot.targetKind == TargetKindUnknown || snapshot.targetKind > TargetKindExitPool {
		return false
	}
	toSite, toExit := snapshot.targetKind == TargetKindSite, snapshot.targetKind == TargetKindExitPool
	if snapshot.targetSiteID.IsValid() != (toSite && snapshot.target.state != ParticipantStateMissing) ||
		snapshot.targetExitPoolID.IsValid() != (toExit && snapshot.target.state != ParticipantStateMissing) ||
		((toSite || toExit) && snapshot.targetNodeID.IsValid()) {
		return false
	}
	shared := snapshot.targetKind == TargetKindImportedResource
	if snapshot.hasShare != (shared && snapshot.target.state != ParticipantStateMissing) ||
		(snapshot.hasShare && !snapshot.share.IsValid()) ||
		(shared && snapshot.targetNodeID.IsValid()) {
		return false
	}
	if len(snapshot.paths) == 0 {
		return true
	}
	return snapshot.source.state == ParticipantStateActive && snapshot.target.state == ParticipantStateActive &&
		(!shared || snapshot.share.state == sharing.ContractStateActive)
}

// Scope returns the exact graph scope.
func (snapshot Snapshot) Scope() network.Scope { return snapshot.scope }

// RevisionVector returns the complete authority state used by this snapshot.
func (snapshot Snapshot) RevisionVector() RevisionVector {
	vector, _ := NewRevisionVector(RevisionVectorParams{
		NetworkRevision: snapshot.networkRevision, InventoryRevision: snapshot.inventoryRevision,
		GroupRevision: snapshot.groupRevision, PolicyRevision: snapshot.policyRevision,
		DNSRevision: snapshot.dnsRevision, RouteRevision: snapshot.routeRevision,
		SharingRevision: snapshot.sharingRevision, IsolationGeneration: snapshot.isolationGeneration,
	})
	return vector
}

// NetworkRevision returns the authority revision observed by the read.
func (snapshot Snapshot) NetworkRevision() int64 { return snapshot.networkRevision }

// InventoryRevision returns the Resource revision observed by the read.
func (snapshot Snapshot) InventoryRevision() int64 { return snapshot.inventoryRevision }

// GroupRevision returns the Resource Group revision observed by the read.
func (snapshot Snapshot) GroupRevision() int64 { return snapshot.groupRevision }

// PolicyRevision returns the active effective-policy revision.
func (snapshot Snapshot) PolicyRevision() int64 { return snapshot.policyRevision }

// DNSRevision returns the DNS authority revision observed by the read.
func (snapshot Snapshot) DNSRevision() int64 { return snapshot.dnsRevision }

// RouteRevision returns the route authority revision observed by the read.
func (snapshot Snapshot) RouteRevision() int64 { return snapshot.routeRevision }

// SharingRevision returns the sharing authority revision observed by the read.
func (snapshot Snapshot) SharingRevision() int64 { return snapshot.sharingRevision }

// IsolationGeneration returns the isolation authority generation observed by the read.
func (snapshot Snapshot) IsolationGeneration() int64 { return snapshot.isolationGeneration }

// ActiveRelease returns immutable release evidence and whether it exists.
func (snapshot Snapshot) ActiveRelease() (
	publication.ReleaseID,
	int,
	publication.SemanticHash,
	bool,
) {
	return snapshot.releaseID, snapshot.compilerFormatVersion, snapshot.semanticHash, snapshot.hasActiveRelease
}

// TargetNodeID returns the active Device resolved for the requested target, when present.
func (snapshot Snapshot) TargetNodeID() node.ID { return snapshot.targetNodeID }

// TargetSiteID returns the Site holding the queried address, when present.
func (snapshot Snapshot) TargetSiteID() site.ID { return snapshot.targetSiteID }

// TargetExitPoolID returns the Exit Pool an Internet address is reached
// through, when present.
func (snapshot Snapshot) TargetExitPoolID() exitpool.ID { return snapshot.targetExitPoolID }

// Paths returns caller-owned canonical matching paths.
func (snapshot Snapshot) Paths() []Path { return clonePaths(snapshot.paths) }

// Source returns the source Device as seen in the explained Network.
func (snapshot Snapshot) Source() Participant { return snapshot.source }

// TargetKind returns what the explained connection is aimed at.
func (snapshot Snapshot) TargetKind() TargetKind { return snapshot.targetKind }

// Target returns the target as seen in the explained Network.
func (snapshot Snapshot) Target() Participant { return snapshot.target }

// Share returns the contract context of a shared target and whether it exists.
func (snapshot Snapshot) Share() (ShareContext, bool) { return snapshot.share, snapshot.hasShare }

func clonePaths(paths []Path) []Path {
	cloned := make([]Path, len(paths))
	for index, path := range paths {
		cloned[index] = path
		cloned[index].destinationPortRanges = slices.Clone(path.destinationPortRanges)
		cloned[index].destinationPrefixes = slices.Clone(path.destinationPrefixes)
	}
	return cloned
}

func comparePaths(first, second Path) int {
	if comparison := strings.Compare(first.ruleID.String(), second.ruleID.String()); comparison != 0 {
		return comparison
	}
	if comparison := strings.Compare(first.destinationNodeID.String(), second.destinationNodeID.String()); comparison != 0 {
		return comparison
	}
	return strings.Compare(first.projectionID.String(), second.projectionID.String())
}

// Decision is the effective network.connect outcome.
type Decision uint8

const (
	// DecisionUnknown is the invalid zero value.
	DecisionUnknown Decision = iota
	// DecisionDeny reports default deny.
	DecisionDeny
	// DecisionAllow reports at least one matching active edge.
	DecisionAllow
)

// String returns the stable wire spelling.
func (decision Decision) String() string {
	switch decision {
	case DecisionDeny:
		return "deny"
	case DecisionAllow:
		return "allow"
	default:
		return ""
	}
}

// Reason is the stable explanation classification.
type Reason uint8

const (
	// ReasonUnknown is the invalid zero value.
	ReasonUnknown Reason = iota
	// ReasonNoMatchingActiveRule classifies default deny.
	ReasonNoMatchingActiveRule
	// ReasonMatchingActiveRule classifies an allow backed by active edges.
	ReasonMatchingActiveRule
)

// String returns the stable wire spelling.
func (reason Reason) String() string {
	switch reason {
	case ReasonNoMatchingActiveRule:
		return "no_matching_active_rule"
	case ReasonMatchingActiveRule:
		return "matching_active_rule"
	default:
		return ""
	}
}

// Result is one bounded, revision-bound effective-policy explanation.
type Result struct {
	query      Query
	snapshot   Snapshot
	decision   Decision
	reason     Reason
	denyReason DenyReason
	paths      []Path
	truncated  bool
}

func newResult(query Query, snapshot Snapshot) (Result, error) {
	if !query.IsValid() || !snapshot.IsValid() || snapshot.scope != query.scope ||
		!query.allowsTargetKind(snapshot.targetKind) {
		return Result{}, ErrInvalidSnapshot
	}
	if query.destinationNodeID.IsValid() && snapshot.targetNodeID.IsValid() &&
		snapshot.targetNodeID != query.destinationNodeID {
		return Result{}, ErrInvalidSnapshot
	}
	paths := snapshot.Paths()
	for _, path := range paths {
		if !path.matches(query, snapshot) {
			return Result{}, ErrInvalidSnapshot
		}
	}
	truncated := len(paths) > MaximumExplanationPaths
	if truncated {
		paths = paths[:MaximumExplanationPaths]
	}
	decision, reason, denyReason := DecisionDeny, ReasonNoMatchingActiveRule, denyReasonFor(snapshot)
	if len(paths) > 0 {
		decision, reason, denyReason = DecisionAllow, ReasonMatchingActiveRule, DenyReasonUnknown
	}
	return Result{
		query: query, snapshot: snapshot, decision: decision, reason: reason, denyReason: denyReason,
		paths: clonePaths(paths), truncated: truncated,
	}, nil
}

// IsValid reports whether the result is internally consistent.
func (result Result) IsValid() bool {
	if !result.query.IsValid() || !result.snapshot.IsValid() ||
		(result.decision != DecisionAllow && result.decision != DecisionDeny) ||
		(result.reason != ReasonMatchingActiveRule && result.reason != ReasonNoMatchingActiveRule) ||
		len(result.paths) > MaximumExplanationPaths {
		return false
	}
	allowed := len(result.paths) > 0
	return (result.decision == DecisionAllow) == allowed &&
		(result.reason == ReasonMatchingActiveRule) == allowed &&
		(result.denyReason == DenyReasonUnknown) == allowed &&
		result.denyReason <= DenyReasonNoMatchingActiveRule
}

// Query returns the exact explanation question.
func (result Result) Query() Query { return result.query }

// Snapshot returns the exact authority evidence used for the decision.
func (result Result) Snapshot() Snapshot { return result.snapshot }

// Decision returns allow or deny.
func (result Result) Decision() Decision { return result.decision }

// Reason returns the stable explanation classification.
func (result Result) Reason() Reason { return result.reason }

// DenyReason returns why the connection is denied, and false for an allow.
func (result Result) DenyReason() (DenyReason, bool) {
	return result.denyReason, result.decision == DecisionDeny
}

// Paths returns caller-owned matching paths.
func (result Result) Paths() []Path { return clonePaths(result.paths) }

// Truncated reports whether more matching paths existed than the response bound.
func (result Result) Truncated() bool { return result.truncated }

func countValid(values ...bool) int {
	count := 0
	for _, value := range values {
		if value {
			count++
		}
	}
	return count
}
