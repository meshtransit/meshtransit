// Package accessgraph owns revision-bound authorization explanations derived
// from effective compiled policy. It never owns packet authority.
package accessgraph

import (
	"errors"
	"slices"
	"strings"

	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/resource"
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
	Scope                 network.Scope
	SourceNodeID          node.ID
	DestinationNodeID     node.ID
	DestinationResourceID resource.ID
	Protocol              policy.Protocol
	DestinationPort       uint16
}

// Query asks whether one Device can initiate an exact packet action toward one
// Device or Resource in the same Network.
type Query struct {
	scope                 network.Scope
	sourceNodeID          node.ID
	destinationNodeID     node.ID
	destinationResourceID resource.ID
	protocol              policy.Protocol
	destinationPort       uint16
}

// NewQuery validates one exact Device-to-Device or Device-to-Resource question.
func NewQuery(params QueryParams) (Query, error) {
	query := Query{
		scope: params.Scope, sourceNodeID: params.SourceNodeID,
		destinationNodeID:     params.DestinationNodeID,
		destinationResourceID: params.DestinationResourceID,
		protocol:              params.Protocol, destinationPort: params.DestinationPort,
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

// Protocol returns the exact packet protocol.
func (query Query) Protocol() policy.Protocol { return query.protocol }

// DestinationPort returns the exact TCP/UDP destination port, or zero for ICMP.
func (query Query) DestinationPort() uint16 { return query.destinationPort }

// IsValid reports whether the query is exact-scoped and unambiguous.
func (query Query) IsValid() bool {
	hasDevice := query.destinationNodeID.IsValid()
	hasResource := query.destinationResourceID.IsValid()
	if !query.scope.IsValid() || !query.sourceNodeID.IsValid() || hasDevice == hasResource ||
		!query.protocol.IsValid() || (hasDevice && query.sourceNodeID == query.destinationNodeID) {
		return false
	}
	if query.protocol == policy.ProtocolICMP {
		return query.destinationPort == 0
	}
	return query.destinationPort > 0
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
}

// Path explains one effective compiled allow edge.
type Path struct {
	projectionID          publication.ProjectionID
	ruleID                policy.RuleID
	sourceNodeID          node.ID
	destinationNodeID     node.ID
	protocol              policy.Protocol
	destinationPortRanges []policy.PortRange
	selectorKind          SelectorKind
	destinationResourceID resource.ID
	destinationGroupID    resource.GroupID
}

// NewPath validates one immutable explanation path.
func NewPath(params PathParams) (Path, error) {
	path := Path{
		projectionID: params.ProjectionID, ruleID: params.RuleID,
		sourceNodeID: params.SourceNodeID, destinationNodeID: params.DestinationNodeID,
		protocol: params.Protocol, destinationPortRanges: slices.Clone(params.DestinationPortRanges),
		selectorKind: params.SelectorKind, destinationResourceID: params.DestinationResourceID,
		destinationGroupID: params.DestinationGroupID,
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

// IsValid reports whether one path has complete canonical provenance.
func (path Path) IsValid() bool {
	if !path.projectionID.IsValid() || !path.ruleID.IsValid() || !path.sourceNodeID.IsValid() ||
		!path.destinationNodeID.IsValid() || path.sourceNodeID == path.destinationNodeID ||
		!path.protocol.IsValid() || len(path.destinationPortRanges) > policy.MaximumPortRangesPerRule {
		return false
	}
	switch path.selectorKind {
	case SelectorKindDevice:
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

func (path Path) matches(query Query, targetNodeID node.ID) bool {
	if path.sourceNodeID != query.sourceNodeID || path.destinationNodeID != targetNodeID ||
		path.protocol != query.protocol {
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
	Paths                 []Path
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
	paths                 []Path
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
		targetNodeID: params.TargetNodeID, paths: paths,
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
	if len(snapshot.paths) > 0 && !snapshot.targetNodeID.IsValid() {
		return false
	}
	projectionIDs := make(map[publication.ProjectionID]struct{}, len(snapshot.paths))
	for index, path := range snapshot.paths {
		_, duplicateProjection := projectionIDs[path.projectionID]
		if !path.IsValid() || duplicateProjection ||
			(index > 0 && comparePaths(snapshot.paths[index-1], path) >= 0) {
			return false
		}
		projectionIDs[path.projectionID] = struct{}{}
	}
	return true
}

// Scope returns the exact graph scope.
func (snapshot Snapshot) Scope() network.Scope { return snapshot.scope }

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

// Paths returns caller-owned canonical matching paths.
func (snapshot Snapshot) Paths() []Path { return clonePaths(snapshot.paths) }

func clonePaths(paths []Path) []Path {
	cloned := make([]Path, len(paths))
	for index, path := range paths {
		cloned[index] = path
		cloned[index].destinationPortRanges = slices.Clone(path.destinationPortRanges)
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
	query     Query
	snapshot  Snapshot
	decision  Decision
	reason    Reason
	paths     []Path
	truncated bool
}

func newResult(query Query, snapshot Snapshot) (Result, error) {
	if !query.IsValid() || !snapshot.IsValid() || snapshot.scope != query.scope {
		return Result{}, ErrInvalidSnapshot
	}
	if query.destinationNodeID.IsValid() && snapshot.targetNodeID.IsValid() &&
		snapshot.targetNodeID != query.destinationNodeID {
		return Result{}, ErrInvalidSnapshot
	}
	paths := snapshot.Paths()
	for _, path := range paths {
		if !path.matches(query, snapshot.targetNodeID) {
			return Result{}, ErrInvalidSnapshot
		}
	}
	truncated := len(paths) > MaximumExplanationPaths
	if truncated {
		paths = paths[:MaximumExplanationPaths]
	}
	decision, reason := DecisionDeny, ReasonNoMatchingActiveRule
	if len(paths) > 0 {
		decision, reason = DecisionAllow, ReasonMatchingActiveRule
	}
	return Result{
		query: query, snapshot: snapshot, decision: decision, reason: reason,
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
	return (result.decision == DecisionAllow) == (len(result.paths) > 0) &&
		(result.reason == ReasonMatchingActiveRule) == (len(result.paths) > 0)
}

// Query returns the exact explanation question.
func (result Result) Query() Query { return result.query }

// Snapshot returns the exact authority evidence used for the decision.
func (result Result) Snapshot() Snapshot { return result.snapshot }

// Decision returns allow or deny.
func (result Result) Decision() Decision { return result.decision }

// Reason returns the stable explanation classification.
func (result Result) Reason() Reason { return result.reason }

// Paths returns caller-owned matching paths.
func (result Result) Paths() []Path { return clonePaths(result.paths) }

// Truncated reports whether more matching paths existed than the response bound.
func (result Result) Truncated() bool { return result.truncated }
