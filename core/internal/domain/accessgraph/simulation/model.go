// Package simulation owns compiler-identical, revision-bound policy impact previews.
// It is read-only and never publishes policy authority.
package simulation

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"

	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/resource"
)

const (
	// MaximumReportedRelationships bounds each added or removed relationship list.
	MaximumReportedRelationships = 256
	// MaximumReportedExplanations bounds each added or removed explanation list.
	MaximumReportedExplanations = 256
	// MaximumReportedEntities bounds each affected-entity list.
	MaximumReportedEntities = 256
)

var (
	// ErrInvalidRequest reports malformed or inconsistent simulation intent.
	ErrInvalidRequest = errors.New("policy simulation: invalid request")
	// ErrInvalidBaseline reports malformed active-policy or revision evidence.
	ErrInvalidBaseline = errors.New("policy simulation: invalid baseline")
	// ErrInvalidResult reports compiler output or impact evidence that failed closed validation.
	ErrInvalidResult = errors.New("policy simulation: invalid result")
	// ErrStaleInputs reports authority changes while a draft was compiled.
	ErrStaleInputs = errors.New("policy simulation: stale inputs")
	// ErrForbidden conceals missing policy.validate authority.
	ErrForbidden = errors.New("policy simulation: forbidden")
	// ErrUnavailable reports a missing or unavailable simulation dependency.
	ErrUnavailable = errors.New("policy simulation: unavailable")
	// ErrTooLarge reports Device Groups or group rules too large to compare
	// Device pair by Device pair.
	ErrTooLarge = errors.New("policy simulation: too large to simulate")
)

// MaximumResolvedRelationships bounds the Device pairs one candidate may
// expand to when group rules are resolved for a simulation.
const MaximumResolvedRelationships = 200_000

// BaselineParams contains the complete current effective-policy evidence.
type BaselineParams struct {
	Scope            network.Scope
	RevisionVector   accessgraph.RevisionVector
	HasActiveRelease bool
	ReleaseID        publication.ReleaseID
	SemanticHash     publication.SemanticHash
	Candidate        publication.Candidate
	// SelectorMembers are the live Devices of every Device Group, Identity
	// Group and tag of the Network that has any, used to resolve group rules
	// of the baseline and the draft. A selector that is absent has none.
	SelectorMembers map[publication.RuleSide][]node.ID
}

// Baseline is one immutable active release plus its complete authority vector.
// Before the first publication, Candidate is the canonical empty format-v1 policy.
type Baseline struct {
	scope            network.Scope
	revisionVector   accessgraph.RevisionVector
	hasActiveRelease bool
	releaseID        publication.ReleaseID
	semanticHash     publication.SemanticHash
	candidate        publication.Candidate
	selectorMembers  map[publication.RuleSide][]node.ID
}

// NewBaseline validates current effective-policy evidence.
func NewBaseline(params BaselineParams) (Baseline, error) {
	members := make(map[publication.RuleSide][]node.ID, len(params.SelectorMembers))
	for side, devices := range params.SelectorMembers {
		if !side.IsValid() || side.Kind() == publication.SideDevice {
			return Baseline{}, ErrInvalidBaseline
		}
		members[side] = slices.Clone(devices)
	}
	baseline := Baseline{
		scope: params.Scope, revisionVector: params.RevisionVector,
		hasActiveRelease: params.HasActiveRelease, releaseID: params.ReleaseID,
		semanticHash: params.SemanticHash, candidate: params.Candidate, selectorMembers: members,
	}
	if !baseline.IsValid() {
		return Baseline{}, ErrInvalidBaseline
	}
	return baseline, nil
}

// Scope returns the exact Workspace-qualified Network scope.
func (baseline Baseline) Scope() network.Scope { return baseline.scope }

// RevisionVector returns the complete current authority vector.
func (baseline Baseline) RevisionVector() accessgraph.RevisionVector {
	return baseline.revisionVector
}

// ActiveRelease returns immutable release identity, semantic hash, and presence.
func (baseline Baseline) ActiveRelease() (
	publication.ReleaseID,
	publication.SemanticHash,
	bool,
) {
	return baseline.releaseID, baseline.semanticHash, baseline.hasActiveRelease
}

// Candidate returns the current effective compiled policy.
func (baseline Baseline) Candidate() publication.Candidate { return baseline.candidate }

// IsValid reports whether release, compiled policy, and revision evidence agree.
func (baseline Baseline) IsValid() bool {
	if !baseline.scope.IsValid() || !baseline.revisionVector.IsValid() ||
		!baseline.candidate.IsValid() || baseline.candidate.Snapshot().Scope() != baseline.scope ||
		baseline.candidate.Snapshot().Revision() != baseline.revisionVector.PolicyRevision() {
		return false
	}
	if baseline.hasActiveRelease {
		return baseline.releaseID.IsValid() && baseline.semanticHash.IsValid() &&
			baseline.semanticHash == baseline.candidate.SemanticHash() &&
			baseline.revisionVector.PolicyRevision() > 1
	}
	return !baseline.releaseID.IsValid() && !baseline.semanticHash.IsValid() &&
		baseline.revisionVector.PolicyRevision() == 1 &&
		baseline.candidate.CompilerFormatVersion() == 1 &&
		len(baseline.candidate.Snapshot().Rules()) == 0 &&
		len(baseline.candidate.ResourceDestinations()) == 0 &&
		len(baseline.candidate.ResourceGroupDestinations()) == 0
}

// Equal reports whether two reads observed the same complete authority state.
func (baseline Baseline) Equal(other Baseline) bool {
	return baseline.IsValid() && other.IsValid() && baseline.scope == other.scope &&
		baseline.revisionVector.Equal(other.revisionVector) &&
		baseline.hasActiveRelease == other.hasActiveRelease && baseline.releaseID == other.releaseID &&
		baseline.semanticHash == other.semanticHash &&
		baseline.candidate.CompilerFormatVersion() == other.candidate.CompilerFormatVersion() &&
		baseline.candidate.SemanticHash() == other.candidate.SemanticHash()
}

// Relationship is one effective packet authorization interval. Rule identity
// and authoring provenance are intentionally represented by Explanation.
type Relationship struct {
	sourceNodeID      node.ID
	destinationNodeID node.ID
	protocol          policy.Protocol
	firstPort         uint16
	lastPort          uint16
}

func newRelationship(
	sourceNodeID node.ID,
	destinationNodeID node.ID,
	protocol policy.Protocol,
	firstPort uint16,
	lastPort uint16,
) (Relationship, error) {
	relationship := Relationship{
		sourceNodeID: sourceNodeID, destinationNodeID: destinationNodeID,
		protocol: protocol, firstPort: firstPort, lastPort: lastPort,
	}
	if !relationship.IsValid() {
		return Relationship{}, ErrInvalidResult
	}
	return relationship, nil
}

// SourceNodeID returns the initiating Device identity.
func (relationship Relationship) SourceNodeID() node.ID { return relationship.sourceNodeID }

// DestinationNodeID returns the destination Device identity.
func (relationship Relationship) DestinationNodeID() node.ID {
	return relationship.destinationNodeID
}

// Protocol returns the exact packet protocol.
func (relationship Relationship) Protocol() policy.Protocol { return relationship.protocol }

// DestinationPortRange returns the changed inclusive interval and whether ports apply.
func (relationship Relationship) DestinationPortRange() (uint16, uint16, bool) {
	return relationship.firstPort, relationship.lastPort, relationship.protocol != policy.ProtocolICMP
}

// IsValid reports whether the effective relationship is exact and unambiguous.
func (relationship Relationship) IsValid() bool {
	if !relationship.sourceNodeID.IsValid() || !relationship.destinationNodeID.IsValid() ||
		relationship.sourceNodeID == relationship.destinationNodeID || !relationship.protocol.IsValid() {
		return false
	}
	if relationship.protocol == policy.ProtocolICMP {
		return relationship.firstPort == 0 && relationship.lastPort == 0
	}
	return relationship.firstPort > 0 && relationship.lastPort >= relationship.firstPort
}

// Explanation is one compiled rule path with exact Resource and Group provenance.
type Explanation struct {
	scope                 network.Scope
	ruleID                policy.RuleID
	sourceNodeID          node.ID
	destinationNodeID     node.ID
	protocol              policy.Protocol
	destinationPortRanges []policy.PortRange
	selectorKind          accessgraph.SelectorKind
	resourceID            resource.ID
	resourceVersion       int64
	targetGeneration      int64
	inventoryRevision     int64
	resourceSemanticHash  resource.SemanticHash
	groupID               resource.GroupID
	groupVersion          int64
	definitionVersion     int64
	groupRevision         int64
	groupSemanticHash     resource.SemanticHash
}

// RuleID returns the stable Access Rule identity.
func (explanation Explanation) RuleID() policy.RuleID { return explanation.ruleID }

// Scope returns the exact Workspace-qualified Network scope.
func (explanation Explanation) Scope() network.Scope { return explanation.scope }

// SourceNodeID returns the initiating Device identity.
func (explanation Explanation) SourceNodeID() node.ID { return explanation.sourceNodeID }

// DestinationNodeID returns the compiled destination Device identity.
func (explanation Explanation) DestinationNodeID() node.ID { return explanation.destinationNodeID }

// Protocol returns the exact packet protocol.
func (explanation Explanation) Protocol() policy.Protocol { return explanation.protocol }

// DestinationPortRanges returns caller-owned canonical intervals.
func (explanation Explanation) DestinationPortRanges() []policy.PortRange {
	return slices.Clone(explanation.destinationPortRanges)
}

// SelectorKind returns the authoring destination selector type.
func (explanation Explanation) SelectorKind() accessgraph.SelectorKind {
	return explanation.selectorKind
}

// ResourceEvidence returns Resource provenance and whether it applies.
func (explanation Explanation) ResourceEvidence() (
	resource.ID,
	int64,
	int64,
	int64,
	resource.SemanticHash,
	bool,
) {
	found := explanation.resourceID.IsValid()
	return explanation.resourceID, explanation.resourceVersion, explanation.targetGeneration,
		explanation.inventoryRevision, explanation.resourceSemanticHash, found
}

// GroupEvidence returns Resource Group provenance and whether it applies.
func (explanation Explanation) GroupEvidence() (
	resource.GroupID,
	int64,
	int64,
	int64,
	resource.SemanticHash,
	bool,
) {
	found := explanation.groupID.IsValid()
	return explanation.groupID, explanation.groupVersion, explanation.definitionVersion,
		explanation.groupRevision, explanation.groupSemanticHash, found
}

// IsValid reports whether authoring and compiled provenance are complete.
func (explanation Explanation) IsValid() bool {
	rule, err := policy.NewRule(policy.RuleParams{
		ID: explanation.ruleID, Scope: explanation.scope,
		SourceNodeID: explanation.sourceNodeID, DestinationNodeID: explanation.destinationNodeID,
		Protocol: explanation.protocol, DestinationPortRanges: explanation.destinationPortRanges,
	})
	if err != nil || !rule.IsValid() {
		return false
	}
	resourceValid := explanation.resourceID.IsValid() && explanation.resourceVersion > 0 &&
		explanation.targetGeneration > 0 && explanation.inventoryRevision > 0 &&
		explanation.resourceSemanticHash.IsValid()
	groupValid := explanation.groupID.IsValid() && explanation.groupVersion > 0 &&
		explanation.definitionVersion > 0 && explanation.groupRevision > 0 &&
		explanation.groupSemanticHash.IsValid()
	switch explanation.selectorKind {
	case accessgraph.SelectorKindDevice:
		return !resourceValid && !groupValid && explanation.emptyProvenance()
	case accessgraph.SelectorKindResource:
		return resourceValid && !groupValid && !explanation.groupID.IsValid() &&
			explanation.groupVersion == 0 && explanation.definitionVersion == 0 &&
			explanation.groupRevision == 0 && !explanation.groupSemanticHash.IsValid()
	case accessgraph.SelectorKindResourceGroup:
		return resourceValid && groupValid
	default:
		return false
	}
}

func (explanation Explanation) emptyProvenance() bool {
	return !explanation.resourceID.IsValid() && explanation.resourceVersion == 0 &&
		explanation.targetGeneration == 0 && explanation.inventoryRevision == 0 &&
		!explanation.resourceSemanticHash.IsValid() && !explanation.groupID.IsValid() &&
		explanation.groupVersion == 0 && explanation.definitionVersion == 0 &&
		explanation.groupRevision == 0 && !explanation.groupSemanticHash.IsValid()
}

// UnsupportedCapability identifies an input dimension not represented by the
// current publication compiler. It prevents a narrow preview from claiming full assurance.
type UnsupportedCapability uint8

const (
	// UnsupportedCapabilityUnknown is the invalid zero value.
	UnsupportedCapabilityUnknown UnsupportedCapability = iota
	// UnsupportedCapabilityPrincipalProjection reports missing Principal-to-Device expansion.
	UnsupportedCapabilityPrincipalProjection
	// UnsupportedCapabilitySensitiveResourceClassification reports missing sensitivity classes.
	UnsupportedCapabilitySensitiveResourceClassification
	// UnsupportedCapabilityCrossScopeRelationships reports missing cross-Network/Workspace paths.
	UnsupportedCapabilityCrossScopeRelationships
	// UnsupportedCapabilityGuardrailEvaluation reports missing policy Guardrail evaluation.
	UnsupportedCapabilityGuardrailEvaluation
	// UnsupportedCapabilityShareIntersection reports missing share-policy intersection.
	UnsupportedCapabilityShareIntersection
	// UnsupportedCapabilityRoutedServiceResources reports missing routed/service Resource semantics.
	UnsupportedCapabilityRoutedServiceResources
)

// String returns the stable wire spelling.
func (capability UnsupportedCapability) String() string {
	switch capability {
	case UnsupportedCapabilityPrincipalProjection:
		return "principal_projection"
	case UnsupportedCapabilitySensitiveResourceClassification:
		return "sensitive_resource_classification"
	case UnsupportedCapabilityCrossScopeRelationships:
		return "cross_scope_relationships"
	case UnsupportedCapabilityGuardrailEvaluation:
		return "guardrail_evaluation"
	case UnsupportedCapabilityShareIntersection:
		return "share_intersection"
	case UnsupportedCapabilityRoutedServiceResources:
		return "routed_service_resources"
	default:
		return ""
	}
}

func (capability UnsupportedCapability) isValid() bool {
	return capability >= UnsupportedCapabilityPrincipalProjection &&
		capability <= UnsupportedCapabilityRoutedServiceResources
}

// ImpactHash is the canonical digest of complete, untruncated simulation evidence.
type ImpactHash [sha256.Size]byte

// NewImpactHash validates a non-zero digest loaded at a boundary.
func NewImpactHash(value [sha256.Size]byte) (ImpactHash, error) {
	hash := ImpactHash(value)
	if !hash.IsValid() {
		return ImpactHash{}, ErrInvalidResult
	}
	return hash, nil
}

// Bytes returns a defensive copy of the digest.
func (hash ImpactHash) Bytes() [sha256.Size]byte { return [sha256.Size]byte(hash) }

// IsValid reports whether impact evidence is present.
func (hash ImpactHash) IsValid() bool { return hash != ImpactHash{} }

// Result is a deterministic, read-only before/after policy impact.
type Result struct {
	baseline               Baseline
	proposedCandidate      publication.Candidate
	proposedVector         accessgraph.RevisionVector
	addedRelationships     []Relationship
	removedRelationships   []Relationship
	addedExplanations      []Explanation
	removedExplanations    []Explanation
	addedImportedIntents   []publication.ImportedResourceDestination
	removedImportedIntents []publication.ImportedResourceDestination
	affectedDevices        []node.ID
	affectedResources      []resource.ID
	affectedGroups         []resource.GroupID
	unsupported            []UnsupportedCapability
	hash                   ImpactHash
	peers                  PeerEstimate // not part of the impact hash
}

// Peers estimates how many peers the proposed policy puts in each map.
func (result Result) Peers() PeerEstimate { return result.peers }

// IsValid reports whether the immutable result and its canonical digest agree.
func (result Result) IsValid() bool {
	if !result.baseline.IsValid() || !result.proposedCandidate.IsValid() ||
		!result.proposedVector.IsValid() ||
		result.proposedCandidate.Snapshot().Scope() != result.baseline.scope ||
		result.proposedCandidate.Snapshot().Revision() != result.proposedVector.PolicyRevision() ||
		!validRelationships(result.addedRelationships) ||
		!validRelationships(result.removedRelationships) ||
		!validExplanations(result.addedExplanations) ||
		!validExplanations(result.removedExplanations) ||
		!validImportedIntents(result.addedImportedIntents, result.baseline.scope) ||
		!validImportedIntents(result.removedImportedIntents, result.baseline.scope) ||
		!validNodeIDs(result.affectedDevices) || !validResourceIDs(result.affectedResources) ||
		!validGroupIDs(result.affectedGroups) || !validCapabilities(result.unsupported) ||
		!result.hash.IsValid() {
		return false
	}
	expectedVector, err := result.baseline.revisionVector.NextPolicy()
	return err == nil && expectedVector.Equal(result.proposedVector) &&
		result.hash == hashResult(result)
}

// Baseline returns the exact current evidence.
func (result Result) Baseline() Baseline { return result.baseline }

// ProposedCandidate returns the compiler-produced draft artifact.
func (result Result) ProposedCandidate() publication.Candidate { return result.proposedCandidate }

// ProposedRevisionVector returns the expected vector after an unchanged publication.
func (result Result) ProposedRevisionVector() accessgraph.RevisionVector {
	return result.proposedVector
}

// ImpactHash returns the complete untruncated evidence digest.
func (result Result) ImpactHash() ImpactHash { return result.hash }

// AddedRelationshipCount returns the complete added relationship count.
func (result Result) AddedRelationshipCount() int { return len(result.addedRelationships) }

// AddedRelationships returns a bounded canonical prefix.
func (result Result) AddedRelationships() []Relationship {
	return boundedClone(result.addedRelationships, MaximumReportedRelationships)
}

// RemovedRelationshipCount returns the complete removed relationship count.
func (result Result) RemovedRelationshipCount() int { return len(result.removedRelationships) }

// RemovedRelationships returns a bounded canonical prefix.
func (result Result) RemovedRelationships() []Relationship {
	return boundedClone(result.removedRelationships, MaximumReportedRelationships)
}

// AddedExplanationCount returns the complete added explanation count.
func (result Result) AddedExplanationCount() int { return len(result.addedExplanations) }

// AddedExplanations returns a bounded canonical prefix.
func (result Result) AddedExplanations() []Explanation {
	return cloneExplanations(boundedClone(result.addedExplanations, MaximumReportedExplanations))
}

// RemovedExplanationCount returns the complete removed explanation count.
func (result Result) RemovedExplanationCount() int { return len(result.removedExplanations) }

// RemovedExplanations returns a bounded canonical prefix.
func (result Result) RemovedExplanations() []Explanation {
	return cloneExplanations(boundedClone(result.removedExplanations, MaximumReportedExplanations))
}

// AddedImportedIntentCount returns the complete added bilateral-intent count.
func (result Result) AddedImportedIntentCount() int { return len(result.addedImportedIntents) }

// AddedImportedIntents returns bounded Consumer-local intents, never packet edges.
func (result Result) AddedImportedIntents() []publication.ImportedResourceDestination {
	return boundedClone(result.addedImportedIntents, MaximumReportedExplanations)
}

// RemovedImportedIntentCount returns the complete removed bilateral-intent count.
func (result Result) RemovedImportedIntentCount() int { return len(result.removedImportedIntents) }

// RemovedImportedIntents returns bounded old intent and its immutable provenance.
func (result Result) RemovedImportedIntents() []publication.ImportedResourceDestination {
	return boundedClone(result.removedImportedIntents, MaximumReportedExplanations)
}

// AffectedDeviceCount returns the complete affected Device count.
func (result Result) AffectedDeviceCount() int { return len(result.affectedDevices) }

// AffectedDevices returns a bounded canonical prefix.
func (result Result) AffectedDevices() []node.ID {
	return boundedClone(result.affectedDevices, MaximumReportedEntities)
}

// AffectedResourceCount returns the complete affected Resource count.
func (result Result) AffectedResourceCount() int { return len(result.affectedResources) }

// AffectedResources returns a bounded canonical prefix.
func (result Result) AffectedResources() []resource.ID {
	return boundedClone(result.affectedResources, MaximumReportedEntities)
}

// AffectedGroupCount returns the complete affected Resource Group count.
func (result Result) AffectedGroupCount() int { return len(result.affectedGroups) }

// AffectedGroups returns a bounded canonical prefix.
func (result Result) AffectedGroups() []resource.GroupID {
	return boundedClone(result.affectedGroups, MaximumReportedEntities)
}

// UnsupportedCapabilities returns the explicit canonical capability gaps.
func (result Result) UnsupportedCapabilities() []UnsupportedCapability {
	return slices.Clone(result.unsupported)
}

// Truncated reports whether any public evidence list is a bounded prefix.
func (result Result) Truncated() bool {
	return len(result.addedRelationships) > MaximumReportedRelationships ||
		len(result.removedRelationships) > MaximumReportedRelationships ||
		len(result.addedExplanations) > MaximumReportedExplanations ||
		len(result.removedExplanations) > MaximumReportedExplanations ||
		len(result.addedImportedIntents) > MaximumReportedExplanations ||
		len(result.removedImportedIntents) > MaximumReportedExplanations ||
		len(result.affectedDevices) > MaximumReportedEntities ||
		len(result.affectedResources) > MaximumReportedEntities ||
		len(result.affectedGroups) > MaximumReportedEntities
}

// StaleInputs reports whether this successful result used stale authority.
func (Result) StaleInputs() bool { return false }

// Uncertain reports whether supported compiler dimensions were evaluated uncertainly.
func (Result) Uncertain() bool { return false }

func cloneExplanations(values []Explanation) []Explanation {
	cloned := make([]Explanation, len(values))
	for index, value := range values {
		cloned[index] = value
		cloned[index].destinationPortRanges = slices.Clone(value.destinationPortRanges)
	}
	return cloned
}

func boundedClone[T any](values []T, limit int) []T {
	return slices.Clone(values[:min(len(values), limit)])
}

func compareRelationships(first, second Relationship) int {
	if comparison := strings.Compare(first.sourceNodeID.String(), second.sourceNodeID.String()); comparison != 0 {
		return comparison
	}
	if comparison := strings.Compare(first.destinationNodeID.String(), second.destinationNodeID.String()); comparison != 0 {
		return comparison
	}
	if first.protocol != second.protocol {
		return int(first.protocol) - int(second.protocol)
	}
	if first.firstPort != second.firstPort {
		return int(first.firstPort) - int(second.firstPort)
	}
	return int(first.lastPort) - int(second.lastPort)
}

func compareExplanations(first, second Explanation) int {
	for _, comparison := range [...]int{
		strings.Compare(first.scope.WorkspaceID().String(), second.scope.WorkspaceID().String()),
		strings.Compare(first.scope.NetworkID().String(), second.scope.NetworkID().String()),
		strings.Compare(first.ruleID.String(), second.ruleID.String()),
		strings.Compare(first.sourceNodeID.String(), second.sourceNodeID.String()),
		strings.Compare(first.destinationNodeID.String(), second.destinationNodeID.String()),
	} {
		if comparison != 0 {
			return comparison
		}
	}
	if first.protocol != second.protocol {
		return int(first.protocol) - int(second.protocol)
	}
	if comparison := comparePortRangeSlices(first.destinationPortRanges, second.destinationPortRanges); comparison != 0 {
		return comparison
	}
	if first.selectorKind != second.selectorKind {
		return int(first.selectorKind) - int(second.selectorKind)
	}
	for _, comparison := range [...]int{
		strings.Compare(first.resourceID.String(), second.resourceID.String()),
		compareInt64(first.resourceVersion, second.resourceVersion),
		compareInt64(first.targetGeneration, second.targetGeneration),
		compareInt64(first.inventoryRevision, second.inventoryRevision),
		compareResourceSemanticHashes(first.resourceSemanticHash, second.resourceSemanticHash),
		strings.Compare(first.groupID.String(), second.groupID.String()),
		compareInt64(first.groupVersion, second.groupVersion),
		compareInt64(first.definitionVersion, second.definitionVersion),
		compareInt64(first.groupRevision, second.groupRevision),
		compareResourceSemanticHashes(first.groupSemanticHash, second.groupSemanticHash),
	} {
		if comparison != 0 {
			return comparison
		}
	}
	return 0
}

func comparePortRangeSlices(first, second []policy.PortRange) int {
	for index := range min(len(first), len(second)) {
		if first[index].First() != second[index].First() {
			return int(first[index].First()) - int(second[index].First())
		}
		if first[index].Last() != second[index].Last() {
			return int(first[index].Last()) - int(second[index].Last())
		}
	}
	return len(first) - len(second)
}

func compareInt64(first, second int64) int {
	switch {
	case first < second:
		return -1
	case first > second:
		return 1
	default:
		return 0
	}
}

func compareResourceSemanticHashes(first, second resource.SemanticHash) int {
	firstBytes := first.Bytes()
	secondBytes := second.Bytes()
	return bytes.Compare(firstBytes[:], secondBytes[:])
}

func validRelationships(values []Relationship) bool {
	for index, value := range values {
		if !value.IsValid() || index > 0 && compareRelationships(values[index-1], value) >= 0 {
			return false
		}
	}
	return values != nil
}

func validExplanations(values []Explanation) bool {
	for index, value := range values {
		if !value.IsValid() || index > 0 && compareExplanations(values[index-1], value) >= 0 {
			return false
		}
	}
	return values != nil
}

func validNodeIDs(values []node.ID) bool {
	for index, value := range values {
		if !value.IsValid() || index > 0 && values[index-1].String() >= value.String() {
			return false
		}
	}
	return values != nil
}

func validResourceIDs(values []resource.ID) bool {
	for index, value := range values {
		if !value.IsValid() || index > 0 && values[index-1].String() >= value.String() {
			return false
		}
	}
	return values != nil
}

func validGroupIDs(values []resource.GroupID) bool {
	for index, value := range values {
		if !value.IsValid() || index > 0 && values[index-1].String() >= value.String() {
			return false
		}
	}
	return values != nil
}

func validCapabilities(values []UnsupportedCapability) bool {
	for index, value := range values {
		if !value.isValid() || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return len(values) > 0
}
