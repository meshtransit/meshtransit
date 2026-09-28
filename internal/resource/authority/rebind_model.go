package authority

import (
	"crypto/sha256"
	"errors"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/idempotency"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/resource"
)

const (
	rebindImpactHashDomain  = "meshtransit/resource-rebind-impact/v1\x00"
	rebindRequestHashDomain = "meshtransit/resource-rebind-request/v1\x00"
	// MaximumRebindAffectedGroups bounds impact disclosure and hashing work.
	MaximumRebindAffectedGroups = 256
)

var (
	// ErrInvalidRebindPreview reports incomplete preview authority.
	ErrInvalidRebindPreview = errors.New("resource rebind: invalid preview")
	// ErrInvalidRebindImpact reports inconsistent impact evidence.
	ErrInvalidRebindImpact = errors.New("resource rebind: invalid impact")
	// ErrInvalidRebindCommand reports incomplete mutation authority.
	ErrInvalidRebindCommand = errors.New("resource rebind: invalid command")
	// ErrInvalidRebindResolution reports inconsistent locked authority.
	ErrInvalidRebindResolution = errors.New("resource rebind: invalid resolution")
	// ErrInvalidRebindChange reports inconsistent atomic mutation evidence.
	ErrInvalidRebindChange = errors.New("resource rebind: invalid change")
	// ErrInvalidRebindResult reports malformed committed evidence.
	ErrInvalidRebindResult = errors.New("resource rebind: invalid result")
	// ErrRebindNotFound hides absent and cross-scope Resource or Device identities.
	ErrRebindNotFound = errors.New("resource rebind: authority unavailable")
	// ErrRebindVersionConflict reports a stale Resource version precondition.
	ErrRebindVersionConflict = errors.New("resource rebind: stale Resource version")
	// ErrRebindTargetConflict reports an unchanged or already-bound Device target.
	ErrRebindTargetConflict = errors.New("resource rebind: target conflict")
	// ErrRebindStateConflict reports a terminal Resource or inactive Device.
	ErrRebindStateConflict = errors.New("resource rebind: state conflict")
	// ErrRebindImpactChanged reports that the acknowledged preview is stale.
	ErrRebindImpactChanged = errors.New("resource rebind: impact changed")
	// ErrRebindImpactTooLarge reports impact outside the bounded preview contract.
	ErrRebindImpactTooLarge = errors.New("resource rebind: impact exceeds limit")
	// ErrRebindApprovalRequired fails closed until durable approval evidence exists.
	ErrRebindApprovalRequired = errors.New("resource rebind: approval required")
)

// RebindPreview is one authenticated, version-bound impact request.
type RebindPreview struct {
	scope           network.Scope
	resourceID      resource.ID
	expectedVersion int64
	deviceID        node.ID
	accountSession  accountsession.Session
}

// NewRebindPreview validates one target-rebinding impact request.
func NewRebindPreview(
	scope network.Scope,
	resourceID resource.ID,
	expectedVersion int64,
	deviceID node.ID,
	session accountsession.Session,
) (RebindPreview, error) {
	preview := RebindPreview{
		scope: scope, resourceID: resourceID, expectedVersion: expectedVersion,
		deviceID: deviceID, accountSession: session,
	}
	if !preview.IsValid() {
		return RebindPreview{}, ErrInvalidRebindPreview
	}
	return preview, nil
}

// Scope returns the exact home Network scope.
func (preview RebindPreview) Scope() network.Scope { return preview.scope }

// ResourceID returns the stable Resource identity.
func (preview RebindPreview) ResourceID() resource.ID { return preview.resourceID }

// ExpectedVersion returns the Resource CAS base.
func (preview RebindPreview) ExpectedVersion() int64 { return preview.expectedVersion }

// DeviceID returns the proposed Device target.
func (preview RebindPreview) DeviceID() node.ID { return preview.deviceID }

// AccountSession returns current management authentication evidence.
func (preview RebindPreview) AccountSession() accountsession.Session { return preview.accountSession }

// IsValid reports whether the preview is safe to evaluate.
func (preview RebindPreview) IsValid() bool {
	return preview.scope.IsValid() && preview.resourceID.IsValid() &&
		preview.expectedVersion > 0 && preview.expectedVersion < math.MaxInt64 &&
		preview.deviceID.IsValid() && preview.accountSession.IsValid()
}

// RebindImpactParams contains authoritative state used to construct one impact preview.
type RebindImpactParams struct {
	ResourceID              resource.ID
	ExpectedVersion         int64
	CurrentDeviceID         node.ID
	CurrentTargetGeneration int64
	CurrentSemanticHash     resource.SemanticHash
	ProposedRevision        resource.DeviceRevision
	AffectedGroupIDs        []resource.GroupID
	ApprovalRequired        bool
}

// RebindImpact is deterministic preview evidence that must be acknowledged by apply.
type RebindImpact struct {
	resourceID              resource.ID
	expectedVersion         int64
	currentDeviceID         node.ID
	currentTargetGeneration int64
	currentSemanticHash     resource.SemanticHash
	proposedRevision        resource.DeviceRevision
	affectedGroupIDs        []resource.GroupID
	approvalRequired        bool
	hash                    RebindImpactHash
}

// NewRebindImpact validates, canonicalizes, and hashes one preview.
func NewRebindImpact(params RebindImpactParams) (RebindImpact, error) {
	groupIDs := slices.Clone(params.AffectedGroupIDs)
	slices.SortFunc(groupIDs, func(left, right resource.GroupID) int {
		return strings.Compare(left.String(), right.String())
	})
	impact := RebindImpact{
		resourceID: params.ResourceID, expectedVersion: params.ExpectedVersion,
		currentDeviceID:         params.CurrentDeviceID,
		currentTargetGeneration: params.CurrentTargetGeneration,
		currentSemanticHash:     params.CurrentSemanticHash,
		proposedRevision:        params.ProposedRevision, affectedGroupIDs: groupIDs,
		approvalRequired: params.ApprovalRequired,
	}
	if !validRebindImpactFields(impact) {
		return RebindImpact{}, ErrInvalidRebindImpact
	}
	impact.hash = hashRebindImpact(impact)
	return impact, nil
}

// ResourceID returns the stable affected Resource identity.
func (impact RebindImpact) ResourceID() resource.ID { return impact.resourceID }

// ExpectedVersion returns the Resource version used by the preview.
func (impact RebindImpact) ExpectedVersion() int64 { return impact.expectedVersion }

// CurrentDeviceID returns the currently active target.
func (impact RebindImpact) CurrentDeviceID() node.ID { return impact.currentDeviceID }

// CurrentTargetGeneration returns the target generation replaced by apply.
func (impact RebindImpact) CurrentTargetGeneration() int64 {
	return impact.currentTargetGeneration
}

// CurrentSemanticHash returns the before-state semantic digest.
func (impact RebindImpact) CurrentSemanticHash() resource.SemanticHash {
	return impact.currentSemanticHash
}

// ProposedRevision returns the complete proposed Device-backed semantics.
func (impact RebindImpact) ProposedRevision() resource.DeviceRevision {
	return impact.proposedRevision
}

// AffectedGroupIDs returns a caller-owned canonical list of pinned current definitions.
func (impact RebindImpact) AffectedGroupIDs() []resource.GroupID {
	return slices.Clone(impact.affectedGroupIDs)
}

// ApprovalRequired reports whether durable approval evidence must precede apply.
func (impact RebindImpact) ApprovalRequired() bool { return impact.approvalRequired }

// Hash returns the exact preview acknowledgement digest.
func (impact RebindImpact) Hash() RebindImpactHash { return impact.hash }

// IsValid reports whether the impact fields and digest agree.
func (impact RebindImpact) IsValid() bool {
	return validRebindImpactFields(impact) && impact.hash.IsValid() &&
		impact.hash == hashRebindImpact(impact)
}

// Equal reports exact deterministic impact equality.
func (impact RebindImpact) Equal(other RebindImpact) bool {
	return impact.IsValid() && other.IsValid() && impact.hash == other.hash
}

func validRebindImpactFields(impact RebindImpact) bool {
	if !impact.resourceID.IsValid() || impact.expectedVersion <= 0 ||
		impact.expectedVersion == math.MaxInt64 || !impact.currentDeviceID.IsValid() ||
		!impact.currentSemanticHash.IsValid() || !impact.proposedRevision.IsValid() ||
		impact.currentDeviceID == impact.proposedRevision.DeviceID() ||
		impact.currentSemanticHash == impact.proposedRevision.SemanticHash() ||
		impact.currentTargetGeneration <= 0 || impact.currentTargetGeneration == math.MaxInt64 ||
		impact.proposedRevision.TargetGeneration() != impact.currentTargetGeneration+1 ||
		len(impact.affectedGroupIDs) > MaximumRebindAffectedGroups {
		return false
	}
	for index, groupID := range impact.affectedGroupIDs {
		if !groupID.IsValid() || (index > 0 && impact.affectedGroupIDs[index-1].String() >= groupID.String()) {
			return false
		}
	}
	return true
}

func hashRebindImpact(impact RebindImpact) RebindImpactHash {
	material := make([]byte, 0, 512+len(impact.affectedGroupIDs)*16)
	material = append(material, rebindImpactHashDomain...)
	for _, value := range [...]string{
		impact.proposedRevision.Scope().WorkspaceID().String(),
		impact.proposedRevision.Scope().NetworkID().String(),
		impact.resourceID.String(), impact.currentDeviceID.String(),
		impact.proposedRevision.DeviceID().String(),
	} {
		material = appendAuthorityText(material, value)
	}
	material = appendAuthorityInt64(material, impact.expectedVersion)
	material = appendAuthorityInt64(material, impact.currentTargetGeneration)
	material = appendAuthorityInt64(material, impact.proposedRevision.TargetGeneration())
	currentHash := impact.currentSemanticHash.Bytes()
	proposedHash := impact.proposedRevision.SemanticHash().Bytes()
	material = append(material, currentHash[:]...)
	material = append(material, proposedHash[:]...)
	if impact.approvalRequired {
		material = append(material, 1)
	} else {
		material = append(material, 0)
	}
	material = appendAuthorityInt64(material, int64(len(impact.affectedGroupIDs)))
	for _, groupID := range impact.affectedGroupIDs {
		value := publicid.ID(groupID).Bytes()
		material = append(material, value[:]...)
	}
	return RebindImpactHash(sha256.Sum256(material))
}

// RebindImpactHash is deterministic acknowledgement evidence for one preview.
type RebindImpactHash [sha256.Size]byte

// NewRebindImpactHash validates a non-zero digest from a boundary.
func NewRebindImpactHash(value [sha256.Size]byte) (RebindImpactHash, error) {
	hash := RebindImpactHash(value)
	if !hash.IsValid() {
		return RebindImpactHash{}, ErrInvalidRebindImpact
	}
	return hash, nil
}

// Bytes returns a defensive copy of the digest.
func (hash RebindImpactHash) Bytes() [sha256.Size]byte { return [sha256.Size]byte(hash) }

// IsValid reports whether acknowledgement evidence is present.
func (hash RebindImpactHash) IsValid() bool { return hash != RebindImpactHash{} }

// RebindCommand is one authenticated mutation bound to an exact preview.
type RebindCommand struct {
	preview             RebindPreview
	impactHash          RebindImpactHash
	auditReason         AuditReason
	idempotencyEvidence idempotency.Proof
}

// NewRebindCommand validates one target-rebinding mutation.
func NewRebindCommand(
	preview RebindPreview,
	impactHash RebindImpactHash,
	reason AuditReason,
	evidence idempotency.Proof,
) (RebindCommand, error) {
	command := RebindCommand{
		preview: preview, impactHash: impactHash, auditReason: reason,
		idempotencyEvidence: evidence,
	}
	if !command.IsValid() {
		return RebindCommand{}, ErrInvalidRebindCommand
	}
	return command, nil
}

// Preview returns the immutable target and version intent.
func (command RebindCommand) Preview() RebindPreview { return command.preview }

// Scope returns the exact home Network scope.
func (command RebindCommand) Scope() network.Scope { return command.preview.Scope() }

// ResourceID returns the stable Resource identity.
func (command RebindCommand) ResourceID() resource.ID { return command.preview.ResourceID() }

// ExpectedVersion returns the Resource CAS base.
func (command RebindCommand) ExpectedVersion() int64 { return command.preview.ExpectedVersion() }

// DeviceID returns the proposed target Device.
func (command RebindCommand) DeviceID() node.ID { return command.preview.DeviceID() }

// AccountSession returns current management authentication evidence.
func (command RebindCommand) AccountSession() accountsession.Session {
	return command.preview.AccountSession()
}

// ImpactHash returns the exact acknowledged preview digest.
func (command RebindCommand) ImpactHash() RebindImpactHash { return command.impactHash }

// AuditReason returns the explicit mutation explanation.
func (command RebindCommand) AuditReason() AuditReason { return command.auditReason }

// IdempotencyEvidence returns secret-safe replay evidence.
func (command RebindCommand) IdempotencyEvidence() idempotency.Proof {
	return command.idempotencyEvidence
}

// RequestHash binds one idempotency key to exact rebinding semantics.
func (command RebindCommand) RequestHash() (RebindRequestHash, error) {
	if !command.IsValid() {
		return RebindRequestHash{}, ErrInvalidRebindCommand
	}
	material := make([]byte, 0, 384)
	material = append(material, rebindRequestHashDomain...)
	for _, value := range [...]string{
		command.Scope().WorkspaceID().String(), command.Scope().NetworkID().String(),
		command.ResourceID().String(), command.DeviceID().String(),
		command.AccountSession().ID().String(), command.AccountSession().PrincipalID().String(),
		command.auditReason.String(),
	} {
		material = appendAuthorityText(material, value)
	}
	material = appendAuthorityInt64(material, command.ExpectedVersion())
	impactHash := command.impactHash.Bytes()
	material = append(material, impactHash[:]...)
	return NewRebindRequestHash(sha256.Sum256(material))
}

// IsValid reports whether mutation inputs are complete and bounded.
func (command RebindCommand) IsValid() bool {
	return command.preview.IsValid() && command.impactHash.IsValid() &&
		command.auditReason.IsValid() && command.idempotencyEvidence.IsValid()
}

// RebindRequestHash is deterministic idempotency evidence.
type RebindRequestHash [sha256.Size]byte

// NewRebindRequestHash validates a non-zero request digest.
func NewRebindRequestHash(value [sha256.Size]byte) (RebindRequestHash, error) {
	hash := RebindRequestHash(value)
	if !hash.IsValid() {
		return RebindRequestHash{}, ErrInvalidRebindCommand
	}
	return hash, nil
}

// Bytes returns a defensive copy of the digest.
func (hash RebindRequestHash) Bytes() [sha256.Size]byte { return [sha256.Size]byte(hash) }

// IsValid reports whether request evidence is present.
func (hash RebindRequestHash) IsValid() bool { return hash != RebindRequestHash{} }

// RebindResolution is revision and impact authority observed under locks.
type RebindResolution struct {
	scope               network.Scope
	networkRevision     int64
	inventoryRevision   int64
	groupRevision       int64
	idempotencyRecordID publicid.ID
	requestHash         RebindRequestHash
	impact              RebindImpact
	completed           RebindResult
}

// NewRebindResolution validates locked revision and impact evidence.
func NewRebindResolution(
	scope network.Scope,
	networkRevision, inventoryRevision, groupRevision int64,
	idempotencyRecordID publicid.ID,
	requestHash RebindRequestHash,
	impact RebindImpact,
) (RebindResolution, error) {
	resolution := RebindResolution{
		scope: scope, networkRevision: networkRevision, inventoryRevision: inventoryRevision,
		groupRevision: groupRevision, idempotencyRecordID: idempotencyRecordID,
		requestHash: requestHash, impact: impact,
	}
	if !resolution.IsValid() {
		return RebindResolution{}, ErrInvalidRebindResolution
	}
	return resolution, nil
}

// NewCompletedRebindResolution validates immutable replay evidence.
func NewCompletedRebindResolution(
	result RebindResult,
	idempotencyRecordID publicid.ID,
	requestHash RebindRequestHash,
) (RebindResolution, error) {
	resolution := RebindResolution{
		scope: result.Scope(), idempotencyRecordID: idempotencyRecordID,
		requestHash: requestHash, completed: result,
	}
	if !resolution.IsValid() {
		return RebindResolution{}, ErrInvalidRebindResolution
	}
	return resolution, nil
}

// Scope returns exact locked scope.
func (resolution RebindResolution) Scope() network.Scope { return resolution.scope }

// NetworkRevision returns the current client-visible revision.
func (resolution RebindResolution) NetworkRevision() int64 { return resolution.networkRevision }

// InventoryRevision returns current Resource inventory authority.
func (resolution RebindResolution) InventoryRevision() int64 { return resolution.inventoryRevision }

// GroupRevision returns current Resource Group authority observed for impact.
func (resolution RebindResolution) GroupRevision() int64 { return resolution.groupRevision }

// IdempotencyRecordID returns durable replay identity.
func (resolution RebindResolution) IdempotencyRecordID() publicid.ID {
	return resolution.idempotencyRecordID
}

// RequestHash returns exact idempotent request semantics.
func (resolution RebindResolution) RequestHash() RebindRequestHash { return resolution.requestHash }

// Impact returns the recomputed locked impact.
func (resolution RebindResolution) Impact() RebindImpact { return resolution.impact }

// CompletedResult returns replayed committed evidence, if present.
func (resolution RebindResolution) CompletedResult() RebindResult { return resolution.completed }

// IsCompleted reports whether this is immutable replay evidence.
func (resolution RebindResolution) IsCompleted() bool { return resolution.completed.IsValid() }

// Equal reports exact deterministic resolution equality.
func (resolution RebindResolution) Equal(other RebindResolution) bool {
	if !resolution.IsValid() || !other.IsValid() {
		return false
	}
	if resolution.IsCompleted() || other.IsCompleted() {
		return resolution.completed == other.completed && resolution.scope == other.scope &&
			resolution.idempotencyRecordID == other.idempotencyRecordID &&
			resolution.requestHash == other.requestHash
	}
	return resolution.scope == other.scope && resolution.networkRevision == other.networkRevision &&
		resolution.inventoryRevision == other.inventoryRevision &&
		resolution.groupRevision == other.groupRevision &&
		resolution.idempotencyRecordID == other.idempotencyRecordID &&
		resolution.requestHash == other.requestHash && resolution.impact.Equal(other.impact)
}

// IsValid reports whether all monotonic revisions and evidence are coherent.
func (resolution RebindResolution) IsValid() bool {
	if !resolution.scope.IsValid() || !resolution.idempotencyRecordID.IsValid() ||
		!resolution.requestHash.IsValid() {
		return false
	}
	if resolution.completed.IsValid() {
		return resolution.completed.Scope() == resolution.scope && resolution.networkRevision == 0 &&
			resolution.inventoryRevision == 0 && resolution.groupRevision == 0 && !resolution.impact.IsValid()
	}
	return resolution.networkRevision > 0 && resolution.inventoryRevision > 0 &&
		resolution.groupRevision > 0 && resolution.networkRevision >= resolution.inventoryRevision &&
		resolution.networkRevision >= resolution.groupRevision && resolution.impact.IsValid() &&
		resolution.impact.ProposedRevision().Scope() == resolution.scope &&
		!resolution.impact.ApprovalRequired()
}

// RebindChange is one validated, replayable atomic target replacement.
type RebindChange struct {
	command     RebindCommand
	resolution  RebindResolution
	mutationIDs RebindMutationIDs
	occurredAt  time.Time
	expiresAt   time.Time
}

// NewRebindChange validates CAS, stable IDs, and decision time.
func NewRebindChange(
	command RebindCommand,
	resolution RebindResolution,
	mutationIDs RebindMutationIDs,
	occurredAt, expiresAt time.Time,
) (RebindChange, error) {
	change := RebindChange{
		command: command, resolution: resolution, mutationIDs: mutationIDs,
		occurredAt: occurredAt.UTC(), expiresAt: expiresAt.UTC(),
	}
	if !change.IsValid() {
		return RebindChange{}, ErrInvalidRebindChange
	}
	return change, nil
}

// Command returns the immutable request.
func (change RebindChange) Command() RebindCommand { return change.command }

// Resolution returns locked authority and impact.
func (change RebindChange) Resolution() RebindResolution { return change.resolution }

// MutationIDs returns stable durable identities.
func (change RebindChange) MutationIDs() RebindMutationIDs { return change.mutationIDs }

// OccurredAt returns one stable decision time shared across retries.
func (change RebindChange) OccurredAt() time.Time { return change.occurredAt }

// ExpiresAt returns the exclusive durable replay-window bound.
func (change RebindChange) ExpiresAt() time.Time { return change.expiresAt }

// IsValid reports whether all atomic facts agree.
func (change RebindChange) IsValid() bool {
	return change.command.IsValid() && change.resolution.IsValid() &&
		change.mutationIDs.IsValid() && change.command.Scope() == change.resolution.Scope() &&
		!change.resolution.IsCompleted() && change.command.ImpactHash() == change.resolution.Impact().Hash() &&
		change.command.ResourceID() == change.resolution.Impact().ResourceID() &&
		change.command.ExpectedVersion() == change.resolution.Impact().ExpectedVersion() &&
		change.command.DeviceID() == change.resolution.Impact().ProposedRevision().DeviceID() &&
		!change.occurredAt.IsZero() && change.expiresAt.After(change.occurredAt)
}

// RebindResult is safe committed target-replacement evidence.
type RebindResult struct {
	resourceID        resource.ID
	scope             network.Scope
	deviceID          node.ID
	targetGeneration  int64
	version           int64
	networkRevision   int64
	inventoryRevision int64
	semanticHash      resource.SemanticHash
	impactHash        RebindImpactHash
}

// NewRebindResult validates committed target-replacement evidence.
func NewRebindResult(
	resourceID resource.ID,
	scope network.Scope,
	deviceID node.ID,
	targetGeneration, version, networkRevision, inventoryRevision int64,
	semanticHash resource.SemanticHash,
	impactHash RebindImpactHash,
) (RebindResult, error) {
	result := RebindResult{
		resourceID: resourceID, scope: scope, deviceID: deviceID,
		targetGeneration: targetGeneration, version: version,
		networkRevision: networkRevision, inventoryRevision: inventoryRevision,
		semanticHash: semanticHash, impactHash: impactHash,
	}
	if !result.IsValid() {
		return RebindResult{}, ErrInvalidRebindResult
	}
	return result, nil
}

// ResourceID returns the stable rebound Resource identity.
func (result RebindResult) ResourceID() resource.ID { return result.resourceID }

// Scope returns committed exact scope.
func (result RebindResult) Scope() network.Scope { return result.scope }

// DeviceID returns the new active Device target.
func (result RebindResult) DeviceID() node.ID { return result.deviceID }

// TargetGeneration returns the new binding generation.
func (result RebindResult) TargetGeneration() int64 { return result.targetGeneration }

// Version returns the new Resource authority version.
func (result RebindResult) Version() int64 { return result.version }

// NetworkRevision returns the new client-visible revision.
func (result RebindResult) NetworkRevision() int64 { return result.networkRevision }

// InventoryRevision returns the new Resource inventory revision.
func (result RebindResult) InventoryRevision() int64 { return result.inventoryRevision }

// SemanticHash returns the after-state semantic digest.
func (result RebindResult) SemanticHash() resource.SemanticHash { return result.semanticHash }

// ImpactHash returns the exact preview digest applied by the mutation.
func (result RebindResult) ImpactHash() RebindImpactHash { return result.impactHash }

// IsValid reports whether committed evidence is complete and coherent.
func (result RebindResult) IsValid() bool {
	return result.resourceID.IsValid() && result.scope.IsValid() && result.deviceID.IsValid() &&
		result.targetGeneration > 1 && result.version > 1 && result.networkRevision > 1 &&
		result.inventoryRevision > 1 && result.networkRevision >= result.inventoryRevision &&
		result.semanticHash.IsValid() && result.impactHash.IsValid()
}
