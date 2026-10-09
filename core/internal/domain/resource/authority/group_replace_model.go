package authority

import (
	"crypto/sha256"
	"errors"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/resource"
	"github.com/meshtransit/meshtransit/core/internal/platform/idempotency"
)

const (
	groupReplaceImpactHashDomain  = "meshtransit/resource-group-replace-impact/v1\x00"
	groupReplaceRequestHashDomain = "meshtransit/resource-group-replace-request/v1\x00"
)

var (
	// ErrInvalidGroupReplacePreview reports incomplete replacement preview authority.
	ErrInvalidGroupReplacePreview = errors.New("resource group replace: invalid preview")
	// ErrInvalidGroupReplaceImpact reports inconsistent impact evidence.
	ErrInvalidGroupReplaceImpact = errors.New("resource group replace: invalid impact")
	// ErrInvalidGroupReplaceCommand reports incomplete mutation authority.
	ErrInvalidGroupReplaceCommand = errors.New("resource group replace: invalid command")
	// ErrInvalidGroupReplaceResolution reports inconsistent locked authority.
	ErrInvalidGroupReplaceResolution = errors.New("resource group replace: invalid resolution")
	// ErrInvalidGroupReplaceChange reports inconsistent atomic mutation evidence.
	ErrInvalidGroupReplaceChange = errors.New("resource group replace: invalid change")
	// ErrInvalidGroupReplaceResult reports malformed committed evidence.
	ErrInvalidGroupReplaceResult = errors.New("resource group replace: invalid result")
	// ErrGroupReplaceNotFound hides absent and cross-scope identities.
	ErrGroupReplaceNotFound = errors.New("resource group replace: authority unavailable")
	// ErrGroupReplaceVersionConflict reports a stale Resource Group version precondition.
	ErrGroupReplaceVersionConflict = errors.New("resource group replace: stale Resource Group version")
	// ErrGroupReplaceMemberConflict reports unavailable or stale pinned membership.
	ErrGroupReplaceMemberConflict = errors.New("resource group replace: member conflict")
	// ErrGroupReplaceStateConflict reports terminal Resource Group authority.
	ErrGroupReplaceStateConflict = errors.New("resource group replace: state conflict")
	// ErrGroupReplaceNoChange reports semantically unchanged replacement intent.
	ErrGroupReplaceNoChange = errors.New("resource group replace: unchanged definition")
	// ErrGroupReplaceImpactChanged reports stale acknowledged impact.
	ErrGroupReplaceImpactChanged = errors.New("resource group replace: impact changed")
	// ErrGroupReplaceApprovalRequired fails closed until durable approval evidence exists.
	ErrGroupReplaceApprovalRequired = errors.New("resource group replace: approval required")
)

// GroupReplacePreview is one authenticated, version-bound replacement preview.
type GroupReplacePreview struct {
	scope           network.Scope
	groupID         resource.GroupID
	expectedVersion int64
	members         []resource.Reference
	accountSession  accountsession.Session
}

// NewGroupReplacePreview validates and canonicalizes replacement intent.
func NewGroupReplacePreview(
	scope network.Scope,
	groupID resource.GroupID,
	expectedVersion int64,
	members []resource.Reference,
	session accountsession.Session,
) (GroupReplacePreview, error) {
	canonical := slices.Clone(members)
	slices.SortFunc(canonical, func(left, right resource.Reference) int {
		return strings.Compare(left.ResourceID().String(), right.ResourceID().String())
	})
	preview := GroupReplacePreview{
		scope: scope, groupID: groupID, expectedVersion: expectedVersion,
		members: canonical, accountSession: session,
	}
	if !preview.IsValid() {
		return GroupReplacePreview{}, ErrInvalidGroupReplacePreview
	}
	return preview, nil
}

// Scope returns the exact home Network scope.
func (preview GroupReplacePreview) Scope() network.Scope { return preview.scope }

// GroupID returns the stable Resource Group identity.
func (preview GroupReplacePreview) GroupID() resource.GroupID { return preview.groupID }

// ExpectedVersion returns the Resource Group aggregate CAS base.
func (preview GroupReplacePreview) ExpectedVersion() int64 { return preview.expectedVersion }

// Members returns caller-owned canonical proposed membership.
func (preview GroupReplacePreview) Members() []resource.Reference {
	return slices.Clone(preview.members)
}

// AccountSession returns current management authentication evidence.
func (preview GroupReplacePreview) AccountSession() accountsession.Session {
	return preview.accountSession
}

// IsValid reports whether preview intent is complete and bounded.
func (preview GroupReplacePreview) IsValid() bool {
	return preview.scope.IsValid() && preview.groupID.IsValid() && preview.expectedVersion > 0 &&
		preview.expectedVersion < math.MaxInt64 && preview.accountSession.IsValid() &&
		validGroupReplaceMembers(preview.scope, preview.members)
}

func validGroupReplaceMembers(scope network.Scope, members []resource.Reference) bool {
	if !scope.IsValid() || len(members) == 0 || len(members) > resource.MaximumGroupMembers {
		return false
	}
	for index, member := range members {
		if !member.IsValid() || member.Scope() != scope ||
			(index > 0 && members[index-1].ResourceID().String() >= member.ResourceID().String()) {
			return false
		}
	}
	return true
}

// GroupReplaceImpactParams contains authoritative before and proposed definitions.
type GroupReplaceImpactParams struct {
	GroupID          resource.GroupID
	ExpectedVersion  int64
	CurrentRevision  resource.GroupRevision
	ProposedRevision resource.GroupRevision
	ApprovalRequired bool
}

// GroupReplaceImpact is deterministic preview evidence acknowledged by apply.
type GroupReplaceImpact struct {
	groupID          resource.GroupID
	expectedVersion  int64
	currentRevision  resource.GroupRevision
	proposedRevision resource.GroupRevision
	approvalRequired bool
	hash             GroupReplaceImpactHash
}

// NewGroupReplaceImpact validates and hashes one replacement preview.
func NewGroupReplaceImpact(params GroupReplaceImpactParams) (GroupReplaceImpact, error) {
	impact := GroupReplaceImpact{
		groupID: params.GroupID, expectedVersion: params.ExpectedVersion,
		currentRevision: params.CurrentRevision, proposedRevision: params.ProposedRevision,
		approvalRequired: params.ApprovalRequired,
	}
	if !validGroupReplaceImpactFields(impact) {
		return GroupReplaceImpact{}, ErrInvalidGroupReplaceImpact
	}
	impact.hash = hashGroupReplaceImpact(impact)
	return impact, nil
}

// GroupID returns the stable affected Resource Group identity.
func (impact GroupReplaceImpact) GroupID() resource.GroupID { return impact.groupID }

// ExpectedVersion returns the Resource Group version used by the preview.
func (impact GroupReplaceImpact) ExpectedVersion() int64 { return impact.expectedVersion }

// CurrentRevision returns the complete active before-state definition.
func (impact GroupReplaceImpact) CurrentRevision() resource.GroupRevision {
	return impact.currentRevision
}

// ProposedRevision returns the complete immutable definition to append.
func (impact GroupReplaceImpact) ProposedRevision() resource.GroupRevision {
	return impact.proposedRevision
}

// AddedMembers returns proposed references absent from the current definition.
func (impact GroupReplaceImpact) AddedMembers() []resource.Reference {
	return groupReferenceDifference(impact.proposedRevision.Members(), impact.currentRevision.Members())
}

// RemovedMembers returns current references absent from the proposed definition.
func (impact GroupReplaceImpact) RemovedMembers() []resource.Reference {
	return groupReferenceDifference(impact.currentRevision.Members(), impact.proposedRevision.Members())
}

// RetainedMembers returns exact pinned references present in both definitions.
func (impact GroupReplaceImpact) RetainedMembers() []resource.Reference {
	current := impact.currentRevision.Members()
	proposed := impact.proposedRevision.Members()
	retained := make([]resource.Reference, 0, min(len(current), len(proposed)))
	for _, candidate := range current {
		if slices.Contains(proposed, candidate) {
			retained = append(retained, candidate)
		}
	}
	return retained
}

func groupReferenceDifference(left, right []resource.Reference) []resource.Reference {
	difference := make([]resource.Reference, 0, len(left))
	for _, candidate := range left {
		if !slices.Contains(right, candidate) {
			difference = append(difference, candidate)
		}
	}
	return difference
}

// ApprovalRequired reports whether durable approval evidence must precede apply.
func (impact GroupReplaceImpact) ApprovalRequired() bool { return impact.approvalRequired }

// Hash returns exact preview acknowledgement evidence.
func (impact GroupReplaceImpact) Hash() GroupReplaceImpactHash { return impact.hash }

// IsValid reports whether all fields and the digest agree.
func (impact GroupReplaceImpact) IsValid() bool {
	return validGroupReplaceImpactFields(impact) && impact.hash.IsValid() &&
		impact.hash == hashGroupReplaceImpact(impact)
}

// Equal reports exact deterministic impact equality.
func (impact GroupReplaceImpact) Equal(other GroupReplaceImpact) bool {
	return impact.IsValid() && other.IsValid() && impact.hash == other.hash
}

func validGroupReplaceImpactFields(impact GroupReplaceImpact) bool {
	current := impact.currentRevision
	proposed := impact.proposedRevision
	return impact.groupID.IsValid() && impact.expectedVersion > 0 &&
		impact.expectedVersion < math.MaxInt64 && current.IsValid() && proposed.IsValid() &&
		current.Scope() == proposed.Scope() && current.DisplayName() == proposed.DisplayName() &&
		current.OwnerPrincipalID() == proposed.OwnerPrincipalID() &&
		current.CustodianPrincipalID() == proposed.CustodianPrincipalID() &&
		current.DefinitionVersion()+1 == proposed.DefinitionVersion() &&
		current.SemanticHash() != proposed.SemanticHash()
}

func hashGroupReplaceImpact(impact GroupReplaceImpact) GroupReplaceImpactHash {
	current := impact.currentRevision
	proposed := impact.proposedRevision
	material := make([]byte, 0, 256+(len(current.Members())+len(proposed.Members()))*40)
	material = append(material, groupReplaceImpactHashDomain...)
	for _, value := range [...]string{
		proposed.Scope().WorkspaceID().String(), proposed.Scope().NetworkID().String(),
		impact.groupID.String(), proposed.DisplayName().String(),
		proposed.OwnerPrincipalID().String(), proposed.CustodianPrincipalID().String(),
	} {
		material = appendAuthorityText(material, value)
	}
	material = appendAuthorityInt64(material, impact.expectedVersion)
	material = appendAuthorityInt64(material, current.DefinitionVersion())
	material = appendAuthorityInt64(material, proposed.DefinitionVersion())
	currentHash := current.SemanticHash().Bytes()
	proposedHash := proposed.SemanticHash().Bytes()
	material = append(material, currentHash[:]...)
	material = append(material, proposedHash[:]...)
	if impact.approvalRequired {
		material = append(material, 1)
	} else {
		material = append(material, 0)
	}
	material = appendGroupReplaceMembers(material, current.Members())
	material = appendGroupReplaceMembers(material, proposed.Members())
	return GroupReplaceImpactHash(sha256.Sum256(material))
}

func appendGroupReplaceMembers(material []byte, members []resource.Reference) []byte {
	material = appendAuthorityInt64(material, int64(len(members)))
	for _, member := range members {
		id := member.ResourceID().Bytes()
		material = append(material, id[:]...)
		material = appendAuthorityInt64(material, member.ResourceVersion())
		material = appendAuthorityInt64(material, member.TargetGeneration())
	}
	return material
}

// GroupReplaceImpactHash is deterministic acknowledgement evidence for one preview.
type GroupReplaceImpactHash [sha256.Size]byte

// NewGroupReplaceImpactHash validates a non-zero digest from a boundary.
func NewGroupReplaceImpactHash(value [sha256.Size]byte) (GroupReplaceImpactHash, error) {
	hash := GroupReplaceImpactHash(value)
	if !hash.IsValid() {
		return GroupReplaceImpactHash{}, ErrInvalidGroupReplaceImpact
	}
	return hash, nil
}

// Bytes returns a defensive copy of the digest.
func (hash GroupReplaceImpactHash) Bytes() [sha256.Size]byte {
	return [sha256.Size]byte(hash)
}

// IsValid reports whether acknowledgement evidence is present.
func (hash GroupReplaceImpactHash) IsValid() bool { return hash != GroupReplaceImpactHash{} }

// GroupReplaceCommand is one authenticated mutation bound to an exact preview.
type GroupReplaceCommand struct {
	preview             GroupReplacePreview
	impactHash          GroupReplaceImpactHash
	auditReason         AuditReason
	idempotencyEvidence idempotency.Proof
}

// NewGroupReplaceCommand validates one immutable-definition replacement mutation.
func NewGroupReplaceCommand(
	preview GroupReplacePreview,
	impactHash GroupReplaceImpactHash,
	reason AuditReason,
	evidence idempotency.Proof,
) (GroupReplaceCommand, error) {
	command := GroupReplaceCommand{
		preview: preview, impactHash: impactHash, auditReason: reason,
		idempotencyEvidence: evidence,
	}
	if !command.IsValid() {
		return GroupReplaceCommand{}, ErrInvalidGroupReplaceCommand
	}
	return command, nil
}

// Preview returns immutable replacement intent.
func (command GroupReplaceCommand) Preview() GroupReplacePreview { return command.preview }

// Scope returns the exact home Network scope.
func (command GroupReplaceCommand) Scope() network.Scope { return command.preview.Scope() }

// GroupID returns the stable Resource Group identity.
func (command GroupReplaceCommand) GroupID() resource.GroupID { return command.preview.GroupID() }

// ExpectedVersion returns the Resource Group aggregate CAS base.
func (command GroupReplaceCommand) ExpectedVersion() int64 {
	return command.preview.ExpectedVersion()
}

// Members returns caller-owned canonical proposed membership.
func (command GroupReplaceCommand) Members() []resource.Reference { return command.preview.Members() }

// AccountSession returns current management authentication evidence.
func (command GroupReplaceCommand) AccountSession() accountsession.Session {
	return command.preview.AccountSession()
}

// ImpactHash returns exact acknowledged preview evidence.
func (command GroupReplaceCommand) ImpactHash() GroupReplaceImpactHash { return command.impactHash }

// AuditReason returns the explicit mutation explanation.
func (command GroupReplaceCommand) AuditReason() AuditReason { return command.auditReason }

// IdempotencyEvidence returns secret-safe replay evidence.
func (command GroupReplaceCommand) IdempotencyEvidence() idempotency.Proof {
	return command.idempotencyEvidence
}

// RequestHash binds one idempotency key to exact replacement semantics.
func (command GroupReplaceCommand) RequestHash() (GroupReplaceRequestHash, error) {
	if !command.IsValid() {
		return GroupReplaceRequestHash{}, ErrInvalidGroupReplaceCommand
	}
	material := make([]byte, 0, 384+len(command.Members())*40)
	material = append(material, groupReplaceRequestHashDomain...)
	for _, value := range [...]string{
		command.Scope().WorkspaceID().String(), command.Scope().NetworkID().String(),
		command.GroupID().String(), command.AccountSession().ID().String(),
		command.AccountSession().PrincipalID().String(), command.auditReason.String(),
	} {
		material = appendAuthorityText(material, value)
	}
	material = appendAuthorityInt64(material, command.ExpectedVersion())
	material = appendGroupReplaceMembers(material, command.Members())
	impactHash := command.impactHash.Bytes()
	material = append(material, impactHash[:]...)
	return NewGroupReplaceRequestHash(sha256.Sum256(material))
}

// IsValid reports whether mutation inputs are complete and bounded.
func (command GroupReplaceCommand) IsValid() bool {
	return command.preview.IsValid() && command.impactHash.IsValid() &&
		command.auditReason.IsValid() && command.idempotencyEvidence.IsValid()
}

// GroupReplaceRequestHash is deterministic idempotency evidence.
type GroupReplaceRequestHash [sha256.Size]byte

// NewGroupReplaceRequestHash validates a non-zero request digest.
func NewGroupReplaceRequestHash(value [sha256.Size]byte) (GroupReplaceRequestHash, error) {
	hash := GroupReplaceRequestHash(value)
	if !hash.IsValid() {
		return GroupReplaceRequestHash{}, ErrInvalidGroupReplaceCommand
	}
	return hash, nil
}

// Bytes returns a defensive copy of the digest.
func (hash GroupReplaceRequestHash) Bytes() [sha256.Size]byte {
	return [sha256.Size]byte(hash)
}

// IsValid reports whether request evidence is present.
func (hash GroupReplaceRequestHash) IsValid() bool { return hash != GroupReplaceRequestHash{} }

// GroupReplaceResolution is revision and impact authority observed under locks.
type GroupReplaceResolution struct {
	scope               network.Scope
	networkRevision     int64
	groupRevision       int64
	idempotencyRecordID publicid.ID
	requestHash         GroupReplaceRequestHash
	impact              GroupReplaceImpact
	completed           GroupReplaceResult
}

// NewGroupReplaceResolution validates locked revision and impact evidence.
func NewGroupReplaceResolution(
	scope network.Scope,
	networkRevision, groupRevision int64,
	idempotencyRecordID publicid.ID,
	requestHash GroupReplaceRequestHash,
	impact GroupReplaceImpact,
) (GroupReplaceResolution, error) {
	resolution := GroupReplaceResolution{
		scope: scope, networkRevision: networkRevision, groupRevision: groupRevision,
		idempotencyRecordID: idempotencyRecordID, requestHash: requestHash, impact: impact,
	}
	if !resolution.IsValid() {
		return GroupReplaceResolution{}, ErrInvalidGroupReplaceResolution
	}
	return resolution, nil
}

// NewCompletedGroupReplaceResolution validates immutable replay evidence.
func NewCompletedGroupReplaceResolution(
	result GroupReplaceResult,
	idempotencyRecordID publicid.ID,
	requestHash GroupReplaceRequestHash,
) (GroupReplaceResolution, error) {
	resolution := GroupReplaceResolution{
		scope: result.Scope(), idempotencyRecordID: idempotencyRecordID,
		requestHash: requestHash, completed: result,
	}
	if !resolution.IsValid() {
		return GroupReplaceResolution{}, ErrInvalidGroupReplaceResolution
	}
	return resolution, nil
}

// Scope returns exact locked scope.
func (resolution GroupReplaceResolution) Scope() network.Scope { return resolution.scope }

// NetworkRevision returns current client-visible authority.
func (resolution GroupReplaceResolution) NetworkRevision() int64 {
	return resolution.networkRevision
}

// GroupRevision returns current Resource Group subsystem authority.
func (resolution GroupReplaceResolution) GroupRevision() int64 {
	return resolution.groupRevision
}

// IdempotencyRecordID returns durable replay identity.
func (resolution GroupReplaceResolution) IdempotencyRecordID() publicid.ID {
	return resolution.idempotencyRecordID
}

// RequestHash returns exact idempotent request semantics.
func (resolution GroupReplaceResolution) RequestHash() GroupReplaceRequestHash {
	return resolution.requestHash
}

// Impact returns recomputed locked impact.
func (resolution GroupReplaceResolution) Impact() GroupReplaceImpact { return resolution.impact }

// CompletedResult returns replayed committed evidence, if present.
func (resolution GroupReplaceResolution) CompletedResult() GroupReplaceResult {
	return resolution.completed
}

// IsCompleted reports whether this is immutable replay evidence.
func (resolution GroupReplaceResolution) IsCompleted() bool { return resolution.completed.IsValid() }

// Equal reports exact deterministic resolution equality.
func (resolution GroupReplaceResolution) Equal(other GroupReplaceResolution) bool {
	if !resolution.IsValid() || !other.IsValid() {
		return false
	}
	if resolution.IsCompleted() || other.IsCompleted() {
		return resolution.completed == other.completed && resolution.scope == other.scope &&
			resolution.idempotencyRecordID == other.idempotencyRecordID &&
			resolution.requestHash == other.requestHash
	}
	return resolution.scope == other.scope && resolution.networkRevision == other.networkRevision &&
		resolution.groupRevision == other.groupRevision &&
		resolution.idempotencyRecordID == other.idempotencyRecordID &&
		resolution.requestHash == other.requestHash && resolution.impact.Equal(other.impact)
}

// IsValid reports whether revisions and evidence are coherent.
func (resolution GroupReplaceResolution) IsValid() bool {
	if !resolution.scope.IsValid() || !resolution.idempotencyRecordID.IsValid() ||
		!resolution.requestHash.IsValid() {
		return false
	}
	if resolution.completed.IsValid() {
		return resolution.completed.Scope() == resolution.scope && resolution.networkRevision == 0 &&
			resolution.groupRevision == 0 && !resolution.impact.IsValid()
	}
	return resolution.networkRevision > 0 && resolution.groupRevision > 0 &&
		resolution.networkRevision >= resolution.groupRevision && resolution.impact.IsValid() &&
		resolution.impact.ProposedRevision().Scope() == resolution.scope &&
		!resolution.impact.ApprovalRequired()
}

// GroupReplaceChange is one validated, replayable atomic definition replacement.
type GroupReplaceChange struct {
	command     GroupReplaceCommand
	resolution  GroupReplaceResolution
	mutationIDs GroupReplaceMutationIDs
	occurredAt  time.Time
	expiresAt   time.Time
}

// NewGroupReplaceChange validates CAS, stable IDs, and decision time.
func NewGroupReplaceChange(
	command GroupReplaceCommand,
	resolution GroupReplaceResolution,
	mutationIDs GroupReplaceMutationIDs,
	occurredAt, expiresAt time.Time,
) (GroupReplaceChange, error) {
	change := GroupReplaceChange{
		command: command, resolution: resolution, mutationIDs: mutationIDs,
		occurredAt: occurredAt.UTC(), expiresAt: expiresAt.UTC(),
	}
	if !change.IsValid() {
		return GroupReplaceChange{}, ErrInvalidGroupReplaceChange
	}
	return change, nil
}

// Command returns the immutable request.
func (change GroupReplaceChange) Command() GroupReplaceCommand { return change.command }

// Resolution returns locked authority and impact.
func (change GroupReplaceChange) Resolution() GroupReplaceResolution { return change.resolution }

// MutationIDs returns stable durable identities.
func (change GroupReplaceChange) MutationIDs() GroupReplaceMutationIDs { return change.mutationIDs }

// OccurredAt returns one stable decision time shared across retries.
func (change GroupReplaceChange) OccurredAt() time.Time { return change.occurredAt }

// ExpiresAt returns exclusive durable replay-window bound.
func (change GroupReplaceChange) ExpiresAt() time.Time { return change.expiresAt }

// IsValid reports whether all atomic facts agree.
func (change GroupReplaceChange) IsValid() bool {
	return change.command.IsValid() && change.resolution.IsValid() &&
		change.mutationIDs.IsValidFor(change.command) &&
		change.command.Scope() == change.resolution.Scope() && !change.resolution.IsCompleted() &&
		change.command.ImpactHash() == change.resolution.Impact().Hash() &&
		change.command.GroupID() == change.resolution.Impact().GroupID() &&
		change.command.ExpectedVersion() == change.resolution.Impact().ExpectedVersion() &&
		slices.Equal(change.command.Members(), change.resolution.Impact().ProposedRevision().Members()) &&
		!change.occurredAt.IsZero() && change.expiresAt.After(change.occurredAt)
}

// GroupReplaceResult is safe committed immutable-definition evidence.
type GroupReplaceResult struct {
	groupID           resource.GroupID
	scope             network.Scope
	definitionVersion int64
	version           int64
	networkRevision   int64
	groupRevision     int64
	semanticHash      resource.SemanticHash
	impactHash        GroupReplaceImpactHash
}

// NewGroupReplaceResult validates committed definition replacement evidence.
func NewGroupReplaceResult(
	groupID resource.GroupID,
	scope network.Scope,
	definitionVersion, version, networkRevision, groupRevision int64,
	semanticHash resource.SemanticHash,
	impactHash GroupReplaceImpactHash,
) (GroupReplaceResult, error) {
	result := GroupReplaceResult{
		groupID: groupID, scope: scope, definitionVersion: definitionVersion,
		version: version, networkRevision: networkRevision, groupRevision: groupRevision,
		semanticHash: semanticHash, impactHash: impactHash,
	}
	if !result.IsValid() {
		return GroupReplaceResult{}, ErrInvalidGroupReplaceResult
	}
	return result, nil
}

// GroupID returns the stable Resource Group identity.
func (result GroupReplaceResult) GroupID() resource.GroupID { return result.groupID }

// Scope returns committed exact scope.
func (result GroupReplaceResult) Scope() network.Scope { return result.scope }

// DefinitionVersion returns the appended immutable definition version.
func (result GroupReplaceResult) DefinitionVersion() int64 { return result.definitionVersion }

// Version returns the new Resource Group aggregate version.
func (result GroupReplaceResult) Version() int64 { return result.version }

// NetworkRevision returns the new client-visible revision.
func (result GroupReplaceResult) NetworkRevision() int64 { return result.networkRevision }

// GroupRevision returns the new Resource Group subsystem revision.
func (result GroupReplaceResult) GroupRevision() int64 { return result.groupRevision }

// SemanticHash returns the after-state definition digest.
func (result GroupReplaceResult) SemanticHash() resource.SemanticHash { return result.semanticHash }

// ImpactHash returns exact preview evidence applied by the mutation.
func (result GroupReplaceResult) ImpactHash() GroupReplaceImpactHash { return result.impactHash }

// IsValid reports whether committed evidence is complete and coherent.
func (result GroupReplaceResult) IsValid() bool {
	return result.groupID.IsValid() && result.scope.IsValid() && result.definitionVersion > 1 &&
		result.version > 1 && result.networkRevision > 1 && result.groupRevision > 1 &&
		result.networkRevision >= result.groupRevision && result.semanticHash.IsValid() &&
		result.impactHash.IsValid()
}
