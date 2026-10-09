package authority

import (
	"crypto/sha256"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/resource"
	"meshtransit.net/core/internal/platform/idempotency"
)

const authorityChangeConfirmationHashDomain = "meshtransit/resource-authority-change-confirmation/v1\x00"

var (
	// ErrInvalidAuthorityChangeConfirmationCommand reports incomplete confirmation authority.
	ErrInvalidAuthorityChangeConfirmationCommand = errors.New("resource authority change: invalid confirmation command")
	// ErrInvalidAuthorityChangeConfirmationResolution reports inconsistent locked request authority.
	ErrInvalidAuthorityChangeConfirmationResolution = errors.New("resource authority change: invalid confirmation resolution")
	// ErrInvalidAuthorityChangeConfirmationChange reports inconsistent final mutation evidence.
	ErrInvalidAuthorityChangeConfirmationChange = errors.New("resource authority change: invalid confirmation change")
	// ErrInvalidAuthorityChangeConfirmationResult reports malformed applied evidence.
	ErrInvalidAuthorityChangeConfirmationResult = errors.New("resource authority change: invalid confirmation result")
	// ErrAuthorityChangeRequestVersionConflict reports a stale request precondition.
	ErrAuthorityChangeRequestVersionConflict = errors.New("resource authority change: stale request version")
	// ErrAuthorityChangeRequestExpired reports a lapsed confirmation deadline.
	ErrAuthorityChangeRequestExpired = errors.New("resource authority change: request expired")
	// ErrAuthorityChangeRequestStateConflict reports a non-pending request.
	ErrAuthorityChangeRequestStateConflict = errors.New("resource authority change: request state conflict")
)

// ChangeConfirmationCommand confirms one pending request as its target actor.
type ChangeConfirmationCommand struct {
	scope                  network.Scope
	subjectKind            SubjectKind
	resourceID             resource.ID
	groupID                resource.GroupID
	requestID              ChangeRequestID
	expectedRequestVersion int64
	impactHash             ChangeImpactHash
	accountSession         accountsession.Session
	auditReason            AuditReason
	idempotencyEvidence    idempotency.Proof
}

// NewResourceAuthorityChangeConfirmation validates a Resource confirmation.
func NewResourceAuthorityChangeConfirmation(
	scope network.Scope,
	resourceID resource.ID,
	requestID ChangeRequestID,
	expectedRequestVersion int64,
	impactHash ChangeImpactHash,
	session accountsession.Session,
	reason AuditReason,
	evidence idempotency.Proof,
) (ChangeConfirmationCommand, error) {
	command := ChangeConfirmationCommand{
		scope: scope, subjectKind: AuthoritySubjectResource, resourceID: resourceID,
		requestID: requestID, expectedRequestVersion: expectedRequestVersion,
		impactHash: impactHash, accountSession: session, auditReason: reason,
		idempotencyEvidence: evidence,
	}
	if !command.IsValid() {
		return ChangeConfirmationCommand{}, ErrInvalidAuthorityChangeConfirmationCommand
	}
	return command, nil
}

// NewGroupAuthorityChangeConfirmation validates a Resource Group confirmation.
func NewGroupAuthorityChangeConfirmation(
	scope network.Scope,
	groupID resource.GroupID,
	requestID ChangeRequestID,
	expectedRequestVersion int64,
	impactHash ChangeImpactHash,
	session accountsession.Session,
	reason AuditReason,
	evidence idempotency.Proof,
) (ChangeConfirmationCommand, error) {
	command := ChangeConfirmationCommand{
		scope: scope, subjectKind: AuthoritySubjectGroup, groupID: groupID,
		requestID: requestID, expectedRequestVersion: expectedRequestVersion,
		impactHash: impactHash, accountSession: session, auditReason: reason,
		idempotencyEvidence: evidence,
	}
	if !command.IsValid() {
		return ChangeConfirmationCommand{}, ErrInvalidAuthorityChangeConfirmationCommand
	}
	return command, nil
}

// Scope returns the exact home Network scope.
func (command ChangeConfirmationCommand) Scope() network.Scope { return command.scope }

// SubjectKind returns the protected aggregate type.
func (command ChangeConfirmationCommand) SubjectKind() SubjectKind {
	return command.subjectKind
}

// ResourceID returns the Resource identity when applicable.
func (command ChangeConfirmationCommand) ResourceID() resource.ID {
	return command.resourceID
}

// GroupID returns the Resource Group identity when applicable.
func (command ChangeConfirmationCommand) GroupID() resource.GroupID {
	return command.groupID
}

// SubjectPublicID returns the exact target aggregate identity.
func (command ChangeConfirmationCommand) SubjectPublicID() publicid.ID {
	if command.subjectKind == AuthoritySubjectGroup {
		return publicid.ID(command.groupID)
	}
	return publicid.ID(command.resourceID)
}

// RequestID returns the pending authority-change identity.
func (command ChangeConfirmationCommand) RequestID() ChangeRequestID {
	return command.requestID
}

// ExpectedRequestVersion returns the confirmation CAS base.
func (command ChangeConfirmationCommand) ExpectedRequestVersion() int64 {
	return command.expectedRequestVersion
}

// ImpactHash returns exact proposal acknowledgement evidence.
func (command ChangeConfirmationCommand) ImpactHash() ChangeImpactHash {
	return command.impactHash
}

// AccountSession returns the independent confirming actor.
func (command ChangeConfirmationCommand) AccountSession() accountsession.Session {
	return command.accountSession
}

// AuditReason returns the explicit confirmation explanation.
func (command ChangeConfirmationCommand) AuditReason() AuditReason {
	return command.auditReason
}

// IdempotencyEvidence returns secret-safe replay evidence.
func (command ChangeConfirmationCommand) IdempotencyEvidence() idempotency.Proof {
	return command.idempotencyEvidence
}

// RequestHash binds a raw-key digest to exact confirmation semantics.
func (command ChangeConfirmationCommand) RequestHash() (
	ChangeConfirmationHash,
	error,
) {
	if !command.IsValid() {
		return ChangeConfirmationHash{}, ErrInvalidAuthorityChangeConfirmationCommand
	}
	material := make([]byte, 0, 512)
	material = append(material, authorityChangeConfirmationHashDomain...)
	for _, value := range [...]string{
		command.scope.WorkspaceID().String(), command.scope.NetworkID().String(),
		command.subjectKind.String(), command.SubjectPublicID().String(), command.requestID.String(),
		command.accountSession.ID().String(), command.accountSession.PrincipalID().String(),
		command.auditReason.String(),
	} {
		material = appendAuthorityText(material, value)
	}
	material = appendAuthorityInt64(material, command.expectedRequestVersion)
	impactHash := command.impactHash.Bytes()
	material = append(material, impactHash[:]...)
	return NewAuthorityChangeConfirmationHash(sha256.Sum256(material))
}

// IsValid reports whether confirmation inputs are complete and typed.
func (command ChangeConfirmationCommand) IsValid() bool {
	if !command.scope.IsValid() || !command.requestID.IsValid() ||
		command.expectedRequestVersion != 1 ||
		!command.impactHash.IsValid() || !command.accountSession.IsValid() ||
		!command.auditReason.IsValid() || !command.idempotencyEvidence.IsValid() {
		return false
	}
	switch command.subjectKind {
	case AuthoritySubjectResource:
		return command.resourceID.IsValid() && !command.groupID.IsValid()
	case AuthoritySubjectGroup:
		return command.groupID.IsValid() && !command.resourceID.IsValid()
	default:
		return false
	}
}

// ChangeConfirmationHash is deterministic confirmation idempotency evidence.
type ChangeConfirmationHash [sha256.Size]byte

// NewAuthorityChangeConfirmationHash validates a non-zero digest.
func NewAuthorityChangeConfirmationHash(
	value [sha256.Size]byte,
) (ChangeConfirmationHash, error) {
	hash := ChangeConfirmationHash(value)
	if !hash.IsValid() {
		return ChangeConfirmationHash{}, ErrInvalidAuthorityChangeConfirmationCommand
	}
	return hash, nil
}

// Bytes returns a defensive copy of the digest.
func (hash ChangeConfirmationHash) Bytes() [sha256.Size]byte {
	return [sha256.Size]byte(hash)
}

// IsValid reports whether confirmation evidence is present.
func (hash ChangeConfirmationHash) IsValid() bool {
	return hash != ChangeConfirmationHash{}
}

// ChangeConfirmationResolution is locked request and aggregate authority.
type ChangeConfirmationResolution struct {
	scope               network.Scope
	requestID           ChangeRequestID
	requestVersion      int64
	requestExpiresAt    time.Time
	networkRevision     int64
	subsystemRevision   int64
	idempotencyRecordID publicid.ID
	requestHash         ChangeConfirmationHash
	impact              ChangeImpact
	completed           ChangeConfirmationResult
}

// NewAuthorityChangeConfirmationResolution validates locked confirmation authority.
func NewAuthorityChangeConfirmationResolution(
	scope network.Scope,
	requestID ChangeRequestID,
	requestVersion int64,
	requestExpiresAt time.Time,
	networkRevision, subsystemRevision int64,
	idempotencyRecordID publicid.ID,
	requestHash ChangeConfirmationHash,
	impact ChangeImpact,
) (ChangeConfirmationResolution, error) {
	resolution := ChangeConfirmationResolution{
		scope: scope, requestID: requestID, requestVersion: requestVersion,
		requestExpiresAt: requestExpiresAt.UTC(), networkRevision: networkRevision,
		subsystemRevision: subsystemRevision, idempotencyRecordID: idempotencyRecordID,
		requestHash: requestHash, impact: impact,
	}
	if !resolution.IsValid() {
		return ChangeConfirmationResolution{}, ErrInvalidAuthorityChangeConfirmationResolution
	}
	return resolution, nil
}

// NewCompletedAuthorityChangeConfirmationResolution validates replay evidence.
func NewCompletedAuthorityChangeConfirmationResolution(
	result ChangeConfirmationResult,
	idempotencyRecordID publicid.ID,
	requestHash ChangeConfirmationHash,
) (ChangeConfirmationResolution, error) {
	resolution := ChangeConfirmationResolution{
		scope: result.Scope(), requestID: result.RequestID(),
		idempotencyRecordID: idempotencyRecordID, requestHash: requestHash,
		completed: result,
	}
	if !resolution.IsValid() {
		return ChangeConfirmationResolution{}, ErrInvalidAuthorityChangeConfirmationResolution
	}
	return resolution, nil
}

// Scope returns the exact locked scope.
func (resolution ChangeConfirmationResolution) Scope() network.Scope {
	return resolution.scope
}

// RequestID returns the exact pending request.
func (resolution ChangeConfirmationResolution) RequestID() ChangeRequestID {
	return resolution.requestID
}

// RequestVersion returns the locked request CAS base.
func (resolution ChangeConfirmationResolution) RequestVersion() int64 {
	return resolution.requestVersion
}

// RequestExpiresAt returns the exclusive confirmation deadline.
func (resolution ChangeConfirmationResolution) RequestExpiresAt() time.Time {
	return resolution.requestExpiresAt
}

// NetworkRevision returns current client-visible authority.
func (resolution ChangeConfirmationResolution) NetworkRevision() int64 {
	return resolution.networkRevision
}

// SubsystemRevision returns current inventory or group authority.
func (resolution ChangeConfirmationResolution) SubsystemRevision() int64 {
	return resolution.subsystemRevision
}

// IdempotencyRecordID returns durable replay identity.
func (resolution ChangeConfirmationResolution) IdempotencyRecordID() publicid.ID {
	return resolution.idempotencyRecordID
}

// RequestHash returns exact confirmation semantics.
func (resolution ChangeConfirmationResolution) RequestHash() ChangeConfirmationHash {
	return resolution.requestHash
}

// Impact returns the recomputed locked proposal.
func (resolution ChangeConfirmationResolution) Impact() ChangeImpact {
	return resolution.impact
}

// CompletedResult returns replayed final evidence, if present.
func (resolution ChangeConfirmationResolution) CompletedResult() ChangeConfirmationResult {
	return resolution.completed
}

// IsCompleted reports whether this is immutable replay evidence.
func (resolution ChangeConfirmationResolution) IsCompleted() bool {
	return resolution.completed.IsValid()
}

// Equal reports exact deterministic resolution equality.
func (resolution ChangeConfirmationResolution) Equal(
	other ChangeConfirmationResolution,
) bool {
	if !resolution.IsValid() || !other.IsValid() {
		return false
	}
	if resolution.IsCompleted() || other.IsCompleted() {
		return resolution.completed.Equal(other.completed) && resolution.scope == other.scope &&
			resolution.idempotencyRecordID == other.idempotencyRecordID &&
			resolution.requestHash == other.requestHash
	}
	return resolution.scope == other.scope && resolution.requestID == other.requestID &&
		resolution.requestVersion == other.requestVersion &&
		resolution.requestExpiresAt.Equal(other.requestExpiresAt) &&
		resolution.networkRevision == other.networkRevision &&
		resolution.subsystemRevision == other.subsystemRevision &&
		resolution.idempotencyRecordID == other.idempotencyRecordID &&
		resolution.requestHash == other.requestHash && resolution.impact.Equal(other.impact)
}

// IsValid reports whether request, revision, actor, and impact evidence agree.
func (resolution ChangeConfirmationResolution) IsValid() bool {
	if !resolution.scope.IsValid() || !resolution.requestID.IsValid() ||
		!resolution.idempotencyRecordID.IsValid() || !resolution.requestHash.IsValid() {
		return false
	}
	if resolution.completed.IsValid() {
		return resolution.completed.Scope() == resolution.scope &&
			resolution.completed.RequestID() == resolution.requestID &&
			resolution.requestVersion == 0 && resolution.requestExpiresAt.IsZero() &&
			resolution.networkRevision == 0 && resolution.subsystemRevision == 0 &&
			!resolution.impact.IsValid()
	}
	return resolution.requestVersion > 0 && !resolution.requestExpiresAt.IsZero() &&
		resolution.networkRevision > 0 && resolution.subsystemRevision > 0 &&
		resolution.networkRevision >= resolution.subsystemRevision &&
		resolution.impact.IsValid() && resolution.impact.Preview().Scope() == resolution.scope
}

// ChangeConfirmationChange is one atomic second-actor application.
type ChangeConfirmationChange struct {
	command     ChangeConfirmationCommand
	resolution  ChangeConfirmationResolution
	mutationIDs ChangeConfirmationMutationIDs
	occurredAt  time.Time
	expiresAt   time.Time
}

// NewAuthorityChangeConfirmationChange validates final mutation evidence.
func NewAuthorityChangeConfirmationChange(
	command ChangeConfirmationCommand,
	resolution ChangeConfirmationResolution,
	mutationIDs ChangeConfirmationMutationIDs,
	occurredAt, expiresAt time.Time,
) (ChangeConfirmationChange, error) {
	change := ChangeConfirmationChange{
		command: command, resolution: resolution, mutationIDs: mutationIDs,
		occurredAt: occurredAt.UTC(), expiresAt: expiresAt.UTC(),
	}
	if !change.IsValid() {
		return ChangeConfirmationChange{}, ErrInvalidAuthorityChangeConfirmationChange
	}
	return change, nil
}

// Command returns immutable confirmation intent.
func (change ChangeConfirmationChange) Command() ChangeConfirmationCommand {
	return change.command
}

// Resolution returns locked request and aggregate authority.
func (change ChangeConfirmationChange) Resolution() ChangeConfirmationResolution {
	return change.resolution
}

// MutationIDs returns retry-stable durable identities.
func (change ChangeConfirmationChange) MutationIDs() ChangeConfirmationMutationIDs {
	return change.mutationIDs
}

// OccurredAt returns one stable decision time.
func (change ChangeConfirmationChange) OccurredAt() time.Time { return change.occurredAt }

// ExpiresAt returns the exclusive confirmation replay window.
func (change ChangeConfirmationChange) ExpiresAt() time.Time { return change.expiresAt }

// IsValid reports whether all final mutation facts agree.
func (change ChangeConfirmationChange) IsValid() bool {
	impact := change.resolution.Impact()
	return change.command.IsValid() && change.resolution.IsValid() &&
		!change.resolution.IsCompleted() && change.mutationIDs.IsValid() &&
		change.command.Scope() == change.resolution.Scope() &&
		change.command.RequestID() == change.resolution.RequestID() &&
		change.command.ExpectedRequestVersion() == change.resolution.RequestVersion() &&
		change.command.ImpactHash() == impact.Hash() &&
		change.command.SubjectKind() == impact.Preview().SubjectKind() &&
		change.command.SubjectPublicID() == impact.Preview().SubjectPublicID() &&
		change.command.AccountSession().PrincipalID() == impact.ConfirmationPrincipalID() &&
		change.command.AccountSession().ID() != impact.Preview().AccountSession().ID() &&
		!change.occurredAt.IsZero() && change.occurredAt.Before(change.resolution.RequestExpiresAt()) &&
		change.expiresAt.After(change.occurredAt)
}

// ChangeConfirmationResult is safe committed final authority evidence.
type ChangeConfirmationResult struct {
	requestID            ChangeRequestID
	scope                network.Scope
	subjectKind          SubjectKind
	resourceID           resource.ID
	groupID              resource.GroupID
	action               ChangeAction
	subjectVersion       int64
	requestVersion       int64
	networkRevision      int64
	subsystemRevision    int64
	ownerPrincipalID     identity.PrincipalID
	custodianPrincipalID identity.PrincipalID
	semanticHash         resource.SemanticHash
	impactHash           ChangeImpactHash
}

// NewAuthorityChangeConfirmationResult validates applied authority evidence.
func NewAuthorityChangeConfirmationResult(
	requestID ChangeRequestID,
	scope network.Scope,
	subjectKind SubjectKind,
	resourceID resource.ID,
	groupID resource.GroupID,
	action ChangeAction,
	subjectVersion, requestVersion, networkRevision, subsystemRevision int64,
	ownerPrincipalID, custodianPrincipalID identity.PrincipalID,
	semanticHash resource.SemanticHash,
	impactHash ChangeImpactHash,
) (ChangeConfirmationResult, error) {
	result := ChangeConfirmationResult{
		requestID: requestID, scope: scope, subjectKind: subjectKind,
		resourceID: resourceID, groupID: groupID, action: action,
		subjectVersion: subjectVersion, requestVersion: requestVersion,
		networkRevision: networkRevision, subsystemRevision: subsystemRevision,
		ownerPrincipalID: ownerPrincipalID, custodianPrincipalID: custodianPrincipalID,
		semanticHash: semanticHash, impactHash: impactHash,
	}
	if !result.IsValid() {
		return ChangeConfirmationResult{}, ErrInvalidAuthorityChangeConfirmationResult
	}
	return result, nil
}

// RequestID returns the applied request identity.
func (result ChangeConfirmationResult) RequestID() ChangeRequestID {
	return result.requestID
}

// Scope returns the exact home Network scope.
func (result ChangeConfirmationResult) Scope() network.Scope { return result.scope }

// SubjectKind returns the changed aggregate type.
func (result ChangeConfirmationResult) SubjectKind() SubjectKind {
	return result.subjectKind
}

// ResourceID returns the changed Resource identity when applicable.
func (result ChangeConfirmationResult) ResourceID() resource.ID {
	return result.resourceID
}

// GroupID returns the changed Resource Group identity when applicable.
func (result ChangeConfirmationResult) GroupID() resource.GroupID { return result.groupID }

// SubjectPublicID returns the exact changed aggregate identity.
func (result ChangeConfirmationResult) SubjectPublicID() publicid.ID {
	if result.subjectKind == AuthoritySubjectGroup {
		return publicid.ID(result.groupID)
	}
	return publicid.ID(result.resourceID)
}

// Action returns the applied protected operation.
func (result ChangeConfirmationResult) Action() ChangeAction {
	return result.action
}

// SubjectVersion returns the new aggregate version.
func (result ChangeConfirmationResult) SubjectVersion() int64 {
	return result.subjectVersion
}

// RequestVersion returns the terminal request version.
func (result ChangeConfirmationResult) RequestVersion() int64 {
	return result.requestVersion
}

// NetworkRevision returns the new client-visible revision.
func (result ChangeConfirmationResult) NetworkRevision() int64 {
	return result.networkRevision
}

// SubsystemRevision returns the new inventory or group revision.
func (result ChangeConfirmationResult) SubsystemRevision() int64 {
	return result.subsystemRevision
}

// OwnerPrincipalID returns committed owner authority.
func (result ChangeConfirmationResult) OwnerPrincipalID() identity.PrincipalID {
	return result.ownerPrincipalID
}

// CustodianPrincipalID returns committed custodian authority.
func (result ChangeConfirmationResult) CustodianPrincipalID() identity.PrincipalID {
	return result.custodianPrincipalID
}

// SemanticHash returns the committed after-state digest.
func (result ChangeConfirmationResult) SemanticHash() resource.SemanticHash {
	return result.semanticHash
}

// ImpactHash returns exact applied proposal evidence.
func (result ChangeConfirmationResult) ImpactHash() ChangeImpactHash {
	return result.impactHash
}

// Equal reports exact committed evidence equality.
func (result ChangeConfirmationResult) Equal(
	other ChangeConfirmationResult,
) bool {
	return result.IsValid() && other.IsValid() && result.requestID == other.requestID &&
		result.scope == other.scope && result.subjectKind == other.subjectKind &&
		result.resourceID == other.resourceID && result.groupID == other.groupID &&
		result.action == other.action && result.subjectVersion == other.subjectVersion &&
		result.requestVersion == other.requestVersion &&
		result.networkRevision == other.networkRevision &&
		result.subsystemRevision == other.subsystemRevision &&
		result.ownerPrincipalID == other.ownerPrincipalID &&
		result.custodianPrincipalID == other.custodianPrincipalID &&
		result.semanticHash == other.semanticHash && result.impactHash == other.impactHash
}

// IsValid reports whether committed final evidence is complete and coherent.
func (result ChangeConfirmationResult) IsValid() bool {
	if !result.requestID.IsValid() || !result.scope.IsValid() ||
		result.action <= AuthorityChangeUnknown || result.action > AuthorityChangeDelegateCustodian ||
		result.subjectVersion <= 1 || result.requestVersion != 2 ||
		result.networkRevision <= 1 || result.subsystemRevision <= 1 ||
		result.networkRevision < result.subsystemRevision ||
		!result.ownerPrincipalID.IsValid() || !result.custodianPrincipalID.IsValid() ||
		!result.semanticHash.IsValid() || !result.impactHash.IsValid() {
		return false
	}
	switch result.subjectKind {
	case AuthoritySubjectResource:
		return result.resourceID.IsValid() && !result.groupID.IsValid()
	case AuthoritySubjectGroup:
		return result.groupID.IsValid() && !result.resourceID.IsValid()
	default:
		return false
	}
}
