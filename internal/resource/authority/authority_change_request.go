package authority

import (
	"crypto/sha256"
	"errors"
	"time"

	"github.com/meshtransit/meshtransit/internal/idempotency"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

const authorityChangeRequestHashDomain = "meshtransit/resource-authority-change-request/v1\x00"

var (
	// ErrInvalidAuthorityChangeRequestID reports a malformed request UUIDv7.
	ErrInvalidAuthorityChangeRequestID = errors.New("resource authority change: invalid request id")
	// ErrInvalidAuthorityChangeRequestCommand reports incomplete proposal authority.
	ErrInvalidAuthorityChangeRequestCommand = errors.New("resource authority change: invalid request command")
	// ErrInvalidAuthorityChangeRequestResolution reports inconsistent locked proposal authority.
	ErrInvalidAuthorityChangeRequestResolution = errors.New("resource authority change: invalid request resolution")
	// ErrInvalidAuthorityChangeRequestChange reports inconsistent proposal mutation evidence.
	ErrInvalidAuthorityChangeRequestChange = errors.New("resource authority change: invalid request change")
	// ErrInvalidAuthorityChangeRequestResult reports malformed committed proposal evidence.
	ErrInvalidAuthorityChangeRequestResult = errors.New("resource authority change: invalid request result")
)

// ChangeRequestID is a validated protected-change UUIDv7.
type ChangeRequestID publicid.ID

// ParseAuthorityChangeRequestID validates a canonical request UUIDv7.
func ParseAuthorityChangeRequestID(value string) (ChangeRequestID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return ChangeRequestID{}, ErrInvalidAuthorityChangeRequestID
	}
	return ChangeRequestID(id), nil
}

// String returns the canonical public ID.
func (id ChangeRequestID) String() string { return publicid.ID(id).String() }

// IsValid reports whether the public ID is a UUIDv7.
func (id ChangeRequestID) IsValid() bool { return publicid.ID(id).IsValid() }

// ChangeRequestCommand proposes one exact impact for second-actor confirmation.
type ChangeRequestCommand struct {
	preview             ChangePreview
	impactHash          ChangeImpactHash
	auditReason         AuditReason
	idempotencyEvidence idempotency.Proof
}

// NewAuthorityChangeRequestCommand validates one protected proposal mutation.
func NewAuthorityChangeRequestCommand(
	preview ChangePreview,
	impactHash ChangeImpactHash,
	reason AuditReason,
	evidence idempotency.Proof,
) (ChangeRequestCommand, error) {
	command := ChangeRequestCommand{
		preview: preview, impactHash: impactHash, auditReason: reason,
		idempotencyEvidence: evidence,
	}
	if !command.IsValid() {
		return ChangeRequestCommand{}, ErrInvalidAuthorityChangeRequestCommand
	}
	return command, nil
}

// Preview returns the exact protected intent.
func (command ChangeRequestCommand) Preview() ChangePreview {
	return command.preview
}

// Scope returns the exact home Network scope.
func (command ChangeRequestCommand) Scope() network.Scope {
	return command.preview.Scope()
}

// ImpactHash returns the acknowledged before/after evidence.
func (command ChangeRequestCommand) ImpactHash() ChangeImpactHash {
	return command.impactHash
}

// AuditReason returns the explicit proposal explanation.
func (command ChangeRequestCommand) AuditReason() AuditReason {
	return command.auditReason
}

// IdempotencyEvidence returns secret-safe replay evidence.
func (command ChangeRequestCommand) IdempotencyEvidence() idempotency.Proof {
	return command.idempotencyEvidence
}

// RequestHash binds a raw-key digest to exact proposal semantics.
func (command ChangeRequestCommand) RequestHash() (ChangeRequestHash, error) {
	if !command.IsValid() {
		return ChangeRequestHash{}, ErrInvalidAuthorityChangeRequestCommand
	}
	preview := command.preview
	material := make([]byte, 0, 512)
	material = append(material, authorityChangeRequestHashDomain...)
	for _, value := range [...]string{
		preview.Scope().WorkspaceID().String(), preview.Scope().NetworkID().String(),
		preview.SubjectKind().String(), preview.SubjectPublicID().String(), preview.Action().String(),
		preview.TargetPrincipalID().String(), preview.AccountSession().ID().String(),
		preview.AccountSession().PrincipalID().String(), command.auditReason.String(),
	} {
		material = appendAuthorityText(material, value)
	}
	material = appendAuthorityInt64(material, preview.ExpectedVersion())
	impactHash := command.impactHash.Bytes()
	material = append(material, impactHash[:]...)
	return NewAuthorityChangeRequestHash(sha256.Sum256(material))
}

// IsValid reports whether proposal inputs are complete and bounded.
func (command ChangeRequestCommand) IsValid() bool {
	return command.preview.IsValid() && command.impactHash.IsValid() &&
		command.auditReason.IsValid() && command.idempotencyEvidence.IsValid()
}

// ChangeRequestHash is deterministic idempotency evidence.
type ChangeRequestHash [sha256.Size]byte

// NewAuthorityChangeRequestHash validates a non-zero request digest.
func NewAuthorityChangeRequestHash(
	value [sha256.Size]byte,
) (ChangeRequestHash, error) {
	hash := ChangeRequestHash(value)
	if !hash.IsValid() {
		return ChangeRequestHash{}, ErrInvalidAuthorityChangeRequestCommand
	}
	return hash, nil
}

// Bytes returns a defensive copy of the digest.
func (hash ChangeRequestHash) Bytes() [sha256.Size]byte {
	return [sha256.Size]byte(hash)
}

// IsValid reports whether request evidence is present.
func (hash ChangeRequestHash) IsValid() bool {
	return hash != ChangeRequestHash{}
}

// ChangeRequestResolution is locked proposal authority or replay evidence.
type ChangeRequestResolution struct {
	scope               network.Scope
	networkRevision     int64
	subsystemRevision   int64
	idempotencyRecordID publicid.ID
	requestHash         ChangeRequestHash
	impact              ChangeImpact
	completed           ChangeRequestResult
}

// NewAuthorityChangeRequestResolution validates locked proposal authority.
func NewAuthorityChangeRequestResolution(
	scope network.Scope,
	networkRevision, subsystemRevision int64,
	idempotencyRecordID publicid.ID,
	requestHash ChangeRequestHash,
	impact ChangeImpact,
) (ChangeRequestResolution, error) {
	resolution := ChangeRequestResolution{
		scope: scope, networkRevision: networkRevision,
		subsystemRevision: subsystemRevision, idempotencyRecordID: idempotencyRecordID,
		requestHash: requestHash, impact: impact,
	}
	if !resolution.IsValid() {
		return ChangeRequestResolution{}, ErrInvalidAuthorityChangeRequestResolution
	}
	return resolution, nil
}

// NewCompletedAuthorityChangeRequestResolution validates proposal replay evidence.
func NewCompletedAuthorityChangeRequestResolution(
	result ChangeRequestResult,
	idempotencyRecordID publicid.ID,
	requestHash ChangeRequestHash,
) (ChangeRequestResolution, error) {
	resolution := ChangeRequestResolution{
		scope: result.Scope(), idempotencyRecordID: idempotencyRecordID,
		requestHash: requestHash, completed: result,
	}
	if !resolution.IsValid() {
		return ChangeRequestResolution{}, ErrInvalidAuthorityChangeRequestResolution
	}
	return resolution, nil
}

// Scope returns the exact locked scope.
func (resolution ChangeRequestResolution) Scope() network.Scope {
	return resolution.scope
}

// NetworkRevision returns current client-visible authority.
func (resolution ChangeRequestResolution) NetworkRevision() int64 {
	return resolution.networkRevision
}

// SubsystemRevision returns current inventory or group authority.
func (resolution ChangeRequestResolution) SubsystemRevision() int64 {
	return resolution.subsystemRevision
}

// IdempotencyRecordID returns durable replay identity.
func (resolution ChangeRequestResolution) IdempotencyRecordID() publicid.ID {
	return resolution.idempotencyRecordID
}

// RequestHash returns exact proposal semantics.
func (resolution ChangeRequestResolution) RequestHash() ChangeRequestHash {
	return resolution.requestHash
}

// Impact returns recomputed locked impact.
func (resolution ChangeRequestResolution) Impact() ChangeImpact {
	return resolution.impact
}

// CompletedResult returns replayed proposal evidence, if present.
func (resolution ChangeRequestResolution) CompletedResult() ChangeRequestResult {
	return resolution.completed
}

// IsCompleted reports whether this is immutable replay evidence.
func (resolution ChangeRequestResolution) IsCompleted() bool {
	return resolution.completed.IsValid()
}

// Equal reports exact deterministic resolution equality.
func (resolution ChangeRequestResolution) Equal(
	other ChangeRequestResolution,
) bool {
	if !resolution.IsValid() || !other.IsValid() {
		return false
	}
	if resolution.IsCompleted() || other.IsCompleted() {
		return resolution.completed.Equal(other.completed) && resolution.scope == other.scope &&
			resolution.idempotencyRecordID == other.idempotencyRecordID &&
			resolution.requestHash == other.requestHash
	}
	return resolution.scope == other.scope &&
		resolution.networkRevision == other.networkRevision &&
		resolution.subsystemRevision == other.subsystemRevision &&
		resolution.idempotencyRecordID == other.idempotencyRecordID &&
		resolution.requestHash == other.requestHash && resolution.impact.Equal(other.impact)
}

// IsValid reports whether revisions and evidence are coherent.
func (resolution ChangeRequestResolution) IsValid() bool {
	if !resolution.scope.IsValid() || !resolution.idempotencyRecordID.IsValid() ||
		!resolution.requestHash.IsValid() {
		return false
	}
	if resolution.completed.IsValid() {
		return resolution.completed.Scope() == resolution.scope &&
			resolution.networkRevision == 0 && resolution.subsystemRevision == 0 &&
			!resolution.impact.IsValid()
	}
	return resolution.networkRevision > 0 && resolution.subsystemRevision > 0 &&
		resolution.networkRevision >= resolution.subsystemRevision &&
		resolution.impact.IsValid() && resolution.impact.Preview().Scope() == resolution.scope
}

// ChangeRequestChange is one atomic, replayable pending proposal.
type ChangeRequestChange struct {
	command            ChangeRequestCommand
	resolution         ChangeRequestResolution
	mutationIDs        ChangeRequestMutationIDs
	occurredAt         time.Time
	requestExpiresAt   time.Time
	idempotencyExpires time.Time
}

// NewAuthorityChangeRequestChange validates proposal mutation evidence.
func NewAuthorityChangeRequestChange(
	command ChangeRequestCommand,
	resolution ChangeRequestResolution,
	mutationIDs ChangeRequestMutationIDs,
	occurredAt, requestExpiresAt, idempotencyExpiresAt time.Time,
) (ChangeRequestChange, error) {
	change := ChangeRequestChange{
		command: command, resolution: resolution, mutationIDs: mutationIDs,
		occurredAt: occurredAt.UTC(), requestExpiresAt: requestExpiresAt.UTC(),
		idempotencyExpires: idempotencyExpiresAt.UTC(),
	}
	if !change.IsValid() {
		return ChangeRequestChange{}, ErrInvalidAuthorityChangeRequestChange
	}
	return change, nil
}

// Command returns immutable proposal intent.
func (change ChangeRequestChange) Command() ChangeRequestCommand {
	return change.command
}

// Resolution returns locked before/after evidence.
func (change ChangeRequestChange) Resolution() ChangeRequestResolution {
	return change.resolution
}

// MutationIDs returns retry-stable durable identities.
func (change ChangeRequestChange) MutationIDs() ChangeRequestMutationIDs {
	return change.mutationIDs
}

// OccurredAt returns one stable decision time.
func (change ChangeRequestChange) OccurredAt() time.Time { return change.occurredAt }

// RequestExpiresAt returns the exclusive second-actor deadline.
func (change ChangeRequestChange) RequestExpiresAt() time.Time {
	return change.requestExpiresAt
}

// IdempotencyExpiresAt returns the exclusive replay-evidence deadline.
func (change ChangeRequestChange) IdempotencyExpiresAt() time.Time {
	return change.idempotencyExpires
}

// IsValid reports whether all proposal mutation facts agree.
func (change ChangeRequestChange) IsValid() bool {
	return change.command.IsValid() && change.resolution.IsValid() &&
		!change.resolution.IsCompleted() && change.mutationIDs.IsValid() &&
		change.command.Scope() == change.resolution.Scope() &&
		change.command.ImpactHash() == change.resolution.Impact().Hash() &&
		!change.occurredAt.IsZero() &&
		change.requestExpiresAt.Equal(change.occurredAt.Add(AuthorityChangeRequestLifetime)) &&
		change.idempotencyExpires.After(change.requestExpiresAt)
}

// ChangeRequestResult is safe committed pending-request evidence.
type ChangeRequestResult struct {
	requestID         ChangeRequestID
	preview           ChangePreview
	requestVersion    int64
	networkRevision   int64
	subsystemRevision int64
	impactHash        ChangeImpactHash
	expiresAt         time.Time
}

// NewAuthorityChangeRequestResult validates committed pending-request evidence.
func NewAuthorityChangeRequestResult(
	requestID ChangeRequestID,
	preview ChangePreview,
	requestVersion, networkRevision, subsystemRevision int64,
	impactHash ChangeImpactHash,
	expiresAt time.Time,
) (ChangeRequestResult, error) {
	result := ChangeRequestResult{
		requestID: requestID, preview: preview, requestVersion: requestVersion,
		networkRevision: networkRevision, subsystemRevision: subsystemRevision,
		impactHash: impactHash, expiresAt: expiresAt.UTC(),
	}
	if !result.IsValid() {
		return ChangeRequestResult{}, ErrInvalidAuthorityChangeRequestResult
	}
	return result, nil
}

// RequestID returns the durable confirmation target.
func (result ChangeRequestResult) RequestID() ChangeRequestID {
	return result.requestID
}

// Preview returns the exact proposed protected intent.
func (result ChangeRequestResult) Preview() ChangePreview {
	return result.preview
}

// Scope returns the exact home Network scope.
func (result ChangeRequestResult) Scope() network.Scope { return result.preview.Scope() }

// RequestVersion returns the pending request CAS version.
func (result ChangeRequestResult) RequestVersion() int64 { return result.requestVersion }

// NetworkRevision returns the proposal visibility revision.
func (result ChangeRequestResult) NetworkRevision() int64 {
	return result.networkRevision
}

// SubsystemRevision returns the proposal subsystem revision.
func (result ChangeRequestResult) SubsystemRevision() int64 {
	return result.subsystemRevision
}

// ImpactHash returns the exact confirmation binding.
func (result ChangeRequestResult) ImpactHash() ChangeImpactHash {
	return result.impactHash
}

// ExpiresAt returns the exclusive confirmation deadline.
func (result ChangeRequestResult) ExpiresAt() time.Time { return result.expiresAt }

// Equal reports exact committed proposal evidence equality.
func (result ChangeRequestResult) Equal(other ChangeRequestResult) bool {
	return result.IsValid() && other.IsValid() && result.requestID == other.requestID &&
		result.preview.Scope() == other.preview.Scope() &&
		result.preview.SubjectKind() == other.preview.SubjectKind() &&
		result.preview.SubjectPublicID() == other.preview.SubjectPublicID() &&
		result.preview.ExpectedVersion() == other.preview.ExpectedVersion() &&
		result.preview.Action() == other.preview.Action() &&
		result.preview.TargetPrincipalID() == other.preview.TargetPrincipalID() &&
		result.preview.AccountSession().ID() == other.preview.AccountSession().ID() &&
		result.preview.AccountSession().PrincipalID() == other.preview.AccountSession().PrincipalID() &&
		result.requestVersion == other.requestVersion &&
		result.networkRevision == other.networkRevision &&
		result.subsystemRevision == other.subsystemRevision &&
		result.impactHash == other.impactHash && result.expiresAt.Equal(other.expiresAt)
}

// IsValid reports whether committed proposal evidence is complete.
func (result ChangeRequestResult) IsValid() bool {
	return result.requestID.IsValid() && result.preview.IsValid() && result.requestVersion == 1 &&
		result.networkRevision > 1 && result.subsystemRevision > 1 &&
		result.networkRevision >= result.subsystemRevision && result.impactHash.IsValid() &&
		!result.expiresAt.IsZero()
}
