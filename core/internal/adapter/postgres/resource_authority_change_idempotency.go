package postgres

import (
	"encoding/hex"
	"time"

	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/resource"
	authority "meshtransit.net/core/internal/domain/resource/authority"
)

func (record resourceAuthorityIdempotencyRecord) authorityChangeRequestResult(
	command authority.ChangeRequestCommand,
) (authority.ChangeRequestResult, error) {
	preview := command.Preview()
	if record.state != "completed" ||
		record.resultKind != resourceAuthorityChangeRequestResultKind ||
		record.resultVersion != 1 || record.resultNetworkRevision <= 1 {
		return authority.ChangeRequestResult{}, ErrResourceAuthorityEvidence
	}
	requestID, err := authority.ParseAuthorityChangeRequestID(record.resultPublicID)
	if err != nil {
		return authority.ChangeRequestResult{}, ErrResourceAuthorityEvidence
	}
	var payload resourceAuthorityChangeRequestPayload
	if err := decodeAuthorityChangePayload(record.resultPayload, &payload); err != nil ||
		payload.SubjectKind != preview.SubjectKind().String() ||
		payload.SubjectPublicID != preview.SubjectPublicID().String() ||
		payload.Action != preview.Action().String() ||
		payload.TargetPrincipalID != preview.TargetPrincipalID().String() ||
		payload.SubsystemRevision <= 1 {
		return authority.ChangeRequestResult{}, ErrResourceAuthorityEvidence
	}
	impactHash, err := decodeAuthorityChangeImpactHash(payload.ImpactHash)
	if err != nil || impactHash != command.ImpactHash() {
		return authority.ChangeRequestResult{}, ErrResourceAuthorityEvidence
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, payload.ExpiresAt)
	if err != nil {
		return authority.ChangeRequestResult{}, ErrResourceAuthorityEvidence
	}
	result, err := authority.NewAuthorityChangeRequestResult(
		requestID, preview, record.resultVersion, record.resultNetworkRevision,
		payload.SubsystemRevision, impactHash, expiresAt,
	)
	if err != nil {
		return authority.ChangeRequestResult{}, ErrResourceAuthorityEvidence
	}
	return result, nil
}

func resolveAuthorityChangeRequestIdempotency(
	record resourceAuthorityIdempotencyRecord,
	command authority.ChangeRequestCommand,
	ids authority.ChangeRequestMutationIDs,
	occurredAt time.Time,
) (authority.ChangeRequestResolution, error) {
	requestHash, err := command.RequestHash()
	if err != nil {
		return authority.ChangeRequestResolution{},
			authority.ErrInvalidAuthorityChangeRequestCommand
	}
	storedHash, err := authorityChangeRequestHash(record.requestSemanticHash)
	if err != nil {
		return authority.ChangeRequestResolution{}, err
	}
	if storedHash != requestHash {
		return authority.ChangeRequestResolution{}, authority.ErrIntentConflict
	}
	if !record.expiresAt.After(occurredAt) {
		return authority.ChangeRequestResolution{}, authority.ErrIdempotencyExpired
	}
	if record.created {
		if record.state != "pending" ||
			record.publicID != ids.IdempotencyRecordID().String() ||
			record.resultKind != "" || record.resultPublicID != "" ||
			record.resultVersion != 0 || record.resultNetworkRevision != 0 ||
			record.resultPayload != "{}" {
			return authority.ChangeRequestResolution{}, ErrResourceAuthorityEvidence
		}
		return authority.ChangeRequestResolution{}, nil
	}
	result, err := record.authorityChangeRequestResult(command)
	if err != nil {
		return authority.ChangeRequestResolution{}, err
	}
	recordID, err := publicid.Parse(record.publicID)
	if err != nil {
		return authority.ChangeRequestResolution{}, ErrResourceAuthorityEvidence
	}
	resolution, err := authority.NewCompletedAuthorityChangeRequestResolution(
		result, recordID, storedHash,
	)
	if err != nil {
		return authority.ChangeRequestResolution{}, ErrResourceAuthorityEvidence
	}
	return resolution, nil
}

func authorityChangeRequestCommittedRecord(
	record resourceAuthorityIdempotencyRecord,
	command authority.ChangeRequestCommand,
	now time.Time,
) (authority.ChangeRequestResult, bool, error) {
	if record.publicID == "" {
		return authority.ChangeRequestResult{}, false, nil
	}
	requestHash, err := command.RequestHash()
	if err != nil {
		return authority.ChangeRequestResult{}, false,
			authority.ErrInvalidAuthorityChangeRequestCommand
	}
	storedHash, err := authorityChangeRequestHash(record.requestSemanticHash)
	if err != nil {
		return authority.ChangeRequestResult{}, false, err
	}
	if storedHash != requestHash {
		return authority.ChangeRequestResult{}, false, authority.ErrIntentConflict
	}
	if !record.expiresAt.After(now) {
		return authority.ChangeRequestResult{}, false, nil
	}
	result, err := record.authorityChangeRequestResult(command)
	if err != nil {
		return authority.ChangeRequestResult{}, false, err
	}
	return result, true, nil
}

func (record resourceAuthorityIdempotencyRecord) authorityChangeConfirmationResult(
	command authority.ChangeConfirmationCommand,
) (authority.ChangeConfirmationResult, error) {
	if record.state != "completed" || record.resultKind != resourceAuthorityChangeResultKind ||
		record.resultPublicID != command.SubjectPublicID().String() ||
		record.resultVersion <= 1 || record.resultNetworkRevision <= 1 {
		return authority.ChangeConfirmationResult{}, ErrResourceAuthorityEvidence
	}
	var payload resourceAuthorityChangeResultPayload
	if err := decodeAuthorityChangePayload(record.resultPayload, &payload); err != nil ||
		payload.SubjectKind != command.SubjectKind().String() ||
		payload.SubjectPublicID != command.SubjectPublicID().String() ||
		payload.RequestVersion != command.ExpectedRequestVersion()+1 ||
		payload.SubsystemRevision <= 1 {
		return authority.ChangeConfirmationResult{}, ErrResourceAuthorityEvidence
	}
	action, err := authority.ParseAuthorityChangeAction(payload.Action)
	if err != nil {
		return authority.ChangeConfirmationResult{}, ErrResourceAuthorityEvidence
	}
	ownerID, err := identity.ParsePrincipalID(payload.OwnerPrincipalID)
	if err != nil {
		return authority.ChangeConfirmationResult{}, ErrResourceAuthorityEvidence
	}
	custodianID, err := identity.ParsePrincipalID(payload.CustodianPrincipalID)
	if err != nil {
		return authority.ChangeConfirmationResult{}, ErrResourceAuthorityEvidence
	}
	semanticHashBytes, err := hex.DecodeString(payload.SemanticHash)
	if err != nil {
		return authority.ChangeConfirmationResult{}, ErrResourceAuthorityEvidence
	}
	semanticHash, err := resourceSemanticHash(semanticHashBytes)
	if err != nil {
		return authority.ChangeConfirmationResult{}, err
	}
	impactHash, err := decodeAuthorityChangeImpactHash(payload.ImpactHash)
	if err != nil || impactHash != command.ImpactHash() {
		return authority.ChangeConfirmationResult{}, ErrResourceAuthorityEvidence
	}
	var resourceID resource.ID
	var groupID resource.GroupID
	if command.SubjectKind() == authority.AuthoritySubjectResource {
		resourceID = command.ResourceID()
	} else {
		groupID = command.GroupID()
	}
	result, err := authority.NewAuthorityChangeConfirmationResult(
		command.RequestID(), command.Scope(), command.SubjectKind(), resourceID, groupID,
		action, record.resultVersion, payload.RequestVersion,
		record.resultNetworkRevision, payload.SubsystemRevision,
		ownerID, custodianID, semanticHash, impactHash,
	)
	if err != nil {
		return authority.ChangeConfirmationResult{}, ErrResourceAuthorityEvidence
	}
	return result, nil
}

func resolveAuthorityChangeConfirmationIdempotency(
	record resourceAuthorityIdempotencyRecord,
	command authority.ChangeConfirmationCommand,
	ids authority.ChangeConfirmationMutationIDs,
	occurredAt time.Time,
) (authority.ChangeConfirmationResolution, error) {
	requestHash, err := command.RequestHash()
	if err != nil {
		return authority.ChangeConfirmationResolution{},
			authority.ErrInvalidAuthorityChangeConfirmationCommand
	}
	storedHash, err := authorityChangeConfirmationHash(record.requestSemanticHash)
	if err != nil {
		return authority.ChangeConfirmationResolution{}, err
	}
	if storedHash != requestHash {
		return authority.ChangeConfirmationResolution{}, authority.ErrIntentConflict
	}
	if !record.expiresAt.After(occurredAt) {
		return authority.ChangeConfirmationResolution{}, authority.ErrIdempotencyExpired
	}
	if record.created {
		if record.state != "pending" ||
			record.publicID != ids.IdempotencyRecordID().String() ||
			record.resultKind != "" || record.resultPublicID != "" ||
			record.resultVersion != 0 || record.resultNetworkRevision != 0 ||
			record.resultPayload != "{}" {
			return authority.ChangeConfirmationResolution{}, ErrResourceAuthorityEvidence
		}
		return authority.ChangeConfirmationResolution{}, nil
	}
	result, err := record.authorityChangeConfirmationResult(command)
	if err != nil {
		return authority.ChangeConfirmationResolution{}, err
	}
	recordID, err := publicid.Parse(record.publicID)
	if err != nil {
		return authority.ChangeConfirmationResolution{}, ErrResourceAuthorityEvidence
	}
	resolution, err := authority.NewCompletedAuthorityChangeConfirmationResolution(
		result, recordID, storedHash,
	)
	if err != nil {
		return authority.ChangeConfirmationResolution{}, ErrResourceAuthorityEvidence
	}
	return resolution, nil
}

func authorityChangeConfirmationCommittedRecord(
	record resourceAuthorityIdempotencyRecord,
	command authority.ChangeConfirmationCommand,
	now time.Time,
) (authority.ChangeConfirmationResult, bool, error) {
	if record.publicID == "" {
		return authority.ChangeConfirmationResult{}, false, nil
	}
	requestHash, err := command.RequestHash()
	if err != nil {
		return authority.ChangeConfirmationResult{}, false,
			authority.ErrInvalidAuthorityChangeConfirmationCommand
	}
	storedHash, err := authorityChangeConfirmationHash(record.requestSemanticHash)
	if err != nil {
		return authority.ChangeConfirmationResult{}, false, err
	}
	if storedHash != requestHash {
		return authority.ChangeConfirmationResult{}, false, authority.ErrIntentConflict
	}
	if !record.expiresAt.After(now) {
		return authority.ChangeConfirmationResult{}, false, nil
	}
	result, err := record.authorityChangeConfirmationResult(command)
	if err != nil {
		return authority.ChangeConfirmationResult{}, false, err
	}
	return result, true, nil
}
