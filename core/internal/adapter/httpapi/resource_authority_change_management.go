package httpapi

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/resource"
	authority "github.com/meshtransit/meshtransit/core/internal/domain/resource/authority"
	"github.com/meshtransit/meshtransit/core/internal/platform/idempotency"
)

type resourceAuthorityChangePreviewRequest struct {
	Action            string `json:"action"`
	TargetPrincipalID string `json:"target_principal_id"`
}

type resourceAuthorityChangeRequest struct {
	Action            string `json:"action"`
	TargetPrincipalID string `json:"target_principal_id"`
	ImpactHash        string `json:"impact_hash"`
	Reason            string `json:"reason"`
}

type resourceAuthorityChangeConfirmationRequest struct {
	ChangeRequestID string `json:"change_request_id"`
	ImpactHash      string `json:"impact_hash"`
	Reason          string `json:"reason"`
}

func (handler *ManagementHandler) changeResourceAuthority(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	correlationID publicid.ID,
	path resourceManagementPath,
	session accountsession.Session,
) string {
	if request.URL.RawQuery != "" || request.Body == nil ||
		!validJSONContentType(singleHeader(request.Header, "Content-Type")) {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	scope, err := path.scope()
	if err != nil {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	expectedVersion, requestErr := parseIfMatch(request.Header.Values("If-Match"))
	if requestErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
		return requestErr.Code
	}
	if path.action == "confirm-authority-change" {
		return handler.confirmResourceAuthorityChange(
			ctx, response, request, correlationID, path, scope, expectedVersion, session,
		)
	}
	var wire resourceAuthorityChangePreviewRequest
	if path.action == "preview-authority-change" {
		if len(request.Header.Values("Idempotency-Key")) != 0 {
			return handler.writeResourceRequestError(ctx, response, correlationID)
		}
		if requestErr = decodeResourceBody(response, request, &wire); requestErr != nil {
			writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
			return requestErr.Code
		}
		preview, err := newResourceAuthorityChangePreview(
			path, scope, expectedVersion, wire.Action, wire.TargetPrincipalID, session,
		)
		if err != nil {
			return handler.writeResourceRequestError(ctx, response, correlationID)
		}
		impact, err := handler.resourceAuthorityChanges.Preview(ctx, preview)
		if err != nil {
			classified := classifyResourceAuthorityChangeError(err)
			writeManagementError(ctx, handler.logger, response, correlationID, classified)
			return classified.Code
		}
		if !resourceAuthorityChangeImpactMatches(impact, preview) {
			writeManagementError(ctx, handler.logger, response, correlationID, internalManagementError())
			return "internal_failure"
		}
		response.Header().Set("ETag", strongVersionETag(expectedVersion))
		writeManagementJSON(
			ctx, handler.logger, response, http.StatusOK,
			resourceAuthorityChangePreviewEnvelope{
				Data:          resourceAuthorityChangePreviewDataFromImpact(impact),
				CorrelationID: correlationID.String(),
			},
		)
		return "success"
	}
	var body resourceAuthorityChangeRequest
	if requestErr = decodeResourceBody(response, request, &body); requestErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
		return requestErr.Code
	}
	preview, err := newResourceAuthorityChangePreview(
		path, scope, expectedVersion, body.Action, body.TargetPrincipalID, session,
	)
	if err != nil {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	proof, err := handler.resourceAuthorityChangeProof(request)
	if err != nil {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	impactHash, err := parseResourceAuthorityChangeImpactHash(body.ImpactHash)
	if err != nil {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	reason, err := authority.NewAuditReason(body.Reason)
	if err != nil {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	command, err := authority.NewAuthorityChangeRequestCommand(
		preview, impactHash, reason, proof,
	)
	if err != nil {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	result, err := handler.resourceAuthorityChanges.Request(ctx, command)
	if err != nil {
		classified := classifyResourceAuthorityChangeError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, classified)
		return classified.Code
	}
	if !resourceAuthorityChangeRequestResultMatches(result, command) {
		writeManagementError(ctx, handler.logger, response, correlationID, internalManagementError())
		return "internal_failure"
	}
	response.Header().Set("ETag", strongVersionETag(result.RequestVersion()))
	writeManagementJSON(
		ctx, handler.logger, response, http.StatusAccepted,
		resourceAuthorityChangeRequestEnvelope{
			Data:          resourceAuthorityChangeRequestDataFromResult(result),
			CorrelationID: correlationID.String(),
		},
	)
	return "success"
}

func (handler *ManagementHandler) confirmResourceAuthorityChange(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	correlationID publicid.ID,
	path resourceManagementPath,
	scope network.Scope,
	expectedRequestVersion int64,
	session accountsession.Session,
) string {
	var body resourceAuthorityChangeConfirmationRequest
	requestErr := decodeResourceBody(response, request, &body)
	if requestErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
		return requestErr.Code
	}
	proof, err := handler.resourceAuthorityChangeProof(request)
	if err != nil {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	requestID, err := authority.ParseAuthorityChangeRequestID(body.ChangeRequestID)
	if err != nil {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	impactHash, err := parseResourceAuthorityChangeImpactHash(body.ImpactHash)
	if err != nil {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	reason, err := authority.NewAuditReason(body.Reason)
	if err != nil {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	var command authority.ChangeConfirmationCommand
	if path.kind == resourceGroupManagementItem {
		groupID, parseErr := resource.ParseGroupID(path.publicID)
		if parseErr != nil {
			return handler.writeResourceRequestError(ctx, response, correlationID)
		}
		command, err = authority.NewGroupAuthorityChangeConfirmation(
			scope, groupID, requestID, expectedRequestVersion,
			impactHash, session, reason, proof,
		)
	} else {
		resourceID, parseErr := resource.ParseID(path.publicID)
		if parseErr != nil {
			return handler.writeResourceRequestError(ctx, response, correlationID)
		}
		command, err = authority.NewResourceAuthorityChangeConfirmation(
			scope, resourceID, requestID, expectedRequestVersion,
			impactHash, session, reason, proof,
		)
	}
	if err != nil {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	result, err := handler.resourceAuthorityChanges.Confirm(ctx, command)
	if err != nil {
		classified := classifyResourceAuthorityChangeError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, classified)
		return classified.Code
	}
	if !resourceAuthorityChangeConfirmationResultMatches(result, command) {
		writeManagementError(ctx, handler.logger, response, correlationID, internalManagementError())
		return "internal_failure"
	}
	response.Header().Set("ETag", strongVersionETag(result.SubjectVersion()))
	writeManagementJSON(
		ctx, handler.logger, response, http.StatusOK,
		resourceAuthorityChangeConfirmationEnvelope{
			Data:          resourceAuthorityChangeConfirmationDataFromResult(result),
			CorrelationID: correlationID.String(),
		},
	)
	return "success"
}

func newResourceAuthorityChangePreview(
	path resourceManagementPath,
	scope network.Scope,
	expectedVersion int64,
	actionValue, targetValue string,
	session accountsession.Session,
) (authority.ChangePreview, error) {
	action, err := authority.ParseAuthorityChangeAction(actionValue)
	if err != nil {
		return authority.ChangePreview{}, err
	}
	targetID, err := identity.ParsePrincipalID(targetValue)
	if err != nil {
		return authority.ChangePreview{}, err
	}
	if path.kind == resourceGroupManagementItem {
		groupID, err := resource.ParseGroupID(path.publicID)
		if err != nil {
			return authority.ChangePreview{}, err
		}
		return authority.NewGroupAuthorityChangePreview(
			scope, groupID, expectedVersion, action, targetID, session,
		)
	}
	resourceID, err := resource.ParseID(path.publicID)
	if err != nil {
		return authority.ChangePreview{}, err
	}
	return authority.NewResourceAuthorityChangePreview(
		scope, resourceID, expectedVersion, action, targetID, session,
	)
}

func (handler *ManagementHandler) resourceAuthorityChangeProof(
	request *http.Request,
) (idempotency.Proof, error) {
	rawKey := singleHeader(request.Header, "Idempotency-Key")
	if rawKey == "" {
		return idempotency.Proof{}, idempotency.ErrInvalidRawKey
	}
	proof, err := handler.idempotency.Proof(rawKey)
	if err != nil || !proof.IsValid() {
		return idempotency.Proof{}, idempotency.ErrInvalidRawKey
	}
	return proof, nil
}

func parseResourceAuthorityChangeImpactHash(
	value string,
) (authority.ChangeImpactHash, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != value {
		return authority.ChangeImpactHash{}, authority.ErrInvalidAuthorityChangeImpact
	}
	var fixed [32]byte
	copy(fixed[:], decoded)
	return authority.NewAuthorityChangeImpactHash(fixed)
}

type resourceAuthorityChangePreviewData struct {
	SubjectKind                  string `json:"subject_kind"`
	SubjectPublicID              string `json:"subject_public_id"`
	Action                       string `json:"action"`
	TargetPrincipalID            string `json:"target_principal_id"`
	CurrentOwnerPrincipalID      string `json:"current_owner_principal_id"`
	CurrentCustodianPrincipalID  string `json:"current_custodian_principal_id"`
	ProposedOwnerPrincipalID     string `json:"proposed_owner_principal_id"`
	ProposedCustodianPrincipalID string `json:"proposed_custodian_principal_id"`
	CurrentSemanticHash          string `json:"current_semantic_hash"`
	ProposedSemanticHash         string `json:"proposed_semantic_hash"`
	ImpactHash                   string `json:"impact_hash"`
	ConfirmationPrincipalID      string `json:"confirmation_principal_id"`
	RequiredConfirmations        int    `json:"required_confirmations"`
	MaximumStepUpAgeSeconds      int64  `json:"maximum_step_up_age_seconds"`
}

type resourceAuthorityChangePreviewEnvelope struct {
	Data          resourceAuthorityChangePreviewData `json:"data"`
	CorrelationID string                             `json:"correlation_id"`
}

type resourceAuthorityChangeRequestData struct {
	ChangeRequestID   string    `json:"change_request_id"`
	SubjectKind       string    `json:"subject_kind"`
	SubjectPublicID   string    `json:"subject_public_id"`
	Action            string    `json:"action"`
	TargetPrincipalID string    `json:"target_principal_id"`
	RequestVersion    int64     `json:"request_version"`
	NetworkRevision   int64     `json:"network_revision"`
	SubsystemRevision int64     `json:"subsystem_revision"`
	ImpactHash        string    `json:"impact_hash"`
	ExpiresAt         time.Time `json:"expires_at"`
}

type resourceAuthorityChangeRequestEnvelope struct {
	Data          resourceAuthorityChangeRequestData `json:"data"`
	CorrelationID string                             `json:"correlation_id"`
}

type resourceAuthorityChangeConfirmationData struct {
	ChangeRequestID      string `json:"change_request_id"`
	SubjectKind          string `json:"subject_kind"`
	SubjectPublicID      string `json:"subject_public_id"`
	Action               string `json:"action"`
	SubjectVersion       int64  `json:"subject_version"`
	RequestVersion       int64  `json:"request_version"`
	NetworkRevision      int64  `json:"network_revision"`
	SubsystemRevision    int64  `json:"subsystem_revision"`
	OwnerPrincipalID     string `json:"owner_principal_id"`
	CustodianPrincipalID string `json:"custodian_principal_id"`
	SemanticHash         string `json:"semantic_hash"`
	ImpactHash           string `json:"impact_hash"`
}

type resourceAuthorityChangeConfirmationEnvelope struct {
	Data          resourceAuthorityChangeConfirmationData `json:"data"`
	CorrelationID string                                  `json:"correlation_id"`
}

func resourceAuthorityChangeImpactMatches(
	impact authority.ChangeImpact,
	preview authority.ChangePreview,
) bool {
	actual := impact.Preview()
	return impact.IsValid() && actual.Scope() == preview.Scope() &&
		actual.SubjectKind() == preview.SubjectKind() &&
		actual.SubjectPublicID() == preview.SubjectPublicID() &&
		actual.ExpectedVersion() == preview.ExpectedVersion() &&
		actual.Action() == preview.Action() &&
		actual.TargetPrincipalID() == preview.TargetPrincipalID() &&
		actual.AccountSession().ID() == preview.AccountSession().ID()
}

func resourceAuthorityChangePreviewDataFromImpact(
	impact authority.ChangeImpact,
) resourceAuthorityChangePreviewData {
	preview := impact.Preview()
	currentHash := impact.CurrentSemanticHash().Bytes()
	proposedHash := impact.ProposedSemanticHash().Bytes()
	impactHash := impact.Hash().Bytes()
	return resourceAuthorityChangePreviewData{
		SubjectKind:     preview.SubjectKind().String(),
		SubjectPublicID: preview.SubjectPublicID().String(), Action: preview.Action().String(),
		TargetPrincipalID:            preview.TargetPrincipalID().String(),
		CurrentOwnerPrincipalID:      impact.CurrentOwnerPrincipalID().String(),
		CurrentCustodianPrincipalID:  impact.CurrentCustodianPrincipalID().String(),
		ProposedOwnerPrincipalID:     impact.ProposedOwnerPrincipalID().String(),
		ProposedCustodianPrincipalID: impact.ProposedCustodianPrincipalID().String(),
		CurrentSemanticHash:          hex.EncodeToString(currentHash[:]),
		ProposedSemanticHash:         hex.EncodeToString(proposedHash[:]),
		ImpactHash:                   hex.EncodeToString(impactHash[:]),
		ConfirmationPrincipalID:      impact.ConfirmationPrincipalID().String(),
		RequiredConfirmations:        impact.RequiredConfirmations(),
		MaximumStepUpAgeSeconds:      int64(impact.MaximumStepUpAge() / time.Second),
	}
}

func resourceAuthorityChangeRequestResultMatches(
	result authority.ChangeRequestResult,
	command authority.ChangeRequestCommand,
) bool {
	actual, expected := result.Preview(), command.Preview()
	return result.IsValid() && result.Scope() == command.Scope() &&
		actual.SubjectKind() == expected.SubjectKind() &&
		actual.SubjectPublicID() == expected.SubjectPublicID() &&
		actual.ExpectedVersion() == expected.ExpectedVersion() &&
		actual.Action() == expected.Action() &&
		actual.TargetPrincipalID() == expected.TargetPrincipalID() &&
		actual.AccountSession().ID() == expected.AccountSession().ID() &&
		actual.AccountSession().PrincipalID() == expected.AccountSession().PrincipalID() &&
		result.ImpactHash() == command.ImpactHash()
}

func resourceAuthorityChangeRequestDataFromResult(
	result authority.ChangeRequestResult,
) resourceAuthorityChangeRequestData {
	preview := result.Preview()
	impactHash := result.ImpactHash().Bytes()
	return resourceAuthorityChangeRequestData{
		ChangeRequestID: result.RequestID().String(),
		SubjectKind:     preview.SubjectKind().String(),
		SubjectPublicID: preview.SubjectPublicID().String(), Action: preview.Action().String(),
		TargetPrincipalID: preview.TargetPrincipalID().String(),
		RequestVersion:    result.RequestVersion(), NetworkRevision: result.NetworkRevision(),
		SubsystemRevision: result.SubsystemRevision(),
		ImpactHash:        hex.EncodeToString(impactHash[:]), ExpiresAt: result.ExpiresAt(),
	}
}

func resourceAuthorityChangeConfirmationResultMatches(
	result authority.ChangeConfirmationResult,
	command authority.ChangeConfirmationCommand,
) bool {
	return result.IsValid() && result.RequestID() == command.RequestID() &&
		result.Scope() == command.Scope() && result.SubjectKind() == command.SubjectKind() &&
		result.SubjectPublicID() == command.SubjectPublicID() &&
		result.RequestVersion() == command.ExpectedRequestVersion()+1 &&
		result.ImpactHash() == command.ImpactHash()
}

func resourceAuthorityChangeConfirmationDataFromResult(
	result authority.ChangeConfirmationResult,
) resourceAuthorityChangeConfirmationData {
	semanticHash := result.SemanticHash().Bytes()
	impactHash := result.ImpactHash().Bytes()
	return resourceAuthorityChangeConfirmationData{
		ChangeRequestID: result.RequestID().String(), SubjectKind: result.SubjectKind().String(),
		SubjectPublicID: result.SubjectPublicID().String(), Action: result.Action().String(),
		SubjectVersion: result.SubjectVersion(), RequestVersion: result.RequestVersion(),
		NetworkRevision: result.NetworkRevision(), SubsystemRevision: result.SubsystemRevision(),
		OwnerPrincipalID:     result.OwnerPrincipalID().String(),
		CustodianPrincipalID: result.CustodianPrincipalID().String(),
		SemanticHash:         hex.EncodeToString(semanticHash[:]),
		ImpactHash:           hex.EncodeToString(impactHash[:]),
	}
}

func classifyResourceAuthorityChangeError(err error) managementError {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return managementError{Status: http.StatusGatewayTimeout, Code: "request_timeout", Message: "the request deadline expired", Retryable: true}
	case errors.Is(err, authority.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "forbidden", Message: "the request is not authorized"}
	case errors.Is(err, authority.ErrAuthorityChangeNotFound):
		return managementError{Status: http.StatusNotFound, Code: "not_found", Message: "the authority change target is unavailable"}
	case errors.Is(err, authority.ErrAuthorityChangeVersionConflict),
		errors.Is(err, authority.ErrAuthorityChangeRequestVersionConflict):
		return managementError{Status: http.StatusPreconditionFailed, Code: "precondition_failed", Message: "the authority version precondition is stale"}
	case errors.Is(err, authority.ErrAuthorityChangeStepUpRequired):
		return managementError{Status: http.StatusPreconditionRequired, Code: "step_up_required", Message: "fresh single-use step-up authentication is required"}
	case errors.Is(err, authority.ErrAuthorityChangeRequestExpired):
		return managementError{Status: http.StatusGone, Code: "request_expired", Message: "the authority change request expired"}
	case errors.Is(err, authority.ErrAuthorityChangeImpactChanged):
		return managementError{Status: http.StatusConflict, Code: "impact_changed", Message: "the acknowledged authority change impact is stale"}
	case errors.Is(err, authority.ErrAuthorityChangeStateConflict),
		errors.Is(err, authority.ErrAuthorityChangeRequestStateConflict):
		return managementError{Status: http.StatusConflict, Code: "invalid_state_transition", Message: "the authority change cannot be applied in its current state"}
	case errors.Is(err, authority.ErrAuthorityChangeTargetConflict):
		return managementError{Status: http.StatusConflict, Code: "target_conflict", Message: "the proposed authority holder is unavailable"}
	case errors.Is(err, authority.ErrIntentConflict):
		return managementError{Status: http.StatusConflict, Code: "idempotency_conflict", Message: "the idempotency key is bound to different request semantics"}
	case errors.Is(err, authority.ErrIdempotencyExpired):
		return managementError{Status: http.StatusConflict, Code: "idempotency_expired", Message: "the idempotency replay window expired"}
	case errors.Is(err, context.Canceled), errors.Is(err, authority.ErrRetryableTransaction),
		errors.Is(err, authority.ErrCommitOutcomeUnknown), errors.Is(err, authority.ErrRetryExhausted):
		return resourceUnavailableError()
	default:
		return internalManagementError()
	}
}
