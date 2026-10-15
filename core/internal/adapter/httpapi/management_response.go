package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"meshtransit.net/core/internal/domain/guardrail"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/node/revocation"
	"meshtransit.net/core/internal/domain/publicid"
)

type revokeDeviceRequest struct {
	Reason string `json:"reason"`
}

type revokeDeviceResponse struct {
	Data          revokedDevice `json:"data"`
	CorrelationID string        `json:"correlation_id"`
}

type revokedDevice struct {
	DeviceID          string `json:"device_id"`
	State             string `json:"state"`
	DeviceVersion     int64  `json:"device_version"`
	SessionGeneration int64  `json:"session_generation"`
	NetworkRevision   int64  `json:"network_revision"`
	InventoryRevision int64  `json:"inventory_revision"`
}

type managementError struct {
	Status    int
	Code      string
	Message   string
	Retryable bool
	// GuardrailFindings names the acting Workspace's guardrails that blocked
	// a change (code guardrail_violation); empty otherwise.
	GuardrailFindings []guardrailFindingBody
	// PeerEstimate comes with simulation_too_large: the peer counts need no
	// Device-by-Device expansion.
	PeerEstimate *peerEstimateBody
}

type guardrailFindingBody struct {
	GuardrailID string `json:"guardrail_id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Reason      string `json:"reason"`
}

type managementErrorResponse struct {
	Error managementErrorBody `json:"error"`
}

type managementErrorBody struct {
	Code              string                 `json:"code"`
	Message           string                 `json:"message"`
	CorrelationID     string                 `json:"correlation_id"`
	Retryable         bool                   `json:"retryable"`
	GuardrailFindings []guardrailFindingBody `json:"guardrail_findings,omitempty"`
	PeerEstimate      *peerEstimateBody      `json:"peer_estimate,omitempty"`
}

func classifyAuthenticationError(err error) managementError {
	if errors.Is(err, context.DeadlineExceeded) {
		return managementError{
			Status: http.StatusGatewayTimeout, Code: "request_timeout",
			Message: "the request deadline expired", Retryable: true,
		}
	}
	if errors.Is(err, accountsession.ErrAuthenticationUnavailable) || errors.Is(err, context.Canceled) {
		return managementError{
			Status: http.StatusServiceUnavailable, Code: "authentication_unavailable",
			Message: "session authority is temporarily unavailable", Retryable: true,
		}
	}
	return managementError{
		Status: http.StatusUnauthorized, Code: "unauthenticated",
		Message: "Account Session authentication is required",
	}
}

func classifyRevocationError(err error) managementError {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return managementError{
			Status: http.StatusGatewayTimeout, Code: "request_timeout",
			Message: "the request deadline expired", Retryable: true,
		}
	case errors.Is(err, revocation.ErrForbidden):
		return managementError{
			Status: http.StatusForbidden, Code: "forbidden",
			Message: "the request is not authorized",
		}
	case errors.Is(err, revocation.ErrNotFound):
		return managementError{
			Status: http.StatusNotFound, Code: "not_found",
			Message: "the requested resource is unavailable",
		}
	case errors.Is(err, revocation.ErrConflict):
		return managementError{
			Status: http.StatusPreconditionFailed, Code: "precondition_failed",
			Message: "the Device version precondition is stale",
		}
	case errors.Is(err, revocation.ErrIntentConflict):
		return managementError{
			Status: http.StatusConflict, Code: "idempotency_conflict",
			Message: "the idempotency key is bound to different request semantics",
		}
	case errors.Is(err, revocation.ErrAlreadyRevoked):
		return managementError{
			Status: http.StatusConflict, Code: "device_already_revoked",
			Message: "the Device is already revoked",
		}
	case errors.Is(err, revocation.ErrInvalidTransition):
		return managementError{
			Status: http.StatusConflict, Code: "invalid_device_state",
			Message: "the Device cannot be revoked from its current state",
		}
	case errors.Is(err, context.Canceled), errors.Is(err, revocation.ErrRetryableTransaction),
		errors.Is(err, revocation.ErrCommitOutcomeUnknown), errors.Is(err, revocation.ErrRetryExhausted):
		return managementError{
			Status: http.StatusServiceUnavailable, Code: "operation_unavailable",
			Message: "the operation is temporarily unavailable", Retryable: true,
		}
	default:
		return managementError{
			Status: http.StatusInternalServerError, Code: "internal_failure",
			Message: "the request could not be completed",
		}
	}
}

func setManagementSecurityHeaders(header http.Header, correlationID publicid.ID) {
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("X-Correlation-ID", correlationID.String())
}

func writeManagementError(
	ctx context.Context,
	logger *slog.Logger,
	response http.ResponseWriter,
	correlationID publicid.ID,
	apiError managementError,
) {
	if apiError.Status == http.StatusUnauthorized {
		response.Header().Set("WWW-Authenticate", `Bearer realm="meshtransit", error="invalid_token"`)
	}
	if apiError.Retryable {
		if response.Header().Get("Retry-After") == "" {
			response.Header().Set("Retry-After", "1")
		}
	}
	writeManagementJSON(ctx, logger, response, apiError.Status, managementErrorResponse{
		Error: managementErrorBody{
			Code: apiError.Code, Message: apiError.Message,
			CorrelationID: correlationID.String(), Retryable: apiError.Retryable,
			GuardrailFindings: apiError.GuardrailFindings,
			PeerEstimate:      apiError.PeerEstimate,
		},
	})
}

func writeManagementJSON(
	ctx context.Context,
	logger *slog.Logger,
	response http.ResponseWriter,
	status int,
	payload any,
) {
	body, err := json.Marshal(payload)
	if err != nil {
		http.Error(response, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	body = append(body, '\n')
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	if _, err := response.Write(body); err != nil && logger != nil {
		logger.DebugContext(ctx, "management response write failed", "error", err)
	}
}

// guardrailViolation reports a change an enforced guardrail blocked, naming
// each guardrail of the acting Workspace that applies, so the caller can show
// which invariant it broke. ok is false for any other error.
func guardrailViolation(err error) (managementError, bool) {
	// The other Workspace's guardrails stay private: no name, kind or reason.
	var counterpart *guardrail.CounterpartViolationError
	if errors.As(err, &counterpart) {
		return managementError{
			Status: http.StatusConflict, Code: "counterpart_guardrail_violation",
			Message: "the other Workspace does not allow this share",
		}, true
	}
	var violation *guardrail.ViolationError
	if !errors.As(err, &violation) || len(violation.Findings) == 0 {
		return managementError{}, false
	}
	findings := make([]guardrailFindingBody, len(violation.Findings))
	for index, finding := range violation.Findings {
		findings[index] = guardrailFindingBody{
			GuardrailID: finding.GuardrailID.String(), Name: finding.Name,
			Kind: string(finding.Kind), Reason: finding.Reason,
		}
	}
	return managementError{
		Status: http.StatusConflict, Code: "guardrail_violation",
		Message: "a Workspace guardrail blocks this change", GuardrailFindings: findings,
	}, true
}
