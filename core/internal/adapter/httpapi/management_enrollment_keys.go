package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/enrollmentkey"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

const (
	enrollmentKeyListOperation   = "enrollment_key_list"
	enrollmentKeyCreateOperation = "enrollment_key_create"
	enrollmentKeyRevokeOperation = "enrollment_key_revoke"
)

// EnrollmentKeyManager issues, lists and revokes a Network's enrollment keys.
type EnrollmentKeyManager interface {
	Issue(context.Context, accountsession.Session, enrollmentkey.IssueRequest) (enrollmentkey.Issued, error)
	List(context.Context, accountsession.Session, network.Scope) ([]enrollmentkey.Key, error)
	Revoke(context.Context, accountsession.Session, network.Scope, enrollment.CredentialID, publicid.ID) (
		enrollmentkey.Key, error)
}

type enrollmentKeyPath struct {
	scope network.Scope
	// kind is "list", "create" or "revoke".
	kind  string
	keyID enrollment.CredentialID
}

// parseEnrollmentKeyPath matches, under /api/v1/workspaces/{ws}/networks/{net}:
// GET enrollment-keys, POST enrollment-keys/actions/create and
// POST enrollment-keys/{key}/actions/revoke. None takes a query.
func parseEnrollmentKeyPath(request *http.Request) (enrollmentKeyPath, bool) {
	if request == nil || request.URL == nil || request.URL.RawPath != "" || request.URL.RawQuery != "" {
		return enrollmentKeyPath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) < 7 || segments[0] != "api" || segments[1] != "v1" || segments[2] != "workspaces" ||
		segments[4] != "networks" || segments[6] != "enrollment-keys" {
		return enrollmentKeyPath{}, false
	}
	workspaceID, workspaceOK := canonicalPublicID(segments[3])
	networkID, networkOK := canonicalPublicID(segments[5])
	if !workspaceOK || !networkOK {
		return enrollmentKeyPath{}, false
	}
	scope, err := network.NewScope(workspace.ID(workspaceID), network.ID(networkID))
	if err != nil {
		return enrollmentKeyPath{}, false
	}
	path := enrollmentKeyPath{scope: scope}
	switch rest := segments[7:]; {
	case len(rest) == 0:
		path.kind = "list"
	case len(rest) == 2 && rest[0] == "actions" && rest[1] == "create":
		path.kind = "create"
	case len(rest) == 3 && rest[1] == "actions" && rest[2] == "revoke":
		key, ok := canonicalPublicID(rest[0])
		if !ok {
			return enrollmentKeyPath{}, false
		}
		path.kind, path.keyID = "revoke", enrollment.CredentialID(key)
	default:
		return enrollmentKeyPath{}, false
	}
	return path, true
}

func (path enrollmentKeyPath) allowedMethod() string {
	if path.kind == "list" {
		return http.MethodGet
	}
	return http.MethodPost
}

func (path enrollmentKeyPath) operation() string {
	switch path.kind {
	case "list":
		return enrollmentKeyListOperation
	case "create":
		return enrollmentKeyCreateOperation
	default:
		return enrollmentKeyRevokeOperation
	}
}

// isEnrollmentKeyOperation admits only the method each path allows.
func isEnrollmentKeyOperation(request *http.Request) bool {
	path, ok := parseEnrollmentKeyPath(request)
	return ok && request.Method == path.allowedMethod()
}

type enrollmentKeyCreateRequest struct {
	Description           *string `json:"description"`
	KeyLifetimeSeconds    *int64  `json:"key_lifetime_seconds"`
	DeviceNeverExpires    *bool   `json:"device_never_expires"`
	DeviceLifetimeSeconds *int64  `json:"device_lifetime_seconds"`
}

// issueRequest reads the body: the Device lifetime must be either never or
// a number of seconds, never both and never left out.
func (body enrollmentKeyCreateRequest) issueRequest(scope network.Scope,
	correlationID publicid.ID) (enrollmentkey.IssueRequest, bool) {
	request := enrollmentkey.IssueRequest{Scope: scope, CorrelationID: correlationID}
	if body.Description != nil {
		request.Description = *body.Description
	}
	if body.KeyLifetimeSeconds != nil {
		seconds := *body.KeyLifetimeSeconds
		if seconds <= 0 || seconds > int64(enrollmentkey.MaximumKeyLifetime/time.Second) {
			return enrollmentkey.IssueRequest{}, false
		}
		request.KeyLifetime = time.Duration(seconds) * time.Second
	}
	never := body.DeviceNeverExpires != nil && *body.DeviceNeverExpires
	switch {
	case never && body.DeviceLifetimeSeconds == nil:
		request.DeviceLifetime = enrollment.NeverExpiringDeviceLifetime()
	case !never && body.DeviceLifetimeSeconds != nil:
		seconds := *body.DeviceLifetimeSeconds
		if seconds <= 0 || seconds > int64(enrollment.MaximumDeviceLifetime/time.Second) {
			return enrollmentkey.IssueRequest{}, false
		}
		lifetime, err := enrollment.NewDeviceLifetime(time.Duration(seconds) * time.Second)
		if err != nil {
			return enrollmentkey.IssueRequest{}, false
		}
		request.DeviceLifetime = lifetime
	default:
		return enrollmentkey.IssueRequest{}, false
	}
	return request, true
}

func (handler *ManagementHandler) handleEnrollmentKeys(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path enrollmentKeyPath, session accountsession.Session) string {
	fail := func(failure managementError) string {
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	// A new key's secret is in the body: nothing may store a response.
	response.Header().Set("Cache-Control", "no-store")
	if nilContinuationDependency(handler.enrollmentKeys) {
		return fail(managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Enrollment keys are temporarily unavailable", Retryable: true})
	}
	switch path.kind {
	case "list":
		keys, err := handler.enrollmentKeys.List(ctx, session, path.scope)
		if err != nil {
			return fail(classifyEnrollmentKeyError(err))
		}
		bodies := make([]enrollmentKeyBody, len(keys))
		for index, key := range keys {
			bodies[index] = newEnrollmentKeyBody(key)
		}
		writeManagementJSON(ctx, handler.logger, response, http.StatusOK, struct {
			Data struct {
				NetworkID string              `json:"network_id"`
				Keys      []enrollmentKeyBody `json:"keys"`
			} `json:"data"`
			CorrelationID string `json:"correlation_id"`
		}{Data: struct {
			NetworkID string              `json:"network_id"`
			Keys      []enrollmentKeyBody `json:"keys"`
		}{path.scope.NetworkID().String(), bodies}, CorrelationID: correlationID.String()})
	case "create":
		var body enrollmentKeyCreateRequest
		if !readDeviceGroupBody(response, request, &body) {
			return fail(*invalidManagementRequest())
		}
		issueRequest, ok := body.issueRequest(path.scope, correlationID)
		if !ok {
			return fail(*invalidManagementRequest())
		}
		issued, err := handler.enrollmentKeys.Issue(ctx, session, issueRequest)
		if err != nil {
			return fail(classifyEnrollmentKeyError(err))
		}
		writeManagementJSON(ctx, handler.logger, response, http.StatusCreated, struct {
			Data struct {
				Key enrollmentKeyBody `json:"key"`
				// Secret is shown only here; Core keeps a digest of it.
				Secret string `json:"secret"`
			} `json:"data"`
			CorrelationID string `json:"correlation_id"`
		}{Data: struct {
			Key    enrollmentKeyBody `json:"key"`
			Secret string            `json:"secret"`
		}{newEnrollmentKeyBody(issued.Key()), issued.Presentation().Reveal()}, CorrelationID: correlationID.String()})
	default:
		var body struct{}
		if !readDeviceGroupBody(response, request, &body) {
			return fail(*invalidManagementRequest())
		}
		key, err := handler.enrollmentKeys.Revoke(ctx, session, path.scope, path.keyID, correlationID)
		if err != nil {
			return fail(classifyEnrollmentKeyError(err))
		}
		writeManagementJSON(ctx, handler.logger, response, http.StatusOK, struct {
			Data          enrollmentKeyBody `json:"data"`
			CorrelationID string            `json:"correlation_id"`
		}{newEnrollmentKeyBody(key), correlationID.String()})
	}
	return "success"
}

type enrollmentKeyDeviceLifetimeBody struct {
	NeverExpires bool   `json:"never_expires"`
	Seconds      *int64 `json:"seconds"`
}

type enrollmentKeyDeviceBody struct {
	DeviceID string `json:"device_id"`
	Name     string `json:"name"`
}

type enrollmentKeyBody struct {
	KeyID               string                          `json:"key_id"`
	Description         string                          `json:"description"`
	IssuedByPrincipalID string                          `json:"issued_by_principal_id"`
	CreatedAt           string                          `json:"created_at"`
	ExpiresAt           string                          `json:"expires_at"`
	RevokedAt           *string                         `json:"revoked_at"`
	State               string                          `json:"state"`
	DeviceLifetime      enrollmentKeyDeviceLifetimeBody `json:"device_lifetime"`
	Device              *enrollmentKeyDeviceBody        `json:"device"`
}

func newEnrollmentKeyBody(key enrollmentkey.Key) enrollmentKeyBody {
	body := enrollmentKeyBody{
		KeyID: key.ID().String(), Description: key.Description(),
		IssuedByPrincipalID: key.IssuedBy().String(), CreatedAt: managementTime(key.CreatedAt()),
		ExpiresAt: managementTime(key.ExpiresAt()), State: string(key.State()),
	}
	if !key.RevokedAt().IsZero() {
		revoked := managementTime(key.RevokedAt())
		body.RevokedAt = &revoked
	}
	if lifetime := key.DeviceLifetime(); lifetime.Kind() == enrollment.DeviceLifetimeNever {
		body.DeviceLifetime.NeverExpires = true
	} else {
		seconds := int64(lifetime.Duration() / time.Second)
		body.DeviceLifetime.Seconds = &seconds
	}
	if deviceID, name, enrolled := key.Device(); enrolled {
		body.Device = &enrollmentKeyDeviceBody{DeviceID: deviceID.String(), Name: name}
	}
	return body
}

func classifyEnrollmentKeyError(err error) managementError {
	switch {
	case errors.Is(err, enrollmentkey.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "permission_denied",
			Message: "You cannot manage enrollment keys in this Network"}
	case errors.Is(err, enrollmentkey.ErrNotFound):
		return managementError{Status: http.StatusNotFound, Code: "enrollment_key_not_found",
			Message: "The enrollment key is not in this Network"}
	case errors.Is(err, enrollmentkey.ErrNotActive):
		return managementError{Status: http.StatusConflict, Code: "enrollment_key_revoked",
			Message: "The enrollment key is already revoked"}
	case errors.Is(err, enrollmentkey.ErrLimitReached):
		return managementError{Status: http.StatusConflict, Code: "enrollment_key_limit",
			Message: "The Network already has 100 usable enrollment keys. Revoke one first."}
	case errors.Is(err, enrollmentkey.ErrInvalid):
		return *invalidManagementRequest()
	default:
		return managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "The result is uncertain. Reload before trying again.", Retryable: true}
	}
}
