package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/invitation"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

// InvitationManager creates, resends, revokes and lists Workspace invitations.
type InvitationManager interface {
	Create(context.Context, accountsession.Session, invitation.CreateRequest) (invitation.Sent, error)
	Resend(context.Context, accountsession.Session, invitation.ActionRequest) (invitation.Sent, error)
	Revoke(context.Context, accountsession.Session, invitation.ActionRequest) (invitation.Invitation, error)
	List(context.Context, accountsession.Session, workspace.ID) ([]invitation.Invitation, error)
	MailConfigured() bool
}

type invitationPath struct {
	workspaceID  workspace.ID
	invitationID publicid.ID
	// methods are the methods the path accepts; action is what the request's
	// method does there: "" for the list, else create, resend or revoke, and
	// "" when the path does not accept the method.
	methods restMethods
	action  string
}

// parseInvitationPath matches, with no query,
//
//	GET|POST /api/v1/workspaces/{ws}/invitations  list, create
//	POST     /api/v1/workspaces/{ws}/invitations/{id}/actions/{resend|revoke}
func parseInvitationPath(request *http.Request) (invitationPath, bool) {
	if request == nil || request.URL == nil || request.URL.RawPath != "" || request.URL.RawQuery != "" {
		return invitationPath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) < 5 || segments[0] != "api" || segments[1] != "v1" || segments[2] != "workspaces" ||
		segments[4] != "invitations" {
		return invitationPath{}, false
	}
	workspaceID, ok := canonicalPublicID(segments[3])
	if !ok {
		return invitationPath{}, false
	}
	path := invitationPath{workspaceID: workspace.ID(workspaceID)}
	var actions map[string]string
	switch len(segments) {
	case 5:
		path.methods, actions = collectionMethods, map[string]string{http.MethodPost: "create"}
	case 8:
		invitationID, idOK := canonicalPublicID(segments[5])
		if !idOK || segments[6] != "actions" || (segments[7] != "resend" && segments[7] != "revoke") {
			return invitationPath{}, false
		}
		path.invitationID, path.methods = invitationID, restMethods{http.MethodPost}
		actions = map[string]string{http.MethodPost: segments[7]}
	default:
		return invitationPath{}, false
	}
	if path.methods.allows(request.Method) {
		path.action = actions[request.Method]
	}
	return path, true
}

// isInvitationOperation admits only the methods each path accepts.
func isInvitationOperation(request *http.Request) bool {
	path, ok := parseInvitationPath(request)
	return ok && path.methods.allows(request.Method)
}

// isInvitationRead admits the exact, query-free invitation list.
func isInvitationRead(request *http.Request) bool {
	path, ok := parseInvitationPath(request)
	return ok && path.action == "" && request.Method == http.MethodGet
}

// allowedMethod is GET for the list and POST for every action.
func (path invitationPath) operation() string {
	if path.action == "" {
		return "workspace_invitations_read"
	}
	return "workspace_invitation_" + path.action
}

func (handler *ManagementHandler) handleInvitations(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path invitationPath, session accountsession.Session) string {
	fail := func(failure managementError) string {
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	response.Header().Set("Cache-Control", "no-store")
	if nilContinuationDependency(handler.invitations) {
		return fail(managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Invitations are temporarily unavailable", Retryable: true})
	}
	if !isInvitationOperation(request) {
		response.Header().Set("Allow", path.methods.header())
		return fail(managementError{Status: http.StatusMethodNotAllowed, Code: "method_not_allowed",
			Message: "the method is not allowed"})
	}
	switch path.action {
	case "":
		listed, err := handler.invitations.List(ctx, session, path.workspaceID)
		if err != nil {
			return fail(classifyInvitationError(err))
		}
		bodies := make([]invitationBody, len(listed))
		for index, value := range listed {
			bodies[index] = newInvitationBody(value)
		}
		writeManagementJSON(ctx, handler.logger, response, http.StatusOK, struct {
			Data struct {
				Invitations    []invitationBody `json:"invitations"`
				MailConfigured bool             `json:"mail_configured"`
			} `json:"data"`
			CorrelationID string `json:"correlation_id"`
		}{Data: struct {
			Invitations    []invitationBody `json:"invitations"`
			MailConfigured bool             `json:"mail_configured"`
		}{bodies, handler.invitations.MailConfigured()}, CorrelationID: correlationID.String()})
		return "success"
	case "create":
		var body struct {
			Email *string `json:"email"`
			Role  *string `json:"role"`
		}
		if !readDeviceGroupBody(response, request, &body) || body.Email == nil {
			return fail(*invalidManagementRequest())
		}
		create := invitation.CreateRequest{WorkspaceID: path.workspaceID, Email: *body.Email, CorrelationID: correlationID}
		if body.Role != nil {
			create.Role = *body.Role
		}
		sent, err := handler.invitations.Create(ctx, session, create)
		if err != nil {
			return fail(classifyInvitationError(err))
		}
		return handler.writeSentInvitation(ctx, response, correlationID, sent, http.StatusCreated)
	}
	expectedVersion, precondition := parseIfMatch(request.Header.Values("If-Match"))
	if precondition != nil {
		return fail(*precondition)
	}
	var empty struct{}
	if !readDeviceGroupBody(response, request, &empty) {
		return fail(*invalidManagementRequest())
	}
	action := invitation.ActionRequest{
		WorkspaceID: path.workspaceID, InvitationID: path.invitationID, ExpectedVersion: expectedVersion,
		CorrelationID: correlationID,
	}
	if path.action == "resend" {
		sent, err := handler.invitations.Resend(ctx, session, action)
		if err != nil {
			return fail(classifyInvitationError(err))
		}
		return handler.writeSentInvitation(ctx, response, correlationID, sent, http.StatusOK)
	}
	revoked, err := handler.invitations.Revoke(ctx, session, action)
	if err != nil {
		return fail(classifyInvitationError(err))
	}
	response.Header().Set("ETag", strongVersionETag(revoked.Version))
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, struct {
		Data          invitationBody `json:"data"`
		CorrelationID string         `json:"correlation_id"`
	}{newInvitationBody(revoked), correlationID.String()})
	return "success"
}

// writeSentInvitation answers the invitation with its link, shown once.
func (handler *ManagementHandler) writeSentInvitation(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, sent invitation.Sent, status int) string {
	response.Header().Set("ETag", strongVersionETag(sent.Invitation.Version))
	type sentBody struct {
		Invitation invitationBody `json:"invitation"`
		InviteURL  string         `json:"invite_url"`
	}
	writeManagementJSON(ctx, handler.logger, response, status, struct {
		Data          sentBody `json:"data"`
		CorrelationID string   `json:"correlation_id"`
	}{sentBody{newInvitationBody(sent.Invitation), sent.Link}, correlationID.String()})
	return "success"
}

type invitationPersonBody struct {
	PrincipalID string `json:"principal_id"`
	DisplayName string `json:"display_name"`
}

type invitationBody struct {
	ID            string               `json:"invitation_id"`
	Email         string               `json:"email"`
	Role          *string              `json:"role"`
	State         string               `json:"state"`
	ExpiresAt     string               `json:"expires_at"`
	InvitedBy     invitationPersonBody `json:"invited_by"`
	DeliveryState string               `json:"delivery_state"`
	LastSentAt    *string              `json:"last_sent_at"`
	SendCount     int                  `json:"send_count"`
	CreatedAt     string               `json:"created_at"`
	Version       int64                `json:"version"`
}

func newInvitationBody(value invitation.Invitation) invitationBody {
	body := invitationBody{
		ID: value.ID.String(), Email: value.Email, State: value.State,
		ExpiresAt: value.ExpiresAt.UTC().Format(time.RFC3339),
		InvitedBy: invitationPersonBody{
			PrincipalID: value.InvitedBy.PrincipalID.String(), DisplayName: value.InvitedBy.DisplayName,
		},
		DeliveryState: value.DeliveryState, SendCount: value.SendCount,
		CreatedAt: value.CreatedAt.UTC().Format(time.RFC3339), Version: value.Version,
	}
	if value.Role != "" {
		role := value.Role
		body.Role = &role
	}
	if value.LastSentAt != nil {
		sent := value.LastSentAt.UTC().Format(time.RFC3339)
		body.LastSentAt = &sent
	}
	return body
}

func classifyInvitationError(err error) managementError {
	switch {
	case errors.Is(err, invitation.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "permission_denied",
			Message: "You cannot invite people, or grant that role, in this Workspace"}
	case errors.Is(err, invitation.ErrNotFound):
		return managementError{Status: http.StatusNotFound, Code: "invitation_not_found",
			Message: "The invitation no longer exists"}
	case errors.Is(err, invitation.ErrVersionConflict):
		return managementError{Status: http.StatusPreconditionFailed, Code: "version_conflict",
			Message: "The invitation changed. Reload and review it again."}
	case errors.Is(err, invitation.ErrAlreadyInvited):
		return managementError{Status: http.StatusConflict, Code: "already_invited",
			Message: "This address already has a pending invitation"}
	case errors.Is(err, invitation.ErrTooMany):
		return managementError{Status: http.StatusConflict, Code: "too_many_invitations",
			Message: "The Workspace has 200 pending invitations"}
	case errors.Is(err, invitation.ErrNotPending):
		return managementError{Status: http.StatusConflict, Code: "invitation_not_pending",
			Message: "The invitation was accepted, revoked or has expired"}
	case errors.Is(err, invitation.ErrTooSoon):
		return managementError{Status: http.StatusTooManyRequests, Code: "resent_too_soon",
			Message: "Wait a minute before resending", Retryable: true}
	case errors.Is(err, invitation.ErrInvalid):
		return *invalidManagementRequest()
	default:
		return managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "The result is uncertain. Reload before trying again.", Retryable: true}
	}
}
