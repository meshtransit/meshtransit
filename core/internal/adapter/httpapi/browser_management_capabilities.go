package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/sessioncontext"
	"github.com/meshtransit/meshtransit/core/internal/platform/ratelimit"
)

// SessionDeploymentCapabilities reads one fresh non-secret Deployment projection.
type SessionDeploymentCapabilities interface {
	Read(context.Context, accountsession.Session) (sessioncontext.DeploymentCapabilities, error)
}

func (browser *BrowserManagement) readDeploymentCapabilities(
	ctx context.Context,
	response *browserManagementResponse,
	request *http.Request,
	admission *browserManagementAdmission,
) error {
	correlationID, err := browser.management.correlationIDs.NewID()
	if err != nil || !correlationID.IsValid() {
		return ErrBrowserManagementUnavailable
	}
	setManagementSecurityHeaders(response.header, correlationID)
	address, err := browser.management.clientIPs.Resolve(request)
	if err != nil {
		writeManagementError(ctx, browser.management.logger, response, correlationID, *invalidManagementRequest())
		return nil
	}
	if limitErr := browser.management.enforceAdmittedRateLimit(ctx, admission, continuationBudget{
		response: response,
		kind:     ratelimit.SubjectSource,
		raw:      address.String(),
		policy:   browser.management.sourcePolicy,
	}); limitErr != nil {
		writeManagementError(ctx, browser.management.logger, response, correlationID, *limitErr)
		return nil
	}
	session, err := admission.authenticate(ctx, request)
	if err != nil {
		writeManagementError(ctx, browser.management.logger, response, correlationID, classifyAuthenticationError(err))
		return nil
	}
	if limitErr := browser.management.enforceAdmittedRateLimit(ctx, admission, continuationBudget{
		response: response,
		kind:     ratelimit.SubjectAccountSession,
		raw:      session.ID().String(),
		policy:   browser.management.sessionPolicy,
	}); limitErr != nil {
		writeManagementError(ctx, browser.management.logger, response, correlationID, *limitErr)
		return nil
	}
	capabilities, err := browser.capabilities.Read(ctx, session)
	if err != nil {
		writeManagementError(
			ctx,
			browser.management.logger,
			response,
			correlationID,
			classifyDeploymentCapabilityError(err),
		)
		return nil
	}
	writeManagementJSON(ctx, browser.management.logger, response, http.StatusOK, deploymentCapabilityResponse{
		DeploymentProfile:   string(capabilities.Profile()),
		WorkspaceMode:       string(capabilities.WorkspaceMode()),
		MaxActiveWorkspaces: capabilities.MaxActiveWorkspaces(),
		MaxOwnedWorkspaces:  capabilities.MaxOwnedWorkspacesPerAccount(),
		WorkspaceCreation:   string(capabilities.WorkspaceCreation()),
		EntitlementState:    string(capabilities.EntitlementState()),
		CloudBilling:        capabilities.CloudBilling(),
		PlatformOperations:  capabilities.PlatformOperations(),
		CapabilityRevision:  capabilities.Revision(),
	})
	return nil
}

func classifyDeploymentCapabilityError(err error) managementError {
	switch {
	case errors.Is(err, sessioncontext.ErrInvalidCapabilityRequest):
		return *invalidManagementRequest()
	case errors.Is(err, sessioncontext.ErrCapabilitiesUnauthenticated):
		return classifyAuthenticationError(accountsession.ErrUnauthenticated)
	case errors.Is(err, sessioncontext.ErrCapabilitiesUnavailable),
		errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return managementError{
			Status: http.StatusServiceUnavailable, Code: "deployment_capabilities_unavailable",
			Message: "deployment capabilities are temporarily unavailable", Retryable: true,
		}
	default:
		return internalManagementError()
	}
}

type deploymentCapabilityResponse struct {
	DeploymentProfile   string `json:"deployment_profile"`
	WorkspaceMode       string `json:"workspace_mode"`
	MaxActiveWorkspaces int    `json:"max_active_workspaces"`
	MaxOwnedWorkspaces  int    `json:"max_owned_workspaces_per_account"`
	WorkspaceCreation   string `json:"workspace_creation"`
	EntitlementState    string `json:"entitlement_state"`
	CloudBilling        bool   `json:"cloud_billing"`
	PlatformOperations  bool   `json:"platform_operations"`
	CapabilityRevision  int64  `json:"capability_revision"`
}
