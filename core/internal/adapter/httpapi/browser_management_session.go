package httpapi

import (
	"context"
	"errors"
	"net/http"
	"sync"

	"meshtransit.net/core/internal/domain/identity/sessioncontext"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/platform/ratelimit"
)

// AccountSessionPath is the Console's start read: the Deployment capabilities
// and the first management-scope page under one admission (TD-CON-48).
const AccountSessionPath = "/auth/v1/session"

type sessionData struct {
	Capabilities    deploymentCapabilityResponse `json:"capabilities"`
	ManagementScope managementScopeData          `json:"management_scope"`
}

type sessionEnvelope struct {
	Data          sessionData `json:"data"`
	NextPageToken string      `json:"next_page_token,omitempty"`
	CorrelationID string      `json:"correlation_id"`
}

// readSession answers one Console start with what /v1/system/capabilities and
// the first page of /auth/v1/session/management-scopes answer, read at once
// after one authentication. It takes no query: later scope pages come from
// the scope collection with the returned token.
func (browser *BrowserManagement) readSession(
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
	sourceBudget := continuationBudget{
		response: response, kind: ratelimit.SubjectSource, raw: address.String(),
		policy: browser.management.sourcePolicy,
	}
	if limitErr := browser.management.enforceAdmittedRateLimit(ctx, admission, sourceBudget); limitErr != nil {
		writeManagementError(ctx, browser.management.logger, response, correlationID, *limitErr)
		return nil
	}
	session, err := admission.authenticate(ctx, request)
	if err != nil {
		writeManagementError(ctx, browser.management.logger, response, correlationID, classifyAuthenticationError(err))
		return nil
	}
	browser.management.refundAuthenticated(ctx, sourceBudget)
	if limitErr := browser.management.enforceAdmittedRateLimit(ctx, admission, continuationBudget{
		response: response, kind: ratelimit.SubjectAccountSession, raw: session.ID().String(),
		policy: browser.management.sessionPolicy,
	}); limitErr != nil {
		writeManagementError(ctx, browser.management.logger, response, correlationID, *limitErr)
		return nil
	}
	if _, hasWorkspace := session.LoginWorkspaceID(); !hasWorkspace {
		writeManagementError(ctx, browser.management.logger, response, correlationID,
			classifyManagementScopeError(sessioncontext.ErrUnauthenticated))
		return nil
	}
	// The two reads are independent; reading them at once saves one database
	// round trip on every Console start, at the cost of two pooled
	// connections held at once instead of one after the other.
	var (
		capabilities    sessioncontext.DeploymentCapabilities
		capabilitiesErr error
		wait            sync.WaitGroup
	)
	wait.Go(func() {
		// A panic here would escape the server's per-request recovery.
		defer func() {
			if recovered := recover(); recovered != nil {
				capabilitiesErr = errSessionReadPanicked
			}
		}()
		capabilities, capabilitiesErr = browser.capabilities.Read(ctx, session)
	})
	page, scopeErr := browser.scopes.List(ctx, session, defaultManagementScopePageSize, network.ID{})
	wait.Wait()
	if failure, failed := sessionReadFailure(capabilitiesErr, scopeErr); failed {
		writeManagementError(ctx, browser.management.logger, response, correlationID, failure)
		return nil
	}
	scope, next, err := managementScopeView(session, page)
	if err != nil {
		writeManagementError(ctx, browser.management.logger, response, correlationID, internalManagementError())
		return nil
	}
	writeManagementJSON(ctx, browser.management.logger, response, http.StatusOK, sessionEnvelope{
		Data:          sessionData{Capabilities: deploymentCapabilityView(capabilities), ManagementScope: scope},
		NextPageToken: next,
		CorrelationID: correlationID.String(),
	})
	return nil
}

var errSessionReadPanicked = errors.New("http api: Deployment capability read panicked")

// sessionReadFailure answers a start read where one or both reads failed. A
// Session that ended between authentication and the reads is a sign-in, not
// an outage: either read seeing it wins, then the capabilities' error, then
// the scopes'.
func sessionReadFailure(capabilitiesErr, scopeErr error) (managementError, bool) {
	switch {
	case capabilitiesErr == nil && scopeErr == nil:
		return managementError{}, false
	case errors.Is(capabilitiesErr, sessioncontext.ErrCapabilitiesUnauthenticated):
		return classifyDeploymentCapabilityError(capabilitiesErr), true
	case errors.Is(scopeErr, sessioncontext.ErrUnauthenticated):
		return classifyManagementScopeError(scopeErr), true
	case capabilitiesErr != nil:
		return classifyDeploymentCapabilityError(capabilitiesErr), true
	default:
		return classifyManagementScopeError(scopeErr), true
	}
}
