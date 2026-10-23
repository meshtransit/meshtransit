package httpapi

import (
	"context"
	"meshtransit.net/core/internal/domain/publicid"
	"net/http"
)

// browserResourceSharingOperation is the private profile's closed operation set.
// Collection query syntax remains owned by the management handler. This does not
// admit Resource group, lifecycle, rebind or authority-transfer operations.
func browserResourceSharingOperation(request *http.Request) (operation, collectionRead bool) {
	if request == nil {
		return false, false
	}
	if path, matched := parseResourceManagementPath(request); matched {
		supported := path.action == "" &&
			(path.kind == resourceManagementCollection || path.kind == resourceManagementItem)
		if !supported || path.allowedMethod(request.Method) != request.Method {
			return false, false
		}
		return true, request.Method == http.MethodGet && path.kind == resourceManagementCollection
	}
	path, matched := parseResourceSharingPath(request)
	if !matched || path.allowedMethod(request.Method) != request.Method {
		return false, false
	}
	return true, request.Method == http.MethodGet && path.isCollection()
}

// Parsing may consume proof lifetime. Revalidate immediately before the existing
// service effect; that service owns fresh Session and scoped authorization in SQL.
func (handler *ManagementHandler) validateBrowserResourceMutation(ctx context.Context, response http.ResponseWriter, correlationID publicid.ID, browser *browserManagementAdmission) string {
	if err := browser.validate(ctx); err != nil {
		classified := classifyAuthenticationError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, classified)
		return classified.Code
	}
	return ""
}

// isContractServiceNamesOperation reports the service names of a running
// share, the one sharing route that takes PUT.
func isContractServiceNamesOperation(request *http.Request) bool {
	path, matched := parseResourceSharingPath(request)
	return matched && path.kind == resourceSharingContractServiceNames
}
