package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/network/deletion"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

const (
	networkReadOperation   = "network_read"
	networkDeleteOperation = "network_delete"
	// networkDeleteReasonHeader carries the reason, percent-encoded: a
	// DELETE has no body and a query string is logged (design §4.5, Q11).
	networkDeleteReasonHeader = "X-Meshtransit-Reason"
	// maximumNetworkDeleteReasonHeaderBytes bounds the encoded reason: every
	// byte of the 512 decoded may take three.
	maximumNetworkDeleteReasonHeaderBytes = 3 * deletion.MaxReasonBytes
)

var networkItemMethods = restMethods{http.MethodGet, http.MethodDelete}

// NetworkDeletion deletes and reads one Network.
type NetworkDeletion interface {
	Delete(context.Context, deletion.Command) (deletion.Outcome, error)
	Read(context.Context, accountsession.Session, network.Scope) (deletion.View, error)
}

// parseNetworkItemPath matches /api/v1/workspaces/{ws}/networks/{net}
// exactly, without a query.
func parseNetworkItemPath(request *http.Request) (network.Scope, bool) {
	if request == nil || request.URL == nil || request.URL.RawPath != "" || request.URL.RawQuery != "" {
		return network.Scope{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) != 6 || segments[0] != "api" || segments[1] != "v1" || segments[2] != "workspaces" ||
		segments[4] != "networks" {
		return network.Scope{}, false
	}
	workspaceID, workspaceErr := workspace.ParseID(segments[3])
	networkID, networkErr := network.ParseID(segments[5])
	if workspaceErr != nil || networkErr != nil || workspaceID.String() != segments[3] ||
		networkID.String() != segments[5] {
		return network.Scope{}, false
	}
	scope, err := network.NewScope(workspaceID, networkID)
	return scope, err == nil
}

// isNetworkItemOperation admits GET and DELETE on the exact path.
func isNetworkItemOperation(request *http.Request) bool {
	_, ok := parseNetworkItemPath(request)
	return ok && networkItemMethods.allows(request.Method)
}

// isNetworkItemRead admits GET on the exact path.
func isNetworkItemRead(request *http.Request) bool {
	_, ok := parseNetworkItemPath(request)
	return ok && request.Method == http.MethodGet
}

func networkItemOperation(method string) string {
	if method == http.MethodDelete {
		return networkDeleteOperation
	}
	return networkReadOperation
}

// parseNetworkDeleteReason decodes the one percent-encoded reason header.
func parseNetworkDeleteReason(header http.Header) (string, bool) {
	values := header.Values(networkDeleteReasonHeader)
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > maximumNetworkDeleteReasonHeaderBytes {
		return "", false
	}
	reason, err := url.PathUnescape(values[0])
	return reason, err == nil && deletion.ValidReason(reason)
}

type networkDeletionView struct {
	NetworkID      string     `json:"network_id"`
	State          string     `json:"state"`
	RequestedAt    time.Time  `json:"requested_at"`
	DevicesTotal   int64      `json:"devices_total"`
	DevicesRevoked int64      `json:"devices_revoked"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
}

func networkDeletionProgressView(progress deletion.Progress) networkDeletionView {
	state := deletion.StateDeleting
	if progress.CompletedAt != nil {
		state = "deleted"
	}
	return networkDeletionView{NetworkID: progress.NetworkID.String(), State: state,
		RequestedAt: progress.RequestedAt, DevicesTotal: progress.DevicesTotal,
		DevicesRevoked: progress.DevicesRevoked, CompletedAt: progress.CompletedAt}
}

type networkItemView struct {
	NetworkID   string               `json:"network_id"`
	DisplayName string               `json:"display_name"`
	DisplayCode string               `json:"display_code,omitempty"`
	State       string               `json:"state"`
	Version     int64                `json:"version"`
	CreatedAt   time.Time            `json:"created_at"`
	Deletion    *networkDeletionView `json:"deletion,omitempty"`
}

type networkDeletionBlockerView struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

type networkDeletionBlockersView struct {
	Total              int64                        `json:"total"`
	TrustContracts     int64                        `json:"trust_contracts"`
	KubernetesClusters int64                        `json:"kubernetes_clusters"`
	KubernetesCAs      int64                        `json:"kubernetes_cas"`
	Items              []networkDeletionBlockerView `json:"items"`
}

// networkDeletionBlockedError is the 409 that names what to end first.
func networkDeletionBlockedError(blockers deletion.Blockers) managementError {
	view := networkDeletionBlockersView{Total: blockers.Total, TrustContracts: blockers.TrustContracts,
		KubernetesClusters: blockers.KubernetesClusters, KubernetesCAs: blockers.KubernetesCAs,
		Items: make([]networkDeletionBlockerView, 0, len(blockers.Items))}
	for _, item := range blockers.Items {
		view.Items = append(view.Items, networkDeletionBlockerView{Kind: item.Kind, ID: item.ID.String(),
			Name: item.Name})
	}
	return managementError{Status: http.StatusConflict, Code: "network_delete_blocked",
		Message: "End the Network's Trust Contracts and Kubernetes clusters first. A deleted cluster's CAs " +
			"must be retired too, which can take days.",
		NetworkDeleteBlockers: &view}
}

func (handler *ManagementHandler) handleNetworkItem(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, scope network.Scope, session accountsession.Session) string {
	if nilContinuationDependency(handler.networkDeletion) {
		failure := managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Networks are temporarily unavailable", Retryable: true}
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	response.Header().Set("Cache-Control", "no-store")
	if request.Method == http.MethodGet {
		view, err := handler.networkDeletion.Read(ctx, session, scope)
		if err != nil {
			return handler.writeNetworkDeletionError(ctx, response, correlationID, err)
		}
		output := networkItemView{NetworkID: view.NetworkID.String(), DisplayName: view.DisplayName,
			DisplayCode: view.DisplayCode, State: view.State, Version: view.Version, CreatedAt: view.CreatedAt}
		if view.Deletion != nil {
			progress := networkDeletionProgressView(*view.Deletion)
			output.Deletion = &progress
		} else {
			response.Header().Set("ETag", strongVersionETag(view.Version))
		}
		writeManagementJSON(ctx, handler.logger, response, http.StatusOK, struct {
			Data          networkItemView `json:"data"`
			CorrelationID string          `json:"correlation_id"`
		}{Data: output, CorrelationID: correlationID.String()})
		return "success"
	}
	expectedVersion, precondition := parseIfMatch(request.Header.Values("If-Match"))
	if precondition != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *precondition)
		return precondition.Code
	}
	reason, ok := parseNetworkDeleteReason(request.Header)
	if !ok || request.ContentLength != 0 {
		writeManagementError(ctx, handler.logger, response, correlationID, managementError{
			Status: http.StatusBadRequest, Code: "invalid_request",
			Message: "say why in X-Meshtransit-Reason: 1 to 512 bytes of percent-encoded UTF-8, no body"})
		return "invalid_request"
	}
	outcome, err := handler.networkDeletion.Delete(ctx, deletion.Command{Session: session, Scope: scope,
		ExpectedVersion: expectedVersion, Reason: reason, CorrelationID: correlationID})
	if err != nil {
		return handler.writeNetworkDeletionError(ctx, response, correlationID, err)
	}
	if outcome.Kind == deletion.OutcomeBlocked {
		failure := networkDeletionBlockedError(outcome.Blockers)
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	writeManagementJSON(ctx, handler.logger, response, http.StatusAccepted, struct {
		Data          networkDeletionView `json:"data"`
		CorrelationID string              `json:"correlation_id"`
	}{Data: networkDeletionProgressView(outcome.Progress), CorrelationID: correlationID.String()})
	return "success"
}

func (handler *ManagementHandler) writeNetworkDeletionError(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, err error) string {
	var failure managementError
	switch {
	case errors.Is(err, deletion.ErrForbidden):
		failure = managementError{Status: http.StatusForbidden, Code: "permission_denied",
			Message: "Only the Workspace owner or an admin can delete a Network"}
	case errors.Is(err, deletion.ErrNotFound):
		failure = managementError{Status: http.StatusNotFound, Code: "not_found",
			Message: "the requested resource is unavailable"}
	case errors.Is(err, deletion.ErrVersionConflict):
		failure = managementError{Status: http.StatusPreconditionFailed, Code: "version_conflict",
			Message: "the Network changed; read it again"}
	case errors.Is(err, deletion.ErrInvalid):
		failure = *invalidManagementRequest()
	default:
		failure = managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "The Network could not be changed or read. Try again.", Retryable: true}
	}
	writeManagementError(ctx, handler.logger, response, correlationID, failure)
	return failure.Code
}
