package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/accessgraph"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

// maximumAccessGraphQueryBytes bounds the listing query string.
const maximumAccessGraphQueryBytes = 512

// AccessGraphLister lists the effective access graph of one Network.
type AccessGraphLister interface {
	Graph(context.Context, accountsession.Session, accessgraph.GraphQuery) (accessgraph.GraphPage, error)
}

type accessGraphListPath struct {
	scope network.Scope
}

// parseAccessGraphListPath matches GET /api/v1/workspaces/{ws}/networks/{net}/access-graph.
// The query string is validated separately by parseAccessGraphListQuery.
func parseAccessGraphListPath(request *http.Request) (accessGraphListPath, bool) {
	if request == nil || request.URL == nil || request.URL.RawPath != "" {
		return accessGraphListPath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) != 7 || segments[0] != "api" || segments[1] != "v1" ||
		segments[2] != "workspaces" || segments[4] != "networks" || segments[6] != "access-graph" {
		return accessGraphListPath{}, false
	}
	workspaceID, workspaceErr := workspace.ParseID(segments[3])
	networkID, networkErr := network.ParseID(segments[5])
	scope, scopeErr := network.NewScope(workspaceID, networkID)
	if workspaceErr != nil || networkErr != nil || scopeErr != nil ||
		workspaceID.String() != segments[3] || networkID.String() != segments[5] {
		return accessGraphListPath{}, false
	}
	return accessGraphListPath{scope: scope}, true
}

// parseAccessGraphListQuery accepts only device_id, protocol, page_size and
// page_token, each at most once and never empty.
func parseAccessGraphListQuery(raw string, scope network.Scope) (accessgraph.GraphQuery, bool) {
	if len(raw) > maximumAccessGraphQueryBytes {
		return accessgraph.GraphQuery{}, false
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return accessgraph.GraphQuery{}, false
	}
	for key, entries := range values {
		switch key {
		case "device_id", "protocol", "page_size", "page_token":
		default:
			return accessgraph.GraphQuery{}, false
		}
		if len(entries) != 1 || entries[0] == "" {
			return accessgraph.GraphQuery{}, false
		}
	}
	params := accessgraph.GraphQueryParams{Scope: scope}
	if value := values.Get("device_id"); value != "" {
		deviceID, err := node.ParseID(value)
		if err != nil || deviceID.String() != value {
			return accessgraph.GraphQuery{}, false
		}
		params.DeviceID = deviceID
	}
	if value := values.Get("protocol"); value != "" {
		params.Protocol = parsePolicyProtocol(value)
		if !params.Protocol.IsValid() {
			return accessgraph.GraphQuery{}, false
		}
	}
	if value := values.Get("page_size"); value != "" {
		size, err := strconv.Atoi(value)
		if err != nil || size < 1 || size > accessgraph.MaximumGraphPageSize || strconv.Itoa(size) != value {
			return accessgraph.GraphQuery{}, false
		}
		params.PageSize = size
	}
	if value := values.Get("page_token"); value != "" {
		cursor, err := accessgraph.ParseGraphCursor(value)
		if err != nil {
			return accessgraph.GraphQuery{}, false
		}
		params.Cursor = cursor
	}
	query, err := accessgraph.NewGraphQuery(params)
	return query, err == nil
}

func (handler *ManagementHandler) listAccessGraph(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	correlationID publicid.ID,
	path accessGraphListPath,
	session accountsession.Session,
) string {
	if handler.accessGraphs == nil {
		apiError := managementError{
			Status: http.StatusServiceUnavailable, Code: "dependency_unavailable",
			Message: "the request could not be completed", Retryable: true,
		}
		writeManagementError(ctx, handler.logger, response, correlationID, apiError)
		return apiError.Code
	}
	query, valid := parseAccessGraphListQuery(request.URL.RawQuery, path.scope)
	if !valid {
		apiError := *invalidManagementRequest()
		writeManagementError(ctx, handler.logger, response, correlationID, apiError)
		return apiError.Code
	}
	page, err := handler.accessGraphs.Graph(ctx, session, query)
	if err != nil {
		classified := classifyAccessGraphListError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, classified)
		return classified.Code
	}
	if page.Scope() != query.Scope() {
		apiError := managementError{
			Status: http.StatusInternalServerError, Code: "internal_failure",
			Message: "the request could not be completed",
		}
		writeManagementError(ctx, handler.logger, response, correlationID, apiError)
		return apiError.Code
	}
	response.Header().Set("ETag", strongVersionETag(page.Revision().PolicyRevision()))
	response.Header().Set("Cache-Control", "no-store")
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, accessGraphListResponse{
		Data:          newAccessGraphListing(page),
		CorrelationID: correlationID.String(),
	})
	return "success"
}

func classifyAccessGraphListError(err error) managementError {
	if errors.Is(err, accessgraph.ErrStaleGraphCursor) {
		return managementError{
			Status: http.StatusConflict, Code: "stale_page_token",
			Message: "the policy or its groups changed; start again from the first page",
		}
	}
	if errors.Is(err, accessgraph.ErrGraphTooLarge) {
		return managementError{
			Status: http.StatusUnprocessableEntity, Code: "access_graph_too_large",
			Message: "group rules allow too many connections to list; choose a Device",
		}
	}
	return classifyAccessGraphError(err)
}

type accessGraphListResponse struct {
	Data          accessGraphListing `json:"data"`
	CorrelationID string             `json:"correlation_id"`
}

type accessGraphListing struct {
	Evidence      explainedPolicyEvidence `json:"evidence"`
	Nodes         []accessGraphNode       `json:"nodes"`
	Paths         []explainedPolicyPath   `json:"paths"`
	MatchingPaths int                     `json:"matching_paths"`
	NextPageToken *string                 `json:"next_page_token"`
}

type accessGraphNode struct {
	Kind  string                `json:"kind"`
	ID    string                `json:"id"`
	Name  *string               `json:"name"`
	State string                `json:"state"`
	Share *explainedPolicyShare `json:"share"`
}

func newAccessGraphListing(page accessgraph.GraphPage) accessGraphListing {
	revision := page.Revision()
	releaseID, compilerFormat, semanticHash, hasRelease := page.ActiveRelease()
	evidence := newExplainedPolicyEvidenceFrom(revision, releaseID.String(), compilerFormat, semanticHash, hasRelease)
	graphNodes := page.Nodes()
	nodes := make([]accessGraphNode, len(graphNodes))
	for index, graphNode := range graphNodes {
		participant := graphNode.Participant()
		rendered := accessGraphNode{
			Kind: graphNode.Kind().String(), State: participant.State().String(),
			Name: optionalText(participant.Name()),
		}
		switch graphNode.Kind() {
		case accessgraph.GraphNodeKindDevice:
			rendered.ID = graphNode.DeviceID().String()
		case accessgraph.GraphNodeKindResource:
			rendered.ID = graphNode.ResourceID().String()
		default:
			rendered.ID = graphNode.ImportedResourceID().String()
		}
		if share, ok := graphNode.Share(); ok {
			rendered.Share = newExplainedPolicyShare(share)
		}
		nodes[index] = rendered
	}
	listing := accessGraphListing{
		Evidence: evidence, Nodes: nodes, Paths: newExplainedPolicyPaths(page.Paths()),
		MatchingPaths: page.MatchingPaths(),
	}
	if next, more := page.Next(); more {
		token := next.String()
		listing.NextPageToken = &token
	}
	return listing
}

func newExplainedPolicyShare(share accessgraph.ShareContext) *explainedPolicyShare {
	rendered := &explainedPolicyShare{
		TrustContractID: share.ContractID().String(), State: sharingContractStateString(share.State()),
		ProviderWorkspaceCode: share.ProviderWorkspaceCode().String(),
		ProviderNetworkCode:   share.ProviderNetworkCode().String(),
		AccessName:            optionalText(share.AccessName()),
	}
	if expiresAt, expires := share.ExpiresAt(); expires {
		value := expiresAt.UTC().Format(time.RFC3339)
		rendered.ExpiresAt = &value
	}
	return rendered
}
