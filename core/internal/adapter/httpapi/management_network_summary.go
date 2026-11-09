package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/networksummary"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

const (
	networkSummaryListOperation     = "network_summary_list"
	workspaceOverviewReadOperation  = "workspace_overview_read"
	networkSummaryReadOperation     = "network_summary_read"
	defaultNetworkSummaryPageSize   = 10
	networkSummaryKindList          = "list"
	networkSummaryKindOverview      = "overview"
	networkSummaryKindNetwork       = "network"
	networkSummaryCollectionSegment = "network-summaries"
)

type networkSummaryPath struct {
	kind      string
	workspace workspace.ID
	scope     network.Scope
}

// parseNetworkSummaryPath matches, GET only:
//   - /api/v1/workspaces/{ws}/network-summaries (page_size, page_token, q)
//   - /api/v1/workspaces/{ws}/overview (no query)
//   - /api/v1/workspaces/{ws}/networks/{net}/summary (no query)
func parseNetworkSummaryPath(request *http.Request) (networkSummaryPath, bool) {
	if request == nil || request.URL == nil || request.URL.RawPath != "" {
		return networkSummaryPath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) < 5 || segments[0] != "api" || segments[1] != "v1" || segments[2] != "workspaces" {
		return networkSummaryPath{}, false
	}
	workspaceID, err := workspace.ParseID(segments[3])
	if err != nil || workspaceID.String() != segments[3] {
		return networkSummaryPath{}, false
	}
	switch {
	case len(segments) == 5 && segments[4] == networkSummaryCollectionSegment:
		return networkSummaryPath{kind: networkSummaryKindList, workspace: workspaceID}, true
	case len(segments) == 5 && segments[4] == "overview" && request.URL.RawQuery == "":
		return networkSummaryPath{kind: networkSummaryKindOverview, workspace: workspaceID}, true
	case len(segments) == 7 && segments[4] == "networks" && segments[6] == "summary" && request.URL.RawQuery == "":
		networkID, err := network.ParseID(segments[5])
		scope, scopeErr := network.NewScope(workspaceID, networkID)
		if err != nil || scopeErr != nil || networkID.String() != segments[5] {
			return networkSummaryPath{}, false
		}
		return networkSummaryPath{kind: networkSummaryKindNetwork, workspace: workspaceID, scope: scope}, true
	default:
		return networkSummaryPath{}, false
	}
}

// isNetworkSummaryRead admits only GET on the exact paths.
func isNetworkSummaryRead(request *http.Request) bool {
	_, ok := parseNetworkSummaryPath(request)
	return ok && request.Method == http.MethodGet
}

// isNetworkSummaryList is the one summary read that takes a query.
func isNetworkSummaryList(request *http.Request) bool {
	path, ok := parseNetworkSummaryPath(request)
	return ok && request.Method == http.MethodGet && path.kind == networkSummaryKindList
}

func (path networkSummaryPath) operation() string {
	switch path.kind {
	case networkSummaryKindList:
		return networkSummaryListOperation
	case networkSummaryKindOverview:
		return workspaceOverviewReadOperation
	default:
		return networkSummaryReadOperation
	}
}

func parseNetworkSummaryQuery(rawQuery string, workspaceID workspace.ID) (networksummary.PageRequest, bool) {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return networksummary.PageRequest{}, false
	}
	for key, entries := range values {
		if (key != "page_size" && key != "page_token" && key != "q") || len(entries) != 1 || entries[0] == "" {
			return networksummary.PageRequest{}, false
		}
	}
	request := networksummary.PageRequest{Limit: defaultNetworkSummaryPageSize, Query: values.Get("q")}
	if raw := values.Get("page_size"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || strconv.Itoa(limit) != raw {
			return networksummary.PageRequest{}, false
		}
		request.Limit = limit
	}
	if encoded := values.Get("page_token"); encoded != "" {
		after, err := decodeManagementScopePageToken(encoded, workspaceID)
		if err != nil {
			return networksummary.PageRequest{}, false
		}
		request.After = after
	}
	return request, networksummary.ValidPageRequest(request)
}

type networkSummaryItem struct {
	NetworkID          string     `json:"network_id"`
	DisplayName        string     `json:"display_name"`
	DisplayCode        string     `json:"display_code,omitempty"`
	Permissions        []string   `json:"permissions"`
	ComputedAt         *time.Time `json:"computed_at,omitempty"`
	IPv4Prefix         *string    `json:"ipv4_prefix,omitempty"`
	AddressesCapacity  *int64     `json:"addresses_capacity,omitempty"`
	AddressesInUse     *int64     `json:"addresses_in_use,omitempty"`
	AddressesHeld      *int64     `json:"addresses_held,omitempty"`
	KubernetesClusters *int64     `json:"kubernetes_clusters,omitempty"`
	ActiveDevices      *int64     `json:"active_devices,omitempty"`
	RuleCount          *int64     `json:"rule_count,omitempty"`
	PolicyRevision     *int64     `json:"policy_revision,omitempty"`
	PolicyPublishedAt  *time.Time `json:"policy_published_at,omitempty"`
	PendingApprovals   *int64     `json:"pending_approvals,omitempty"`
	SharesOutActive    *int64     `json:"shares_out_active,omitempty"`
	SharesInActive     *int64     `json:"shares_in_active,omitempty"`
	OffersWaiting      *int64     `json:"offers_waiting,omitempty"`
	Sites              *int64     `json:"sites,omitempty"`
}

func networkSummaryItemView(figures networksummary.Figures) networkSummaryItem {
	item := networkSummaryItem{NetworkID: figures.NetworkID.String(), DisplayName: figures.DisplayName,
		DisplayCode: figures.DisplayCode, Permissions: append([]string{}, figures.Permissions...),
		AddressesCapacity: figures.AddressesCapacity, AddressesInUse: figures.AddressesInUse,
		AddressesHeld: figures.AddressesHeld, KubernetesClusters: figures.KubernetesClusters,
		ActiveDevices: figures.ActiveDevices, RuleCount: figures.RuleCount, PolicyRevision: figures.PolicyRevision,
		PendingApprovals: figures.PendingApprovals, SharesOutActive: figures.SharesOutActive,
		SharesInActive: figures.SharesInActive, OffersWaiting: figures.OffersWaiting, Sites: figures.Sites}
	if figures.ComputedAt != nil {
		at := figures.ComputedAt.UTC()
		item.ComputedAt = &at
	}
	if figures.PolicyPublishedAt != nil {
		at := figures.PolicyPublishedAt.UTC()
		item.PolicyPublishedAt = &at
	}
	if figures.IPv4Prefix != nil {
		prefix := figures.IPv4Prefix.String()
		item.IPv4Prefix = &prefix
	}
	return item
}

type workspaceOverviewSide struct {
	Kind        string `json:"kind"`
	ID          string `json:"id,omitempty"`
	DisplayCode string `json:"display_code,omitempty"`
}

func workspaceOverviewSideView(side networksummary.Side) workspaceOverviewSide {
	if side.NetworkID.IsValid() {
		return workspaceOverviewSide{Kind: "network", ID: side.NetworkID.String()}
	}
	return workspaceOverviewSide{Kind: "workspace", DisplayCode: side.DisplayCode}
}

type workspaceOverviewLink struct {
	From    workspaceOverviewSide `json:"from"`
	To      workspaceOverviewSide `json:"to"`
	Active  int64                 `json:"active"`
	Waiting int64                 `json:"waiting"`
}

type workspaceOverviewView struct {
	Networks             int64                   `json:"networks"`
	AddressesTaken       int64                   `json:"addresses_taken"`
	ActiveContracts      int64                   `json:"active_contracts"`
	CrossWorkspace       int64                   `json:"cross_workspace_contracts"`
	OffersWaiting        int64                   `json:"offers_waiting"`
	AddressesPartial     bool                    `json:"addresses_partial"`
	SharesPartial        bool                    `json:"shares_partial"`
	LinksPartial         bool                    `json:"links_partial"`
	OldestComputedAt     *time.Time              `json:"oldest_computed_at,omitempty"`
	WorkspaceDisplayCode string                  `json:"workspace_display_code,omitempty"`
	Links                []workspaceOverviewLink `json:"links"`
}

func (handler *ManagementHandler) readNetworkSummaries(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path networkSummaryPath, session accountsession.Session) string {
	if nilContinuationDependency(handler.networkSummaries) {
		failure := managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Network summaries are temporarily unavailable", Retryable: true}
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	response.Header().Set("Cache-Control", "no-store")
	switch path.kind {
	case networkSummaryKindList:
		pageRequest, ok := parseNetworkSummaryQuery(request.URL.RawQuery, path.workspace)
		if !ok {
			writeManagementError(ctx, handler.logger, response, correlationID, *invalidManagementRequest())
			return "invalid_request"
		}
		page, err := handler.networkSummaries.ReadPage(ctx, session, path.workspace, pageRequest)
		if err != nil {
			return handler.writeNetworkSummaryError(ctx, response, correlationID, err)
		}
		output := struct {
			Data          []networkSummaryItem `json:"data"`
			NextPageToken string               `json:"next_page_token,omitempty"`
			SearchedAll   bool                 `json:"searched_all"`
			CorrelationID string               `json:"correlation_id"`
		}{Data: make([]networkSummaryItem, 0, len(page.Items)), SearchedAll: page.SearchedAll,
			CorrelationID: correlationID.String()}
		for _, figures := range page.Items {
			output.Data = append(output.Data, networkSummaryItemView(figures))
		}
		if page.Next.IsValid() {
			token, err := encodeManagementScopePageToken(path.workspace, page.Next)
			if err != nil {
				writeManagementError(ctx, handler.logger, response, correlationID, internalManagementError())
				return "internal_error"
			}
			output.NextPageToken = token
		}
		writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
	case networkSummaryKindOverview:
		overview, err := handler.networkSummaries.ReadOverview(ctx, session, path.workspace)
		if err != nil {
			return handler.writeNetworkSummaryError(ctx, response, correlationID, err)
		}
		view := workspaceOverviewView{Networks: overview.Networks, AddressesTaken: overview.AddressesTaken,
			ActiveContracts: overview.ActiveContracts, CrossWorkspace: overview.CrossWorkspace,
			OffersWaiting: overview.OffersWaiting, AddressesPartial: overview.AddressesPartial,
			SharesPartial: overview.SharesPartial, LinksPartial: overview.LinksPartial,
			OldestComputedAt: overview.OldestComputedAt, WorkspaceDisplayCode: overview.WorkspaceDisplayCode,
			Links: make([]workspaceOverviewLink, 0, len(overview.Links))}
		for _, link := range overview.Links {
			view.Links = append(view.Links, workspaceOverviewLink{From: workspaceOverviewSideView(link.From),
				To: workspaceOverviewSideView(link.To), Active: link.Active, Waiting: link.Waiting})
		}
		writeManagementJSON(ctx, handler.logger, response, http.StatusOK, struct {
			Data          workspaceOverviewView `json:"data"`
			CorrelationID string                `json:"correlation_id"`
		}{Data: view, CorrelationID: correlationID.String()})
	default:
		figures, err := handler.networkSummaries.ReadNetwork(ctx, session, path.scope)
		if err != nil {
			return handler.writeNetworkSummaryError(ctx, response, correlationID, err)
		}
		writeManagementJSON(ctx, handler.logger, response, http.StatusOK, struct {
			Data          networkSummaryItem `json:"data"`
			CorrelationID string             `json:"correlation_id"`
		}{Data: networkSummaryItemView(figures), CorrelationID: correlationID.String()})
	}
	return "success"
}

func (handler *ManagementHandler) writeNetworkSummaryError(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, err error) string {
	var failure managementError
	switch {
	case errors.Is(err, networksummary.ErrReadForbidden):
		failure = managementError{Status: http.StatusForbidden, Code: "permission_denied",
			Message: "You cannot view these Network summaries"}
	case errors.Is(err, networksummary.ErrInvalidRead):
		failure = *invalidManagementRequest()
	case errors.Is(err, networksummary.ErrInvalidResult):
		failure = internalManagementError()
	default:
		failure = managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Network summaries could not be read. Try again.", Retryable: true}
	}
	writeManagementError(ctx, handler.logger, response, correlationID, failure)
	return failure.Code
}
