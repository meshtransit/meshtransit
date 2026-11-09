package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/networksummary"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

func TestParseNetworkSummaryPath(t *testing.T) {
	t.Parallel()
	base := "/api/v1/workspaces/" + aliasRangeWorkspace
	for _, test := range []struct {
		name, method, target string
		kind                 string
		read, list           bool
	}{
		{name: "list", method: http.MethodGet, target: base + "/network-summaries", kind: "list", read: true, list: true},
		{name: "list with query", method: http.MethodGet, target: base + "/network-summaries?q=prod&page_size=10",
			kind: "list", read: true, list: true},
		{name: "overview", method: http.MethodGet, target: base + "/overview", kind: "overview", read: true},
		{name: "overview with query", method: http.MethodGet, target: base + "/overview?x=1"},
		{name: "one Network", method: http.MethodGet, target: base + "/networks/" + aliasRangeNetwork + "/summary",
			kind: "network", read: true},
		{name: "one Network with query", method: http.MethodGet,
			target: base + "/networks/" + aliasRangeNetwork + "/summary?x=1"},
		{name: "post", method: http.MethodPost, target: base + "/overview", kind: "overview"},
		{name: "sub-path", method: http.MethodGet, target: base + "/overview/x"},
		{name: "not a v7 id", method: http.MethodGet,
			target: "/api/v1/workspaces/01890f00-0000-4000-8000-000000000101/overview"},
	} {
		request := httptest.NewRequestWithContext(t.Context(), test.method, test.target, nil)
		path, matched := parseNetworkSummaryPath(request)
		if matched != (test.kind != "") || matched && path.kind != test.kind {
			t.Errorf("%s: matched = %v kind %q", test.name, matched, path.kind)
		}
		if isNetworkSummaryRead(request) != test.read || isNetworkSummaryList(request) != test.list {
			t.Errorf("%s: read %v list %v", test.name, isNetworkSummaryRead(request), isNetworkSummaryList(request))
		}
	}
}

func TestParseNetworkSummaryQuery(t *testing.T) {
	t.Parallel()
	workspaceID, _ := workspace.ParseID(aliasRangeWorkspace)
	other, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000102")
	after, _ := network.ParseID(aliasRangeNetwork)
	token, err := encodeManagementScopePageToken(workspaceID, after)
	if err != nil {
		t.Fatal(err)
	}
	foreign, _ := encodeManagementScopePageToken(other, after)
	if request, ok := parseNetworkSummaryQuery("", workspaceID); !ok || request.Limit != 10 || request.Query != "" {
		t.Fatalf("default = %+v %v", request, ok)
	}
	if request, ok := parseNetworkSummaryQuery("page_size=50&q=prod&page_token="+token, workspaceID); !ok ||
		request.Limit != 50 || request.Query != "prod" || request.After != after {
		t.Fatalf("full = %+v %v", request, ok)
	}
	// A search is counted in characters, as names are.
	if request, ok := parseNetworkSummaryQuery("q="+url.QueryEscape(strings.Repeat("ạ", 128)), workspaceID); !ok ||
		request.Query != strings.Repeat("ạ", 128) {
		t.Fatalf("128 Vietnamese characters refused: %+v %v", request, ok)
	}
	for _, raw := range []string{"page_size=51", "page_size=0", "page_size=01", "q=", "x=1", "page_size=5&page_size=6",
		"page_token=" + foreign, "q=" + strings.Repeat("a", 129), "q=%00", "q=%ff", "q=a%0Ab"} {
		if _, ok := parseNetworkSummaryQuery(raw, workspaceID); ok {
			t.Errorf("%q accepted", raw)
		}
	}
}

type stubNetworkSummaries struct {
	page     networksummary.Page
	overview networksummary.Overview
	figures  networksummary.Figures
	err      error
}

func (stub stubNetworkSummaries) ReadPage(context.Context, accountsession.Session, workspace.ID,
	networksummary.PageRequest) (networksummary.Page, error) {
	return stub.page, stub.err
}

func (stub stubNetworkSummaries) ReadOverview(context.Context, accountsession.Session,
	workspace.ID) (networksummary.Overview, error) {
	return stub.overview, stub.err
}

func (stub stubNetworkSummaries) ReadNetwork(context.Context, accountsession.Session,
	network.Scope) (networksummary.Figures, error) {
	return stub.figures, stub.err
}

func serveNetworkSummary(t *testing.T, handler *ManagementHandler, target string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	path, ok := parseNetworkSummaryPath(request)
	if !ok {
		t.Fatalf("%s not matched", target)
	}
	correlation, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.readNetworkSummaries(t.Context(), recorder, request, correlation, path, accountsession.Session{})
	return recorder
}

// A figure the Session may not see is absent from the answer, not zero.
func TestNetworkSummariesOmitWhatTheSessionMayNotSee(t *testing.T) {
	t.Parallel()
	networkID, _ := network.ParseID(aliasRangeNetwork)
	prefix := netip.MustParsePrefix("100.80.0.0/24")
	devices, rules := int64(9), int64(4)
	computed := time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)
	next, _ := network.ParseID("01890f00-0000-7000-8000-000000000299")
	stub := stubNetworkSummaries{page: networksummary.Page{Items: []networksummary.Figures{
		{NetworkID: networkID, DisplayName: "Production", DisplayCode: "000000000202",
			Permissions: []string{"device.read", "network.read"}, ComputedAt: &computed, IPv4Prefix: &prefix,
			ActiveDevices: &devices},
		{NetworkID: next, DisplayName: "Rules only", Permissions: []string{"policy.read"}, RuleCount: &rules},
	}, Next: next, SearchedAll: true}}
	handler := &ManagementHandler{logger: slog.New(slog.DiscardHandler), networkSummaries: stub}
	recorder := serveNetworkSummary(t, handler, "/api/v1/workspaces/"+aliasRangeWorkspace+"/network-summaries")
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status %d", recorder.Code)
	}
	var body struct {
		Data          []map[string]any `json:"data"`
		NextPageToken string           `json:"next_page_token"`
		SearchedAll   bool             `json:"searched_all"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	first, second := body.Data[0], body.Data[1]
	if first["ipv4_prefix"] != "100.80.0.0/24" || first["active_devices"] != float64(9) || first["rule_count"] != nil {
		t.Fatalf("first = %v", first)
	}
	if second["rule_count"] != float64(4) || second["ipv4_prefix"] != nil || second["active_devices"] != nil ||
		second["computed_at"] != nil {
		t.Fatalf("second = %v", second)
	}
	workspaceID, _ := workspace.ParseID(aliasRangeWorkspace)
	if after, err := decodeManagementScopePageToken(body.NextPageToken, workspaceID); err != nil || after != next ||
		!body.SearchedAll {
		t.Fatalf("next page token = %q (%v)", body.NextPageToken, err)
	}
}

func TestWorkspaceOverviewNamesOtherWorkspacesByCodeOnly(t *testing.T) {
	t.Parallel()
	networkID, _ := network.ParseID(aliasRangeNetwork)
	stub := stubNetworkSummaries{overview: networksummary.Overview{Networks: 3, ActiveContracts: 2, CrossWorkspace: 1,
		Links: []networksummary.Link{{From: networksummary.Side{NetworkID: networkID},
			To: networksummary.Side{DisplayCode: "000000000104"}, Active: 1}}}}
	handler := &ManagementHandler{logger: slog.New(slog.DiscardHandler), networkSummaries: stub}
	recorder := serveNetworkSummary(t, handler, "/api/v1/workspaces/"+aliasRangeWorkspace+"/overview")
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK || !strings.Contains(body, `"to":{"kind":"workspace","display_code":"000000000104"}`) ||
		!strings.Contains(body, `"from":{"kind":"network","id":"`+aliasRangeNetwork+`"}`) ||
		!strings.Contains(body, `"cross_workspace_contracts":1`) {
		t.Fatalf("overview = %d %s", recorder.Code, body)
	}
}

func TestNetworkSummaryFailures(t *testing.T) {
	t.Parallel()
	target := "/api/v1/workspaces/" + aliasRangeWorkspace + "/networks/" + aliasRangeNetwork + "/summary"
	for err, status := range map[error]int{
		networksummary.ErrReadForbidden:   http.StatusForbidden,
		networksummary.ErrInvalidRead:     http.StatusBadRequest,
		networksummary.ErrInvalidResult:   http.StatusInternalServerError,
		networksummary.ErrReadUnavailable: http.StatusServiceUnavailable,
		errors.New("anything"):            http.StatusServiceUnavailable,
	} {
		handler := &ManagementHandler{logger: slog.New(slog.DiscardHandler), networkSummaries: stubNetworkSummaries{err: err}}
		if recorder := serveNetworkSummary(t, handler, target); recorder.Code != status {
			t.Errorf("%v: status %d, want %d", err, recorder.Code, status)
		}
	}
	handler := &ManagementHandler{logger: slog.New(slog.DiscardHandler)}
	if recorder := serveNetworkSummary(t, handler, target); recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("missing reader: status %d", recorder.Code)
	}
	bad := &ManagementHandler{logger: slog.New(slog.DiscardHandler), networkSummaries: stubNetworkSummaries{}}
	if recorder := serveNetworkSummary(t, bad,
		"/api/v1/workspaces/"+aliasRangeWorkspace+"/network-summaries?page_size=99"); recorder.Code != http.StatusBadRequest {
		t.Errorf("bad page size: status %d", recorder.Code)
	}
}

// The cookie path admits the list's query and refuses a query elsewhere.
func TestBrowserManagementAdmitsNetworkSummaryReads(t *testing.T) {
	t.Parallel()
	browser, _ := newBrowserManagementFixture(t)
	base := "/api/v1/workspaces/" + aliasRangeWorkspace
	for target, admitted := range map[string]bool{
		base + "/network-summaries?q=prod&page_size=10": true,
		base + "/overview": true,
		base + "/networks/" + aliasRangeNetwork + "/summary":     true,
		base + "/overview?q=prod":                                false,
		base + "/networks/" + aliasRangeNetwork + "/summary?x=1": false,
	} {
		if got := browser.validRequest(browserManagementReadRequest(t, target)); got != admitted {
			t.Errorf("%s: admitted = %v", target, got)
		}
	}
}
