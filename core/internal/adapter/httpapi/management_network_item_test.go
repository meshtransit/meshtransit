package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/network/deletion"
	"meshtransit.net/core/internal/domain/publicid"
)

type stubNetworkDeletion struct {
	outcome deletion.Outcome
	view    deletion.View
	err     error
	got     *deletion.Command
}

func (stub stubNetworkDeletion) Delete(_ context.Context, command deletion.Command) (deletion.Outcome, error) {
	if stub.got != nil {
		*stub.got = command
	}
	return stub.outcome, stub.err
}

func (stub stubNetworkDeletion) Read(context.Context, accountsession.Session, network.Scope) (deletion.View, error) {
	return stub.view, stub.err
}

func TestParseNetworkItemPath(t *testing.T) {
	t.Parallel()
	item := "/api/v1/workspaces/" + aliasRangeWorkspace + "/networks/" + aliasRangeNetwork
	for _, test := range []struct {
		method, target string
		matched, op    bool
	}{
		{http.MethodGet, item, true, true},
		{http.MethodDelete, item, true, true},
		{http.MethodPatch, item, true, false},
		{http.MethodGet, item + "?x=1", false, false},
		{http.MethodGet, item + "/", false, false},
		{http.MethodGet, "/api/v1/workspaces/" + aliasRangeWorkspace + "/networks", false, false},
		{http.MethodGet, "/api/v1/workspaces/" + aliasRangeWorkspace + "/networks/01890f00-0000-4000-8000-000000000201",
			false, false},
	} {
		request := httptest.NewRequestWithContext(t.Context(), test.method, test.target, nil)
		if _, matched := parseNetworkItemPath(request); matched != test.matched ||
			isNetworkItemOperation(request) != test.op {
			t.Errorf("%s %s: matched %v op %v", test.method, test.target, matched, isNetworkItemOperation(request))
		}
	}
}

func TestParseNetworkDeleteReason(t *testing.T) {
	t.Parallel()
	header := func(values ...string) http.Header {
		result := http.Header{}
		for _, value := range values {
			result.Add(networkDeleteReasonHeader, value)
		}
		return result
	}
	vietnamese := "Dự án kết thúc"
	if reason, ok := parseNetworkDeleteReason(header(url.PathEscape(vietnamese))); !ok || reason != vietnamese {
		t.Fatalf("percent-encoded UTF-8 = %q %v", reason, ok)
	}
	for name, value := range map[string]http.Header{
		"missing":       header(),
		"twice":         header("a", "b"),
		"bad escape":    header("%zz"),
		"control":       header("a%0Ab"),
		"leading space": header("%20a"),
		"not UTF-8":     header("%ff"),
		"too long":      header(strings.Repeat("a", 513)),
	} {
		if _, ok := parseNetworkDeleteReason(value); ok {
			t.Errorf("%s accepted", name)
		}
	}
}

func serveNetworkItem(t *testing.T, handler *ManagementHandler, method string, header http.Header) *httptest.ResponseRecorder {
	t.Helper()
	target := "/api/v1/workspaces/" + aliasRangeWorkspace + "/networks/" + aliasRangeNetwork
	request := httptest.NewRequestWithContext(t.Context(), method, target, nil)
	for name, values := range header {
		request.Header[name] = values
	}
	scope, ok := parseNetworkItemPath(request)
	if !ok {
		t.Fatal("not matched")
	}
	correlation, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.handleNetworkItem(t.Context(), recorder, request, correlation, scope, accountsession.Session{})
	return recorder
}

func TestNetworkDeleteAcceptsAndReportsProgress(t *testing.T) {
	t.Parallel()
	networkID, _ := network.ParseID(aliasRangeNetwork)
	requested := time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	var got deletion.Command
	handler := &ManagementHandler{logger: slog.New(slog.DiscardHandler), networkDeletion: stubNetworkDeletion{
		outcome: deletion.Outcome{Kind: deletion.OutcomeDeleted, Version: 4, Progress: deletion.Progress{
			NetworkID: networkID, RequestedAt: requested, DevicesTotal: 12}}, got: &got}}
	recorder := serveNetworkItem(t, handler, http.MethodDelete, http.Header{
		"If-Match": {`"3"`}, networkDeleteReasonHeader: {url.PathEscape("Dự án kết thúc")}})
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status %d %s", recorder.Code, recorder.Body)
	}
	var body struct {
		Data networkDeletionView `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || body.Data.State != "deleting" ||
		body.Data.DevicesTotal != 12 || body.Data.NetworkID != aliasRangeNetwork {
		t.Fatalf("body = %+v %v", body, err)
	}
	if got.ExpectedVersion != 3 || got.Reason != "Dự án kết thúc" {
		t.Fatalf("command = %+v", got)
	}
}

func TestNetworkDeleteNeedsVersionAndReason(t *testing.T) {
	t.Parallel()
	handler := &ManagementHandler{logger: slog.New(slog.DiscardHandler), networkDeletion: stubNetworkDeletion{}}
	if recorder := serveNetworkItem(t, handler, http.MethodDelete,
		http.Header{networkDeleteReasonHeader: {"x"}}); recorder.Code != http.StatusPreconditionRequired {
		t.Errorf("without If-Match: %d", recorder.Code)
	}
	if recorder := serveNetworkItem(t, handler, http.MethodDelete,
		http.Header{"If-Match": {`"3"`}}); recorder.Code != http.StatusBadRequest {
		t.Errorf("without a reason: %d", recorder.Code)
	}
}

func TestNetworkDeleteBlockedNamesWhatToEndFirst(t *testing.T) {
	t.Parallel()
	contract, _ := publicid.Parse("01890f00-0000-7000-8000-000000000901")
	cluster, _ := publicid.Parse("01890f00-0000-7000-8000-000000000902")
	handler := &ManagementHandler{logger: slog.New(slog.DiscardHandler), networkDeletion: stubNetworkDeletion{
		outcome: deletion.Outcome{Kind: deletion.OutcomeBlocked, Blockers: deletion.Blockers{Total: 2,
			TrustContracts: 1, KubernetesClusters: 1, Items: []deletion.Blocker{
				{Kind: deletion.BlockerKubernetesCluster, ID: cluster, Name: "prod"},
				{Kind: deletion.BlockerTrustContract, ID: contract}}}}}}
	recorder := serveNetworkItem(t, handler, http.MethodDelete,
		http.Header{"If-Match": {`"3"`}, networkDeleteReasonHeader: {"done"}})
	body := recorder.Body.String()
	if recorder.Code != http.StatusConflict || !strings.Contains(body, `"code":"network_delete_blocked"`) ||
		!strings.Contains(body, `{"kind":"kubernetes_cluster","id":"`+cluster.String()+`","name":"prod"}`) ||
		!strings.Contains(body, `"trust_contracts":1`) {
		t.Fatalf("blocked = %d %s", recorder.Code, body)
	}
}

func TestNetworkReadAndFailures(t *testing.T) {
	t.Parallel()
	networkID, _ := network.ParseID(aliasRangeNetwork)
	created := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	handler := &ManagementHandler{logger: slog.New(slog.DiscardHandler), networkDeletion: stubNetworkDeletion{
		view: deletion.View{NetworkID: networkID, DisplayName: "Production", State: deletion.StateActive, Version: 3,
			CreatedAt: created}}}
	recorder := serveNetworkItem(t, handler, http.MethodGet, nil)
	if recorder.Code != http.StatusOK || recorder.Header().Get("ETag") != `"3"` ||
		!strings.Contains(recorder.Body.String(), `"state":"active"`) {
		t.Fatalf("read = %d %s", recorder.Code, recorder.Body)
	}
	for err, status := range map[error]int{
		deletion.ErrForbidden:       http.StatusForbidden,
		deletion.ErrNotFound:        http.StatusNotFound,
		deletion.ErrVersionConflict: http.StatusPreconditionFailed,
		deletion.ErrInvalid:         http.StatusBadRequest,
		errors.New("anything"):      http.StatusServiceUnavailable,
	} {
		failing := &ManagementHandler{logger: slog.New(slog.DiscardHandler), networkDeletion: stubNetworkDeletion{err: err}}
		if recorder := serveNetworkItem(t, failing, http.MethodGet, nil); recorder.Code != status {
			t.Errorf("%v: status %d, want %d", err, recorder.Code, status)
		}
	}
	missing := &ManagementHandler{logger: slog.New(slog.DiscardHandler)}
	if recorder := serveNetworkItem(t, missing, http.MethodGet, nil); recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("missing service: %d", recorder.Code)
	}
}

// The cookie path admits GET and a body-less DELETE of one Network.
func TestBrowserManagementAdmitsNetworkItem(t *testing.T) {
	t.Parallel()
	browser, _ := newBrowserManagementFixture(t)
	target := "/api/v1/workspaces/" + aliasRangeWorkspace + "/networks/" + aliasRangeNetwork
	if !browser.validRequest(browserManagementReadRequest(t, target)) {
		t.Error("GET refused")
	}
	if browser.validRequest(browserManagementReadRequest(t, target+"?x=1")) {
		t.Error("GET with a query admitted")
	}
	remove := browserManagementReadRequest(t, target)
	remove.Method = http.MethodDelete
	remove.Header.Set("If-Match", `"3"`)
	remove.Header.Set(networkDeleteReasonHeader, "done")
	if !browser.validRequest(remove) {
		t.Error("DELETE refused")
	}
}
