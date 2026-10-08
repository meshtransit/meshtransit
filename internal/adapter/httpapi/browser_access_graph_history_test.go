package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/accessgraph/ledger"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

type historyTestReader struct {
	result ledger.Result
	err    error
	reads  int
	query  ledger.Query
}

func (reader *historyTestReader) ReadHistory(_ context.Context, _ accountsession.Session, _ network.Scope,
	query ledger.Query, _ time.Time) (ledger.Result, error) {
	reader.reads++
	reader.query = query
	result := reader.result
	result.At = query.At
	return result, reader.err
}

func accessGraphHistoryTestPath() string {
	return strings.TrimSuffix(deviceInventoryTestPath(), "/devices") + "/access-graph/history"
}

func historyTestEdge(t *testing.T, key byte, from time.Time) ledger.Edge {
	t.Helper()
	var edgeKey ledger.EdgeKey
	edgeKey[0] = key
	rule, _ := publicid.Parse("01890f00-0000-7000-8000-000000000501")
	source, _ := node.ParseID("01890f00-0000-7000-8000-000000000301")
	destination, _ := node.ParseID("01890f00-0000-7000-8000-000000000302")
	ssh, _ := policy.NewPortRange(22, 22)
	return ledger.Edge{Key: edgeKey, AccessRuleID: rule, SelectorKind: ledger.SelectorDevice,
		SourceDeviceID: source, SourceHostname: "poc-01", DestinationDeviceID: destination,
		Protocol: policy.ProtocolTCP, Ports: []policy.PortRange{ssh}, ValidFromRevision: 3, ValidFrom: from}
}

func TestBrowserAccessGraphHistoryReadsEdgesAtAnInstant(t *testing.T) {
	t.Parallel()
	options, fixture := browserManagementTestOptions(t)
	at := time.Date(2026, time.September, 1, 11, 0, 0, 0, time.UTC)
	request := browserManagementReadRequest(t, accessGraphHistoryTestPath()+
		"?at=2026-09-01T11:00:00Z&protocol=tcp&page_size=1")
	scope, ok := parseAccessGraphHistoryPath(request)
	if !ok {
		t.Fatal("valid exact scope rejected")
	}
	if _, listed := parseAccessGraphListPath(request); listed {
		t.Fatal("history path matched the listing route")
	}
	reader := &historyTestReader{result: ledger.Result{Scope: scope, RecordedSince: at.Add(-time.Hour),
		NetworkRevision: 6, Edges: []ledger.Edge{historyTestEdge(t, 1, at.Add(-time.Minute)),
			historyTestEdge(t, 2, at.Add(-time.Minute))}}}
	service, err := ledger.NewService(reader, fixture)
	if err != nil {
		t.Fatal(err)
	}
	options.AccessGraphHistory = service
	browser, err := NewBrowserManagement(options)
	if err != nil {
		t.Fatal(err)
	}
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, request); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || reader.reads != 1 || !reader.query.At.Equal(at) || reader.query.Limit != 2 ||
		reader.query.Protocol != policy.ProtocolTCP || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("history read = %d %+v", response.Code, reader.query)
	}
	var envelope accessGraphHistoryEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	data := envelope.Data
	if len(data.Edges) != 1 || data.NetworkRevision == nil || *data.NetworkRevision != 6 ||
		data.Edges[0].ValidTo != nil || data.Edges[0].PortFirst[0] != 22 || *data.Edges[0].SourceHostname != "poc-01" ||
		envelope.NextPageToken == "" {
		t.Fatalf("history page = %+v next=%q", data, envelope.NextPageToken)
	}

	// The token pins the instant and the filters.
	next, err := parseAccessGraphHistoryQuery("protocol=tcp&page_token="+envelope.NextPageToken, scope)
	if err != nil || !next.At.Equal(at) || next.After != data.edgeKey(t, 0) {
		t.Fatalf("continuation = %+v %v", next, err)
	}
	if _, err := parseAccessGraphHistoryQuery("page_token="+envelope.NextPageToken, scope); err == nil {
		t.Fatal("continuation without its filters accepted")
	}
	if _, err := parseAccessGraphHistoryQuery("protocol=tcp&at=2026-09-01T10:00:00Z&page_token="+
		envelope.NextPageToken, scope); err == nil {
		t.Fatal("continuation at another instant accepted")
	}

	reader.err = ledger.ErrForbidden
	response = &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, request); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusForbidden || strings.Contains(response.Body.String(), "poc-01") {
		t.Fatal("denied read disclosed history")
	}
}

func (data accessGraphHistoryData) edgeKey(t *testing.T, index int) ledger.EdgeKey {
	t.Helper()
	key, err := ledger.ParseEdgeKey(data.Edges[index].EdgeID)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestBrowserAccessGraphHistoryRejectsInvalidQueries(t *testing.T) {
	t.Parallel()
	request := browserManagementReadRequest(t, accessGraphHistoryTestPath())
	scope, _ := parseAccessGraphHistoryPath(request)
	for _, query := range []string{
		"at=yesterday", "at=2026-10-08", "device=not-a-uuid", "protocol=any", "page_size=0", "page_size=501",
		"page_size=01", "source=01890f00-0000-7000-8000-000000000301&source=01890f00-0000-7000-8000-000000000302",
		"status=all", "page_token=", "page_token=e30",
	} {
		if _, err := parseAccessGraphHistoryQuery(query, scope); err == nil {
			t.Errorf("invalid history query accepted: %s", query)
		}
	}
	options, _ := browserManagementTestOptions(t)
	plain, err := NewBrowserManagement(options)
	if err != nil {
		t.Fatal(err)
	}
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if !errors.Is(plain.Handle(response, request), ErrInvalidBrowserManagement) {
		t.Fatal("history served without its dependency")
	}
}
