package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/accessgraph"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/sharing"
)

type managementGraphReaderFunc func(
	context.Context, accountsession.Session, accessgraph.GraphQuery, time.Time,
) (accessgraph.GraphPage, error)

func (function managementGraphReaderFunc) ReadGraph(
	ctx context.Context,
	session accountsession.Session,
	query accessgraph.GraphQuery,
	evaluatedAt time.Time,
) (accessgraph.GraphPage, error) {
	return function(ctx, session, query, evaluatedAt)
}

func TestManagementHandlerListsAccessGraphPage(t *testing.T) {
	t.Parallel()

	var seen accessgraph.GraphQuery
	handler := managementGraphHandler(t, func(
		_ context.Context, _ accountsession.Session, query accessgraph.GraphQuery, _ time.Time,
	) (accessgraph.GraphPage, error) {
		seen = query
		return managementGraphPage(t, query, true), nil
	})
	request := newManagementRequest(t, http.MethodGet,
		validAccessGraphListPath()+"?device_id="+managementDeviceID()+"&protocol=tcp&page_size=1", "")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"6"` ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status = %d, headers = %v, body = %s", response.Code, response.Header(), response.Body.String())
	}
	deviceID, filtered := seen.DeviceID()
	protocol, byProtocol := seen.Protocol()
	if !filtered || deviceID.String() != managementDeviceID() || !byProtocol ||
		protocol != policy.ProtocolTCP || seen.PageSize() != 1 {
		t.Fatalf("query = %+v", seen)
	}
	var body struct {
		Data struct {
			Nodes []struct {
				Kind  string          `json:"kind"`
				ID    string          `json:"id"`
				Name  string          `json:"name"`
				State string          `json:"state"`
				Share json.RawMessage `json:"share"`
			} `json:"nodes"`
			Paths []struct {
				SelectorKind                  string `json:"selector_kind"`
				DestinationImportedResourceID string `json:"destination_imported_resource_id"`
			} `json:"paths"`
			MatchingPaths int     `json:"matching_paths"`
			NextPageToken *string `json:"next_page_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	data := body.Data
	if len(data.Paths) != 1 || data.Paths[0].SelectorKind != "imported_resource" ||
		len(data.Nodes) != 2 || data.Nodes[0].Kind != "device" || data.Nodes[1].Kind != "imported_resource" ||
		string(data.Nodes[0].Share) != "null" || len(data.Nodes[1].Share) < 10 ||
		data.MatchingPaths != 3 || data.NextPageToken == nil {
		t.Fatalf("listing = %+v", data)
	}
	if _, err := accessgraph.ParseGraphCursor(*data.NextPageToken); err != nil {
		t.Fatalf("next token = %q: %v", *data.NextPageToken, err)
	}
}

func TestManagementHandlerRejectsInvalidAccessGraphQueries(t *testing.T) {
	t.Parallel()

	handler := managementGraphHandler(t, func(
		context.Context, accountsession.Session, accessgraph.GraphQuery, time.Time,
	) (accessgraph.GraphPage, error) {
		t.Error("reader called for an invalid query")
		return accessgraph.GraphPage{}, accessgraph.ErrUnavailable
	})
	for name, query := range map[string]string{
		"unknown parameter":     "?owner=me",
		"repeated parameter":    "?protocol=tcp&protocol=udp",
		"empty value":           "?protocol=",
		"unknown protocol":      "?protocol=sctp",
		"non-canonical size":    "?page_size=010",
		"oversized page":        "?page_size=501",
		"bad device":            "?device_id=not-a-uuid",
		"tampered continuation": "?page_token=eyJ2Ijo5fQ",
	} {
		// One handler has bounded request slots, so these share it in sequence.
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, newManagementRequest(t, http.MethodGet, validAccessGraphListPath()+query, ""))
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
		})
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, newManagementRequest(t, http.MethodPost, validAccessGraphListPath(), "{}"))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d", response.Code)
	}
}

func TestManagementHandlerMapsAccessGraphListFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "stale page token", err: accessgraph.ErrStaleGraphCursor, want: http.StatusConflict},
		{name: "too many group edges", err: accessgraph.ErrGraphTooLarge, want: http.StatusUnprocessableEntity},
		{name: "forbidden", err: accessgraph.ErrForbidden, want: http.StatusForbidden},
		{name: "unavailable", err: accessgraph.ErrUnavailable, want: http.StatusServiceUnavailable},
		{name: "invalid snapshot", err: accessgraph.ErrInvalidSnapshot, want: http.StatusInternalServerError},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			handler := managementGraphHandler(t, func(
				context.Context, accountsession.Session, accessgraph.GraphQuery, time.Time,
			) (accessgraph.GraphPage, error) {
				return accessgraph.GraphPage{}, test.err
			})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, newManagementRequest(t, http.MethodGet, validAccessGraphListPath(), ""))
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, test.want, response.Body.String())
			}
		})
	}
}

func TestManagementHandlerWithoutAccessGraphListerIsUnavailable(t *testing.T) {
	t.Parallel()

	handler, err := NewManagementHandler(validManagementHandlerOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, newManagementRequest(t, http.MethodGet, validAccessGraphListPath(), ""))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", response.Code)
	}
}

func managementGraphHandler(t *testing.T, reader managementGraphReaderFunc) *ManagementHandler {
	t.Helper()
	service, err := accessgraph.NewService(accessgraph.Dependencies{
		Reader: managementAccessGraphReaderFunc(func(
			context.Context, accountsession.Session, accessgraph.Query, time.Time,
		) (accessgraph.Snapshot, error) {
			return accessgraph.Snapshot{}, accessgraph.ErrUnavailable
		}),
		Clock: accessgraph.SystemClock{}, GraphReader: reader,
	})
	if err != nil {
		t.Fatal(err)
	}
	options := validManagementHandlerOptions(t)
	options.AccessGraphs = service
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func managementGraphPage(t *testing.T, query accessgraph.GraphQuery, more bool) accessgraph.GraphPage {
	t.Helper()
	sourceID, err := node.ParseID(managementDeviceID())
	if err != nil {
		t.Fatal(err)
	}
	importedID, err := sharing.ParseImportedResourceID("01890f00-0000-7000-8000-000000000981")
	if err != nil {
		t.Fatal(err)
	}
	projectionID, err := publication.ParseProjectionID("01890f00-0000-7000-8000-000000000701")
	if err != nil {
		t.Fatal(err)
	}
	ruleID, err := policy.ParseRuleID("01890f00-0000-7000-8000-000000000501")
	if err != nil {
		t.Fatal(err)
	}
	portRange, err := policy.NewPortRange(443, 443)
	if err != nil {
		t.Fatal(err)
	}
	share := managementAccessGraphShare(t, sharing.ContractStateActive)
	path, err := accessgraph.NewPath(accessgraph.PathParams{
		ProjectionID: projectionID, RuleID: ruleID, SourceNodeID: sourceID,
		Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{portRange},
		SelectorKind:                  accessgraph.SelectorKindImportedResource,
		DestinationImportedResourceID: importedID, TrustContractID: share.ContractID(),
	})
	if err != nil {
		t.Fatal(err)
	}
	device, err := accessgraph.NewGraphNode(accessgraph.GraphNodeParams{
		Kind: accessgraph.GraphNodeKindDevice, DeviceID: sourceID,
		Participant: managementAccessGraphParticipant(t, "poc-02"),
	})
	if err != nil {
		t.Fatal(err)
	}
	imported, err := accessgraph.NewGraphNode(accessgraph.GraphNodeParams{
		Kind: accessgraph.GraphNodeKindImportedResource, ImportedResourceID: importedID,
		Participant: managementAccessGraphParticipant(t, "poc01b"), Share: share,
	})
	if err != nil {
		t.Fatal(err)
	}
	revision, err := accessgraph.NewRevisionVector(accessgraph.RevisionVectorParams{
		NetworkRevision: 12, InventoryRevision: 8, GroupRevision: 9, PolicyRevision: 6,
		DNSRevision: 2, RouteRevision: 2, SharingRevision: 2, IsolationGeneration: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	releaseID, err := publication.ParseReleaseID("01890f00-0000-7000-8000-000000000901")
	if err != nil {
		t.Fatal(err)
	}
	semanticHash, err := publication.NewSemanticHash(sha256.Sum256([]byte("graph fixture")))
	if err != nil {
		t.Fatal(err)
	}
	page, err := accessgraph.NewGraphPage(query, accessgraph.GraphPageParams{
		Scope: query.Scope(), Revision: revision, HasActiveRelease: true, ReleaseID: releaseID,
		CompilerFormatVersion: 4, SemanticHash: semanticHash,
		Nodes: []accessgraph.GraphNode{device, imported}, Paths: []accessgraph.Path{path},
		MatchingPaths: 3, HasMore: more,
	})
	if err != nil {
		t.Fatal(err)
	}
	return page
}

func validAccessGraphListPath() string {
	return "/api/v1/workspaces/" + managementWorkspaceID() + "/networks/" +
		managementNetworkID() + "/access-graph"
}
