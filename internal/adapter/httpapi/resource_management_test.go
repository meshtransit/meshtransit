package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/resource"
	authority "github.com/meshtransit/meshtransit/internal/resource/authority"
	"github.com/meshtransit/meshtransit/internal/resource/catalog"
)

func TestManagementHandlerCreatesDeviceResource(t *testing.T) {
	t.Parallel()
	var captured authority.Command
	options := validManagementHandlerOptions(t)
	options.ResourceCreations = managementResourceCreatorFunc(func(
		_ context.Context,
		command authority.Command,
	) (authority.Result, error) {
		captured = command
		id, err := resource.ParseID("01890f00-0000-7000-8000-000000000501")
		if err != nil {
			t.Fatal(err)
		}
		return authority.NewResult(
			command.Operation(), id, resource.GroupID{}, command.Scope(),
			2, 2, 1, command.SemanticHash(),
		)
	})
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	path := resourceCollectionPath()
	request := newManagementRequest(
		t, http.MethodPost, path,
		`{"display_name":"Database 01","device_id":"`+managementDeviceID()+`","reason":"create production Resource"}`,
	)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated || response.Header().Get("ETag") != `"1"` ||
		response.Header().Get("Location") != path+"/01890f00-0000-7000-8000-000000000501" {
		t.Fatalf("status/headers = %d/%+v; body=%s", response.Code, response.Header(), response.Body.String())
	}
	if captured.Operation() != authority.OperationCreateDevice ||
		captured.Scope().WorkspaceID().String() != managementWorkspaceID() ||
		captured.Scope().NetworkID().String() != managementNetworkID() ||
		captured.Device().DeviceID().String() != managementDeviceID() ||
		captured.ExpectedSubsystemRevision() != 1 || !captured.IdempotencyEvidence().IsValid() {
		t.Fatalf("captured Resource command = %+v", captured)
	}
	var body resourceItemEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil ||
		body.Data.ResourceID != "01890f00-0000-7000-8000-000000000501" ||
		body.Data.DisplayName != "Database 01" || body.Data.State != "active" {
		t.Fatalf("Resource response = %+v, error=%v", body, err)
	}
}

func TestManagementHandlerCreatesResourceGroup(t *testing.T) {
	t.Parallel()
	var captured authority.Command
	options := validManagementHandlerOptions(t)
	options.ResourceCreations = managementResourceCreatorFunc(func(
		_ context.Context,
		command authority.Command,
	) (authority.Result, error) {
		captured = command
		id, err := resource.ParseGroupID("01890f00-0000-7000-8000-000000000502")
		if err != nil {
			t.Fatal(err)
		}
		return authority.NewResult(
			command.Operation(), resource.ID{}, id, command.Scope(),
			2, 2, 1, command.SemanticHash(),
		)
	})
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/workspaces/" + managementWorkspaceID() + "/networks/" +
		managementNetworkID() + "/resource-groups"
	request := newManagementRequest(
		t, http.MethodPost, path,
		`{"display_name":"Production databases","members":[{"resource_id":"01890f00-0000-7000-8000-000000000501","resource_version":1,"target_generation":1}],"reason":"create destination group"}`,
	)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated || response.Header().Get("ETag") != `"1"` ||
		captured.Operation() != authority.OperationCreateGroup || len(captured.Group().Members()) != 1 {
		t.Fatalf("status/headers/command = %d/%+v/%+v; body=%s", response.Code,
			response.Header(), captured, response.Body.String())
	}
}

func TestManagementHandlerListsResourcesWithFreshAuthority(t *testing.T) {
	t.Parallel()
	var capturedState resource.State
	var capturedLimit int
	options := validManagementHandlerOptions(t)
	options.ResourceCatalog = managementResourceCatalogFixture{
		listResources: func(
			_ context.Context,
			_ accountsession.Session,
			_ network.Scope,
			state resource.State,
			limit int,
			cursor catalog.PageCursor,
		) (catalog.ResourcePage, error) {
			capturedState, capturedLimit = state, limit
			if cursor.IsValid() {
				t.Fatal("first page unexpectedly carried a cursor")
			}
			return catalog.ResourcePage{Items: []catalog.Resource{}, Revision: 7}, nil
		},
	}
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequestWithContext(
		t.Context(), http.MethodGet, resourceCollectionPath()+"?state=active&page_size=25", nil,
	)
	request.Header.Set("Authorization", "Bearer "+managementTokenFixture)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"7"` ||
		capturedState != resource.StateActive || capturedLimit != 25 {
		t.Fatalf("list status/etag/state/limit = %d/%q/%v/%d; body=%s", response.Code,
			response.Header().Get("ETag"), capturedState, capturedLimit, response.Body.String())
	}
	var body resourceListEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.Data == nil || len(body.Data) != 0 {
		t.Fatalf("list response = %+v, error=%v", body, err)
	}
}

func TestManagementHandlerHidesCrossScopeResourceID(t *testing.T) {
	t.Parallel()
	options := validManagementHandlerOptions(t)
	options.ResourceCatalog = managementResourceCatalogFixture{
		getResource: func(
			context.Context,
			accountsession.Session,
			network.Scope,
			resource.ID,
		) (catalog.Resource, error) {
			return catalog.Resource{}, catalog.ErrNotFound
		},
	}
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequestWithContext(
		t.Context(), http.MethodGet,
		resourceCollectionPath()+"/01890f00-0000-7000-8000-000000000501", nil,
	)
	request.Header.Set("Authorization", "Bearer "+managementTokenFixture)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", response.Code, response.Body.String())
	}
}

func TestResourcePageCursorBindsCollectionAndFilter(t *testing.T) {
	t.Parallel()
	id, err := publicid.Parse("01890f00-0000-7000-8000-000000000501")
	if err != nil {
		t.Fatal(err)
	}
	cursor, err := catalog.NewPageCursor(7, id)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeResourcePageCursor("resources", "active", cursor)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeResourcePageCursor(encoded, "resources", "active")
	if err != nil || decoded.Revision() != 7 || decoded.After() != id {
		t.Fatalf("decoded cursor = %+v, error=%v", decoded, err)
	}
	if _, err := decodeResourcePageCursor(encoded, "resource-groups", "active"); err == nil {
		t.Fatal("Resource cursor crossed collection kind")
	}
	if _, err := decodeResourcePageCursor(encoded, "resources", "deleted"); err == nil {
		t.Fatal("Resource cursor crossed state filter")
	}
}

func TestParseResourceListQueryRejectsAmbiguousValues(t *testing.T) {
	t.Parallel()
	for _, rawQuery := range []string{
		"state=",
		"page_size=",
		"page_token=",
		"page_size=01",
		"page_size=101",
		"state=active&state=deleted",
		"unknown=value",
	} {
		t.Run(rawQuery, func(t *testing.T) {
			t.Parallel()
			if _, _, _, requestErr := parseResourceListQuery(rawQuery, "resources"); requestErr == nil {
				t.Fatalf("query %q was accepted", rawQuery)
			}
		})
	}
}

func TestResourceReadRejectsChunkedBody(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequestWithContext(
		t.Context(), http.MethodGet, resourceCollectionPath(), strings.NewReader("{}"),
	)
	request.ContentLength = -1
	request.TransferEncoding = []string{"chunked"}
	if validResourceReadHeaders(request) {
		t.Fatal("chunked GET body was accepted")
	}
}

func TestResourceAuthorityExpiredIdempotencyIsConflict(t *testing.T) {
	t.Parallel()
	classified := classifyResourceAuthorityError(authority.ErrIdempotencyExpired)
	if classified.Status != http.StatusConflict || classified.Code != "idempotency_expired" {
		t.Fatalf("classification = %+v", classified)
	}
}

func resourceCollectionPath() string {
	return "/api/v1/workspaces/" + managementWorkspaceID() + "/networks/" +
		managementNetworkID() + "/resources"
}

type managementResourceCreatorFunc func(context.Context, authority.Command) (authority.Result, error)

func (function managementResourceCreatorFunc) Create(
	ctx context.Context,
	command authority.Command,
) (authority.Result, error) {
	return function(ctx, command)
}

type managementResourceCatalogFixture struct {
	getResource   func(context.Context, accountsession.Session, network.Scope, resource.ID) (catalog.Resource, error)
	listResources func(context.Context, accountsession.Session, network.Scope, resource.State, int, catalog.PageCursor) (catalog.ResourcePage, error)
	getGroup      func(context.Context, accountsession.Session, network.Scope, resource.GroupID) (catalog.Group, error)
	listGroups    func(context.Context, accountsession.Session, network.Scope, resource.State, int, catalog.PageCursor) (catalog.GroupPage, error)
}

func (fixture managementResourceCatalogFixture) GetResource(
	ctx context.Context,
	session accountsession.Session,
	scope network.Scope,
	id resource.ID,
) (catalog.Resource, error) {
	if fixture.getResource == nil {
		return catalog.Resource{}, errors.New("unexpected Resource lookup")
	}
	return fixture.getResource(ctx, session, scope, id)
}

func (fixture managementResourceCatalogFixture) ListResources(
	ctx context.Context,
	session accountsession.Session,
	scope network.Scope,
	state resource.State,
	limit int,
	cursor catalog.PageCursor,
) (catalog.ResourcePage, error) {
	if fixture.listResources == nil {
		return catalog.ResourcePage{}, errors.New("unexpected Resource list")
	}
	return fixture.listResources(ctx, session, scope, state, limit, cursor)
}

func (fixture managementResourceCatalogFixture) GetGroup(
	ctx context.Context,
	session accountsession.Session,
	scope network.Scope,
	id resource.GroupID,
) (catalog.Group, error) {
	if fixture.getGroup == nil {
		return catalog.Group{}, errors.New("unexpected Resource Group lookup")
	}
	return fixture.getGroup(ctx, session, scope, id)
}

func (fixture managementResourceCatalogFixture) ListGroups(
	ctx context.Context,
	session accountsession.Session,
	scope network.Scope,
	state resource.State,
	limit int,
	cursor catalog.PageCursor,
) (catalog.GroupPage, error) {
	if fixture.listGroups == nil {
		return catalog.GroupPage{}, errors.New("unexpected Resource Group list")
	}
	return fixture.listGroups(ctx, session, scope, state, limit, cursor)
}
