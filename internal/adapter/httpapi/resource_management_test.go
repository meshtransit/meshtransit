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
	"github.com/meshtransit/meshtransit/internal/node"
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

func TestManagementHandlerSuspendsResource(t *testing.T) {
	t.Parallel()
	var captured authority.LifecycleCommand
	options := validManagementHandlerOptions(t)
	options.ResourceLifecycles = managementResourceLifecycleFunc(func(
		_ context.Context,
		command authority.LifecycleCommand,
	) (authority.LifecycleResult, error) {
		captured = command
		hash, err := resource.NewSemanticHash([32]byte{31: 1})
		if err != nil {
			t.Fatal(err)
		}
		return authority.NewLifecycleResult(
			command.Operation(), command.ResourceID(), command.GroupID(), command.Scope(),
			resource.StateSuspended, 2, 9, 4, hash,
		)
	})
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	path := resourceCollectionPath() +
		"/01890f00-0000-7000-8000-000000000501/actions/suspend"
	request := newManagementRequest(
		t, http.MethodPost, path, `{"reason":"temporarily remove destination"}`,
	)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"2"` ||
		captured.Operation() != authority.LifecycleSuspendResource ||
		captured.ExpectedVersion() != 1 || captured.ResourceID().String() !=
		"01890f00-0000-7000-8000-000000000501" {
		t.Fatalf("status/headers/command = %d/%+v/%+v; body=%s", response.Code,
			response.Header(), captured, response.Body.String())
	}
	var body resourceLifecycleEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil ||
		body.Data.ResourceID != "01890f00-0000-7000-8000-000000000501" ||
		body.Data.ResourceGroupID != "" || body.Data.State != "suspended" ||
		body.Data.Version != 2 || body.Data.InventoryRevision != 4 || body.Data.GroupRevision != 0 {
		t.Fatalf("lifecycle response = %+v, error=%v", body, err)
	}
}

func TestResourceLifecycleRequiresStrongPrecondition(t *testing.T) {
	t.Parallel()
	options := validManagementHandlerOptions(t)
	options.ResourceLifecycles = managementResourceLifecycleFunc(func(
		context.Context,
		authority.LifecycleCommand,
	) (authority.LifecycleResult, error) {
		return authority.LifecycleResult{}, errors.New("unexpected lifecycle call")
	})
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	request := newManagementRequest(
		t, http.MethodPost,
		resourceCollectionPath()+"/01890f00-0000-7000-8000-000000000501/actions/delete",
		`{"reason":"retire destination"}`,
	)
	request.Header.Del("If-Match")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusPreconditionRequired {
		t.Fatalf("status = %d, want 428; body=%s", response.Code, response.Body.String())
	}
}

func TestResourceLifecycleErrorClassification(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{err: authority.ErrLifecycleNotFound, status: http.StatusNotFound, code: "not_found"},
		{err: authority.ErrLifecycleVersionConflict, status: http.StatusPreconditionFailed, code: "precondition_failed"},
		{err: authority.ErrInvalidLifecycleTransition, status: http.StatusConflict, code: "invalid_state_transition"},
	}
	for _, test := range tests {
		classified := classifyResourceLifecycleError(test.err)
		if classified.Status != test.status || classified.Code != test.code {
			t.Fatalf("classification for %v = %+v", test.err, classified)
		}
	}
}

func TestManagementHandlerPreviewsResourceRebindImpact(t *testing.T) {
	t.Parallel()
	var captured authority.RebindPreview
	options := validManagementHandlerOptions(t)
	options.ResourceRebindings = managementResourceRebinderFixture{
		preview: func(
			_ context.Context,
			preview authority.RebindPreview,
		) (authority.RebindImpact, error) {
			captured = preview
			return managementRebindImpactFixture(t, preview), nil
		},
	}
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	request := newManagementRequest(
		t, http.MethodPost,
		resourceCollectionPath()+"/01890f00-0000-7000-8000-000000000501/actions/preview-rebind",
		`{"device_id":"01890f00-0000-7000-8000-000000000302"}`,
	)
	request.Header.Del("Idempotency-Key")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"1"` ||
		captured.DeviceID().String() != "01890f00-0000-7000-8000-000000000302" {
		t.Fatalf("status/headers/preview = %d/%+v/%+v; body=%s", response.Code,
			response.Header(), captured, response.Body.String())
	}
	var body resourceRebindPreviewEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil ||
		body.Data.ResourceID != "01890f00-0000-7000-8000-000000000501" ||
		body.Data.TargetGeneration != 2 || len(body.Data.AffectedResourceGroupIDs) != 1 ||
		body.Data.ApprovalRequired || len(body.Data.ImpactHash) != 64 {
		t.Fatalf("Resource rebind preview = %+v, error=%v", body, err)
	}
}

func TestManagementHandlerRejectsPreviewRebindMutationFields(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name               string
		body               string
		keepIdempotencyKey bool
	}{
		{
			name: "mutation field", body: `{"device_id":"01890f00-0000-7000-8000-000000000302","impact_hash":""}`,
		},
		{
			name: "idempotency key", body: `{"device_id":"01890f00-0000-7000-8000-000000000302"}`,
			keepIdempotencyKey: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := validManagementHandlerOptions(t)
			options.ResourceRebindings = managementResourceRebinderFixture{}
			handler, err := NewManagementHandler(options)
			if err != nil {
				t.Fatal(err)
			}
			request := newManagementRequest(
				t, http.MethodPost,
				resourceCollectionPath()+"/01890f00-0000-7000-8000-000000000501/actions/preview-rebind",
				test.body,
			)
			if !test.keepIdempotencyKey {
				request.Header.Del("Idempotency-Key")
			}
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestManagementHandlerAppliesAcknowledgedResourceRebind(t *testing.T) {
	t.Parallel()
	var captured authority.RebindCommand
	options := validManagementHandlerOptions(t)
	options.ResourceRebindings = managementResourceRebinderFixture{
		rebind: func(
			_ context.Context,
			command authority.RebindCommand,
		) (authority.RebindResult, error) {
			captured = command
			semanticHash, err := resource.NewSemanticHash([32]byte{31: 2})
			if err != nil {
				t.Fatal(err)
			}
			return authority.NewRebindResult(
				command.ResourceID(), command.Scope(), command.DeviceID(), 2, 2, 9, 4,
				semanticHash, command.ImpactHash(),
			)
		},
	}
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	request := newManagementRequest(
		t, http.MethodPost,
		resourceCollectionPath()+"/01890f00-0000-7000-8000-000000000501/actions/rebind",
		`{"device_id":"01890f00-0000-7000-8000-000000000302","impact_hash":"`+
			strings.Repeat("01", 32)+`","reason":"replace failed Device target"}`,
	)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"2"` ||
		captured.ExpectedVersion() != 1 || !captured.ImpactHash().IsValid() {
		t.Fatalf("status/headers/command = %d/%+v/%+v; body=%s", response.Code,
			response.Header(), captured, response.Body.String())
	}
	var body resourceRebindEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil ||
		body.Data.DeviceID != "01890f00-0000-7000-8000-000000000302" ||
		body.Data.TargetGeneration != 2 || body.Data.Version != 2 ||
		body.Data.InventoryRevision != 4 {
		t.Fatalf("Resource rebind response = %+v, error=%v", body, err)
	}
}

func TestManagementHandlerRejectsNonCanonicalRebindImpactHash(t *testing.T) {
	t.Parallel()
	options := validManagementHandlerOptions(t)
	options.ResourceRebindings = managementResourceRebinderFixture{}
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	request := newManagementRequest(
		t, http.MethodPost,
		resourceCollectionPath()+"/01890f00-0000-7000-8000-000000000501/actions/rebind",
		`{"device_id":"01890f00-0000-7000-8000-000000000302","impact_hash":"`+
			strings.Repeat("AB", 32)+`","reason":"replace failed Device target"}`,
	)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", response.Code, response.Body.String())
	}
}

func TestResourceRebindErrorClassification(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{err: authority.ErrRebindNotFound, status: http.StatusNotFound, code: "not_found"},
		{err: authority.ErrRebindVersionConflict, status: http.StatusPreconditionFailed, code: "precondition_failed"},
		{err: authority.ErrRebindImpactChanged, status: http.StatusConflict, code: "impact_changed"},
		{err: authority.ErrRebindApprovalRequired, status: http.StatusConflict, code: "approval_required"},
	}
	for _, test := range tests {
		classified := classifyResourceRebindError(test.err)
		if classified.Status != test.status || classified.Code != test.code {
			t.Fatalf("classification for %v = %+v", test.err, classified)
		}
	}
}

func TestManagementHandlerPreviewsResourceGroupReplacement(t *testing.T) {
	t.Parallel()
	var captured authority.GroupReplacePreview
	options := validManagementHandlerOptions(t)
	options.ResourceGroupReplacements = managementResourceGroupReplacerFixture{
		preview: func(
			_ context.Context,
			preview authority.GroupReplacePreview,
		) (authority.GroupReplaceImpact, error) {
			captured = preview
			return managementGroupReplaceImpactFixture(t, preview), nil
		},
	}
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	request := newManagementRequest(
		t, http.MethodPost, resourceGroupItemPath()+"/actions/preview-replace",
		`{"members":[{"resource_id":"01890f00-0000-7000-8000-000000000503","resource_version":1,"target_generation":1}]}`,
	)
	request.Header.Del("Idempotency-Key")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"1"` ||
		len(captured.Members()) != 1 {
		t.Fatalf("status/headers/preview = %d/%+v/%+v; body=%s", response.Code,
			response.Header(), captured, response.Body.String())
	}
	var body resourceGroupReplacePreviewEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil ||
		body.Data.ResourceGroupID != "01890f00-0000-7000-8000-000000000502" ||
		body.Data.CurrentDefinitionVersion != 1 || body.Data.DefinitionVersion != 2 ||
		len(body.Data.AddedMembers) != 1 || len(body.Data.RemovedMembers) != 1 ||
		len(body.Data.RetainedMembers) != 0 || body.Data.ApprovalRequired ||
		len(body.Data.ImpactHash) != 64 {
		t.Fatalf("Resource Group replacement preview = %+v, error=%v", body, err)
	}
}

func TestManagementHandlerAppliesResourceGroupReplacement(t *testing.T) {
	t.Parallel()
	var captured authority.GroupReplaceCommand
	options := validManagementHandlerOptions(t)
	options.ResourceGroupReplacements = managementResourceGroupReplacerFixture{
		replace: func(
			_ context.Context,
			command authority.GroupReplaceCommand,
		) (authority.GroupReplaceResult, error) {
			captured = command
			semanticHash, err := resource.NewSemanticHash([32]byte{31: 3})
			if err != nil {
				t.Fatal(err)
			}
			return authority.NewGroupReplaceResult(
				command.GroupID(), command.Scope(), 2, 2, 9, 4,
				semanticHash, command.ImpactHash(),
			)
		},
	}
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	request := newManagementRequest(
		t, http.MethodPost, resourceGroupItemPath()+"/actions/replace",
		`{"members":[{"resource_id":"01890f00-0000-7000-8000-000000000503","resource_version":1,"target_generation":1}],"impact_hash":"`+
			strings.Repeat("02", 32)+`","reason":"replace immutable production group definition"}`,
	)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"2"` ||
		captured.ExpectedVersion() != 1 || len(captured.Members()) != 1 ||
		!captured.ImpactHash().IsValid() {
		t.Fatalf("status/headers/command = %d/%+v/%+v; body=%s", response.Code,
			response.Header(), captured, response.Body.String())
	}
	var body resourceGroupReplaceEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil ||
		body.Data.ResourceGroupID != "01890f00-0000-7000-8000-000000000502" ||
		body.Data.DefinitionVersion != 2 || body.Data.Version != 2 ||
		body.Data.GroupRevision != 4 || len(body.Data.Members) != 1 {
		t.Fatalf("Resource Group replacement response = %+v, error=%v", body, err)
	}
}

func TestResourceGroupReplaceErrorClassification(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{err: authority.ErrGroupReplaceNotFound, status: http.StatusNotFound, code: "not_found"},
		{err: authority.ErrGroupReplaceVersionConflict, status: http.StatusPreconditionFailed, code: "precondition_failed"},
		{err: authority.ErrGroupReplaceMemberConflict, status: http.StatusConflict, code: "member_conflict"},
		{err: authority.ErrGroupReplaceNoChange, status: http.StatusConflict, code: "definition_unchanged"},
		{err: authority.ErrGroupReplaceImpactChanged, status: http.StatusConflict, code: "impact_changed"},
		{err: authority.ErrGroupReplaceApprovalRequired, status: http.StatusConflict, code: "approval_required"},
	}
	for _, test := range tests {
		classified := classifyResourceGroupReplaceError(test.err)
		if classified.Status != test.status || classified.Code != test.code {
			t.Fatalf("classification for %v = %+v", test.err, classified)
		}
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

func resourceGroupItemPath() string {
	return "/api/v1/workspaces/" + managementWorkspaceID() + "/networks/" +
		managementNetworkID() + "/resource-groups/01890f00-0000-7000-8000-000000000502"
}

type managementResourceCreatorFunc func(context.Context, authority.Command) (authority.Result, error)

func (function managementResourceCreatorFunc) Create(
	ctx context.Context,
	command authority.Command,
) (authority.Result, error) {
	return function(ctx, command)
}

type managementResourceLifecycleFunc func(
	context.Context,
	authority.LifecycleCommand,
) (authority.LifecycleResult, error)

func (function managementResourceLifecycleFunc) Transition(
	ctx context.Context,
	command authority.LifecycleCommand,
) (authority.LifecycleResult, error) {
	return function(ctx, command)
}

type managementResourceRebinderFixture struct {
	preview func(context.Context, authority.RebindPreview) (authority.RebindImpact, error)
	rebind  func(context.Context, authority.RebindCommand) (authority.RebindResult, error)
}

type managementResourceGroupReplacerFixture struct {
	preview func(context.Context, authority.GroupReplacePreview) (authority.GroupReplaceImpact, error)
	replace func(context.Context, authority.GroupReplaceCommand) (authority.GroupReplaceResult, error)
}

func (fixture managementResourceGroupReplacerFixture) Preview(
	ctx context.Context,
	preview authority.GroupReplacePreview,
) (authority.GroupReplaceImpact, error) {
	if fixture.preview == nil {
		return authority.GroupReplaceImpact{}, errors.New("unexpected Resource Group replacement preview")
	}
	return fixture.preview(ctx, preview)
}

func (fixture managementResourceGroupReplacerFixture) Replace(
	ctx context.Context,
	command authority.GroupReplaceCommand,
) (authority.GroupReplaceResult, error) {
	if fixture.replace == nil {
		return authority.GroupReplaceResult{}, errors.New("unexpected Resource Group replacement")
	}
	return fixture.replace(ctx, command)
}

func managementGroupReplaceImpactFixture(
	t *testing.T,
	preview authority.GroupReplacePreview,
) authority.GroupReplaceImpact {
	t.Helper()
	name, err := resource.ParseDisplayName("Production databases")
	if err != nil {
		t.Fatal(err)
	}
	currentResourceID, err := resource.ParseID("01890f00-0000-7000-8000-000000000501")
	if err != nil {
		t.Fatal(err)
	}
	currentMember, err := resource.NewReference(preview.Scope(), currentResourceID, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	current, err := resource.NewGroupRevision(resource.GroupRevisionParams{
		Scope: preview.Scope(), DisplayName: name,
		OwnerPrincipalID:     preview.AccountSession().PrincipalID(),
		CustodianPrincipalID: preview.AccountSession().PrincipalID(),
		DefinitionVersion:    1, Members: []resource.Reference{currentMember},
	})
	if err != nil {
		t.Fatal(err)
	}
	proposed, err := resource.NewGroupRevision(resource.GroupRevisionParams{
		Scope: preview.Scope(), DisplayName: name,
		OwnerPrincipalID:     preview.AccountSession().PrincipalID(),
		CustodianPrincipalID: preview.AccountSession().PrincipalID(),
		DefinitionVersion:    2, Members: preview.Members(),
	})
	if err != nil {
		t.Fatal(err)
	}
	impact, err := authority.NewGroupReplaceImpact(authority.GroupReplaceImpactParams{
		GroupID: preview.GroupID(), ExpectedVersion: preview.ExpectedVersion(),
		CurrentRevision: current, ProposedRevision: proposed,
	})
	if err != nil {
		t.Fatal(err)
	}
	return impact
}

func (fixture managementResourceRebinderFixture) Preview(
	ctx context.Context,
	preview authority.RebindPreview,
) (authority.RebindImpact, error) {
	if fixture.preview == nil {
		return authority.RebindImpact{}, errors.New("unexpected Resource rebind preview")
	}
	return fixture.preview(ctx, preview)
}

func (fixture managementResourceRebinderFixture) Rebind(
	ctx context.Context,
	command authority.RebindCommand,
) (authority.RebindResult, error) {
	if fixture.rebind == nil {
		return authority.RebindResult{}, errors.New("unexpected Resource rebind")
	}
	return fixture.rebind(ctx, command)
}

func managementRebindImpactFixture(
	t *testing.T,
	preview authority.RebindPreview,
) authority.RebindImpact {
	t.Helper()
	currentDeviceID, err := node.ParseID(managementDeviceID())
	if err != nil {
		t.Fatal(err)
	}
	name, err := resource.ParseDisplayName("Database 01")
	if err != nil {
		t.Fatal(err)
	}
	revision, err := resource.NewDeviceRevision(resource.DeviceRevisionParams{
		Scope: preview.Scope(), DisplayName: name,
		OwnerPrincipalID:     preview.AccountSession().PrincipalID(),
		CustodianPrincipalID: preview.AccountSession().PrincipalID(),
		DeviceID:             preview.DeviceID(), TargetGeneration: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	currentHash, err := resource.NewSemanticHash([32]byte{31: 1})
	if err != nil {
		t.Fatal(err)
	}
	groupID, err := resource.ParseGroupID("01890f00-0000-7000-8000-000000000502")
	if err != nil {
		t.Fatal(err)
	}
	impact, err := authority.NewRebindImpact(authority.RebindImpactParams{
		ResourceID: preview.ResourceID(), ExpectedVersion: preview.ExpectedVersion(),
		CurrentDeviceID: currentDeviceID, CurrentTargetGeneration: 1,
		CurrentSemanticHash: currentHash,
		ProposedRevision:    revision, AffectedGroupIDs: []resource.GroupID{groupID},
	})
	if err != nil {
		t.Fatal(err)
	}
	return impact
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
