package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/resource"
	"github.com/meshtransit/meshtransit/internal/sharing"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

func TestManagementHandlerCreatesShareOfferWithOneTimeToken(t *testing.T) {
	t.Parallel()

	fixture := managementSharingFixture(t, sharing.OfferStateOffered)
	var captured sharing.CreateOffer
	options := validManagementHandlerOptions(t)
	options.ResourceSharing = &managementResourceSharingStub{
		create: func(_ context.Context, command sharing.CreateOffer) (sharing.MutationResult, error) {
			captured = command
			return fixture.createResult, nil
		},
	}
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	path := sharingOfferCollectionPath()
	request := newManagementRequest(t, http.MethodPost, path,
		`{"consumer_workspace_id":"`+fixture.consumer.WorkspaceID().String()+
			`","consumer_network_id":"`+fixture.consumer.NetworkID().String()+
			`","resource_id":"`+fixture.binding.ResourceID().String()+
			`","maximum_traffic":[{"protocol":"tcp","destination_port_ranges":[{"first":443,"last":443}]}],`+
			`"expires_at":"2026-09-30T00:00:00Z","reason":"share production database"}`,
	)
	request.Header.Del("If-Match")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated || response.Header().Get("ETag") != `"1"` ||
		response.Header().Get("Location") != path+"/"+fixture.snapshot.Offer().ID().String() {
		t.Fatalf("status/headers = %d/%+v; body=%s", response.Code, response.Header(), response.Body.String())
	}
	if !captured.IsValid() || captured.ProviderScope() != fixture.provider ||
		captured.ConsumerScope() != fixture.consumer ||
		captured.ResourceID() != fixture.binding.ResourceID() ||
		!captured.MaximumTraffic().Allows(policy.ProtocolTCP, 443) {
		t.Fatalf("captured sharing command = %+v", captured)
	}
	var body shareOfferEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	token := fixture.token.Bytes()
	if body.Data.OfferID != fixture.snapshot.Offer().ID().String() ||
		body.Data.ScopeRelation != "cross_workspace" ||
		body.Data.State != "offered" || body.Data.Version != 1 ||
		body.Data.OfferToken != base64.RawURLEncoding.EncodeToString(token[:]) ||
		body.Data.ProviderSharingRevision != 2 || body.Data.ConsumerSharingRevision != 2 {
		t.Fatalf("sharing response = %+v", body)
	}
}

func TestManagementHandlerListsRevisionPinnedIncomingShareOffers(t *testing.T) {
	t.Parallel()

	fixture := managementSharingFixture(t, sharing.OfferStateOffered)
	nextID, _ := sharing.ParseOfferID("01890f00-0000-7000-8000-000000000823")
	next, err := sharing.NewPageCursor(7, nextID)
	if err != nil {
		t.Fatal(err)
	}
	page, err := sharing.NewOfferPage([]sharing.OfferSnapshot{fixture.snapshot}, 7, next)
	if err != nil {
		t.Fatal(err)
	}
	var capturedDirection sharing.Direction
	var capturedLimit int
	options := validManagementHandlerOptions(t)
	options.ResourceSharing = &managementResourceSharingStub{
		list: func(
			_ context.Context,
			_ accountsession.Session,
			scope network.Scope,
			direction sharing.Direction,
			state sharing.OfferState,
			limit int,
			cursor sharing.PageCursor,
		) (sharing.OfferPage, error) {
			if scope != fixture.consumer || state != sharing.OfferStateOffered || cursor.IsValid() {
				t.Fatal("list sharing request widened or supplied an unexpected cursor")
			}
			capturedDirection, capturedLimit = direction, limit
			return page, nil
		},
	}
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/workspaces/" + fixture.consumer.WorkspaceID().String() +
		"/networks/" + fixture.consumer.NetworkID().String() + "/share-offers" +
		"?direction=incoming&state=offered&page_size=25"
	request := newManagementRequest(t, http.MethodGet, path, "")
	request.Body = http.NoBody
	request.Header.Del("Content-Type")
	request.Header.Del("If-Match")
	request.Header.Del("Idempotency-Key")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"7"` ||
		capturedDirection != sharing.DirectionIncoming || capturedLimit != 25 {
		t.Fatalf("status/header/direction/limit = %d/%s/%v/%d; body=%s",
			response.Code, response.Header().Get("ETag"), capturedDirection, capturedLimit,
			response.Body.String())
	}
	var body shareOfferListEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || len(body.Data) != 1 ||
		body.Revision != 7 || body.NextPageToken == "" {
		t.Fatalf("list response = %+v, error=%v", body, err)
	}
	decoded, err := decodeSharingPageCursor(
		body.NextPageToken, sharing.DirectionIncoming, sharing.OfferStateOffered,
	)
	if err != nil || decoded != next {
		t.Fatalf("decoded next cursor = %+v, error=%v", decoded, err)
	}
}

func TestManagementHandlerSharingMutationRequiresPreconditionAndIdempotency(t *testing.T) {
	t.Parallel()

	fixture := managementSharingFixture(t, sharing.OfferStateOffered)
	path := "/api/v1/workspaces/" + fixture.consumer.WorkspaceID().String() +
		"/networks/" + fixture.consumer.NetworkID().String() + "/share-offers/" +
		fixture.snapshot.Offer().ID().String() + "/actions/accept"
	body := `{"provider_workspace_id":"` + fixture.provider.WorkspaceID().String() +
		`","provider_network_id":"` + fixture.provider.NetworkID().String() +
		`","consumer_workspace_id":"` + fixture.consumer.WorkspaceID().String() +
		`","consumer_network_id":"` + fixture.consumer.NetworkID().String() +
		`","offer_token":"invalid","imported_display_name":"database",` +
		`"access_name":"database.shared.consumer.example","reason":"accept database"}`
	for _, test := range []struct {
		name   string
		mutate func(*http.Request)
		status int
		code   string
	}{
		{name: "missing ETag", mutate: func(request *http.Request) { request.Header.Del("If-Match") }, status: http.StatusPreconditionRequired, code: "precondition_required"},
		{name: "missing idempotency", mutate: func(request *http.Request) { request.Header.Del("Idempotency-Key") }, status: http.StatusBadRequest, code: "invalid_request"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := validManagementHandlerOptions(t)
			options.ResourceSharing = &managementResourceSharingStub{}
			handler, err := NewManagementHandler(options)
			if err != nil {
				t.Fatal(err)
			}
			request := newManagementRequest(t, http.MethodPost, path, body)
			test.mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || decodeManagementErrorCode(t, response.Body.Bytes()) != test.code {
				t.Fatalf("status/body = %d/%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestManagementHandlerAcceptsShareOfferIntoFailClosedContract(t *testing.T) {
	t.Parallel()

	fixture, contract, result := managementSharingContractFixture(
		t, sharing.ContractStateActivating, 1,
	)
	var captured sharing.DecideOffer
	options := validManagementHandlerOptions(t)
	options.ResourceSharing = &managementResourceSharingStub{
		decide: func(_ context.Context, command sharing.DecideOffer) (sharing.MutationResult, error) {
			captured = command
			return result, nil
		},
	}
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	token := fixture.token.Bytes()
	path := "/api/v1/workspaces/" + fixture.consumer.WorkspaceID().String() +
		"/networks/" + fixture.consumer.NetworkID().String() + "/share-offers/" +
		fixture.snapshot.Offer().ID().String() + "/actions/accept"
	body := `{"provider_workspace_id":"` + fixture.provider.WorkspaceID().String() +
		`","provider_network_id":"` + fixture.provider.NetworkID().String() +
		`","consumer_workspace_id":"` + fixture.consumer.WorkspaceID().String() +
		`","consumer_network_id":"` + fixture.consumer.NetworkID().String() +
		`","offer_token":"` + base64.RawURLEncoding.EncodeToString(token[:]) +
		`","imported_display_name":"production database",` +
		`"access_name":"database.shared.consumer.example","reason":"accept reviewed share"}`
	request := newManagementRequest(t, http.MethodPost, path, body)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"1"` ||
		!captured.IsValid() || captured.Action() != sharing.DecisionActionAccept ||
		captured.ConsumerScope() != fixture.consumer || captured.ExpectedOfferVersion() != 1 ||
		captured.AccessName().String() != "database.shared.consumer.example" {
		t.Fatalf("status/header/command = %d/%s/%+v; body=%s",
			response.Code, response.Header().Get("ETag"), captured, response.Body.String())
	}
	var envelope shareContractEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil ||
		envelope.Data.TrustContractID != contract.ID().String() ||
		envelope.Data.State != "activating" || envelope.Data.ImportedResourceVersion != 1 ||
		envelope.Data.AccessName != "database.shared.consumer.example" {
		t.Fatalf("accept response = %+v, error=%v", envelope, err)
	}
}

func TestManagementHandlerRequiresAccessNameOnlyForShareAcceptance(t *testing.T) {
	t.Parallel()

	fixture := managementSharingFixture(t, sharing.OfferStateOffered)
	token := fixture.token.Bytes()
	baseBody := `{"provider_workspace_id":"` + fixture.provider.WorkspaceID().String() +
		`","provider_network_id":"` + fixture.provider.NetworkID().String() +
		`","consumer_workspace_id":"` + fixture.consumer.WorkspaceID().String() +
		`","consumer_network_id":"` + fixture.consumer.NetworkID().String() +
		`","offer_token":"` + base64.RawURLEncoding.EncodeToString(token[:]) + `"`
	for _, test := range []struct {
		name   string
		action string
		body   string
	}{
		{
			name:   "accept without access name",
			action: "accept",
			body:   baseBody + `,"imported_display_name":"production database"}`,
		},
		{
			name:   "reject with access name",
			action: "reject",
			body:   baseBody + `,"access_name":"database.shared.consumer.example"}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := validManagementHandlerOptions(t)
			options.ResourceSharing = &managementResourceSharingStub{
				decide: func(context.Context, sharing.DecideOffer) (sharing.MutationResult, error) {
					t.Fatal("invalid request reached resource-sharing service")
					return sharing.MutationResult{}, nil
				},
			}
			handler, err := NewManagementHandler(options)
			if err != nil {
				t.Fatal(err)
			}
			path := "/api/v1/workspaces/" + fixture.consumer.WorkspaceID().String() +
				"/networks/" + fixture.consumer.NetworkID().String() + "/share-offers/" +
				fixture.snapshot.Offer().ID().String() + "/actions/" + test.action
			request := newManagementRequest(t, http.MethodPost, path, test.body)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest ||
				decodeManagementErrorCode(t, response.Body.Bytes()) != "invalid_request" {
				t.Fatalf("status/body = %d/%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestManagementHandlerActivatesTrustContractFromConsumerScope(t *testing.T) {
	t.Parallel()

	fixture, contract, result := managementSharingContractFixture(
		t, sharing.ContractStateActive, 2,
	)
	var captured sharing.ActivateContract
	options := validManagementHandlerOptions(t)
	options.ResourceSharing = &managementResourceSharingStub{
		activate: func(
			_ context.Context,
			command sharing.ActivateContract,
		) (sharing.MutationResult, error) {
			captured = command
			return result, nil
		},
	}
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/workspaces/" + fixture.consumer.WorkspaceID().String() +
		"/networks/" + fixture.consumer.NetworkID().String() + "/trust-contracts/" +
		contract.ID().String() + "/actions/activate"
	body := `{"provider_workspace_id":"` + fixture.provider.WorkspaceID().String() +
		`","provider_network_id":"` + fixture.provider.NetworkID().String() +
		`","consumer_workspace_id":"` + fixture.consumer.WorkspaceID().String() +
		`","consumer_network_id":"` + fixture.consumer.NetworkID().String() +
		`","reason":"consumer activates reviewed share"}`
	request := newManagementRequest(t, http.MethodPost, path, body)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"2"` ||
		!captured.IsValid() || captured.ConsumerScope() != fixture.consumer ||
		captured.ContractID() != contract.ID() || captured.ExpectedContractVersion() != 1 {
		t.Fatalf("status/header/command = %d/%s/%+v; body=%s",
			response.Code, response.Header().Get("ETag"), captured, response.Body.String())
	}
	var envelope shareContractEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil ||
		envelope.Data.State != "active" || envelope.Data.Version != 2 ||
		envelope.Data.ImportedResourceVersion != 2 {
		t.Fatalf("activate response = %+v, error=%v", envelope, err)
	}
}

func TestManagementHandlerRevokesTrustContractFromProviderScope(t *testing.T) {
	t.Parallel()

	fixture, contract, result := managementSharingContractFixture(
		t, sharing.ContractStateRevoked, 2,
	)
	var captured sharing.RevokeContract
	options := validManagementHandlerOptions(t)
	options.ResourceSharing = &managementResourceSharingStub{
		revoke: func(_ context.Context, command sharing.RevokeContract) (sharing.MutationResult, error) {
			captured = command
			return result, nil
		},
	}
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/workspaces/" + fixture.provider.WorkspaceID().String() +
		"/networks/" + fixture.provider.NetworkID().String() + "/trust-contracts/" +
		contract.ID().String() + "/actions/revoke"
	body := `{"provider_workspace_id":"` + fixture.provider.WorkspaceID().String() +
		`","provider_network_id":"` + fixture.provider.NetworkID().String() +
		`","consumer_workspace_id":"` + fixture.consumer.WorkspaceID().String() +
		`","consumer_network_id":"` + fixture.consumer.NetworkID().String() +
		`","reason":"provider emergency revocation"}`
	request := newManagementRequest(t, http.MethodPost, path, body)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"2"` ||
		!captured.IsValid() || captured.LocalScope() != fixture.provider ||
		captured.ContractID() != contract.ID() || captured.ExpectedContractVersion() != 1 {
		t.Fatalf("status/header/command = %d/%s/%+v; body=%s",
			response.Code, response.Header().Get("ETag"), captured, response.Body.String())
	}
	var envelope shareContractEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil ||
		envelope.Data.State != "revoked" || envelope.Data.Version != 2 ||
		envelope.Data.ImportedResourceVersion != 2 {
		t.Fatalf("revoke response = %+v, error=%v", envelope, err)
	}
}

func TestSharingErrorsDoNotLeakAuthorityDetails(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		err    error
		status int
		code   string
	}{
		{err: sharing.ErrForbidden, status: http.StatusForbidden, code: "forbidden"},
		{err: sharing.ErrNotFound, status: http.StatusNotFound, code: "not_found"},
		{err: sharing.ErrConflict, status: http.StatusConflict, code: "conflict"},
		{err: sharing.ErrUnavailable, status: http.StatusServiceUnavailable, code: "operation_unavailable"},
		{err: errors.New("sensitive database detail"), status: http.StatusInternalServerError, code: "internal_failure"},
	} {
		classified := classifySharingError(test.err)
		if classified.Status != test.status || classified.Code != test.code ||
			classified.Message == test.err.Error() {
			t.Fatalf("classifySharingError(%v) = %+v", test.err, classified)
		}
	}
}

type managementResourceSharingStub struct {
	getContract func(context.Context, accountsession.Session, network.Scope, sharing.ContractID) (sharing.ContractSnapshot, error)
	create      func(context.Context, sharing.CreateOffer) (sharing.MutationResult, error)
	decide      func(context.Context, sharing.DecideOffer) (sharing.MutationResult, error)
	activate    func(context.Context, sharing.ActivateContract) (sharing.MutationResult, error)
	revoke      func(context.Context, sharing.RevokeContract) (sharing.MutationResult, error)
	get         func(context.Context, accountsession.Session, network.Scope, sharing.OfferID) (sharing.OfferSnapshot, error)
	list        func(context.Context, accountsession.Session, network.Scope, sharing.Direction, sharing.OfferState, int, sharing.PageCursor) (sharing.OfferPage, error)
}

func (stub *managementResourceSharingStub) CreateOffer(ctx context.Context, command sharing.CreateOffer) (sharing.MutationResult, error) {
	if stub.create == nil {
		return sharing.MutationResult{}, sharing.ErrUnavailable
	}
	return stub.create(ctx, command)
}

func (stub *managementResourceSharingStub) DecideOffer(ctx context.Context, command sharing.DecideOffer) (sharing.MutationResult, error) {
	if stub.decide == nil {
		return sharing.MutationResult{}, sharing.ErrUnavailable
	}
	return stub.decide(ctx, command)
}

func (stub *managementResourceSharingStub) ActivateContract(
	ctx context.Context,
	command sharing.ActivateContract,
) (sharing.MutationResult, error) {
	if stub.activate == nil {
		return sharing.MutationResult{}, sharing.ErrUnavailable
	}
	return stub.activate(ctx, command)
}

func (stub *managementResourceSharingStub) RevokeContract(ctx context.Context, command sharing.RevokeContract) (sharing.MutationResult, error) {
	if stub.revoke == nil {
		return sharing.MutationResult{}, sharing.ErrUnavailable
	}
	return stub.revoke(ctx, command)
}

func (stub *managementResourceSharingStub) GetOffer(ctx context.Context, session accountsession.Session, scope network.Scope, id sharing.OfferID) (sharing.OfferSnapshot, error) {
	if stub.get == nil {
		return sharing.OfferSnapshot{}, sharing.ErrUnavailable
	}
	return stub.get(ctx, session, scope, id)
}

func (stub *managementResourceSharingStub) ListOffers(ctx context.Context, session accountsession.Session, scope network.Scope, direction sharing.Direction, state sharing.OfferState, limit int, cursor sharing.PageCursor) (sharing.OfferPage, error) {
	if stub.list == nil {
		return sharing.OfferPage{}, sharing.ErrUnavailable
	}
	return stub.list(ctx, session, scope, direction, state, limit, cursor)
}

type managementSharingFixtureValue struct {
	provider     network.Scope
	consumer     network.Scope
	binding      sharing.ResourceBinding
	snapshot     sharing.OfferSnapshot
	token        sharing.OfferToken
	createResult sharing.MutationResult
}

func managementSharingFixture(t *testing.T, state sharing.OfferState) managementSharingFixtureValue {
	t.Helper()
	provider := managementSharingScope(t, managementWorkspaceID(), managementNetworkID())
	consumer := managementSharingScope(
		t,
		"01890f00-0000-7000-8000-000000000102",
		"01890f00-0000-7000-8000-000000000202",
	)
	resourceID, _ := resource.ParseID("01890f00-0000-7000-8000-000000000521")
	semanticHash, err := resource.NewSemanticHash([32]byte{31: 1})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := sharing.NewResourceBinding(provider, resourceID, 3, 2, semanticHash)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := policy.NewPortRange(443, 443)
	constraint, _ := sharing.NewTrafficConstraint(sharing.TrafficConstraintParams{
		Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{port},
	})
	traffic, _ := sharing.NewTrafficSet([]sharing.TrafficConstraint{constraint})
	exportID, _ := sharing.ParseExportID("01890f00-0000-7000-8000-000000000821")
	offerID, _ := sharing.ParseOfferID("01890f00-0000-7000-8000-000000000822")
	createdAt := time.Date(2026, time.September, 29, 0, 0, 0, 0, time.UTC)
	offer, err := sharing.NewOffer(sharing.OfferParams{
		ID: offerID, ExportID: exportID, ProviderScope: provider, ConsumerScope: consumer,
		MaximumTraffic: traffic, NonceDigest: [32]byte{31: 2},
		ExpiresAt: createdAt.Add(24 * time.Hour), State: state, Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := sharing.NewOfferSnapshot(offer, binding, offer.ExpiresAt(), createdAt)
	if err != nil {
		t.Fatal(err)
	}
	token, err := sharing.NewOfferToken([32]byte{31: 3})
	if err != nil {
		t.Fatal(err)
	}
	result, err := sharing.NewMutationResult(sharing.MutationResultParams{
		Offer: snapshot, Token: token, HasOffer: true, HasToken: true,
		ProviderNetworkRevision: 3, ProviderSharingRevision: 2,
		ConsumerNetworkRevision: 3, ConsumerSharingRevision: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	return managementSharingFixtureValue{
		provider: provider, consumer: consumer, binding: binding,
		snapshot: snapshot, token: token, createResult: result,
	}
}

func managementSharingContractFixture(
	t *testing.T,
	state sharing.ContractState,
	version int64,
) (managementSharingFixtureValue, sharing.Contract, sharing.MutationResult) {
	t.Helper()
	fixture := managementSharingFixture(t, sharing.OfferStateOffered)
	contractID, _ := sharing.ParseContractID("01890f00-0000-7000-8000-000000000824")
	importedID, _ := sharing.ParseImportedResourceID("01890f00-0000-7000-8000-000000000825")
	decidedAt := fixture.snapshot.CreatedAt().Add(time.Minute)
	offer, err := sharing.NewOffer(sharing.OfferParams{
		ID: fixture.snapshot.Offer().ID(), ExportID: fixture.snapshot.Offer().ExportID(),
		ProviderScope: fixture.provider, ConsumerScope: fixture.consumer,
		MaximumTraffic: fixture.snapshot.Offer().MaximumTraffic(),
		NonceDigest:    fixture.snapshot.Offer().NonceDigest(),
		ExpiresAt:      fixture.snapshot.Offer().ExpiresAt(), State: sharing.OfferStateAccepted,
		Version: 2, DecidedAt: decidedAt, AcceptedContractID: contractID,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.snapshot, err = sharing.NewOfferSnapshot(offer, fixture.binding, fixture.snapshot.ShareExpiresAt(), fixture.snapshot.CreatedAt())
	if err != nil {
		t.Fatal(err)
	}
	endedAt := time.Time{}
	if state == sharing.ContractStateRevoked {
		endedAt = decidedAt.Add(time.Minute)
	}
	contract, err := sharing.NewContract(sharing.ContractParams{
		ID: contractID, ImportedResourceID: importedID,
		OfferID: offer.ID(), ExportID: offer.ExportID(),
		ProviderScope: fixture.provider, ConsumerScope: fixture.consumer,
		Resource: fixture.binding, MaximumTraffic: offer.MaximumTraffic(),
		ProviderAuthorityGeneration: 4, ConsumerAuthorityGeneration: 5,
		RecoveryEpoch: 6, ExpiresAt: offer.ExpiresAt(), State: state,
		Version: version, EndedAt: endedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := sharing.NewMutationResult(sharing.MutationResultParams{
		Offer: fixture.snapshot, Contract: contract,
		ProviderNetworkRevision: 4, ProviderSharingRevision: 3,
		ConsumerNetworkRevision: 4, ConsumerSharingRevision: 3,
		ImportedResourceVersion: version, HasOffer: true, HasContract: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture, contract, result
}

func managementSharingScope(t *testing.T, workspaceValue, networkValue string) network.Scope {
	t.Helper()
	workspaceID, _ := workspace.ParseID(workspaceValue)
	networkID, _ := network.ParseID(networkValue)
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func sharingOfferCollectionPath() string {
	return "/api/v1/workspaces/" + managementWorkspaceID() + "/networks/" +
		managementNetworkID() + "/share-offers"
}

func decodeManagementErrorCode(t *testing.T, payload []byte) string {
	t.Helper()
	var envelope managementErrorResponse
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatalf("decode management error: %v", err)
	}
	return envelope.Error.Code
}

func TestManagementHandlerReadsCurrentConsumerContract(t *testing.T) {
	t.Parallel()
	fixture, contract, _ := managementSharingContractFixture(t, sharing.ContractStateActivating, 1)
	displayName, err := resource.ParseDisplayName("database")
	if err != nil {
		t.Fatal(err)
	}
	accessName, err := sharing.ParseAccessName("database.shared.consumer.example")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := sharing.NewContractSnapshot(sharing.ContractSnapshotParams{
		Contract: contract, ImportedDisplayName: displayName, ImportedResourceVersion: 1, AccessName: accessName,
	})
	if err != nil {
		t.Fatal(err)
	}
	options := validManagementHandlerOptions(t)
	options.ResourceSharing = &managementResourceSharingStub{
		getContract: func(_ context.Context, session accountsession.Session, scope network.Scope, id sharing.ContractID) (sharing.ContractSnapshot, error) {
			if !session.IsValid() || scope != fixture.consumer || id != contract.ID() {
				t.Fatal("GET lost exact consumer or authenticated session")
			}
			return snapshot, nil
		},
	}
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/workspaces/" + fixture.consumer.WorkspaceID().String() +
		"/networks/" + fixture.consumer.NetworkID().String() + "/trust-contracts/" + contract.ID().String()
	newReadRequest := func(method, requestPath, body string) *http.Request {
		request := newManagementRequest(t, method, requestPath, body)
		if body == "" {
			request.Body = http.NoBody
		}
		request.Header.Del("Content-Type")
		request.Header.Del("If-Match")
		request.Header.Del("Idempotency-Key")
		return request
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, newReadRequest(http.MethodGet, path, ""))
	var envelope shareContractDetailEnvelope
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"1"` || json.Unmarshal(response.Body.Bytes(), &envelope) != nil {
		t.Fatalf("Contract GET status/header/body = %d/%s/%s", response.Code, response.Header().Get("ETag"), response.Body.String())
	}
	data := envelope.Data
	if data.TrustContractID != contract.ID().String() || data.ImportedResourceID != contract.ImportedResourceID().String() ||
		data.State != "activating" || data.Version != 1 || data.ImportedResourceVersion != 1 || data.AccessName != accessName.String() ||
		data.ImportedDisplayName != displayName.String() || data.ConsumerWorkspaceID != fixture.consumer.WorkspaceID().String() ||
		data.ConsumerNetworkID != fixture.consumer.NetworkID().String() || data.ProviderWorkspaceID != fixture.provider.WorkspaceID().String() ||
		data.ResourceID != fixture.binding.ResourceID().String() || data.ResourceVersion != fixture.binding.ResourceVersion() ||
		data.ScopeRelation != "cross_workspace" || len(data.MaximumTraffic) != 1 || !data.ExpiresAt.Equal(contract.ExpiresAt()) ||
		strings.Contains(response.Body.String(), "offer_token") {
		t.Fatal("Contract GET lost current scope/provenance or exposed a token")
	}
	for _, test := range []struct{ name, method, suffix, body, header string }{
		{name: "query", method: http.MethodGet, suffix: "?state=active"},
		{name: "body", method: http.MethodGet, body: "{}"},
		{name: "mutation precondition", method: http.MethodGet, header: "If-Match"},
		{name: "idempotency", method: http.MethodGet, header: "Idempotency-Key"},
		{name: "wrong method", method: http.MethodPost},
	} {
		request := newReadRequest(test.method, path+test.suffix, test.body)
		if test.header != "" {
			request.Header.Set(test.header, "1")
		}
		denied := httptest.NewRecorder()
		handler.ServeHTTP(denied, request)
		if denied.Code == http.StatusOK {
			t.Fatal("contract read admitted", test.name)
		}
	}
}

func (stub *managementResourceSharingStub) GetContract(ctx context.Context, session accountsession.Session, scope network.Scope, id sharing.ContractID) (sharing.ContractSnapshot, error) {
	if stub.getContract == nil {
		return sharing.ContractSnapshot{}, sharing.ErrUnavailable
	}
	return stub.getContract(ctx, session, scope, id)
}
