package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/accessgraph/simulation"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	approval "meshtransit.net/core/internal/domain/policy/approval"
	"meshtransit.net/core/internal/domain/policy/publication"
)

func TestManagementHandlerRequestsPolicyApproval(t *testing.T) {
	t.Parallel()

	binding := managementPolicyApprovalBinding(t)
	now := time.Date(2026, 9, 29, 1, 0, 0, 0, time.UTC)
	requestID, _ := approval.ParseRequestID("01890f00-0000-7000-8000-000000000901")
	var captured approval.RequestIntent
	workflow := &managementPolicyApprovalWorkflow{
		request: func(_ context.Context, intent approval.RequestIntent) (approval.RequestResult, error) {
			captured = intent
			return approval.NewRequestResult(approval.RequestResultParams{
				RequestID: requestID, Binding: binding,
				ProposerPrincipalID: intent.AccountSession().PrincipalID(),
				ProposerSessionID:   intent.AccountSession().ID(), RequestVersion: 1,
				CreatedAt: now, ExpiresAt: now.Add(approval.RequestLifetime),
			})
		},
	}
	options := validManagementHandlerOptions(t)
	options.PolicyApprovals = workflow
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	candidate := binding.CandidateSemanticHash().Bytes()
	impact := binding.ImpactHash().Bytes()
	request := newManagementRequest(
		t,
		http.MethodPost,
		managementPolicyApprovalCollectionPath(),
		`{"rules":[],"candidate_semantic_hash":"`+hex.EncodeToString(candidate[:])+`",`+
			`"impact_hash":"`+hex.EncodeToString(impact[:])+`","reason":"reviewed simulation"}`,
	)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated || response.Header().Get("ETag") != `"1"` ||
		response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("Location") != managementPolicyApprovalCollectionPath()+"/"+requestID.String() {
		t.Fatalf("status/headers = %d/%+v; body = %s", response.Code, response.Header(), response.Body.String())
	}
	if !captured.IsValid() || captured.CompilationRequest().Revision() != 2 ||
		captured.CandidateSemanticHash() != binding.CandidateSemanticHash() ||
		captured.ImpactHash() != binding.ImpactHash() || captured.AuditReason().String() != "reviewed simulation" {
		t.Fatalf("captured intent = %+v", captured)
	}
	var body policyApprovalRequestEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil ||
		body.Data.RequestID != requestID.String() || body.Data.State != "pending" ||
		body.Data.Binding.ImpactHash != hex.EncodeToString(impact[:]) {
		t.Fatalf("response = (%+v, %v)", body, err)
	}
}

func TestManagementHandlerApprovesPolicyAsIndependentHuman(t *testing.T) {
	t.Parallel()

	binding := managementPolicyApprovalBinding(t)
	now := time.Date(2026, 9, 29, 1, 1, 0, 0, time.UTC)
	requestID, _ := approval.ParseRequestID("01890f00-0000-7000-8000-000000000901")
	evidenceID, _ := approval.ParseEvidenceID("01890f00-0000-7000-8000-000000000902")
	proposerPrincipal, _ := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000402")
	proposerSession, _ := accountsession.ParseID("01890f00-0000-7000-8000-000000000812")
	var captured approval.Command
	workflow := &managementPolicyApprovalWorkflow{
		approve: func(_ context.Context, command approval.Command) (approval.Result, error) {
			captured = command
			return approval.NewResult(approval.ResultParams{
				EvidenceID: evidenceID, RequestID: requestID, Binding: binding,
				ProposerPrincipalID: proposerPrincipal, ProposerSessionID: proposerSession,
				ApproverPrincipalID: command.AccountSession().PrincipalID(),
				ApproverSessionID:   command.AccountSession().ID(), RequestVersion: 2,
				EvidenceVersion: 1, ApprovedAt: now, ExpiresAt: now.Add(9 * time.Minute),
			})
		},
	}
	options := validManagementHandlerOptions(t)
	options.PolicyApprovals = workflow
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	candidate := binding.CandidateSemanticHash().Bytes()
	impact := binding.ImpactHash().Bytes()
	request := newManagementRequest(
		t,
		http.MethodPost,
		managementPolicyApprovalCollectionPath()+"/"+requestID.String()+"/actions/approve",
		`{"candidate_semantic_hash":"`+hex.EncodeToString(candidate[:])+`",`+
			`"impact_hash":"`+hex.EncodeToString(impact[:])+`","reason":"independent review"}`,
	)
	request.Header.Set("If-Match", `"1"`)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"2"` ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status/headers = %d/%+v; body = %s", response.Code, response.Header(), response.Body.String())
	}
	if !captured.IsValid() || captured.RequestID() != requestID || captured.ExpectedRequestVersion() != 1 ||
		captured.AuditReason().String() != "independent review" {
		t.Fatalf("captured command = %+v", captured)
	}
	var body policyApprovalDecisionEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil ||
		body.Data.EvidenceID != evidenceID.String() || body.Data.State != "approved" {
		t.Fatalf("response = (%+v, %v)", body, err)
	}
}

func TestManagementHandlerReadsPolicyApprovalCatalog(t *testing.T) {
	t.Parallel()

	snapshot := managementPolicyApprovalSnapshot(t, approval.StatePending)
	catalog := &managementPolicyApprovalCatalog{
		get: func(_ context.Context, _ accountsession.Session, _ network.Scope, id approval.RequestID) (approval.Snapshot, error) {
			if id != snapshot.RequestID() {
				return approval.Snapshot{}, approval.ErrRequestNotFound
			}
			return snapshot, nil
		},
		list: func(_ context.Context, _ accountsession.Session, _ network.Scope, state approval.State, limit int, _ approval.RequestID) (approval.CatalogPage, error) {
			if state != approval.StatePending || limit != 1 {
				return approval.CatalogPage{}, approval.ErrInvalidCatalogRequest
			}
			return approval.CatalogPage{Items: []approval.Snapshot{snapshot}, Next: snapshot.RequestID()}, nil
		},
	}
	options := validManagementHandlerOptions(t)
	options.PolicyApprovalCatalog = catalog
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}

	getRequest := newManagementRequest(
		t,
		http.MethodGet,
		managementPolicyApprovalCollectionPath()+"/"+snapshot.RequestID().String(),
		"",
	)
	getRequest.Body = http.NoBody
	getRequest.ContentLength = 0
	getRequest.Header.Del("Content-Type")
	getRequest.Header.Del("Idempotency-Key")
	getRequest.Header.Del("If-Match")
	getResponse := httptest.NewRecorder()
	handler.ServeHTTP(getResponse, getRequest)
	if getResponse.Code != http.StatusOK || getResponse.Header().Get("ETag") != `"1"` ||
		getResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("get status/headers = %d/%+v; body = %s", getResponse.Code, getResponse.Header(), getResponse.Body.String())
	}

	listRequest := newManagementRequest(
		t,
		http.MethodGet,
		managementPolicyApprovalCollectionPath()+"?state=pending&page_size=1",
		"",
	)
	listRequest.Body = http.NoBody
	listRequest.ContentLength = 0
	listRequest.Header.Del("Content-Type")
	listRequest.Header.Del("Idempotency-Key")
	listRequest.Header.Del("If-Match")
	listResponse := httptest.NewRecorder()
	handler.ServeHTTP(listResponse, listRequest)
	if listResponse.Code != http.StatusOK || listResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("list status/headers = %d/%+v; body = %s", listResponse.Code, listResponse.Header(), listResponse.Body.String())
	}
	var body policyApprovalListEnvelope
	if err := json.Unmarshal(listResponse.Body.Bytes(), &body); err != nil ||
		len(body.Data) != 1 || body.Data[0].RequestID != snapshot.RequestID().String() ||
		body.NextPageToken == "" {
		t.Fatalf("list response = (%+v, %v)", body, err)
	}
}

func TestManagementHandlerPolicyApprovalFailsClosed(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{name: "forbidden", err: approval.ErrForbidden, status: http.StatusForbidden, code: "forbidden"},
		{name: "self approval", err: approval.ErrIndependentApproverRequired, status: http.StatusConflict, code: "approval_conflict"},
		{name: "changed impact", err: approval.ErrImpactChanged, status: http.StatusConflict, code: "approval_conflict"},
		{name: "unavailable", err: approval.ErrOperationFailed, status: http.StatusServiceUnavailable, code: "operation_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			binding := managementPolicyApprovalBinding(t)
			options := validManagementHandlerOptions(t)
			options.PolicyApprovals = &managementPolicyApprovalWorkflow{
				request: func(context.Context, approval.RequestIntent) (approval.RequestResult, error) {
					return approval.RequestResult{}, test.err
				},
			}
			handler, err := NewManagementHandler(options)
			if err != nil {
				t.Fatal(err)
			}
			candidate := binding.CandidateSemanticHash().Bytes()
			impact := binding.ImpactHash().Bytes()
			request := newManagementRequest(
				t,
				http.MethodPost,
				managementPolicyApprovalCollectionPath(),
				`{"rules":[],"candidate_semantic_hash":"`+hex.EncodeToString(candidate[:])+`",`+
					`"impact_hash":"`+hex.EncodeToString(impact[:])+`","reason":"reviewed"}`,
			)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			var body managementErrorResponse
			if err := json.Unmarshal(response.Body.Bytes(), &body); response.Code != test.status ||
				err != nil || body.Error.Code != test.code {
				t.Fatalf("response = %d/%+v/%v; want %d/%s", response.Code, body, err, test.status, test.code)
			}
		})
	}
}

type managementPolicyApprovalWorkflow struct {
	request func(context.Context, approval.RequestIntent) (approval.RequestResult, error)
	approve func(context.Context, approval.Command) (approval.Result, error)
}

func (workflow *managementPolicyApprovalWorkflow) Request(
	ctx context.Context,
	intent approval.RequestIntent,
) (approval.RequestResult, error) {
	if workflow == nil || workflow.request == nil {
		return approval.RequestResult{}, approval.ErrOperationFailed
	}
	return workflow.request(ctx, intent)
}

func (workflow *managementPolicyApprovalWorkflow) Approve(
	ctx context.Context,
	command approval.Command,
) (approval.Result, error) {
	if workflow == nil || workflow.approve == nil {
		return approval.Result{}, approval.ErrOperationFailed
	}
	return workflow.approve(ctx, command)
}

type managementPolicyApprovalCatalog struct {
	get  func(context.Context, accountsession.Session, network.Scope, approval.RequestID) (approval.Snapshot, error)
	list func(context.Context, accountsession.Session, network.Scope, approval.State, int, approval.RequestID) (approval.CatalogPage, error)
}

func (catalog *managementPolicyApprovalCatalog) Get(
	ctx context.Context,
	session accountsession.Session,
	scope network.Scope,
	id approval.RequestID,
) (approval.Snapshot, error) {
	return catalog.get(ctx, session, scope, id)
}

func (catalog *managementPolicyApprovalCatalog) List(
	ctx context.Context,
	session accountsession.Session,
	scope network.Scope,
	state approval.State,
	limit int,
	after approval.RequestID,
) (approval.CatalogPage, error) {
	return catalog.list(ctx, session, scope, state, limit, after)
}

func managementPolicyApprovalCollectionPath() string {
	return "/api/v1/workspaces/" + managementWorkspaceID() + "/networks/" +
		managementNetworkID() + "/policy/approval-requests"
}

func managementPolicyApprovalBinding(t *testing.T) approval.Binding {
	t.Helper()
	scope := managementPolicySimulationScope(t)
	baseline, err := accessgraph.NewRevisionVector(accessgraph.RevisionVectorParams{
		NetworkRevision: 1, InventoryRevision: 1, GroupRevision: 1, PolicyRevision: 1,
		DNSRevision: 1, RouteRevision: 1, SharingRevision: 1, IsolationGeneration: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	proposed, err := baseline.NextPolicy()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := publication.NewSemanticHash(sha256.Sum256([]byte("approval candidate")))
	if err != nil {
		t.Fatal(err)
	}
	impact, err := simulation.NewImpactHash(sha256.Sum256([]byte("approval impact")))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := approval.NewBinding(approval.BindingParams{
		Scope: scope, BaselineVector: baseline, ProposedVector: proposed,
		CandidateSemanticHash: candidate, CompilerFormatVersion: 1, ImpactHash: impact,
	})
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func managementPolicyApprovalSnapshot(t *testing.T, state approval.State) approval.Snapshot {
	t.Helper()
	if state != approval.StatePending {
		t.Fatal(errors.New("fixture currently supports pending state only"))
	}
	requestID, _ := approval.ParseRequestID("01890f00-0000-7000-8000-000000000901")
	proposer, _ := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000402")
	reason, _ := approval.NewAuditReason("reviewed simulation")
	now := time.Date(2026, 9, 29, 1, 0, 0, 0, time.UTC)
	value, err := approval.NewSnapshot(approval.SnapshotParams{
		RequestID: requestID, Binding: managementPolicyApprovalBinding(t),
		ProposerPrincipalID: proposer, ProposalReason: reason, State: state,
		RequestVersion: 1, CreatedAt: now, ExpiresAt: now.Add(approval.RequestLifetime),
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}
