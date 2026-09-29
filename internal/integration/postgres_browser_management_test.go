//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/accessgraph"
	"github.com/meshtransit/meshtransit/internal/accessgraph/simulation"
	"github.com/meshtransit/meshtransit/internal/adapter/httpapi"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/identity/sessioncontext"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/policy/approval"
	"github.com/meshtransit/meshtransit/internal/policy/compilation"
	publication "github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/ratelimit"
	"github.com/meshtransit/meshtransit/internal/resource/catalog"
)

// This source fixture uses real least-privileged Session and mutation authority.
// Synthetic completed TLS/deadlines and controlled budgets are not live HTTPS,
// Redis, browser, external broker, root-dispatch or native-host clock qualification.
func prepareIntegrationBrowserManagement(
	ctx context.Context,
	t *testing.T,
	handler *httpapi.ManagementHandler,
	rawToken string,
) (*httpapi.BrowserManagement, string) {
	t.Helper()
	token, err := accountsession.ParseToken(rawToken)
	if err != nil {
		t.Fatal(err)
	}
	browser, err := httpapi.NewBrowserManagement(httpapi.BrowserManagementOptions{Management: handler,
		Logout: integrationAccountSessionLogoutFunc(func(context.Context, accountsession.Token) (bool, error) {
			return false, nil
		}),
		Scopes:       integrationManagementScopes{},
		DeploymentID: token.DeploymentID(), Origin: "https://console.example.test", Clock: accountsession.SystemClock{},
		Key:           httpapi.BrowserLoginKey{ID: "integration-session-csrf-v1", Material: bytes.Repeat([]byte{0x74}, 32)},
		ProofLifetime: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	request := integrationBrowserManagementRequest(
		ctx,
		rawToken,
		httpapi.AccountSessionCSRFPreparePath,
		"{}",
	)
	response := &integrationCompletionWriter{ResponseRecorder: httptest.NewRecorder()}
	if err := browser.Handle(response, request); err != nil {
		t.Fatal("private proof preparation failed", err)
	}
	var payload struct {
		Token     string    `json:"csrf_token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal("decode private proof", err)
	}
	invalidStatus := response.Code != http.StatusOK || response.statusWrites != 1
	invalidProof := payload.Token == "" || !time.Now().Before(payload.ExpiresAt)
	unexpectedNavigation := response.Header().Get("Set-Cookie") != "" || response.Header().Get("Location") != ""
	if invalidStatus || invalidProof || unexpectedNavigation {
		t.Fatal("prepare changed cookie/authority/navigation")
	}
	return browser, payload.Token
}

type integrationManagementScopes struct{}

func (integrationManagementScopes) List(
	context.Context,
	accountsession.Session,
	int,
	network.ID,
) (sessioncontext.Page, error) {
	return sessioncontext.Page{}, sessioncontext.ErrUnavailable
}

type integrationAccountSessionLogoutFunc func(context.Context, accountsession.Token) (bool, error)

func (function integrationAccountSessionLogoutFunc) Logout(
	ctx context.Context,
	token accountsession.Token,
) (bool, error) {
	return function(ctx, token)
}

func integrationBrowserManagementRequest(
	ctx context.Context,
	rawToken string,
	path string,
	body string,
) *http.Request {
	request := httptest.NewRequestWithContext(
		ctx,
		http.MethodPost,
		path,
		bytes.NewBufferString(body),
	)
	request.Host, request.RemoteAddr = "console.example.test", "192.0.2.10:12345"
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	request.Header.Set("Origin", "https://console.example.test")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-MeshTransit-Session", "v1")
	request.Header.Set("Cookie", httpapi.AccountSessionCookieName+"="+rawToken)
	return request
}

type integrationBrowserPolicyCapture struct {
	service *publication.Service
	result  publication.Result
	calls   int
}

type integrationBrowserApprovalCapture struct {
	service       *approval.Service
	requested     approval.RequestResult
	approved      approval.Result
	requestCalls  int
	approvalCalls int
}

func (capture *integrationBrowserApprovalCapture) Request(
	ctx context.Context,
	intent approval.RequestIntent,
) (approval.RequestResult, error) {
	capture.requestCalls++
	result, err := capture.service.Request(ctx, intent)
	capture.requested = result
	return result, err
}

func (capture *integrationBrowserApprovalCapture) Approve(
	ctx context.Context,
	command approval.Command,
) (approval.Result, error) {
	capture.approvalCalls++
	result, err := capture.service.Approve(ctx, command)
	capture.approved = result
	return result, err
}

func approveEmptyPolicyOverBrowserManagement(
	ctx context.Context,
	t *testing.T,
	runtimePool *postgresadapter.Pool,
	request compilation.Request,
) approval.Result {
	t.Helper()
	if len(request.Rules()) != 0 {
		t.Fatal("browser approval integration helper requires an empty policy")
	}
	proposer := managementRBACAccountSessionFixture(t)
	simulated, err := newIntegrationPolicySimulator(t, runtimePool).Simulate(ctx, proposer, request)
	if err != nil {
		t.Fatalf("simulate browser Policy approval candidate: %v", err)
	}
	service, catalog := newIntegrationPolicyApprovalWorkflow(t, runtimePool)
	capture := &integrationBrowserApprovalCapture{service: service}
	store, err := postgresadapter.NewAccountSessionStore(
		runtimePool,
		postgresadapter.AccountSessionOptions{
			StatementTimeout: 5 * time.Second,
			IdleTimeout:      10 * time.Second,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	keyring, _, proposerToken := integrationManagementAccountSessionSecurity(t)
	sessions, err := accountsession.NewService(keyring, store, accountsession.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := ratelimit.NewDigestKeyID("integration-v1")
	if err != nil {
		t.Fatal(err)
	}
	digester, err := ratelimit.NewDigester(keyID, bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ratePolicy, err := ratelimit.NewPolicy(100, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := httpapi.NewManagementHandler(httpapi.ManagementHandlerOptions{
		Sessions: sessions, Revocations: newIntegrationDeviceRevocationService(t, runtimePool),
		PolicyPublications: newIntegrationManagementPolicyPublicationService(t, runtimePool),
		PolicyCompilations: newIntegrationPolicyCompiler(t, runtimePool),
		PolicyExplanations: newIntegrationPolicyExplainer(t, runtimePool),
		PolicySimulations:  newIntegrationPolicySimulator(t, runtimePool),
		PolicyApprovals:    capture, PolicyApprovalCatalog: catalog,
		Idempotency: integrationDeviceRevocationDigester(t), RateLimitSubjects: digester,
		RateLimiter: integrationAllowAllRateLimiter{}, SourceRateLimit: ratePolicy,
		SessionRateLimit: ratePolicy, CorrelationIDs: httpapi.PublicCorrelationIDGenerator{},
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), RequestTimeout: 10 * time.Second,
		MaxConcurrentRequests: 2,
	})
	if err != nil {
		t.Fatal(err)
	}

	proposerBrowser, proposerProof := prepareIntegrationBrowserManagement(
		ctx, t, handler, proposerToken,
	)
	scope := request.Scope()
	collectionPath := fmt.Sprintf(
		"/api/v1/workspaces/%s/networks/%s/policy/approval-requests",
		scope.WorkspaceID().String(),
		scope.NetworkID().String(),
	)
	candidateHash := simulated.ProposedCandidate().SemanticHash().Bytes()
	impactHash := simulated.ImpactHash().Bytes()
	requestBody, err := json.Marshal(struct {
		Rules                 []struct{} `json:"rules"`
		CandidateSemanticHash string     `json:"candidate_semantic_hash"`
		ImpactHash            string     `json:"impact_hash"`
		Reason                string     `json:"reason"`
	}{
		Rules: make([]struct{}, 0), CandidateSemanticHash: hex.EncodeToString(candidateHash[:]),
		ImpactHash: hex.EncodeToString(impactHash[:]), Reason: "request browser integration approval",
	})
	if err != nil {
		t.Fatal(err)
	}
	proposalRequest := integrationBrowserManagementRequest(
		ctx, proposerToken, collectionPath, string(requestBody),
	)
	proposalRequest.Header.Set("X-MeshTransit-CSRF", proposerProof)
	proposalRequest.Header.Set("If-Match", fmt.Sprintf(`"%d"`, request.Revision()-1))
	proposalRequest.Header.Set("Idempotency-Key", "integration-policy-approval-request")
	proposalResponse := &integrationCompletionWriter{ResponseRecorder: httptest.NewRecorder()}
	if err := proposerBrowser.Handle(proposalResponse, proposalRequest); err != nil {
		t.Fatalf("request Policy approval over private browser: %v", err)
	}
	if proposalResponse.Code != http.StatusCreated || proposalResponse.statusWrites != 1 ||
		capture.requestCalls != 1 || !capture.requested.IsValid() ||
		proposalResponse.Header().Get("ETag") != `"1"` ||
		proposalResponse.Header().Get("Location") != "" {
		t.Fatalf(
			"browser Policy proposal response=%d writes=%d calls=%d valid=%t body=%s",
			proposalResponse.Code,
			proposalResponse.statusWrites,
			capture.requestCalls,
			capture.requested.IsValid(),
			proposalResponse.Body.String(),
		)
	}

	_, _, approverToken := integrationAuthorityConfirmerAccountSessionSecurity(t)
	newReadRequest := func(path string) *http.Request {
		read := httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil)
		read.Host, read.RemoteAddr = "console.example.test", "192.0.2.10:12345"
		read.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
		read.Header.Set("Authorization", "Bearer "+approverToken)
		return read
	}
	listResponse := httptest.NewRecorder()
	handler.ServeHTTP(
		listResponse,
		newReadRequest(collectionPath+"?state=pending&page_size=1"),
	)
	var listed struct {
		Data []struct {
			RequestID string `json:"request_id"`
			State     string `json:"state"`
		} `json:"data"`
	}
	if err := json.Unmarshal(listResponse.Body.Bytes(), &listed); err != nil ||
		listResponse.Code != http.StatusOK || len(listed.Data) != 1 ||
		listed.Data[0].RequestID != capture.requested.RequestID().String() ||
		listed.Data[0].State != "pending" || bytes.Contains(listResponse.Body.Bytes(), []byte("session_id")) {
		_, catalogErr := catalog.List(
			ctx,
			authorityConfirmerAccountSessionFixture(t),
			scope,
			approval.StatePending,
			1,
			approval.RequestID{},
		)
		t.Fatalf(
			"list pending Policy approvals = %d/%+v/%v/%s; catalog error=%v",
			listResponse.Code,
			listed,
			err,
			listResponse.Body.String(),
			catalogErr,
		)
	}

	itemPath := collectionPath + "/" + capture.requested.RequestID().String()
	getResponse := httptest.NewRecorder()
	handler.ServeHTTP(getResponse, newReadRequest(itemPath))
	var fetched struct {
		Data struct {
			RequestID string `json:"request_id"`
			State     string `json:"state"`
		} `json:"data"`
	}
	if err := json.Unmarshal(getResponse.Body.Bytes(), &fetched); err != nil ||
		getResponse.Code != http.StatusOK || fetched.Data.RequestID != capture.requested.RequestID().String() ||
		fetched.Data.State != "pending" || bytes.Contains(getResponse.Body.Bytes(), []byte("session_id")) {
		t.Fatalf("get pending Policy approval = %d/%+v/%v/%s", getResponse.Code, fetched, err, getResponse.Body.String())
	}

	approverBrowser, approverProof := prepareIntegrationBrowserManagement(ctx, t, handler, approverToken)
	approvalBody, err := json.Marshal(struct {
		CandidateSemanticHash string `json:"candidate_semantic_hash"`
		ImpactHash            string `json:"impact_hash"`
		Reason                string `json:"reason"`
	}{
		CandidateSemanticHash: hex.EncodeToString(candidateHash[:]),
		ImpactHash:            hex.EncodeToString(impactHash[:]), Reason: "independent browser integration review",
	})
	if err != nil {
		t.Fatal(err)
	}
	approvalRequest := integrationBrowserManagementRequest(
		ctx, approverToken, itemPath+"/actions/approve", string(approvalBody),
	)
	approvalRequest.Header.Set("X-MeshTransit-CSRF", approverProof)
	approvalRequest.Header.Set("If-Match", `"1"`)
	approvalRequest.Header.Set("Idempotency-Key", "integration-policy-approval-decision")
	approvalResponse := &integrationCompletionWriter{ResponseRecorder: httptest.NewRecorder()}
	if err := approverBrowser.Handle(approvalResponse, approvalRequest); err != nil {
		t.Fatalf("approve Policy over private browser: %v", err)
	}
	if approvalResponse.Code != http.StatusOK || approvalResponse.statusWrites != 1 ||
		capture.approvalCalls != 1 || !capture.approved.IsValid() ||
		capture.approved.RequestID() != capture.requested.RequestID() ||
		approvalResponse.Header().Get("ETag") != `"2"` {
		t.Fatalf(
			"browser Policy approval response=%d writes=%d calls=%d valid=%t body=%s",
			approvalResponse.Code,
			approvalResponse.statusWrites,
			capture.approvalCalls,
			capture.approved.IsValid(),
			approvalResponse.Body.String(),
		)
	}

	approvedResponse := httptest.NewRecorder()
	handler.ServeHTTP(approvedResponse, newReadRequest(itemPath))
	if err := json.Unmarshal(approvedResponse.Body.Bytes(), &fetched); err != nil ||
		approvedResponse.Code != http.StatusOK || fetched.Data.State != "approved" ||
		!bytes.Contains(approvedResponse.Body.Bytes(), []byte(integrationAuthorityConfirmerID)) ||
		bytes.Contains(approvedResponse.Body.Bytes(), []byte("session_id")) {
		t.Fatalf("get approved Policy approval = %d/%+v/%v/%s", approvedResponse.Code, fetched, err, approvedResponse.Body.String())
	}
	return capture.approved
}

func (capture *integrationBrowserPolicyCapture) Publish(
	ctx context.Context,
	command publication.Command,
) (publication.Result, error) {
	capture.calls++
	result, err := capture.service.Publish(ctx, command)
	capture.result = result
	return result, err
}

func publishPolicyOverBrowserManagement(
	ctx context.Context,
	t *testing.T,
	runtimePool *postgresadapter.Pool,
	service *publication.Service,
	command publication.Command,
) publication.Result {
	t.Helper()
	store, err := postgresadapter.NewAccountSessionStore(runtimePool, postgresadapter.AccountSessionOptions{
		StatementTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	keyring, _, rawToken := integrationManagementAccountSessionSecurity(t)
	sessions, err := accountsession.NewService(keyring, store, accountsession.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := ratelimit.NewDigestKeyID("integration-v1")
	if err != nil {
		t.Fatal(err)
	}
	digester, err := ratelimit.NewDigester(keyID, bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ratelimit.NewPolicy(100, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	capture := &integrationBrowserPolicyCapture{service: service}
	handler, err := httpapi.NewManagementHandler(httpapi.ManagementHandlerOptions{Sessions: sessions,
		Revocations: newIntegrationDeviceRevocationService(t, runtimePool), PolicyPublications: capture,
		PolicyCompilations: newIntegrationPolicyCompiler(t, runtimePool),
		PolicyExplanations: newIntegrationPolicyExplainer(t, runtimePool),
		PolicySimulations:  newIntegrationPolicySimulator(t, runtimePool),
		Idempotency:        integrationDeviceRevocationDigester(t), RateLimitSubjects: digester,
		RateLimiter:     integrationAllowAllRateLimiter{},
		SourceRateLimit: policy, SessionRateLimit: policy, CorrelationIDs: httpapi.PublicCorrelationIDGenerator{},
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), RequestTimeout: 10 * time.Second, MaxConcurrentRequests: 2})
	if err != nil {
		t.Fatal(err)
	}
	browser, proof := prepareIntegrationBrowserManagement(
		ctx,
		t,
		handler,
		rawToken,
	)
	scope := command.Candidate().Snapshot().Scope()
	path := fmt.Sprintf("/api/v1/workspaces/%s/networks/%s/policy/actions/publish",
		scope.WorkspaceID().String(), scope.NetworkID().String())
	type portRange struct {
		First uint16 `json:"first"`
		Last  uint16 `json:"last"`
	}
	type rule struct {
		ID                    string      `json:"id"`
		SourceDeviceID        string      `json:"source_device_id"`
		DestinationDeviceID   string      `json:"destination_device_id,omitempty"`
		DestinationResourceID string      `json:"destination_resource_id,omitempty"`
		DestinationGroupID    string      `json:"destination_resource_group_id,omitempty"`
		Protocol              string      `json:"protocol"`
		DestinationPortRanges []portRange `json:"destination_port_ranges"`
	}
	resourceDestinations := make(map[string]publication.ResourceDestination)
	for _, destination := range command.Candidate().ResourceDestinations() {
		resourceDestinations[destination.RuleID().String()] = destination
	}
	groupDestinations := make(map[string]publication.ResourceGroupDestination)
	for _, destination := range command.Candidate().ResourceGroupDestinations() {
		groupDestinations[destination.RuleID().String()] = destination
	}
	emittedGroups := make(map[string]struct{}, len(groupDestinations))
	rules := make([]rule, 0, len(command.Candidate().Snapshot().Rules()))
	for _, compiled := range command.Candidate().Snapshot().Rules() {
		if _, emitted := emittedGroups[compiled.ID().String()]; emitted {
			continue
		}
		ranges := compiled.DestinationPortRanges()
		ports := make([]portRange, len(ranges))
		for index, value := range ranges {
			ports[index] = portRange{First: value.First(), Last: value.Last()}
		}
		input := rule{
			ID:                    compiled.ID().String(),
			SourceDeviceID:        compiled.SourceNodeID().String(),
			DestinationDeviceID:   compiled.DestinationNodeID().String(),
			Protocol:              compiled.Protocol().String(),
			DestinationPortRanges: ports,
		}
		if destination, ok := resourceDestinations[compiled.ID().String()]; ok {
			input.DestinationDeviceID = ""
			input.DestinationResourceID = destination.Reference().ResourceID().String()
		} else if destination, ok := groupDestinations[compiled.ID().String()]; ok {
			input.DestinationDeviceID = ""
			input.DestinationGroupID = destination.ResourceGroupID().String()
			emittedGroups[compiled.ID().String()] = struct{}{}
		}
		rules = append(rules, input)
	}
	body, err := json.Marshal(struct {
		Rules              []rule `json:"rules"`
		Reason             string `json:"reason"`
		ApprovalEvidenceID string `json:"approval_evidence_id"`
	}{
		Rules: rules, Reason: command.AuditReason().String(),
		ApprovalEvidenceID: command.ApprovalEvidenceID().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := integrationBrowserManagementRequest(
		ctx,
		rawToken,
		path,
		string(body),
	)
	request.Header.Set("X-MeshTransit-CSRF", proof)
	request.Header.Set("If-Match", fmt.Sprintf(`"%d"`, command.BasePolicyRevision()))
	response := &integrationCompletionWriter{ResponseRecorder: httptest.NewRecorder()}
	if err := browser.Handle(response, request); err != nil {
		t.Fatal("private cookie policy publication failed", err)
	}
	if response.Code != http.StatusOK || response.statusWrites != 1 || capture.calls != 1 || !capture.result.IsValid() ||
		response.Header().Get("Set-Cookie") != "" || request.Header.Get("Authorization") != "" {
		t.Fatalf(
			"cookie transport bypassed confirmed management policy authority: status=%d writes=%d calls=%d result_valid=%t body=%s",
			response.Code,
			response.statusWrites,
			capture.calls,
			capture.result.IsValid(),
			response.Body.String(),
		)
	}
	return capture.result
}

func newIntegrationPolicyCompiler(
	t *testing.T,
	runtimePool *postgresadapter.Pool,
) *compilation.Service {
	t.Helper()
	store, err := postgresadapter.NewResourceCatalogStore(
		runtimePool,
		postgresadapter.ResourceCatalogOptions{
			StatementTimeout: 5 * time.Second,
			LockTimeout:      2 * time.Second,
			IdleTimeout:      10 * time.Second,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	resources, err := catalog.NewService(catalog.Dependencies{
		Transactions: store,
		Clock:        catalog.SystemClock{},
	})
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := compilation.NewService(resources)
	if err != nil {
		t.Fatal(err)
	}
	return compiler
}

func newIntegrationPolicyExplainer(
	t *testing.T,
	runtimePool *postgresadapter.Pool,
) *accessgraph.Service {
	t.Helper()
	store, err := postgresadapter.NewAccessGraphStore(
		runtimePool,
		postgresadapter.AccessGraphOptions{
			StatementTimeout: 5 * time.Second,
			LockTimeout:      2 * time.Second,
			IdleTimeout:      10 * time.Second,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	service, err := accessgraph.NewService(accessgraph.Dependencies{
		Reader: store, Clock: accessgraph.SystemClock{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func newIntegrationPolicySimulator(
	t *testing.T,
	runtimePool *postgresadapter.Pool,
) *simulation.Service {
	t.Helper()
	store, err := postgresadapter.NewPolicySimulationStore(
		runtimePool,
		postgresadapter.PolicySimulationOptions{
			StatementTimeout: 5 * time.Second,
			LockTimeout:      2 * time.Second,
			IdleTimeout:      10 * time.Second,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	service, err := simulation.NewService(simulation.Dependencies{
		Baselines: store, Compiler: newIntegrationPolicyCompiler(t, runtimePool),
		Clock: simulation.SystemClock{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}
