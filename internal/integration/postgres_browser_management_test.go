//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/tls"
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
