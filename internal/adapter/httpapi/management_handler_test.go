package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/accessgraph"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/idempotency"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/node/revocation"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/policy/compilation"
	policypublication "github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/ratelimit"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

// #nosec G101 -- canonical token grammar fixture; it has no authority outside this test.
const managementTokenFixture = "mtas1.01890f00-0000-7000-8000-000000000001.7.AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"

func TestManagementHandlerRevokesDevice(t *testing.T) {
	t.Parallel()

	session := managementSessionFixture(t)
	var captured revocation.Command
	handler := managementHandlerFixture(t, managementHandlerFixtureOptions{
		session: session,
		revoke: func(_ context.Context, command revocation.Command) (revocation.Result, error) {
			captured = command
			return managementResultFixture(t, command), nil
		},
	})
	request := newManagementRequest(t, http.MethodPost, validManagementPath(), `{"reason":" compromised device "}`)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	if captured.Scope().WorkspaceID().String() != managementWorkspaceID() ||
		captured.Scope().NetworkID().String() != managementNetworkID() ||
		captured.NodeID().String() != managementDeviceID() || captured.ExpectedVersion() != 1 ||
		captured.AccountSession().ID() != session.ID() || captured.Reason().String() != "compromised device" ||
		!captured.IdempotencyEvidence().IsValid() {
		t.Fatalf("captured command = %+v, want exact authenticated request", captured)
	}
	if response.Header().Get("ETag") != `"2"` ||
		response.Header().Get("X-Correlation-ID") != managementCorrelationID() ||
		response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("X-Content-Type-Options") != "nosniff" ||
		response.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("response headers = %+v", response.Header())
	}
	var body struct {
		Data struct {
			DeviceID          string `json:"device_id"`
			State             string `json:"state"`
			DeviceVersion     int64  `json:"device_version"`
			SessionGeneration int64  `json:"session_generation"`
			NetworkRevision   int64  `json:"network_revision"`
			InventoryRevision int64  `json:"inventory_revision"`
		} `json:"data"`
		CorrelationID string `json:"correlation_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; body = %s", err, response.Body.String())
	}
	if body.Data.DeviceID != managementDeviceID() || body.Data.State != "revoked" ||
		body.Data.DeviceVersion != 2 || body.Data.SessionGeneration != 4 ||
		body.Data.NetworkRevision != 8 || body.Data.InventoryRevision != 6 ||
		body.CorrelationID != managementCorrelationID() {
		t.Fatalf("response body = %+v", body)
	}
}

func TestManagementHandlerFailsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		method           string
		path             string
		body             string
		mutate           func(*http.Request)
		authErr          error
		revokeErr        error
		status           int
		code             string
		retryable        bool
		wantAuthenticate bool
		wantRevoke       bool
	}{
		{name: "wrong method", method: http.MethodGet, path: validManagementPath(), status: http.StatusMethodNotAllowed, code: "method_not_allowed"},
		{name: "unknown route", method: http.MethodPost, path: "/api/v1/unknown", status: http.StatusNotFound, code: "not_found"},
		{name: "missing bearer", method: http.MethodPost, path: validManagementPath(), mutate: func(request *http.Request) { request.Header.Del("Authorization") }, status: http.StatusUnauthorized, code: "unauthenticated"},
		{name: "malformed bearer", method: http.MethodPost, path: validManagementPath(), mutate: func(request *http.Request) { request.Header.Set("Authorization", "Bearer invalid") }, status: http.StatusUnauthorized, code: "unauthenticated"},
		{name: "revoked session", method: http.MethodPost, path: validManagementPath(), authErr: accountsession.ErrUnauthenticated, status: http.StatusUnauthorized, code: "unauthenticated", wantAuthenticate: true},
		{name: "session authority unavailable", method: http.MethodPost, path: validManagementPath(), authErr: accountsession.ErrAuthenticationUnavailable, status: http.StatusServiceUnavailable, code: "authentication_unavailable", retryable: true, wantAuthenticate: true},
		{name: "missing precondition", method: http.MethodPost, path: validManagementPath(), mutate: func(request *http.Request) { request.Header.Del("If-Match") }, status: http.StatusPreconditionRequired, code: "precondition_required", wantAuthenticate: true},
		{name: "weak precondition", method: http.MethodPost, path: validManagementPath(), mutate: func(request *http.Request) { request.Header.Set("If-Match", `W/"1"`) }, status: http.StatusBadRequest, code: "invalid_request", wantAuthenticate: true},
		{name: "missing idempotency", method: http.MethodPost, path: validManagementPath(), mutate: func(request *http.Request) { request.Header.Del("Idempotency-Key") }, status: http.StatusBadRequest, code: "invalid_request", wantAuthenticate: true},
		{name: "duplicate content type", method: http.MethodPost, path: validManagementPath(), mutate: func(request *http.Request) { request.Header.Add("Content-Type", "application/json") }, status: http.StatusBadRequest, code: "invalid_request", wantAuthenticate: true},
		{name: "unknown json field", method: http.MethodPost, path: validManagementPath(), body: `{"reason":"compromised","unexpected":true}`, status: http.StatusBadRequest, code: "invalid_request", wantAuthenticate: true},
		{name: "forbidden", method: http.MethodPost, path: validManagementPath(), revokeErr: revocation.ErrForbidden, status: http.StatusForbidden, code: "forbidden", wantAuthenticate: true, wantRevoke: true},
		{name: "hidden target", method: http.MethodPost, path: validManagementPath(), revokeErr: revocation.ErrNotFound, status: http.StatusNotFound, code: "not_found", wantAuthenticate: true, wantRevoke: true},
		{name: "stale version", method: http.MethodPost, path: validManagementPath(), revokeErr: revocation.ErrConflict, status: http.StatusPreconditionFailed, code: "precondition_failed", wantAuthenticate: true, wantRevoke: true},
		{name: "idempotency conflict", method: http.MethodPost, path: validManagementPath(), revokeErr: revocation.ErrIntentConflict, status: http.StatusConflict, code: "idempotency_conflict", wantAuthenticate: true, wantRevoke: true},
		{name: "already revoked", method: http.MethodPost, path: validManagementPath(), revokeErr: revocation.ErrAlreadyRevoked, status: http.StatusConflict, code: "device_already_revoked", wantAuthenticate: true, wantRevoke: true},
		{name: "dependency unavailable", method: http.MethodPost, path: validManagementPath(), revokeErr: revocation.ErrRetryExhausted, status: http.StatusServiceUnavailable, code: "operation_unavailable", retryable: true, wantAuthenticate: true, wantRevoke: true},
		{name: "deadline", method: http.MethodPost, path: validManagementPath(), revokeErr: context.DeadlineExceeded, status: http.StatusGatewayTimeout, code: "request_timeout", retryable: true, wantAuthenticate: true, wantRevoke: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var authenticated, revoked bool
			handler := managementHandlerFixture(t, managementHandlerFixtureOptions{
				authenticate: func(context.Context, accountsession.Token) (accountsession.Session, error) {
					authenticated = true
					return managementSessionFixture(t), test.authErr
				},
				revoke: func(_ context.Context, command revocation.Command) (revocation.Result, error) {
					revoked = true
					if test.revokeErr != nil {
						return revocation.Result{}, errors.Join(revocation.ErrRevocationFailed, test.revokeErr, errors.New("private database detail"))
					}
					return managementResultFixture(t, command), nil
				},
			})
			body := test.body
			if body == "" {
				body = `{"reason":"compromised device"}`
			}
			request := newManagementRequest(t, test.method, test.path, body)
			if test.mutate != nil {
				test.mutate(request)
			}
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != test.status {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, test.status, response.Body.String())
			}
			var envelope struct {
				Error struct {
					Code          string `json:"code"`
					Message       string `json:"message"`
					CorrelationID string `json:"correlation_id"`
					Retryable     bool   `json:"retryable"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatalf("json.Unmarshal() error = %v; body = %s", err, response.Body.String())
			}
			if envelope.Error.Code != test.code || envelope.Error.CorrelationID != managementCorrelationID() ||
				envelope.Error.Retryable != test.retryable || envelope.Error.Message == "" {
				t.Fatalf("error envelope = %+v", envelope.Error)
			}
			if authenticated != test.wantAuthenticate || revoked != test.wantRevoke {
				t.Fatalf("authenticate/revoke = %t/%t, want %t/%t", authenticated, revoked, test.wantAuthenticate, test.wantRevoke)
			}
			for _, secret := range []string{managementTokenFixture, "request-key-0001", "private database detail"} {
				if strings.Contains(response.Body.String(), secret) {
					t.Fatalf("response disclosed %q: %s", secret, response.Body.String())
				}
			}
		})
	}
}

func TestManagementHandlerRateLimitsBeforeAuthorityMutation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		denyKind         ratelimit.SubjectKind
		limitErr         error
		status           int
		code             string
		wantAuthenticate bool
		wantCalls        int
		wantHeaders      bool
	}{
		{
			name: "source denied", denyKind: ratelimit.SubjectSource,
			status: http.StatusTooManyRequests, code: "rate_limited",
			wantCalls: 1, wantHeaders: true,
		},
		{
			name: "source limiter unavailable", limitErr: errors.New("redis unavailable"),
			status: http.StatusServiceUnavailable, code: "rate_limit_unavailable",
			wantCalls: 1,
		},
		{
			name: "session denied", denyKind: ratelimit.SubjectAccountSession,
			status: http.StatusTooManyRequests, code: "rate_limited",
			wantAuthenticate: true, wantCalls: 2, wantHeaders: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var authenticated, revoked bool
			calls := 0
			handler := managementHandlerFixture(t, managementHandlerFixtureOptions{
				authenticate: func(context.Context, accountsession.Token) (accountsession.Session, error) {
					authenticated = true
					return managementSessionFixture(t), nil
				},
				revoke: func(_ context.Context, command revocation.Command) (revocation.Result, error) {
					revoked = true
					return managementResultFixture(t, command), nil
				},
				limit: func(
					_ context.Context,
					subject ratelimit.Subject,
					policy ratelimit.Policy,
				) (ratelimit.Decision, error) {
					calls++
					if test.limitErr != nil {
						return ratelimit.Decision{}, test.limitErr
					}
					if subject.Kind() == test.denyKind {
						return ratelimit.NewDecision(false, policy.Capacity(), 0, 1500*time.Millisecond)
					}
					return ratelimit.NewDecision(true, policy.Capacity(), policy.Capacity()-1, 0)
				},
			})
			request := newManagementRequest(
				t,
				http.MethodPost,
				validManagementPath(),
				`{"reason":"compromised device"}`,
			)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != test.status {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, test.status, response.Body.String())
			}
			var envelope managementErrorResponse
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil ||
				envelope.Error.Code != test.code {
				t.Fatalf("error envelope = (%+v, %v)", envelope, err)
			}
			if authenticated != test.wantAuthenticate || revoked || calls != test.wantCalls {
				t.Fatalf(
					"authenticate/revoke/calls = %t/%t/%d, want %t/false/%d",
					authenticated,
					revoked,
					calls,
					test.wantAuthenticate,
					test.wantCalls,
				)
			}
			if test.wantHeaders {
				if response.Header().Get("RateLimit-Limit") != "5" ||
					response.Header().Get("RateLimit-Remaining") != "0" ||
					response.Header().Get("RateLimit-Reset") != "2" ||
					response.Header().Get("Retry-After") != "2" {
					t.Fatalf("rate limit headers = %+v", response.Header())
				}
			}
		})
	}
}

func TestNewManagementHandlerRejectsInvalidDependencies(t *testing.T) {
	t.Parallel()

	options := validManagementHandlerOptions(t)
	for _, mutate := range []func(*ManagementHandlerOptions){
		func(options *ManagementHandlerOptions) { options.Sessions = nil },
		func(options *ManagementHandlerOptions) { options.Revocations = nil },
		func(options *ManagementHandlerOptions) { options.PolicyPublications = nil },
		func(options *ManagementHandlerOptions) { options.PolicyCompilations = nil },
		func(options *ManagementHandlerOptions) { options.PolicyExplanations = nil },
		func(options *ManagementHandlerOptions) { options.Idempotency = nil },
		func(options *ManagementHandlerOptions) { options.RateLimitSubjects = nil },
		func(options *ManagementHandlerOptions) { options.RateLimiter = nil },
		func(options *ManagementHandlerOptions) { options.SourceRateLimit = ratelimit.Policy{} },
		func(options *ManagementHandlerOptions) { options.SessionRateLimit = ratelimit.Policy{} },
		func(options *ManagementHandlerOptions) { options.CorrelationIDs = nil },
		func(options *ManagementHandlerOptions) { options.Logger = nil },
		func(options *ManagementHandlerOptions) { options.RequestTimeout = 0 },
		func(options *ManagementHandlerOptions) { options.MaxConcurrentRequests = 0 },
	} {
		invalid := options
		mutate(&invalid)
		if _, err := NewManagementHandler(invalid); !errors.Is(err, ErrInvalidManagementHandler) {
			t.Fatalf("NewManagementHandler() error = %v, want ErrInvalidManagementHandler", err)
		}
	}
}

type managementHandlerFixtureOptions struct {
	session      accountsession.Session
	authenticate func(context.Context, accountsession.Token) (accountsession.Session, error)
	revoke       func(context.Context, revocation.Command) (revocation.Result, error)
	publish      func(context.Context, policypublication.Command) (policypublication.Result, error)
	compile      func(context.Context, accountsession.Session, compilation.Request) (policypublication.Candidate, error)
	limit        func(context.Context, ratelimit.Subject, ratelimit.Policy) (ratelimit.Decision, error)
}

func managementHandlerFixture(t *testing.T, fixture managementHandlerFixtureOptions) http.Handler {
	t.Helper()
	options := validManagementHandlerOptions(t)
	if fixture.authenticate != nil {
		options.Sessions = managementSessionAuthenticatorFunc(fixture.authenticate)
	} else if fixture.session.IsValid() {
		options.Sessions = managementSessionAuthenticatorFunc(func(context.Context, accountsession.Token) (accountsession.Session, error) {
			return fixture.session, nil
		})
	}
	if fixture.revoke != nil {
		options.Revocations = managementDeviceRevokerFunc(fixture.revoke)
	}
	if fixture.publish != nil {
		options.PolicyPublications = managementPolicyPublisherFunc(fixture.publish)
	}
	if fixture.compile != nil {
		options.PolicyCompilations = managementPolicyCompilerFunc(fixture.compile)
	}
	if fixture.limit != nil {
		options.RateLimiter = managementRateLimiterFunc(fixture.limit)
	}
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatalf("NewManagementHandler() error = %v", err)
	}
	return handler
}

func validManagementHandlerOptions(t *testing.T) ManagementHandlerOptions {
	t.Helper()
	proof, err := idempotency.NewProof("management-v1", [32]byte{31: 1})
	if err != nil {
		t.Fatalf("idempotency.NewProof() error = %v", err)
	}
	correlationID, err := publicid.Parse(managementCorrelationID())
	if err != nil {
		t.Fatalf("publicid.Parse() error = %v", err)
	}
	rateDigester, ratePolicy := managementRateLimitFixture(t)
	return ManagementHandlerOptions{
		Sessions: managementSessionAuthenticatorFunc(func(context.Context, accountsession.Token) (accountsession.Session, error) {
			return managementSessionFixture(t), nil
		}),
		Revocations: managementDeviceRevokerFunc(func(_ context.Context, command revocation.Command) (revocation.Result, error) {
			return managementResultFixture(t, command), nil
		}),
		PolicyPublications: managementPolicyPublisherFunc(func(
			_ context.Context,
			command policypublication.Command,
		) (policypublication.Result, error) {
			return managementPolicyResultFixture(t, command), nil
		}),
		PolicyCompilations: managementPolicyCompilerFunc(func(
			_ context.Context,
			_ accountsession.Session,
			request compilation.Request,
		) (policypublication.Candidate, error) {
			return compileDirectManagementPolicy(request)
		}),
		PolicyExplanations: managementPolicyExplainerFunc(func(
			context.Context,
			accountsession.Session,
			accessgraph.Query,
		) (accessgraph.Result, error) {
			return accessgraph.Result{}, accessgraph.ErrUnavailable
		}),
		Idempotency: managementIdempotencyProverFunc(func(string) (idempotency.Proof, error) {
			return proof, nil
		}),
		RateLimitSubjects: rateDigester,
		RateLimiter: managementRateLimiterFunc(func(
			_ context.Context,
			_ ratelimit.Subject,
			policy ratelimit.Policy,
		) (ratelimit.Decision, error) {
			return ratelimit.NewDecision(true, policy.Capacity(), policy.Capacity()-1, 0)
		}),
		SourceRateLimit:  ratePolicy,
		SessionRateLimit: ratePolicy,
		CorrelationIDs: managementPublicIDGeneratorFunc(func() (publicid.ID, error) {
			return correlationID, nil
		}),
		Logger:                slog.New(slog.NewJSONHandler(io.Discard, nil)),
		RequestTimeout:        time.Second,
		MaxConcurrentRequests: 2,
	}
}

func managementRateLimitFixture(t *testing.T) (*ratelimit.Digester, ratelimit.Policy) {
	t.Helper()
	keyID, err := ratelimit.NewDigestKeyID("management-v1")
	if err != nil {
		t.Fatalf("ratelimit.NewDigestKeyID() error = %v", err)
	}
	material := make([]byte, 32)
	material[31] = 1
	digester, err := ratelimit.NewDigester(keyID, material)
	if err != nil {
		t.Fatalf("ratelimit.NewDigester() error = %v", err)
	}
	policy, err := ratelimit.NewPolicy(5, time.Second)
	if err != nil {
		t.Fatalf("ratelimit.NewPolicy() error = %v", err)
	}
	return digester, policy
}

type managementSessionAuthenticatorFunc func(context.Context, accountsession.Token) (accountsession.Session, error)

func (function managementSessionAuthenticatorFunc) Authenticate(ctx context.Context, token accountsession.Token) (accountsession.Session, error) {
	return function(ctx, token)
}

type managementDeviceRevokerFunc func(context.Context, revocation.Command) (revocation.Result, error)

func (function managementDeviceRevokerFunc) Revoke(ctx context.Context, command revocation.Command) (revocation.Result, error) {
	return function(ctx, command)
}

type managementPolicyPublisherFunc func(
	context.Context,
	policypublication.Command,
) (policypublication.Result, error)

func (function managementPolicyPublisherFunc) Publish(
	ctx context.Context,
	command policypublication.Command,
) (policypublication.Result, error) {
	return function(ctx, command)
}

type managementPolicyCompilerFunc func(
	context.Context,
	accountsession.Session,
	compilation.Request,
) (policypublication.Candidate, error)

func (function managementPolicyCompilerFunc) Compile(
	ctx context.Context,
	session accountsession.Session,
	request compilation.Request,
) (policypublication.Candidate, error) {
	return function(ctx, session, request)
}

type managementPolicyExplainerFunc func(
	context.Context,
	accountsession.Session,
	accessgraph.Query,
) (accessgraph.Result, error)

func (function managementPolicyExplainerFunc) Explain(
	ctx context.Context,
	session accountsession.Session,
	query accessgraph.Query,
) (accessgraph.Result, error) {
	return function(ctx, session, query)
}

func compileDirectManagementPolicy(request compilation.Request) (policypublication.Candidate, error) {
	rules := make([]policy.Rule, len(request.Rules()))
	for index, intent := range request.Rules() {
		if intent.DestinationResourceID().IsValid() {
			return policypublication.Candidate{}, compilation.ErrResourceConflict
		}
		rule, err := policy.NewRule(policy.RuleParams{
			ID: intent.ID(), Scope: intent.Scope(), SourceNodeID: intent.SourceNodeID(),
			DestinationNodeID: intent.DestinationNodeID(), Protocol: intent.Protocol(),
			DestinationPortRanges: intent.DestinationPortRanges(),
		})
		if err != nil {
			return policypublication.Candidate{}, err
		}
		rules[index] = rule
	}
	snapshot, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope: request.Scope(), Revision: request.Revision(), Rules: rules,
	})
	if err != nil {
		return policypublication.Candidate{}, err
	}
	return policypublication.NewCandidate(snapshot, 1)
}

type managementIdempotencyProverFunc func(string) (idempotency.Proof, error)

func (function managementIdempotencyProverFunc) Proof(value string) (idempotency.Proof, error) {
	return function(value)
}

type managementRateLimiterFunc func(
	context.Context,
	ratelimit.Subject,
	ratelimit.Policy,
) (ratelimit.Decision, error)

func (function managementRateLimiterFunc) Allow(
	ctx context.Context,
	subject ratelimit.Subject,
	policy ratelimit.Policy,
) (ratelimit.Decision, error) {
	return function(ctx, subject, policy)
}

type managementPublicIDGeneratorFunc func() (publicid.ID, error)

func (function managementPublicIDGeneratorFunc) NewID() (publicid.ID, error) { return function() }

func newManagementRequest(t *testing.T, method, path, body string) *http.Request {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), method, path, bytes.NewBufferString(body))
	request.Header.Set("Authorization", "Bearer "+managementTokenFixture)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("If-Match", `"1"`)
	request.Header.Set("Idempotency-Key", "request-key-0001")
	return request
}

func validManagementPath() string {
	return "/api/v1/workspaces/" + managementWorkspaceID() + "/networks/" + managementNetworkID() +
		"/devices/" + managementDeviceID() + "/actions/revoke"
}

func managementWorkspaceID() string   { return "01890f00-0000-7000-8000-000000000101" }
func managementNetworkID() string     { return "01890f00-0000-7000-8000-000000000201" }
func managementDeviceID() string      { return "01890f00-0000-7000-8000-000000000301" }
func managementCorrelationID() string { return "01890f00-0000-7000-8000-000000000901" }

func managementSessionFixture(t *testing.T) accountsession.Session {
	t.Helper()
	deploymentID, _ := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	principalID, _ := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000401")
	sessionID, _ := accountsession.ParseID("01890f00-0000-7000-8000-000000000811")
	subjectID, _ := accountsession.ParseIdentitySubjectID("01890f00-0000-7000-8000-000000000611")
	workspaceID, _ := workspace.ParseID(managementWorkspaceID())
	now := time.Date(2026, time.September, 16, 0, 0, 0, 0, time.UTC)
	session, err := accountsession.NewSession(accountsession.Params{
		ID: sessionID, DeploymentID: deploymentID, PrincipalID: principalID,
		IdentitySubjectID: subjectID, LoginWorkspaceID: workspaceID, HasLoginWorkspace: true,
		AuthenticationTime: now.Add(-time.Hour), ACR: "urn:meshtransit:test", AMR: []string{"pwd"},
		Version: 1, PrincipalAuthorityGeneration: 1, AccountSessionGeneration: 1,
		ProviderGeneration: 1, DeploymentRecoveryEpoch: 7,
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatalf("accountsession.NewSession() error = %v", err)
	}
	return session
}

func managementResultFixture(t *testing.T, command revocation.Command) revocation.Result {
	t.Helper()
	recordID, _ := publicid.Parse("01890f00-0000-7000-8000-000000000402")
	result, err := revocation.NewResult(revocation.ResultParams{
		IdempotencyRecordID: recordID,
		Scope:               command.Scope(), NodeID: command.NodeID(), DeviceVersion: 2,
		SessionGeneration: 4, NetworkRevision: 8, InventoryRevision: 6,
	})
	if err != nil {
		t.Fatalf("revocation.NewResult() error = %v", err)
	}
	return result
}

func managementPolicyResultFixture(
	t *testing.T,
	command policypublication.Command,
) policypublication.Result {
	t.Helper()
	releaseID, err := policypublication.ParseReleaseID(
		"01890f00-0000-7000-8000-000000000412",
	)
	if err != nil {
		t.Fatalf("publication.ParseReleaseID() error = %v", err)
	}
	result, err := policypublication.NewResult(policypublication.ResultParams{
		ReleaseID: releaseID, Scope: command.Candidate().Snapshot().Scope(),
		NetworkRevision: 8, PolicyRevision: command.Candidate().Snapshot().Revision(),
		SemanticHash: command.Candidate().SemanticHash(),
	})
	if err != nil {
		t.Fatalf("publication.NewResult() error = %v", err)
	}
	return result
}
