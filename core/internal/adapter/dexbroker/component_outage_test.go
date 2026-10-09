//go:build dexbroker

package dexbroker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/memory"
	"github.com/go-jose/go-jose/v4"
	"meshtransit.net/core/internal/platform/app"
)

var errBrokerStorageOutage = errors.New("synthetic broker storage unavailable")
var errBrokerSignerOutage = errors.New("synthetic broker signer unavailable")

func TestBrokerDatabaseOutageIsolatedAndRecoversWithoutRestart(t *testing.T) {
	logger := componentTestLogger()
	storageGate := &brokerStorageOutage{Storage: memory.New(logger)}
	prepared := &postgreSQLResourceTestStorage{Storage: storageGate}
	prepared.check = func(ctx context.Context) error {
		if storageGate.unavailable.Load() {
			return errBrokerStorageOutage
		}
		return ctx.Err()
	}
	resource := openPostgreSQLResourceTestDouble(t, prepared)
	options := validServiceTestOptions(t)
	service, err := NewService(options, resource, logger)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer cancel()
		if service.Done() != nil {
			if err := service.Shutdown(cleanup); err != nil {
				t.Error("stop broker outage fixture")
			}
			select {
			case <-service.Done():
			case <-cleanup.Done():
				t.Error("join broker outage fixture")
			}
		}
		if err := resource.Shutdown(cleanup); err != nil {
			t.Error("close broker outage storage")
		}
	})
	if err := service.Start(t.Context()); err != nil || !service.Ready() {
		t.Fatal("start broker outage fixture")
	}
	runtime := service.runtime
	if runtime == nil {
		t.Fatal("service did not retain one runtime")
	}

	assertBrokerDiscoveryStatus(t, service, http.StatusOK)
	storageGate.unavailable.Store(true)
	if err := resource.Check(t.Context()); !errors.Is(err, ErrCheckPostgreSQLResource) ||
		strings.Contains(err.Error(), errBrokerStorageOutage.Error()) {
		t.Fatal("database outage was not closed and redacted")
	}
	aggregate := brokerOutageRuntimeState(t, true)
	identity := brokerOutageRuntimeState(t, false)
	if !aggregate.Ready() || identity.Ready() {
		t.Fatal("database outage changed the role-scoped readiness boundary")
	}

	failed := brokerAuthorize(t, service, options, "outage-attempt")
	if failed.Code != http.StatusInternalServerError || failed.Header().Get("Cache-Control") != "no-store" ||
		failed.Header().Get("Location") != "" || failed.Header().Get("Set-Cookie") != "" ||
		strings.Contains(failed.Body.String(), errBrokerStorageOutage.Error()) ||
		storageGate.createCalls.Load() != 1 || storageGate.created.Load() != 0 {
		t.Fatalf(
			"database outage result status=%d cache=%t location=%t cookie=%t calls=%d created=%d",
			failed.Code,
			failed.Header().Get("Cache-Control") == "no-store",
			failed.Header().Get("Location") != "",
			failed.Header().Get("Set-Cookie") != "",
			storageGate.createCalls.Load(),
			storageGate.created.Load(),
		)
	}
	if !service.Ready() || service.runtime != runtime {
		t.Fatal("database outage replaced or stopped the broker runtime")
	}
	assertBrokerDiscoveryStatus(t, service, http.StatusOK)

	storageGate.unavailable.Store(false)
	if err := resource.Check(t.Context()); err != nil {
		t.Fatalf("database readiness did not recover: %v", err)
	}
	setBrokerDatabaseStatus(t, aggregate, app.ComponentStatusReady)
	setBrokerDatabaseStatus(t, identity, app.ComponentStatusReady)
	if !aggregate.Ready() || !identity.Ready() {
		t.Fatal("role-scoped readiness did not recover")
	}
	recovered := brokerAuthorize(t, service, options, "fresh-recovery-attempt")
	location, err := url.Parse(recovered.Header().Get("Location"))
	query := location.Query()
	configuredConnector := query.Get("client_id") == options.OIDCConnectors[0].ClientID &&
		query.Get("redirect_uri") == options.Issuer+"/callback" && query.Get("response_type") == "code" &&
		query.Get("code_challenge_method") == "S256"
	if err != nil || recovered.Code != http.StatusFound || recovered.Header().Get("Set-Cookie") != "" ||
		location.Scheme+"://"+location.Host+location.Path != GoogleOIDCProviderEndpoints().AuthorizationURL ||
		!configuredConnector ||
		storageGate.createCalls.Load() != 2 || storageGate.created.Load() != 1 {
		t.Fatal("fresh login did not recover through the configured connector")
	}
	if !service.Ready() || service.runtime != runtime {
		t.Fatal("database recovery reconstructed the broker runtime")
	}
}

func TestBrokerSignerOutageFailsClosedAndRecoversWithoutRestart(t *testing.T) {
	logger := componentTestLogger()
	signerGate := &brokerSignerOutage{Storage: memory.New(logger)}
	prepared := &postgreSQLResourceTestStorage{Storage: signerGate}
	resource := openPostgreSQLResourceTestDouble(t, prepared)
	options := validServiceTestOptions(t)
	service, err := NewService(options, resource, logger)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer cancel()
		if service.Done() != nil {
			if err := service.Shutdown(cleanup); err != nil {
				t.Error("stop broker signer fixture")
			}
			select {
			case <-service.Done():
			case <-cleanup.Done():
				t.Error("join broker signer fixture")
			}
		}
		if err := resource.Shutdown(cleanup); err != nil {
			t.Error("close broker signer storage")
		}
	})
	if err := service.Start(t.Context()); err != nil || !service.Ready() {
		t.Fatal("start broker signer fixture")
	}
	runtime := service.runtime
	if runtime == nil || service.CheckSigner(t.Context()) != nil {
		t.Fatal("running broker did not prove its signer and JWKS")
	}
	assertBrokerDiscoveryStatus(t, service, http.StatusOK)
	componentJWKS(t, runtime)

	code := storage.AuthCode{
		ID: "signer-outage-code", ClientID: options.Clients[0].ID,
		RedirectURI: options.Clients[0].RedirectURI, Nonce: "synthetic-nonce",
		Scopes: []string{"openid", "federated:id"}, ConnectorID: options.OIDCConnectors[0].ID,
		Claims: storage.Claims{UserID: "synthetic-user"},
		Expiry: time.Now().Add(time.Hour),
	}
	if err := signerGate.CreateAuthCode(t.Context(), code); err != nil {
		t.Fatalf("seed authorization code: %v", err)
	}

	signerGate.unavailable.Store(true)
	if err := service.CheckSigner(t.Context()); !errors.Is(err, ErrSignerCheck) ||
		strings.Contains(err.Error(), errBrokerSignerOutage.Error()) {
		t.Fatal("signer outage was not closed and redacted")
	}
	if err := resource.Check(t.Context()); err != nil {
		t.Fatal("signer outage incorrectly changed database health")
	}
	aggregate := brokerSignerRuntimeState(t, true)
	identity := brokerSignerRuntimeState(t, false)
	if !aggregate.Ready() || identity.Ready() {
		t.Fatal("signer outage changed the role-scoped readiness boundary")
	}

	jwksFailure := brokerJWKS(t, service)
	if jwksFailure.Code != http.StatusInternalServerError ||
		jwksFailure.Header().Get("Cache-Control") != "no-store" ||
		strings.Contains(jwksFailure.Body.String(), errBrokerSignerOutage.Error()) {
		t.Fatal("JWKS outage was not generic and non-cacheable")
	}
	failed := brokerTokenExchange(t, service, options, code.ID)
	if failed.Code != http.StatusInternalServerError || failed.Header().Get("Cache-Control") != "no-store" ||
		failed.Header().Get("Location") != "" || failed.Header().Get("Set-Cookie") != "" ||
		strings.Contains(failed.Body.String(), errBrokerSignerOutage.Error()) ||
		strings.Contains(failed.Body.String(), "id_token") ||
		strings.Contains(failed.Body.String(), "access_token") {
		t.Fatal("signer outage disclosed detail or issued token material")
	}
	if _, err := signerGate.GetAuthCode(t.Context(), code.ID); err != nil {
		t.Fatal("signer outage consumed the retryable authorization code")
	}
	if !service.Ready() || service.runtime != runtime {
		t.Fatal("signer outage replaced or stopped the broker runtime")
	}
	assertBrokerDiscoveryStatus(t, service, http.StatusOK)

	signerGate.unavailable.Store(false)
	if err := service.CheckSigner(t.Context()); err != nil {
		t.Fatalf("signer readiness did not recover: %v", err)
	}
	setBrokerSignerStatus(t, aggregate, app.ComponentStatusReady)
	setBrokerSignerStatus(t, identity, app.ComponentStatusReady)
	if !aggregate.Ready() || !identity.Ready() {
		t.Fatal("role-scoped signer readiness did not recover")
	}
	recoveredJWKS := componentJWKS(t, runtime)
	recovered := brokerTokenExchange(t, service, options, code.ID)
	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.NewDecoder(recovered.Body).Decode(&tokenResponse); err != nil {
		t.Fatalf("decode recovered token response: %v", err)
	}
	if recovered.Code != http.StatusOK || tokenResponse.AccessToken == "" ||
		tokenResponse.IDToken == "" || tokenResponse.TokenType != "bearer" {
		t.Fatal("fresh token issuance did not recover")
	}
	parts := strings.Split(tokenResponse.IDToken, ".")
	if len(parts) != 3 {
		t.Fatal("broker returned malformed ID token")
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		t.Fatal("decode broker ID token payload")
	}
	var claims struct {
		Federated struct {
			ConnectorID string `json:"connector_id"`
		} `json:"federated_claims"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Federated.ConnectorID != options.OIDCConnectors[0].ID {
		t.Fatal("broker ID token did not bind the selected connector")
	}
	assertBrokerTokenSignature(t, recoveredJWKS, tokenResponse.IDToken)
	if _, err := signerGate.GetAuthCode(t.Context(), code.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("successful recovery did not consume the authorization code exactly once")
	}
	if !service.Ready() || service.runtime != runtime {
		t.Fatal("signer recovery reconstructed the broker runtime")
	}
}

func TestBrokerSignerUnavailableAtStartupFailsClosed(t *testing.T) {
	logger := componentTestLogger()
	signerGate := &brokerSignerOutage{Storage: memory.New(logger)}
	signerGate.unavailable.Store(true)
	prepared := &postgreSQLResourceTestStorage{Storage: signerGate}
	resource := openPostgreSQLResourceTestDouble(t, prepared)
	t.Cleanup(func() {
		if err := resource.Shutdown(context.Background()); err != nil {
			t.Error("close startup signer fixture")
		}
	})
	service, err := NewService(validServiceTestOptions(t), resource, logger)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	err = service.Start(t.Context())
	if !errors.Is(err, ErrServiceStart) || strings.Contains(err.Error(), errBrokerSignerOutage.Error()) {
		t.Fatalf("Start() error = %v, want redacted signer failure", err)
	}
	if service.Done() != nil || service.Ready() || resource.activeUses != 0 {
		t.Fatal("unusable startup signer published runtime state or retained storage")
	}
}

type brokerStorageOutage struct {
	storage.Storage
	unavailable atomic.Bool
	createCalls atomic.Int64
	created     atomic.Int64
}

type brokerSignerOutage struct {
	storage.Storage
	unavailable atomic.Bool
}

func (gate *brokerSignerOutage) GetKeys(ctx context.Context) (storage.Keys, error) {
	if gate.unavailable.Load() {
		return storage.Keys{}, errBrokerSignerOutage
	}
	return gate.Storage.GetKeys(ctx)
}

func (gate *brokerStorageOutage) CreateAuthRequest(ctx context.Context, request storage.AuthRequest) error {
	gate.createCalls.Add(1)
	if gate.unavailable.Load() {
		return errBrokerStorageOutage
	}
	if err := gate.Storage.CreateAuthRequest(ctx, request); err != nil {
		return err
	}
	gate.created.Add(1)
	return nil
}

func brokerOutageRuntimeState(t *testing.T, aggregate bool) *app.RuntimeState {
	t.Helper()
	roles := []app.Role{app.RoleIdentity}
	statuses := map[app.Component]app.ComponentStatus{
		app.ComponentIdentityPostgreSQL:    app.ComponentStatusUnavailable,
		app.ComponentIdentityConfiguration: app.ComponentStatusReady,
		app.ComponentIdentitySigner:        app.ComponentStatusReady,
	}
	if aggregate {
		roles = []app.Role{app.RoleAPI, app.RoleControl, app.RoleWorker, app.RoleRelay, app.RoleIdentity}
		statuses[app.ComponentPostgreSQL] = app.ComponentStatusReady
		statuses[app.ComponentRedis] = app.ComponentStatusReady
	}
	state, err := app.NewRuntimeState(roles)
	if err != nil {
		t.Fatal("construct role-scoped readiness")
	}
	state.SetReady(true)
	if err := state.SetComponentStatuses(statuses); err != nil {
		t.Fatal("set role-scoped outage")
	}
	return state
}

func brokerSignerRuntimeState(t *testing.T, aggregate bool) *app.RuntimeState {
	t.Helper()
	roles := []app.Role{app.RoleIdentity}
	statuses := map[app.Component]app.ComponentStatus{
		app.ComponentIdentityPostgreSQL:    app.ComponentStatusReady,
		app.ComponentIdentityConfiguration: app.ComponentStatusReady,
		app.ComponentIdentitySigner:        app.ComponentStatusUnavailable,
	}
	if aggregate {
		roles = []app.Role{app.RoleAPI, app.RoleControl, app.RoleWorker, app.RoleRelay, app.RoleIdentity}
		statuses[app.ComponentPostgreSQL] = app.ComponentStatusReady
		statuses[app.ComponentRedis] = app.ComponentStatusReady
	}
	state, err := app.NewRuntimeState(roles)
	if err != nil {
		t.Fatal("construct signer role-scoped readiness")
	}
	state.SetReady(true)
	if err := state.SetComponentStatuses(statuses); err != nil {
		t.Fatal("set role-scoped signer outage")
	}
	return state
}

func setBrokerDatabaseStatus(t *testing.T, state *app.RuntimeState, status app.ComponentStatus) {
	t.Helper()
	if err := state.SetComponentStatus(app.ComponentIdentityPostgreSQL, status); err != nil {
		t.Fatal("set broker database readiness")
	}
}

func setBrokerSignerStatus(t *testing.T, state *app.RuntimeState, status app.ComponentStatus) {
	t.Helper()
	if err := state.SetComponentStatus(app.ComponentIdentitySigner, status); err != nil {
		t.Fatal("set broker signer readiness")
	}
}

func assertBrokerDiscoveryStatus(t *testing.T, service *Service, want int) {
	t.Helper()
	request := httptest.NewRequestWithContext(
		t.Context(), http.MethodGet, "https://issuer.example/dex/.well-known/openid-configuration", nil,
	)
	response := httptest.NewRecorder()
	service.ServeHTTP(response, request)
	if response.Code != want {
		t.Fatalf("broker discovery status = %d, want %d", response.Code, want)
	}
}

func brokerAuthorize(
	t *testing.T,
	service *Service,
	options ServiceOptions,
	state string,
) *httptest.ResponseRecorder {
	t.Helper()
	query := url.Values{
		"client_id":             {options.Clients[0].ID},
		"code_challenge":        {strings.Repeat("a", 43)},
		"code_challenge_method": {"S256"},
		"connector_id":          {options.OIDCConnectors[0].ID},
		"nonce":                 {"synthetic-nonce"},
		"redirect_uri":          {options.Clients[0].RedirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {state},
	}
	request := httptest.NewRequestWithContext(
		t.Context(), http.MethodGet,
		options.Issuer+"/auth/"+url.PathEscape(options.OIDCConnectors[0].ID)+"?"+query.Encode(), nil,
	)
	response := httptest.NewRecorder()
	service.ServeHTTP(response, request)
	return response
}

func brokerJWKS(t *testing.T, service *Service) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequestWithContext(
		t.Context(), http.MethodGet, "https://issuer.example/dex/keys", nil,
	)
	response := httptest.NewRecorder()
	service.ServeHTTP(response, request)
	return response
}

func brokerTokenExchange(
	t *testing.T,
	service *Service,
	options ServiceOptions,
	code string,
) *httptest.ResponseRecorder {
	t.Helper()
	secret, err := options.Clients[0].SecretFile.Read()
	if err != nil {
		t.Fatal("read synthetic client credential")
	}
	form := url.Values{
		"code":         {code},
		"grant_type":   {authorizationCodeGrant},
		"redirect_uri": {options.Clients[0].RedirectURI},
	}
	request := httptest.NewRequestWithContext(
		t.Context(), http.MethodPost, options.Issuer+"/token", strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(options.Clients[0].ID, secret)
	response := httptest.NewRecorder()
	service.ServeHTTP(response, request)
	return response
}

func assertBrokerTokenSignature(t *testing.T, jwks jose.JSONWebKeySet, rawToken string) {
	t.Helper()
	message, err := jose.ParseSigned(rawToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parse recovered token: %v", err)
	}
	for _, key := range jwks.Keys {
		if _, err := message.Verify(key.Key); err == nil {
			return
		}
	}
	t.Fatal("recovered token was not signed by the published JWKS")
}
