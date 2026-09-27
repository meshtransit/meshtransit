//go:build dexbroker

package dexbroker

import (
	"context"
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
	"github.com/meshtransit/meshtransit/internal/app"
)

var errBrokerStorageOutage = errors.New("synthetic broker storage unavailable")

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

type brokerStorageOutage struct {
	storage.Storage
	unavailable atomic.Bool
	createCalls atomic.Int64
	created     atomic.Int64
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

func setBrokerDatabaseStatus(t *testing.T, state *app.RuntimeState, status app.ComponentStatus) {
	t.Helper()
	if err := state.SetComponentStatus(app.ComponentIdentityPostgreSQL, status); err != nil {
		t.Fatal("set broker database readiness")
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
