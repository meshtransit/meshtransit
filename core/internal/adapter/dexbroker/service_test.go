//go:build dexbroker

package dexbroker

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dexidp/dex/storage"
	"meshtransit.net/core/internal/platform/config"
)

func TestServiceServeHTTPFailsClosedBeforeStart(t *testing.T) {
	var service *Service
	response := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"https://issuer.example/dex/keys",
		nil,
	)
	service.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("pre-start response = (%d, %q)", response.Code, response.Header().Get("Cache-Control"))
	}
}

func TestServiceHoldsStorageBorrowUntilCompleteJoin(t *testing.T) {
	serverStorage := newPostgreSQLResourceTestStorage(componentTestLogger())
	if err := serverStorage.CreateConnector(t.Context(), storage.Connector{
		ID: "mock", Type: "mockCallback", Name: "Mock", ResourceVersion: "1",
	}); err != nil {
		t.Fatalf("create connector: %v", err)
	}
	resource := openPostgreSQLResourceTestDouble(t, serverStorage)
	service, err := NewService(validServiceTestOptions(t), resource, componentTestLogger())
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	service.newRuntime = testRuntimeWithoutStaticConfiguration
	if service.Done() != nil || service.Ready() {
		t.Fatal("service performed work before Start")
	}
	if err := service.Start(t.Context()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if service.Done() == nil || !service.Ready() {
		t.Fatal("service did not publish a running runtime")
	}

	shutdownCtx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := resource.Shutdown(shutdownCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("resource Shutdown() error = %v, want deadline", err)
	}
	if got := serverStorage.closeCalls.Load(); got != 0 {
		t.Fatalf("storage closed while service active: %d", got)
	}
	if err := service.Shutdown(t.Context()); err != nil {
		t.Fatalf("service Shutdown() error = %v", err)
	}
	if err := <-service.Done(); err != nil {
		t.Fatalf("service join error = %v", err)
	}
	if err := resource.Shutdown(t.Context()); err != nil {
		t.Fatalf("resource second Shutdown() error = %v", err)
	}
	if got := serverStorage.closeCalls.Load(); got != 1 {
		t.Fatalf("storage close calls = %d, want 1", got)
	}
}

func TestServiceRejectsInvalidInputAndRepeatedStart(t *testing.T) {
	var nilResource *PostgreSQLResource
	if _, err := NewService(validServiceTestOptions(t), nilResource, componentTestLogger()); !errors.Is(err, ErrInvalidService) {
		t.Fatalf("NewService() error = %v, want invalid", err)
	}

	serverStorage := newPostgreSQLResourceTestStorage(componentTestLogger())
	if err := serverStorage.CreateConnector(t.Context(), storage.Connector{
		ID: "mock", Type: "mockCallback", Name: "Mock", ResourceVersion: "1",
	}); err != nil {
		t.Fatalf("create connector: %v", err)
	}
	resource := openPostgreSQLResourceTestDouble(t, serverStorage)
	t.Cleanup(func() { _ = resource.Shutdown(context.Background()) })
	service, err := NewService(validServiceTestOptions(t), resource, componentTestLogger())
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	service.newRuntime = testRuntimeWithoutStaticConfiguration
	if err := service.Start(t.Context()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := service.Start(t.Context()); !errors.Is(err, ErrServiceStarted) {
		t.Fatalf("second Start() error = %v, want already started", err)
	}
	if err := service.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	<-service.Done()
}

func TestServiceFormattingAndJSONAreRedacted(t *testing.T) {
	options := validServiceTestOptions(t)
	formatted := fmt.Sprintf("%v %#v", options, options)
	if strings.Contains(formatted, options.Issuer) || !strings.Contains(formatted, "REDACTED") {
		t.Fatalf("formatting disclosed service options: %q", formatted)
	}
	if _, err := json.Marshal(options); !errors.Is(err, ErrInvalidService) {
		t.Fatalf("json.Marshal(options) error = %v", err)
	}
	for name, value := range map[string]any{
		"connector":   options.OIDCConnectors[0],
		"client":      options.Clients[0],
		"fingerprint": options.ExpectedFingerprint,
	} {
		if fmt.Sprint(value) != redactedConfiguration || fmt.Sprintf("%#v", value) != redactedConfiguration {
			t.Fatalf("%s formatting disclosed configuration", name)
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrInvalidService) {
			t.Fatalf("json.Marshal(%s) error = %v", name, err)
		}
	}
}

func TestServiceRejectsConfigurationFingerprintMismatchBeforeBorrow(t *testing.T) {
	serverStorage := newPostgreSQLResourceTestStorage(componentTestLogger())
	resource := openPostgreSQLResourceTestDouble(t, serverStorage)
	t.Cleanup(func() { _ = resource.Shutdown(context.Background()) })
	options := validServiceTestOptions(t)
	options.ExpectedFingerprint[0] ^= 0xff
	service, err := NewService(options, resource, componentTestLogger())
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if err := service.Start(t.Context()); !errors.Is(err, ErrServiceStart) {
		t.Fatalf("Start() error = %v, want start failure", err)
	}
	if service.Done() != nil || service.Ready() {
		t.Fatal("fingerprint mismatch published a runtime")
	}
	if resource.activeUses != 0 {
		t.Fatalf("storage active uses = %d, want zero", resource.activeUses)
	}
}

func TestServiceConfigurationCheckDetectsSecretDrift(t *testing.T) {
	options := validServiceTestOptions(t)
	serverStorage := newPostgreSQLResourceTestStorage(componentTestLogger())
	resource := openPostgreSQLResourceTestDouble(t, serverStorage)
	t.Cleanup(func() { _ = resource.Shutdown(context.Background()) })
	service, err := NewService(options, resource, componentTestLogger())
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if err := service.CheckConfiguration(t.Context()); err != nil {
		t.Fatalf("CheckConfiguration() error = %v", err)
	}
	service.options.OIDCConnectors[0].ClientSecretFile = testServiceSecretFile(
		t,
		"changed-connector-secret",
		strings.Repeat("d", 48),
	)
	if err := service.CheckConfiguration(t.Context()); !errors.Is(err, ErrConfigurationCheck) {
		t.Fatalf("CheckConfiguration() after drift error = %v", err)
	}
}

func TestServiceSignerCheckRequiresRunningRuntime(t *testing.T) {
	var absent *Service
	if err := absent.CheckSigner(t.Context()); !errors.Is(err, ErrSignerCheck) {
		t.Fatalf("nil CheckSigner() error = %v", err)
	}
	serverStorage := newPostgreSQLResourceTestStorage(componentTestLogger())
	resource := openPostgreSQLResourceTestDouble(t, serverStorage)
	t.Cleanup(func() { _ = resource.Shutdown(context.Background()) })
	service, err := NewService(validServiceTestOptions(t), resource, componentTestLogger())
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if err := service.CheckSigner(t.Context()); !errors.Is(err, ErrSignerCheck) {
		t.Fatalf("pre-start CheckSigner() error = %v", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := service.CheckSigner(canceled); !errors.Is(err, ErrSignerCheck) {
		t.Fatalf("canceled CheckSigner() error = %v", err)
	}
}

func validServiceTestOptions(t *testing.T) ServiceOptions {
	t.Helper()
	connectorSecret := testServiceSecretFile(t, "connector-secret", strings.Repeat("c", 48))
	clientSecret := testServiceSecretFile(t, "client-secret", strings.Repeat("b", 48))
	options := ServiceOptions{
		Issuer: "https://issuer.example/dex",
		OIDCConnectors: []OIDCConnectorOptions{{
			ID: "google-v1", DisplayName: "Google", Generation: 1,
			Issuer: "https://accounts.google.com", Endpoints: GoogleOIDCProviderEndpoints(),
			ClientID:         "google-client.apps.googleusercontent.com",
			ClientSecretFile: connectorSecret,
		}},
		Clients: []ClientOptions{{
			ID: "meshtransit-core", DisplayName: "MeshTransit Core", Generation: 1,
			SecretFile: clientSecret, RedirectURI: "https://app.example.test/auth/callback",
		}},
		IDTokenLifetime:           time.Hour,
		AuthRequestLifetime:       5 * time.Minute,
		SigningKeyRotation:        6 * time.Hour,
		GarbageCollectionInterval: time.Hour,
	}
	encoded, err := CalculateConfigurationFingerprint(options)
	if err != nil {
		t.Fatalf("CalculateConfigurationFingerprint() error = %v", err)
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(encoded, configurationFingerprintPrefix))
	if err != nil {
		t.Fatalf("decode fingerprint: %v", err)
	}
	copy(options.ExpectedFingerprint[:], decoded)
	return options
}

func testServiceSecretFile(t *testing.T, name, value string) config.SecretFile {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	file, err := config.NewSecretFile(path)
	if err != nil {
		t.Fatalf("NewSecretFile() error = %v", err)
	}
	return file
}

func testRuntimeWithoutStaticConfiguration(
	ctx context.Context,
	options componentOptions,
	resources componentResources,
) (*Runtime, error) {
	options.configuration = componentConfiguration{}
	return newDexRuntime(ctx, options, resources)
}

func TestServiceRetriesATransientStartFailure(t *testing.T) {
	previous := startRetryDelays
	startRetryDelays = []time.Duration{time.Millisecond, time.Millisecond}
	t.Cleanup(func() { startRetryDelays = previous })

	serverStorage := newPostgreSQLResourceTestStorage(componentTestLogger())
	if err := serverStorage.CreateConnector(t.Context(), storage.Connector{
		ID: "mock", Type: "mockCallback", Name: "Mock", ResourceVersion: "1",
	}); err != nil {
		t.Fatalf("create connector: %v", err)
	}
	resource := openPostgreSQLResourceTestDouble(t, serverStorage)
	t.Cleanup(func() { _ = resource.Shutdown(context.Background()) })
	service, err := NewService(validServiceTestOptions(t), resource, componentTestLogger())
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	attempts := 0
	service.newRuntime = func(ctx context.Context, options componentOptions, resources componentResources) (*Runtime, error) {
		attempts++
		if attempts < 3 {
			return nil, ErrComponentStart
		}
		return testRuntimeWithoutStaticConfiguration(ctx, options, resources)
	}
	if err := service.Start(t.Context()); err != nil {
		t.Fatalf("Start() error = %v after %d attempts", err, attempts)
	}
	if attempts != 3 || !service.Ready() {
		t.Fatalf("attempts = %d ready = %t, want 3 and ready", attempts, service.Ready())
	}
	if err := service.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	<-service.Done()
}

func TestServiceStopsRetryingAfterTheBudget(t *testing.T) {
	previous := startRetryDelays
	startRetryDelays = []time.Duration{time.Millisecond}
	t.Cleanup(func() { startRetryDelays = previous })

	serverStorage := newPostgreSQLResourceTestStorage(componentTestLogger())
	resource := openPostgreSQLResourceTestDouble(t, serverStorage)
	t.Cleanup(func() { _ = resource.Shutdown(context.Background()) })
	for _, failure := range []error{ErrComponentStart, ErrInvalidComponent} {
		service, err := NewService(validServiceTestOptions(t), resource, componentTestLogger())
		if err != nil {
			t.Fatalf("NewService() error = %v", err)
		}
		attempts := 0
		service.newRuntime = func(context.Context, componentOptions, componentResources) (*Runtime, error) {
			attempts++
			return nil, failure
		}
		if err := service.Start(t.Context()); !errors.Is(err, ErrServiceStart) {
			t.Fatalf("Start() error = %v, want start failure", err)
		}
		want := 2
		if errors.Is(failure, ErrInvalidComponent) {
			want = 1
		}
		if attempts != want {
			t.Fatalf("%v: attempts = %d, want %d", failure, attempts, want)
		}
	}
}
