//go:build dexbroker

package dexbroker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/memory"
)

func TestDexComponentServesConstrainedDiscoveryAndJoins(t *testing.T) {
	logger := componentTestLogger()
	serverStorage := newComponentTestStorage(t, logger, true)
	runtime, err := newDexRuntime(t.Context(), validComponentTestOptions(logger), componentResources{
		storage: serverStorage,
	})
	if err != nil {
		t.Fatalf("construct runtime: %v", err)
	}
	registerRuntimeCleanup(t, runtime, serverStorage)

	request := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"https://issuer.example/dex/.well-known/openid-configuration",
		nil,
	)
	response := httptest.NewRecorder()
	runtime.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("discovery status = %d, want %d", response.Code, http.StatusOK)
	}
	for header, want := range map[string]string{
		"Cache-Control":          "no-store",
		"Referrer-Policy":        "no-referrer",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := response.Header().Get(header); got != want {
			t.Fatalf("%s = %q, want %q", header, got, want)
		}
	}

	var document struct {
		Issuer                 string   `json:"issuer"`
		GrantTypesSupported    []string `json:"grant_types_supported"`
		ResponseTypesSupported []string `json:"response_types_supported"`
	}
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	if document.Issuer != "https://issuer.example/dex" {
		t.Fatalf("issuer = %q", document.Issuer)
	}
	if !slices.Equal(document.GrantTypesSupported, []string{authorizationCodeGrant}) {
		t.Fatalf("grant types = %v", document.GrantTypesSupported)
	}
	if !slices.Equal(document.ResponseTypesSupported, []string{codeResponseType}) {
		t.Fatalf("response types = %v", document.ResponseTypesSupported)
	}

	shutdownDexComponentRuntime(t, runtime)
	waitForComponentChannel(t, runtime.Done(), "runtime join")
	assertComponentChannelOpen(t, serverStorage.closed, "runtime closed borrowed storage")
	if got := serverStorage.closeCalls.Load(); got != 0 {
		t.Fatalf("storage close calls = %d, want 0", got)
	}
}

func TestDexComponentWaitsForServerWorkersWithoutClosingBorrowedStorage(t *testing.T) {
	logger := componentTestLogger()
	serverStorage := newComponentTestStorage(t, logger, true)
	serverStorage.blockGarbageCollection()
	options := validComponentTestOptions(logger)
	options.garbageCollectionFrequency = time.Nanosecond

	runtime, err := newDexRuntime(t.Context(), options, componentResources{storage: serverStorage})
	if err != nil {
		t.Fatalf("construct runtime: %v", err)
	}
	registerRuntimeCleanup(t, runtime, serverStorage)
	waitForComponentChannel(t, serverStorage.gcEntered, "garbage collection entry")

	shutdownResult := make(chan error, 1)
	go func() {
		shutdownResult <- runtime.Shutdown(context.Background())
	}()
	waitForComponentChannel(t, serverStorage.gcCanceled, "component cancellation")
	assertComponentChannelOpen(t, serverStorage.closed, "storage closed before worker exit")
	assertComponentChannelOpen(t, runtime.Done(), "runtime joined before worker exit")

	serverStorage.releaseGarbageCollection()
	select {
	case err := <-shutdownResult:
		if err != nil {
			t.Fatalf("shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not join")
	}
	assertComponentChannelOpen(t, serverStorage.closed, "runtime closed borrowed storage")
	if got := serverStorage.closeCalls.Load(); got != 0 {
		t.Fatalf("storage close calls = %d, want 0", got)
	}
}

func TestDexComponentConstructionFailureLeavesBorrowedStorageOpen(t *testing.T) {
	logger := componentTestLogger()
	serverStorage := newComponentTestStorage(t, logger, false)
	_, err := newDexRuntime(t.Context(), validComponentTestOptions(logger), componentResources{
		storage: serverStorage,
	})
	if !errors.Is(err, ErrComponentStart) {
		t.Fatalf("construct error = %v, want %v", err, ErrComponentStart)
	}
	assertComponentChannelOpen(t, serverStorage.closed, "construction failure closed borrowed storage")
	if got := serverStorage.closeCalls.Load(); got != 0 {
		t.Fatalf("storage close calls = %d, want 0", got)
	}
	t.Cleanup(func() { _ = serverStorage.Close() })
}

func TestDexComponentRejectsInvalidInputWithoutClosingBorrowedStorage(t *testing.T) {
	logger := componentTestLogger()
	options := validComponentTestOptions(logger)
	options.issuer = "http://issuer.example/dex"
	serverStorage := newComponentTestStorage(t, logger, false)

	_, err := newDexRuntime(t.Context(), options, componentResources{storage: serverStorage})
	if !errors.Is(err, ErrInvalidComponent) {
		t.Fatalf("construct error = %v, want %v", err, ErrInvalidComponent)
	}
	assertComponentChannelOpen(t, serverStorage.closed, "invalid input closed borrowed storage")
	if got := serverStorage.closeCalls.Load(); got != 0 {
		t.Fatalf("storage close calls = %d, want 0", got)
	}
	t.Cleanup(func() { _ = serverStorage.Close() })
}

func TestDexComponentParentCancellationDrainsRuntime(t *testing.T) {
	logger := componentTestLogger()
	serverStorage := newComponentTestStorage(t, logger, true)
	lifecycleCtx, cancelLifecycle := context.WithCancel(t.Context())
	runtime, err := newDexRuntime(lifecycleCtx, validComponentTestOptions(logger), componentResources{
		storage: serverStorage,
	})
	if err != nil {
		t.Fatalf("construct runtime: %v", err)
	}
	registerRuntimeCleanup(t, runtime, serverStorage)

	cancelLifecycle()
	waitForComponentChannel(t, runtime.Done(), "runtime join")
	if runtime.Ready() {
		t.Fatal("runtime remained ready after parent cancellation")
	}
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	if err := runtime.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown after parent cancellation: %v", err)
	}
	assertComponentChannelOpen(t, serverStorage.closed, "parent cancellation closed borrowed storage")
}

func validComponentTestOptions(logger *slog.Logger) componentOptions {
	return componentOptions{
		issuer:                     "https://issuer.example/dex",
		idTokensValidFor:           time.Hour,
		authRequestsValidFor:       5 * time.Minute,
		signingKeysRotateAfter:     6 * time.Hour,
		garbageCollectionFrequency: time.Hour,
		logger:                     logger,
		now:                        func() time.Time { return time.Unix(1_800_000_000, 0) },
	}
}

func componentTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type componentTestStorage struct {
	storage.Storage
	closeCalls    atomic.Int64
	closeErr      error
	closed        chan struct{}
	closeOnce     sync.Once
	gcEntered     chan struct{}
	gcCanceled    chan struct{}
	gcRelease     chan struct{}
	gcEnterOnce   sync.Once
	gcCancelOnce  sync.Once
	gcReleaseOnce sync.Once
}

func newComponentTestStorage(t *testing.T, logger *slog.Logger, withConnector bool) *componentTestStorage {
	t.Helper()
	base := memory.New(logger)
	if withConnector {
		err := base.CreateConnector(t.Context(), storage.Connector{
			ID:              "mock",
			Type:            "mockCallback",
			Name:            "Mock",
			ResourceVersion: "1",
		})
		if err != nil {
			t.Fatalf("create connector: %v", err)
		}
	}
	return &componentTestStorage{
		Storage: base,
		closed:  make(chan struct{}),
	}
}

func (serverStorage *componentTestStorage) blockGarbageCollection() {
	serverStorage.gcEntered = make(chan struct{})
	serverStorage.gcCanceled = make(chan struct{})
	serverStorage.gcRelease = make(chan struct{})
}

func (serverStorage *componentTestStorage) GarbageCollect(ctx context.Context, now time.Time) (storage.GCResult, error) {
	if serverStorage.gcEntered == nil {
		return serverStorage.Storage.GarbageCollect(ctx, now)
	}
	serverStorage.gcEnterOnce.Do(func() { close(serverStorage.gcEntered) })
	<-ctx.Done()
	serverStorage.gcCancelOnce.Do(func() { close(serverStorage.gcCanceled) })
	<-serverStorage.gcRelease
	return storage.GCResult{}, nil
}

func (serverStorage *componentTestStorage) releaseGarbageCollection() {
	if serverStorage.gcRelease != nil {
		serverStorage.gcReleaseOnce.Do(func() { close(serverStorage.gcRelease) })
	}
}

func (serverStorage *componentTestStorage) Close() error {
	serverStorage.closeCalls.Add(1)
	serverStorage.closeOnce.Do(func() { close(serverStorage.closed) })
	baseErr := serverStorage.Storage.Close()
	if serverStorage.closeErr != nil {
		return serverStorage.closeErr
	}
	return baseErr
}

func registerRuntimeCleanup(t *testing.T, runtime *Runtime, serverStorage *componentTestStorage) {
	t.Helper()
	t.Cleanup(func() {
		serverStorage.releaseGarbageCollection()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = runtime.Shutdown(ctx)
		_ = serverStorage.Close()
	})
}

func shutdownDexComponentRuntime(t *testing.T, runtime *Runtime) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := runtime.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

func waitForComponentChannel(t *testing.T, channel <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-channel:
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for %s", name)
	}
}

func assertComponentChannelOpen(t *testing.T, channel <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-channel:
		t.Fatal(message)
	default:
	}
}
