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
	"github.com/go-jose/go-jose/v4"
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

func TestDexComponentSharesSigningKeyRotationAndJWKSOverlapAcrossReplicas(t *testing.T) {
	logger := componentTestLogger()
	serverStorage := newComponentTestStorage(t, logger, true)
	clock := newComponentTestClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	options := validComponentTestOptions(logger)
	options.now = clock.Now

	var runtimes []*Runtime
	t.Cleanup(func() {
		for _, runtime := range runtimes {
			shutdownDexComponentRuntime(t, runtime)
		}
		if err := serverStorage.Close(); err != nil {
			t.Fatalf("close storage: %v", err)
		}
	})
	startReplica := func() *Runtime {
		t.Helper()
		runtime, err := newDexRuntime(t.Context(), options, componentResources{storage: serverStorage})
		if err != nil {
			t.Fatalf("construct runtime: %v", err)
		}
		runtimes = append(runtimes, runtime)
		return runtime
	}

	first := startReplica()
	second := startReplica()
	initialKeys := componentStoredKeys(t, serverStorage)
	initialKeyID := initialKeys.SigningKey.KeyID
	preRotationPayload := []byte("issued-before-rotation")
	preRotationSignature := componentSignedPayload(t, initialKeys.SigningKey, preRotationPayload)
	for _, runtime := range []*Runtime{first, second} {
		assertComponentJWKSKeyIDs(t, runtime, initialKeyID)
	}

	shutdownDexComponentRuntime(t, second)
	clock.Set(initialKeys.NextRotation.Add(time.Nanosecond))
	second = startReplica()
	rotatedKeys := componentStoredKeys(t, serverStorage)
	rotatedKeyID := rotatedKeys.SigningKey.KeyID
	if rotatedKeyID == initialKeyID {
		t.Fatal("second replica did not rotate the shared signing key")
	}
	if len(rotatedKeys.VerificationKeys) != 1 ||
		rotatedKeys.VerificationKeys[0].PublicKey.KeyID != initialKeyID ||
		!rotatedKeys.VerificationKeys[0].Expiry.Equal(clock.Now().Add(options.idTokensValidFor)) {
		t.Fatal("retired signing key did not retain the configured token lifetime")
	}
	for _, runtime := range []*Runtime{first, second} {
		jwks := componentJWKS(t, runtime)
		assertComponentJWKSKeyIDs(t, runtime, initialKeyID, rotatedKeyID)
		assertComponentSignature(t, jwks, initialKeyID, preRotationSignature, preRotationPayload)
	}

	shutdownDexComponentRuntime(t, second)
	clock.Set(rotatedKeys.NextRotation.Add(time.Nanosecond))
	third := startReplica()
	retiredKeys := componentStoredKeys(t, serverStorage)
	thirdKeyID := retiredKeys.SigningKey.KeyID
	if thirdKeyID == initialKeyID || thirdKeyID == rotatedKeyID {
		t.Fatal("third replica did not publish a fresh shared signing key")
	}
	for _, runtime := range []*Runtime{first, third} {
		assertComponentJWKSKeyIDs(t, runtime, rotatedKeyID, thirdKeyID)
	}
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

type componentTestClock struct {
	nanoseconds atomic.Int64
}

func newComponentTestClock(initial time.Time) *componentTestClock {
	clock := &componentTestClock{}
	clock.Set(initial)
	return clock
}

func (clock *componentTestClock) Now() time.Time {
	return time.Unix(0, clock.nanoseconds.Load()).UTC()
}

func (clock *componentTestClock) Set(now time.Time) {
	clock.nanoseconds.Store(now.UnixNano())
}

func componentStoredKeys(t *testing.T, serverStorage storage.Storage) storage.Keys {
	t.Helper()
	keys, err := serverStorage.GetKeys(t.Context())
	if err != nil {
		t.Fatalf("get shared signing keys: %v", err)
	}
	if keys.SigningKey == nil || keys.SigningKeyPub == nil {
		t.Fatal("shared signing key pair is incomplete")
	}
	return keys
}

func componentSignedPayload(t *testing.T, key *jose.JSONWebKey, payload []byte) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
	if err != nil {
		t.Fatalf("construct signer: %v", err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign payload: %v", err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize signature: %v", err)
	}
	return compact
}

func componentJWKS(t *testing.T, runtime *Runtime) jose.JSONWebKeySet {
	t.Helper()
	request := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"https://issuer.example/dex/keys",
		nil,
	)
	response := httptest.NewRecorder()
	runtime.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("JWKS status = %d, want %d", response.Code, http.StatusOK)
	}
	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(response.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	if len(jwks.Keys) == 0 {
		t.Fatal("JWKS has no verification keys")
	}
	for index := range jwks.Keys {
		key := &jwks.Keys[index]
		if key.KeyID == "" || key.Algorithm != string(jose.RS256) || key.Use != "sig" || !key.IsPublic() {
			t.Fatal("JWKS contains a non-public or incomplete signing key")
		}
	}
	return jwks
}

func assertComponentJWKSKeyIDs(t *testing.T, runtime *Runtime, want ...string) {
	t.Helper()
	jwks := componentJWKS(t, runtime)
	got := make([]string, 0, len(jwks.Keys))
	for _, key := range jwks.Keys {
		got = append(got, key.KeyID)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("JWKS key ids = %v, want %v", got, want)
	}
}

func assertComponentSignature(
	t *testing.T,
	jwks jose.JSONWebKeySet,
	keyID string,
	compact string,
	wantPayload []byte,
) {
	t.Helper()
	keys := jwks.Key(keyID)
	if len(keys) != 1 {
		t.Fatalf("JWKS key matches for %q = %d, want 1", keyID, len(keys))
	}
	signed, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parse signature: %v", err)
	}
	payload, err := signed.Verify(keys[0].Key)
	if err != nil {
		t.Fatalf("verify pre-rotation signature: %v", err)
	}
	if string(payload) != string(wantPayload) {
		t.Fatalf("verified payload = %q, want %q", payload, wantPayload)
	}
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
