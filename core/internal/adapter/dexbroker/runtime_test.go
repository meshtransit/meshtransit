package dexbroker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewRuntimeRejectsInvalidComponents(t *testing.T) {
	t.Parallel()

	var typedNil *runtimeFixture
	tests := []struct {
		name      string
		component runtimeComponent
	}{
		{name: "nil component"},
		{name: "typed nil component", component: typedNil},
		{name: "nil done channel", component: &runtimeFixture{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := newRuntime(test.component); !errors.Is(err, ErrInvalidRuntime) {
				t.Fatalf("newRuntime() error = %v, want %v", err, ErrInvalidRuntime)
			}
		})
	}
}

func TestRuntimeServesWhileReady(t *testing.T) {
	t.Parallel()

	component := newRuntimeFixture(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	runtime := mustRuntime(t, component)
	t.Cleanup(func() { shutdownRuntime(t, runtime, component) })

	response := httptest.NewRecorder()
	runtime.Handler().ServeHTTP(
		response,
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://issuer.example/dex", nil),
	)
	if response.Code != http.StatusNoContent || !runtime.Ready() || component.calls.Load() != 1 {
		t.Fatalf("broker response = %d, ready = %t, calls = %d", response.Code, runtime.Ready(), component.calls.Load())
	}
}

func TestRuntimeSignerCheckIsDrainedBeforeComponentStop(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{})
	release := make(chan struct{})
	component := newRuntimeFixture(http.NotFoundHandler())
	component.signerCheck = func(context.Context) error {
		close(entered)
		<-release
		return nil
	}
	component.completeOnStop = true
	runtime := mustRuntime(t, component)

	checkResult := make(chan error, 1)
	go func() { checkResult <- runtime.CheckSigner(context.Background()) }()
	<-entered
	shutdownResult := make(chan error, 1)
	go func() { shutdownResult <- runtime.Shutdown(context.Background()) }()
	waitForNotReady(t, runtime)
	if component.stopCalls.Load() != 0 {
		t.Fatal("component stopped before admitted signer check drained")
	}

	close(release)
	if err := <-checkResult; err != nil {
		t.Fatalf("CheckSigner() error = %v", err)
	}
	if err := <-shutdownResult; err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if component.signerCalls.Load() != 1 || component.stopCalls.Load() != 1 {
		t.Fatal("signer check or component stop did not complete exactly once")
	}
}

func TestRuntimeShutdownFencesAdmissionAndDrainsHandlers(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{})
	release := make(chan struct{})
	component := newRuntimeFixture(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		response.WriteHeader(http.StatusNoContent)
	}))
	component.completeOnStop = true
	runtime := mustRuntime(t, component)

	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		runtime.ServeHTTP(
			httptest.NewRecorder(),
			httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://issuer.example/dex", nil),
		)
	}()
	<-entered

	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- runtime.Shutdown(t.Context()) }()
	waitForNotReady(t, runtime)

	rejected := httptest.NewRecorder()
	runtime.ServeHTTP(
		rejected,
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://issuer.example/dex/auth", nil),
	)
	if rejected.Code != http.StatusServiceUnavailable || rejected.Header().Get("Cache-Control") != "no-store" ||
		rejected.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("rejected response = %d, headers = %v", rejected.Code, rejected.Header())
	}
	if component.stopCalls.Load() != 0 {
		t.Fatal("component stopped before admitted handler drained")
	}

	close(release)
	<-requestDone
	if err := <-shutdownDone; err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if component.stopCalls.Load() != 1 {
		t.Fatalf("stop calls = %d, want 1", component.stopCalls.Load())
	}
	select {
	case <-runtime.Done():
	default:
		t.Fatal("Done() did not close after complete join")
	}
}

func TestRuntimeParentCancellationFencesAdmissionAndDrainsHandlers(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	component := newRuntimeFixture(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		response.WriteHeader(http.StatusNoContent)
	}))
	component.completeOnStop = true
	parentDone := make(chan struct{})
	runtime, err := newRuntimeWithCancellation(component, parentDone)
	if err != nil {
		t.Fatalf("newRuntimeWithCancellation() error = %v", err)
	}
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		shutdownRuntime(t, runtime, component)
	})

	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		runtime.ServeHTTP(
			httptest.NewRecorder(),
			httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://issuer.example/dex", nil),
		)
	}()
	<-entered

	close(parentDone)
	waitForNotReady(t, runtime)
	if component.stopCalls.Load() != 0 {
		t.Fatal("component stopped before admitted handler drained")
	}

	releaseOnce.Do(func() { close(release) })
	<-requestDone
	select {
	case <-runtime.Done():
	case <-time.After(time.Second):
		t.Fatal("parent cancellation did not join runtime")
	}
	if component.stopCalls.Load() != 1 {
		t.Fatalf("stop calls = %d, want 1", component.stopCalls.Load())
	}
}

func TestRuntimeShutdownTimeoutDoesNotAbandonJoin(t *testing.T) {
	t.Parallel()

	componentErr := errors.New("component stopped with error")
	component := newRuntimeFixture(http.NotFoundHandler())
	component.result = componentErr
	runtime := mustRuntime(t, component)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := runtime.Shutdown(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Shutdown() error = %v, want context canceled", err)
	}
	waitForStop(t, component)
	component.complete()

	if err := runtime.Shutdown(t.Context()); !errors.Is(err, componentErr) {
		t.Fatalf("second Shutdown() error = %v, want component error", err)
	}
	if component.stopCalls.Load() != 1 {
		t.Fatalf("stop calls = %d, want 1", component.stopCalls.Load())
	}
}

func TestRuntimeConcurrentShutdownReturnsStableResult(t *testing.T) {
	t.Parallel()

	componentErr := errors.New("stable component error")
	component := newRuntimeFixture(http.NotFoundHandler())
	component.completeOnStop = true
	component.result = componentErr
	runtime := mustRuntime(t, component)

	const callers = 8
	results := make(chan error, callers)
	var callersReady sync.WaitGroup
	callersReady.Add(callers)
	start := make(chan struct{})
	for range callers {
		go func() {
			callersReady.Done()
			<-start
			results <- runtime.Shutdown(t.Context())
		}()
	}
	callersReady.Wait()
	close(start)
	for range callers {
		if err := <-results; !errors.Is(err, componentErr) {
			t.Fatalf("Shutdown() error = %v, want stable component error", err)
		}
	}
	if component.stopCalls.Load() != 1 {
		t.Fatalf("stop calls = %d, want 1", component.stopCalls.Load())
	}
}

func TestRuntimeUnexpectedCompletionFailsClosed(t *testing.T) {
	t.Parallel()

	component := newRuntimeFixture(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	runtime := mustRuntime(t, component)
	component.complete()
	<-runtime.Done()

	if runtime.Ready() {
		t.Fatal("Ready() = true after unexpected completion")
	}
	response := httptest.NewRecorder()
	runtime.ServeHTTP(
		response,
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://issuer.example/dex", nil),
	)
	if response.Code != http.StatusServiceUnavailable || component.calls.Load() != 0 {
		t.Fatalf("response = %d, component calls = %d", response.Code, component.calls.Load())
	}
	if err := runtime.Shutdown(t.Context()); !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("Shutdown() error = %v, want unavailable", err)
	}
}

func TestRuntimeInvalidValueFailsClosed(t *testing.T) {
	t.Parallel()

	var runtime *Runtime
	response := httptest.NewRecorder()
	runtime.Handler().ServeHTTP(
		response,
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://issuer.example/dex", nil),
	)
	if response.Code != http.StatusServiceUnavailable || runtime.Ready() || runtime.Done() != nil {
		t.Fatalf("invalid runtime response = %d, ready = %t, done = %v", response.Code, runtime.Ready(), runtime.Done())
	}
	if err := runtime.Shutdown(t.Context()); !errors.Is(err, ErrInvalidRuntime) {
		t.Fatalf("Shutdown() error = %v, want invalid runtime", err)
	}
	invalid := &Runtime{}
	if err := invalid.Shutdown(t.Context()); !errors.Is(err, ErrInvalidRuntime) {
		t.Fatalf("zero-value Shutdown() error = %v, want invalid runtime", err)
	}
}

func TestRuntimeConcealsOwnedGraph(t *testing.T) {
	t.Parallel()

	component := newRuntimeFixture(http.NotFoundHandler())
	component.completeOnStop = true
	runtime := mustRuntime(t, component)
	t.Cleanup(func() { shutdownRuntime(t, runtime, component) })

	if fmt.Sprint(runtime) != "[REDACTED]" || fmt.Sprintf("%#v", runtime) != "dexbroker.Runtime([REDACTED])" {
		t.Fatal("runtime formatting disclosed its owned graph")
	}
	if runtime.LogValue().Kind() != slog.KindString || runtime.LogValue().String() != "[REDACTED]" {
		t.Fatal("runtime log value disclosed its owned graph")
	}
	if _, err := json.Marshal(runtime); !errors.Is(err, ErrInvalidRuntime) {
		t.Fatalf("json.Marshal() error = %v, want refusal", err)
	}
}

type runtimeFixture struct {
	handler        http.Handler
	doneChannel    chan struct{}
	completeOnce   sync.Once
	completeOnStop bool
	result         error
	signerErr      error
	signerCheck    func(context.Context) error
	calls          atomic.Int64
	signerCalls    atomic.Int64
	stopCalls      atomic.Int64
}

func newRuntimeFixture(handler http.Handler) *runtimeFixture {
	return &runtimeFixture{handler: handler, doneChannel: make(chan struct{})}
}

func (fixture *runtimeFixture) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	fixture.calls.Add(1)
	fixture.handler.ServeHTTP(response, request)
}

func (fixture *runtimeFixture) checkSigner(ctx context.Context) error {
	fixture.signerCalls.Add(1)
	if fixture.signerCheck != nil {
		return fixture.signerCheck(ctx)
	}
	return fixture.signerErr
}

func (fixture *runtimeFixture) stop() {
	fixture.stopCalls.Add(1)
	if fixture.completeOnStop {
		fixture.complete()
	}
}

func (fixture *runtimeFixture) done() <-chan struct{} { return fixture.doneChannel }

func (fixture *runtimeFixture) err() error { return fixture.result }

func (fixture *runtimeFixture) complete() {
	fixture.completeOnce.Do(func() { close(fixture.doneChannel) })
}

func mustRuntime(t *testing.T, component runtimeComponent) *Runtime {
	t.Helper()

	runtime, err := newRuntime(component)
	if err != nil {
		t.Fatalf("newRuntime() error = %v", err)
	}
	return runtime
}

func shutdownRuntime(t *testing.T, runtime *Runtime, component *runtimeFixture) {
	t.Helper()

	component.completeOnStop = true
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := runtime.Shutdown(ctx); err != nil {
		t.Errorf("cleanup Shutdown() error = %v", err)
	}
}

func waitForNotReady(t *testing.T, runtime *Runtime) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for runtime.Ready() {
		if time.Now().After(deadline) {
			t.Fatal("runtime remained ready")
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForStop(t *testing.T, component *runtimeFixture) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for component.stopCalls.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("component was not stopped")
		}
		time.Sleep(time.Millisecond)
	}
}
