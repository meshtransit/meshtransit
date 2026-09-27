package dexbroker

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"reflect"
	"sync"
)

var (
	// ErrInvalidRuntime indicates a missing runtime dependency or an invalid call.
	ErrInvalidRuntime = errors.New("invalid dex broker runtime")
	// ErrRuntimeUnavailable indicates that the owned broker component stopped unexpectedly.
	ErrRuntimeUnavailable = errors.New("dex broker runtime unavailable")
	// ErrSignerCheck indicates that token signing or its published verification keys are unavailable.
	ErrSignerCheck = errors.New("check dex broker signer")
)

// Runtime owns admission to one embedded broker component and its complete
// shutdown join. It does not own a network listener.
type Runtime struct {
	mu            sync.Mutex
	component     runtimeComponent
	componentDone <-chan struct{}
	parentDone    <-chan struct{}
	inFlight      sync.WaitGroup
	stopOnce      sync.Once
	stop          chan struct{}
	joined        chan struct{}
	accepting     bool
	stopping      bool
	result        error
}

// runtimeComponent is implemented only by the version-specific Dex bridge.
// Done must close after every background task owned by the component exits;
// Err must be stable after Done closes.
type runtimeComponent interface {
	http.Handler
	checkSigner(context.Context) error
	stop()
	done() <-chan struct{}
	err() error
}

// CheckSigner proves that the running component can publish its current JWKS,
// sign a bounded probe, and verify that signature with the published keys.
func (runtime *Runtime) CheckSigner(ctx context.Context) error {
	if runtime == nil || ctx == nil || ctx.Err() != nil {
		return ErrSignerCheck
	}
	runtime.mu.Lock()
	if !runtime.accepting || runtime.component == nil || runtime.componentCompletedLocked() {
		runtime.accepting = false
		runtime.mu.Unlock()
		return ErrSignerCheck
	}
	runtime.inFlight.Add(1)
	component := runtime.component
	runtime.mu.Unlock()
	defer runtime.inFlight.Done()

	if err := component.checkSigner(ctx); err != nil {
		return ErrSignerCheck
	}
	return nil
}

func newRuntime(component runtimeComponent) (*Runtime, error) {
	return newRuntimeWithCancellation(component, nil)
}

func newRuntimeWithCancellation(component runtimeComponent, parentDone <-chan struct{}) (*Runtime, error) {
	if isNilComponent(component) {
		return nil, ErrInvalidRuntime
	}
	componentDone := component.done()
	if componentDone == nil {
		return nil, ErrInvalidRuntime
	}
	runtime := &Runtime{
		component:     component,
		componentDone: componentDone,
		parentDone:    parentDone,
		stop:          make(chan struct{}),
		joined:        make(chan struct{}),
		accepting:     true,
	}
	go runtime.ownLifecycle()
	return runtime, nil
}

func isNilComponent(component runtimeComponent) bool {
	if component == nil {
		return true
	}
	value := reflect.ValueOf(component)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// Handler returns the fail-closed HTTP boundary. Requests admitted before
// shutdown are allowed to finish; later requests receive a generic 503.
func (runtime *Runtime) Handler() http.Handler {
	return runtime
}

// ServeHTTP implements the broker admission fence.
func (runtime *Runtime) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if runtime == nil {
		writeUnavailable(response)
		return
	}
	runtime.mu.Lock()
	if !runtime.accepting || runtime.component == nil || runtime.componentCompletedLocked() {
		runtime.accepting = false
		runtime.mu.Unlock()
		writeUnavailable(response)
		return
	}
	runtime.inFlight.Add(1)
	component := runtime.component
	runtime.mu.Unlock()
	defer runtime.inFlight.Done()

	component.ServeHTTP(response, request)
}

func writeUnavailable(response http.ResponseWriter) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
}

// Ready reports whether this runtime is admitting new broker requests.
func (runtime *Runtime) Ready() bool {
	if runtime == nil {
		return false
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.componentCompletedLocked() {
		runtime.accepting = false
	}
	return runtime.accepting
}

// Done closes only after admitted handlers and all component-owned background
// work have joined. It is nil for an invalid zero-value runtime.
func (runtime *Runtime) Done() <-chan struct{} {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.joined
}

// Shutdown fences admission, drains admitted handlers and signer checks, stops
// the component, and waits for its complete join. A caller timeout does not
// abandon cleanup; a later call can continue waiting for the same stable result.
func (runtime *Runtime) Shutdown(ctx context.Context) error {
	if runtime == nil || ctx == nil {
		return ErrInvalidRuntime
	}
	runtime.mu.Lock()
	if runtime.component == nil || runtime.componentDone == nil || runtime.stop == nil || runtime.joined == nil {
		runtime.mu.Unlock()
		return ErrInvalidRuntime
	}
	runtime.mu.Unlock()

	runtime.requestStop()

	select {
	case <-runtime.joined:
		runtime.mu.Lock()
		result := runtime.result
		runtime.mu.Unlock()
		return result
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (runtime *Runtime) requestStop() {
	runtime.stopOnce.Do(func() {
		runtime.mu.Lock()
		runtime.accepting = false
		runtime.stopping = true
		close(runtime.stop)
		runtime.mu.Unlock()
	})
}

func (runtime *Runtime) ownLifecycle() {
	select {
	case <-runtime.stop:
		runtime.stopAndJoin()
	case <-runtime.parentDone:
		runtime.requestStop()
		runtime.stopAndJoin()
	case <-runtime.componentDone:
		runtime.mu.Lock()
		runtime.accepting = false
		stopping := runtime.stopping
		runtime.mu.Unlock()
		runtime.inFlight.Wait()
		runtime.finish(runtime.component.err(), !stopping)
	}
}

func (runtime *Runtime) stopAndJoin() {
	runtime.inFlight.Wait()
	runtime.component.stop()
	<-runtime.componentDone
	runtime.finish(runtime.component.err(), false)
}

func (runtime *Runtime) componentCompletedLocked() bool {
	if runtime.componentDone == nil {
		return true
	}
	select {
	case <-runtime.componentDone:
		return true
	default:
		return false
	}
}

func (runtime *Runtime) finish(result error, unexpected bool) {
	if unexpected && result == nil {
		result = ErrRuntimeUnavailable
	}
	runtime.mu.Lock()
	runtime.accepting = false
	runtime.result = result
	close(runtime.joined)
	runtime.mu.Unlock()
}

// String conceals the embedded handler and lifecycle graph.
func (*Runtime) String() string { return "[REDACTED]" }

// GoString conceals the embedded handler and lifecycle graph.
func (*Runtime) GoString() string { return "dexbroker.Runtime([REDACTED])" }

// LogValue prevents the embedded handler and lifecycle graph from entering logs.
func (*Runtime) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON refuses accidental publication of the embedded runtime graph.
func (*Runtime) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRuntime }
