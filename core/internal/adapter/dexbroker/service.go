//go:build dexbroker

package dexbroker

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"reflect"
	"slices"
	"sync"
	"time"
)

var (
	// ErrInvalidService indicates incomplete or unsafe service input.
	ErrInvalidService = errors.New("invalid dex broker service")
	// ErrServiceStarted indicates that a service instance starts at most once.
	ErrServiceStarted = errors.New("dex broker service already started")
	// ErrServiceNotStarted indicates shutdown before a successful start.
	ErrServiceNotStarted = errors.New("dex broker service not started")
	// ErrServiceStart indicates that the embedded runtime could not be created.
	ErrServiceStart = errors.New("start dex broker service")
	// ErrConfigurationCheck indicates missing, changed, or unapproved immutable configuration.
	ErrConfigurationCheck = errors.New("check dex broker immutable configuration")
)

// ServiceOptions is the product-owned broker runtime contract. It deliberately
// contains no version-specific Dex type.
type ServiceOptions struct {
	Issuer                    string
	OIDCConnectors            []OIDCConnectorOptions
	Clients                   []ClientOptions
	ExpectedFingerprint       ConfigurationFingerprint
	IDTokenLifetime           time.Duration
	AuthRequestLifetime       time.Duration
	SigningKeyRotation        time.Duration
	GarbageCollectionInterval time.Duration
}

// Service lazily owns one embedded runtime. The PostgreSQL handle remains
// borrowed until every handler and component worker has joined.
type Service struct {
	options  ServiceOptions
	resource *PostgreSQLResource
	logger   *slog.Logger

	mu         sync.Mutex
	started    bool
	cancel     context.CancelFunc
	runtime    *Runtime
	done       chan error
	newRuntime runtimeFactory
	// startDelays and backgroundDelays space the start attempts (defaults
	// startRetryDelays and backgroundRetryDelays; tests shorten them).
	startDelays      []time.Duration
	backgroundDelays []time.Duration
}

type runtimeFactory func(context.Context, componentOptions, componentResources) (*Runtime, error)

// NewService validates immutable dependencies without opening the embedded
// runtime or starting background work.
func NewService(
	options ServiceOptions,
	resource *PostgreSQLResource,
	logger *slog.Logger,
) (*Service, error) {
	if !validServiceOptions(options) || nilServiceDependency(resource) || logger == nil {
		return nil, ErrInvalidService
	}
	options.OIDCConnectors = slices.Clone(options.OIDCConnectors)
	options.Clients = slices.Clone(options.Clients)
	return &Service{
		options: options, resource: resource, logger: logger, newRuntime: newDexRuntime,
		startDelays:      slices.Clone(startRetryDelays),
		backgroundDelays: slices.Clone(backgroundRetryDelays),
	}, nil
}

func validServiceOptions(options ServiceOptions) bool {
	return validFingerprintOptions(options) &&
		options.ExpectedFingerprint != (ConfigurationFingerprint{})
}

// CheckConfiguration re-reads bounded secret files and proves that the exact
// immutable connector/client configuration matches the approved fingerprint.
func (service *Service) CheckConfiguration(ctx context.Context) error {
	if service == nil || ctx == nil || ctx.Err() != nil || !validServiceOptions(service.options) {
		return ErrConfigurationCheck
	}
	configuration, fingerprint, err := resolveConfiguration(service.options)
	clearComponentConfiguration(&configuration)
	if err != nil || !fingerprintMatches(service.options.ExpectedFingerprint, fingerprint) {
		return ErrConfigurationCheck
	}
	return nil
}

// CheckSigner performs one bounded cryptographic proof against the active
// signer and the exact public keys it currently publishes.
func (service *Service) CheckSigner(ctx context.Context) error {
	if service == nil || ctx == nil || ctx.Err() != nil {
		return ErrSignerCheck
	}
	service.mu.Lock()
	runtime := service.runtime
	service.mu.Unlock()
	if runtime == nil {
		return ErrSignerCheck
	}
	return runtime.CheckSigner(ctx)
}

func nilServiceDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// Start borrows prepared storage and constructs the pinned runtime. No listener
// is opened at this boundary. Invalid or unapproved configuration fails at
// once. A runtime that cannot start for a transient reason (the upstream
// provider's discovery unreachable, a database or signer outage) does not
// fail Start: after a short synchronous budget the service keeps retrying in
// the background, serving 503 and reporting not ready meanwhile, so a
// provider outage never stops the rest of a Core process (TD-CORE-161).
func (service *Service) Start(ctx context.Context) error {
	if service == nil || ctx == nil || ctx.Err() != nil ||
		!validServiceOptions(service.options) || nilServiceDependency(service.resource) || service.logger == nil ||
		service.newRuntime == nil {
		return ErrInvalidService
	}
	service.mu.Lock()
	if service.started {
		service.mu.Unlock()
		return ErrServiceStarted
	}
	service.started = true
	service.mu.Unlock()

	if _, err := service.resolveApprovedConfiguration(); err != nil {
		return ErrServiceStart
	}
	storage, release, err := service.resource.borrowStorage(ctx)
	if err != nil {
		return ErrServiceStart
	}
	ownedCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	resources := componentResources{storage: storage}
	runtime, err := service.startRuntime(ctx, ownedCtx, resources)
	if err != nil && !errors.Is(err, ErrComponentStart) {
		cancel()
		release()
		return ErrServiceStart
	}

	done := make(chan error, 1)
	service.mu.Lock()
	service.cancel = cancel
	service.runtime = runtime
	service.done = done
	service.mu.Unlock()
	if runtime == nil {
		service.logger.WarnContext(ctx, "identity broker not started; retrying in the background")
		go service.retryInBackground(ownedCtx, resources, release, cancel, done)
		return nil
	}
	go service.join(runtime, release, cancel, done)
	return nil
}

// join publishes the runtime's result once it has stopped and released its
// storage borrow.
func (service *Service) join(runtime *Runtime, release func(), cancel context.CancelFunc, done chan<- error) {
	<-runtime.Done()
	result := terminalRuntimeResult(runtime)
	release()
	cancel()
	done <- result
	close(done)
}

// retryInBackground starts the runtime once the transient cause clears. It
// never ends the service on its own: a configuration that stopped matching
// its approval keeps it degraded too (the configuration check reports it),
// as it would a running broker. Only Shutdown stops it.
func (service *Service) retryInBackground(
	ownedCtx context.Context,
	resources componentResources,
	release func(),
	cancel context.CancelFunc,
	done chan<- error,
) {
	stopped := func() {
		release()
		done <- nil
		close(done)
	}
	delays := service.backgroundDelays
	for attempt := 0; ; attempt++ {
		timer := time.NewTimer(delays[min(attempt, len(delays)-1)])
		select {
		case <-ownedCtx.Done():
			timer.Stop()
			stopped()
			return
		case <-timer.C:
		}
		runtime, err := service.attemptRuntime(ownedCtx, resources)
		if runtime != nil {
			// Started, possibly while Shutdown cancelled ownedCtx: the
			// runtime then stops at once and join reports it.
			service.mu.Lock()
			service.runtime = runtime
			service.mu.Unlock()
			service.logger.InfoContext(ownedCtx, "identity broker started after retrying",
				"attempts", attempt+1)
			service.join(runtime, release, cancel, done)
			return
		}
		if ownedCtx.Err() != nil {
			stopped()
			return
		}
		code := "start"
		if errors.Is(err, ErrConfigurationCheck) {
			code = "configuration"
		}
		service.logger.WarnContext(ownedCtx, "identity broker start failed; retrying", "error_code", code,
			"attempt", attempt+1, "retry_in", delays[min(attempt+1, len(delays)-1)].String())
	}
}

// startRetryDelays bound how long Start itself waits for a transient failure
// to clear, such as connector discovery while a fresh node's network and DNS
// come up. Later attempts run in the background (backgroundRetryDelays).
var startRetryDelays = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}

// backgroundRetryDelays space the background attempts; the last one repeats.
var backgroundRetryDelays = []time.Duration{15 * time.Second, 30 * time.Second, time.Minute}

// startRuntime builds the runtime, retrying a component start failure with a
// fresh copy of the approved configuration each time. Invalid input fails at
// once.
func (service *Service) startRuntime(
	ctx context.Context,
	ownedCtx context.Context,
	resources componentResources,
) (*Runtime, error) {
	for attempt := 0; ; attempt++ {
		runtime, err := service.attemptRuntime(ownedCtx, resources)
		if err == nil {
			return runtime, nil
		}
		if !errors.Is(err, ErrComponentStart) || attempt >= len(service.startDelays) {
			return nil, err
		}
		delay := service.startDelays[attempt]
		service.logger.WarnContext(ctx, "identity broker start failed; retrying",
			"attempt", attempt+1, "retry_in", delay.String())
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// attemptRuntime builds the runtime once from a fresh copy of the approved
// configuration.
func (service *Service) attemptRuntime(ownedCtx context.Context, resources componentResources) (*Runtime, error) {
	configuration, err := service.resolveApprovedConfiguration()
	if err != nil {
		return nil, err
	}
	runtime, err := service.newRuntime(ownedCtx, componentOptions{
		issuer:                     service.options.Issuer,
		configuration:              configuration,
		idTokensValidFor:           service.options.IDTokenLifetime,
		authRequestsValidFor:       service.options.AuthRequestLifetime,
		signingKeysRotateAfter:     service.options.SigningKeyRotation,
		garbageCollectionFrequency: service.options.GarbageCollectionInterval,
		logger:                     service.logger,
	}, resources)
	clearComponentConfiguration(&configuration)
	return runtime, err
}

func (service *Service) resolveApprovedConfiguration() (componentConfiguration, error) {
	configuration, fingerprint, err := resolveConfiguration(service.options)
	if err != nil || !fingerprintMatches(service.options.ExpectedFingerprint, fingerprint) {
		clearComponentConfiguration(&configuration)
		return componentConfiguration{}, ErrConfigurationCheck
	}
	return configuration, nil
}

func terminalRuntimeResult(runtime *Runtime) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.result
}

// Handler returns the fail-closed broker handler for a future product-owned
// routing boundary. This step intentionally does not register it on a listener.
func (service *Service) Handler() http.Handler {
	if service == nil {
		return http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			writeUnavailable(response)
		})
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.runtime == nil {
		return http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			writeUnavailable(response)
		})
	}
	return service.runtime.Handler()
}

// ServeHTTP resolves the current fail-closed runtime for each request. The
// listener starts after this service and stops before it, so a request never
// retains a stale runtime handler across the lifecycle boundary.
func (service *Service) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	service.Handler().ServeHTTP(response, request)
}

// Ready reports whether the embedded runtime is admitting requests.
func (service *Service) Ready() bool {
	if service == nil {
		return false
	}
	service.mu.Lock()
	runtime := service.runtime
	service.mu.Unlock()
	return runtime != nil && runtime.Ready()
}

// Done publishes a result only after the runtime has joined and released its
// long-lived PostgreSQL borrow.
func (service *Service) Done() <-chan error {
	if service == nil {
		return nil
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	return service.done
}

// Shutdown fences the runtime through its owned cancellation context. Done is
// the authoritative bounded join path used by the application lifecycle.
func (service *Service) Shutdown(ctx context.Context) error {
	if service == nil || ctx == nil {
		return ErrInvalidService
	}
	service.mu.Lock()
	if !service.started || service.cancel == nil {
		service.mu.Unlock()
		return ErrServiceNotStarted
	}
	cancel := service.cancel
	service.mu.Unlock()
	cancel()
	return nil
}

// String conceals the owned runtime graph.
func (*Service) String() string { return "[REDACTED]" }

// GoString conceals the owned runtime graph.
func (*Service) GoString() string { return "dexbroker.Service([REDACTED])" }

// LogValue prevents the owned graph from entering structured logs.
func (*Service) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON refuses accidental publication of the owned graph.
func (*Service) MarshalJSON() ([]byte, error) { return nil, ErrInvalidService }

// String conceals broker settings.
func (ServiceOptions) String() string { return "[REDACTED]" }

// GoString conceals detailed broker settings.
func (ServiceOptions) GoString() string { return "dexbroker.ServiceOptions([REDACTED])" }

// LogValue conceals broker settings in structured logs.
func (ServiceOptions) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

var _ http.Handler = (*Service)(nil)

// MarshalJSON refuses accidental publication of broker settings.
func (ServiceOptions) MarshalJSON() ([]byte, error) { return nil, ErrInvalidService }

var _ json.Marshaler = ServiceOptions{}
var _ json.Marshaler = (*Service)(nil)
