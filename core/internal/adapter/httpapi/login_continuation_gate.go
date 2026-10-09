package httpapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"strconv"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/adapter/oidc"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/oidcauth"
	"github.com/meshtransit/meshtransit/core/internal/platform/ratelimit"
)

// LoginContinuationPreparePath issues only current-cookie-bound intent, not authority.
const LoginContinuationPreparePath = "/auth/v1/login/continue/prepare"

var (
	// ErrInvalidLoginContinuation conceals malformed HTTP/CSRF/capsule input or config.
	ErrInvalidLoginContinuation = errors.New("http api: invalid login continuation")
	// ErrLoginContinuationLimited reports exhausted shared budgets, without subject material.
	ErrLoginContinuationLimited = errors.New("http api: login continuation limited")
	// ErrLoginContinuationSaturated reports non-queuing local admission rejection.
	ErrLoginContinuationSaturated = errors.New("http api: login continuation saturated")
	// ErrLoginContinuationUnavailable conceals cancellation, transport and dependency failures.
	ErrLoginContinuationUnavailable = errors.New("http api: login continuation unavailable")
)

// LoginContinuationOperation is a closed private HTTP-admission phase.
type LoginContinuationOperation uint8

const (
	// LoginContinuationOperationUnknown coalesces unsupported values.
	LoginContinuationOperationUnknown LoginContinuationOperation = iota
	// LoginContinuationPrepare prepares no-grant browser intent.
	LoginContinuationPrepare
	// LoginContinuationRead admits untrusted syntax, never durable proof.
	LoginContinuationRead
)

// String returns only closed metric labels.
func (operation LoginContinuationOperation) String() string {
	switch operation {
	case LoginContinuationPrepare:
		return "prepare"
	case LoginContinuationRead:
		return "read"
	default:
		return "unknown"
	}
}

// LoginContinuationOutcome must not be interpreted as authentication or a grant.
type LoginContinuationOutcome uint8

const (
	// LoginContinuationUnknown coalesces unsupported values.
	LoginContinuationUnknown LoginContinuationOutcome = iota
	// LoginContinuationPrepared means proof JSON was written, not authority committed.
	LoginContinuationPrepared
	// LoginContinuationInputReleased means syntax was admitted, not possession verified.
	LoginContinuationInputReleased
	// LoginContinuationInvalid means HTTP, proof, capsule or time failed validation.
	LoginContinuationInvalid
	// LoginContinuationLimited means shared source or state budget was exhausted.
	LoginContinuationLimited
	// LoginContinuationSaturated means local capacity was full, with no queue.
	LoginContinuationSaturated
	// LoginContinuationUnavailable means canceled or unavailable dependency/transport.
	LoginContinuationUnavailable
)

// String returns only closed metric labels even for arbitrary numeric values.
func (outcome LoginContinuationOutcome) String() string {
	switch outcome {
	case LoginContinuationPrepared:
		return "prepared"
	case LoginContinuationInputReleased:
		return "input_released"
	case LoginContinuationInvalid:
		return "invalid"
	case LoginContinuationLimited:
		return "limited"
	case LoginContinuationSaturated:
		return "saturated"
	case LoginContinuationUnavailable:
		return "unavailable"
	default:
		return "unknown"
	}
}

// LoginContinuationObserver receives only closed phases/outcomes and numeric duration.
// It must be private, bounded, nonblocking, concurrency-safe and perform no external I/O.
type LoginContinuationObserver interface {
	ObserveLoginContinuation(LoginContinuationOperation, LoginContinuationOutcome, time.Duration)
}

// LoginContinuationGateOptions supplies explicit no-grant browser-admission dependencies.
// All replicas must use identical route/key/policies and shared Redis counters.
type LoginContinuationGateOptions struct {
	CSRF                  *oidc.LoginContinuationGuard
	Capsule               *LoginCallbackCapsuleCodec
	RateLimitSubjects     RateLimitSubjectDigester
	RateLimiter           ManagementRateLimiter
	SourceRateLimit       ratelimit.Policy
	StateRateLimit        ratelimit.Policy
	TrustedProxyPrefixes  []netip.Prefix
	Clock                 oidcauth.StartClock
	Observer              LoginContinuationObserver
	RequestTimeout        time.Duration
	MaxConcurrentRequests int
}

// LoginContinuationGate prepares intent or reads syntax without claim/exchange/issuance.
// It registers no public route and owns no per-browser state, queue or goroutine.
type LoginContinuationGate struct {
	options   LoginContinuationGateOptions
	host      string
	clientIPs clientIPResolver
	// Only run acquires/releases these capacity tokens; the channel is never closed.
	// This is a non-queuing semaphore, not a work buffer or authentication lock.
	slots chan struct{}
}

// NewLoginContinuationGate rejects incomplete, mismatched or typed-nil dependencies before effects.
func NewLoginContinuationGate(options LoginContinuationGateOptions) (*LoginContinuationGate, error) {
	if !options.CSRF.IsValid() || !options.Capsule.valid() {
		return nil, ErrInvalidLoginContinuation
	}
	missingBudget := nilContinuationDependency(options.RateLimitSubjects) || nilContinuationDependency(options.RateLimiter)
	missingTelemetry := nilContinuationDependency(options.Clock) || nilContinuationDependency(options.Observer)
	validBounds := options.RequestTimeout > 0 && options.RequestTimeout <= 30*time.Second &&
		options.MaxConcurrentRequests >= 1 && options.MaxConcurrentRequests <= 128
	if missingBudget || missingTelemetry || !validBounds ||
		!options.SourceRateLimit.IsValid() || !options.StateRateLimit.IsValid() {
		return nil, ErrInvalidLoginContinuation
	}
	binding, err := callbackRouteFingerprint(options.CSRF.Route())
	if err != nil || binding != options.Capsule.binding {
		return nil, ErrInvalidLoginContinuation
	}
	origin, err := url.Parse(options.CSRF.Origin())
	if err != nil || origin.Host == "" {
		return nil, ErrInvalidLoginContinuation
	}
	clientIPs, err := newClientIPResolver(options.TrustedProxyPrefixes)
	if err != nil {
		return nil, ErrInvalidLoginContinuation
	}
	options.TrustedProxyPrefixes = nil // The resolver owns the immutable defensive copy.
	return &LoginContinuationGate{options: options, host: origin.Host, clientIPs: clientIPs,
		slots: make(chan struct{}, options.MaxConcurrentRequests)}, nil
}

// Prepare writes only no-store CSRF JSON for an authenticated live capsule transport.
// Pre-release failure writes no body/status/cookie; caller maps its closed error safely.
// Write failure may follow partial proof delivery; never retry or rewrite that response.
// Call this only with a pristine writer and an independently bounded whole-request pipeline.
func (gate *LoginContinuationGate) Prepare(response http.ResponseWriter, request *http.Request) error {
	return gate.run(continuationHTTPCall{response: response, request: request, operation: LoginContinuationPrepare,
		work: func(ctx context.Context) error {
			if _, err := gate.input(ctx, response, request); err != nil {
				return err
			}
			proof, err := gate.options.CSRF.Prepare(ctx, request.Header, gate.options.Clock.Now())
			if err != nil {
				return ErrLoginContinuationUnavailable
			}
			if _, err := gate.options.Capsule.Open(ctx, request.Header, gate.options.Clock.Now()); err != nil {
				return continuationCapsuleError(err)
			}
			token, remaining, err := proof.Token(gate.options.Clock.Now())
			if err != nil {
				return ErrInvalidLoginContinuation
			}
			body, err := json.Marshal(struct {
				Token     string `json:"csrf_token"`
				ExpiresIn int    `json:"expires_in"`
			}{Token: token, ExpiresIn: remaining})
			if err != nil || ctx.Err() != nil {
				return ErrLoginContinuationUnavailable
			}
			response.WriteHeader(http.StatusOK)
			if written, err := response.Write(body); err != nil || written != len(body) {
				return ErrLoginContinuationUnavailable
			}
			return nil
		}})
}

// Read admits exact POST/CSRF/current-cookie syntax only, not authenticated browser possession.
// It writes no status/body/cookie and never claims/exchanges/issues; a future caller must
// freshly verify durable proof and own the entire application/response deadline and capacity.
func (gate *LoginContinuationGate) Read(
	response http.ResponseWriter,
	request *http.Request,
) (LoginCallbackInput, error) {
	var input LoginCallbackInput
	err := gate.run(continuationHTTPCall{response: response, request: request, operation: LoginContinuationRead,
		work: func(ctx context.Context) error {
			result, err := gate.input(ctx, response, request)
			if err != nil {
				return err
			}
			input = result
			return nil
		}})
	if err != nil {
		return LoginCallbackInput{}, err
	}
	return input, nil
}

type continuationHTTPCall struct {
	response  http.ResponseWriter
	request   *http.Request
	operation LoginContinuationOperation
	work      func(context.Context) error
}

func (gate *LoginContinuationGate) run(call continuationHTTPCall) (resultErr error) {
	if gate == nil || nilContinuationDependency(call.response) || !gate.options.CSRF.IsValid() ||
		!gate.options.Capsule.valid() || nilContinuationDependency(gate.options.Observer) || gate.slots == nil {
		return ErrLoginContinuationUnavailable
	}
	started := time.Now()
	defer func() {
		gate.options.Observer.ObserveLoginContinuation(call.operation, continuationHTTPOutcome(call.operation, resultErr),
			time.Since(started))
	}()
	setLoginSecurityHeaders(call.response.Header())
	if !gate.validRequest(call.request, call.operation) {
		return ErrInvalidLoginContinuation
	}
	ctx, cancel := context.WithTimeout(call.request.Context(), gate.options.RequestTimeout)
	defer cancel()
	if ctx.Err() != nil {
		return ErrLoginContinuationUnavailable
	}
	select {
	case <-ctx.Done():
		return ErrLoginContinuationUnavailable
	case gate.slots <- struct{}{}:
		defer func() { <-gate.slots }()
	default:
		return ErrLoginContinuationSaturated
	}
	deadline, hasDeadline := ctx.Deadline()
	controller := http.NewResponseController(call.response)
	if !hasDeadline || controller.SetReadDeadline(deadline) != nil || controller.SetWriteDeadline(deadline) != nil {
		return ErrLoginContinuationUnavailable
	}
	if err := gate.sourceBudget(ctx, call.response, call.request); err != nil {
		return err
	}
	if !validLoginBody(call.response, call.request) {
		return ErrInvalidLoginContinuation
	}
	if ctx.Err() != nil {
		return ErrLoginContinuationUnavailable
	}
	if err := call.work(ctx); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ErrLoginContinuationUnavailable
	}
	return nil
}

func (gate *LoginContinuationGate) validRequest(request *http.Request, operation LoginContinuationOperation) bool {
	if request == nil || request.URL == nil || request.TLS == nil {
		return false
	}
	validTLS := request.TLS.HandshakeComplete && request.TLS.Version >= tls.VersionTLS12
	validMethod := request.Method == http.MethodPost && request.Host == gate.host
	if !validTLS || !validMethod || !boundedLoginHeaders(request.Header) {
		return false
	}
	path := LoginContinuationPreparePath
	if operation == LoginContinuationRead {
		path = LoginCallbackContinuePath
	}
	if operation != LoginContinuationPrepare && operation != LoginContinuationRead {
		return false
	}
	if request.URL.Path != path || request.RequestURI != path || request.URL.RequestURI() != path {
		return false
	}
	alternateRouting := request.URL.Scheme != "" || request.URL.Host != "" || request.URL.User != nil ||
		request.URL.Opaque != "" || request.URL.Fragment != "" || request.URL.RawFragment != "" ||
		request.URL.RawPath != "" || request.URL.ForceQuery
	invalidBodyTransport := request.Body == nil || request.ContentLength < 0 ||
		request.ContentLength > maximumLoginBodyBytes || len(request.TransferEncoding) != 0 || len(request.Trailer) != 0
	if alternateRouting || invalidBodyTransport {
		return false
	}
	for _, name := range []string{"Authorization", "Host", "Transfer-Encoding", "Trailer"} {
		if _, present := request.Header[name]; present {
			return false
		}
	}
	// net/http retains Content-Length on ordinary incoming fixed-length requests.
	// Any adapter-supplied header must agree with the parsed transport length.
	if lengths, present := request.Header["Content-Length"]; present {
		if len(lengths) != 1 || lengths[0] != strconv.FormatInt(request.ContentLength, 10) {
			return false
		}
	}
	for name, expected := range map[string]string{"Origin": gate.options.CSRF.Origin(),
		"X-Meshtransit-Login": "v1", "Content-Type": "application/json"} {
		values := request.Header.Values(name)
		if len(values) != 1 || values[0] != expected {
			return false
		}
	}
	return validContinuationFetchMetadata(request.Header)
}

func validContinuationFetchMetadata(headers http.Header) bool {
	metadata := map[string][]string{"Sec-Fetch-Site": {"same-origin"}, "Sec-Fetch-Mode": {"same-origin", "cors"},
		"Sec-Fetch-Dest": {"empty"}}
	present := 0
	for name, allowed := range metadata {
		values, exists := headers[name]
		if !exists {
			continue
		}
		present++
		if len(values) != 1 {
			return false
		}
		valid := false
		for _, value := range allowed {
			valid = valid || values[0] == value
		}
		if !valid {
			return false
		}
	}
	_, userPresent := headers["Sec-Fetch-User"]
	return !userPresent && (present == 0 || present == len(metadata))
}

func (gate *LoginContinuationGate) input(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
) (LoginCallbackInput, error) {
	continuing := request.URL.Path == LoginCallbackContinuePath
	if continuing && gate.options.CSRF.Verify(request.Header, gate.options.Clock.Now()) != nil {
		return LoginCallbackInput{}, ErrInvalidLoginContinuation
	}
	input, err := gate.options.Capsule.Open(ctx, request.Header, gate.options.Clock.Now())
	if err != nil {
		return LoginCallbackInput{}, continuationCapsuleError(err)
	}
	route := gate.options.CSRF.Route()
	raw := "browser-login-continuation-state/v1\x00" + route.DeploymentID().String() + "\x00" +
		strconv.FormatInt(route.RecoveryEpoch(), 10) + "\x00" + input.State().Encoded()
	if err := gate.budget(ctx, continuationBudget{response: response, kind: ratelimit.SubjectAuthTransaction,
		raw: raw, policy: gate.options.StateRateLimit}); err != nil {
		return LoginCallbackInput{}, err
	}
	if continuing && gate.options.CSRF.Verify(request.Header, gate.options.Clock.Now()) != nil {
		return LoginCallbackInput{}, ErrInvalidLoginContinuation
	}
	// Reopen no-grant input at fresh release time: Redis waits must not extend its TTL.
	input, err = gate.options.Capsule.Open(ctx, request.Header, gate.options.Clock.Now())
	if err != nil {
		return LoginCallbackInput{}, continuationCapsuleError(err)
	}
	return input, nil
}

func (gate *LoginContinuationGate) sourceBudget(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
) error {
	address, err := gate.clientIPs.Resolve(request)
	if err != nil {
		return ErrInvalidLoginContinuation
	}
	raw := "browser-login-continuation-source/v1\x00" + gate.options.CSRF.Route().DeploymentID().String() +
		"\x00" + address.String()
	return gate.budget(ctx, continuationBudget{response: response, kind: ratelimit.SubjectSource,
		raw: raw, policy: gate.options.SourceRateLimit})
}

type continuationBudget struct {
	response http.ResponseWriter
	kind     ratelimit.SubjectKind
	raw      string
	policy   ratelimit.Policy
}

func (gate *LoginContinuationGate) budget(ctx context.Context, budget continuationBudget) error {
	if ctx.Err() != nil {
		return ErrLoginContinuationUnavailable
	}
	subject, err := gate.options.RateLimitSubjects.Subject(budget.kind, budget.raw)
	if err != nil || !subject.IsValid() || subject.Kind() != budget.kind {
		return ErrLoginContinuationUnavailable
	}
	decision, err := gate.options.RateLimiter.Allow(ctx, subject, budget.policy)
	if err != nil || ctx.Err() != nil || !decision.IsValid() || decision.Limit() != budget.policy.Capacity() {
		return ErrLoginContinuationUnavailable
	}
	if decision.RetryAfter() > 24*time.Hour {
		return ErrLoginContinuationUnavailable
	}
	setRateLimitHeaders(budget.response.Header(), decision)
	if !decision.Allowed() {
		return ErrLoginContinuationLimited
	}
	return nil
}

func continuationCapsuleError(err error) error {
	if errors.Is(err, ErrInvalidLoginCapsule) {
		return ErrInvalidLoginContinuation
	}
	return ErrLoginContinuationUnavailable
}

func continuationHTTPOutcome(operation LoginContinuationOperation, err error) LoginContinuationOutcome {
	switch {
	case errors.Is(err, ErrInvalidLoginContinuation):
		return LoginContinuationInvalid
	case errors.Is(err, ErrLoginContinuationLimited):
		return LoginContinuationLimited
	case errors.Is(err, ErrLoginContinuationSaturated):
		return LoginContinuationSaturated
	case err != nil:
		return LoginContinuationUnavailable
	case operation == LoginContinuationPrepare:
		return LoginContinuationPrepared
	case operation == LoginContinuationRead:
		return LoginContinuationInputReleased
	default:
		return LoginContinuationUnknown
	}
}

func nilContinuationDependency(dependency any) bool {
	if dependency == nil {
		return true
	}
	value := reflect.ValueOf(dependency)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
