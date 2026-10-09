package httpapi

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/meshtransit/meshtransit/core/internal/adapter/oidc"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/oidcauth"
	"github.com/meshtransit/meshtransit/core/internal/platform/ratelimit"
)

var (
	// ErrInvalidBrowserLogin conceals invalid construction or capture ingress/release.
	ErrInvalidBrowserLogin = errors.New("http api: invalid browser composition")
	// ErrBrowserCaptureUnavailable conceals cancellation, budget or transport failure.
	ErrBrowserCaptureUnavailable = errors.New("http api: browser capture unavailable")
	// ErrBrowserCaptureLimited means a shared no-grant capture budget rejected input.
	ErrBrowserCaptureLimited = errors.New("http api: browser capture limited")
	// ErrBrowserCaptureSaturated means capture capacity rejected without queueing.
	ErrBrowserCaptureSaturated = errors.New("http api: browser capture saturated")
)

// BrowserLoginKey supplies one dedicated resident key. Caller owns input erasure.
// Constructors copy material; never reuse transaction, Session or rate-limit keys.
type BrowserLoginKey struct {
	ID       string
	Material []byte
}

// BrowserLoginOptions is a private construction profile, not environment configuration.
// Application ports must share this exact clock/route and confirmed-only authority.
// No constructor effect or component accessor enables a public runtime route.
type BrowserLoginOptions struct {
	Route                                      oidcauth.Route
	Origin, ReturnPath                         string
	InitiationKey, CaptureKey, ContinuationKey BrowserLoginKey
	IntentLifetime, CaptureLifetime            time.Duration
	ContinuationLifetime                       time.Duration
	Admission                                  LoginRouteAdmission
	Starter                                    BrowserLoginStarter
	Callback                                   BrowserLoginCompleter
	RateLimitSubjects                          RateLimitSubjectDigester
	RateLimiter                                ManagementRateLimiter
	SourceRateLimit, StateRateLimit            ratelimit.Policy
	TrustedProxyPrefixes                       []netip.Prefix
	Clock                                      oidcauth.StartClock
	RequestTimeout                             time.Duration
	CompletionTimeout                          time.Duration
	MaxConcurrent                              int
}

// BrowserLogin coherently constructs private BFF components, not a public dispatcher.
// Components own their documented limits. Capture owns a separate non-queuing cap.
type BrowserLogin struct {
	start      *LoginStartHandler
	reader     *LoginCallbackReader
	capsule    *LoginCallbackCapsuleCodec
	gate       *LoginContinuationGate
	completion *LoginCompletion
	landing    *LoginContinuationLanding
	metrics    *prometheus.Registry
	capture    *BrowserCaptureTelemetry
	// Capture acquires/releases these tokens through submission; never close.
	slots chan struct{}
}

// NewBrowserLogin rejects incomplete ports and mixed key purposes before effects.
// It creates only resident components and an isolated registry; no global registration.
func NewBrowserLogin(options BrowserLoginOptions) (*BrowserLogin, error) {
	missingApplication := nilContinuationDependency(options.Admission) ||
		nilContinuationDependency(options.Starter) || nilContinuationDependency(options.Callback)
	missingBoundary := nilContinuationDependency(options.RateLimitSubjects) ||
		nilContinuationDependency(options.RateLimiter) || nilContinuationDependency(options.Clock)
	validRequestTimeout := options.RequestTimeout > 0 && options.RequestTimeout <= 30*time.Second
	validCapacity := options.MaxConcurrent >= 1 && options.MaxConcurrent <= 128
	validBounds := validRequestTimeout && validCapacity
	validCompletionBound := options.CompletionTimeout > 0 && options.CompletionTimeout <= 30*time.Second
	validTimeoutsAndCapacity := validBounds && validCompletionBound
	validProfile := validTimeoutsAndCapacity && distinctBrowserKeys(options) &&
		validBrowserProxies(options.TrustedProxyPrefixes)
	if missingApplication || missingBoundary || !validProfile {
		return nil, ErrInvalidBrowserLogin
	}
	initiation, err := oidc.NewLoginInitiationGuard(oidc.LoginInitiationOptions{
		Route: options.Route, Origin: options.Origin, KeyID: options.InitiationKey.ID,
		KeyMaterial: options.InitiationKey.Material, Lifetime: options.IntentLifetime,
	})
	if err != nil {
		return nil, ErrInvalidBrowserLogin
	}
	continuation, err := oidc.NewLoginContinuationGuard(oidc.LoginContinuationOptions{
		Route: options.Route, Origin: options.Origin, KeyID: options.ContinuationKey.ID,
		KeyMaterial: options.ContinuationKey.Material, Lifetime: options.ContinuationLifetime,
	})
	if err != nil {
		return nil, ErrInvalidBrowserLogin
	}
	startMetrics, readerMetrics := NewLoginHTTPTelemetry(), NewLoginCallbackTelemetry()
	capsuleMetrics, gateMetrics := NewLoginCapsuleTelemetry(), NewLoginContinuationTelemetry()
	completionMetrics, landingMetrics := NewLoginCompletionTelemetry(), NewLoginLandingTelemetry()
	captureMetrics := NewBrowserCaptureTelemetry()
	start, err := NewLoginStartHandler(LoginStartHandlerOptions{
		Initiation: initiation, Admission: options.Admission, Starter: options.Starter,
		RateLimitSubjects: options.RateLimitSubjects, RateLimiter: options.RateLimiter,
		SourceRateLimit: options.SourceRateLimit, TrustedProxyPrefixes: options.TrustedProxyPrefixes,
		Clock: options.Clock, Observer: startMetrics,
		RequestTimeout: options.RequestTimeout, MaxConcurrentRequests: options.MaxConcurrent,
	})
	if err != nil {
		return nil, ErrInvalidBrowserLogin
	}
	reader, err := NewLoginCallbackReader(LoginCallbackReaderOptions{Route: options.Route, Observer: readerMetrics})
	if err != nil {
		return nil, ErrInvalidBrowserLogin
	}
	// A callback path must not overlap any other fixed browser operation.
	switch reader.path {
	case LoginPreparePath, LoginStartPath, LoginCallbackContinuePath, LoginContinuationPreparePath:
		return nil, ErrInvalidBrowserLogin
	}
	capsule, err := NewLoginCallbackCapsuleCodec(LoginCallbackCapsuleOptions{
		Route: options.Route, KeyID: options.CaptureKey.ID, KeyMaterial: options.CaptureKey.Material,
		Lifetime: options.CaptureLifetime, Observer: capsuleMetrics,
	})
	if err != nil {
		return nil, ErrInvalidBrowserLogin
	}
	gate, err := NewLoginContinuationGate(LoginContinuationGateOptions{
		CSRF: continuation, Capsule: capsule, RateLimitSubjects: options.RateLimitSubjects,
		RateLimiter: options.RateLimiter, SourceRateLimit: options.SourceRateLimit, StateRateLimit: options.StateRateLimit,
		TrustedProxyPrefixes: options.TrustedProxyPrefixes, Clock: options.Clock, Observer: gateMetrics,
		RequestTimeout: options.RequestTimeout, MaxConcurrentRequests: options.MaxConcurrent,
	})
	if err != nil {
		return nil, ErrInvalidBrowserLogin
	}
	completion, err := NewLoginCompletion(LoginCompletionOptions{
		Admission: gate, Callback: options.Callback,
		ReturnRouteID: options.Route.ReturnRouteID(), ReturnPath: options.ReturnPath,
		Observer: completionMetrics, RequestTimeout: options.CompletionTimeout, MaxConcurrent: options.MaxConcurrent,
	})
	if err != nil {
		return nil, ErrInvalidBrowserLogin
	}
	landing, err := NewLoginContinuationLanding(LoginContinuationLandingOptions{
		Completion: completion, Observer: landingMetrics, RequestTimeout: options.RequestTimeout,
		MaxConcurrent: options.MaxConcurrent,
	})
	if err != nil {
		return nil, ErrInvalidBrowserLogin
	}
	registry := prometheus.NewPedanticRegistry()
	for _, collector := range []prometheus.Collector{
		startMetrics, readerMetrics, capsuleMetrics, gateMetrics, completionMetrics, landingMetrics, captureMetrics,
	} {
		if err := registry.Register(collector); err != nil {
			return nil, ErrInvalidBrowserLogin
		}
	}
	return &BrowserLogin{start: start, reader: reader, capsule: capsule, gate: gate,
		completion: completion, landing: landing, metrics: registry, capture: captureMetrics,
		slots: make(chan struct{}, options.MaxConcurrent)}, nil
}

func distinctBrowserKeys(options BrowserLoginOptions) bool {
	keys := []BrowserLoginKey{options.InitiationKey, options.CaptureKey, options.ContinuationKey}
	var zero [32]byte
	for index, key := range keys {
		if len(key.Material) != len(zero) || subtle.ConstantTimeCompare(key.Material, zero[:]) == 1 {
			return false
		}
		for _, other := range keys[:index] {
			if key.ID == other.ID || subtle.ConstantTimeCompare(key.Material, other.Material) == 1 {
				return false
			}
		}
	}
	return true
}

func validBrowserProxies(prefixes []netip.Prefix) bool {
	if len(prefixes) > 16 {
		return false
	}
	for index, prefix := range prefixes {
		invalidCanonicalPrefix := !prefix.IsValid() || prefix != prefix.Masked()
		if invalidCanonicalPrefix || prefix.Bits() == 0 || prefix.Addr().Is4In6() {
			return false
		}
		for _, other := range prefixes[:index] {
			if prefix == other {
				return false
			}
		}
	}
	return true
}

// Capture owns GET-only no-grant syntax capture through bounded zero-body redirect.
// Pre-release errors write no header/status/body; never retry or infer authentication.
// The future process root must suppress edge/BFF query logging before mounting it.
func (browser *BrowserLogin) Capture(response http.ResponseWriter, request *http.Request) (resultErr error) {
	missingOwner := browser == nil || browser.slots == nil
	missingCall := request == nil || nilContinuationDependency(response)
	if missingOwner || missingCall {
		return ErrBrowserCaptureUnavailable
	}
	started := time.Now()
	browser.capture.opened()
	defer func() { browser.capture.closed(resultErr, time.Since(started)) }()
	if !pristineLandingResponse(response.Header()) {
		return ErrInvalidBrowserLogin
	}
	if _, present := request.Header["Authorization"]; present {
		return ErrInvalidBrowserLogin
	}
	ctx, cancel := context.WithTimeout(request.Context(), browser.gate.options.RequestTimeout)
	defer cancel()
	if ctx.Err() != nil {
		return ErrBrowserCaptureUnavailable
	}
	select {
	case browser.slots <- struct{}{}:
		defer func() { <-browser.slots }()
	default:
		return ErrBrowserCaptureSaturated
	}
	deadline, hasDeadline := ctx.Deadline()
	controller := http.NewResponseController(response)
	if !hasDeadline {
		return ErrBrowserCaptureUnavailable
	}
	if controller.SetReadDeadline(deadline) != nil || controller.SetWriteDeadline(deadline) != nil {
		return ErrBrowserCaptureUnavailable
	}
	input, err := browser.reader.Read(ctx, request)
	if err != nil {
		if errors.Is(err, ErrInvalidLoginCallback) {
			return ErrInvalidBrowserLogin
		}
		return ErrBrowserCaptureUnavailable
	}
	address, err := browser.gate.clientIPs.Resolve(request)
	if err != nil {
		return ErrInvalidBrowserLogin
	}
	// Nothing reaches the caller's headers until the complete redirect is ready.
	candidate := &browserCaptureHeaders{header: response.Header().Clone()}
	deploymentID := input.Route().DeploymentID().String()
	for _, budget := range []continuationBudget{
		{response: candidate, kind: ratelimit.SubjectSource,
			raw:    "browser-login-capture-source/v1\x00" + deploymentID + "\x00" + address.String(),
			policy: browser.gate.options.SourceRateLimit},
		{response: candidate, kind: ratelimit.SubjectAuthTransaction,
			raw:    "browser-login-capture-state/v1\x00" + deploymentID + "\x00" + input.State().Encoded(),
			policy: browser.gate.options.StateRateLimit},
	} {
		if err := browser.gate.budget(ctx, budget); err != nil {
			if errors.Is(err, ErrLoginContinuationLimited) {
				return ErrBrowserCaptureLimited
			}
			return ErrBrowserCaptureUnavailable
		}
	}
	capture, err := browser.capsule.Capture(ctx, input, browser.gate.options.Clock.Now())
	if err != nil {
		if errors.Is(err, ErrInvalidLoginCapsule) {
			return ErrInvalidBrowserLogin
		}
		return ErrBrowserCaptureUnavailable
	}
	if err := capture.WriteRedirect(ctx, candidate, browser.gate.options.Clock.Now()); err != nil {
		return ErrBrowserCaptureUnavailable
	}
	invalidSubmission := candidate.status != http.StatusSeeOther || candidate.writes != 1
	if !boundedLoginHeaders(candidate.header) || invalidSubmission {
		return ErrInvalidBrowserLogin
	}
	now := browser.gate.options.Clock.Now()
	validTimes := validCapsuleTime(now) && !now.Before(capture.issuedAt) && now.Before(capture.expiresAt)
	validRemainingLifetime := validTimes && capture.expiresAt.Sub(now) >= time.Second
	if !validRemainingLifetime || ctx.Err() != nil {
		return ErrBrowserCaptureUnavailable
	}
	header := response.Header()
	clear(header)
	for name, values := range candidate.header {
		header[name] = values
	}
	response.WriteHeader(http.StatusSeeOther)
	return nil
}

type browserCaptureHeaders struct {
	header http.Header
	status int
	writes int
}

func (candidate *browserCaptureHeaders) Header() http.Header { return candidate.header }
func (candidate *browserCaptureHeaders) WriteHeader(status int) {
	candidate.status, candidate.writes = status, candidate.writes+1
}
func (*browserCaptureHeaders) Write([]byte) (int, error) { return 0, ErrInvalidBrowserLogin }

// Initiation returns bounded private prepare/start ownership, not runtime admission.
func (browser *BrowserLogin) Initiation() *LoginStartHandler { return browser.start }

// Continuation returns no-grant protected POST admission, not an application grant.
func (browser *BrowserLogin) Continuation() *LoginContinuationGate { return browser.gate }

// Completion returns confirmed-only private cookie/response ownership.
func (browser *BrowserLogin) Completion() *LoginCompletion { return browser.completion }

// Landing returns read-only private hash-CSP presentation ownership.
func (browser *BrowserLogin) Landing() *LoginContinuationLanding { return browser.landing }

// MetricsCollector permits explicit private root registration, never global/public setup.
func (browser *BrowserLogin) MetricsCollector() prometheus.Collector { return browser.metrics }

// String conceals resident key/configuration data from incidental formatting.
func (BrowserLoginKey) String() string { return "[REDACTED]" }

// GoString conceals resident key material from detailed formatting.
func (BrowserLoginKey) GoString() string { return "httpapi.BrowserLoginKey([REDACTED])" }

// LogValue conceals resident key material from structured logs.
func (BrowserLoginKey) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON refuses accidental credential publication.
func (BrowserLoginKey) MarshalJSON() ([]byte, error) { return nil, ErrInvalidBrowserLogin }

// String conceals construction topology and resident input key material.
func (BrowserLoginOptions) String() string { return "[REDACTED]" }

// GoString conceals detailed construction configuration.
func (BrowserLoginOptions) GoString() string { return "httpapi.BrowserLoginOptions([REDACTED])" }

// LogValue conceals construction configuration from structured logs.
func (BrowserLoginOptions) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON refuses accidental resident configuration publication.
func (BrowserLoginOptions) MarshalJSON() ([]byte, error) { return nil, ErrInvalidBrowserLogin }

// String conceals private component topology from incidental formatting.
func (*BrowserLogin) String() string { return "[REDACTED]" }

// GoString conceals detailed private component topology.
func (*BrowserLogin) GoString() string { return "httpapi.BrowserLogin([REDACTED])" }

// LogValue conceals private topology from structured logs.
func (*BrowserLogin) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }
