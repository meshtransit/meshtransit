package main

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net/netip"
	"reflect"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/meshtransit/meshtransit/api/openapi"
	"github.com/meshtransit/meshtransit/internal/adapter/httpapi"
	"github.com/meshtransit/meshtransit/internal/adapter/oidc"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/meshtransit/meshtransit/internal/ratelimit"
)

// These options are private source preparation, not configuration or enablement.
// No alternate clock, Deployment, key or login-service injection is permitted.
type privateIdentityOptions struct {
	Route              oidcauth.Route
	Origin, ReturnPath string
	Start              oidcauth.StartOptions
	Callback           oidcauth.CallbackOptions
	Browser            privateIdentityBrowserOptions
	Management         privateIdentityManagementOptions
}

type privateIdentityBrowserOptions struct {
	IntentLifetime, CaptureLifetime, ContinuationLifetime time.Duration
	RequestTimeout, CompletionTimeout                     time.Duration
	MaxConcurrent                                         int
	SourceRateLimit, StateRateLimit                       ratelimit.Policy
	TrustedProxyPrefixes                                  []netip.Prefix
}

type privateIdentityManagementOptions struct {
	RequestTimeout, ProofLifetime     time.Duration
	MaxConcurrent                     int
	SourceRateLimit, SessionRateLimit ratelimit.Policy
}

// Ports are effects, not prebuilt authentication services or secret owners.
// Production binding must supply current durable authority and shared budgets;
// this helper neither opens dependencies nor probes their operational readiness.
type privateIdentityPorts struct {
	Admission          httpapi.LoginRouteAdmission
	Metadata           oidcauth.MetadataResolver
	Creations          oidcauth.Transactions
	Committed          oidcauth.CommittedCreationResolver
	Pending            oidcauth.PendingLoader
	Claims             oidcauth.ClaimTransactions
	Failures           oidcauth.FailureTransactions
	Issues             oidcauth.IssueTransactions
	Provider           oidcauth.TokenAuthenticator
	Subjects           oidcauth.LoginSubjectResolver
	SessionAuthority   accountsession.Resolver
	SessionRevocations accountsession.Revoker
	StartIDs           oidcauth.StartIDGenerator
	Secrets            oidcauth.SecretsGenerator
	ClaimIDs           oidcauth.ClaimIDGenerator
	IssueMaterial      oidcauth.IssueMaterialGenerator
	Revocations        httpapi.DeviceRevoker
	PolicyPublications httpapi.PolicyPublisher
	PolicyCompilations httpapi.PolicyCompiler
	RateLimiter        httpapi.ManagementRateLimiter
	CorrelationIDs     httpapi.PublicIDGenerator
	Clock              oidcauth.StartClock
	Logger             *slog.Logger
}

// A complete private graph has explicit source dispatch/document ownership, but
// no listener, readiness, global registration or main/runtime configuration binding.
type privateIdentity struct {
	start         *oidcauth.StartService
	callback      *oidcauth.CallbackService
	sessions      *accountsession.Service
	logout        *accountsession.LogoutService
	login         *httpapi.BrowserLogin
	dispatcher    *httpapi.LoginDispatcher
	loginDocument []byte
	management    *httpapi.BrowserManagement
	metrics       *prometheus.Registry
}

// composePrivateIdentity uses only the resident bundle prepared by
// composePrivateIdentityKeys. Constructors copy mutable browser input; the caller
// exclusively owns and may erase that input after this function returns.
func composePrivateIdentity(
	ctx context.Context,
	keys *privateIdentityKeys,
	options privateIdentityOptions,
	ports privateIdentityPorts,
) (*privateIdentity, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	if !completePrivateIdentityKeys(keys) || !completePrivateIdentityPorts(ports) {
		return nil, errInvalidPrivateIdentityComposition
	}
	validStartWindow := options.Start.RequestTimeout <= options.Browser.RequestTimeout
	validCallbackWindow := options.Callback.RequestTimeout <= options.Browser.CompletionTimeout
	if !validStartWindow || !validCallbackWindow {
		return nil, errInvalidPrivateIdentityComposition
	}
	ctx, cancel := context.WithTimeout(ctx, privateIdentityConstructionTimeout)
	defer cancel()
	startMetrics, callbackMetrics := oidc.NewStartTelemetry(), oidc.NewCallbackTelemetry()
	subjectMetrics, issueMetrics := oidc.NewSubjectTelemetry(), oidc.NewIssueTelemetry()
	start, err := oidcauth.NewStartService(options.Start, oidcauth.StartDependencies{
		Metadata: ports.Metadata, Transactions: ports.Creations, Committed: ports.Committed,
		IDs: ports.StartIDs, Secrets: ports.Secrets, Clock: ports.Clock, Observer: startMetrics,
		DigestKey: keys.transaction, VerifierCipher: keys.verifier,
	})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	callback, err := oidcauth.NewCallbackService(options.Callback, oidcauth.CallbackDependencies{
		Pending: ports.Pending, Claims: ports.Claims, Failures: ports.Failures, Issues: ports.Issues,
		IDs: ports.ClaimIDs, Material: ports.IssueMaterial, Provider: ports.Provider, Subjects: ports.Subjects,
		DigestKey: keys.transaction, VerifierCipher: keys.verifier, SubjectKeys: keys.subjects,
		SessionKeys: keys.sessions, ProviderSessions: keys.providerSessions, Clock: ports.Clock,
		Observer: callbackMetrics, SubjectObserver: subjectMetrics, IssueObserver: issueMetrics,
	})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	sessions, err := accountsession.NewService(keys.sessions, ports.SessionAuthority, ports.Clock)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	logout, err := accountsession.NewLogoutService(keys.sessions, ports.SessionRevocations)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	profile := options.Browser
	login, err := httpapi.NewBrowserLogin(httpapi.BrowserLoginOptions{
		Route: options.Route, Origin: options.Origin, ReturnPath: options.ReturnPath,
		InitiationKey: keys.initiation, CaptureKey: keys.capture, ContinuationKey: keys.continuation,
		IntentLifetime: profile.IntentLifetime, CaptureLifetime: profile.CaptureLifetime,
		ContinuationLifetime: profile.ContinuationLifetime, Admission: ports.Admission, Starter: start, Callback: callback,
		RateLimitSubjects: keys.rateLimit, RateLimiter: ports.RateLimiter,
		SourceRateLimit: profile.SourceRateLimit, StateRateLimit: profile.StateRateLimit,
		TrustedProxyPrefixes: profile.TrustedProxyPrefixes, Clock: ports.Clock,
		RequestTimeout: profile.RequestTimeout, CompletionTimeout: profile.CompletionTimeout,
		MaxConcurrent: profile.MaxConcurrent,
	})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	managementOptions := options.Management
	resources, err := httpapi.NewManagementHandler(httpapi.ManagementHandlerOptions{
		Sessions: sessions, Revocations: ports.Revocations, PolicyPublications: ports.PolicyPublications,
		PolicyCompilations: ports.PolicyCompilations,
		Idempotency:        keys.idempotency, RateLimitSubjects: keys.rateLimit, RateLimiter: ports.RateLimiter,
		TrustedProxyPrefixes: profile.TrustedProxyPrefixes, SourceRateLimit: managementOptions.SourceRateLimit,
		SessionRateLimit: managementOptions.SessionRateLimit, CorrelationIDs: ports.CorrelationIDs, Logger: ports.Logger,
		RequestTimeout: managementOptions.RequestTimeout, MaxConcurrentRequests: managementOptions.MaxConcurrent,
	})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	management, err := httpapi.NewBrowserManagement(httpapi.BrowserManagementOptions{
		Management: resources, Logout: logout, DeploymentID: options.Route.DeploymentID(), Origin: options.Origin,
		Key: keys.csrf, Clock: ports.Clock, ProofLifetime: managementOptions.ProofLifetime,
	})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	dispatcher, err := httpapi.NewLoginDispatcher(login, management)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	loginDocument, err := openapi.LoginDocument(openapi.ManagementProfileConsoleCookiePrivateV1, dispatcher.CallbackPath())
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	registry := prometheus.NewPedanticRegistry()
	for _, collector := range []prometheus.Collector{
		startMetrics, callbackMetrics, subjectMetrics, issueMetrics, login.MetricsCollector(),
		resources.MetricsCollector(), management.MetricsCollector(), dispatcher.MetricsCollector(),
	} {
		if err := registry.Register(collector); err != nil {
			return nil, errInvalidPrivateIdentityComposition
		}
	}
	if ctx.Err() != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	return &privateIdentity{start: start, callback: callback, sessions: sessions, logout: logout,
		login: login, dispatcher: dispatcher, loginDocument: loginDocument, management: management, metrics: registry}, nil
}

func completePrivateIdentityKeys(keys *privateIdentityKeys) bool {
	if keys == nil || keys.verifier == nil || keys.subjects == nil || keys.sessions == nil ||
		keys.idempotency == nil || keys.rateLimit == nil {
		return false
	}
	// Opaque immutable application owners were validated together at loading.
	// Recheck the four caller-owned mutable browser buffers before copying them.
	browserKeys := []httpapi.BrowserLoginKey{keys.initiation, keys.capture, keys.continuation, keys.csrf}
	var zero [32]byte
	for index, key := range browserKeys {
		if len(key.Material) != len(zero) || subtle.ConstantTimeCompare(key.Material, zero[:]) == 1 {
			return false
		}
		for _, previous := range browserKeys[:index] {
			if key.ID == previous.ID || subtle.ConstantTimeCompare(key.Material, previous.Material) == 1 {
				return false
			}
		}
	}
	return true
}

func completePrivateIdentityPorts(ports privateIdentityPorts) bool {
	for _, port := range []any{
		ports.Admission, ports.Metadata, ports.Creations, ports.Committed, ports.Pending, ports.Claims,
		ports.Failures, ports.Issues, ports.Provider, ports.Subjects, ports.SessionAuthority, ports.StartIDs,
		ports.SessionRevocations,
		ports.Secrets, ports.ClaimIDs, ports.IssueMaterial, ports.Revocations, ports.PolicyPublications,
		ports.PolicyCompilations,
		ports.RateLimiter, ports.CorrelationIDs, ports.Clock, ports.Logger,
	} {
		if port == nil {
			return false
		}
		// Reflection only guards typed nil. It never discovers or injects dependencies.
		value := reflect.ValueOf(port)
		switch value.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			if value.IsNil() {
				return false
			}
		}
	}
	return true
}

func (privateIdentityOptions) String() string       { return "[REDACTED]" }
func (privateIdentityOptions) GoString() string     { return "[REDACTED]" }
func (privateIdentityOptions) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }
func (privateIdentityOptions) MarshalJSON() ([]byte, error) {
	return nil, errInvalidPrivateIdentityComposition
}

func (privateIdentityPorts) String() string       { return "[REDACTED]" }
func (privateIdentityPorts) GoString() string     { return "[REDACTED]" }
func (privateIdentityPorts) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }
func (privateIdentityPorts) MarshalJSON() ([]byte, error) {
	return nil, errInvalidPrivateIdentityComposition
}

func (privateIdentity) String() string       { return "[REDACTED]" }
func (privateIdentity) GoString() string     { return "[REDACTED]" }
func (privateIdentity) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }
func (privateIdentity) MarshalJSON() ([]byte, error) {
	return nil, errInvalidPrivateIdentityComposition
}
