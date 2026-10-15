package main

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net/netip"
	"reflect"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"meshtransit.net/api/openapi"
	"meshtransit.net/core/internal/adapter/httpapi"
	"meshtransit.net/core/internal/adapter/oidc"
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/identity/oidcauth"
	"meshtransit.net/core/internal/platform/ratelimit"
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
	// DNSSuffix names Devices and shares in responses; zero: the default.
	DNSSuffix dnsname.Suffix
}

// Ports are effects, not prebuilt authentication services or secret owners.
// Production binding must supply current durable authority and shared budgets;
// this helper neither opens dependencies nor probes their operational readiness.
type privateIdentityPorts struct {
	Admission           httpapi.LoginRouteAdmission
	Metadata            oidcauth.MetadataResolver
	CreationClock       oidcauth.CreationClock
	Creations           oidcauth.Transactions
	Committed           oidcauth.CommittedCreationResolver
	Pending             oidcauth.PendingLoader
	Claims              oidcauth.ClaimTransactions
	Failures            oidcauth.FailureTransactions
	Issues              oidcauth.IssueTransactions
	Provider            oidcauth.TokenAuthenticator
	Subjects            oidcauth.LoginSubjectResolver
	SessionAuthority    accountsession.Resolver
	SessionRevocations  accountsession.Revoker
	SessionLogoutAll    httpapi.AccountSessionLogoutAll
	SessionScopes       httpapi.SessionManagementScopes
	DeviceInventory     httpapi.SessionDeviceInventory
	DeviceDistribution  httpapi.SessionDeviceDistribution
	AccessGraphHistory  httpapi.SessionAccessGraphHistory
	EnforcementHistory  httpapi.SessionEnforcementHistory
	SessionCapabilities httpapi.SessionDeploymentCapabilities
	StartIDs            oidcauth.StartIDGenerator
	Secrets             oidcauth.SecretsGenerator
	ClaimIDs            oidcauth.ClaimIDGenerator
	IssueMaterial       oidcauth.IssueMaterialGenerator
	Revocations         httpapi.DeviceRevoker
	PolicyPublications  httpapi.PolicyPublisher
	PolicyCompilations  httpapi.PolicyCompiler
	PolicyExplanations  httpapi.PolicyExplainer
	AccessGraphs        httpapi.AccessGraphLister
	PolicySimulations   httpapi.PolicySimulator
	ActivePolicies      httpapi.ActivePolicyReader
	WorkspaceRenames    httpapi.WorkspaceRenamer
	WorkspaceRoles      httpapi.WorkspaceRoleManager
	WorkspaceCreations  httpapi.WorkspaceCreator
	NetworkCreations    httpapi.NetworkCreator
	AliasRanges         httpapi.NetworkAliasRanges
	AddressUsage        httpapi.NetworkAddressUsage
	AuditHistory        httpapi.AuditHistoryReader
	AuditExports        httpapi.AuditExporter
	Guardrails          httpapi.GuardrailManager
	Interchanges        httpapi.InterchangeManager
	InterchangeTrust    httpapi.InterchangeRelayTrust
	DeviceGroups        httpapi.DeviceGroupManager
	IdentityGroups      httpapi.IdentityGroupManager
	DeviceTags          httpapi.DeviceTagManager
	DeviceLifecycle     httpapi.DeviceLifecycleManager
	MemberLifecycle     httpapi.MemberLifecycleManager
	NetworkMembers      httpapi.NetworkMemberManager
	Invitations         httpapi.InvitationManager
	// InvitationPreviews and InvitationAcceptor serve links and sign-in.
	InvitationPreviews httpapi.InvitationPreviewer
	InvitationAcceptor oidcauth.InvitationAcceptor
	// AccountSignups creates an Account at a first sign-in; nil leaves self
	// sign-up off.
	AccountSignups        oidcauth.AccountSignupStore
	SessionWorkspaces     httpapi.SessionWorkspaceSelector
	ShareTargets          httpapi.ShareTargetResolver
	PolicyApprovals       httpapi.PolicyApprovalWorkflow
	PolicyApprovalCatalog httpapi.PolicyApprovalCatalog
	ResourceCreations     httpapi.ResourceCreator
	ResourceCatalog       httpapi.ResourceCatalog
	ResourceSharing       httpapi.ResourceSharingManagement
	RateLimiter           httpapi.ManagementRateLimiter
	CorrelationIDs        httpapi.PublicIDGenerator
	Clock                 oidcauth.StartClock
	Logger                *slog.Logger
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
		Metadata: ports.Metadata, Transactions: ports.Creations, Committed: ports.Committed, CreationClock: ports.CreationClock,
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
		Invitations: ports.InvitationAcceptor, Signups: ports.AccountSignups,
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
		PolicyCompilations:    ports.PolicyCompilations,
		PolicyExplanations:    ports.PolicyExplanations,
		AccessGraphs:          ports.AccessGraphs,
		PolicySimulations:     ports.PolicySimulations,
		ActivePolicies:        ports.ActivePolicies,
		WorkspaceRenames:      ports.WorkspaceRenames,
		WorkspaceRoles:        ports.WorkspaceRoles,
		WorkspaceCreations:    ports.WorkspaceCreations,
		NetworkCreations:      ports.NetworkCreations,
		AliasRanges:           ports.AliasRanges,
		AddressUsage:          ports.AddressUsage,
		AuditHistory:          ports.AuditHistory,
		AuditExports:          ports.AuditExports,
		Guardrails:            ports.Guardrails,
		Interchanges:          ports.Interchanges,
		InterchangeTrust:      ports.InterchangeTrust,
		DeviceGroups:          ports.DeviceGroups,
		IdentityGroups:        ports.IdentityGroups,
		DeviceTags:            ports.DeviceTags,
		DeviceLifecycle:       ports.DeviceLifecycle,
		MemberLifecycle:       ports.MemberLifecycle,
		NetworkMembers:        ports.NetworkMembers,
		Invitations:           ports.Invitations,
		SessionWorkspaces:     ports.SessionWorkspaces,
		ShareTargets:          ports.ShareTargets,
		PolicyApprovals:       ports.PolicyApprovals,
		PolicyApprovalCatalog: ports.PolicyApprovalCatalog,
		ResourceCreations:     ports.ResourceCreations, ResourceCatalog: ports.ResourceCatalog,
		ResourceSharing: ports.ResourceSharing,
		Idempotency:     keys.idempotency, RateLimitSubjects: keys.rateLimit, RateLimiter: ports.RateLimiter,
		TrustedProxyPrefixes: profile.TrustedProxyPrefixes, SourceRateLimit: managementOptions.SourceRateLimit,
		SessionRateLimit: managementOptions.SessionRateLimit, CorrelationIDs: ports.CorrelationIDs, Logger: ports.Logger,
		RequestTimeout: managementOptions.RequestTimeout, MaxConcurrentRequests: managementOptions.MaxConcurrent,
		DNSSuffix: managementOptions.DNSSuffix,
	})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	management, err := httpapi.NewBrowserManagement(httpapi.BrowserManagementOptions{
		Management: resources, Logout: logout, LogoutAll: ports.SessionLogoutAll, Scopes: ports.SessionScopes,
		Inventory:    ports.DeviceInventory,
		Distribution: ports.DeviceDistribution, AccessGraphHistory: ports.AccessGraphHistory,
		EnforcementHistory: ports.EnforcementHistory,
		Capabilities:       ports.SessionCapabilities,
		DeploymentID:       options.Route.DeploymentID(), Origin: options.Origin,
		Key: keys.csrf, Clock: ports.Clock, ProofLifetime: managementOptions.ProofLifetime,
	})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	dispatcher, err := httpapi.NewLoginDispatcher(login, management)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	if ports.InvitationPreviews != nil {
		invitationPrepare, prepareErr := httpapi.NewInvitationPrepareHandler(httpapi.InvitationPrepareOptions{
			Origin: options.Origin, DeploymentID: options.Route.DeploymentID(), Previewer: ports.InvitationPreviews,
			RateLimitSubjects: keys.rateLimit, RateLimiter: ports.RateLimiter,
			SourceRateLimit: options.Browser.SourceRateLimit, TrustedProxyPrefixes: options.Browser.TrustedProxyPrefixes,
			RequestTimeout: options.Browser.RequestTimeout, MaxConcurrentRequests: options.Browser.MaxConcurrent,
		})
		if prepareErr != nil {
			return nil, errInvalidPrivateIdentityComposition
		}
		if dispatcher, err = dispatcher.WithInvitations(invitationPrepare); err != nil {
			return nil, errInvalidPrivateIdentityComposition
		}
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
		ports.Admission, ports.Metadata, ports.CreationClock, ports.Creations, ports.Committed, ports.Pending, ports.Claims,
		ports.Failures, ports.Issues, ports.Provider, ports.Subjects, ports.SessionAuthority, ports.StartIDs,
		ports.SessionRevocations, ports.SessionLogoutAll, ports.SessionScopes, ports.SessionCapabilities,
		ports.Secrets, ports.ClaimIDs, ports.IssueMaterial, ports.Revocations, ports.PolicyPublications,
		ports.PolicyCompilations,
		ports.PolicyExplanations,
		ports.PolicySimulations,
		ports.PolicyApprovals,
		ports.PolicyApprovalCatalog,
		ports.ResourceCreations, ports.ResourceCatalog, ports.ResourceSharing,
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
