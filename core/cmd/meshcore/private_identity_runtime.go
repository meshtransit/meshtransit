package main

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/adapter/httpapi"
	"github.com/meshtransit/meshtransit/core/internal/adapter/oidc"
	"github.com/meshtransit/meshtransit/core/internal/domain/enrollment"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/oidcauth"
	"github.com/meshtransit/meshtransit/core/internal/platform/app"
	"github.com/meshtransit/meshtransit/core/internal/platform/config"
	"github.com/meshtransit/meshtransit/core/internal/platform/ratelimit"
)

var (
	errPrivateIdentityAdmissionCheck     = errors.New("private identity admission check unavailable")
	errPrivateIdentityDiscoveryCheck     = errors.New("private identity discovery check unavailable")
	errPrivateIdentityDiscoveryDeadline  = errors.New("private identity discovery deadline exceeded")
	errPrivateIdentityDiscoveryMetadata  = errors.New("private identity discovery metadata rejected")
	errPrivateIdentityDiscoveryTransport = errors.New("private identity discovery transport unavailable")
)

type browserRegistrationRuntime struct {
	profile *config.BrowserRegistrationConfig
	keys    *enrollment.BrowserIntentKeyring
}

// The process receives only a validated immutable configuration and its concrete
// already-owned dependencies. No alternate clock/provider/handler can be bound.
func composePrivateIdentityRuntime(
	ctx context.Context,
	profile *config.PrivateLoginConfig,
	dependencies privateIdentityFactoryDependencies,
	browserRegistration ...browserRegistrationRuntime,
) (*privateIdentityFactory, *httpapi.LoginServer, error) {
	if profile == nil || ctx == nil || ctx.Err() != nil || len(browserRegistration) > 1 {
		return nil, nil, errInvalidPrivateIdentityComposition
	}
	ctx, cancel := context.WithTimeout(ctx, privateIdentityConstructionTimeout)
	defer cancel()
	candidate, err := profile.LoadConstruction(ctx)
	if err != nil {
		return nil, nil, errInvalidPrivateIdentityComposition
	}
	defer candidate.Clear()
	keys, err := composePrivateIdentityKeyMaterial(ctx, candidate.Keys)
	if err != nil {
		return nil, nil, errInvalidPrivateIdentityComposition
	}
	defer func() {
		clear(keys.initiation.Material)
		clear(keys.capture.Material)
		clear(keys.continuation.Material)
		clear(keys.csrf.Material)
	}()
	material := candidate.Material
	secretBytes := bytes.TrimSuffix(material.ClientSecret, []byte("\r\n"))
	secretBytes = bytes.TrimSuffix(secretBytes, []byte("\n"))
	dependencies.Secret, err = oidc.NewBasicSecret(string(secretBytes))
	if err != nil {
		return nil, nil, errInvalidPrivateIdentityComposition
	}
	options, err := privateIdentityRuntimeOptions(profile)
	if err != nil {
		return nil, nil, errInvalidPrivateIdentityComposition
	}
	factory, err := composePrivateIdentityFactory(ctx, keys, options, dependencies)
	if err != nil {
		return nil, nil, errInvalidPrivateIdentityComposition
	}
	if len(browserRegistration) == 1 {
		page, pageErr := composeBrowserRegistrationPage(
			browserRegistration[0].profile, browserRegistration[0].keys,
			factory, dependencies.Runtime,
		)
		if pageErr != nil {
			factory.Close()
			return nil, nil, errInvalidPrivateIdentityComposition
		}
		dispatcher, dispatchErr := factory.identity.dispatcher.WithRegistration(page)
		if dispatchErr != nil {
			factory.Close()
			return nil, nil, errInvalidPrivateIdentityComposition
		}
		factory.identity.dispatcher = dispatcher
	}
	service, err := composePrivateIdentityLoginService(factory, privateIdentityLoginServiceOptions{
		Address: profile.Address(), CertificatePEM: material.CertificatePEM,
		PrivateKeyPEM: material.PrivateKeyPEM, MaxConnections: 64,
	})
	if err != nil || candidate.CheckCurrent(ctx) != nil || ctx.Err() != nil {
		factory.Close()
		return nil, nil, errInvalidPrivateIdentityComposition
	}
	return factory, service, nil
}

// Sign-in admission stays tight: a browser starts a login rarely. Console
// management reads are many small calls per page, so a person switching tabs
// quickly must stay well inside its per-Session budget, and an office behind
// one NAT address shares the per-source budget.
const (
	loginSourceBurst, loginStateBurst             = 30, 10
	managementSourceBurst, managementSessionBurst = 240, 60
	managementSourceRefill                        = 50 * time.Millisecond
	managementSessionRefill                       = 200 * time.Millisecond
)

func privateIdentityRuntimeOptions(profile *config.PrivateLoginConfig) (privateIdentityFactoryOptions, error) {
	source, err := ratelimit.NewPolicy(loginSourceBurst, time.Second)
	if err != nil {
		return privateIdentityFactoryOptions{}, errInvalidPrivateIdentityComposition
	}
	state, err := ratelimit.NewPolicy(loginStateBurst, time.Second)
	if err != nil {
		return privateIdentityFactoryOptions{}, errInvalidPrivateIdentityComposition
	}
	managementSource, err := ratelimit.NewPolicy(managementSourceBurst, managementSourceRefill)
	if err != nil {
		return privateIdentityFactoryOptions{}, errInvalidPrivateIdentityComposition
	}
	managementSession, err := ratelimit.NewPolicy(managementSessionBurst, managementSessionRefill)
	if err != nil {
		return privateIdentityFactoryOptions{}, errInvalidPrivateIdentityComposition
	}
	return privateIdentityFactoryOptions{
		Application: privateIdentityOptions{
			Route: profile.Route(), Origin: profile.Origin(), ReturnPath: "/console",
			Start: oidcauth.StartOptions{RequestTimeout: 5 * time.Second, PendingLifetime: 2 * time.Minute,
				RollbackTimeout: time.Second, ResolveTimeout: time.Second},
			Callback: oidcauth.CallbackOptions{RequestTimeout: 25 * time.Second, FailureTimeout: time.Second,
				RollbackTimeout: time.Second, IdleLifetime: time.Hour, AbsoluteLifetime: 24 * time.Hour, MaxConcurrent: 16},
			Browser: privateIdentityBrowserOptions{IntentLifetime: time.Minute, CaptureLifetime: time.Minute,
				ContinuationLifetime: time.Minute, RequestTimeout: 5 * time.Second, CompletionTimeout: 25 * time.Second,
				MaxConcurrent: 16, SourceRateLimit: source, StateRateLimit: state,
				TrustedProxyPrefixes: profile.TrustedProxyPrefixes()},
			Management: privateIdentityManagementOptions{RequestTimeout: 5 * time.Second, ProofLifetime: time.Minute,
				MaxConcurrent: 16, SourceRateLimit: managementSource, SessionRateLimit: managementSession},
		},
		Discovery: oidc.Options{Timeout: 2 * time.Second, MaxMetadataBytes: 64 * 1024},
		Token: privateIdentityTokenOptions{
			Timeout: 20 * time.Second, MaxTokenAge: 5 * time.Minute, ClockSkew: 30 * time.Second,
		},
	}, nil
}

// Component is the fixed private prerequisite, never an operator label.
func (factory *privateIdentityFactory) Component() app.Component { return app.ComponentPrivateLogin }

// Check is a no-grant prerequisite snapshot. Actual requests retain durable
// admission and exact provider validation; this state is never a trust lease.
func (factory *privateIdentityFactory) Check(ctx context.Context) error {
	complete := factory != nil && factory.identity != nil && factory.discovery != nil
	if ctx == nil || ctx.Err() != nil || !complete || factory.admission == nil || !factory.route.IsValid() {
		return errInvalidPrivateIdentityComposition
	}
	if err := factory.admission.Admit(ctx, factory.route); err != nil {
		return errors.Join(errPrivateIdentityAdmissionCheck, errInvalidPrivateIdentityComposition)
	}
	_, err := factory.discovery.Resolve(ctx, factory.route)
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		return errors.Join(
			errPrivateIdentityDiscoveryCheck,
			classifyPrivateIdentityDiscoveryError(err),
			errInvalidPrivateIdentityComposition,
		)
	}
	return nil
}

func classifyPrivateIdentityDiscoveryError(err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return errPrivateIdentityDiscoveryDeadline
	case errors.Is(err, oidc.ErrInvalidDiscoveryResponse):
		return errPrivateIdentityDiscoveryMetadata
	case errors.Is(err, oidc.ErrDiscoveryUnavailable):
		return errPrivateIdentityDiscoveryTransport
	default:
		return errPrivateIdentityDiscoveryCheck
	}
}

var _ app.DependencyChecker = (*privateIdentityFactory)(nil)
