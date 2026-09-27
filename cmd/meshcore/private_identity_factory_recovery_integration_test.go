//go:build integration

package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"runtime"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/meshtransit/meshtransit/internal/adapter/httpapi"
	"github.com/meshtransit/meshtransit/internal/adapter/oidc"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
)

func TestPrivateIdentityFactoryProviderRecoveryGenerationIntegration(t *testing.T) {
	if os.Getenv("MESHTRANSIT_PRIVATE_FACTORY_INTEGRATION") != "1" {
		t.Skip("requires the owned Linux private-factory fixture lane")
	}
	missingTrust := os.Getenv("SSL_CERT_FILE") == "" || os.Getenv("SSL_CERT_DIR") == ""
	if runtime.GOOS != "linux" || missingTrust {
		t.Fatal("requires explicit Linux process-startup fixture trust")
	}
	t.Cleanup(func() { goleak.VerifyNone(t) })
	storage := openPrivateFactoryIntegrationStorage(t, "meshtransit_private_factory_recovery")
	storage.seedAccount(t)
	fixture := newPrivateIdentityFixture(t)
	provider, secret := newPrivateFactorySigningProvider(t, 96)
	oldRoute := provider.route
	fixture.options.Route = oldRoute
	storage.seedRoute(t, oldRoute)
	storage.seedLoginSubject(t, fixture, 96, privateFactorySubject, true)
	seen := storage.subjectLastSeen(t, 96)
	cache, _ := storage.openRedis(t)
	oldFactory, err := composePrivateIdentityFactory(
		t.Context(), fixture.keys,
		privateIdentityFactoryOptions{
			Application: fixture.options,
			Discovery:   oidc.Options{Timeout: time.Second, MaxMetadataBytes: 64 * 1024},
			Token:       privateIdentityTokenOptions{Timeout: 10 * time.Second, MaxTokenAge: time.Minute},
		},
		privateIdentityFactoryDependencies{
			Runtime: storage.runtime, Redis: cache, Secret: secret, Logger: discardCompositionLogger(),
		},
	)
	if err != nil || oldFactory == nil {
		t.Fatal("compose generation-one factory")
	}
	t.Cleanup(oldFactory.Close)

	location, cookies, sessionTransaction := storage.startConcreteLogin(
		t, fixture, oldFactory, "192.0.2.96:12345",
	)
	provider.arm(t, location, false)
	post := prepareConcreteCallback(t, fixture, oldFactory, location, cookies, "192.0.2.96:12345", false)
	completed := newPrivateIdentityResponse()
	if err := oldFactory.identity.dispatcher.Handle(completed, post); err != nil ||
		completed.Code != http.StatusOK || completed.Body.String() != `{"return_path":"/console"}` {
		t.Fatal("create generation-one Session")
	}
	oldToken := assertConcreteSessionCookies(t, completed, true)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	oldSession, err := oldFactory.identity.sessions.Authenticate(ctx, oldToken)
	cancel()
	if err != nil {
		t.Fatal("authenticate generation-one Session before recovery")
	}
	assertPrivateFactorySession(t, oldSession, oldRoute, 96)
	storage.assertPersistedSession(t, fixture, oldSession, oldToken)
	storage.assertCallbackTerminal(t, sessionTransaction, oldSession)

	location, cookies, pendingTransaction := storage.startConcreteLogin(
		t, fixture, oldFactory, "192.0.2.97:12345",
	)
	provider.arm(t, location, false)
	stalePost := prepareConcreteCallback(
		t, fixture, oldFactory, location, cookies, "192.0.2.97:12345", false,
	)
	before := storage.census(t)
	if before.sessions != 1 || before.transactions != 2 || provider.tokens.Load() != 1 || provider.jwks.Load() != 1 {
		t.Fatal("recovery fixture did not own one Session and one pending continuation")
	}

	storage.quarantineFixtureProviderRecovery(t, oldRoute)
	quarantined := before
	quarantined.mutations += 3
	quarantined.audit++
	quarantined.outbox++
	storage.assertFixtureProviderRecovery(
		t, oldRoute, "quarantined", 2, oldSession.ID().String(), pendingTransaction,
	)
	assertPrivateFactorySessionDenied(t, oldFactory, oldToken)
	response := newPrivateIdentityResponse()
	assertConcreteCallbackRejected(t, response, oldFactory.identity.dispatcher.Handle(response, stalePost))
	assertPrivateFactoryRecoveryRouteDenied(t, fixture, oldFactory, "192.0.2.98:12345")
	if storage.census(t) != quarantined || provider.tokens.Load() != 1 || provider.jwks.Load() != 1 {
		t.Fatal("quarantine exchanged provider evidence or changed stale authority")
	}

	newRoute := privateFactoryRouteGeneration(t, oldRoute, 2)
	fixture.options.Route = newRoute
	replicaRuntime := storage.openRuntime(t)
	replicaCache, _ := storage.openRedis(t)
	newFactory, err := composePrivateIdentityFactory(
		t.Context(), fixture.keys,
		privateIdentityFactoryOptions{
			Application: fixture.options,
			Discovery:   oidc.Options{Timeout: time.Second, MaxMetadataBytes: 64 * 1024},
			Token:       privateIdentityTokenOptions{Timeout: 10 * time.Second, MaxTokenAge: time.Minute},
		},
		privateIdentityFactoryDependencies{
			Runtime: replicaRuntime, Redis: replicaCache, Secret: secret, Logger: discardCompositionLogger(),
		},
	)
	if err != nil || newFactory == nil {
		t.Fatal("compose generation-two replacement factory")
	}
	t.Cleanup(newFactory.Close)
	assertPrivateFactoryRecoveryRouteDenied(t, fixture, newFactory, "192.0.2.99:12345")
	if storage.census(t) != quarantined {
		t.Fatal("new generation bypassed provider quarantine")
	}

	storage.approveFixtureProviderRecovery(t, oldRoute)
	verified := quarantined
	verified.mutations++
	verified.audit++
	verified.outbox++
	storage.assertFixtureProviderRecovery(
		t, oldRoute, "verified", 3, oldSession.ID().String(), pendingTransaction,
	)
	assertPrivateFactorySessionDenied(t, newFactory, oldToken)
	assertPrivateFactoryRecoveryRouteDenied(t, fixture, oldFactory, "192.0.2.100:12345")
	if storage.census(t) != verified || provider.tokens.Load() != 1 || provider.jwks.Load() != 1 {
		t.Fatal("recovery approval revived stale generation authority")
	}

	location, cookies, recoveredTransaction := storage.startConcreteLogin(
		t, fixture, newFactory, "192.0.2.101:12345",
	)
	provider.arm(t, location, false)
	post = prepareConcreteCallback(t, fixture, newFactory, location, cookies, "192.0.2.101:12345", false)
	completed = newPrivateIdentityResponse()
	if err := newFactory.identity.dispatcher.Handle(completed, post); err != nil ||
		completed.Code != http.StatusOK || completed.Body.String() != `{"return_path":"/console"}` {
		t.Fatal("complete approved generation-two login")
	}
	newToken := assertConcreteSessionCookies(t, completed, true)
	ctx, cancel = context.WithTimeout(t.Context(), 5*time.Second)
	newSession, err := newFactory.identity.sessions.Authenticate(ctx, newToken)
	cancel()
	if err != nil {
		t.Fatal("authenticate generation-two Session")
	}
	assertPrivateFactorySession(t, newSession, newRoute, 96)
	storage.assertPersistedSession(t, fixture, newSession, newToken)
	storage.assertCallbackTerminal(t, recoveredTransaction, newSession)
	storage.assertFixtureProviderRecovery(
		t, oldRoute, "verified", 3, oldSession.ID().String(), pendingTransaction,
	)
	assertPrivateFactorySessionDenied(t, newFactory, oldToken)

	want := before
	want.transactions++
	want.sessions++
	want.mutations += 8
	want.audit += 6
	want.outbox += 6
	if storage.census(t) != want || !storage.subjectLastSeen(t, 96).Equal(seen) ||
		provider.tokens.Load() != 2 || provider.jwks.Load() != 2 || provider.unexpected.Load() != 0 ||
		fixture.clockReads != 0 || len(fixture.effects) != 0 {
		t.Fatal("generation-two recovery widened authority or changed unrelated effects")
	}

	oldFactory.Close()
	newFactory.Close()
	ctx, cancel = context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if storage.runtime.Check(ctx) != nil || replicaRuntime.Check(ctx) != nil ||
		cache.Check(ctx) != nil || replicaCache.Check(ctx) != nil {
		t.Fatal("recovery factories closed borrowed dependencies")
	}
}

func assertPrivateFactorySessionDenied(
	t *testing.T,
	factory *privateIdentityFactory,
	token accountsession.Token,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	session, err := factory.identity.sessions.Authenticate(ctx, token)
	if !errors.Is(err, accountsession.ErrUnauthenticated) || session.IsValid() {
		t.Fatal("provider recovery admitted stale Session")
	}
}

func assertPrivateFactoryRecoveryRouteDenied(
	t *testing.T,
	fixture *privateIdentityFixture,
	factory *privateIdentityFactory,
	address string,
) {
	t.Helper()
	request := fixture.loginRequest(t, httpapi.LoginPreparePath)
	request.RemoteAddr = address
	response := newPrivateIdentityResponse()
	if err := factory.identity.dispatcher.Handle(response, request); err != nil {
		t.Fatal("dispatch recovery route admission")
	}
	assertPrivateFactoryInitiationDenied(t, response)
}
