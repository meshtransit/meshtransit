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

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/goleak"

	"github.com/meshtransit/meshtransit/core/internal/adapter/oidc"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/authexpiry"
	"github.com/meshtransit/meshtransit/core/internal/platform/config"
)

func TestPrivateIdentityFactoryExpiryQuarantineIntegration(t *testing.T) {
	if os.Getenv("MESHTRANSIT_PRIVATE_FACTORY_INTEGRATION") != "1" {
		t.Skip("requires the owned Linux private-factory fixture lane")
	}
	missingTrust := os.Getenv("SSL_CERT_FILE") == "" || os.Getenv("SSL_CERT_DIR") == ""
	if runtime.GOOS != "linux" || missingTrust {
		t.Fatal("requires explicit Linux process-startup fixture trust")
	}
	t.Cleanup(func() { goleak.VerifyNone(t) })
	storage := openPrivateFactoryIntegrationStorage(t, "meshtransit_private_factory_expiry")
	storage.seedAccount(t)
	fixture := newPrivateIdentityFixture(t)
	provider, secret := newPrivateFactorySigningProvider(t, 90)
	fixture.options.Route = provider.route
	fixture.options.Start.PendingLifetime = time.Minute
	storage.seedRoute(t, provider.route)
	storage.seedLoginSubject(t, fixture, 90, privateFactorySubject, true)
	seen := storage.subjectLastSeen(t, 90)
	cache, _ := storage.openRedis(t)
	factory, err := composePrivateIdentityFactory(
		t.Context(),
		fixture.keys,
		privateIdentityFactoryOptions{
			Application: fixture.options,
			Discovery:   oidc.Options{Timeout: time.Second, MaxMetadataBytes: 64 * 1024},
			Token:       privateIdentityTokenOptions{Timeout: 10 * time.Second, MaxTokenAge: time.Minute},
		},
		privateIdentityFactoryDependencies{
			Runtime: storage.runtime, Redis: cache, Secret: secret, Logger: discardCompositionLogger(),
		},
	)
	if err != nil || factory == nil {
		t.Fatal("compose concrete natural-expiry factory")
	}
	t.Cleanup(factory.Close)
	address := "192.0.2.90:12345"
	location, cookies, sessionTransaction := storage.startConcreteLogin(t, fixture, factory, address)
	provider.arm(t, location, false)
	post := prepareConcreteCallback(t, fixture, factory, location, cookies, address, false)
	completed := newPrivateIdentityResponse()
	if err := factory.identity.dispatcher.Handle(completed, post); err != nil || completed.Code != http.StatusOK ||
		completed.Body.String() != `{"return_path":"/console"}` {
		t.Fatal("create prior concrete Session")
	}
	token := assertConcreteSessionCookies(t, completed, true)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	session, err := factory.identity.sessions.Authenticate(ctx, token)
	cancel()
	if err != nil {
		t.Fatal("authenticate prior same-ring Session")
	}
	assertPrivateFactorySession(t, session, provider.route, 90)
	storage.assertPersistedSession(t, fixture, session, token)
	storage.assertCallbackTerminal(t, sessionTransaction, session)

	address = "192.0.2.91:12345"
	location, cookies, transactionID := storage.startConcreteLogin(t, fixture, factory, address)
	provider.arm(t, location, false)
	post = prepareConcreteCallback(t, fixture, factory, location, cookies, address, false)
	snapshot := storage.originalPendingExpiry(t, transactionID, provider.route.DeploymentID())
	before := storage.census(t)
	if before.sessions != 1 || before.transactions != 2 {
		t.Fatal("cold fixture did not own exactly one issued and one pending login")
	}
	workerPool := storage.openExpiryWorkerPool(t)
	settings := config.AuthExpiryConfig{
		DeploymentID: provider.route.DeploymentID(), BatchSize: 8, PollInterval: 100 * time.Millisecond,
		PassTimeout: 3 * time.Second, UnitTimeout: time.Second, RollbackTimeout: time.Second,
	}
	worker, registry := startPrivateFactoryExpiryWorker(t, settings, workerPool)
	privateFactoryWait(t, time.Now().Add(3*time.Second), worker.Done(), func(context.Context) bool {
		return privateFactoryExpiryMetric(t, registry, "meshtransit_oidc_expiry_passes_total", "empty") > 0
	})
	if storage.census(t) != before ||
		privateFactoryExpiryMetric(t, registry, "meshtransit_oidc_expiry_units_attempted_total", "") != 0 {
		t.Fatal("worker expired not-due factory evidence")
	}
	storage.quarantineFixtureDeployment(t)
	before.mutations++
	before.audit++
	before.outbox++
	for _, test := range []struct {
		name  string
		check func(*testing.T)
	}{
		{name: "old Session denied without durable rewrite", check: func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			got, err := factory.identity.sessions.Authenticate(ctx, token)
			if !errors.Is(err, accountsession.ErrUnauthenticated) || got.IsValid() {
				t.Fatal("quarantine admitted stale Session")
			}
			storage.assertPersistedSession(t, fixture, session, token)
		}},
		{name: "old continuation denied without exchange or claim", check: func(t *testing.T) {
			response := newPrivateIdentityResponse()
			assertConcreteCallbackRejected(t, response, factory.identity.dispatcher.Handle(response, post))
			storage.assertOriginalPendingExpiry(t, snapshot)
		}},
	} {
		t.Run(test.name, test.check)
	}
	if storage.census(t) != before || provider.tokens.Load() != 1 || provider.jwks.Load() != 1 {
		t.Fatal("quarantine fences exchanged or changed authority")
	}

	// Observe durable state, not an elapsed sleep. Creation used the actual
	// factory clock; the immutable minimum one-minute deadline is not rewritten.
	privateFactoryWait(t, snapshot.CreatedAt().Add(75*time.Second), worker.Done(), func(ctx context.Context) bool {
		var expired bool
		if storage.admin.QueryRow(ctx, `SELECT state='expired' FROM mesh.auth_transaction
WHERE public_id=$1::UUID`, transactionID).Scan(&expired) != nil {
			t.Fatal("observe exact natural-deadline predicate")
		}
		return expired
	})
	stopPrivateFactoryExpiryWorker(t, worker)
	before.mutations++
	before.audit++
	before.outbox++
	storage.assertNaturalPendingExpiry(t, snapshot)
	if storage.census(t) != before || !storage.subjectLastSeen(t, 90).Equal(seen) {
		t.Fatal("natural expiry changed unrelated authority or lost exactly-one evidence")
	}
	storage.assertPersistedSession(t, fixture, session, token)
	if privateFactoryExpiryMetric(t, registry, "meshtransit_oidc_expiry_units_confirmed_total", "") != 1 ||
		privateFactoryExpiryMetric(t, registry, "meshtransit_oidc_expiry_worker_running", "") != 0 ||
		privateFactoryExpiryMetric(t, registry, "meshtransit_oidc_expiry_passes_active", "") != 0 {
		t.Fatal("natural-expiry worker receipt or joined lifecycle mismatch")
	}
	replay := newPrivateIdentityResponse()
	assertConcreteCallbackRejected(t, replay, factory.identity.dispatcher.Handle(replay, post))
	fresh, freshRegistry := startPrivateFactoryExpiryWorker(t, settings, workerPool)
	privateFactoryWait(t, time.Now().Add(3*time.Second), fresh.Done(), func(context.Context) bool {
		return privateFactoryExpiryMetric(t, freshRegistry, "meshtransit_oidc_expiry_passes_total", "empty") > 0
	})
	stopPrivateFactoryExpiryWorker(t, fresh)
	if storage.census(t) != before ||
		privateFactoryExpiryMetric(t, freshRegistry, "meshtransit_oidc_expiry_units_attempted_total", "") != 0 ||
		provider.discovery.Load() != 2 || provider.tokens.Load() != 1 || provider.jwks.Load() != 1 ||
		provider.unexpected.Load() != 0 || fixture.clockReads != 0 || len(fixture.effects) != 0 {
		t.Fatal("fresh worker/replay repeated evidence, effects or provider exchange")
	}
	factory.Close()
	ctx, cancel = context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if storage.runtime.Check(ctx) != nil || workerPool.Check(ctx) != nil || cache.Check(ctx) != nil {
		t.Fatal("identity/expiry owner closed borrowed dependencies")
	}
}

// The test owns one finite predicate loop. Each probe has a separate one-second
// query budget, cancellation is observed, and an early worker exit is failure.
func privateFactoryWait(t *testing.T, deadline time.Time, done <-chan error, predicate func(context.Context) bool) {
	t.Helper()
	ctx, cancel := context.WithDeadline(t.Context(), deadline)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			t.Fatal("bounded fixture predicate deadline")
		}
		matched := func() bool {
			probe, stop := context.WithTimeout(ctx, time.Second)
			defer stop()
			return predicate(probe)
		}()
		if ctx.Err() != nil {
			t.Fatal("bounded fixture predicate finished after deadline")
		}
		if matched {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("bounded fixture predicate canceled")
		case <-done:
			t.Fatal("expiry worker exited before predicate")
		case <-ticker.C:
		}
	}
}

func stopPrivateFactoryExpiryWorker(t *testing.T, worker *authexpiry.Worker) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
	defer cancel()
	if worker.Shutdown(ctx) != nil {
		t.Error("signal owned fixture expiry worker")
	}
	select {
	case err := <-worker.Done():
		if err != nil {
			t.Error("join owned fixture expiry worker")
		}
	case <-ctx.Done():
		t.Error("fixture expiry worker did not join")
	}
}

func privateFactoryExpiryMetric(t *testing.T, registry *prometheus.Registry, name, result string) float64 {
	t.Helper()
	families, err := registry.Gather()
	if err != nil {
		t.Fatal("gather owned fixture expiry metrics")
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			matches := result == "" && len(metric.GetLabel()) == 0
			if result != "" && len(metric.GetLabel()) == 1 {
				label := metric.GetLabel()[0]
				matches = label.GetName() == "result" && label.GetValue() == result
			}
			if matches {
				if metric.GetCounter() != nil {
					return metric.GetCounter().GetValue()
				}
				return metric.GetGauge().GetValue()
			}
		}
	}
	if result == "" {
		t.Fatal("missing owned expiry metric")
	}
	return 0
}
