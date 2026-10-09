//go:build integration

package main

import (
	"context"
	"net/http"
	"os"
	"runtime"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/meshtransit/meshtransit/core/internal/adapter/oidc"
	"github.com/meshtransit/meshtransit/core/internal/platform/config"
)

func TestPrivateIdentityFactoryConsumingCleanupIntegration(t *testing.T) {
	if os.Getenv("MESHTRANSIT_PRIVATE_FACTORY_INTEGRATION") != "1" {
		t.Skip("requires the owned Linux private-factory fixture lane")
	}
	missingTrust := os.Getenv("SSL_CERT_FILE") == "" || os.Getenv("SSL_CERT_DIR") == ""
	if runtime.GOOS != "linux" || missingTrust {
		t.Fatal("requires explicit Linux process-startup fixture trust")
	}
	t.Cleanup(func() { goleak.VerifyNone(t) })
	storage := openPrivateFactoryIntegrationStorage(t, "meshtransit_private_factory_consuming")
	storage.seedAccount(t)
	fixture := newPrivateIdentityFixture(t)
	provider, secret := newPrivateFactorySigningProvider(t, 100)
	fixture.options.Route = provider.route
	fixture.options.Start.PendingLifetime = time.Minute
	storage.seedRoute(t, provider.route)
	storage.seedLoginSubject(t, fixture, 100, privateFactorySubject, true)
	seen := storage.subjectLastSeen(t, 100)
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
		t.Fatal("compose concrete consuming-cleanup factory")
	}
	t.Cleanup(factory.Close)
	address := "192.0.2.100:12345"
	location, cookies, transactionID := storage.startConcreteLogin(t, fixture, factory, address)
	provider.arm(t, location, false)
	pending := storage.originalPendingExpiry(t, transactionID, provider.route.DeploymentID())
	proof := storage.privateFactoryProof(t, transactionID)
	before := storage.census(t)
	if before.sessions != 0 || before.transactions != 1 {
		t.Fatal("cold scope did not own exactly one pending no-grant login")
	}
	pool := storage.openConsumingWorkerPool(t)
	settings := config.AuthExpiryConfig{
		DeploymentID: provider.route.DeploymentID(), BatchSize: 8, PollInterval: 100 * time.Millisecond,
		PassTimeout: 3 * time.Second, UnitTimeout: time.Second, RollbackTimeout: time.Second,
	}
	worker, registry := startPrivateFactoryExpiryWorker(t, settings, pool)
	privateFactoryWait(t, time.Now().Add(3*time.Second), worker.Done(), func(context.Context) bool {
		return privateFactoryExpiryMetric(t, registry, "meshtransit_oidc_expiry_passes_total", "empty") > 0
	})
	if storage.census(t) != before ||
		privateFactoryExpiryMetric(t, registry, "meshtransit_oidc_expiry_units_attempted_total", "") != 0 {
		t.Fatal("not-due factory transaction gained effects")
	}
	// The immutable original deadline is approached through a live DB predicate,
	// never rewritten. Capture/proof are prepared fresh inside the remaining window.
	privateFactoryWait(t, pending.ExpiresAt().Add(-2*time.Second), worker.Done(), func(ctx context.Context) bool {
		var ready, live bool
		if storage.admin.QueryRow(ctx, `SELECT pg_catalog.clock_timestamp() >= expires_at-INTERVAL '5 seconds',
state='pending' AND version=1 AND expires_at>pg_catalog.clock_timestamp()+INTERVAL '2 seconds'
FROM mesh.auth_transaction WHERE public_id=$1::UUID`, transactionID).Scan(&ready, &live) != nil || !live {
			t.Fatal("original pending claim window was lost")
		}
		return ready
	})
	post := prepareConcreteCallback(t, fixture, factory, location, cookies, address, false)
	if storage.census(t) != before || provider.tokens.Load() != 0 || provider.jwks.Load() != 0 {
		t.Fatal("fresh capture/preparation granted authority or exchanged")
	}
	barrier := provider.holdToken(t)
	owner := startPrivateFactoryCallbackOwner(t, factory, post, barrier)
	privateFactoryWait(t, time.Now().Add(2*time.Second), worker.Done(), func(context.Context) bool {
		select {
		case <-owner.done:
			t.Fatal("callback completed before checked provider barrier")
		case <-barrier.entered:
			return true
		default:
			return false
		}
		return false
	})
	consuming := storage.originalConsumingExpiry(t, pending, provider.route)
	before.mutations++
	before.audit++
	before.outbox++
	if storage.census(t) != before || storage.privateFactoryProof(t, transactionID) != proof ||
		provider.tokens.Load() != 1 || provider.jwks.Load() != 0 {
		t.Fatal("checked in-flight claim lost proof or exactly-one anonymous evidence")
	}
	privateFactoryWait(t, pending.CreatedAt().Add(75*time.Second), worker.Done(), func(ctx context.Context) bool {
		var expired bool
		if storage.admin.QueryRow(ctx, `SELECT state='expired' FROM mesh.auth_transaction
WHERE public_id=$1::UUID`, transactionID).Scan(&expired) != nil {
			t.Fatal("observe exact consuming natural-deadline predicate")
		}
		return expired
	})
	stopPrivateFactoryExpiryWorker(t, worker)
	before.mutations++
	before.audit++
	before.outbox++
	storage.assertNaturalConsumingExpiry(t, consuming)
	if storage.census(t) != before || provider.jwks.Load() != 0 ||
		privateFactoryExpiryMetric(t, registry, "meshtransit_oidc_expiry_units_confirmed_total", "") != 1 ||
		privateFactoryExpiryMetric(t, registry, "meshtransit_oidc_expiry_worker_running", "") != 0 ||
		privateFactoryExpiryMetric(t, registry, "meshtransit_oidc_expiry_passes_active", "") != 0 {
		t.Fatal("natural consuming expiry lost exactly-one joined no-grant outcome")
	}
	barrier.unblock()
	if owner.join(t, barrier) != nil {
		t.Fatal("join callback and checked token handler before reading response")
	}
	assertConcreteCallbackRejected(t, owner.response, owner.err)
	storage.assertNaturalConsumingExpiry(t, consuming)
	if storage.census(t) != before || !storage.subjectLastSeen(t, 100).Equal(seen) ||
		provider.tokens.Load() != 1 || provider.jwks.Load() != 1 || provider.unexpected.Load() != 0 {
		t.Fatal("valid late exchange created Session, repeated evidence or skipped signature validation")
	}
	t.Run("expired continuation replay has zero effects", func(t *testing.T) {
		response := newPrivateIdentityResponse()
		assertConcreteCallbackRejected(t, response, factory.identity.dispatcher.Handle(response, post))
		if storage.census(t) != before || provider.tokens.Load() != 1 || provider.jwks.Load() != 1 {
			t.Fatal("expired continuation replay changed evidence or exchanged again")
		}
	})
	t.Run("fresh worker observes empty without replay", func(t *testing.T) {
		fresh, metrics := startPrivateFactoryExpiryWorker(t, settings, pool)
		privateFactoryWait(t, time.Now().Add(3*time.Second), fresh.Done(), func(context.Context) bool {
			return privateFactoryExpiryMetric(t, metrics, "meshtransit_oidc_expiry_passes_total", "empty") > 0
		})
		stopPrivateFactoryExpiryWorker(t, fresh)
		if storage.census(t) != before ||
			privateFactoryExpiryMetric(t, metrics, "meshtransit_oidc_expiry_units_attempted_total", "") != 0 {
			t.Fatal("fresh worker repeated terminal mutation")
		}
	})
	if provider.discovery.Load() != 1 || provider.tokens.Load() != 1 || provider.jwks.Load() != 1 ||
		provider.unexpected.Load() != 0 || fixture.clockReads != 0 || len(fixture.effects) != 0 {
		t.Fatal("concrete consuming gate used alternate effects or repeated provider work")
	}
	factory.Close()
	factory.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if storage.runtime.Check(ctx) != nil || pool.Check(ctx) != nil || cache.Check(ctx) != nil {
		t.Fatal("joined request/expiry owners closed borrowed storage")
	}
}

type privateFactoryCallbackOwner struct {
	done     chan struct{}
	response *privateIdentityResponse
	err      error
}

func startPrivateFactoryCallbackOwner(
	t *testing.T,
	factory *privateIdentityFactory,
	request *http.Request,
	barrier *privateFactoryTokenBarrier,
) *privateFactoryCallbackOwner {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	owner := &privateFactoryCallbackOwner{done: make(chan struct{}), response: newPrivateIdentityResponse()}
	// Cleanup is registered before dispatch and runs before worker/client/pool
	// cleanup. No test assertion occurs on the request goroutine.
	t.Cleanup(func() {
		cancel()
		barrier.unblock()
		if owner.join(t, barrier) != nil {
			t.Error("join callback and checked token handler during cleanup")
		}
	})
	go func() {
		defer close(owner.done)
		defer cancel()
		owner.err = factory.identity.dispatcher.Handle(owner.response, request.WithContext(ctx))
	}()
	return owner
}

func (owner *privateFactoryCallbackOwner) join(t *testing.T, barrier *privateFactoryTokenBarrier) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
	defer cancel()
	select {
	case <-owner.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	if barrier.accepted.Load() {
		select {
		case <-barrier.exited:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
