//go:build integration

package main

import (
	"context"
	"io"
	"os"
	"runtime"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/meshtransit/meshtransit/core/internal/adapter/httpapi"
	"github.com/meshtransit/meshtransit/core/internal/adapter/oidc"
	"github.com/meshtransit/meshtransit/core/internal/platform/config"
)

func TestPrivateIdentityFactoryAbandonedChild(t *testing.T) {
	if os.Getenv("MESHTRANSIT_PRIVATE_FACTORY_ABANDONED_CHILD") != "1" {
		t.Skip("requires the exclusively owned helper process")
	}
	if os.Getenv("MESHTRANSIT_PRIVATE_FACTORY_INTEGRATION") != "1" || runtime.GOOS != "linux" ||
		os.Getenv("SSL_CERT_FILE") == "" || os.Getenv("SSL_CERT_DIR") == "" {
		t.Fatal("requires explicit owned Linux startup trust")
	}
	phase := privateFactoryInheritedPipe(t, 5, "redacted-fixture-phase")
	privateFactoryReportPhase(t, phase, 1)
	pipe := privateFactoryInheritedPipe(t, 3, "private-fixture-input")
	if pipe.SetReadDeadline(time.Now().Add(5*time.Second)) != nil {
		t.Fatal("bound private helper read")
	}
	input, err := decodePrivateFactoryAbandonedInput(pipe)
	if err != nil {
		t.Fatal("decode private helper input")
	}
	privateFactoryReportPhase(t, phase, 2)
	credentialPipe := privateFactoryInheritedPipe(t, 4, "private-fixture-credential")
	if credentialPipe.SetReadDeadline(time.Now().Add(5*time.Second)) != nil {
		t.Fatal("bound private credential read")
	}
	material, err := io.ReadAll(io.LimitReader(credentialPipe, 129))
	if err != nil || len(material) == 0 || len(material) > 128 {
		t.Fatal("read bounded private credential")
	}
	defer clear(material)
	privateFactoryReportPhase(t, phase, 3)
	storage := attachPrivateFactoryAbandonedRuntime(t)
	privateFactoryReportPhase(t, phase, 4)
	fixture := newPrivateIdentityFixture(t)
	privateFactoryReportPhase(t, phase, 5)
	fixture.options.Route = privateFactoryRoute(t, input.ProviderOrigin, 120)
	fixture.options.Start.PendingLifetime = time.Minute
	cache, _ := storage.openRedis(t)
	privateFactoryReportPhase(t, phase, 6)
	secret, err := oidc.NewBasicSecret(string(material))
	if err != nil {
		t.Fatal("construct private helper credential")
	}
	factory := composePrivateFactoryAbandoned(t, fixture, storage, cache, secret)
	privateFactoryReportPhase(t, phase, 7)
	request := fixture.loginRequest(t, httpapi.LoginCallbackContinuePath)
	request.RemoteAddr = "192.0.2.120:12345"
	request.Header["Cookie"] = input.Cookies
	request.Header.Set(oidc.LoginCSRFHeader, input.CSRF)
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	response := newPrivateIdentityResponse()
	privateFactoryReportPhase(t, phase, 8)
	if factory.identity.dispatcher.Handle(response, request.WithContext(ctx)) != nil {
		t.Fatal("protected helper returned before owned crash")
	}
	// This helper must never finish normally: parent owns crash and durable
	// acceptance. No private response or provider error is emitted to stderr.
	t.Fatal("protected helper completed before owned crash")
}

func TestPrivateIdentityFactoryProcessAbandonedIntegration(t *testing.T) {
	if os.Getenv("MESHTRANSIT_PRIVATE_FACTORY_INTEGRATION") != "1" {
		t.Skip("requires the owned Linux private-factory fixture lane")
	}
	if runtime.GOOS != "linux" || os.Getenv("SSL_CERT_FILE") == "" || os.Getenv("SSL_CERT_DIR") == "" {
		t.Fatal("requires explicit Linux process-startup fixture trust")
	}
	t.Cleanup(func() { goleak.VerifyNone(t) })
	storage := openPrivateFactoryIntegrationStorage(t, privateFactoryAbandonedDatabase)
	storage.seedAccount(t)
	fixture := newPrivateIdentityFixture(t)
	provider, secret := newPrivateFactorySigningProvider(t, 120)
	fixture.options.Route = provider.route
	fixture.options.Start.PendingLifetime = time.Minute
	storage.seedRoute(t, provider.route)
	storage.seedLoginSubject(t, fixture, 120, privateFactorySubject, true)
	seen := storage.subjectLastSeen(t, 120)
	cache, _ := storage.openRedis(t)
	factory := composePrivateFactoryAbandoned(t, fixture, storage, cache, secret)
	address := "192.0.2.120:12345"
	location, cookies, transactionID := storage.startConcreteLogin(t, fixture, factory, address)
	provider.arm(t, location, false)
	pending := storage.originalPendingExpiry(t, transactionID, provider.route.DeploymentID())
	proof := storage.privateFactoryProof(t, transactionID)
	before := storage.census(t)
	post := prepareConcreteCallback(t, fixture, factory, location, cookies, address, false)
	if before.sessions != 0 || before.transactions != 1 || storage.census(t) != before {
		t.Fatal("cold scope did not own one no-grant protected pending login")
	}
	barrier := provider.holdTokenMode(t, true)
	child := startPrivateFactoryAbandonedChild(t, privateFactoryAbandonedInput{
		ProviderOrigin: provider.server.URL,
		Cookies:        append([]string(nil), post.Header.Values("Cookie")...), CSRF: post.Header.Get(oidc.LoginCSRFHeader),
	}, provider.secret, barrier)
	privateFactoryWait(t, time.Now().Add(5*time.Second), nil, func(context.Context) bool {
		select {
		case <-child.done:
			t.Fatalf("owned helper exited before checked token barrier (closed phase %d)", child.lastPhase(t))
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
	if storage.census(t) != before || storage.privateFactoryProof(t, transactionID) != proof {
		t.Fatal("confirmed helper claim lost intact proof or exactly-one evidence")
	}
	child.killAndJoin(t, barrier)
	if child.lastPhase(t) != 8 {
		t.Fatal("checked crash did not reach exact protected dispatcher phase")
	}
	// No fresh worker exists yet. Reap + accepted-handler join must precede
	// this live stranded-proof read, not merely overlap the natural deadline.
	again := storage.originalConsumingExpiry(t, pending, provider.route)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	var live bool
	err := storage.admin.QueryRow(ctx, `SELECT expires_at>pg_catalog.clock_timestamp()+INTERVAL '10 seconds'
FROM mesh.auth_transaction WHERE public_id=$1::UUID`, transactionID).Scan(&live)
	cancel()
	if err != nil || !live || !again.ConsumedAt().Equal(consuming.ConsumedAt()) ||
		storage.census(t) != before || storage.privateFactoryProof(t, transactionID) != proof ||
		provider.tokens.Load() != 1 || provider.jwks.Load() != 0 || provider.unexpected.Load() != 0 {
		t.Fatal("joined process death did not leave live original consuming proof with zero grants")
	}
	pool := storage.openPrivateFactoryWorkerPool(t, privateFactoryAbandonedDatabase)
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
		t.Fatal("fresh worker changed not-due stranded proof")
	}
	privateFactoryWait(t, pending.CreatedAt().Add(75*time.Second), worker.Done(), func(ctx context.Context) bool {
		var expired bool
		if storage.admin.QueryRow(ctx, `SELECT state='expired' FROM mesh.auth_transaction
WHERE public_id=$1::UUID`, transactionID).Scan(&expired) != nil {
			t.Fatal("observe owned abandoned consuming natural expiry")
		}
		return expired
	})
	stopPrivateFactoryExpiryWorker(t, worker)
	before.mutations++
	before.audit++
	before.outbox++
	storage.assertNaturalConsumingExpiry(t, consuming)
	if storage.census(t) != before || !storage.subjectLastSeen(t, 120).Equal(seen) ||
		privateFactoryExpiryMetric(t, registry, "meshtransit_oidc_expiry_units_confirmed_total", "") != 1 ||
		privateFactoryExpiryMetric(t, registry, "meshtransit_oidc_expiry_worker_running", "") != 0 ||
		privateFactoryExpiryMetric(t, registry, "meshtransit_oidc_expiry_passes_active", "") != 0 {
		t.Fatal("joined abandoned expiry did not preserve exact no-grant lifecycle")
	}
	t.Run("expired continuation replay has zero effects", func(t *testing.T) {
		response := newPrivateIdentityResponse()
		assertConcreteCallbackRejected(t, response, factory.identity.dispatcher.Handle(response, post))
		if storage.census(t) != before || provider.tokens.Load() != 1 || provider.jwks.Load() != 0 {
			t.Fatal("expired abandoned replay changed authority or exchanged")
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
			t.Fatal("fresh worker repeated abandoned expiry evidence")
		}
	})
	if provider.discovery.Load() != 1 || provider.tokens.Load() != 1 || provider.jwks.Load() != 0 ||
		provider.unexpected.Load() != 0 || barrier.disconnected.Load() != 1 || fixture.clockReads != 0 || len(fixture.effects) != 0 {
		t.Fatal("process-abandoned gate used alternate effects or repeated provider work")
	}
	factory.Close()
	factory.Close()
	check, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	if storage.runtime.Check(check) != nil || pool.Check(check) != nil || cache.Check(check) != nil {
		t.Fatal("owned crash/expiry closed borrowed storage")
	}
}
