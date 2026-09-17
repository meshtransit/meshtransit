//go:build integration

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"os"
	"runtime"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/meshtransit/meshtransit/internal/adapter/httpapi"
	"github.com/meshtransit/meshtransit/internal/adapter/oidc"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

func TestPrivateIdentityFactoryWireACKIntegration(t *testing.T) {
	if os.Getenv("MESHTRANSIT_PRIVATE_FACTORY_INTEGRATION") != "1" {
		t.Skip("requires owned Linux wire acknowledgement fixture lane")
	}
	if runtime.GOOS != "linux" || os.Getenv("SSL_CERT_FILE") == "" || os.Getenv("SSL_CERT_DIR") == "" {
		t.Fatal("requires explicit Linux startup fixture trust")
	}
	t.Cleanup(func() { goleak.VerifyNone(t) })
	storage := openPrivateFactoryIntegrationStorage(t, "meshtransit_private_factory_ack")
	storage.seedAccount(t)
	relay := newPrivateFactoryACKRelay(t)
	wirePool := relay.openRuntime(t)
	var stranded oidcauth.ExpirySnapshot
	var undisclosed privateFactoryUndisclosedSession
	var issuePending oidcauth.ExpirySnapshot
	var issueRoute oidcauth.Route
	for index, test := range []struct {
		name   string
		suffix byte
		skip   int
	}{
		// Verification and subject lookup each confirm a read-only unit first.
		{name: "committed claim ACK lost", suffix: 130, skip: 1},
		{name: "committed issuance ACK lost", suffix: 136, skip: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPrivateIdentityFixture(t)
			provider, secret := newPrivateFactorySigningProvider(t, test.suffix)
			fixture.options.Route = provider.route
			fixture.options.Start.PendingLifetime = time.Minute
			storage.seedRoute(t, provider.route)
			storage.seedLoginSubject(t, fixture, test.suffix, privateFactorySubject, true)
			seen := storage.subjectLastSeen(t, test.suffix)
			cache, _ := storage.openRedis(t)
			factory, err := composePrivateIdentityFactory(t.Context(), fixture.keys,
				privateIdentityFactoryOptions{
					Application: fixture.options,
					Discovery:   oidc.Options{Timeout: time.Second, MaxMetadataBytes: 64 * 1024},
					Token:       privateIdentityTokenOptions{Timeout: 10 * time.Second, MaxTokenAge: time.Minute},
				},
				privateIdentityFactoryDependencies{
					Runtime: wirePool, Redis: cache, Secret: secret, Logger: discardCompositionLogger(),
				})
			if err != nil || factory == nil {
				t.Fatal("compose unchanged concrete wire acknowledgement factory")
			}
			t.Cleanup(factory.Close)
			address := "192.0.2.130:12345"
			location, cookies, transactionID := storage.startConcreteLogin(t, fixture, factory, address)
			provider.arm(t, location, false)
			pending := storage.originalPendingExpiry(t, transactionID, provider.route.DeploymentID())
			proof := storage.privateFactoryProof(t, transactionID)
			post := prepareConcreteCallback(t, fixture, factory, location, cookies, address, false)
			before := storage.census(t)
			relay.arm(t, test.skip)
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			response := newPrivateIdentityResponse()
			err = factory.identity.dispatcher.Handle(response, post.WithContext(ctx))
			cancel()
			assertPrivateFactoryUnknownACK(t, response, err)
			relay.assertDrops(t, index+1)
			calls, effects := int64(0), int64(1)
			if test.skip == 1 {
				stranded = storage.originalConsumingExpiry(t, pending, provider.route)
				if storage.privateFactoryProof(t, transactionID) != proof {
					t.Fatal("unknown claim changed original encrypted proof")
				}
			} else {
				issuePending, issueRoute = pending, provider.route
				undisclosed = storage.undisclosedSession(t, pending, provider.route)
				calls, effects = 1, 3
				before.sessions++
			}
			before.mutations += effects
			before.audit += effects
			before.outbox += effects
			if storage.census(t) != before || provider.tokens.Load() != calls || provider.jwks.Load() != calls {
				t.Fatal("unknown wire acknowledgement lost exact durable effects or exchange count")
			}
			// A real new TLS connection is needed after the dropped Commit response.
			ctx, cancel = context.WithTimeout(t.Context(), 5*time.Second)
			if wirePool.Check(ctx) != nil {
				t.Fatal("runtime transport did not reconnect after unknown Commit")
			}
			cancel()
			replay := newPrivateIdentityResponse()
			assertConcreteCallbackRejected(t, replay, factory.identity.dispatcher.Handle(replay, post))
			if storage.census(t) != before || provider.tokens.Load() != calls || provider.jwks.Load() != calls {
				t.Fatal("reconnected replay reclaimed, resolved or exchanged an uncertain callback")
			}
			if test.skip == 1 {
				storage.expireUnknownClaim(t, stranded)
				expiredReplay := newPrivateIdentityResponse()
				before = storage.census(t)
				assertConcreteCallbackRejected(t, expiredReplay, factory.identity.dispatcher.Handle(expiredReplay, post))
				if storage.census(t) != before || provider.tokens.Load() != 0 || provider.jwks.Load() != 0 {
					t.Fatal("expired unknown claim replay exchanged or wrote again")
				}
			}
			// Recovery is a new login, not recovery of a receipt or hidden bearer.
			location, cookies, _ = storage.startConcreteLogin(t, fixture, factory, address)
			provider.arm(t, location, false)
			fresh := prepareConcreteCallback(t, fixture, factory, location, cookies, address, false)
			before = storage.census(t)
			completed := newPrivateIdentityResponse()
			if factory.identity.dispatcher.Handle(completed, fresh) != nil || completed.Code != http.StatusOK ||
				completed.Body.String() != `{"return_path":"/console"}` {
				t.Fatal("independent fresh callback failed after transport recovery")
			}
			token := assertConcreteSessionCookies(t, completed, true)
			ctx, cancel = context.WithTimeout(t.Context(), 5*time.Second)
			session, authErr := factory.identity.sessions.Authenticate(ctx, token)
			cancel()
			if authErr != nil {
				t.Fatal("fresh cookie did not interoperate with existing Account Session verifier")
			}
			assertPrivateFactorySession(t, session, provider.route, test.suffix)
			storage.assertPersistedSession(t, fixture, session, token)
			before.sessions++
			before.mutations += 3
			before.audit += 3
			before.outbox += 3
			if storage.census(t) != before || !storage.subjectLastSeen(t, test.suffix).Equal(seen) ||
				provider.tokens.Load() != calls+1 || provider.jwks.Load() != calls+1 ||
				provider.discovery.Load() != 2 || provider.unexpected.Load() != 0 ||
				fixture.clockReads != 0 || len(fixture.effects) != 0 {
				t.Fatal("fresh recovery callback widened authority or used alternate effects")
			}
			relay.assertDrops(t, index+1)
		})
	}
	if !stranded.IsValid() || undisclosed.id == "" {
		t.Fatal("missing both independently committed unknown outcomes")
	}
	storage.assertNaturalConsumingExpiry(t, stranded)
	before := storage.census(t)
	pool := storage.openPrivateFactoryWorkerPool(t, "meshtransit_private_factory_ack")
	settings := config.AuthExpiryConfig{
		DeploymentID: stranded.DeploymentID(), BatchSize: 8, PollInterval: 100 * time.Millisecond,
		PassTimeout: 3 * time.Second, UnitTimeout: time.Second, RollbackTimeout: time.Second,
	}
	freshWorker, freshMetrics := startPrivateFactoryExpiryWorker(t, settings, pool)
	privateFactoryWait(t, time.Now().Add(3*time.Second), freshWorker.Done(), func(context.Context) bool {
		return privateFactoryExpiryMetric(t, freshMetrics, "meshtransit_oidc_expiry_passes_total", "empty") > 0
	})
	stopPrivateFactoryExpiryWorker(t, freshWorker)
	if storage.census(t) != before ||
		storage.undisclosedSession(t, issuePending, issueRoute) != undisclosed ||
		privateFactoryExpiryMetric(t, freshMetrics, "meshtransit_oidc_expiry_units_attempted_total", "") != 0 {
		t.Fatal("fresh worker replayed an uncertain terminal outcome")
	}
	relay.assertDrops(t, 2)
}

func assertPrivateFactoryUnknownACK(t *testing.T, response *privateIdentityResponse, err error) {
	t.Helper()
	unknown := errors.Is(err, httpapi.ErrLoginCompletionUnavailable) &&
		errors.Is(err, oidcauth.ErrCommitOutcomeUnknown)
	timedOut := errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
	released := response.Body.Len() != 0 || response.Header().Get("Set-Cookie") != "" ||
		response.Header().Get("Location") != ""
	if !unknown || timedOut || released {
		t.Fatal("wire ACK loss did not return exact unknown category with zero browser release")
	}
}

// Application joins precede this guard. pgx canceled-connection destruction
// may still own a lease; never force Close or treat the deadline as idle proof.
func closePrivateFactoryACKPool(ctx context.Context, pool *postgresadapter.Pool) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := pool.Shutdown(ctx)
		if !errors.Is(err, postgresadapter.ErrPoolInUse) {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.Join(err, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (storage *privateFactoryIntegrationStorage) expireUnknownClaim(
	t *testing.T,
	snapshot oidcauth.ExpirySnapshot,
) {
	t.Helper()
	before := storage.census(t)
	pool := storage.openPrivateFactoryWorkerPool(t, "meshtransit_private_factory_ack")
	settings := config.AuthExpiryConfig{
		DeploymentID: snapshot.DeploymentID(), BatchSize: 8, PollInterval: 100 * time.Millisecond,
		PassTimeout: 3 * time.Second, UnitTimeout: time.Second, RollbackTimeout: time.Second,
	}
	worker, metrics := startPrivateFactoryExpiryWorker(t, settings, pool)
	privateFactoryWait(t, snapshot.CreatedAt().Add(75*time.Second), worker.Done(), func(ctx context.Context) bool {
		var expired bool
		if storage.admin.QueryRow(ctx, `SELECT state='expired' FROM mesh.auth_transaction
WHERE public_id=$1::UUID`, snapshot.TransactionID().String()).Scan(&expired) != nil {
			t.Fatal("observe unknown-claim original natural expiry")
		}
		return expired
	})
	stopPrivateFactoryExpiryWorker(t, worker)
	storage.assertNaturalConsumingExpiry(t, snapshot)
	before.mutations++
	before.audit++
	before.outbox++
	if storage.census(t) != before ||
		privateFactoryExpiryMetric(t, metrics, "meshtransit_oidc_expiry_units_confirmed_total", "") != 1 {
		t.Fatal("unknown-claim cleanup lost exact once-only no-grant disposition")
	}
	fresh, freshMetrics := startPrivateFactoryExpiryWorker(t, settings, pool)
	privateFactoryWait(t, time.Now().Add(3*time.Second), fresh.Done(), func(context.Context) bool {
		return privateFactoryExpiryMetric(t, freshMetrics, "meshtransit_oidc_expiry_passes_total", "empty") > 0
	})
	stopPrivateFactoryExpiryWorker(t, fresh)
	if storage.census(t) != before ||
		privateFactoryExpiryMetric(t, freshMetrics, "meshtransit_oidc_expiry_units_attempted_total", "") != 0 {
		t.Fatal("new worker replayed naturally expired unknown claim")
	}
}

type privateFactoryUndisclosedSession struct {
	id         string
	updated    time.Time
	digestHash [32]byte
	version    int64
}

// Read committed result metadata only; never recover the undisclosed bearer.
func (storage *privateFactoryIntegrationStorage) undisclosedSession(
	t *testing.T,
	pending oidcauth.ExpirySnapshot,
	route oidcauth.Route,
) privateFactoryUndisclosedSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var result privateFactoryUndisclosedSession
	var digest []byte
	var exact bool
	hash := pending.SemanticHash()
	if storage.admin.QueryRow(ctx, `SELECT s.public_id::TEXT,s.updated_at,s.version,s.token_digest,
auth.state='succeeded' AND auth.version=3 AND auth.failure_class IS NULL
AND auth.created_at=$2 AND auth.expires_at=$3 AND auth.binding_semantic_hash=$4
AND auth.consumed_at>=auth.created_at AND auth.consumed_at<auth.expires_at
AND auth.operation_kind='login' AND auth.principal_id IS NULL
AND auth.consumed_result_kind='account_session' AND auth.consumed_result_public_id=s.public_id
AND auth.pkce_verifier_encryption_algorithm IS NULL AND auth.pkce_verifier_encryption_key_id IS NULL
AND auth.pkce_verifier_ciphertext IS NULL AND s.state='active' AND s.version=1
AND s.principal_id=11 AND s.identity_provider_id=auth.identity_provider_id
AND s.identity_provider_client_id=auth.identity_provider_client_id AND s.login_workspace_id=auth.workspace_id
AND s.provider_generation=1 AND s.deployment_recovery_epoch=1 AND s.deployment_id=auth.deployment_id
AND s.principal_authority_generation=1 AND s.account_session_generation=1
AND s.token_digest_algorithm='hmac-sha256-v1' AND s.token_digest_key_id IS NOT NULL
AND s.provider_sid_digest_algorithm IS NULL AND s.provider_sid_digest_key_id IS NULL
AND s.provider_sid_digest IS NULL AND s.acr='urn:meshtransit:assurance:mfa'
AND s.authentication_time<=s.created_at AND s.idle_expires_at>pg_catalog.clock_timestamp()
AND s.absolute_expires_at>=s.idle_expires_at
AND s.absolute_expires_at<=s.created_at+INTERVAL '24 hours'
AND d.installation_public_id=$5::UUID AND w.public_id=$6::UUID
AND p.public_id=$7::UUID AND c.public_id=$8::UUID
AND subject.deployment_id=s.deployment_id AND subject.principal_id=s.principal_id
AND subject.identity_provider_id=s.identity_provider_id AND subject.state='active'
FROM mesh.auth_transaction auth JOIN mesh.account_session s ON s.public_id=auth.consumed_result_public_id
	JOIN mesh.deployment d ON d.id=s.deployment_id
	JOIN mesh.workspace w ON w.id=s.login_workspace_id
	JOIN mesh.identity_provider p ON p.id=s.identity_provider_id
	JOIN mesh.identity_provider_client c ON c.id=s.identity_provider_client_id
	JOIN mesh.identity_subject subject ON subject.id=s.identity_subject_id
WHERE auth.public_id=$1::UUID`, pending.TransactionID().String(), pending.CreatedAt(),
		pending.ExpiresAt(), hash[:], route.DeploymentID().String(), route.WorkspaceID().String(),
		route.ProviderID().String(), route.ClientID().String()).Scan(
		&result.id, &result.updated, &result.version, &digest, &exact,
	) != nil ||
		!exact || len(digest) != sha256.Size {
		t.Fatal("undisclosed committed Session lost exact atomic lifecycle and identity fences")
	}
	result.digestHash = sha256.Sum256(digest)
	clear(digest)
	storage.assertCallbackEvidence(t, pending.TransactionID().String(), result.id)
	// Syntax ID construction does not authenticate or disclose this Session.
	if _, err := publicid.Parse(result.id); err != nil || !route.IsValid() {
		t.Fatal("invalid committed undisclosed result identity")
	}
	return result
}
