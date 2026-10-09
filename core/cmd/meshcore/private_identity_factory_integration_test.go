//go:build integration

package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"meshtransit.net/core/internal/adapter/httpapi"
	"meshtransit.net/core/internal/adapter/oidc"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity/oidcauth"
	"meshtransit.net/core/internal/domain/workspace"
)

func TestPrivateIdentityFactoryInitiationIntegration(t *testing.T) {
	if os.Getenv("MESHTRANSIT_PRIVATE_FACTORY_INTEGRATION") != "1" {
		t.Skip("requires the owned Linux private-factory fixture lane")
	}
	missingTrust := os.Getenv("SSL_CERT_FILE") == "" || os.Getenv("SSL_CERT_DIR") == ""
	if runtime.GOOS != "linux" || missingTrust {
		t.Fatal("requires explicit Linux process-startup fixture trust")
	}
	// Register first so leak verification runs after every owned resource closes.
	t.Cleanup(func() { goleak.VerifyNone(t) })
	storage := openPrivateFactoryIntegrationStorage(t, "meshtransit_private_factory")
	// Cases share only an immutable Deployment and its audited fixture scope.
	// Each route/request/provider is independent; no parallel shared-head writes.
	for index, test := range []struct {
		name, metadata         string
		suffix                 byte
		untrusted, closedRedis bool
	}{
		{name: "pending login", metadata: "valid", suffix: 20},
		{name: "endpoint mismatch", metadata: "mismatch", suffix: 24},
		{name: "discovery redirect", metadata: "redirect", suffix: 28},
		{name: "untrusted TLS", metadata: "valid", suffix: 32, untrusted: true},
		{name: "shared budget unavailable", metadata: "valid", suffix: 36, closedRedis: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPrivateIdentityFixture(t)
			provider := newPrivateFactoryMetadataProvider(t, test.metadata, test.untrusted)
			fixture.options.Route = provider.route(t, test.suffix)
			storage.seedRoute(t, fixture.options.Route)
			cache, closeCache := storage.openRedis(t)
			material := [32]byte{}
			if _, err := rand.Read(material[:]); err != nil {
				t.Fatal("generate resident fixture credential")
			}
			secret, err := oidc.NewBasicSecret(base64.RawURLEncoding.EncodeToString(material[:]))
			clear(material[:])
			if err != nil {
				t.Fatal("construct resident fixture credential")
			}
			factory, err := composePrivateIdentityFactory(t.Context(), fixture.keys, privateIdentityFactoryOptions{
				Application: fixture.options,
				Discovery:   oidc.Options{Timeout: time.Second, MaxMetadataBytes: 64 * 1024},
				Token:       privateIdentityTokenOptions{Timeout: 10 * time.Second, MaxTokenAge: time.Minute},
			}, privateIdentityFactoryDependencies{
				Runtime: storage.runtime, Redis: cache, Secret: secret, Logger: discardCompositionLogger(),
			})
			if err != nil || factory == nil {
				t.Fatal("compose concrete private factory")
			}
			t.Cleanup(factory.Close)
			before := storage.census(t)
			if test.closedRedis {
				if err := closeCache(); err != nil {
					t.Fatal("close borrowed fixture Redis")
				}
			}
			request := fixture.loginRequest(t, httpapi.LoginPreparePath)
			request.RemoteAddr = "192.0.2." + strconv.Itoa(20+index) + ":12345"
			prepared := newPrivateIdentityResponse()
			if err := factory.identity.dispatcher.Handle(prepared, request); err != nil {
				t.Fatal("private prepare dispatcher")
			}
			if test.closedRedis {
				assertPrivateFactoryInitiationDenied(t, prepared)
			} else {
				var intent struct {
					Proof string `json:"csrf_token"`
				}
				if err := json.Unmarshal(prepared.Body.Bytes(), &intent); err != nil {
					t.Fatal("decode prepare response")
				}
				invalidIntent := prepared.Code != http.StatusOK || intent.Proof == ""
				if invalidIntent {
					t.Fatal("prepare concrete route without granting authority")
				}
				if storage.census(t) != before || provider.discovery.Load() != 0 {
					t.Fatal("prepare persisted login authority or contacted provider")
				}
				started := newPrivateIdentityResponse()
				request = fixture.loginRequest(t, httpapi.LoginStartPath)
				request.RemoteAddr = "192.0.2." + strconv.Itoa(20+index) + ":12345"
				request.Header.Set(oidc.LoginCSRFHeader, intent.Proof)
				for _, cookie := range privateFactoryResponseCookies(t, prepared) {
					request.AddCookie(cookie)
				}
				if err := factory.identity.dispatcher.Handle(started, request); err != nil {
					t.Fatal("private start dispatcher")
				}
				if test.metadata == "valid" && !test.untrusted {
					storage.assertPending(t, fixture, started)
					before.transactions++ // Pending auth, never a Session.
					before.mutations++
					before.audit++
					before.outbox++
				} else {
					assertPrivateFactoryInitiationDenied(t, started)
				}
			}
			if storage.census(t) != before || provider.other.Load() != 0 {
				t.Fatal("initiation changed unrelated authority or followed provider endpoints")
			}
			expectedDiscovery := int64(1)
			if test.closedRedis || test.untrusted {
				expectedDiscovery = 0
			}
			alternateEffects := fixture.clockReads != 0 || len(fixture.effects) != 0
			if provider.discovery.Load() != expectedDiscovery || alternateEffects {
				t.Fatal("unexpected provider attempt or alternate fixture effect")
			}
			factory.Close()
			factory.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if err := storage.runtime.Check(ctx); err != nil {
				t.Fatal("factory closed borrowed runtime pool")
			}
			if !test.closedRedis {
				if err := cache.Check(ctx); err != nil {
					t.Fatal("factory closed borrowed Redis")
				}
			}
		})
	}
}

func privateFactoryResponseCookies(t *testing.T, response *privateIdentityResponse) []*http.Cookie {
	t.Helper()
	result := response.Result()
	defer func() {
		if err := result.Body.Close(); err != nil {
			t.Error("close fixture response")
		}
	}()
	return result.Cookies()
}

func assertPrivateFactoryInitiationDenied(t *testing.T, response *privateIdentityResponse) {
	t.Helper()
	releasedMaterial := response.Header().Get("Set-Cookie") != "" || response.Header().Get("Location") != ""
	if response.Code != http.StatusServiceUnavailable || releasedMaterial {
		t.Fatal("dependency rejection released browser material")
	}
	if response.Body.String() != `{"error":{"code":"login_unavailable","message":"login could not be completed"}}` {
		t.Fatal("dependency rejection reflected authorization material")
	}
}

type privateFactoryMetadataProvider struct {
	server           *httptest.Server
	discovery, other atomic.Int64
	unavailable      atomic.Bool
}

func newPrivateFactoryMetadataProvider(t *testing.T, mode string, untrusted bool) *privateFactoryMetadataProvider {
	t.Helper()
	provider := &privateFactoryMetadataProvider{}
	provider.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		invalidTarget := r.URL.Path != "/realm/discovery" || r.URL.RawQuery != ""
		if r.Method != http.MethodGet || invalidTarget {
			provider.other.Add(1)
			http.Error(w, "unexpected fixture request", http.StatusBadRequest)
			return
		}
		provider.discovery.Add(1)
		if provider.unavailable.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if mode == "redirect" {
			http.Redirect(w, r, provider.server.URL+"/trap", http.StatusTemporaryRedirect)
			return
		}
		base := provider.server.URL + "/realm"
		token := base + "/token"
		if mode == "mismatch" {
			token = base + "/unregistered-token"
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"issuer": base, "authorization_endpoint": base + "/authorize", "token_endpoint": token, "jwks_uri": base + "/jwks",
			"response_types_supported": []string{"code"}, "code_challenge_methods_supported": []string{"S256"},
			"id_token_signing_alg_values_supported": []string{"RS256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		}); err != nil {
			provider.other.Add(1)
		}
	}))
	provider.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	if !untrusted {
		certificate, err := tls.LoadX509KeyPair(os.Getenv("MESHTRANSIT_TEST_OIDC_TLS_CERTIFICATE_FILE"), os.Getenv("MESHTRANSIT_TEST_OIDC_TLS_PRIVATE_KEY_FILE"))
		if err != nil {
			t.Fatal("load owned provider TLS fixture")
		}
		provider.server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
	}
	provider.server.StartTLS()
	t.Cleanup(provider.server.Close)
	return provider
}

func (provider *privateFactoryMetadataProvider) route(t *testing.T, suffix byte) oidcauth.Route {
	t.Helper()
	return privateFactoryRoute(t, provider.server.URL, suffix)
}

// privateFactoryLoginWorkspaceID names the fixture Workspace whose routing and
// active membership let the fixture Account sign in. Routes name no Workspace;
// the fixture keeps one owned identity per provider, one byte below it.
func privateFactoryLoginWorkspaceID(t *testing.T, route oidcauth.Route) workspace.ID {
	t.Helper()
	provider := route.ProviderID().Bytes()
	return workspace.ID(privateIdentityID(t, provider[15]-1))
}

func privateFactoryRoute(t *testing.T, origin string, suffix byte) oidcauth.Route {
	t.Helper()
	base := origin + "/realm"
	route, err := oidcauth.NewRoute(oidcauth.RouteParams{
		DeploymentID: deployment.ID(privateIdentityID(t, 1)), ProviderID: oidcauth.ProviderID(privateIdentityID(t, suffix+1)),
		ClientID: oidcauth.ClientID(privateIdentityID(t, suffix+2)), ProviderGeneration: 1,
		RecoveryEpoch: 1, Issuer: base, DiscoveryURI: base + "/discovery",
		AuthorizationEndpoint: base + "/authorize", TokenEndpoint: base + "/token", JWKSURI: base + "/jwks",
		OIDCClientID: "private-browser-client", ClientKind: "confidential", ClientAuthMethod: "client_secret_basic",
		Scopes: []string{"openid"}, AllowedAlgorithms: []string{"RS256"}, RedirectID: "browser-callback",
		RedirectURI: "https://console.example.test/auth/v1/callback", ReturnRouteID: "console",
	})
	if err != nil {
		t.Fatal("construct owned fixture route")
	}
	return route
}

func (storage *privateFactoryIntegrationStorage) assertPending(t *testing.T, fixture *privateIdentityFixture, response *privateIdentityResponse) {
	t.Helper()
	var body struct {
		URL string `json:"authorization_url"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || response.Code != http.StatusOK {
		t.Fatal("start concrete factory")
	}
	location, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal("parse owned authorization result")
	}
	route := fixture.options.Route
	if location.Scheme+"://"+location.Host+location.Path != route.AuthorizationEndpoint() {
		t.Fatal("authorization endpoint changed")
	}
	state, err := oidcauth.ParseState(location.Query().Get("state"))
	if err != nil {
		t.Fatal("authorization state is malformed")
	}
	nonce, err := oidcauth.ParseNonce(location.Query().Get("nonce"))
	if err != nil {
		t.Fatal("authorization nonce is malformed")
	}
	digest, err := fixture.keys.transaction.State(route.DeploymentID(), route.RecoveryEpoch(), state)
	if err != nil {
		t.Fatal("derive resident lookup evidence")
	}
	window, err := privateIdentityDatabaseWindow(5 * time.Second)
	if err != nil {
		t.Fatal("bound durable read owner")
	}
	store, err := postgresadapter.NewAuthTransactionStore(storage.runtime, window)
	if err != nil {
		t.Fatal("open independent durable read owner")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	snapshot, found, err := store.LoadPending(ctx, route, digest)
	invalidSnapshot := !snapshot.MatchesRoute(route) || snapshot.Version() != 1
	loadFailed := err != nil || !found
	if loadFailed || invalidSnapshot {
		t.Fatal("load exact anonymous pending transaction")
	}
	expectedNonce, err := fixture.keys.transaction.Nonce(route.DeploymentID(), route.RecoveryEpoch(), nonce)
	if err != nil || snapshot.NonceDigest() != expectedNonce {
		t.Fatal("persisted nonce evidence changed")
	}
	binding, err := route.Binding(snapshot.TransactionID())
	if err != nil {
		t.Fatal("bind exact pending transaction")
	}
	proof, err := fixture.keys.verifier.OpenBrowser(binding, snapshot.VerifierCiphertext())
	invalidChallenge := proof.Verifier().Challenge() != location.Query().Get("code_challenge") || location.Query().Get("code_challenge_method") != "S256"
	if err != nil || invalidChallenge {
		t.Fatal("durable PKCE envelope does not bind authorization request")
	}
	var cookie oidcauth.PreAuthCookie
	preAuthCookies := 0
	for _, candidate := range privateFactoryResponseCookies(t, response) {
		if candidate.Name == "__Host-mt_session" {
			t.Fatal("initiation granted a Session cookie")
		}
		if candidate.Name == oidc.PreAuthCookieName {
			preAuthCookies++
			cookie, err = oidcauth.ParsePreAuthCookie(candidate.Value)
			missingFlags := !candidate.Secure || !candidate.HttpOnly
			unsafeCookie := missingFlags || candidate.Path != "/"
			wrongScope := candidate.Domain != "" || candidate.SameSite != http.SameSiteLaxMode
			if err != nil || unsafeCookie || wrongScope {
				t.Fatal("invalid pre-auth cookie")
			}
		}
	}
	if preAuthCookies != 1 || !fixture.keys.transaction.VerifyPreAuthCookie(binding, cookie, proof.CookieDigest()) {
		t.Fatal("durable envelope lost browser-cookie binding")
	}
	var anonymous bool
	if err := storage.admin.QueryRow(ctx, `SELECT auth.operation_kind='login' AND auth.principal_id IS NULL
AND auth.consumed_result_kind IS NULL AND auth.consumed_result_public_id IS NULL
AND audit.action='auth_transaction.created' AND audit.actor_principal_public_id IS NULL
AND outbox.event_class='identity.auth_transaction.created' AND outbox.network_revision IS NULL
FROM mesh.auth_transaction auth
JOIN mesh_audit.audit_event audit ON audit.target_kind='auth_transaction' AND audit.target_public_id=auth.public_id
JOIN mesh_ops.outbox_event outbox ON outbox.aggregate_kind='auth_transaction' AND outbox.aggregate_public_id=auth.public_id
WHERE auth.public_id=$1::UUID`, snapshot.TransactionID().String()).Scan(&anonymous); err != nil || !anonymous {
		t.Fatal("pending login granted Principal authority")
	}
}
