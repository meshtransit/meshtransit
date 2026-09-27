//go:build integration

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/meshtransit/meshtransit/internal/adapter/httpapi"
	"github.com/meshtransit/meshtransit/internal/adapter/oidc"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

func TestPrivateIdentityFactoryCallbackIntegration(t *testing.T) {
	if os.Getenv("MESHTRANSIT_PRIVATE_FACTORY_INTEGRATION") != "1" {
		t.Skip("requires the owned Linux private-factory fixture lane")
	}
	missingTrust := os.Getenv("SSL_CERT_FILE") == "" || os.Getenv("SSL_CERT_DIR") == ""
	if runtime.GOOS != "linux" || missingTrust {
		t.Fatal("requires explicit Linux process-startup fixture trust")
	}
	t.Cleanup(func() { goleak.VerifyNone(t) })
	storage := openPrivateFactoryIntegrationStorage(t, "meshtransit_private_factory_callback")
	storage.seedAccount(t)
	// Each route has independent subject/member authority. Only immutable Account/
	// Deployment and their audit head are shared; writes remain sequential.
	for index, test := range []struct {
		name                          string
		suffix                        byte
		missingSubject, missingMember bool
		wrongNonce, providerError     bool
	}{
		{name: "fresh Session and replay", suffix: 50},
		{name: "case-sensitive subject denial and replay", suffix: 56, missingSubject: true},
		{name: "missing membership denial and replay", suffix: 62, missingMember: true},
		{name: "signed wrong nonce denial and replay", suffix: 68, wrongNonce: true},
		{name: "provider error without exchange and replay", suffix: 74, providerError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPrivateIdentityFixture(t)
			provider, secret := newPrivateFactorySigningProvider(t, test.suffix)
			fixture.options.Route = provider.route
			storage.seedRoute(t, provider.route)
			subject := privateFactorySubject
			if test.missingSubject {
				subject = "opaque-fixture-subject"
			}
			storage.seedLoginSubject(t, fixture, test.suffix, subject, !test.missingMember)
			seen := storage.subjectLastSeen(t, test.suffix)
			cache, _ := storage.openRedis(t)
			factory, err := composePrivateIdentityFactory(
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
			if err != nil || factory == nil {
				t.Fatal("compose concrete callback factory")
			}
			t.Cleanup(factory.Close)
			address := "192.0.2." + strconv.Itoa(60+index) + ":12345"
			location, cookies, transactionID := storage.startConcreteLogin(t, fixture, factory, address)
			provider.arm(t, location, test.wrongNonce)
			before := storage.census(t)
			post := prepareConcreteCallback(t, fixture, factory, location, cookies, address, test.providerError)
			if storage.census(t) != before || provider.tokens.Load() != 0 || provider.jwks.Load() != 0 {
				t.Fatal("callback GET/landing/preparation granted authority or exchanged")
			}
			completed := newPrivateIdentityResponse()
			err = factory.identity.dispatcher.Handle(completed, post)
			var session accountsession.Session
			denied := test.missingSubject || test.missingMember || test.wrongNonce
			if denied {
				assertConcreteCallbackRejected(t, completed, err)
			} else if test.providerError {
				if err != nil || completed.Code != http.StatusForbidden ||
					completed.Body.String() != `{"error":{"code":"login_unavailable","message":"login could not be completed"}}` {
					t.Fatal("provider error did not confirm generic no-grant erasure")
				}
				assertConcreteSessionCookies(t, completed, false)
			} else {
				if err != nil || completed.Code != http.StatusOK || completed.Body.String() != `{"return_path":"/console"}` {
					t.Fatal("confirmed callback did not deliver cookie-only Session")
				}
				token := assertConcreteSessionCookies(t, completed, true)
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				session, err = factory.identity.sessions.Authenticate(ctx, token)
				cancel()
				if err != nil {
					t.Fatal("authenticate cookie with same resident Session ring")
				}
				assertPrivateFactorySession(t, session, provider.route, test.suffix)
				storage.assertPersistedSession(t, fixture, session, token)
				before.sessions++
			}
			increment := int64(2)
			if session.IsValid() {
				increment = 3
			}
			before.mutations += increment
			before.audit += increment
			before.outbox += increment
			storage.assertCallbackTerminal(t, transactionID, session)
			if storage.census(t) != before || !storage.subjectLastSeen(t, test.suffix).Equal(seen) {
				t.Fatal("callback changed unrelated authority or subject last-seen")
			}
			exchanges := int64(1)
			if test.providerError {
				exchanges = 0
			}
			if provider.tokens.Load() != exchanges || provider.jwks.Load() != exchanges ||
				provider.discovery.Load() != 1 || provider.unexpected.Load() != 0 {
				t.Fatal("provider method/credential/PKCE/endpoint or single-attempt contract failed")
			}
			replay := newPrivateIdentityResponse()
			assertConcreteCallbackRejected(t, replay, factory.identity.dispatcher.Handle(replay, post))
			if storage.census(t) != before || provider.tokens.Load() != exchanges || provider.jwks.Load() != exchanges {
				t.Fatal("consumed replay created evidence or exchanged again")
			}
			if fixture.clockReads != 0 || len(fixture.effects) != 0 {
				t.Fatal("concrete factory used alternate fixture ports/clock")
			}
			factory.Close()
			factory.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if storage.runtime.Check(ctx) != nil || cache.Check(ctx) != nil {
				t.Fatal("callback factory closed borrowed storage")
			}
		})
	}
	t.Run("concurrent duplicate across replicas", func(t *testing.T) {
		fixture := newPrivateIdentityFixture(t)
		provider, secret := newPrivateFactorySigningProvider(t, 80)
		fixture.options.Route = provider.route
		storage.seedRoute(t, provider.route)
		storage.seedLoginSubject(t, fixture, 80, privateFactorySubject, true)
		seen := storage.subjectLastSeen(t, 80)

		replicas := make([]*privateIdentityFactory, 2)
		for index := range replicas {
			runtime := storage.runtime
			if index > 0 {
				runtime = storage.openRuntime(t)
			}
			cache, _ := storage.openRedis(t)
			factory, err := composePrivateIdentityFactory(
				t.Context(), fixture.keys,
				privateIdentityFactoryOptions{
					Application: fixture.options,
					Discovery:   oidc.Options{Timeout: time.Second, MaxMetadataBytes: 64 * 1024},
					Token:       privateIdentityTokenOptions{Timeout: 10 * time.Second, MaxTokenAge: time.Minute},
				},
				privateIdentityFactoryDependencies{
					Runtime: runtime, Redis: cache, Secret: secret, Logger: discardCompositionLogger(),
				},
			)
			if err != nil || factory == nil {
				t.Fatal("compose callback replica")
			}
			replicas[index] = factory
			t.Cleanup(factory.Close)
		}

		const address = "192.0.2.90:12345"
		location, cookies, transactionID := storage.startConcreteLogin(t, fixture, replicas[0], address)
		provider.arm(t, location, false)
		post := prepareConcreteCallback(t, fixture, replicas[0], location, cookies, address, false)
		before := storage.census(t)

		type attempt struct {
			replica  int
			response *privateIdentityResponse
			err      error
		}
		ready := make(chan struct{}, len(replicas))
		start := make(chan struct{})
		results := make(chan attempt, len(replicas))
		for index, replica := range replicas {
			request := duplicateConcreteCallbackRequest(t, fixture, post)
			go func(index int, factory *privateIdentityFactory, callback *http.Request) {
				ready <- struct{}{}
				<-start
				response := newPrivateIdentityResponse()
				results <- attempt{replica: index, response: response, err: factory.identity.dispatcher.Handle(response, callback)}
			}(index, replica, request)
		}
		for range replicas {
			<-ready
		}
		close(start)

		winner := -1
		var token accountsession.Token
		for range replicas {
			result := <-results
			if result.err != nil {
				assertConcurrentCallbackClosed(t, result.response, result.err)
				continue
			}
			if winner >= 0 || result.response.Code != http.StatusOK ||
				result.response.Body.String() != `{"return_path":"/console"}` {
				t.Fatal("duplicate callback produced an ambiguous successful response")
			}
			winner = result.replica
			token = assertConcreteSessionCookies(t, result.response, true)
		}
		if winner < 0 || provider.tokens.Load() != 1 || provider.jwks.Load() != 1 ||
			provider.discovery.Load() != 1 || provider.unexpected.Load() != 0 {
			t.Fatal("callback race did not preserve one provider exchange")
		}

		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		session, err := replicas[1-winner].identity.sessions.Authenticate(ctx, token)
		cancel()
		if err != nil {
			t.Fatal("other callback replica could not authenticate the winning Session")
		}
		assertPrivateFactorySession(t, session, provider.route, 80)
		storage.assertPersistedSession(t, fixture, session, token)
		storage.assertCallbackTerminal(t, transactionID, session)
		before.sessions++
		before.mutations += 3
		before.audit += 3
		before.outbox += 3
		if storage.census(t) != before || !storage.subjectLastSeen(t, 80).Equal(seen) {
			t.Fatal("duplicate callback changed authority or emitted duplicate evidence")
		}
	})
}

func duplicateConcreteCallbackRequest(
	t *testing.T,
	fixture *privateIdentityFixture,
	source *http.Request,
) *http.Request {
	t.Helper()
	request := fixture.loginRequest(t, source.URL.Path)
	request.RemoteAddr = source.RemoteAddr
	request.Header = source.Header.Clone()
	return request
}

func (storage *privateFactoryIntegrationStorage) startConcreteLogin(
	t *testing.T,
	fixture *privateIdentityFixture,
	factory *privateIdentityFactory,
	address string,
) (*url.URL, []*http.Cookie, string) {
	t.Helper()
	before := storage.census(t)
	prepare := newPrivateIdentityResponse()
	request := fixture.loginRequest(t, httpapi.LoginPreparePath)
	request.RemoteAddr = address
	if err := factory.identity.dispatcher.Handle(prepare, request); err != nil || prepare.Code != http.StatusOK {
		t.Fatal("prepare concrete callback login")
	}
	proof := concreteCallbackProof(t, prepare)
	if storage.census(t) != before {
		t.Fatal("prepare changed durable authority")
	}
	request = fixture.loginRequest(t, httpapi.LoginStartPath)
	request.RemoteAddr = address
	request.Header.Set(oidc.LoginCSRFHeader, proof)
	for _, cookie := range privateFactoryResponseCookies(t, prepare) {
		request.AddCookie(cookie)
	}
	started := newPrivateIdentityResponse()
	if err := factory.identity.dispatcher.Handle(started, request); err != nil {
		t.Fatal("start concrete callback login")
	}
	storage.assertPending(t, fixture, started)
	before.transactions++
	before.mutations++
	before.audit++
	before.outbox++
	if storage.census(t) != before {
		t.Fatal("start changed more than one pending login and evidence")
	}
	var body struct {
		URL string `json:"authorization_url"`
	}
	if json.Unmarshal(started.Body.Bytes(), &body) != nil {
		t.Fatal("decode authorization response")
	}
	location, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal("parse authorization response")
	}
	state, err := oidcauth.ParseState(location.Query().Get("state"))
	if err != nil {
		t.Fatal("parse concrete login state")
	}
	digest, err := fixture.keys.transaction.State(fixture.options.Route.DeploymentID(), 1, state)
	if err != nil {
		t.Fatal("derive concrete login lookup")
	}
	value := digest.Bytes()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var transactionID string
	if storage.admin.QueryRow(ctx, `SELECT public_id::TEXT FROM mesh.auth_transaction
WHERE state='pending' AND state_digest=$1`, value[:]).Scan(&transactionID) != nil {
		t.Fatal("resolve exact pending transaction fixture")
	}
	return location, privateFactoryResponseCookies(t, started), transactionID
}

func prepareConcreteCallback(
	t *testing.T,
	fixture *privateIdentityFixture,
	factory *privateIdentityFactory,
	location *url.URL,
	cookies []*http.Cookie,
	address string,
	providerError bool,
) *http.Request {
	t.Helper()
	query := url.Values{"state": {location.Query().Get("state")}, "iss": {fixture.options.Route.Issuer()}}
	if providerError {
		query.Set("error", "access_denied")
	} else {
		query.Set("code", privateFactoryCode)
	}
	callback, err := url.Parse(fixture.options.Route.RedirectURI())
	if err != nil {
		t.Fatal("parse configured callback")
	}
	request := concreteCallbackGET(t, fixture, callback.Path+"?"+query.Encode(), address)
	for _, cookie := range cookies {
		if cookie.Name == oidc.PreAuthCookieName {
			request.AddCookie(cookie)
		}
	}
	capture := newPrivateIdentityResponse()
	if err := factory.identity.dispatcher.Handle(capture, request); err != nil ||
		capture.Code != http.StatusSeeOther || capture.Body.Len() != 0 ||
		capture.Header().Get("Location") != httpapi.LoginCallbackContinuePath {
		t.Fatal("capture did not scrub query into no-grant clean continuation")
	}
	for _, cookie := range privateFactoryResponseCookies(t, capture) {
		request.AddCookie(cookie)
	}
	landing := concreteCallbackGET(t, fixture, httpapi.LoginCallbackContinuePath, address)
	landing.Header["Cookie"] = append([]string(nil), request.Header["Cookie"]...)
	page := newPrivateIdentityResponse()
	if err := factory.identity.dispatcher.Handle(page, landing); err != nil || page.Code != http.StatusOK ||
		page.Header().Get("Set-Cookie") != "" || page.Header().Get("Location") != "" {
		t.Fatal("clean landing changed custody or granted authority")
	}
	prepare := fixture.loginRequest(t, httpapi.LoginContinuationPreparePath)
	prepare.RemoteAddr = address
	prepare.Header["Cookie"] = append([]string(nil), request.Header["Cookie"]...)
	prepared := newPrivateIdentityResponse()
	if err := factory.identity.dispatcher.Handle(prepared, prepare); err != nil || prepared.Code != http.StatusOK {
		t.Fatal("prepare protected concrete continuation")
	}
	post := fixture.loginRequest(t, httpapi.LoginCallbackContinuePath)
	post.RemoteAddr = address
	post.Header["Cookie"] = append([]string(nil), request.Header["Cookie"]...)
	post.Header.Set(oidc.LoginCSRFHeader, concreteCallbackProof(t, prepared))
	return post
}

func concreteCallbackGET(t *testing.T, fixture *privateIdentityFixture, path, address string) *http.Request {
	t.Helper()
	request := fixture.loginRequest(t, path)
	request.Method, request.Body, request.ContentLength = http.MethodGet, http.NoBody, 0
	request.RemoteAddr = address
	request.Header.Del("Origin")
	request.Header.Del("X-MeshTransit-Login")
	request.Header.Del("Content-Type")
	return request
}

func concreteCallbackProof(t *testing.T, response *privateIdentityResponse) string {
	t.Helper()
	var proof struct {
		Token string `json:"csrf_token"`
	}
	if json.Unmarshal(response.Body.Bytes(), &proof) != nil || proof.Token == "" {
		t.Fatal("missing protected browser proof")
	}
	return proof.Token
}

func assertConcreteCallbackRejected(t *testing.T, response *privateIdentityResponse, err error) {
	t.Helper()
	rejected := errors.Is(err, httpapi.ErrInvalidLoginCompletion)
	released := response.Body.Len() != 0 || response.Header().Get("Set-Cookie") != "" ||
		response.Header().Get("Location") != ""
	if !rejected || released {
		t.Fatal("rejected callback released browser material or changed error category")
	}
}

func assertConcurrentCallbackClosed(t *testing.T, response *privateIdentityResponse, err error) {
	t.Helper()
	closed := errors.Is(err, httpapi.ErrInvalidLoginCompletion) ||
		errors.Is(err, httpapi.ErrLoginCompletionUnavailable)
	released := response.Body.Len() != 0 || response.Header().Get("Set-Cookie") != "" ||
		response.Header().Get("Location") != ""
	if !closed || released {
		t.Fatal("losing callback released browser material or changed closed error category")
	}
}

func assertConcreteSessionCookies(t *testing.T, response *privateIdentityResponse, issued bool) accountsession.Token {
	t.Helper()
	cookies := privateFactoryResponseCookies(t, response)
	wanted := 3
	if issued {
		wanted++
	}
	if len(cookies) != wanted {
		t.Fatal("completion changed cookie custody")
	}
	var token accountsession.Token
	seen := make(map[string]bool, wanted)
	for _, cookie := range cookies {
		if seen[cookie.Name] {
			t.Fatal("duplicate completion cookie")
		}
		seen[cookie.Name] = true
		unsafeFlags := !cookie.Secure || !cookie.HttpOnly
		unsafe := unsafeFlags || cookie.Path != "/" || cookie.Domain != ""
		expectedSameSite := http.SameSiteLaxMode
		if cookie.Name == oidc.LoginInitiationCookieName {
			expectedSameSite = http.SameSiteStrictMode
		}
		if unsafe || cookie.SameSite != expectedSameSite {
			t.Fatal("unsafe completion cookie")
		}
		if cookie.Name == httpapi.AccountSessionCookieName {
			var err error
			token, err = accountsession.ParseToken(cookie.Value)
			if err != nil || !issued || cookie.MaxAge <= 0 {
				t.Fatal("invalid fresh Session cookie")
			}
		} else {
			allowed := cookie.Name == oidc.PreAuthCookieName || cookie.Name == oidc.LoginCallbackCookieName ||
				cookie.Name == oidc.LoginInitiationCookieName
			if !allowed || cookie.Value != "" || cookie.MaxAge >= 0 {
				t.Fatal("transient proof was not cleared")
			}
		}
	}
	if token.IsValid() != issued {
		t.Fatal("Session bearer custody mismatch")
	}
	return token
}
