package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/meshtransit/meshtransit/api/openapi"
	"github.com/meshtransit/meshtransit/internal/adapter/httpapi"
	"github.com/meshtransit/meshtransit/internal/adapter/oidc"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

func TestPrivateIdentityDispatcherAndDocumentShareCallback(t *testing.T) {
	t.Parallel()
	fixture := newPrivateIdentityFixture(t)
	root := fixture.compose(t)
	if root.dispatcher == nil || len(root.loginDocument) == 0 || len(fixture.effects) != 0 || fixture.clockReads != 0 {
		t.Fatal("root released partial source ownership or performed constructor effects")
	}
	callback, err := url.Parse(fixture.options.Route.RedirectURI())
	if err != nil {
		t.Fatal(err)
	}
	expected, err := openapi.LoginDocument(openapi.ManagementProfileConsoleCookiePrivateV1, callback.Path)
	if err != nil || !bytes.Equal(expected, root.loginDocument) || root.dispatcher.CallbackPath() != callback.Path {
		t.Fatal("root dispatcher/document selected a different callback", err)
	}
	other := fixture.compose(t)
	clear(root.loginDocument)
	if !bytes.Equal(other.loginDocument, expected) || root.metrics == other.metrics {
		t.Fatal("root source bytes/registry ownership is shared")
	}
	if _, err := other.metrics.Gather(); err != nil || len(fixture.effects) != 0 || fixture.clockReads != 0 {
		t.Fatal("source metrics/document touched authority or clock", err)
	}
}

func TestPrivateIdentityDispatcherRejectsForeignNamespaceBeforeEffects(t *testing.T) {
	t.Parallel()
	fixture := newPrivateIdentityFixture(t)
	params := privateIdentityDispatchRouteParams(fixture.options.Route)
	params.RedirectURI = fixture.options.Origin + httpapi.AccountSessionCSRFPreparePath
	var err error
	fixture.options.Route, err = oidcauth.NewRoute(params)
	if err != nil {
		t.Fatal(err)
	}
	root, err := composePrivateIdentity(t.Context(), fixture.keys, fixture.options, fixture.ports)
	if root != nil || !errors.Is(err, errInvalidPrivateIdentityComposition) ||
		len(fixture.effects) != 0 || fixture.clockReads != 0 {
		t.Fatal("root released an overlapping dispatcher/document or performed constructor work")
	}
}

func privateIdentityDispatchRouteParams(route oidcauth.Route) oidcauth.RouteParams {
	return oidcauth.RouteParams{
		DeploymentID: route.DeploymentID(), WorkspaceID: route.WorkspaceID(), ProviderID: route.ProviderID(),
		ClientID: route.ClientID(), ProviderGeneration: route.ProviderGeneration(), RecoveryEpoch: route.RecoveryEpoch(),
		Issuer: route.Issuer(), DiscoveryURI: route.DiscoveryURI(), AuthorizationEndpoint: route.AuthorizationEndpoint(),
		TokenEndpoint: route.TokenEndpoint(), JWKSURI: route.JWKSURI(), OIDCClientID: route.OIDCClientID(),
		ConnectorID: route.ConnectorID(),
		ClientKind:  "confidential", ClientAuthMethod: route.ClientAuthMethod(),
		Scopes: route.Scopes(), AllowedAlgorithms: route.AllowedAlgorithms(), RedirectID: route.RedirectID(),
		RedirectURI: route.RedirectURI(), ReturnRouteID: route.ReturnRouteID(),
	}
}

func TestPrivateIdentityDispatcherCompletesOnlyConfirmedSession(t *testing.T) {
	t.Parallel()
	fixture := newPrivateIdentityFixture(t)
	root := fixture.compose(t)
	prepare := newPrivateIdentityResponse()
	if err := root.dispatcher.Handle(prepare, fixture.loginRequest(t, httpapi.LoginPreparePath)); err != nil {
		t.Fatal(err)
	}
	var intent struct {
		Token string `json:"csrf_token"`
	}
	if err := json.Unmarshal(prepare.Body.Bytes(), &intent); err != nil || intent.Token == "" {
		t.Fatal("private initiation proof missing", err)
	}
	start := fixture.loginRequest(t, httpapi.LoginStartPath)
	start.Header.Set(oidc.LoginCSRFHeader, intent.Token)
	for _, cookie := range prepare.Result().Cookies() {
		start.AddCookie(cookie)
	}
	started := newPrivateIdentityResponse()
	if err := root.dispatcher.Handle(started, start); err != nil || started.Code != http.StatusOK ||
		!slices.Contains(fixture.effects, "commit_create") {
		t.Fatal("private start did not confirm creation", err)
	}
	callback, err := url.Parse(fixture.options.Route.RedirectURI())
	if err != nil {
		t.Fatal(err)
	}
	query := url.Values{
		"state": {fixture.secrets.State().Encoded()},
		"iss":   {fixture.options.Route.Issuer()},
		"code":  {"synthetic-private-code"},
	}.Encode()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, callback.Path+"?"+query, nil)
	request.Host, request.RemoteAddr = callback.Host, "192.0.2.9:12345"
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	for _, cookie := range started.Result().Cookies() {
		if cookie.Name == oidc.PreAuthCookieName {
			request.AddCookie(cookie)
		}
	}
	capture := newPrivateIdentityResponse()
	before := len(fixture.effects)
	if err := root.dispatcher.Handle(capture, request); err != nil || capture.Code != http.StatusSeeOther ||
		capture.Body.Len() != 0 || !slices.Equal(fixture.effects[before:], []string{"budget", "budget"}) {
		t.Fatal("GET dispatch reached authority instead of no-grant custody", err)
	}
	headers := request.Header.Clone()
	for _, cookie := range capture.Result().Cookies() {
		headers.Add("Cookie", cookie.Name+"="+cookie.Value)
	}
	continuationRequest := fixture.loginRequest(t, httpapi.LoginContinuationPreparePath)
	continuationRequest.Header["Cookie"] = slices.Clone(headers["Cookie"])
	continuation := newPrivateIdentityResponse()
	if err := root.dispatcher.Handle(continuation, continuationRequest); err != nil || continuation.Code != http.StatusOK {
		t.Fatal("protected continuation preparation failed", err)
	}
	var proof struct {
		Token string `json:"csrf_token"`
	}
	if err := json.Unmarshal(continuation.Body.Bytes(), &proof); err != nil || proof.Token == "" {
		t.Fatal("continuation proof missing", err)
	}
	post := fixture.loginRequest(t, httpapi.LoginCallbackContinuePath)
	post.Header["Cookie"] = slices.Clone(headers["Cookie"])
	post.Header.Set(oidc.LoginCSRFHeader, proof.Token)
	completed := newPrivateIdentityResponse()
	if err := root.dispatcher.Handle(completed, post); err != nil || completed.Code != http.StatusOK ||
		completed.Body.String() != `{"return_path":"/console"}` || !slices.Contains(fixture.effects, "commit_issue") {
		t.Fatal("dispatch skipped confirmed completion or exposed extra JSON", err)
	}
	cookies := completed.Result().Cookies()
	if len(cookies) != 4 || strings.Contains(completed.Body.String(), "mtas1") {
		t.Fatal("confirmed dispatch changed cookie-only bearer custody")
	}
	before = len(fixture.effects)
	replay := newPrivateIdentityResponse()
	if err := root.dispatcher.Handle(replay, post); err == nil ||
		replay.Body.Len() != 0 || replay.Header().Get("Set-Cookie") != "" {
		t.Fatal("single-use replay manufactured or delivered a second Session", err)
	}
	if slices.Contains(fixture.effects[before:], "provider") || slices.Contains(fixture.effects[before:], "issue") {
		t.Fatal("single-use replay reached exchange/issuance")
	}
}
