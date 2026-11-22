//go:build dexbroker && keycloake2e

package dexbroker

// V1-22 step 3: sign-in through the broker against a real Keycloak
// (core/test/e2e/keycloak/run.sh starts it and runs this binary on the same
// docker network: the broker never reaches loopback, so Keycloak sits at a
// private address the connector lists).

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"meshtransit.net/core/internal/platform/config"
)

const (
	e2eBrokerIssuer = "https://issuer.example/dex"
	e2eRedirectURI  = "https://app.example.test/auth/callback"
	e2eClientID     = "meshtransit-core"
	e2eConnectorID  = "oidc-0123456789abcdef"
)

func e2eEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Skipf("%s not set: run core/test/e2e/keycloak/run.sh", name)
	}
	return value
}

func e2eConnector(t *testing.T, mutate func(*OIDCConnectorOptions)) OIDCConnectorOptions {
	t.Helper()
	issuer := e2eEnv(t, "KC_ISSUER")
	secret, err := config.NewSecretFile(e2eEnv(t, "KC_CLIENT_SECRET_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := config.NewTrustFile(e2eEnv(t, "KC_CA_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	base := issuer + "/protocol/openid-connect"
	connector := OIDCConnectorOptions{
		ID: e2eConnectorID, DisplayName: "Corp SSO", Generation: 1, Issuer: issuer,
		Endpoints: ProviderEndpointsFor(issuer, OIDCProviderEndpoints{
			AuthorizationURL: base + "/auth", TokenURL: base + "/token", JWKSURL: base + "/certs",
		}),
		ClientID: "meshtransit", ClientSecretFile: secret,
		Prompt: PromptLogin, NameClaim: "preferred_username", TokenAuth: TokenAuthBasic, CAFile: ca,
		PrivateNetworks: []netip.Prefix{netip.MustParsePrefix(e2eEnv(t, "KC_CIDR"))},
	}
	if mutate != nil {
		mutate(&connector)
	}
	return connector
}

func TestKeycloakDiscoveryMatchesPinnedEndpoints(t *testing.T) {
	connector := e2eConnector(t, func(c *OIDCConnectorOptions) {
		c.Endpoints.UserInfoURL = c.Issuer + "/protocol/openid-connect/userinfo"
	})
	findings, err := CheckProviderDiscovery(t.Context(), connector)
	if err != nil || len(findings) != 0 {
		t.Fatalf("CheckProviderDiscovery() = %+v, %v", findings, err)
	}
	connector.Endpoints.UserInfoURL = connector.Issuer + "/protocol/openid-connect/userinfo-v2"
	if findings, err := CheckProviderDiscovery(t.Context(), connector); err != nil || len(findings) != 1 ||
		findings[0].Field != "userinfo_url" {
		t.Fatalf("drifted userinfo findings = %+v, %v", findings, err)
	}
	// Without the private range the provider is unreachable.
	closed := e2eConnector(t, func(c *OIDCConnectorOptions) { c.PrivateNetworks = nil })
	if _, err := CheckProviderDiscovery(t.Context(), closed); err == nil {
		t.Fatal("a provider on a private address was reached without its range")
	}
}

func TestKeycloakSignInThroughTheBroker(t *testing.T) {
	cases := []struct {
		name   string
		user   string
		mutate func(*OIDCConnectorOptions)
		fails  bool
		verify func(*testing.T, map[string]any)
	}{
		{
			// No first or last name: the name comes from preferred_username.
			name: "basic, no display name", user: "alice",
			verify: func(t *testing.T, claims map[string]any) {
				if claims["name"] != "alice" || claims["email"] != "alice@example.test" || claims["email_verified"] != true {
					t.Fatalf("claims = %v", claims)
				}
			},
		},
		{
			name: "post and userinfo", user: "alice",
			mutate: func(c *OIDCConnectorOptions) {
				c.TokenAuth = TokenAuthPost
				c.Endpoints.UserInfoURL = c.Issuer + "/protocol/openid-connect/userinfo"
			},
		},
		{
			// Keycloak sends email_verified=false: Dex passes it on, Core
			// does not trust the email.
			name: "unverified email", user: "bob",
			verify: func(t *testing.T, claims map[string]any) {
				if claims["email_verified"] != false {
					t.Fatalf("claims = %v", claims)
				}
			},
		},
		{
			// Dex calls the discovered userinfo endpoint; a pin that differs
			// has no outbound rule, so sign-in fails closed.
			name: "userinfo pin differs from discovery", user: "alice", fails: true,
			mutate: func(c *OIDCConnectorOptions) {
				c.Endpoints.UserInfoURL = c.Issuer + "/protocol/openid-connect/userinfo-v2"
			},
		},
		{
			name: "wrong client secret", user: "alice", fails: true,
			mutate: func(c *OIDCConnectorOptions) {
				wrong := filepathInTemp(t, "wrong-secret", strings.Repeat("x", 40))
				c.ClientSecretFile = wrong
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			connector := e2eConnector(t, test.mutate)
			claims, err := e2eSignIn(t, connector, test.user, e2eEnv(t, "KC_PASSWORD"))
			if test.fails {
				if err == nil {
					t.Fatalf("sign-in succeeded: %v", claims)
				}
				t.Logf("refused as expected: %v", err)
				return
			}
			if err != nil {
				t.Fatalf("sign-in: %v", err)
			}
			userID := e2eEnv(t, "KC_ID_"+strings.ToUpper(test.user))
			if claims["sub"] != e2eDexSubject(userID, e2eConnectorID) {
				t.Fatalf("sub = %v, want the Dex subject of %s", claims["sub"], userID)
			}
			if test.verify != nil {
				test.verify(t, claims)
			}
		})
	}
}

func filepathInTemp(t *testing.T, name, value string) config.SecretFile {
	t.Helper()
	path := t.TempDir() + "/" + name
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := config.NewSecretFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

// e2eDexSubject is Dex's subject encoding (selfhost.dexSubject).
func e2eDexSubject(userID, connectorID string) string {
	var message []byte
	message = protowire.AppendTag(message, 1, protowire.BytesType)
	message = protowire.AppendString(message, userID)
	message = protowire.AppendTag(message, 2, protowire.BytesType)
	message = protowire.AppendString(message, connectorID)
	return base64.RawURLEncoding.EncodeToString(message)
}

// e2eSignIn runs the broker in process and walks a browser through it and
// Keycloak's login form, then redeems the code at the broker.
func e2eSignIn(t *testing.T, connector OIDCConnectorOptions, user, password string) (map[string]any, error) {
	t.Helper()
	clientSecret := strings.Repeat("b", 48)
	options := ServiceOptions{
		Issuer:         e2eBrokerIssuer,
		OIDCConnectors: []OIDCConnectorOptions{connector},
		Clients: []ClientOptions{{
			ID: e2eClientID, DisplayName: "MeshTransit Core", Generation: 1,
			SecretFile: filepathInTemp(t, "client-secret", clientSecret), RedirectURI: e2eRedirectURI,
		}},
		IDTokenLifetime: time.Hour, AuthRequestLifetime: 5 * time.Minute,
		SigningKeyRotation: 6 * time.Hour, GarbageCollectionInterval: time.Hour,
	}
	configuration, _, err := resolveConfiguration(options)
	if err != nil {
		return nil, fmt.Errorf("configuration: %w", err)
	}
	logger := componentTestLogger()
	serverStorage := newComponentTestStorage(t, logger, false)
	runtime, err := newDexRuntime(t.Context(), componentOptions{
		issuer: e2eBrokerIssuer, configuration: configuration, idTokensValidFor: time.Hour,
		authRequestsValidFor: 5 * time.Minute, signingKeysRotateAfter: 6 * time.Hour,
		garbageCollectionFrequency: time.Hour, logger: logger,
	}, componentResources{storage: serverStorage})
	if err != nil {
		return nil, fmt.Errorf("runtime: %w", err)
	}
	t.Cleanup(func() {
		shutdownDexComponentRuntime(t, runtime)
		<-runtime.Done()
	})
	browser := e2eBrowser(t, runtime)

	authorize := e2eBrokerIssuer + "/auth?" + url.Values{
		"client_id": {e2eClientID}, "redirect_uri": {e2eRedirectURI}, "response_type": {"code"},
		"scope": {"openid email profile"}, "state": {"e2e-state"},
	}.Encode()
	page, location, err := e2eFollow(browser, http.MethodGet, authorize, nil)
	if err != nil {
		return nil, err
	}
	if location == "" {
		form := regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`).FindStringSubmatch(page)
		if form == nil {
			return nil, errors.New("no Keycloak login form")
		}
		_, location, err = e2eFollow(browser, http.MethodPost, html.UnescapeString(form[1]),
			url.Values{"username": {user}, "password": {password}, "credentialId": {""}})
		if err != nil {
			return nil, err
		}
	}
	callback, err := url.Parse(location)
	if err != nil || !strings.HasPrefix(location, e2eRedirectURI) || callback.Query().Get("code") == "" {
		return nil, fmt.Errorf("broker did not return a code: %q", location)
	}
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, e2eBrokerIssuer+"/token",
		strings.NewReader(url.Values{
			"grant_type": {"authorization_code"}, "code": {callback.Query().Get("code")},
			"redirect_uri": {e2eRedirectURI},
		}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(e2eClientID, clientSecret)
	response, err := browser.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	var tokens struct {
		IDToken string `json:"id_token"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&tokens) != nil {
		return nil, fmt.Errorf("token status %d", response.StatusCode)
	}
	claims, ok := idTokenClaims(tokens.IDToken)
	if !ok {
		return nil, errors.New("undecodable ID token")
	}
	return claims, nil
}

// e2eBrowser sends broker requests to the in-process runtime and the rest
// to Keycloak, trusting the lab CA.
func e2eBrowser(t *testing.T, runtime http.Handler) *http.Client {
	t.Helper()
	pem, err := os.ReadFile(e2eEnv(t, "KC_CA_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	network := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	t.Cleanup(network.CloseIdleConnections)
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar: jar, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: outboundRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.Host != "issuer.example" {
				return network.RoundTrip(request)
			}
			recorder := httptest.NewRecorder()
			runtime.ServeHTTP(recorder, request.WithContext(context.WithoutCancel(request.Context())))
			response := recorder.Result()
			response.Request = request
			return response, nil
		}),
	}
}

// e2eFollow follows redirects until a page or the client redirect URI.
func e2eFollow(browser *http.Client, method, target string, form url.Values) (string, string, error) {
	for hop := 0; hop < 12; hop++ {
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		request, err := http.NewRequest(method, target, body)
		if err != nil {
			return "", "", err
		}
		if form != nil {
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		response, err := browser.Do(request)
		if err != nil {
			return "", "", err
		}
		contents, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		_ = response.Body.Close()
		if response.StatusCode < 300 || response.StatusCode >= 400 {
			if response.StatusCode != http.StatusOK {
				return "", "", fmt.Errorf("%s %s: status %d", method, request.URL.Host+request.URL.Path, response.StatusCode)
			}
			return string(contents), "", nil
		}
		next, err := response.Location()
		if err != nil {
			return "", "", err
		}
		if strings.HasPrefix(next.String(), e2eRedirectURI) {
			return "", next.String(), nil
		}
		method, target, form = http.MethodGet, next.String(), nil
	}
	return "", "", errors.New("too many redirects")
}
