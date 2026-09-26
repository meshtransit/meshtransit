package qualification

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestRunReportsEveryCompatibilityRequirement(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	tests := []struct {
		name       string
		capability fakeCapabilities
		missing    []CheckID
	}{
		{
			name: "conforming broker",
			capability: fakeCapabilities{
				discoveryIssuer: true,
				successIssuer:   true,
				errorIssuer:     true,
				authTime:        true,
			},
		},
		{
			name:       "all hard requirements absent",
			capability: fakeCapabilities{},
			missing:    orderedChecks[:],
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			broker := newFakeBroker(t, key, test.capability)
			report, err := Run(t.Context(), broker.options())
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if missing := report.Missing(); !slices.Equal(missing, test.missing) {
				t.Fatalf("Report.Missing() = %v, want %v", missing, test.missing)
			}
			if report.Passed() != (len(test.missing) == 0) {
				t.Fatalf("Report.Passed() = %t, missing = %v", report.Passed(), test.missing)
			}
			results := report.Results()
			if len(results) != len(orderedChecks) {
				t.Fatalf("len(Report.Results()) = %d, want %d", len(results), len(orderedChecks))
			}
		})
	}
}

func TestRunRejectsUnsafeOptionsBeforeNetwork(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		change func(*Options)
	}{
		{name: "public plaintext issuer", change: func(options *Options) { options.Issuer = "http://example.test/dex" }},
		{name: "issuer query", change: func(options *Options) { options.Issuer += "?override=true" }},
		{name: "missing client", change: func(options *Options) { options.ClientID = "" }},
		{name: "missing secret", change: func(options *Options) { options.ClientSecret = "" }},
		{name: "invalid connector", change: func(options *Options) { options.ConnectorID = "not valid" }},
		{name: "unbounded timeout", change: func(options *Options) { options.Timeout = time.Minute }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			options := Options{
				Issuer: "https://id.example.test/oauth2", ClientID: "client",
				ClientSecret: "secret", RedirectURI: "https://app.example.test/callback",
				ConnectorID: "mock", Timeout: time.Second,
			}
			test.change(&options)
			if _, err := Run(t.Context(), options); err == nil {
				t.Fatal("Run() error = nil, want invalid options")
			}
		})
	}
}

type fakeCapabilities struct {
	discoveryIssuer bool
	successIssuer   bool
	errorIssuer     bool
	authTime        bool
}

type fakeBroker struct {
	t            *testing.T
	key          *rsa.PrivateKey
	capability   fakeCapabilities
	server       *httptest.Server
	issuer       string
	clientID     string
	clientSecret string
	redirectURI  string
	mu           sync.Mutex
	nonce        string
}

func newFakeBroker(t *testing.T, key *rsa.PrivateKey, capability fakeCapabilities) *fakeBroker {
	t.Helper()

	broker := &fakeBroker{
		t: t, key: key, capability: capability,
		clientID: "qualification-client", clientSecret: "qualification-secret",
		redirectURI: "http://127.0.0.1:1/callback",
	}
	broker.server = httptest.NewServer(http.HandlerFunc(broker.serveHTTP))
	t.Cleanup(broker.server.Close)
	broker.issuer = broker.server.URL + "/dex"
	return broker
}

func (broker *fakeBroker) options() Options {
	return Options{
		Issuer: broker.issuer, ClientID: broker.clientID, ClientSecret: broker.clientSecret,
		RedirectURI: broker.redirectURI, ConnectorID: "mock", Timeout: 5 * time.Second,
	}
}

func (broker *fakeBroker) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/dex/.well-known/openid-configuration":
		broker.serveDiscovery(writer)
	case "/dex/auth":
		broker.serveAuthorization(writer, request)
	case "/dex/token":
		broker.serveToken(writer, request)
	case "/dex/keys":
		broker.serveKeys(writer)
	default:
		http.NotFound(writer, request)
	}
}

func (broker *fakeBroker) serveDiscovery(writer http.ResponseWriter) {
	document := map[string]any{
		"issuer": broker.issuer, "authorization_endpoint": broker.issuer + "/auth",
		"token_endpoint": broker.issuer + "/token", "jwks_uri": broker.issuer + "/keys",
	}
	if broker.capability.discoveryIssuer {
		document["authorization_response_iss_parameter_supported"] = true
	}
	writeJSON(broker.t, writer, document)
}

func (broker *fakeBroker) serveAuthorization(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	callbackURL, err := url.Parse(broker.redirectURI)
	if err != nil {
		broker.t.Errorf("url.Parse(redirect URI) error = %v", err)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	response := callbackURL.Query()
	response.Set("state", query.Get("state"))
	if query.Get("response_type") != "code" {
		response.Set("error", "unsupported_response_type")
		if broker.capability.errorIssuer {
			response.Set("iss", broker.issuer)
		}
	} else {
		broker.mu.Lock()
		broker.nonce = query.Get("nonce")
		broker.mu.Unlock()
		response.Set("code", "qualification-code")
		if broker.capability.successIssuer {
			response.Set("iss", broker.issuer)
		}
	}
	callbackURL.RawQuery = response.Encode()
	http.Redirect(writer, request, callbackURL.String(), http.StatusSeeOther)
}

func (broker *fakeBroker) serveToken(writer http.ResponseWriter, request *http.Request) {
	clientID, clientSecret, ok := request.BasicAuth()
	if !ok || clientID != broker.clientID || clientSecret != broker.clientSecret ||
		request.Method != http.MethodPost {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	if err := request.ParseForm(); err != nil || request.Form.Get("code") != "qualification-code" ||
		request.Form.Get("grant_type") != "authorization_code" || request.Form.Get("code_verifier") == "" {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	broker.mu.Lock()
	nonce := broker.nonce
	broker.mu.Unlock()
	now := time.Now().Unix()
	claims := map[string]any{
		"iss": broker.issuer, "sub": "qualification-subject", "aud": broker.clientID,
		"nonce": nonce, "iat": now, "exp": now + 300,
	}
	if broker.capability.authTime {
		claims["auth_time"] = now - 1
	}
	rawToken, err := signedToken(broker.key, claims)
	if err != nil {
		broker.t.Errorf("signedToken() error = %v", err)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	writeJSON(broker.t, writer, map[string]any{
		"access_token": "not-used", "id_token": rawToken, "token_type": "Bearer", "expires_in": 300,
	})
}

func (broker *fakeBroker) serveKeys(writer http.ResponseWriter) {
	writeJSON(broker.t, writer, map[string]any{"keys": []map[string]any{{
		"alg": "RS256", "kid": "qualification-key", "kty": "RSA", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(broker.key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(broker.key.E)).Bytes()),
	}}})
}

func signedToken(key *rsa.PrivateKey, claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]any{"alg": "RS256", "kid": "qualification-key", "typ": "JWT"})
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	input := encodedHeader + "." + encodedPayload
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func writeJSON(t *testing.T, writer http.ResponseWriter, value any) {
	t.Helper()

	body, err := json.Marshal(value)
	if err != nil {
		t.Errorf("json.Marshal() error = %v", err)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	if _, err := writer.Write(body); err != nil {
		t.Errorf("ResponseWriter.Write() error = %v", err)
	}
}
