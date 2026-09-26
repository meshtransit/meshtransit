// Package qualification black-box qualifies an OIDC broker against the
// MeshTransit browser-login contract. It deliberately imports no broker SDK so
// the same checks survive broker upgrades and alternate implementations.
package qualification

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"strings"
	"time"
)

const (
	defaultTimeout       = 10 * time.Second
	maximumTimeout       = 30 * time.Second
	maximumResponseBytes = 256 * 1024
	maximumRedirects     = 8
)

var (
	// ErrInvalidOptions rejects incomplete or unsafe qualification configuration.
	ErrInvalidOptions = errors.New("oidc qualification: invalid options")
	// ErrUnavailable classifies bounded network and provider failures.
	ErrUnavailable = errors.New("oidc qualification: provider unavailable")
	// ErrInvalidResponse rejects malformed or inconsistent provider output.
	ErrInvalidResponse = errors.New("oidc qualification: invalid provider response")
)

// CheckID names one stable SSO-BROKER-000 requirement.
type CheckID string

const (
	// CheckDiscoveryIssuerParameter requires RFC 9207 discovery advertisement.
	CheckDiscoveryIssuerParameter CheckID = "rfc9207_discovery_advertisement"
	// CheckSuccessIssuerParameter requires exact iss on a successful callback.
	CheckSuccessIssuerParameter CheckID = "rfc9207_success_callback_issuer"
	// CheckErrorIssuerParameter requires exact iss on an error callback.
	CheckErrorIssuerParameter CheckID = "rfc9207_error_callback_issuer"
	// CheckSignedAuthenticationTime requires signed, valid auth_time evidence.
	CheckSignedAuthenticationTime CheckID = "signed_auth_time"
)

var orderedChecks = [...]CheckID{
	CheckDiscoveryIssuerParameter,
	CheckSuccessIssuerParameter,
	CheckErrorIssuerParameter,
	CheckSignedAuthenticationTime,
}

// Options contains only the exact disposable confidential-client contract.
// It always formats redacted because ClientSecret is credential material.
type Options struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	ConnectorID  string
	Timeout      time.Duration
}

// String prevents incidental credential and topology disclosure.
func (Options) String() string { return "[REDACTED]" }

// GoString prevents detailed credential and topology disclosure.
func (Options) GoString() string { return "qualification.Options([REDACTED])" }

// LogValue prevents structured-log credential and topology disclosure.
func (Options) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON refuses accidental serialization of the confidential-client secret.
func (Options) MarshalJSON() ([]byte, error) { return nil, ErrInvalidOptions }

// Result is one closed, non-sensitive qualification outcome.
type Result struct {
	Check  CheckID
	Passed bool
}

// Report contains all SSO-BROKER-000 outcomes in stable order.
type Report struct {
	results [len(orderedChecks)]bool
}

// Results returns a fresh, stable-order result slice.
func (report Report) Results() []Result {
	results := make([]Result, 0, len(orderedChecks))
	for index, check := range orderedChecks {
		results = append(results, Result{Check: check, Passed: report.results[index]})
	}
	return results
}

// Missing returns the unsatisfied requirements in stable order.
func (report Report) Missing() []CheckID {
	missing := make([]CheckID, 0, len(orderedChecks))
	for index, check := range orderedChecks {
		if !report.results[index] {
			missing = append(missing, check)
		}
	}
	return missing
}

// Passed reports whether every hard requirement was observed.
func (report Report) Passed() bool { return len(report.Missing()) == 0 }

type metadata struct {
	issuer                       string
	authorizationEndpoint        string
	tokenEndpoint                string
	jwksURI                      string
	authorizationIssuerParameter bool
}

type probe struct {
	options  Options
	issuer   *url.URL
	callback *url.URL
	client   *http.Client
}

// Run executes the provider-neutral SSO-BROKER-000 browser and token flow.
// Missing requirements are returned in Report without being converted into an
// operational error, so one run records all compatibility gaps.
func Run(ctx context.Context, options Options) (Report, error) {
	qualified, err := newProbe(options)
	if err != nil {
		return Report{}, err
	}
	if ctx == nil {
		return Report{}, ErrInvalidOptions
	}
	defer qualified.client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(ctx, qualified.options.Timeout)
	defer cancel()

	discovered, err := qualified.discover(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("discover broker metadata: %w", err)
	}
	report := Report{}
	report.set(CheckDiscoveryIssuerParameter, discovered.authorizationIssuerParameter)

	errorIssuer, err := qualified.observeErrorCallback(ctx, discovered)
	if err != nil {
		return report, fmt.Errorf("observe error callback: %w", err)
	}
	report.set(CheckErrorIssuerParameter, errorIssuer)

	success, err := qualified.observeSuccessCallback(ctx, discovered)
	if err != nil {
		return report, fmt.Errorf("observe successful callback: %w", err)
	}
	report.set(CheckSuccessIssuerParameter, success.exactIssuer)

	signedAuthTime, err := qualified.exchangeAndVerify(ctx, discovered, success)
	if err != nil {
		return report, fmt.Errorf("verify signed authentication time: %w", err)
	}
	report.set(CheckSignedAuthenticationTime, signedAuthTime)
	return report, nil
}

func (report *Report) set(check CheckID, passed bool) {
	for index, candidate := range orderedChecks {
		if candidate == check {
			report.results[index] = passed
			return
		}
	}
}

func newProbe(options Options) (*probe, error) {
	if options.Timeout == 0 {
		options.Timeout = defaultTimeout
	}
	issuer, issuerOK := exactURL(options.Issuer, true)
	callback, callbackOK := exactURL(options.RedirectURI, false)
	if !issuerOK || !callbackOK || options.Timeout <= 0 || options.Timeout > maximumTimeout ||
		!boundedASCII(options.ClientID, 255) || !boundedASCII(options.ClientSecret, 4096) ||
		!boundedToken(options.ConnectorID, 128) {
		return nil, ErrInvalidOptions
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, ErrInvalidOptions
	}
	dialer := &net.Dialer{Timeout: options.Timeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		ForceAttemptHTTP2:      true,
		DisableCompression:     true,
		MaxIdleConns:           8,
		MaxIdleConnsPerHost:    4,
		IdleConnTimeout:        30 * time.Second,
		TLSHandshakeTimeout:    options.Timeout,
		ResponseHeaderTimeout:  options.Timeout,
		MaxResponseHeaderBytes: 64 * 1024,
		ExpectContinueTimeout:  time.Second,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
	}
	client := &http.Client{
		Transport: transport,
		Jar:       jar,
		Timeout:   options.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &probe{options: options, issuer: issuer, callback: callback, client: client}, nil
}

func exactURL(value string, issuer bool) (*url.URL, bool) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.String() != value || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawFragment != "" || parsed.ForceQuery {
		return nil, false
	}
	if issuer && strings.HasSuffix(parsed.Path, "/") {
		return nil, false
	}
	if parsed.Scheme == "https" {
		return parsed, true
	}
	return parsed, parsed.Scheme == "http" && loopbackHost(parsed.Hostname())
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func boundedASCII(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func boundedToken(value string, maximum int) bool {
	if !boundedASCII(value, maximum) {
		return false
	}
	for _, character := range value {
		letter := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
		digit := character >= '0' && character <= '9'
		if !letter && !digit && !strings.ContainsRune("-._~", character) {
			return false
		}
	}
	return true
}

func (qualified *probe) discover(ctx context.Context) (metadata, error) {
	discoveryURL := *qualified.issuer
	discoveryURL.Path = strings.TrimSuffix(discoveryURL.Path, "/") + "/.well-known/openid-configuration"
	body, err := qualified.getJSON(ctx, discoveryURL.String())
	if err != nil {
		return metadata{}, err
	}
	values, err := decodeJSONObject(body)
	if err != nil {
		return metadata{}, err
	}
	var discovered metadata
	if !decodeRequired(values, "issuer", &discovered.issuer) || discovered.issuer != qualified.options.Issuer ||
		!decodeRequired(values, "authorization_endpoint", &discovered.authorizationEndpoint) ||
		!decodeRequired(values, "token_endpoint", &discovered.tokenEndpoint) ||
		!decodeRequired(values, "jwks_uri", &discovered.jwksURI) {
		return metadata{}, ErrInvalidResponse
	}
	if raw, present := values["authorization_response_iss_parameter_supported"]; present {
		if err := json.Unmarshal(raw, &discovered.authorizationIssuerParameter); err != nil {
			return metadata{}, ErrInvalidResponse
		}
	}
	for _, endpoint := range []string{
		discovered.authorizationEndpoint,
		discovered.tokenEndpoint,
		discovered.jwksURI,
	} {
		if !qualified.trustedEndpoint(endpoint) {
			return metadata{}, ErrInvalidResponse
		}
	}
	return discovered, nil
}

func (qualified *probe) trustedEndpoint(value string) bool {
	endpoint, ok := exactURL(value, false)
	if !ok || endpoint.Scheme != qualified.issuer.Scheme || endpoint.Host != qualified.issuer.Host {
		return false
	}
	base := strings.TrimSuffix(qualified.issuer.EscapedPath(), "/")
	path := endpoint.EscapedPath()
	return base == "" || path == base || strings.HasPrefix(path, base+"/")
}

type callback struct {
	code, verifier, nonce string
	exactIssuer           bool
}

func (qualified *probe) observeErrorCallback(ctx context.Context, discovered metadata) (bool, error) {
	state, err := randomToken()
	if err != nil {
		return false, err
	}
	verifier, err := randomToken()
	if err != nil {
		return false, err
	}
	values := qualified.authorizationValues(state, verifier, "qualification-nonce", "unsupported")
	location, err := qualified.authorizationURL(discovered.authorizationEndpoint, values)
	if err != nil {
		return false, err
	}
	callbackURL, err := qualified.followToCallback(ctx, location)
	if err != nil {
		return false, fmt.Errorf("callback redirect chain: %w", err)
	}
	query := callbackURL.Query()
	if !exactQueryValue(query, "state", state) || len(query["error"]) != 1 || query.Get("error") == "" {
		return false, fmt.Errorf("callback fields: %w", ErrInvalidResponse)
	}
	return exactQueryValue(query, "iss", qualified.options.Issuer), nil
}

func (qualified *probe) observeSuccessCallback(ctx context.Context, discovered metadata) (callback, error) {
	state, err := randomToken()
	if err != nil {
		return callback{}, err
	}
	verifier, err := randomToken()
	if err != nil {
		return callback{}, err
	}
	nonce, err := randomToken()
	if err != nil {
		return callback{}, err
	}
	values := qualified.authorizationValues(state, verifier, nonce, "code")
	current, err := qualified.authorizationURL(discovered.authorizationEndpoint, values)
	if err != nil {
		return callback{}, err
	}
	callbackURL, err := qualified.followToCallback(ctx, current)
	if err != nil {
		return callback{}, err
	}
	query := callbackURL.Query()
	if !exactQueryValue(query, "state", state) || len(query["code"]) != 1 ||
		!boundedASCII(query.Get("code"), 4096) {
		return callback{}, ErrInvalidResponse
	}
	return callback{
		code: query.Get("code"), verifier: verifier, nonce: nonce,
		exactIssuer: exactQueryValue(query, "iss", qualified.options.Issuer),
	}, nil
}

func (qualified *probe) authorizationValues(state, verifier, nonce, responseType string) url.Values {
	digest := sha256.Sum256([]byte(verifier))
	return url.Values{
		"client_id":             {qualified.options.ClientID},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(digest[:])},
		"code_challenge_method": {"S256"},
		"connector_id":          {qualified.options.ConnectorID},
		"nonce":                 {nonce},
		"redirect_uri":          {qualified.options.RedirectURI},
		"response_type":         {responseType},
		"scope":                 {"openid"},
		"state":                 {state},
	}
}

func (qualified *probe) authorizationURL(endpoint string, values url.Values) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", ErrInvalidResponse
	}
	parsed.RawQuery = values.Encode()
	return parsed.String(), nil
}

func (qualified *probe) followToCallback(ctx context.Context, current string) (*url.URL, error) {
	for range maximumRedirects {
		location, err := qualified.getRedirect(ctx, current)
		if err != nil {
			return nil, fmt.Errorf("request redirect hop: %w", err)
		}
		if callbackURL, ok := qualified.callbackLocation(location); ok {
			return callbackURL, nil
		}
		if !qualified.trustedRedirect(location) {
			parsed, parseErr := url.Parse(location)
			if parseErr == nil && parsed.Scheme == qualified.callback.Scheme && parsed.Host == qualified.callback.Host {
				return nil, fmt.Errorf(
					"callback redirect mismatch (path=%t raw_path=%t user=%t fragment=%t): %w",
					parsed.Path == qualified.callback.Path,
					parsed.RawPath == qualified.callback.RawPath,
					parsed.User == nil,
					parsed.Fragment == "" && parsed.RawFragment == "",
					ErrInvalidResponse,
				)
			}
			return nil, fmt.Errorf("redirect escaped allowlists: %w", ErrInvalidResponse)
		}
		current = location
	}
	return nil, fmt.Errorf("redirect limit exceeded: %w", ErrInvalidResponse)
}

func (qualified *probe) trustedRedirect(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != qualified.issuer.Scheme || parsed.Host != qualified.issuer.Host ||
		parsed.User != nil || parsed.Fragment != "" || parsed.RawFragment != "" || parsed.ForceQuery ||
		len(parsed.RawQuery) > 8192 {
		return false
	}
	base := strings.TrimSuffix(qualified.issuer.EscapedPath(), "/")
	path := parsed.EscapedPath()
	return base == "" || path == base || strings.HasPrefix(path, base+"/")
}

func (qualified *probe) callbackLocation(value string) (*url.URL, bool) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != qualified.callback.Scheme || parsed.Host != qualified.callback.Host ||
		parsed.Path != qualified.callback.Path || parsed.RawPath != qualified.callback.RawPath ||
		parsed.User != nil || parsed.Fragment != "" || parsed.RawFragment != "" {
		return nil, false
	}
	return parsed, true
}

func exactQueryValue(values url.Values, name, expected string) bool {
	return len(values[name]) == 1 && values.Get(name) == expected
}

func redirectLocation(response *http.Response, requestURL string) (string, error) {
	if response == nil {
		return "", ErrUnavailable
	}
	if response.StatusCode < http.StatusMultipleChoices || response.StatusCode >= http.StatusBadRequest {
		return "", ErrInvalidResponse
	}
	location, err := response.Location()
	if err != nil {
		return "", ErrInvalidResponse
	}
	base, err := url.Parse(requestURL)
	if err != nil {
		return "", ErrInvalidResponse
	}
	return base.ResolveReference(location).String(), nil
}

func randomToken() (string, error) {
	material := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, material); err != nil {
		return "", fmt.Errorf("%w: entropy", ErrUnavailable)
	}
	return base64.RawURLEncoding.EncodeToString(material), nil
}

func (qualified *probe) exchangeAndVerify(
	ctx context.Context,
	discovered metadata,
	success callback,
) (bool, error) {
	form := url.Values{
		"code":          {success.code},
		"code_verifier": {success.verifier},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {qualified.options.RedirectURI},
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		discovered.tokenEndpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return false, ErrInvalidResponse
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(qualified.options.ClientID, qualified.options.ClientSecret)
	body, err := qualified.doJSON(request, http.StatusOK)
	if err != nil {
		return false, err
	}
	values, err := decodeJSONObject(body)
	if err != nil {
		return false, err
	}
	var rawIDToken string
	if !decodeRequired(values, "id_token", &rawIDToken) || len(rawIDToken) > 32*1024 {
		return false, ErrInvalidResponse
	}
	return qualified.verifyAuthenticationTime(ctx, discovered, rawIDToken, success.nonce)
}

type compactToken struct {
	algorithm, keyID, signingInput string
	claims, signature              []byte
}

func parseCompactToken(raw string) (compactToken, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return compactToken{}, ErrInvalidResponse
	}
	headerBytes, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil || len(headerBytes) > 4096 {
		return compactToken{}, ErrInvalidResponse
	}
	header, err := decodeJSONObject(headerBytes)
	if err != nil {
		return compactToken{}, err
	}
	var algorithm, keyID string
	if !decodeRequired(header, "alg", &algorithm) || algorithm != "RS256" ||
		!decodeRequired(header, "kid", &keyID) || !boundedASCII(keyID, 255) {
		return compactToken{}, ErrInvalidResponse
	}
	claims, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(claims) > 16*1024 {
		return compactToken{}, ErrInvalidResponse
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(signature) > 1024 {
		return compactToken{}, ErrInvalidResponse
	}
	return compactToken{
		algorithm: algorithm, keyID: keyID, signingInput: parts[0] + "." + parts[1],
		claims: claims, signature: signature,
	}, nil
}

func (qualified *probe) verifyAuthenticationTime(
	ctx context.Context,
	discovered metadata,
	rawIDToken string,
	nonce string,
) (bool, error) {
	token, err := parseCompactToken(rawIDToken)
	if err != nil {
		return false, err
	}
	key, err := qualified.signingKey(ctx, discovered.jwksURI, token)
	if err != nil {
		return false, err
	}
	digest := sha256.Sum256([]byte(token.signingInput))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], token.signature); err != nil {
		return false, ErrInvalidResponse
	}
	claims, err := decodeJSONObject(token.claims)
	if err != nil {
		return false, err
	}
	var issuer, subject, tokenNonce string
	var issuedAt, expiresAt int64
	if !decodeRequired(claims, "iss", &issuer) || issuer != qualified.options.Issuer ||
		!decodeRequired(claims, "sub", &subject) || !boundedASCII(subject, 255) ||
		!decodeRequired(claims, "nonce", &tokenNonce) || tokenNonce != nonce ||
		!decodeRequired(claims, "iat", &issuedAt) || !decodeRequired(claims, "exp", &expiresAt) ||
		!tokenAudience(claims, qualified.options.ClientID) {
		return false, ErrInvalidResponse
	}
	now := time.Now().Unix()
	if issuedAt <= 0 || expiresAt <= issuedAt || issuedAt > now+60 || expiresAt <= now {
		return false, ErrInvalidResponse
	}
	var authenticationTime int64
	rawAuthenticationTime, present := claims["auth_time"]
	if !present {
		return false, nil
	}
	if err := json.Unmarshal(rawAuthenticationTime, &authenticationTime); err != nil ||
		authenticationTime <= 0 || authenticationTime > issuedAt || authenticationTime > now+60 {
		return false, ErrInvalidResponse
	}
	return true, nil
}

func tokenAudience(claims map[string]json.RawMessage, expected string) bool {
	var audience string
	if decodeRequired(claims, "aud", &audience) {
		return audience == expected
	}
	var audiences []string
	return decodeRequired(claims, "aud", &audiences) && len(audiences) == 1 && audiences[0] == expected
}

func (qualified *probe) signingKey(
	ctx context.Context,
	endpoint string,
	token compactToken,
) (*rsa.PublicKey, error) {
	body, err := qualified.getJSON(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	set, err := decodeJSONObject(body)
	if err != nil {
		return nil, err
	}
	var keys []json.RawMessage
	if !decodeRequired(set, "keys", &keys) || len(keys) == 0 || len(keys) > 32 {
		return nil, ErrInvalidResponse
	}
	var selected *rsa.PublicKey
	for _, raw := range keys {
		candidate, candidateErr := decodeJSONObject(raw)
		if candidateErr != nil {
			return nil, candidateErr
		}
		var algorithm, keyID, keyType, modulus, exponent, use string
		if !decodeRequired(candidate, "kid", &keyID) {
			return nil, ErrInvalidResponse
		}
		if keyID != token.keyID {
			continue
		}
		if selected != nil || !decodeRequired(candidate, "alg", &algorithm) || algorithm != token.algorithm ||
			!decodeRequired(candidate, "kty", &keyType) || keyType != "RSA" ||
			!decodeRequired(candidate, "use", &use) || use != "sig" ||
			!decodeRequired(candidate, "n", &modulus) || !decodeRequired(candidate, "e", &exponent) {
			return nil, ErrInvalidResponse
		}
		key, keyErr := rsaKey(modulus, exponent)
		if keyErr != nil {
			return nil, keyErr
		}
		selected = key
	}
	if selected == nil {
		return nil, ErrInvalidResponse
	}
	return selected, nil
}

func rsaKey(modulusValue, exponentValue string) (*rsa.PublicKey, error) {
	modulus, err := base64.RawURLEncoding.Strict().DecodeString(modulusValue)
	if err != nil || len(modulus) < 256 || len(modulus) > 1024 {
		return nil, ErrInvalidResponse
	}
	exponentBytes, err := base64.RawURLEncoding.Strict().DecodeString(exponentValue)
	if err != nil || len(exponentBytes) == 0 || len(exponentBytes) > 4 {
		return nil, ErrInvalidResponse
	}
	exponent := 0
	for _, value := range exponentBytes {
		exponent = exponent<<8 | int(value)
	}
	if exponent < 3 || exponent%2 == 0 {
		return nil, ErrInvalidResponse
	}
	key := &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exponent}
	if key.N.BitLen() < 2048 || key.N.BitLen() > 8192 {
		return nil, ErrInvalidResponse
	}
	return key, nil
}

func (qualified *probe) getRequest(ctx context.Context, endpoint string) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, ErrInvalidResponse
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "meshcore-oidc-qualification/1")
	return request, nil
}

func (qualified *probe) getJSON(ctx context.Context, endpoint string) ([]byte, error) {
	request, err := qualified.getRequest(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	return qualified.doJSON(request, http.StatusOK)
}

func (qualified *probe) doJSON(request *http.Request, expectedStatus int) ([]byte, error) {
	response, err := qualified.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%w: request", ErrUnavailable)
	}
	defer func() { _ = response.Body.Close() }()
	return readJSONResponse(response, expectedStatus)
}

func (qualified *probe) getRedirect(ctx context.Context, endpoint string) (string, error) {
	request, err := qualified.getRequest(ctx, endpoint)
	if err != nil {
		return "", err
	}
	response, err := qualified.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("%w: request", ErrUnavailable)
	}
	defer func() { _ = response.Body.Close() }()
	return redirectLocation(response, endpoint)
}

func readJSONResponse(response *http.Response, expectedStatus int) ([]byte, error) {
	if response == nil || response.Body == nil {
		return nil, ErrUnavailable
	}
	if response.StatusCode != expectedStatus || !jsonContentType(response.Header.Get("Content-Type")) {
		return nil, ErrInvalidResponse
	}
	limited := io.LimitReader(response.Body, maximumResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("%w: response body", ErrUnavailable)
	}
	if len(body) == 0 || len(body) > maximumResponseBytes {
		return nil, ErrInvalidResponse
	}
	return body, nil
}

func jsonContentType(value string) bool {
	mediaType, parameters, err := mime.ParseMediaType(value)
	if err != nil || mediaType != "application/json" {
		return false
	}
	for name, parameter := range parameters {
		if name != "charset" || !strings.EqualFold(parameter, "utf-8") {
			return false
		}
	}
	return true
}

func decodeJSONObject(body []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrInvalidResponse
	}
	values := make(map[string]json.RawMessage)
	for decoder.More() {
		nameToken, nameErr := decoder.Token()
		name, ok := nameToken.(string)
		if nameErr != nil || !ok || len(name) > 128 {
			return nil, ErrInvalidResponse
		}
		if _, duplicate := values[name]; duplicate {
			return nil, ErrInvalidResponse
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, ErrInvalidResponse
		}
		values[name] = slices.Clone(raw)
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, ErrInvalidResponse
	}
	if token, err = decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return nil, ErrInvalidResponse
	}
	return values, nil
}

func decodeRequired[T any](values map[string]json.RawMessage, name string, target *T) bool {
	raw, present := values[name]
	return present && json.Unmarshal(raw, target) == nil
}
