//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"go.uber.org/goleak"

	"meshtransit.net/core/internal/adapter/httpapi"
	"meshtransit.net/core/internal/adapter/oidc"
	"meshtransit.net/core/internal/platform/config"
)

func TestPrivateIdentityRuntimeProcessIntegration(t *testing.T) {
	if os.Getenv("MESHTRANSIT_PRIVATE_FACTORY_INTEGRATION") != "1" {
		t.Skip("requires owned Linux process fixture lane")
	}
	if runtime.GOOS != "linux" || os.Getenv("SSL_CERT_FILE") == "" || os.Getenv("SSL_CERT_DIR") == "" {
		t.Fatal("explicit Linux process-startup fixture trust required")
	}
	t.Cleanup(func() { goleak.VerifyNone(t) })
	storage := openPrivateFactoryIntegrationStorage(t, "meshtransit_private_process")
	provider := newPrivateFactoryMetadataProvider(t, "valid", false)
	address, health, api := privateRuntimeAddress(t), privateRuntimeAddress(t), privateRuntimeAddress(t)
	profileFile, certificate := privateRuntimeProfileFile(t, provider, address)
	environment := privateRuntimeEnvironment(t, profileFile, health, api)
	process, err := config.Load(func(name string) (string, bool) {
		for _, value := range environment {
			if key, content, found := strings.Cut(value, "="); found && key == name {
				return content, true
			}
		}
		return "", false
	})
	if err != nil || process.PrivateLogin == nil {
		t.Fatal("load immutable process configuration")
	}
	profile, err := process.PrivateLogin.Load(t.Context(), process)
	if err != nil {
		t.Fatal("load protected process profile")
	}
	storage.seedRoute(t, profile.Route())
	before := storage.census(t)
	binary := os.Getenv("MESHTRANSIT_TEST_MESHCORE_BINARY")
	expected := filepath.Join(filepath.Dir(os.Getenv("MESHTRANSIT_TEST_POSTGRES_ADMIN_PASSWORD_FILE")), "meshcore")
	if !filepath.IsAbs(binary) || binary != expected {
		t.Fatal("refuse non-owned source binary")
	}

	// Initial provider failure closes only login readiness. General API/health
	// admission stays available, and configuration validation performs no I/O.
	provider.unavailable.Store(true)
	var validation, validationErrors bytes.Buffer
	lookup := func(name string) (string, bool) {
		for _, value := range environment {
			if key, content, found := strings.Cut(value, "="); found && key == name {
				return content, true
			}
		}
		return "", false
	}
	if code := runConfigValidate(t.Context(), lookup, &validation, &validationErrors); code != 0 {
		t.Fatal("effect-free private configuration validation failed")
	}
	var validated configValidationOutput
	if err := json.Unmarshal(validation.Bytes(), &validated); err != nil ||
		validated.Status != "valid" || validated.SchemaVersion != config.SchemaVersion || validated.Role != "api" {
		t.Fatal("private configuration validation output changed")
	}
	clear(validationErrors.Bytes())
	validationErrors.Reset()
	if provider.discovery.Load() != 0 || provider.other.Load() != 0 || storage.census(t) != before {
		t.Fatal("configuration validation performed readiness or authority effects")
	}
	child := startPrivateRuntimeProcess(t, binary, environment)
	client := privateRuntimeClient(t, certificate)
	privateRuntimeWait(t, child, func(ctx context.Context) bool {
		return privateRuntimeHealthStatus(ctx, client, health, "/ready", http.StatusOK)
	})
	privateRuntimeWait(t, child, func(ctx context.Context) bool {
		return privateRuntimeHealthStatus(ctx, client, health, "/ready/login", http.StatusServiceUnavailable)
	})
	if provider.discovery.Load() == 0 {
		t.Fatal("login readiness did not reach the unavailable provider")
	}
	if storage.census(t) != before {
		t.Fatal("readiness granted durable authority")
	}
	provider.unavailable.Store(false)
	privateRuntimeWait(t, child, func(ctx context.Context) bool {
		return privateRuntimeHealthStatus(ctx, client, health, "/ready/login", http.StatusOK)
	})
	response, body := privateRuntimeRequest(
		t, client, http.MethodGet, "https://"+address+httpapi.LoginCallbackContinuePath, nil, nil,
	)
	validLanding := response.StatusCode == http.StatusOK && len(body) > 0 && len(response.Cookies()) == 0
	if !validLanding || storage.census(t) != before {
		t.Fatal("real TLS landing granted authority or failed")
	}
	// Synthetic query canaries enter the actual compiled TLS dispatcher without
	// browser possession. No response or durable authority may be released.
	privateRuntimeQueryCanaries(
		t,
		client,
		profile.Route().RedirectURI(),
		profile.Route().Issuer(),
	)
	if storage.census(t) != before || provider.other.Load() != 0 {
		t.Fatal("rejected query canaries changed authority or exchanged credentials")
	}
	response, body = privateRuntimeRequest(
		t,
		client,
		http.MethodGet,
		"http://"+health+"/ready",
		nil,
		nil,
	)
	if response.StatusCode != http.StatusOK || !privateRuntimeCanaryFree(body) {
		t.Fatal("runtime health disclosed query material or became unavailable")
	}
	response, body = privateRuntimeRequest(
		t, client, http.MethodPost, "https://"+address+httpapi.LoginPreparePath, nil, nil,
	)
	var intent struct {
		Proof string `json:"csrf_token"`
	}
	if err := json.Unmarshal(body, &intent); err != nil || response.StatusCode != http.StatusOK || intent.Proof == "" {
		t.Fatal("compiled runtime prepare failed")
	}
	if storage.census(t) != before {
		t.Fatal("prepare granted durable authority")
	}
	response, body = privateRuntimeRequest(
		t, client, http.MethodPost, "https://"+address+httpapi.LoginStartPath,
		response.Cookies(), http.Header{oidc.LoginCSRFHeader: []string{intent.Proof}},
	)
	var started struct {
		URL string `json:"authorization_url"`
	}
	if err := json.Unmarshal(body, &started); err != nil {
		t.Fatal("compiled runtime pending response malformed")
	}
	location, err := url.Parse(started.URL)
	if err != nil {
		t.Fatal("compiled runtime authorization URL malformed")
	}
	query := location.Query()
	location.RawQuery = ""
	route := profile.Route()
	validURL := location.String() == route.AuthorizationEndpoint() &&
		query.Get("client_id") == route.OIDCClientID() && query.Get("redirect_uri") == route.RedirectURI() &&
		query.Get("response_type") == "code" && query.Get("scope") == "openid" &&
		query.Get("code_challenge_method") == "S256"
	if response.StatusCode != http.StatusOK || response.Header.Get("Location") != "" || !validURL {
		t.Fatal("compiled runtime pending creation failed")
	}
	preAuth := 0
	for _, cookie := range response.Cookies() {
		if cookie.Name == "__Host-mt_session" {
			t.Fatal("compiled pending creation granted Session cookie")
		}
		if cookie.Name == oidc.PreAuthCookieName {
			preAuth++
			if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" ||
				cookie.SameSite != http.SameSiteLaxMode {
				t.Fatal("compiled pending response lost protected cookie scope")
			}
		}
	}
	if preAuth != 1 {
		t.Fatal("compiled pending response lost single pre-auth cookie")
	}
	before.transactions++
	before.mutations++
	before.audit++
	before.outbox++
	if storage.census(t) != before {
		t.Fatal("pending creation changed unrelated authority")
	}
	response, body = privateRuntimeRequest(
		t, client, http.MethodGet, "http://"+health+"/metrics", nil, nil,
	)
	privateMetrics := strings.Contains(string(body), `auth_profile="console_cookie_private_v1"`)
	apiMetrics := strings.Contains(string(body), `auth_profile="core_session_bearer_v1"`)
	if response.StatusCode != http.StatusOK || !privateMetrics || !apiMetrics {
		t.Fatal("runtime metrics profile collision or omission")
	}
	if !privateRuntimeCanaryFree(body) {
		t.Fatal("runtime metrics disclosed synthetic query material")
	}
	capturesObserved := false
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "meshtransit_browser_login_dispatch_requests_total{") &&
			strings.Contains(line, `operation="capture"`) && strings.Contains(line, `result="handler_error"`) &&
			strings.HasSuffix(line, "} 3") {
			capturesObserved = true
		}
	}
	if !capturesObserved {
		t.Fatal("canaries did not traverse compiled callback dispatcher")
	}
	provider.unavailable.Store(true)
	privateRuntimeWait(t, child, func(ctx context.Context) bool {
		return privateRuntimeHealthStatus(ctx, client, health, "/ready/login", http.StatusServiceUnavailable)
	})
	if !privateRuntimeHealthStatus(t.Context(), client, health, "/ready", http.StatusOK) {
		t.Fatal("login-only dependency failure evicted the healthy API runtime")
	}
	provider.unavailable.Store(false)
	privateRuntimeWait(t, child, func(ctx context.Context) bool {
		return privateRuntimeHealthStatus(ctx, client, health, "/ready/login", http.StatusOK)
	})
	if storage.census(t) != before || provider.other.Load() != 0 {
		t.Fatal("readiness changed authority or contacted unregistered endpoints")
	}
	if err := child.command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal("signal owned process")
	}
	if err := child.join(t.Context(), 5*time.Second); err != nil {
		t.Fatal("private process did not drain cleanly")
	}
	// Wait joins the sole os/exec output writer before inspecting owned buffers.
	if child.diagnostic.truncated || !privateRuntimeCanaryFree(child.diagnostic.buffer.Bytes()) {
		t.Fatal("joined process query custody window was truncated or disclosed material")
	}
}

const (
	privateRuntimeCodeCanary        = "synthetic-query-code-custody-001"
	privateRuntimeDescriptionCanary = "synthetic-query-description-custody-001"
	privateRuntimeURICanary         = "synthetic-query-uri-custody-001"
)

func privateRuntimeCanaryFree(contents []byte) bool {
	state := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x71}, 32))
	for _, marker := range []string{
		privateRuntimeCodeCanary, privateRuntimeDescriptionCanary, privateRuntimeURICanary, state,
	} {
		if bytes.Contains(contents, []byte(marker)) {
			return false
		}
	}
	return true
}

func privateRuntimeQueryCanaries(t *testing.T, client *http.Client, target, issuer string) {
	t.Helper()
	// Request.Close prevents subsequent reuse, not reuse of the landing socket.
	// Discard existing idle sockets before the first no-response GET.
	client.CloseIdleConnections()
	state := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x71}, 32))
	for _, query := range []string{
		"code=" + privateRuntimeCodeCanary + "&state=" + state + "&state=" + state,
		"code=" + privateRuntimeCodeCanary + "&state=" + state,
		"error=access_denied&state=" + state + "&error_description=" + privateRuntimeDescriptionCanary +
			"&error_uri=https%3A%2F%2Fexample.test%2F" + privateRuntimeURICanary,
	} {
		request, err := http.NewRequestWithContext(
			t.Context(),
			http.MethodGet,
			target+"?"+query+"&iss="+url.QueryEscape(issuer),
			nil,
		)
		if err != nil {
			t.Fatal("create synthetic custody request")
		}
		// Use a fresh owned connection, with no transport retry on a reused one.
		request.Close = true
		response, err := client.Do(request)
		if response != nil {
			if closeErr := response.Body.Close(); closeErr != nil {
				t.Fatal("close unexpected custody response")
			}
			t.Fatal("query without possession released response")
		}
		if !errors.Is(err, io.EOF) {
			t.Fatal("query rejection did not close before response")
		}
	}
}

func TestPrivateRuntimeCanaryTransportDoesNotRetry(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	var captures atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/landing" {
			response.WriteHeader(http.StatusOK)
			return
		}
		captures.Add(1)
		panic(http.ErrAbortHandler)
	}))
	t.Cleanup(server.Close)
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client := privateRuntimeClient(t, certificate)
	response, _ := privateRuntimeRequest(
		t,
		client,
		http.MethodGet,
		server.URL+"/landing",
		nil,
		nil,
	)
	if response.StatusCode != http.StatusOK {
		t.Fatal("transport fixture landing failed")
	}
	privateRuntimeQueryCanaries(
		t,
		client,
		server.URL+"/callback",
		"https://identity.example.test/realm",
	)
	if count := captures.Load(); count != 3 {
		t.Fatalf("canary transport attempted unexpected capture count: %d", count)
	}
}

func privateRuntimeProfileFile(
	t *testing.T,
	provider *privateFactoryMetadataProvider,
	address string,
) (string, []byte) {
	t.Helper()
	directory := t.TempDir()
	keys := map[string]any{}
	for _, purpose := range []string{"initiation", "capture", "continuation", "management_csrf", "transaction_digest",
		"verifier_encryption", "subject_active", "provider_session"} {
		var material [32]byte
		if _, err := rand.Read(material[:]); err != nil {
			t.Fatal("generate synthetic key")
		}
		file := filepath.Join(directory, purpose)
		writeCredentialDigestTestKey(t, file, base64.RawURLEncoding.EncodeToString(material[:]))
		clear(material[:])
		keys[purpose] = map[string]string{"id": purpose + "-v1", "file": file}
	}
	certificate, private := privateRuntimeCertificate(t)
	certFile := filepath.Join(directory, "server.crt")
	keyFile := filepath.Join(directory, "server.key")
	secretFile := filepath.Join(directory, "client-secret")
	for _, file := range []struct {
		path     string
		contents []byte
	}{
		{path: certFile, contents: certificate}, {path: keyFile, contents: private},
	} {
		if err := os.WriteFile(file.path, file.contents, 0o600); err != nil {
			t.Fatal("write protected fixture")
		}
	}
	clear(private)
	var credential [32]byte
	if _, err := rand.Read(credential[:]); err != nil {
		t.Fatal("generate confidential fixture credential")
	}
	writeCredentialDigestTestKey(t, secretFile, base64.RawURLEncoding.EncodeToString(credential[:]))
	clear(credential[:])
	route := provider.route(t, 100)
	document := map[string]any{
		"version": 1, "address": address,
		// Version 1 still requires a valid workspace_id, which Core now ignores;
		// it deliberately differs from the seeded login Workspace. Version 4 would
		// need a named non-IP origin this loopback fixture cannot serve.
		"deployment_id": route.DeploymentID().String(), "workspace_id": privateIdentityID(t, 0xfe).String(),
		"provider_id": route.ProviderID().String(), "client_id": route.ClientID().String(),
		"provider_generation": route.ProviderGeneration(),
		"recovery_epoch":      route.RecoveryEpoch(), "issuer": route.Issuer(), "discovery_uri": route.DiscoveryURI(),
		"authorization_endpoint": route.AuthorizationEndpoint(),
		"token_endpoint":         route.TokenEndpoint(), "jwks_uri": route.JWKSURI(),
		"oidc_client_id": route.OIDCClientID(), "redirect_id": route.RedirectID(), "return_route_id": route.ReturnRouteID(),
		"tls_certificate_file": certFile, "tls_private_key_file": keyFile, "client_secret_file": secretFile, "keys": keys,
	}
	contents, err := json.Marshal(document)
	if err != nil {
		t.Fatal("encode fixture manifest")
	}
	file := filepath.Join(directory, "login.json")
	if err := os.WriteFile(file, contents, 0o600); err != nil {
		t.Fatal("write protected manifest")
	}
	return file, certificate
}

func privateRuntimeCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate fixture TLS key")
	}
	now := time.Now()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	encoded, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal("create fixture TLS certificate")
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("marshal fixture TLS key")
	}
	defer clear(private)
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded})
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	return certificatePEM, privatePEM
}

func privateRuntimeEnvironment(t *testing.T, profile, health, api string) []string {
	t.Helper()
	values := map[string]string{
		"MESHTRANSIT_ROLE": "api", "MESHTRANSIT_PRIVATE_LOGIN_CONFIG_FILE": profile, "MESHTRANSIT_HEALTH_ADDRESS": health,
		"MESHTRANSIT_API_ADDRESS": api, "MESHTRANSIT_DEPENDENCY_CHECK_TIMEOUT": "2s",
		"MESHTRANSIT_DEPENDENCY_CHECK_INTERVAL":                "3s",
		"MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_ACTIVE_KEY_ID": "session-v1",
		"MESHTRANSIT_API_IDEMPOTENCY_DIGEST_KEY_ID":            "idempotency-v1",
		"MESHTRANSIT_API_RATE_LIMIT_DIGEST_KEY_ID":             "rate-limit-v1",
	}
	for _, name := range []string{
		"SSL_CERT_FILE", "SSL_CERT_DIR", "MESHTRANSIT_POSTGRES_ADDRESS", "MESHTRANSIT_POSTGRES_DATABASE",
		"MESHTRANSIT_POSTGRES_CA_FILE", "MESHTRANSIT_POSTGRES_RUNTIME_USER",
		"MESHTRANSIT_POSTGRES_RUNTIME_PASSWORD_FILE", "MESHTRANSIT_POSTGRES_RUNTIME_MAX_CONNECTIONS",
		"MESHTRANSIT_REDIS_ADDRESS", "MESHTRANSIT_REDIS_USERNAME", "MESHTRANSIT_REDIS_PASSWORD_FILE",
		"MESHTRANSIT_REDIS_CA_FILE",
		"MESHTRANSIT_REDIS_POOL_SIZE", "MESHTRANSIT_API_TLS_CERTIFICATE_FILE", "MESHTRANSIT_API_TLS_PRIVATE_KEY_FILE",
		"MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_ACTIVE_KEY_FILE", "MESHTRANSIT_API_IDEMPOTENCY_DIGEST_KEY_FILE",
		"MESHTRANSIT_API_RATE_LIMIT_DIGEST_KEY_FILE",
	} {
		value, present := os.LookupEnv(name)
		if !present || value == "" {
			t.Fatal("missing explicit owned runtime profile")
		}
		values[name] = value
	}
	environment := make([]string, 0, len(values))
	for name, value := range values {
		environment = append(environment, name+"="+value)
	}
	return environment
}

type privateRuntimeProcess struct {
	command    *exec.Cmd
	done       chan struct{}
	err        error // Read only after the single Wait owner closes done.
	diagnostic privateRuntimeDiagnostic
}

// Retain at most one bounded startup log window. Only closed error-code values
// may be reported after Wait joins the writer; raw logs are never printed.
type privateRuntimeDiagnostic struct {
	buffer    bytes.Buffer
	truncated bool
}

func (diagnostic *privateRuntimeDiagnostic) Write(contents []byte) (int, error) {
	limit := min(len(contents), max(0, 8192-diagnostic.buffer.Len()))
	if limit != len(contents) {
		diagnostic.truncated = true
	}
	if _, err := diagnostic.buffer.Write(contents[:limit]); err != nil {
		return 0, err
	}
	return len(contents), nil
}

func (diagnostic *privateRuntimeDiagnostic) failureCode() string {
	defer func() { clear(diagnostic.buffer.Bytes()); diagnostic.buffer.Reset() }()
	if diagnostic.truncated {
		return "closed_process_failure"
	}
	for _, line := range bytes.Split(diagnostic.buffer.Bytes(), []byte{'\n'}) {
		var entry struct {
			Code string `json:"error_code"`
		}
		if json.Unmarshal(line, &entry) != nil {
			continue
		}
		switch entry.Code {
		case "invalid_configuration", "private_login_configuration_failure", "postgres_open_failure",
			"redis_open_failure", "private_login_composition_failure", "management_api_composition_failure",
			"invalid_dependency_monitor", "invalid_health_server", "invalid_application", "runtime_failure":
			return entry.Code
		}
	}
	return "closed_process_failure"
}

func TestPrivateRuntimeDiagnosticCustody(t *testing.T) {
	t.Parallel()
	for _, marker := range []string{privateRuntimeCodeCanary, privateRuntimeDescriptionCanary, privateRuntimeURICanary,
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x71}, 32))} {
		if privateRuntimeCanaryFree([]byte("prefix " + marker + " suffix")) {
			t.Fatal("canary detector missed synthetic query material")
		}
	}
	var diagnostic privateRuntimeDiagnostic
	for _, contents := range [][]byte{bytes.Repeat([]byte{'x'}, 8192), []byte(privateRuntimeCodeCanary)} {
		if written, err := diagnostic.Write(contents); written != len(contents) || err != nil {
			t.Fatal("owned diagnostic write failed")
		}
	}
	if !diagnostic.truncated || diagnostic.buffer.Len() != 8192 || diagnostic.failureCode() != "closed_process_failure" {
		t.Fatal("truncated diagnostic accepted as custody evidence")
	}
	if diagnostic.buffer.Len() != 0 {
		t.Fatal("joined diagnostic retained owned bytes")
	}
}

func startPrivateRuntimeProcess(t *testing.T, binary string, environment []string) *privateRuntimeProcess {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	// Binary is validated as the exact just-built fixture executable, no shell.
	command := exec.CommandContext(ctx, binary, "serve") //nolint:gosec
	child := &privateRuntimeProcess{command: command, done: make(chan struct{})}
	// os/exec serializes identical stdout/stderr writers. Only inspect after Wait.
	command.Env, command.Stdout, command.Stderr = environment, &child.diagnostic, &child.diagnostic
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal("start owned process")
	}
	go func() { child.err = command.Wait(); close(child.done) }()
	t.Cleanup(func() {
		cancel()
		if err := child.join(context.WithoutCancel(t.Context()), 5*time.Second); errors.Is(err, context.DeadlineExceeded) {
			t.Error("owned process wait did not join")
		} else {
			_ = child.diagnostic.failureCode()
		}
	})
	return child
}

func (child *privateRuntimeProcess) join(ctx context.Context, window time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	select {
	case <-child.done:
		return child.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func privateRuntimeAddress(t *testing.T) string {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("reserve fixture address")
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal("release fixture address")
	}
	return address
}

func privateRuntimeClient(t *testing.T, certificate []byte) *http.Client {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		t.Fatal("fixture TLS trust")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout: time.Second, ResponseHeaderTimeout: time.Second, MaxResponseHeaderBytes: 16 * 1024}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

type privateRuntimeResponse struct {
	StatusCode int
	Header     http.Header
	cookies    []*http.Cookie
}

func (response privateRuntimeResponse) Cookies() []*http.Cookie { return response.cookies }

func privateRuntimeRequest(
	t *testing.T,
	client *http.Client,
	method, target string,
	cookies []*http.Cookie,
	headers http.Header,
) (privateRuntimeResponse, []byte) {
	t.Helper()
	var input io.Reader
	if method == http.MethodPost {
		input = strings.NewReader("{}")
	}
	request, err := http.NewRequestWithContext(t.Context(), method, target, input)
	if err != nil {
		t.Fatal("create fixture request")
	}
	request.Header = headers.Clone()
	if request.Header == nil {
		request.Header = http.Header{}
	}
	if method == http.MethodPost {
		request.Header.Set("Origin", "https://"+request.URL.Host)
		request.Header.Set("Sec-Fetch-Site", "same-origin")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-MeshTransit-Login", "v1")
	}
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("owned runtime request failed")
	}
	maxBody := 256 * 1024
	if request.URL.Path == "/metrics" && method == http.MethodGet && len(cookies) == 0 {
		maxBody = 1024 * 1024
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, int64(maxBody)+1))
	closeErr := response.Body.Close()
	if readErr != nil {
		t.Fatalf("fixture response read failed: status=%d bytes=%d", response.StatusCode, len(body))
	}
	if closeErr != nil {
		t.Fatal("fixture response close failed")
	}
	if len(body) > maxBody {
		t.Fatalf("fixture response exceeds byte limit: status=%d bytes=%d", response.StatusCode, len(body))
	}
	return privateRuntimeResponse{StatusCode: response.StatusCode, Header: response.Header.Clone(),
		cookies: response.Cookies()}, body
}

func privateRuntimeHealthStatus(
	ctx context.Context,
	client *http.Client,
	address string,
	path string,
	status int,
) bool {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+path, nil)
	if err != nil {
		return false
	}
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	if err := response.Body.Close(); err != nil {
		return false
	}
	return response.StatusCode == status
}

func privateRuntimeWait(t *testing.T, child *privateRuntimeProcess, ready func(context.Context) bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ready(ctx) {
			return
		}
		select {
		case <-child.done:
			t.Fatal("runtime exited before readiness condition: " + child.diagnostic.failureCode())
		case <-ctx.Done():
			t.Fatal("runtime readiness condition timed out")
		case <-ticker.C:
		}
	}
}
