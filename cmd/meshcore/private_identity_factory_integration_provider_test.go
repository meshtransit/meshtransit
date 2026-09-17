//go:build integration

package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/adapter/oidc"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

const privateFactoryCode = "synthetic-private-factory-code"
const privateFactorySubject = "Opaque-Fixture-Subject"

// Only synthetic provider state is mutable. Snapshot under lock, then perform
// crypto/HTTP without holding it. No handler calls testing.Fatal or logs input.
type privateFactorySigningProvider struct {
	server                              *httptest.Server
	key                                 *rsa.PrivateKey
	secret                              string
	route                               oidcauth.Route
	mu                                  sync.Mutex
	nonce, challenge                    string
	barrier                             *privateFactoryTokenBarrier
	discovery, tokens, jwks, unexpected atomic.Int64
}

func newPrivateFactorySigningProvider(t *testing.T, suffix byte) (*privateFactorySigningProvider, oidc.BasicSecret) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("generate synthetic signing key")
	}
	var material [32]byte
	if _, err := rand.Read(material[:]); err != nil {
		t.Fatal("generate synthetic client credential")
	}
	provider := &privateFactorySigningProvider{key: key, secret: base64.RawURLEncoding.EncodeToString(material[:])}
	clear(material[:])
	secret, err := oidc.NewBasicSecret(provider.secret)
	if err != nil {
		t.Fatal("construct synthetic client credential")
	}
	certificate, err := tls.LoadX509KeyPair(
		os.Getenv("MESHTRANSIT_TEST_OIDC_TLS_CERTIFICATE_FILE"),
		os.Getenv("MESHTRANSIT_TEST_OIDC_TLS_PRIVATE_KEY_FILE"),
	)
	if err != nil {
		t.Fatal("load owned signing-provider TLS fixture")
	}
	provider.server = httptest.NewUnstartedServer(http.HandlerFunc(provider.serve))
	provider.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	provider.server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
	provider.server.StartTLS()
	t.Cleanup(provider.server.Close)
	provider.route = (&privateFactoryMetadataProvider{server: provider.server}).route(t, suffix)
	return provider, secret
}

func (provider *privateFactorySigningProvider) arm(t *testing.T, location *url.URL, wrongNonce bool) {
	t.Helper()
	nonce := location.Query().Get("nonce")
	if wrongNonce {
		secrets, err := oidcauth.GenerateSecrets()
		if err != nil || secrets.Nonce().Encoded() == nonce {
			t.Fatal("generate independent wrong nonce")
		}
		nonce = secrets.Nonce().Encoded()
	}
	provider.mu.Lock()
	provider.nonce, provider.challenge = nonce, location.Query().Get("code_challenge")
	provider.mu.Unlock()
}

func (provider *privateFactorySigningProvider) serve(w http.ResponseWriter, r *http.Request) {
	validTLS := r.TLS != nil && r.TLS.Version >= tls.VersionTLS12
	if !validTLS || r.URL.RawQuery != "" {
		provider.reject(w)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/realm/discovery":
		provider.discovery.Add(1)
		route := provider.route
		provider.write(w, map[string]any{
			"issuer": route.Issuer(), "authorization_endpoint": route.AuthorizationEndpoint(),
			"token_endpoint": route.TokenEndpoint(), "jwks_uri": route.JWKSURI(),
			"response_types_supported": []string{"code"}, "code_challenge_methods_supported": []string{"S256"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		})
	case r.Method == http.MethodPost && r.URL.Path == "/realm/token":
		provider.tokens.Add(1)
		provider.token(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/realm/jwks":
		provider.jwks.Add(1)
		provider.write(w, map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "alg": "RS256", "kid": "synthetic-signing-v1", "use": "sig",
			"key_ops": []string{"verify"}, "n": base64.RawURLEncoding.EncodeToString(provider.key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(provider.key.E)).Bytes()),
		}}})
	default:
		provider.reject(w)
	}
}

func (provider *privateFactorySigningProvider) token(w http.ResponseWriter, r *http.Request) {
	user, password, basic := r.BasicAuth()
	validUser := user == url.QueryEscape(provider.route.OIDCClientID())
	validSecret := subtle.ConstantTimeCompare([]byte(password), []byte(url.QueryEscape(provider.secret))) == 1
	validHeaders := r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" &&
		r.Header.Get("Accept") == "application/json"
	validCredential := basic && validUser && validSecret
	if !validCredential || !validHeaders {
		provider.reject(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		provider.reject(w)
		return
	}
	provider.mu.Lock()
	nonce, challenge, barrier := provider.nonce, provider.challenge, provider.barrier
	provider.mu.Unlock()
	validForm := len(r.PostForm) == 4 && r.PostForm.Get("grant_type") == "authorization_code"
	validCode := r.PostForm.Get("code") == privateFactoryCode &&
		r.PostForm.Get("redirect_uri") == provider.route.RedirectURI()
	verifier, err := oidcauth.ParseVerifier(r.PostForm.Get("code_verifier"))
	validPKCE := err == nil && verifier.Challenge() == challenge && challenge != ""
	for _, values := range r.PostForm {
		validForm = validForm && len(values) == 1
	}
	validRequest := validForm && validCode && validPKCE
	if !validRequest || nonce == "" {
		provider.reject(w)
		return
	}
	if barrier != nil {
		if !barrier.accepted.CompareAndSwap(false, true) {
			provider.reject(w)
			return
		}
		// Sender-owned signals bracket the entire accepted token handler. The
		// owner releases/cancels and joins it before closing the TLS server.
		close(barrier.entered)
		defer close(barrier.exited)
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		select {
		case <-ctx.Done():
			provider.unexpected.Add(1)
			return
		case <-barrier.release:
		}
		if ctx.Err() != nil {
			provider.unexpected.Add(1)
			return
		}
	}
	now := time.Now().UTC().Unix()
	header, headerErr := json.Marshal(map[string]any{"alg": "RS256", "kid": "synthetic-signing-v1", "typ": "JWT"})
	claims, claimsErr := json.Marshal(map[string]any{
		"iss": provider.route.Issuer(), "sub": privateFactorySubject, "aud": provider.route.OIDCClientID(),
		"nonce": nonce, "iat": now - 1, "exp": now + 120, "auth_time": now - 2,
		"acr": "urn:meshtransit:assurance:mfa", "amr": []string{"synthetic-mfa"},
		// Mutable provider profile/roles are deliberately irrelevant to Core access.
		"email": "member@example.test", "email_verified": true, "roles": []string{"realm-admin"},
	})
	if headerErr != nil || claimsErr != nil {
		provider.reject(w)
		return
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(input))
	// Standard RS256 signing, synthetic fixture only; production verifies itself.
	signature, err := rsa.SignPKCS1v15(rand.Reader, provider.key, crypto.SHA256, digest[:])
	if err != nil {
		provider.reject(w)
		return
	}
	provider.write(w, map[string]any{"id_token": input + "." + base64.RawURLEncoding.EncodeToString(signature)})
}

// Optional synthetic-provider scheduling only; never a production clock/effect
// port. Existing signing cases have no barrier and retain their original path.
type privateFactoryTokenBarrier struct {
	entered, release, exited chan struct{}
	accepted                 atomic.Bool
	releaseOnce              sync.Once
}

func (provider *privateFactorySigningProvider) holdToken(t *testing.T) *privateFactoryTokenBarrier {
	t.Helper()
	barrier := &privateFactoryTokenBarrier{
		entered: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{}),
	}
	provider.mu.Lock()
	alreadyHeld := provider.barrier != nil
	if !alreadyHeld {
		provider.barrier = barrier
	}
	provider.mu.Unlock()
	if alreadyHeld {
		t.Fatal("synthetic provider barrier already owned")
	}
	t.Cleanup(barrier.unblock)
	return barrier
}

func (barrier *privateFactoryTokenBarrier) unblock() {
	barrier.releaseOnce.Do(func() { close(barrier.release) })
}

func (provider *privateFactorySigningProvider) reject(w http.ResponseWriter) {
	provider.unexpected.Add(1)
	http.Error(w, "unexpected fixture request", http.StatusBadRequest)
}

func (provider *privateFactorySigningProvider) write(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		provider.unexpected.Add(1)
	}
}
