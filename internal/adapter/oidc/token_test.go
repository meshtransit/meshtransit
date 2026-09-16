package oidc

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

func TestTokenPOSTAndSeparateTrustedJWKSOverTLS(t *testing.T) {
	t.Parallel()
	key, jwk := tokenKey(t, "RS256")
	token := signedToken(t, key, "RS256", tokenClaims(t), nil)
	code, verifier := tokenCodeVerifier(t)
	var posts, gets atomic.Int64
	keys := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		gets.Add(1)
		if request.Method != http.MethodGet || request.URL.Path != "/jwks" || request.Header.Get("Authorization") != "" {
			t.Error("JWKS method/path/credential invalid")
		}
		writer.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(writer, tokenJSON(t, map[string]any{"keys": []any{jwk}})); err != nil {
			t.Error(err)
		}
	}))
	defer keys.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		posts.Add(1)
		if request.Method != http.MethodPost || request.URL.Path != "/token" || request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Error("token method/path/content type invalid")
		}
		username, password, ok := request.BasicAuth()
		if !ok || username != url.QueryEscape(discoveryRoute(t).OIDCClientID()) || password != url.QueryEscape(strings.Repeat("synthetic-", 4)) {
			t.Error("confidential credential encoding invalid")
		}
		if err := request.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		if len(request.PostForm) != 4 || request.PostForm.Get("grant_type") != "authorization_code" || request.PostForm.Get("code") != code.Encoded() || request.PostForm.Get("code_verifier") != verifier.Encoded() || request.PostForm.Get("redirect_uri") != discoveryRoute(t).RedirectURI() {
			t.Error("original PKCE/code/redirect lost")
		}
		writer.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(writer, tokenJSON(t, map[string]any{"id_token": token, "access_token": "discarded-access", "refresh_token": "discarded-refresh"})); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	authenticator := tokenAuthenticator(t, "RS256")
	authenticator.route = tokenRoute(t, authenticator.route, "RS256", server.URL+"/token", keys.URL+"/jwks")
	transport := authenticator.client.(*http.Client).Transport.(*http.Transport)
	// Both httptest servers use the same test certificate. Add that explicit root;
	// hostname verification remains enabled and no production trust is changed.
	transport.TLSClientConfig.RootCAs = server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	evidence, err := authenticator.exchangeToken(t.Context(), code, verifier)
	if err != nil || !evidence.IsValid() || posts.Load() != 1 || gets.Load() != 1 {
		t.Fatalf("TLS exchange failed: %v; posts=%d gets=%d", err, posts.Load(), gets.Load())
	}
}

func TestTokenPOSTNeverRetriesEvenOnUnknownCompletion(t *testing.T) {
	t.Parallel()
	for _, body := range []string{`{"error":"invalid_grant","private":"credential"}`, `{"id_token":null}`, `{"id_token":"bad"}`, `{"id_token":"one","id_token":"two"}`} {
		t.Run(body, func(t *testing.T) {
			t.Parallel()
			authenticator := tokenAuthenticator(t, "RS256")
			calls := 0
			authenticator.client = doerFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return discoveryResponse(200, "application/json", body), nil
			})
			code, verifier := tokenCodeVerifier(t)
			if evidence, err := authenticator.exchangeToken(t.Context(), code, verifier); err == nil || evidence.IsValid() || calls != 1 || strings.Contains(err.Error(), "credential") {
				t.Fatal("failed POST retried or disclosed data")
			}
		})
	}
	authenticator := tokenAuthenticator(t, "RS256")
	calls := 0
	authenticator.client = doerFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("private code/url/credential")
	})
	code, verifier := tokenCodeVerifier(t)
	if evidence, err := authenticator.exchangeToken(t.Context(), code, verifier); !errors.Is(err, ErrTokenUnavailable) || evidence.IsValid() || calls != 1 || strings.Contains(err.Error(), "private") {
		t.Fatal("uncertain POST retried or raw transport error leaked")
	}
}

func TestTokenReadJoinsCloseAndBoundsHeadersAndBody(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"success", "close error", "read error", "oversize", "advertised oversize", "redirect", "compression", "duplicate content type", "wrong charset", "response plus error", "nil response", "nil body"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			body := &tokenTestBody{Reader: strings.NewReader(`{"ok":true}`)}
			response := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: body}
			var doErr error
			switch name {
			case "close error":
				body.closeErr = errors.New("private close")
			case "read error":
				body.readErr = errors.New("private read")
			case "oversize":
				body.Reader = strings.NewReader(strings.Repeat("x", 65))
			case "advertised oversize":
				response.ContentLength = 65
			case "redirect":
				response.StatusCode = 302
			case "compression":
				response.Header.Set("Content-Encoding", "gzip")
			case "duplicate content type":
				response.Header.Add("Content-Type", "application/json")
			case "wrong charset":
				response.Header.Set("Content-Type", "application/json; charset=latin1")
			case "response plus error":
				doErr = errors.New("private transport")
			case "nil response":
				response = nil
			case "nil body":
				response.Body = nil
			}
			authenticator := tokenAuthenticator(t, "RS256")
			authenticator.client = doerFunc(func(*http.Request) (*http.Response, error) { return response, doErr })
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticator.route.JWKSURI(), nil)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := authenticator.readJSON(t.Context(), request, 64)
			if (err == nil) != (name == "success") || err != nil && (len(raw) != 0 || strings.Contains(err.Error(), "private")) {
				t.Fatal("body or error release invariant violated")
			}
			if name != "nil response" && name != "nil body" && body.closes != 1 {
				t.Fatal("body Close was not joined exactly once")
			}
		})
	}
}

func TestTokenExchangeDeadlineAndCancellationReleaseNoEvidence(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		authenticator := tokenAuthenticator(t, "RS256")
		calls := 0
		authenticator.client = doerFunc(func(request *http.Request) (*http.Response, error) {
			calls++
			<-request.Context().Done()
			return nil, request.Context().Err()
		})
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		code, verifier := tokenCodeVerifier(t)
		evidence, err := authenticator.exchangeToken(ctx, code, verifier)
		if !errors.Is(err, context.DeadlineExceeded) || evidence.IsValid() || calls != 1 {
			t.Fatal("deadline leaked evidence or retried")
		}
	})
	authenticator := tokenAuthenticator(t, "RS256")
	authenticator.client = doerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("canceled/invalid request performed I/O")
		return nil, nil
	})
	code, verifier := tokenCodeVerifier(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if evidence, err := authenticator.exchangeToken(ctx, code, verifier); !errors.Is(err, context.Canceled) || evidence.IsValid() {
		t.Fatal("cancellation lost")
	}
	if evidence, err := authenticator.Authenticate(t.Context(), oidcauth.ExchangeRequest{}); !errors.Is(err, ErrInvalidAuthenticator) || evidence.IsValid() {
		t.Fatal("forged request accepted")
	}
}

func TestTokenClientConstructionIsStrictAndRedacted(t *testing.T) {
	t.Parallel()
	authenticator := tokenAuthenticator(t, "RS256")
	client := authenticator.client.(*http.Client)
	transport := client.Transport.(*http.Transport)
	if transport.Proxy != nil || !transport.DisableCompression || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 || transport.TLSClientConfig.InsecureSkipVerify || transport.MaxConnsPerHost == 0 {
		t.Fatal("unsafe token transport")
	}
	if !errors.Is(client.CheckRedirect(nil, nil), http.ErrUseLastResponse) {
		t.Fatal("redirect allowed")
	}
	for _, value := range []any{authenticator, authenticator.secret} {
		if fmt.Sprint(value) != "[REDACTED]" || strings.Contains(fmt.Sprintf("%#v", value), "synthetic-") {
			t.Fatal("secret formatting leaked")
		}
	}
	for _, input := range []string{"", "short", strings.Repeat("x", 4097), strings.Repeat("x", 32) + "\n"} {
		if _, err := NewBasicSecret(input); err == nil {
			t.Fatal("unsafe credential accepted")
		}
	}
}

type tokenTestBody struct {
	io.Reader
	readErr, closeErr error
	closes            int
}

func (body *tokenTestBody) Read(raw []byte) (int, error) {
	if body.readErr != nil {
		return 0, body.readErr
	}
	return body.Reader.Read(raw)
}
func (body *tokenTestBody) Close() error { body.closes++; return body.closeErr }

func tokenCodeVerifier(t *testing.T) (oidcauth.Code, oidcauth.Verifier) {
	t.Helper()
	code, err := oidcauth.ParseCode("synthetic/code+value")
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := oidcauth.ParseVerifier(base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("v", 32))))
	if err != nil {
		t.Fatal(err)
	}
	return code, verifier
}
