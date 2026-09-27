package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

func TestIDTokenValidatesConfiguredAsymmetricAlgorithms(t *testing.T) {
	t.Parallel()
	for _, algorithm := range []string{"RS256", "PS256", "ES256"} {
		t.Run(algorithm, func(t *testing.T) {
			t.Parallel()
			key, jwk := tokenKey(t, algorithm)
			authenticator := tokenAuthenticator(t, algorithm)
			calls := 0
			authenticator.client = doerFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.URL.String() != authenticator.route.JWKSURI() || request.Method != http.MethodGet || request.Header.Get("Authorization") != "" {
					t.Fatal("JWKS request widened trust or leaked credential")
				}
				return discoveryResponse(200, "application/json", tokenJSON(t, map[string]any{"keys": []any{jwk}})), nil
			})
			token := signedToken(t, key, algorithm, tokenClaims(t), nil)
			evidence, err := authenticator.validateIDToken(t.Context(), token)
			if err != nil || !evidence.IsValid() || calls != 1 || fmt.Sprint(evidence) != "[REDACTED]" {
				t.Fatalf("valid ID token rejected: %v; reads=%d", err, calls)
			}
		})
	}
}

func TestIDTokenRejectsClaimsAndKeySubstitution(t *testing.T) {
	t.Parallel()
	key, jwk := tokenKey(t, "RS256")
	tests := []struct {
		name   string
		change func(map[string]any, map[string]any, map[string]any)
	}{
		{"issuer alias", func(c, _, _ map[string]any) { c["iss"] = discoveryRoute(t).Issuer() + "/" }},
		{"missing subject", func(c, _, _ map[string]any) { delete(c, "sub") }},
		{"subject control", func(c, _, _ map[string]any) { c["sub"] = "subject\n" }},
		{"wrong audience", func(c, _, _ map[string]any) { c["aud"] = "another-client" }},
		{"untrusted extra audience", func(c, _, _ map[string]any) {
			c["aud"] = []string{discoveryRoute(t).OIDCClientID(), "another-client"}
			c["azp"] = discoveryRoute(t).OIDCClientID()
		}},
		{"wrong authorized party", func(c, _, _ map[string]any) { c["azp"] = "another-client" }},
		{"null audience", func(c, _, _ map[string]any) { c["aud"] = nil }},
		{"missing nonce", func(c, _, _ map[string]any) { delete(c, "nonce") }},
		{"noncanonical nonce", func(c, _, _ map[string]any) { c["nonce"] = fmt.Sprint(c["nonce"]) + "=" }},
		{"expired exactly now", func(c, _, _ map[string]any) { c["exp"] = tokenNow().Unix() }},
		{"future issue", func(c, _, _ map[string]any) { c["iat"] = tokenNow().Add(2 * time.Minute).Unix() }},
		{"excessive age", func(c, _, _ map[string]any) { c["iat"] = tokenNow().Add(-11 * time.Minute).Unix() }},
		{"not yet valid", func(c, _, _ map[string]any) { c["nbf"] = tokenNow().Add(2 * time.Minute).Unix() }},
		{"fractional date", func(c, _, _ map[string]any) { c["iat"] = float64(tokenNow().Unix()) + 0.5 }},
		{"string date", func(c, _, _ map[string]any) { c["iat"] = fmt.Sprint(tokenNow().Unix()) }},
		{"overflow date", func(c, _, _ map[string]any) { c["exp"] = json.Number("9223372036854775808") }},
		{"excessive lifetime", func(c, _, _ map[string]any) { c["exp"] = tokenNow().Add(25 * time.Hour).Unix() }},
		{"future authentication", func(c, _, _ map[string]any) { c["auth_time"] = tokenNow().Add(time.Second).Unix() }},
		{"null assurance", func(c, _, _ map[string]any) { c["auth_time"] = nil }},
		{"duplicate AMR", func(c, _, _ map[string]any) { c["amr"] = []string{"pwd", "pwd"} }},
		{"symmetric confusion", func(_, h, _ map[string]any) { h["alg"] = "HS256" }},
		{"unsigned", func(_, h, _ map[string]any) { h["alg"] = "none" }},
		{"untrusted URL", func(_, h, _ map[string]any) { h["jku"] = "https://evil.example.test/jwks" }},
		{"embedded key", func(_, h, j map[string]any) { h["jwk"] = j }},
		{"critical extension", func(_, h, _ map[string]any) { h["crit"] = []string{"custom"} }},
		{"unencoded payload", func(_, h, _ map[string]any) { h["b64"] = false }},
		{"access token type", func(_, h, _ map[string]any) { h["typ"] = "at+jwt" }},
		{"wrong key algorithm", func(_, _, j map[string]any) { j["alg"] = "PS256" }},
		{"encryption key", func(_, _, j map[string]any) { j["use"] = "enc" }},
		{"wrong key operations", func(_, _, j map[string]any) { j["key_ops"] = []string{"sign"} }},
		{"private key material", func(_, _, j map[string]any) { j["d"] = "AQAB" }},
		{"weak RSA modulus", func(_, _, j map[string]any) { j["n"] = "AQAB" }},
		{"noncanonical modulus", func(_, _, j map[string]any) { j["n"] = "AA" + j["n"].(string) }},
		{"even exponent", func(_, _, j map[string]any) { j["e"] = "Ag" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			claims, header := tokenClaims(t), map[string]any{"alg": "RS256", "kid": "signing-1", "typ": "JWT"}
			candidate := make(map[string]any, len(jwk))
			for name, value := range jwk {
				candidate[name] = value
			}
			test.change(claims, header, candidate)
			authenticator := tokenAuthenticator(t, "RS256")
			calls := 0
			authenticator.client = doerFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return discoveryResponse(200, "application/json", tokenJSON(t, map[string]any{"keys": []any{candidate}})), nil
			})
			result, err := authenticator.validateIDToken(t.Context(), signedToken(t, key, "RS256", claims, header))
			if !errors.Is(err, ErrTokenRejected) || result.IsValid() || calls > 1 {
				t.Fatalf("substitution accepted/retried: %v; reads=%d", err, calls)
			}
		})
	}
}

func TestIDTokenRequiresExactBrokerConnector(t *testing.T) {
	t.Parallel()

	key, jwk := tokenKey(t, "RS256")
	tests := []struct {
		name      string
		federated any
		accepted  bool
	}{
		{name: "exact connector", federated: map[string]any{
			"connector_id": "google-v1", "user_id": "opaque-upstream-subject",
		}, accepted: true},
		{name: "missing claim"},
		{name: "wrong connector", federated: map[string]any{
			"connector_id": "enterprise-v1", "user_id": "opaque-upstream-subject",
		}},
		{name: "missing connector", federated: map[string]any{
			"user_id": "opaque-upstream-subject",
		}},
		{name: "malformed connector", federated: map[string]any{
			"connector_id": []string{"google-v1"}, "user_id": "opaque-upstream-subject",
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			authenticator := tokenAuthenticator(t, "RS256")
			params := loginRouteParams(authenticator.route)
			params.ConnectorID = "google-v1"
			params.Scopes = append(params.Scopes, "federated:id")
			var err error
			authenticator.route, err = oidcauth.NewRoute(params)
			if err != nil {
				t.Fatal(err)
			}
			authenticator.client = doerFunc(func(*http.Request) (*http.Response, error) {
				return discoveryResponse(200, "application/json", tokenJSON(t, map[string]any{
					"keys": []any{jwk},
				})), nil
			})
			claims := tokenClaims(t)
			if test.federated != nil {
				claims["federated_claims"] = test.federated
			}
			result, err := authenticator.validateIDToken(
				t.Context(), signedToken(t, key, "RS256", claims, nil),
			)
			if result.IsValid() != test.accepted || (err == nil) != test.accepted {
				t.Fatalf("connector result = (%t, %v), want accepted=%t", result.IsValid(), err, test.accepted)
			}
		})
	}
}

func TestUnknownKidRefreshIsBoundedAndRotationDoesNotChangeRoute(t *testing.T) {
	t.Parallel()
	key, jwk := tokenKey(t, "RS256")
	for _, found := range []bool{false, true} {
		t.Run(fmt.Sprint(found), func(t *testing.T) {
			t.Parallel()
			authenticator := tokenAuthenticator(t, "RS256")
			original := authenticator.route
			calls := 0
			authenticator.client = doerFunc(func(*http.Request) (*http.Response, error) {
				calls++
				keys := []any{}
				if calls == 2 && found {
					keys = append(keys, jwk)
				}
				return discoveryResponse(200, "application/json", tokenJSON(t, map[string]any{"keys": keys})), nil
			})
			result, err := authenticator.validateIDToken(t.Context(), signedToken(t, key, "RS256", tokenClaims(t), nil))
			if result.IsValid() != found || (err == nil) != found || calls != 2 || !sameTokenRoute(original, authenticator.route) {
				t.Fatalf("rotation invariant failed: %v; reads=%d", err, calls)
			}
		})
	}
}

func TestIDTokenRejectsForgedSignaturesAndAmbiguousKeys(t *testing.T) {
	t.Parallel()
	for _, algorithm := range []string{"RS256", "PS256", "ES256"} {
		t.Run(algorithm, func(t *testing.T) {
			t.Parallel()
			key, jwk := tokenKey(t, algorithm)
			token := signedToken(t, key, algorithm, tokenClaims(t), nil)
			parts := strings.Split(token, ".")
			signature, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil {
				t.Fatal(err)
			}
			signature[0] ^= 1
			forged := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(signature)
			for _, duplicate := range []bool{false, true} {
				authenticator := tokenAuthenticator(t, algorithm)
				authenticator.client = doerFunc(func(*http.Request) (*http.Response, error) {
					keys := []any{jwk}
					if duplicate {
						keys = append(keys, jwk)
					}
					return discoveryResponse(200, "application/json", tokenJSON(t, map[string]any{"keys": keys})), nil
				})
				input := forged
				if duplicate {
					input = token
				}
				if result, err := authenticator.validateIDToken(t.Context(), input); err == nil || result.IsValid() {
					t.Fatal("forgery/ambiguous kid accepted")
				}
			}
		})
	}
}

func TestTokenJSONRejectsAmbiguityAndAcceptsPairedUnicode(t *testing.T) {
	t.Parallel()
	for _, input := range []string{`{"iss":"a","\u0069ss":"b"}`, `{"other":{"a":1,"a":2}}`, `{"sub":"\ud800"}`, `{"sub":"\udc00"}`, `{"sub":"\ud800x"}`, `{} {}`, `[]`, `null`, strings.Repeat("[", 18) + "0" + strings.Repeat("]", 18)} {
		if _, err := tokenObject([]byte(input), 64); err == nil {
			t.Fatal("ambiguous JSON accepted")
		}
	}
	for _, input := range []string{`{"sub":"\ud83d\ude00"}`, `{"sub":"literal �"}`, `{"sub":"escaped \\ud800"}`} {
		if _, err := tokenObject([]byte(input), 64); err != nil {
			t.Fatal("valid Unicode JSON rejected")
		}
	}
}

func FuzzCompactIDToken(f *testing.F) {
	f.Add("e30.e30.AAAA")
	f.Add("not-a-token")
	f.Fuzz(func(t *testing.T, input string) {
		if _, err := parseCompactIDToken(input, []string{"RS256", "PS256", "ES256"}); err != nil && !errors.Is(err, ErrTokenRejected) {
			t.Fatal("unsafe parser error")
		}
	})
}

func FuzzTokenObject(f *testing.F) {
	f.Add([]byte(`{"sub":"opaque","aud":["client"]}`))
	f.Add([]byte(`{"sub":"\ud800"}`))
	f.Fuzz(func(_ *testing.T, input []byte) { _, _ = tokenObject(input, 64) })
}

func TestCompactProfileRejectsMalformedAndOversizedInput(t *testing.T) {
	t.Parallel()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"signing-1"}`))
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"opaque"}`))
	for _, input := range []string{
		header + "." + claims + ".AA=", header + "." + claims + ".AB", header + "." + claims + ".AA\n", header + "..AA", header + "." + claims + ".AA.more",
		base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","alg":"PS256","kid":"signing-1"}`)) + "." + claims + ".AA",
		base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"signing-1","typ":""}`)) + "." + claims + ".AA",
		header + "." + base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 16*1024+1))) + ".AA", strings.Repeat("x", 32*1024+1),
	} {
		if _, err := parseCompactIDToken(input, []string{"RS256"}); err == nil {
			t.Fatal("unsafe compact profile accepted")
		}
	}
}

func TestJWKSRejectsMalformedSetsAndInvalidECPoints(t *testing.T) {
	t.Parallel()
	_, jwk := tokenKey(t, "ES256")
	for _, name := range []string{"off curve", "wrong curve", "short coordinate", "duplicate kid", "missing keys", "null keys", "oversize keys"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := make(map[string]any, len(jwk))
			for name, value := range jwk {
				candidate[name] = value
			}
			object := map[string]any{"keys": []any{candidate}}
			switch name {
			case "off curve":
				candidate["x"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
				candidate["y"] = candidate["x"]
			case "wrong curve":
				candidate["crv"] = "P-384"
			case "short coordinate":
				candidate["x"] = "AA"
			case "duplicate kid":
				object["keys"] = []any{candidate, candidate}
			case "missing keys":
				delete(object, "keys")
			case "null keys":
				object["keys"] = nil
			case "oversize keys":
				keys := make([]any, 65)
				for i := range keys {
					keys[i] = candidate
				}
				object["keys"] = keys
			}
			if _, _, err := signingJWK([]byte(tokenJSON(t, object)), "signing-1", "ES256"); err == nil {
				t.Fatal("invalid JWKS accepted")
			}
		})
	}
}

func TestPS256RejectsNonstandardSaltLength(t *testing.T) {
	t.Parallel()
	key, jwk := tokenKey(t, "PS256")
	token := signedToken(t, key, "PS256", tokenClaims(t), nil)
	parts := strings.Split(token, ".")
	input := parts[0] + "." + parts[1]
	hash := sha256.Sum256([]byte(input))
	signature, err := key.Sign(rand.Reader, hash[:], &rsa.PSSOptions{SaltLength: 20, Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	authenticator := tokenAuthenticator(t, "PS256")
	authenticator.client = doerFunc(func(*http.Request) (*http.Response, error) {
		return discoveryResponse(200, "application/json", tokenJSON(t, map[string]any{"keys": []any{jwk}})), nil
	})
	if evidence, err := authenticator.validateIDToken(t.Context(), input+"."+base64.RawURLEncoding.EncodeToString(signature)); err == nil || evidence.IsValid() {
		t.Fatal("non-JWA PSS salt accepted")
	}
}

func FuzzSigningJWK(f *testing.F) {
	f.Add([]byte(`{"keys":[]}`), "signing-1", "RS256")
	f.Fuzz(func(_ *testing.T, input []byte, kid, algorithm string) { _, _, _ = signingJWK(input, kid, algorithm) })
}

func tokenNow() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }

type tokenClock struct{ now func() time.Time }

func (clock tokenClock) Now() time.Time { return clock.now() }

func tokenAuthenticator(t *testing.T, algorithm string) *Authenticator {
	t.Helper()
	route := tokenRoute(t, discoveryRoute(t), algorithm, "", "")
	secret, err := NewBasicSecret(strings.Repeat("synthetic-", 4))
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := NewAuthenticator(TokenOptions{Timeout: time.Second, MaxTokenAge: 10 * time.Minute, ClockSkew: time.Minute, Clock: tokenClock{now: tokenNow}}, route, secret)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authenticator.Close)
	return authenticator
}

func tokenRoute(t *testing.T, original oidcauth.Route, algorithm, endpoint, jwksURI string) oidcauth.Route {
	t.Helper()
	if endpoint == "" {
		endpoint = original.TokenEndpoint()
	}
	if jwksURI == "" {
		jwksURI = original.JWKSURI()
	}
	route, err := oidcauth.NewRoute(oidcauth.RouteParams{
		DeploymentID: original.DeploymentID(), WorkspaceID: original.WorkspaceID(), ProviderID: original.ProviderID(), ClientID: original.ClientID(),
		ProviderGeneration: original.ProviderGeneration(), RecoveryEpoch: original.RecoveryEpoch(), Issuer: original.Issuer(), DiscoveryURI: original.DiscoveryURI(),
		AuthorizationEndpoint: original.AuthorizationEndpoint(), TokenEndpoint: endpoint, JWKSURI: jwksURI, OIDCClientID: original.OIDCClientID(),
		ConnectorID: original.ConnectorID(),
		ClientKind:  "confidential", ClientAuthMethod: original.ClientAuthMethod(), Scopes: original.Scopes(), AllowedAlgorithms: []string{algorithm},
		RedirectID: original.RedirectID(), RedirectURI: original.RedirectURI(), ReturnRouteID: original.ReturnRouteID(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return route
}

func tokenClaims(t *testing.T) map[string]any {
	t.Helper()
	nonce, err := oidcauth.ParseNonce(base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("n", 32))))
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"iss": discoveryRoute(t).Issuer(), "sub": "Case-Sensitive-Subject", "aud": discoveryRoute(t).OIDCClientID(), "nonce": nonce.Encoded(), "iat": tokenNow().Unix(), "exp": tokenNow().Add(5 * time.Minute).Unix()}
}

func tokenKey(t *testing.T, algorithm string) (crypto.Signer, map[string]any) {
	t.Helper()
	jwk := map[string]any{"kid": "signing-1", "alg": algorithm, "use": "sig", "key_ops": []string{"verify"}}
	if algorithm == "ES256" {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		jwk["kty"], jwk["crv"] = "EC", "P-256"
		point, err := key.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		jwk["x"] = base64.RawURLEncoding.EncodeToString(point[1:33])
		jwk["y"] = base64.RawURLEncoding.EncodeToString(point[33:])
		return key, jwk
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk["kty"] = "RSA"
	jwk["n"] = base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	jwk["e"] = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	return key, jwk
}

func signedToken(t *testing.T, key crypto.Signer, algorithm string, claims, header map[string]any) string {
	t.Helper()
	if header == nil {
		header = map[string]any{"alg": algorithm, "kid": "signing-1", "typ": "JWT"}
	}
	input := base64.RawURLEncoding.EncodeToString([]byte(tokenJSON(t, header))) + "." + base64.RawURLEncoding.EncodeToString([]byte(tokenJSON(t, claims)))
	hash := sha256.Sum256([]byte(input))
	var signature []byte
	var err error
	if ec, ok := key.(*ecdsa.PrivateKey); ok {
		r, s, signErr := ecdsa.Sign(rand.Reader, ec, hash[:])
		if signErr != nil {
			t.Fatal(signErr)
		}
		signature = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	} else {
		var options crypto.SignerOpts = crypto.SHA256
		if algorithm == "PS256" {
			options = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
		}
		signature, err = key.Sign(rand.Reader, hash[:], options)
		if err != nil {
			t.Fatal(err)
		}
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func tokenJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

var _ oidcauth.StartClock = tokenClock{}
