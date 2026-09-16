package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

const maximumIDTokenBytes = 32 * 1024

type compactIDToken struct {
	algorithm, kid, input string
	claims, signature     []byte
}

func parseCompactIDToken(token string, algorithms []string) (compactIDToken, error) {
	if len(token) == 0 || len(token) > maximumIDTokenBytes {
		return compactIDToken{}, ErrTokenRejected
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return compactIDToken{}, ErrTokenRejected
	}
	headerBytes, ok := tokenBase64(parts[0], 1024)
	if !ok {
		return compactIDToken{}, ErrTokenRejected
	}
	defer clear(headerBytes)
	header, err := tokenObject(headerBytes, 3)
	if err != nil {
		return compactIDToken{}, ErrTokenRejected
	}
	for name := range header {
		if name != "alg" && name != "kid" && name != "typ" {
			return compactIDToken{}, ErrTokenRejected
		}
	}
	var algorithm, kid, kind string
	if !tokenRequired(header, "alg", &algorithm) || !slices.Contains(algorithms, algorithm) ||
		!tokenRequired(header, "kid", &kid) || !validTokenASCII(kid, 255) ||
		!tokenOptional(header, "typ", &kind) || kind != "" && kind != "JWT" {
		return compactIDToken{}, ErrTokenRejected
	}
	if _, present := header["typ"]; present && kind != "JWT" {
		return compactIDToken{}, ErrTokenRejected
	}
	claims, ok := tokenBase64(parts[1], 16*1024)
	if !ok {
		return compactIDToken{}, ErrTokenRejected
	}
	signature, ok := tokenBase64(parts[2], 1024)
	if !ok {
		clear(claims)
		return compactIDToken{}, ErrTokenRejected
	}
	return compactIDToken{algorithm: algorithm, kid: kid, input: parts[0] + "." + parts[1], claims: claims, signature: signature}, nil
}

func tokenBase64(value string, maximum int) ([]byte, bool) {
	if len(value) == 0 || len(value) > base64.RawURLEncoding.EncodedLen(maximum) {
		return nil, false
	}
	for _, character := range value {
		alphaUpper := character >= 'A' && character <= 'Z'
		alphaLower := character >= 'a' && character <= 'z'
		digit := character >= '0' && character <= '9'
		if !alphaUpper && !alphaLower && !digit && character != '-' && character != '_' {
			return nil, false
		}
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) > maximum {
		clear(decoded)
		return nil, false
	}
	return decoded, true
}

func (authenticator *Authenticator) validateIDToken(ctx context.Context, raw string) (oidcauth.TokenEvidence, error) {
	token, err := parseCompactIDToken(raw, authenticator.route.AllowedAlgorithms())
	if err != nil {
		return oidcauth.TokenEvidence{}, err
	}
	defer clear(token.claims)
	defer clear(token.signature)
	if err := authenticator.verifyIDTokenSignature(ctx, token); err != nil {
		return oidcauth.TokenEvidence{}, err
	}
	if ctx.Err() != nil {
		return oidcauth.TokenEvidence{}, errorsWithTokenContext(ctx)
	}
	return authenticator.decodeIDTokenClaims(token.claims)
}

func (authenticator *Authenticator) decodeIDTokenClaims(raw []byte) (oidcauth.TokenEvidence, error) {
	claims, err := tokenObject(raw, 64)
	if err != nil {
		return oidcauth.TokenEvidence{}, ErrTokenRejected
	}
	var params oidcauth.TokenEvidenceParams
	var nonce, authorizedParty string
	if !tokenRequired(claims, "iss", &params.Issuer) || params.Issuer != authenticator.route.Issuer() ||
		!tokenRequired(claims, "sub", &params.Subject) || !tokenAudience(claims, authenticator.route.OIDCClientID()) ||
		!tokenOptional(claims, "azp", &authorizedParty) || authorizedParty != "" && authorizedParty != authenticator.route.OIDCClientID() ||
		!tokenRequired(claims, "nonce", &nonce) || !tokenOptional(claims, "sid", &params.SessionID) ||
		!tokenOptional(claims, "acr", &params.ACR) || !tokenOptional(claims, "amr", &params.AMR) {
		return oidcauth.TokenEvidence{}, ErrTokenRejected
	}
	if _, present := claims["azp"]; present && authorizedParty != authenticator.route.OIDCClientID() {
		return oidcauth.TokenEvidence{}, ErrTokenRejected
	}
	params.Nonce, err = oidcauth.ParseNonce(nonce)
	if err != nil {
		return oidcauth.TokenEvidence{}, ErrTokenRejected
	}
	params.IssuedAt, err = tokenDate(claims, "iat")
	if err != nil {
		return oidcauth.TokenEvidence{}, err
	}
	params.ExpiresAt, err = tokenDate(claims, "exp")
	if err != nil {
		return oidcauth.TokenEvidence{}, err
	}
	now, skew := authenticator.options.Clock.Now(), authenticator.options.ClockSkew
	if !now.Before(params.ExpiresAt) || params.IssuedAt.After(now.Add(skew)) ||
		now.Sub(params.IssuedAt) > authenticator.options.MaxTokenAge || !params.ExpiresAt.After(params.IssuedAt) ||
		params.ExpiresAt.Sub(params.IssuedAt) > 24*time.Hour {
		return oidcauth.TokenEvidence{}, ErrTokenRejected
	}
	if _, present := claims["nbf"]; present {
		notBefore, err := tokenDate(claims, "nbf")
		if err != nil || notBefore.After(now.Add(skew)) || !notBefore.Before(params.ExpiresAt) {
			return oidcauth.TokenEvidence{}, ErrTokenRejected
		}
	}
	if _, present := claims["auth_time"]; present {
		params.AuthTime, err = tokenDate(claims, "auth_time")
		if err != nil || params.AuthTime.After(now.Add(skew)) || params.AuthTime.After(params.IssuedAt) {
			return oidcauth.TokenEvidence{}, ErrTokenRejected
		}
	}
	evidence, err := oidcauth.NewTokenEvidence(params)
	if err != nil {
		return oidcauth.TokenEvidence{}, ErrTokenRejected
	}
	return evidence, nil
}

// No additional audience has been configured as trusted in this route profile.
func tokenAudience(claims map[string]json.RawMessage, expected string) bool {
	var audience string
	if tokenRequired(claims, "aud", &audience) {
		return audience == expected
	}
	var audiences []string
	return tokenRequired(claims, "aud", &audiences) && len(audiences) == 1 && audiences[0] == expected
}

func tokenDate(claims map[string]json.RawMessage, name string) (time.Time, error) {
	var seconds int64
	// Positive Unix seconds through year 9999: bound time arithmetic and reject
	// floats, strings, exponent notation, null, and int64 overflow.
	if !tokenRequired(claims, name, &seconds) || seconds <= 0 || seconds > 253402300799 {
		return time.Time{}, ErrTokenRejected
	}
	return time.Unix(seconds, 0).UTC(), nil
}
