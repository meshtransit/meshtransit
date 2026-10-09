package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
)

func errorsWithTokenContext(ctx context.Context) error {
	return errors.Join(ErrTokenUnavailable, ctx.Err())
}

func (authenticator *Authenticator) verifyIDTokenSignature(ctx context.Context, token compactIDToken) error {
	for attempt := 0; attempt < 2; attempt++ {
		if ctx.Err() != nil {
			return errorsWithTokenContext(ctx)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, authenticator.route.JWKSURI(), nil)
		if err != nil {
			return ErrTokenRejected
		}
		request.Header.Set("Accept", "application/json")
		raw, err := authenticator.readJSON(ctx, request, 256*1024)
		if err != nil {
			return err
		}
		key, found, err := signingJWK(raw, token.kid, token.algorithm)
		clear(raw)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		if ctx.Err() != nil {
			return errorsWithTokenContext(ctx)
		}
		return verifyCompactSignature(token, key)
	}
	return ErrTokenRejected
}

func signingJWK(raw []byte, kid, algorithm string) (crypto.PublicKey, bool, error) {
	object, err := tokenObject(raw, 8)
	if err != nil {
		return nil, false, ErrTokenRejected
	}
	var keys []json.RawMessage
	if !tokenRequired(object, "keys", &keys) || len(keys) > 64 {
		return nil, false, ErrTokenRejected
	}
	seen := make(map[string]struct{}, len(keys))
	var candidate map[string]json.RawMessage
	for _, rawKey := range keys {
		key, err := tokenObject(rawKey, 32)
		var keyID string
		if err != nil || !tokenRequired(key, "kid", &keyID) || !validTokenASCII(keyID, 255) {
			return nil, false, ErrTokenRejected
		}
		if _, duplicate := seen[keyID]; duplicate {
			return nil, false, ErrTokenRejected
		}
		seen[keyID] = struct{}{}
		for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
			if _, present := key[private]; present {
				return nil, false, ErrTokenRejected
			}
		}
		if keyID == kid {
			candidate = key
		}
	}
	if candidate == nil {
		return nil, false, nil
	}
	var kind, keyAlgorithm, use string
	if !tokenRequired(candidate, "kty", &kind) || !tokenRequired(candidate, "alg", &keyAlgorithm) || keyAlgorithm != algorithm ||
		!tokenRequired(candidate, "use", &use) || use != "sig" {
		return nil, false, ErrTokenRejected
	}
	if _, present := candidate["key_ops"]; present {
		var operations []string
		if !tokenRequired(candidate, "key_ops", &operations) || len(operations) != 1 || operations[0] != "verify" {
			return nil, false, ErrTokenRejected
		}
	}
	switch {
	case kind == "RSA" && (algorithm == "RS256" || algorithm == "PS256"):
		key, err := rsaSigningJWK(candidate)
		return key, err == nil, err
	case kind == "EC" && algorithm == "ES256":
		key, err := ecSigningJWK(candidate)
		return key, err == nil, err
	default:
		return nil, false, ErrTokenRejected
	}
}

func jwkBytes(key map[string]json.RawMessage, name string, maximum int) ([]byte, bool) {
	var value string
	if !tokenRequired(key, name, &value) {
		return nil, false
	}
	return tokenBase64(value, maximum)
}

func rsaSigningJWK(key map[string]json.RawMessage) (*rsa.PublicKey, error) {
	n, validN := jwkBytes(key, "n", 1024)
	e, validE := jwkBytes(key, "e", 4)
	if !validN || !validE || len(n) < 256 || n[0] == 0 || e[0] == 0 {
		return nil, ErrTokenRejected
	}
	modulus, exponent := new(big.Int).SetBytes(n), new(big.Int).SetBytes(e)
	if modulus.BitLen() < 2048 || modulus.BitLen() > 8192 || modulus.Bit(0) == 0 || !exponent.IsInt64() {
		return nil, ErrTokenRejected
	}
	exp := exponent.Int64()
	if exp < 3 || exp > 2147483647 || exp%2 == 0 {
		return nil, ErrTokenRejected
	}
	return &rsa.PublicKey{N: modulus, E: int(exp)}, nil
}

func ecSigningJWK(key map[string]json.RawMessage) (*ecdsa.PublicKey, error) {
	var curve string
	x, validX := jwkBytes(key, "x", 32)
	y, validY := jwkBytes(key, "y", 32)
	if !tokenRequired(key, "crv", &curve) || curve != "P-256" || !validX || !validY || len(x) != 32 || len(y) != 32 {
		return nil, ErrTokenRejected
	}
	point := append([]byte{4}, x...)
	point = append(point, y...)
	public, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, ErrTokenRejected
	}
	return public, nil
}

func verifyCompactSignature(token compactIDToken, key crypto.PublicKey) error {
	hash := sha256.Sum256([]byte(token.input))
	switch public := key.(type) {
	case *rsa.PublicKey:
		if len(token.signature) != public.Size() {
			return ErrTokenRejected
		}
		var err error
		switch token.algorithm {
		case "RS256":
			err = rsa.VerifyPKCS1v15(public, crypto.SHA256, hash[:], token.signature)
		case "PS256":
			err = rsa.VerifyPSS(public, crypto.SHA256, hash[:], token.signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
		default:
			return ErrTokenRejected
		}
		if err != nil {
			return ErrTokenRejected
		}
	case *ecdsa.PublicKey:
		if token.algorithm != "ES256" || len(token.signature) != 64 {
			return ErrTokenRejected
		}
		r, s := new(big.Int).SetBytes(token.signature[:32]), new(big.Int).SetBytes(token.signature[32:])
		if !ecdsa.Verify(public, hash[:], r, s) {
			return ErrTokenRejected
		}
	default:
		return ErrTokenRejected
	}
	return nil
}
