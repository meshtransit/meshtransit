package oidc

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

const (
	continuationPurpose    = "meshtransit/oidc-auth/login-continuation-csrf/v1\x00"
	continuationFixedBytes = 2 + 16 + 32 + sha256.Size
)

// ErrLoginContinuation conceals invalid config, cookies, proof, entropy or time.
// Neither this error nor its chain contains browser or dependency material.
var ErrLoginContinuation = errors.New("oidc: invalid login continuation proof")

// LoginContinuationOptions fixes one origin/route and a separate resident HMAC key.
// KeyMaterial must not be reused for initiation, capsule, transaction or Session keys.
type LoginContinuationOptions struct {
	Origin      string
	Route       oidcauth.Route
	KeyID       string
	KeyMaterial []byte
	Lifetime    time.Duration
}

// LoginContinuationGuard owns stateless browser intent, never authentication authority.
// Current private pre-auth/capture cookies bind each proof; it creates no new cookie.
type LoginContinuationGuard struct {
	origin   string
	route    oidcauth.Route
	keyID    string
	key      [32]byte
	binding  [sha256.Size]byte
	lifetime time.Duration
}

// NewLoginContinuationGuard validates without I/O or runtime registration.
// Exact key replacement invalidates old proof; no previous-key fallback exists.
func NewLoginContinuationGuard(options LoginContinuationOptions) (*LoginContinuationGuard, error) {
	_, keyErr := oidcauth.NewDigestKeyID(options.KeyID)
	validLifetime := options.Lifetime >= 30*time.Second && options.Lifetime <= 120*time.Second
	if !validLoginOrigin(options.Origin) || !options.Route.IsValid() || keyErr != nil {
		return nil, ErrLoginContinuation
	}
	if len(options.KeyMaterial) != 32 || !validLifetime || options.Lifetime%time.Second != 0 {
		return nil, ErrLoginContinuation
	}
	callback, err := url.Parse(options.Route.RedirectURI())
	if err != nil || callback.Scheme+"://"+callback.Host != options.Origin {
		return nil, ErrLoginContinuation
	}
	publicBinding, err := json.Marshal(struct {
		Origin string               `json:"origin"`
		Route  oidcauth.RouteParams `json:"route"`
	}{Origin: options.Origin, Route: loginRouteParams(options.Route)})
	if err != nil {
		return nil, ErrLoginContinuation
	}
	guard := &LoginContinuationGuard{origin: options.Origin, route: options.Route,
		keyID: options.KeyID, binding: sha256.Sum256(publicBinding), lifetime: options.Lifetime}
	copy(guard.key[:], options.KeyMaterial)
	if guard.key == ([32]byte{}) {
		return nil, ErrLoginContinuation
	}
	return guard, nil
}

// Origin returns only the exact configured HTTPS origin.
func (guard *LoginContinuationGuard) Origin() string { return guard.origin }

// Route returns the immutable Core-selected route, not request authority.
func (guard *LoginContinuationGuard) Route() oidcauth.Route { return guard.route }

// IsValid rejects zero/partial state and unsafe resident bounds.
func (guard *LoginContinuationGuard) IsValid() bool {
	if guard == nil || guard.key == ([32]byte{}) || guard.binding == ([sha256.Size]byte{}) {
		return false
	}
	_, err := oidcauth.NewDigestKeyID(guard.keyID)
	validLifetime := guard.lifetime >= 30*time.Second && guard.lifetime <= 120*time.Second
	return err == nil && guard.route.IsValid() && validLoginOrigin(guard.origin) &&
		validLifetime && guard.lifetime%time.Second == 0
}

// Prepare creates fresh proof entropy for current canonical cookie syntax only.
// The HTTP caller must authenticate capsule transport, TLS/Origin and shared budgets first.
func (guard *LoginContinuationGuard) Prepare(
	ctx context.Context,
	headers http.Header,
	now time.Time,
) (LoginContinuationProof, error) {
	return guard.prepare(
		ctx,
		headers,
		now,
		rand.Reader,
	)
}

func (guard *LoginContinuationGuard) prepare(
	ctx context.Context,
	headers http.Header,
	now time.Time,
	entropy io.Reader,
) (LoginContinuationProof, error) {
	if !guard.IsValid() || ctx == nil || entropy == nil || !validContinuationTime(now) {
		return LoginContinuationProof{}, ErrLoginContinuation
	}
	if ctx.Err() != nil {
		return LoginContinuationProof{}, ErrLoginContinuation
	}
	cookies, err := continuationCookies(headers)
	if err != nil {
		return LoginContinuationProof{}, ErrLoginContinuation
	}
	var randomValue [32]byte
	defer clear(randomValue[:])
	if _, err := io.ReadFull(entropy, randomValue[:]); err != nil {
		return LoginContinuationProof{}, ErrLoginContinuation
	}
	if randomValue == ([32]byte{}) || ctx.Err() != nil {
		return LoginContinuationProof{}, ErrLoginContinuation
	}
	keyLength := len(guard.keyID)
	if keyLength < 1 || keyLength > 128 {
		return LoginContinuationProof{}, ErrLoginContinuation
	}
	issued := now.UTC().Truncate(time.Second)
	expires := issued.Add(guard.lifetime)
	issuedSeconds, expiresSeconds := issued.Unix(), expires.Unix()
	if issuedSeconds <= 0 || expiresSeconds <= 0 || expires.Year() > 9998 {
		return LoginContinuationProof{}, ErrLoginContinuation
	}
	payload := make([]byte, continuationFixedBytes+keyLength)
	defer clear(payload)
	payload[0], payload[1] = 1, byte(keyLength)
	copy(payload[2:], guard.keyID)
	offset := 2 + keyLength
	binary.BigEndian.PutUint64(payload[offset:], uint64(issuedSeconds))
	binary.BigEndian.PutUint64(payload[offset+8:], uint64(expiresSeconds))
	copy(payload[offset+16:], randomValue[:])
	prefix := payload[:len(payload)-sha256.Size]
	copy(payload[len(prefix):], guard.mac(cookies, prefix))
	value := base64.RawURLEncoding.EncodeToString(payload)
	if ctx.Err() != nil {
		return LoginContinuationProof{}, ErrLoginContinuation
	}
	return LoginContinuationProof{value: value, issuedAt: issued, expiresAt: expires}, nil
}

// Verify checks canonical exact-key proof, cookies, strict lifetime and constant-time MAC.
// This neither validates HTTP origin nor verifies durable browser possession/claim.
func (guard *LoginContinuationGuard) Verify(headers http.Header, now time.Time) error {
	if !guard.IsValid() || !validContinuationTime(now) {
		return ErrLoginContinuation
	}
	cookies, err := continuationCookies(headers)
	if err != nil {
		return ErrLoginContinuation
	}
	values := headers.Values(LoginCSRFHeader)
	expectedBytes := continuationFixedBytes + len(guard.keyID)
	if len(values) != 1 || len(values[0]) != base64.RawURLEncoding.EncodedLen(expectedBytes) {
		return ErrLoginContinuation
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(values[0])
	if err != nil || len(payload) != expectedBytes ||
		base64.RawURLEncoding.EncodeToString(payload) != values[0] {
		return ErrLoginContinuation
	}
	defer clear(payload)
	if payload[0] != 1 || int(payload[1]) != len(guard.keyID) || string(payload[2:2+len(guard.keyID)]) != guard.keyID {
		return ErrLoginContinuation
	}
	offset := 2 + len(guard.keyID)
	issued := binary.BigEndian.Uint64(payload[offset:])
	expires := binary.BigEndian.Uint64(payload[offset+8:])
	if issued > math.MaxInt64 || expires > math.MaxInt64 || issued == 0 || expires <= issued {
		return ErrLoginContinuation
	}
	lifetimeSeconds := int64(guard.lifetime / time.Second)
	if lifetimeSeconds < 30 || lifetimeSeconds > 120 {
		return ErrLoginContinuation
	}
	if expires-issued != uint64(lifetimeSeconds) || now.Unix() < int64(issued) || now.Unix() >= int64(expires) {
		return ErrLoginContinuation
	}
	var randomValue [32]byte
	copy(randomValue[:], payload[offset+16:offset+48])
	defer clear(randomValue[:])
	if randomValue == ([32]byte{}) {
		return ErrLoginContinuation
	}
	prefix := payload[:len(payload)-sha256.Size]
	if !hmac.Equal(guard.mac(cookies, prefix), payload[len(prefix):]) {
		return ErrLoginContinuation
	}
	return nil
}

type continuationCookieBinding struct {
	preAuth     oidcauth.PreAuthCookie
	capsuleHash [sha256.Size]byte
}

func continuationCookies(headers http.Header) (continuationCookieBinding, error) {
	for name := range headers {
		relevant := strings.EqualFold(name, "Cookie") || strings.EqualFold(name, LoginCSRFHeader)
		if relevant && name != http.CanonicalHeaderKey(name) {
			return continuationCookieBinding{}, ErrLoginContinuation
		}
	}
	preAuth, err := ReadPreAuthCookie(headers)
	if err != nil {
		return continuationCookieBinding{}, ErrLoginContinuation
	}
	capsule, err := ReadLoginCallbackCookie(headers)
	if err != nil {
		return continuationCookieBinding{}, ErrLoginContinuation
	}
	return continuationCookieBinding{preAuth: preAuth, capsuleHash: sha256.Sum256([]byte(capsule))}, nil
}

func (guard *LoginContinuationGuard) mac(cookies continuationCookieBinding, payload []byte) []byte {
	mac := hmac.New(sha256.New, guard.key[:])
	_, _ = mac.Write([]byte(continuationPurpose))
	_, _ = mac.Write(guard.binding[:])
	_, _ = mac.Write([]byte(cookies.preAuth.Encoded()))
	_, _ = mac.Write(cookies.capsuleHash[:])
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func validContinuationTime(now time.Time) bool {
	return !now.IsZero() && now.Unix() > 0 && now.Year() <= 9998
}

// String prevents accidental resident key disclosure.
func (*LoginContinuationGuard) String() string { return "[REDACTED]" }

// GoString prevents detailed resident key disclosure.
func (*LoginContinuationGuard) GoString() string { return "oidc.LoginContinuationGuard([REDACTED])" }

// LogValue prevents structured-log key disclosure.
func (*LoginContinuationGuard) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// LoginContinuationProof is explicit pre-auth intent, not an Account Session credential.
type LoginContinuationProof struct {
	value     string
	issuedAt  time.Time
	expiresAt time.Time
}

// Token releases only live proof and bounded remaining seconds for no-store JSON.
// Never place it in URLs, logs, metrics, traces or persistent browser storage.
func (proof LoginContinuationProof) Token(now time.Time) (string, int, error) {
	if proof.value == "" || !validContinuationTime(now) || now.Before(proof.issuedAt) || !now.Before(proof.expiresAt) {
		return "", 0, ErrLoginContinuation
	}
	remaining := proof.expiresAt.Sub(now.UTC()) / time.Second
	if remaining < 1 || remaining > 120 {
		return "", 0, ErrLoginContinuation
	}
	return proof.value, int(remaining), nil
}

// String prevents implicit proof disclosure.
func (LoginContinuationProof) String() string { return "[REDACTED]" }

// GoString prevents detailed proof disclosure.
func (LoginContinuationProof) GoString() string { return "oidc.LoginContinuationProof([REDACTED])" }

// LogValue prevents structured-log proof disclosure.
func (LoginContinuationProof) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON refuses implicit proof serialization; use Token only at the protected boundary.
func (LoginContinuationProof) MarshalJSON() ([]byte, error) { return nil, ErrLoginContinuation }
