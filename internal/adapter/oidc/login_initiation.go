package oidc

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

const (
	// LoginInitiationCookieName identifies browser intent, never authentication.
	LoginInitiationCookieName = "__Host-mt_login_init"
	// LoginCSRFHeader carries a proof bound to the private pre-session cookie.
	LoginCSRFHeader      = "X-Meshtransit-Csrf"
	initiationPurpose    = "meshtransit/oidc-auth/login-initiation/v1\x00"
	initiationFixedBytes = 2 + 8 + 8 + 32 + sha256.Size
)

// ErrLoginInitiation rejects unsafe config, malformed, mismatched, or expired intent.
// It contains no key, cookie, proof, route, or input-derived text.
var ErrLoginInitiation = errors.New("oidc: invalid login initiation")

// LoginInitiationOptions fixes one trusted origin/route and a separate resident key.
// KeyMaterial must not be reused for transaction, session, or rate-limit purposes.
type LoginInitiationOptions struct {
	Origin      string
	Route       oidcauth.Route
	KeyID       string
	KeyMaterial []byte
	Lifetime    time.Duration
}

// LoginInitiationGuard verifies stateless pre-session intent across BFF replicas.
// It owns no authority, request context, mutable keyring, or per-browser state.
type LoginInitiationGuard struct {
	origin   string
	route    oidcauth.Route
	keyID    string
	key      [32]byte
	binding  [sha256.Size]byte
	lifetime time.Duration
}

// NewLoginInitiationGuard rejects unsafe configuration without external effects.
// Replacing its exact key generation invalidates old proofs; prepare must restart.
func NewLoginInitiationGuard(options LoginInitiationOptions) (*LoginInitiationGuard, error) {
	_, keyErr := oidcauth.NewDigestKeyID(options.KeyID)
	if !validLoginOrigin(options.Origin) || !options.Route.IsValid() || keyErr != nil ||
		len(options.KeyMaterial) != 32 || options.Lifetime < time.Minute ||
		options.Lifetime > 5*time.Minute || options.Lifetime%time.Second != 0 {
		return nil, ErrLoginInitiation
	}
	publicBinding, err := json.Marshal(struct {
		Origin string               `json:"origin"`
		Route  oidcauth.RouteParams `json:"route"`
	}{Origin: options.Origin, Route: loginRouteParams(options.Route)})
	if err != nil {
		return nil, ErrLoginInitiation
	}
	guard := &LoginInitiationGuard{origin: options.Origin, route: options.Route,
		keyID: options.KeyID, binding: sha256.Sum256(publicBinding), lifetime: options.Lifetime}
	copy(guard.key[:], options.KeyMaterial)
	if guard.key == ([32]byte{}) {
		return nil, ErrLoginInitiation
	}
	return guard, nil
}

// Origin returns the exact configured HTTPS origin, never a forwarding header.
func (guard *LoginInitiationGuard) Origin() string { return guard.origin }

// Route returns the immutable Core-selected trust decision.
func (guard *LoginInitiationGuard) Route() oidcauth.Route { return guard.route }

// IsValid reports initialized, bounded resident verification state.
func (guard *LoginInitiationGuard) IsValid() bool {
	return guard != nil && guard.key != ([32]byte{}) && guard.binding != ([32]byte{}) &&
		guard.lifetime >= time.Minute && guard.lifetime <= 5*time.Minute
}

// Prepare issues fresh independent cookie and proof entropy from the OS CSPRNG.
// The HTTP caller must validate origin, bounds, rate limits, and route admission first.
func (guard *LoginInitiationGuard) Prepare(now time.Time) (LoginInitiation, error) {
	return guard.prepare(now, rand.Reader)
}

func (guard *LoginInitiationGuard) prepare(now time.Time, entropy io.Reader) (LoginInitiation, error) {
	if !guard.IsValid() || now.IsZero() || now.Unix() <= 0 || now.Year() > 9998 || entropy == nil {
		return LoginInitiation{}, ErrLoginInitiation
	}
	var material [64]byte
	if _, err := io.ReadFull(entropy, material[:]); err != nil {
		return LoginInitiation{}, ErrLoginInitiation
	}
	defer clear(material[:])
	var cookie, randomValue [32]byte
	copy(cookie[:], material[:32])
	copy(randomValue[:], material[32:])
	if cookie == ([32]byte{}) || randomValue == ([32]byte{}) ||
		subtle.ConstantTimeCompare(cookie[:], randomValue[:]) == 1 {
		return LoginInitiation{}, ErrLoginInitiation
	}
	keyLength := len(guard.keyID)
	if keyLength < 1 || keyLength > 128 {
		return LoginInitiation{}, ErrLoginInitiation
	}
	issued := now.UTC().Truncate(time.Second)
	expires := issued.Add(guard.lifetime)
	issuedSeconds, expiresSeconds := issued.Unix(), expires.Unix()
	if issuedSeconds <= 0 || expiresSeconds <= 0 {
		return LoginInitiation{}, ErrLoginInitiation
	}
	payload := make([]byte, initiationFixedBytes+keyLength)
	payload[0], payload[1] = 1, byte(keyLength)
	copy(payload[2:], guard.keyID)
	offset := 2 + keyLength
	binary.BigEndian.PutUint64(payload[offset:], uint64(issuedSeconds))
	binary.BigEndian.PutUint64(payload[offset+8:], uint64(expiresSeconds))
	copy(payload[offset+16:], randomValue[:])
	copy(payload[len(payload)-sha256.Size:], guard.mac(cookie, payload[:len(payload)-sha256.Size]))
	return LoginInitiation{cookie: cookie, payload: payload, issuedAt: issued, expiresAt: expires}, nil
}

// Verify checks the custom-header proof against exactly one canonical private cookie.
// It does not replace the HTTP caller's mandatory exact Origin and TLS checks.
// No decoded or input-derived failure is returned, and no authority is mutated.
func (guard *LoginInitiationGuard) Verify(headers http.Header, now time.Time) error {
	if !guard.IsValid() || now.IsZero() || now.Unix() <= 0 {
		return ErrLoginInitiation
	}
	values := headers.Values(LoginCSRFHeader)
	expectedSize := initiationFixedBytes + len(guard.keyID)
	if len(values) != 1 || len(values[0]) != base64.RawURLEncoding.EncodedLen(expectedSize) {
		return ErrLoginInitiation
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(values[0])
	if err != nil || len(payload) != expectedSize || payload[0] != 1 ||
		int(payload[1]) != len(guard.keyID) || string(payload[2:2+len(guard.keyID)]) != guard.keyID {
		return ErrLoginInitiation
	}
	cookieValue, err := boundedCookieValue(headers, LoginInitiationCookieName)
	if err != nil || len(cookieValue) != 43 {
		return ErrLoginInitiation
	}
	decodedCookie, err := base64.RawURLEncoding.Strict().DecodeString(cookieValue)
	if err != nil || len(decodedCookie) != 32 {
		return ErrLoginInitiation
	}
	var cookie, randomValue [32]byte
	copy(cookie[:], decodedCookie)
	defer clear(decodedCookie)
	offset := 2 + len(guard.keyID)
	issued, expires := binary.BigEndian.Uint64(payload[offset:]), binary.BigEndian.Uint64(payload[offset+8:])
	lifetimeSeconds := int64(guard.lifetime / time.Second)
	if lifetimeSeconds <= 0 || lifetimeSeconds > 300 {
		return ErrLoginInitiation
	}
	if issued > math.MaxInt64 || expires > math.MaxInt64 || expires <= issued ||
		expires-issued != uint64(lifetimeSeconds) {
		return ErrLoginInitiation
	}
	if now.Unix() < int64(issued) || now.Unix() >= int64(expires) {
		return ErrLoginInitiation
	}
	copy(randomValue[:], payload[offset+16:offset+48])
	if cookie == ([32]byte{}) || randomValue == ([32]byte{}) ||
		subtle.ConstantTimeCompare(cookie[:], randomValue[:]) == 1 {
		return ErrLoginInitiation
	}
	prefix := payload[:len(payload)-sha256.Size]
	if !hmac.Equal(guard.mac(cookie, prefix), payload[len(prefix):]) {
		return ErrLoginInitiation
	}
	return nil
}

func (guard *LoginInitiationGuard) mac(cookie [32]byte, payload []byte) []byte {
	mac := hmac.New(sha256.New, guard.key[:])
	_, _ = mac.Write([]byte(initiationPurpose))
	_, _ = mac.Write(guard.binding[:])
	_, _ = mac.Write(cookie[:])
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

// String prevents accidental key disclosure.
func (*LoginInitiationGuard) String() string { return "[REDACTED]" }

// GoString prevents detailed key disclosure.
func (*LoginInitiationGuard) GoString() string { return "oidc.LoginInitiationGuard([REDACTED])" }

// LogValue prevents structured-log key disclosure.
func (*LoginInitiationGuard) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// LoginInitiation contains pre-session secrets, never Account Session evidence.
type LoginInitiation struct {
	cookie    [32]byte
	payload   []byte
	issuedAt  time.Time
	expiresAt time.Time
}

// Proof explicitly releases a secret only into a same-origin no-store response.
func (result LoginInitiation) Proof() string {
	return base64.RawURLEncoding.EncodeToString(result.payload)
}

// ResponseCookie releases the private handle with host-only Strict attributes.
// Its expiry cannot outlive the authenticated proof. Never log http.Cookie.
func (result LoginInitiation) ResponseCookie(now time.Time) (*http.Cookie, error) {
	if result.cookie == ([32]byte{}) || len(result.payload) < initiationFixedBytes+1 || now.IsZero() ||
		now.Before(result.issuedAt) || !now.Before(result.expiresAt) {
		return nil, ErrLoginInitiation
	}
	remaining := result.expiresAt.Sub(now.UTC()) / time.Second
	if remaining < 1 || remaining > 300 {
		return nil, ErrLoginInitiation
	}
	return &http.Cookie{Name: LoginInitiationCookieName,
		Value: base64.RawURLEncoding.EncodeToString(result.cookie[:]), Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Expires: result.expiresAt, MaxAge: int(remaining)}, nil
}

// ExpiredLoginInitiationCookie clears the pre-session scope, not durable authority.
func ExpiredLoginInitiationCookie() *http.Cookie {
	return &http.Cookie{Name: LoginInitiationCookieName, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Expires: time.Unix(1, 0).UTC(), MaxAge: -1}
}

// String prevents accidental intent disclosure.
func (LoginInitiation) String() string { return "[REDACTED]" }

// GoString prevents detailed intent disclosure.
func (LoginInitiation) GoString() string { return "oidc.LoginInitiation([REDACTED])" }

// LogValue prevents structured-log intent disclosure.
func (LoginInitiation) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

func validLoginOrigin(origin string) bool {
	if len(origin) == 0 || len(origin) > 255 || strings.ContainsAny(origin, "\\ \t\r\n") {
		return false
	}
	for _, character := range origin {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.String() != origin || !validLoginHostname(parsed.Hostname()) {
		return false
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 || strconv.Itoa(value) != port {
			return false
		}
	} else if strings.HasSuffix(parsed.Host, ":") {
		return false
	}
	return parsed.Scheme == "https" && parsed.User == nil &&
		parsed.Host == strings.ToLower(parsed.Host) && parsed.Path == "" && parsed.RawPath == "" &&
		parsed.RawQuery == "" && !parsed.ForceQuery && parsed.Fragment == "" && parsed.Opaque == ""
}

func validLoginHostname(hostname string) bool {
	if address, err := netip.ParseAddr(hostname); err == nil {
		return address.Zone() == ""
	}
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}
	for label := range strings.SplitSeq(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func loginRouteParams(route oidcauth.Route) oidcauth.RouteParams {
	return oidcauth.RouteParams{DeploymentID: route.DeploymentID(), WorkspaceID: route.WorkspaceID(),
		ProviderID: route.ProviderID(), ClientID: route.ClientID(), ProviderGeneration: route.ProviderGeneration(),
		RecoveryEpoch: route.RecoveryEpoch(), Issuer: route.Issuer(), DiscoveryURI: route.DiscoveryURI(),
		AuthorizationEndpoint: route.AuthorizationEndpoint(), TokenEndpoint: route.TokenEndpoint(), JWKSURI: route.JWKSURI(),
		OIDCClientID: route.OIDCClientID(), ClientKind: "confidential", ClientAuthMethod: route.ClientAuthMethod(),
		Scopes: route.Scopes(), AllowedAlgorithms: route.AllowedAlgorithms(), RedirectID: route.RedirectID(),
		RedirectURI: route.RedirectURI(), ReturnRouteID: route.ReturnRouteID()}
}
