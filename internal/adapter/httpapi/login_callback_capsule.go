package httpapi

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
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
	"reflect"
	"time"

	"github.com/meshtransit/meshtransit/internal/adapter/oidc"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

const (
	// LoginCallbackContinuePath is a fixed clean destination, not an enabled route.
	LoginCallbackContinuePath = "/auth/v1/login/continue"
	callbackCapsulePurpose    = "meshtransit/oidc-auth/callback-capture/v1\x00"
	callbackCapsuleFixedBytes = 16 + 1 + 43 + 2
	maximumCapsuleCodeBytes   = 2048
)

var (
	// ErrInvalidLoginCapsule conceals malformed config, syntax, ciphertext or expiry.
	ErrInvalidLoginCapsule = errors.New("http api: invalid callback capsule")
	// ErrLoginCapsuleUnavailable suppresses release after cancellation/entropy failure.
	ErrLoginCapsuleUnavailable = errors.New("http api: callback capsule unavailable")
)

// LoginCapsuleOperation is a closed private telemetry phase.
type LoginCapsuleOperation uint8

const (
	// LoginCapsuleOperationUnknown coalesces unsupported values.
	LoginCapsuleOperationUnknown LoginCapsuleOperation = iota
	// LoginCapsuleCapture seals syntax only, not authority or HTTP delivery.
	LoginCapsuleCapture
	// LoginCapsuleOpen authenticates transport only, not durable browser proof.
	LoginCapsuleOpen
)

// String returns a bounded telemetry label.
func (operation LoginCapsuleOperation) String() string {
	switch operation {
	case LoginCapsuleCapture:
		return "capture"
	case LoginCapsuleOpen:
		return "open"
	default:
		return "unknown"
	}
}

// LoginCapsuleOutcome is not an authentication decision.
type LoginCapsuleOutcome uint8

const (
	// LoginCapsuleUnknown coalesces unsupported values.
	LoginCapsuleUnknown LoginCapsuleOutcome = iota
	// LoginCapsuleAccepted means untrusted transport was processed.
	LoginCapsuleAccepted
	// LoginCapsuleInvalid means invalid config/input/binding/time.
	LoginCapsuleInvalid
	// LoginCapsuleUnavailable means canceled work or unavailable entropy.
	LoginCapsuleUnavailable
)

// String returns only a closed result label.
func (outcome LoginCapsuleOutcome) String() string {
	switch outcome {
	case LoginCapsuleAccepted:
		return "accepted"
	case LoginCapsuleInvalid:
		return "invalid"
	case LoginCapsuleUnavailable:
		return "unavailable"
	default:
		return "unknown"
	}
}

// LoginCapsuleObserver must be private, bounded, nonblocking and concurrency-safe.
// It receives no input, error text, secrets or identity.
type LoginCapsuleObserver interface {
	ObserveLoginCapsule(LoginCapsuleOperation, LoginCapsuleOutcome, time.Duration)
}

// LoginCallbackCapsuleOptions supplies separate resident key and immutable routing.
// Rotate before 2^32 total seals per key across replicas/restarts; never reuse other keys.
type LoginCallbackCapsuleOptions struct {
	Route       oidcauth.Route
	KeyID       string
	KeyMaterial []byte
	Lifetime    time.Duration
	Observer    LoginCapsuleObserver
}

// LoginCallbackCapsuleCodec owns no authority, request context or per-browser state.
type LoginCallbackCapsuleCodec struct {
	route    oidcauth.Route
	keyID    string
	binding  [sha256.Size]byte
	aead     cipher.AEAD
	lifetime time.Duration
	observer LoginCapsuleObserver
}

// NewLoginCallbackCapsuleCodec validates without listener/registration/I/O effects.
// Key removal/replacement invalidates previous input; no old-key or routing fallback exists.
func NewLoginCallbackCapsuleCodec(options LoginCallbackCapsuleOptions) (*LoginCallbackCapsuleCodec, error) {
	_, keyErr := oidcauth.NewDigestKeyID(options.KeyID)
	validLifetime := options.Lifetime >= 30*time.Second && options.Lifetime <= 120*time.Second
	if !options.Route.IsValid() || keyErr != nil || len(options.KeyMaterial) != 32 {
		return nil, ErrInvalidLoginCapsule
	}
	if !validLifetime || options.Lifetime%time.Second != 0 || nilCapsuleObserver(options.Observer) {
		return nil, ErrInvalidLoginCapsule
	}
	registered, err := url.Parse(options.Route.RedirectURI())
	if err != nil || !canonicalCallbackPath(registered.Path) || registered.ForceQuery ||
		registered.Path == LoginCallbackContinuePath {
		return nil, ErrInvalidLoginCapsule
	}
	var key [32]byte
	copy(key[:], options.KeyMaterial)
	defer clear(key[:])
	if key == ([32]byte{}) {
		return nil, ErrInvalidLoginCapsule
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, ErrInvalidLoginCapsule
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalidLoginCapsule
	}
	binding, err := callbackRouteFingerprint(options.Route)
	if err != nil {
		return nil, ErrInvalidLoginCapsule
	}
	return &LoginCallbackCapsuleCodec{route: options.Route, keyID: options.KeyID, binding: binding,
		aead: aead, lifetime: options.Lifetime, observer: options.Observer}, nil
}

func nilCapsuleObserver(observer LoginCapsuleObserver) bool {
	if observer == nil {
		return true
	}
	value := reflect.ValueOf(observer)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (codec *LoginCallbackCapsuleCodec) valid() bool {
	if codec == nil || codec.aead == nil || nilCapsuleObserver(codec.observer) {
		return false
	}
	_, err := oidcauth.NewDigestKeyID(codec.keyID)
	validLifetime := codec.lifetime >= 30*time.Second && codec.lifetime <= 120*time.Second
	ownedRoute := err == nil && codec.route.IsValid() && codec.binding != ([sha256.Size]byte{})
	ownedCrypto := codec.aead.NonceSize() == 12 && codec.aead.Overhead() == 16
	return ownedRoute && ownedCrypto && validLifetime && codec.lifetime%time.Second == 0
}

// Capture seals bounded syntax with fresh OS entropy; it creates no claim or Session.
func (codec *LoginCallbackCapsuleCodec) Capture(
	ctx context.Context,
	input LoginCallbackInput,
	now time.Time,
) (LoginCallbackCapture, error) {
	return codec.capture(
		ctx,
		input,
		now,
		rand.Reader,
	)
}

func (codec *LoginCallbackCapsuleCodec) capture(
	ctx context.Context,
	input LoginCallbackInput,
	now time.Time,
	entropy io.Reader,
) (LoginCallbackCapture, error) {
	if !codec.valid() {
		return LoginCallbackCapture{}, ErrInvalidLoginCapsule
	}
	started, outcome := time.Now(), LoginCapsuleInvalid
	defer func() { codec.observer.ObserveLoginCapsule(LoginCapsuleCapture, outcome, time.Since(started)) }()
	validInput := input.IsValid() && len(input.Code().Encoded()) <= maximumCapsuleCodeBytes
	if ctx == nil || !validCapsuleTime(now) || !validInput {
		return LoginCallbackCapture{}, ErrInvalidLoginCapsule
	}
	if err := capsuleContextError(ctx); err != nil {
		outcome = LoginCapsuleUnavailable
		return LoginCallbackCapture{}, err
	}
	binding, err := callbackRouteFingerprint(input.Route())
	if err != nil || binding != codec.binding {
		return LoginCallbackCapture{}, ErrInvalidLoginCapsule
	}
	issued := now.UTC().Truncate(time.Second)
	expires := issued.Add(codec.lifetime)
	if expires.Year() > 9998 {
		return LoginCallbackCapture{}, ErrInvalidLoginCapsule
	}
	issuedSeconds, expiresSeconds := issued.Unix(), expires.Unix()
	if issuedSeconds <= 0 || expiresSeconds <= 0 {
		return LoginCallbackCapture{}, ErrInvalidLoginCapsule
	}
	codeLength, keyLength := len(input.Code().Encoded()), len(codec.keyID)
	if codeLength > maximumCapsuleCodeBytes || keyLength < 1 || keyLength > 128 {
		return LoginCallbackCapture{}, ErrInvalidLoginCapsule
	}
	plaintext := make([]byte, callbackCapsuleFixedBytes+codeLength)
	defer clear(plaintext)
	binary.BigEndian.PutUint64(plaintext, uint64(issuedSeconds))
	binary.BigEndian.PutUint64(plaintext[8:], uint64(expiresSeconds))
	plaintext[16] = byte(input.Kind())
	copy(plaintext[17:60], input.State().Encoded())
	binary.BigEndian.PutUint16(plaintext[60:], uint16(codeLength))
	copy(plaintext[62:], input.Code().Encoded())
	envelope := make([]byte, 2+keyLength+codec.aead.NonceSize())
	envelope[0], envelope[1] = 1, byte(keyLength)
	copy(envelope[2:], codec.keyID)
	nonce := envelope[2+len(codec.keyID):]
	if entropy == nil {
		return LoginCallbackCapture{}, ErrInvalidLoginCapsule
	}
	if _, err := io.ReadFull(entropy, nonce); err != nil {
		outcome = LoginCapsuleUnavailable
		return LoginCallbackCapture{}, ErrLoginCapsuleUnavailable
	}
	if err := capsuleContextError(ctx); err != nil {
		outcome = LoginCapsuleUnavailable
		return LoginCallbackCapture{}, err
	}
	aad := codec.additionalData(envelope[:2+len(codec.keyID)], input.PreAuthCookie())
	defer clear(aad)
	sealed := codec.aead.Seal(
		envelope,
		nonce,
		plaintext,
		aad,
	)
	value := base64.RawURLEncoding.EncodeToString(sealed)
	clear(sealed)
	if len(value) > 3800 {
		return LoginCallbackCapture{}, ErrInvalidLoginCapsule
	}
	if err := capsuleContextError(ctx); err != nil {
		outcome = LoginCapsuleUnavailable
		return LoginCallbackCapture{}, err
	}
	outcome = LoginCapsuleAccepted
	return LoginCallbackCapture{value: value, issuedAt: issued, expiresAt: expires}, nil
}

// Open returns authenticated transport syntax only; mandatory durable verification/claim follows.
// Repeated opens within TTL are allowed and never imply single-use authentication.
func (codec *LoginCallbackCapsuleCodec) Open(
	ctx context.Context,
	headers http.Header,
	now time.Time,
) (LoginCallbackInput, error) {
	if !codec.valid() {
		return LoginCallbackInput{}, ErrInvalidLoginCapsule
	}
	started, outcome := time.Now(), LoginCapsuleInvalid
	defer func() { codec.observer.ObserveLoginCapsule(LoginCapsuleOpen, outcome, time.Since(started)) }()
	if ctx == nil || !validCapsuleTime(now) || !boundedLoginHeaders(headers) {
		return LoginCallbackInput{}, ErrInvalidLoginCapsule
	}
	if err := capsuleContextError(ctx); err != nil {
		outcome = LoginCapsuleUnavailable
		return LoginCallbackInput{}, err
	}
	value, cookieErr := oidc.ReadLoginCallbackCookie(headers)
	cookie, authCookieErr := oidc.ReadPreAuthCookie(headers)
	if cookieErr != nil || authCookieErr != nil {
		return LoginCallbackInput{}, ErrInvalidLoginCapsule
	}
	envelope, err := base64.RawURLEncoding.Strict().DecodeString(value)
	prefixBytes := 2 + len(codec.keyID)
	minimum := prefixBytes + codec.aead.NonceSize() + codec.aead.Overhead() + callbackCapsuleFixedBytes
	if err != nil || len(envelope) < minimum {
		return LoginCallbackInput{}, ErrInvalidLoginCapsule
	}
	if envelope[0] != 1 || int(envelope[1]) != len(codec.keyID) || string(envelope[2:prefixBytes]) != codec.keyID {
		return LoginCallbackInput{}, ErrInvalidLoginCapsule
	}
	aad := codec.additionalData(envelope[:prefixBytes], cookie)
	defer clear(aad)
	plaintext, err := codec.aead.Open(
		nil,
		envelope[prefixBytes:prefixBytes+codec.aead.NonceSize()],
		envelope[prefixBytes+codec.aead.NonceSize():],
		aad,
	)
	if err != nil {
		return LoginCallbackInput{}, ErrInvalidLoginCapsule
	}
	defer clear(plaintext)
	input, err := codec.decode(plaintext, cookie, now)
	if err != nil {
		return LoginCallbackInput{}, err
	}
	if err := capsuleContextError(ctx); err != nil {
		outcome = LoginCapsuleUnavailable
		return LoginCallbackInput{}, err
	}
	outcome = LoginCapsuleAccepted
	return input, nil
}

func (codec *LoginCallbackCapsuleCodec) decode(
	plaintext []byte,
	cookie oidcauth.PreAuthCookie,
	now time.Time,
) (LoginCallbackInput, error) {
	if len(plaintext) < callbackCapsuleFixedBytes {
		return LoginCallbackInput{}, ErrInvalidLoginCapsule
	}
	issued, expires := binary.BigEndian.Uint64(plaintext), binary.BigEndian.Uint64(plaintext[8:])
	if issued == 0 || expires <= issued || issued > math.MaxInt64 || expires > math.MaxInt64 {
		return LoginCallbackInput{}, ErrInvalidLoginCapsule
	}
	lifetimeSeconds := int64(codec.lifetime / time.Second)
	if lifetimeSeconds < 30 || lifetimeSeconds > 120 {
		return LoginCallbackInput{}, ErrInvalidLoginCapsule
	}
	if expires-issued != uint64(lifetimeSeconds) {
		return LoginCallbackInput{}, ErrInvalidLoginCapsule
	}
	nowSeconds := now.Unix()
	if nowSeconds <= 0 {
		return LoginCallbackInput{}, ErrInvalidLoginCapsule
	}
	if uint64(nowSeconds) < issued || uint64(nowSeconds) >= expires {
		return LoginCallbackInput{}, ErrInvalidLoginCapsule
	}
	codeLength := int(binary.BigEndian.Uint16(plaintext[60:]))
	if codeLength > maximumCapsuleCodeBytes || len(plaintext) != callbackCapsuleFixedBytes+codeLength {
		return LoginCallbackInput{}, ErrInvalidLoginCapsule
	}
	state, err := oidcauth.ParseState(string(plaintext[17:60]))
	if err != nil {
		return LoginCallbackInput{}, ErrInvalidLoginCapsule
	}
	input := LoginCallbackInput{route: codec.route, state: state, cookie: cookie,
		kind: LoginCallbackOutcome(plaintext[16])}
	switch input.kind {
	case LoginCallbackCodeReceived:
		input.code, err = oidcauth.ParseCode(string(plaintext[62:]))
		if err != nil {
			return LoginCallbackInput{}, ErrInvalidLoginCapsule
		}
	case LoginCallbackProviderErrorReceived:
		if codeLength != 0 {
			return LoginCallbackInput{}, ErrInvalidLoginCapsule
		}
	default:
		return LoginCallbackInput{}, ErrInvalidLoginCapsule
	}
	if !input.IsValid() {
		return LoginCallbackInput{}, ErrInvalidLoginCapsule
	}
	return input, nil
}

func (codec *LoginCallbackCapsuleCodec) additionalData(prefix []byte, cookie oidcauth.PreAuthCookie) []byte {
	aad := []byte(callbackCapsulePurpose + oidc.LoginCallbackCookieName + "\x00" + LoginCallbackContinuePath + "\x00")
	aad = append(aad, codec.binding[:]...)
	aad = append(aad, prefix...)
	return append(aad, cookie.Encoded()...)
}

func callbackRouteFingerprint(route oidcauth.Route) ([sha256.Size]byte, error) {
	value, err := json.Marshal(oidcauth.RouteParams{
		DeploymentID: route.DeploymentID(), WorkspaceID: route.WorkspaceID(), ProviderID: route.ProviderID(),
		ClientID: route.ClientID(), ProviderGeneration: route.ProviderGeneration(), RecoveryEpoch: route.RecoveryEpoch(),
		Issuer: route.Issuer(), DiscoveryURI: route.DiscoveryURI(), AuthorizationEndpoint: route.AuthorizationEndpoint(),
		TokenEndpoint: route.TokenEndpoint(), JWKSURI: route.JWKSURI(), OIDCClientID: route.OIDCClientID(),
		ClientKind: "confidential", ClientAuthMethod: route.ClientAuthMethod(), Scopes: route.Scopes(),
		AllowedAlgorithms: route.AllowedAlgorithms(), RedirectID: route.RedirectID(), RedirectURI: route.RedirectURI(),
		ReturnRouteID: route.ReturnRouteID(),
	})
	if err != nil {
		return [sha256.Size]byte{}, ErrInvalidLoginCapsule
	}
	return sha256.Sum256(value), nil
}

func validCapsuleTime(now time.Time) bool {
	return !now.IsZero() && now.Unix() > 0 && now.Year() <= 9998
}

func capsuleContextError(ctx context.Context) error {
	err := ctx.Err()
	if err == nil {
		return nil
	}
	classified := ErrLoginCapsuleUnavailable
	for _, category := range []error{context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, category) {
			classified = errors.Join(classified, category)
		}
	}
	return classified
}

// String prevents resident-key and route disclosure.
func (*LoginCallbackCapsuleCodec) String() string { return "[REDACTED]" }

// GoString prevents detailed resident-key disclosure.
func (*LoginCallbackCapsuleCodec) GoString() string {
	return "httpapi.LoginCallbackCapsuleCodec([REDACTED])"
}

// LogValue prevents structured-log disclosure.
func (*LoginCallbackCapsuleCodec) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// LoginCallbackCapture carries encrypted temporary syntax, not positive authority.
type LoginCallbackCapture struct {
	value     string
	issuedAt  time.Time
	expiresAt time.Time
}

// WriteRedirect emits only a live encrypted cookie and fixed clean zero-body 303.
// The caller must suppress query logging and own transport deadlines; never log Cookie headers.
func (capture LoginCallbackCapture) WriteRedirect(
	ctx context.Context,
	response http.ResponseWriter,
	now time.Time,
) error {
	if ctx == nil || response == nil || capture.value == "" {
		return ErrInvalidLoginCapsule
	}
	writer := reflect.ValueOf(response)
	if writer.Kind() == reflect.Pointer && writer.IsNil() {
		return ErrInvalidLoginCapsule
	}
	if err := capsuleContextError(ctx); err != nil {
		return err
	}
	validTimes := validCapsuleTime(now) && !now.Before(capture.issuedAt) && now.Before(capture.expiresAt)
	remaining := capture.expiresAt.Sub(now) / time.Second
	if !validTimes || remaining < 1 || remaining > 120 || len(capture.value) > 3800 {
		return ErrInvalidLoginCapsule
	}
	cookie := &http.Cookie{Name: oidc.LoginCallbackCookieName, Value: capture.value, Path: "/", Secure: true,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: capture.expiresAt, MaxAge: int(remaining)}
	if err := cookie.Valid(); err != nil || len(cookie.String()) >= 4096 {
		return ErrInvalidLoginCapsule
	}
	if err := capsuleContextError(ctx); err != nil {
		return err
	}
	setLoginSecurityHeaders(response.Header())
	response.Header().Set("Location", LoginCallbackContinuePath)
	response.Header().Set("Content-Length", "0")
	http.SetCookie(response, cookie)
	response.WriteHeader(http.StatusSeeOther)
	return nil
}

// String prevents capture disclosure.
func (LoginCallbackCapture) String() string { return "[REDACTED]" }

// GoString prevents detailed capture disclosure.
func (LoginCallbackCapture) GoString() string { return "httpapi.LoginCallbackCapture([REDACTED])" }

// LogValue prevents structured-log capture disclosure.
func (LoginCallbackCapture) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON refuses publication of server-only captured material.
func (LoginCallbackCapture) MarshalJSON() ([]byte, error) { return nil, ErrInvalidLoginCapsule }
