package httpapi

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"reflect"
	"strings"
	"time"

	"meshtransit.net/core/internal/adapter/oidc"
	"meshtransit.net/core/internal/domain/identity/oidcauth"
)

const maximumCallbackQueryBytes = 8192

var (
	// ErrInvalidLoginCallbackReader rejects missing immutable route/observer ownership.
	ErrInvalidLoginCallbackReader = errors.New("http api: invalid callback reader")
	// ErrInvalidLoginCallback conceals malformed or ambiguous untrusted input.
	ErrInvalidLoginCallback = errors.New("http api: invalid callback input")
	// ErrLoginCallbackUnavailable suppresses input release after cancellation.
	ErrLoginCallbackUnavailable = errors.New("http api: callback input unavailable")
)

// LoginCallbackOutcome describes syntax only, never authentication or authority.
type LoginCallbackOutcome uint8

const (
	// LoginCallbackUnknown coalesces unsupported numeric categories.
	LoginCallbackUnknown LoginCallbackOutcome = iota
	// LoginCallbackCodeReceived means bounded untrusted code input, not an exchange grant.
	LoginCallbackCodeReceived
	// LoginCallbackProviderErrorReceived discards provider diagnostic text and error URI.
	LoginCallbackProviderErrorReceived
	// LoginCallbackInvalid means rejected transport, syntax or handle shape.
	LoginCallbackInvalid
	// LoginCallbackUnavailable means canceled work released no input.
	LoginCallbackUnavailable
)

// String maps unknown outcomes to one bounded operator label.
func (outcome LoginCallbackOutcome) String() string {
	switch outcome {
	case LoginCallbackCodeReceived:
		return "code_received"
	case LoginCallbackProviderErrorReceived:
		return "provider_error_received"
	case LoginCallbackInvalid:
		return "invalid"
	case LoginCallbackUnavailable:
		return "unavailable"
	default:
		return "unknown"
	}
}

// LoginCallbackInput is immutable untrusted syntax, not verified browser possession.
// It carries no raw query, issuer override, provider diagnostics or session hint.
type LoginCallbackInput struct {
	route  oidcauth.Route
	state  oidcauth.State
	cookie oidcauth.PreAuthCookie
	code   oidcauth.Code
	kind   LoginCallbackOutcome
}

// Route returns only the reader's fixed Core-owned configuration, not request scope.
func (input LoginCallbackInput) Route() oidcauth.Route { return input.route }

// State releases original material only for server-side capture/reverification.
func (input LoginCallbackInput) State() oidcauth.State { return input.state }

// PreAuthCookie releases a shape-valid handle; authoritative HMAC verification is mandatory later.
func (input LoginCallbackInput) PreAuthCookie() oidcauth.PreAuthCookie { return input.cookie }

// Code returns an untrusted code, or an invalid zero value for provider-error input.
func (input LoginCallbackInput) Code() oidcauth.Code { return input.code }

// Kind reports code versus generic provider error, never authentication success.
func (input LoginCallbackInput) Kind() LoginCallbackOutcome { return input.kind }

// IsValid checks syntax only; neither handle possession nor identity is authenticated.
func (input LoginCallbackInput) IsValid() bool {
	validHandles := input.state.IsValid() && input.cookie.IsValid()
	if !input.route.IsValid() || !validHandles {
		return false
	}
	switch input.kind {
	case LoginCallbackCodeReceived:
		return input.code.IsValid()
	case LoginCallbackProviderErrorReceived:
		return !input.code.IsValid()
	default:
		return false
	}
}

// String prevents accidental callback secret disclosure.
func (LoginCallbackInput) String() string { return "[REDACTED]" }

// GoString prevents detailed formatting disclosure.
func (LoginCallbackInput) GoString() string { return "httpapi.LoginCallbackInput([REDACTED])" }

// LogValue prevents structured-log disclosure.
func (LoginCallbackInput) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON refuses accidental publication of server-only callback material.
func (LoginCallbackInput) MarshalJSON() ([]byte, error) { return nil, ErrInvalidLoginCallback }

// LoginCallbackObserver receives no request, secret, error text or identity.
// Implementations must be concurrency-safe, bounded, nonblocking and perform no I/O.
type LoginCallbackObserver interface {
	ObserveLoginCallback(LoginCallbackOutcome, time.Duration)
}

// LoginCallbackReaderOptions fixes one Core-owned route and private telemetry ownership.
type LoginCallbackReaderOptions struct {
	Route    oidcauth.Route
	Observer LoginCallbackObserver
}

// LoginCallbackReader owns no listener, request, mutable browser state or privileged port.
// It cannot verify possession, consume Auth, exchange codes or issue Sessions.
type LoginCallbackReader struct {
	route              oidcauth.Route
	host, origin, path string
	observer           LoginCallbackObserver
}

// NewLoginCallbackReader validates before any request/effect; no handler is registered.
func NewLoginCallbackReader(options LoginCallbackReaderOptions) (*LoginCallbackReader, error) {
	if !options.Route.IsValid() || nilCallbackObserver(options.Observer) {
		return nil, ErrInvalidLoginCallbackReader
	}
	registered, err := url.Parse(options.Route.RedirectURI())
	if err != nil || registered.ForceQuery || !canonicalCallbackPath(registered.Path) {
		return nil, ErrInvalidLoginCallbackReader
	}
	return &LoginCallbackReader{
		route: options.Route, host: registered.Host, origin: "https://" + registered.Host,
		path: registered.Path, observer: options.Observer,
	}, nil
}

func nilCallbackObserver(observer LoginCallbackObserver) bool {
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

func canonicalCallbackPath(value string) bool {
	if value == "" || value == "/" {
		return false
	}
	if !strings.HasPrefix(value, "/") || path.Clean(value) != value {
		return false
	}
	for _, character := range value {
		letter := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
		digit := character >= '0' && character <= '9'
		if !letter && !digit && !strings.ContainsRune("/-._~", character) {
			return false
		}
	}
	return true
}

// Read accepts only incoming origin-form code-query GET input on completed direct TLS.
// The caller owns body/listener deadlines and must never log the request target.
// No body read or I/O occurs. Capture/clean redirect and protected POST are separate gates.
func (reader *LoginCallbackReader) Read(ctx context.Context, request *http.Request) (LoginCallbackInput, error) {
	if reader == nil {
		return LoginCallbackInput{}, ErrInvalidLoginCallbackReader
	}
	unowned := reader.host == "" || reader.path == "" || reader.origin == ""
	if unowned || !reader.route.IsValid() || nilCallbackObserver(reader.observer) {
		return LoginCallbackInput{}, ErrInvalidLoginCallbackReader
	}
	started := time.Now()
	outcome := LoginCallbackInvalid
	defer func() { reader.observer.ObserveLoginCallback(outcome, time.Since(started)) }()
	if ctx == nil || request == nil {
		return LoginCallbackInput{}, ErrInvalidLoginCallback
	}
	if err := callbackContextError(ctx, request.Context()); err != nil {
		outcome = LoginCallbackUnavailable
		return LoginCallbackInput{}, err
	}
	if !reader.validRequest(request) {
		return LoginCallbackInput{}, ErrInvalidLoginCallback
	}
	values, err := readCallbackQuery(request.URL.RawQuery)
	if err != nil || values["iss"] != reader.route.Issuer() {
		return LoginCallbackInput{}, ErrInvalidLoginCallback
	}
	state, stateErr := oidcauth.ParseState(values["state"])
	cookie, cookieErr := oidc.ReadPreAuthCookie(request.Header)
	if stateErr != nil || cookieErr != nil {
		return LoginCallbackInput{}, ErrInvalidLoginCallback
	}
	input := LoginCallbackInput{route: reader.route, state: state, cookie: cookie}
	code, hasCode := values["code"]
	providerError, hasError := values["error"]
	if hasCode == hasError {
		return LoginCallbackInput{}, ErrInvalidLoginCallback
	}
	if hasCode {
		_, hasDescription := values["error_description"]
		_, hasURI := values["error_uri"]
		if hasDescription || hasURI {
			return LoginCallbackInput{}, ErrInvalidLoginCallback
		}
		// QueryUnescape can return a substring of the raw query. Clone only code
		// so returned custody cannot retain the complete diagnostic/query backing.
		input.code, err = oidcauth.ParseCode(strings.Clone(code))
		if err != nil {
			return LoginCallbackInput{}, ErrInvalidLoginCallback
		}
		input.kind = LoginCallbackCodeReceived
	} else {
		if !callbackToken(providerError, 128) {
			return LoginCallbackInput{}, ErrInvalidLoginCallback
		}
		input.kind = LoginCallbackProviderErrorReceived
	}
	if err := callbackContextError(ctx, request.Context()); err != nil {
		outcome = LoginCallbackUnavailable
		return LoginCallbackInput{}, err
	}
	outcome = input.kind
	return input, nil
}

// String omits private route configuration from incidental formatting.
func (*LoginCallbackReader) String() string { return "[REDACTED]" }

// GoString omits detailed route configuration.
func (*LoginCallbackReader) GoString() string { return "httpapi.LoginCallbackReader([REDACTED])" }

// LogValue omits configured topology from structured logging.
func (*LoginCallbackReader) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

func callbackContextError(ctx, requestContext context.Context) error {
	var classified error
	for _, err := range []error{ctx.Err(), requestContext.Err()} {
		if err == nil {
			continue
		}
		classified = errors.Join(classified, ErrLoginCallbackUnavailable)
		for _, category := range []error{context.Canceled, context.DeadlineExceeded} {
			if errors.Is(err, category) {
				classified = errors.Join(classified, category)
			}
		}
	}
	return classified
}

func (reader *LoginCallbackReader) validRequest(request *http.Request) bool {
	transport := request.TLS
	validTransport := transport != nil && transport.HandshakeComplete && transport.Version >= tls.VersionTLS12
	validMethod := request.Method == http.MethodGet && request.Host == reader.host
	if !validTransport || !validMethod {
		return false
	}
	if request.URL == nil || !boundedLoginHeaders(request.Header) {
		return false
	}
	target := request.URL
	wrongPath := target.Path != reader.path || target.RawPath != ""
	hasURLAuthority := target.Scheme != "" || target.Host != ""
	hasURLIdentity := target.User != nil || target.Opaque != ""
	fragment := target.Fragment != "" || target.RawFragment != ""
	if wrongPath || hasURLAuthority || hasURLIdentity {
		return false
	}
	if fragment || target.ForceQuery || len(target.RawQuery) > maximumCallbackQueryBytes {
		return false
	}
	if request.RequestURI != target.RequestURI() {
		return false
	}
	hasBody := request.Body != nil && request.Body != http.NoBody
	hasTransfer := request.ContentLength != 0 || len(request.TransferEncoding) != 0 || len(request.Trailer) != 0
	if hasBody || hasTransfer {
		return false
	}
	for _, name := range []string{
		"Host", "Content-Type", "Content-Encoding", "Transfer-Encoding", "Trailer", "Expect", "Upgrade",
	} {
		if _, present := request.Header[name]; present {
			return false
		}
	}
	lengths, hasLength := request.Header["Content-Length"]
	if hasLength && (len(lengths) != 1 || lengths[0] != "0") {
		return false
	}
	origins, hasOrigin := request.Header["Origin"]
	if hasOrigin && (len(origins) != 1 || origins[0] != reader.origin) {
		return false
	}
	return validCallbackNavigation(request.Header)
}

func validCallbackNavigation(headers http.Header) bool {
	mode, hasMode := headers["Sec-Fetch-Mode"]
	destination, hasDestination := headers["Sec-Fetch-Dest"]
	site, hasSite := headers["Sec-Fetch-Site"]
	if hasMode || hasDestination || hasSite {
		validMode := len(mode) == 1 && mode[0] == "navigate"
		validDestination := len(destination) == 1 && destination[0] == "document"
		if !validMode || !validDestination || len(site) != 1 {
			return false
		}
		switch site[0] {
		case "cross-site", "same-site", "same-origin", "none":
		default:
			return false
		}
	}
	user, present := headers["Sec-Fetch-User"]
	return !present || hasMode && len(user) == 1 && user[0] == "?1"
}

func readCallbackQuery(raw string) (map[string]string, error) {
	if raw == "" || len(raw) > maximumCallbackQueryBytes {
		return nil, ErrInvalidLoginCallback
	}
	if strings.Count(raw, "&") >= 8 {
		return nil, ErrInvalidLoginCallback
	}
	for _, character := range raw {
		if character <= 0x20 || character >= 0x7f || character == ';' || character == '#' {
			return nil, ErrInvalidLoginCallback
		}
	}
	values := make(map[string]string, 8)
	for pair := range strings.SplitSeq(raw, "&") {
		name, encoded, separated := strings.Cut(pair, "=")
		if !separated || !callbackToken(name, 64) {
			return nil, ErrInvalidLoginCallback
		}
		if _, duplicate := values[name]; duplicate {
			return nil, ErrInvalidLoginCallback
		}
		value, err := url.QueryUnescape(encoded)
		if err != nil || !validCallbackValue(name, value) {
			return nil, ErrInvalidLoginCallback
		}
		values[name] = value
	}
	return values, nil
}

func callbackToken(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
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

func validCallbackValue(name, value string) bool {
	maximum := 1024
	spaces := true
	switch strings.ToLower(name) {
	case "access_token", "id_token", "refresh_token", "token_type", "expires_in", "response":
		return false
	}
	switch name {
	case "state":
		return len(value) == 43
	case "code":
		code, err := oidcauth.ParseCode(value)
		return err == nil && code.IsValid()
	case "error":
		return callbackToken(value, 128)
	case "iss":
		maximum, spaces = 2048, false
	case "error_description":
		maximum = 512
	case "error_uri":
		maximum, spaces = 2048, false
	}
	if len(value) > maximum {
		return false
	}
	for _, character := range value {
		outsideASCII := character < 0x20 || character >= 0x7f
		disallowedSpace := !spaces && character == 0x20
		if outsideASCII || disallowedSpace {
			return false
		}
		if (name == "error_description" || name == "error_uri") && (character == '"' || character == '\\') {
			return false
		}
	}
	return true
}
