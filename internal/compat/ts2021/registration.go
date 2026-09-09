package ts2021

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"runtime"
	"strings"
	"unicode"
	"unicode/utf8"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	maxRegistrationResponseBytes = 64 << 10
	maxCredentialBytes           = 4096
	maxHostnameRunes             = 253
	maxServerErrorRunes          = 200
	maxVersionRunes              = 128
)

var (
	// ErrInvalidFingerprint indicates a malformed operator-supplied SHA-256 pin.
	ErrInvalidFingerprint = errors.New("ts2021: invalid control key fingerprint")
	// ErrFingerprintMismatch indicates that the operator pin does not match discovery.
	ErrFingerprintMismatch = errors.New("ts2021: control key fingerprint mismatch")
	// ErrControlKeyChanged indicates that discovery no longer matches persisted trust.
	ErrControlKeyChanged = errors.New("ts2021: pinned control key changed")
	// ErrInvalidMaterial indicates malformed persisted protocol key material.
	ErrInvalidMaterial = errors.New("ts2021: invalid identity material")
	// ErrRegistration indicates a rejected or internally inconsistent response.
	ErrRegistration = errors.New("ts2021: registration failed")
	// ErrNodeKeyExpired indicates that registration requires a deliberate key rotation.
	ErrNodeKeyExpired = errors.New("ts2021: node key expired")
)

// KeyMaterial contains serialized protocol keys. Formatting is always redacted.
type KeyMaterial struct {
	MachinePrivateKey []byte `json:"-"`
	NodePrivateKey    []byte `json:"-"`
	ControlPublicKey  []byte `json:"-"`
}

// NodePrivateRaw decodes the WireGuard-compatible node key at the compatibility
// boundary. Callers must clear the returned array after transferring it to the
// packet engine.
func NodePrivateRaw(material KeyMaterial) ([32]byte, error) {
	var nodeKey key.NodePrivate
	if err := nodeKey.UnmarshalText(material.NodePrivateKey); err != nil || nodeKey.IsZero() {
		return [32]byte{}, ErrInvalidMaterial
	}

	return nodeKey.Raw32(), nil
}

func (KeyMaterial) String() string { return "<ts2021 key material redacted>" }

func (KeyMaterial) GoString() string { return "ts2021.KeyMaterial{<redacted>}" }

// TrustResult is created only after the operator pin and Noise peer both verify.
type TrustResult struct {
	Fingerprint string
	Material    KeyMaterial
}

// RegistrationState is a stable product-facing registration outcome.
type RegistrationState string

const (
	RegistrationStateAuthorized            RegistrationState = "authorized"
	RegistrationStateAuthorizationRequired RegistrationState = "authorization_required"
)

// RegisterOptions contains non-persisted inputs for one registration request.
type RegisterOptions struct {
	Hostname          string
	Version           string
	PinnedFingerprint string
	AuthKey           string
	FollowupURL       string
}

// RegistrationResult excludes upstream user/login data and private material.
type RegistrationResult struct {
	State             RegistrationState
	AuthURL           string
	MachineAuthorized bool
}

// BootstrapTrust verifies an operator-provided fingerprint, proves the server
// owns the corresponding Noise key, then creates fresh per-profile keys.
func (c *Client) BootstrapTrust(
	ctx context.Context,
	controlURL string,
	expectedFingerprint string,
) (TrustResult, error) {
	discovered, err := c.discoverControlKey(ctx, controlURL)
	if err != nil {
		return TrustResult{}, err
	}
	canonical, err := verifyFingerprint(expectedFingerprint, discovered.fingerprint)
	if err != nil {
		return TrustResult{}, err
	}

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()
	connection, err := strictBaseNoiseConnection(ctx, discovered.endpoint, machineKey, discovered.publicKey)
	if err != nil {
		return TrustResult{}, fmt.Errorf("ts2021: verifying pinned noise key: %w", err)
	}
	if err := connection.Close(); err != nil {
		return TrustResult{}, fmt.Errorf("ts2021: closing trust-verification connection: %w", err)
	}

	material, err := marshalMaterial(machineKey, nodeKey, discovered.publicKey)
	if err != nil {
		return TrustResult{}, err
	}

	return TrustResult{Fingerprint: canonical, Material: material}, nil
}

// VerifyTrust checks persisted material, the operator pin, current HTTPS
// discovery, and Noise server possession without rotating any key.
func (c *Client) VerifyTrust(
	ctx context.Context,
	controlURL string,
	material KeyMaterial,
	expectedFingerprint string,
) error {
	machineKey, _, pinnedControlKey, err := parseMaterial(material)
	if err != nil {
		return err
	}
	discovered, err := c.discoverControlKey(ctx, controlURL)
	if err != nil {
		return err
	}
	if _, err := verifyFingerprint(expectedFingerprint, controlKeyFingerprint(pinnedControlKey)); err != nil {
		return fmt.Errorf("%w: persisted fingerprint does not match persisted key", ErrInvalidMaterial)
	}
	if !constantTimeFingerprintEqual(discovered.fingerprint, expectedFingerprint) ||
		pinnedControlKey != discovered.publicKey {
		return ErrControlKeyChanged
	}

	connection, err := strictBaseNoiseConnection(ctx, discovered.endpoint, machineKey, pinnedControlKey)
	if err != nil {
		return fmt.Errorf("ts2021: verifying existing noise pin: %w", err)
	}
	if err := connection.Close(); err != nil {
		return fmt.Errorf("ts2021: closing pin-verification connection: %w", err)
	}

	return nil
}

// Register sends one bounded registration request over a freshly established,
// pinned Noise HTTP/2 connection. AuthKey is never retained by the client.
func (c *Client) Register(
	ctx context.Context,
	controlURL string,
	material KeyMaterial,
	options RegisterOptions,
) (RegistrationResult, error) {
	machineKey, nodeKey, pinnedControlKey, err := parseMaterial(material)
	if err != nil {
		return RegistrationResult{}, err
	}
	if err := validateRegisterOptions(controlURL, options); err != nil {
		return RegistrationResult{}, err
	}
	discovered, err := c.discoverControlKey(ctx, controlURL)
	if err != nil {
		return RegistrationResult{}, err
	}
	if _, err := verifyFingerprint(
		options.PinnedFingerprint,
		controlKeyFingerprint(pinnedControlKey),
	); err != nil {
		return RegistrationResult{}, fmt.Errorf(
			"%w: persisted fingerprint does not match persisted key",
			ErrInvalidMaterial,
		)
	}
	if !constantTimeFingerprintEqual(discovered.fingerprint, options.PinnedFingerprint) ||
		pinnedControlKey != discovered.publicKey {
		return RegistrationResult{}, ErrControlKeyChanged
	}

	registerRequest := newRegisterRequest(nodeKey, options)
	encoded, err := json.Marshal(registerRequest)
	if err != nil {
		return RegistrationResult{}, fmt.Errorf("ts2021: encoding registration request: %w", err)
	}

	endpoint := registrationEndpoint(discovered.endpoint)
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint.String(),
		bytes.NewReader(encoded),
	)
	if err != nil {
		return RegistrationResult{}, fmt.Errorf("ts2021: creating registration request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "meshd")
	request.Header.Set(tailcfg.LBHeader, nodeKey.Public().String())

	expectedAddress := net.JoinHostPort(endpoint.Hostname(), "443")
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	transport := &http.Transport{
		Protocols:              protocols,
		DisableCompression:     true,
		MaxConnsPerHost:        1,
		MaxIdleConnsPerHost:    1,
		MaxResponseHeaderBytes: maxRegistrationResponseBytes,
		ResponseHeaderTimeout:  requestTimeout,
		ExpectContinueTimeout:  requestTimeout,
		DialTLSContext: func(
			dialCtx context.Context,
			network string,
			address string,
		) (net.Conn, error) {
			if network != "tcp" || address != expectedAddress {
				return nil, errors.New("ts2021: registration transport attempted an unexpected dial")
			}

			connection, err := strictBaseNoiseConnection(
				dialCtx,
				discovered.endpoint,
				machineKey,
				pinnedControlKey,
			)
			if err != nil {
				return nil, err
			}

			return newEarlyPayloadConn(connection), nil
		},
	}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	response, err := httpClient.Do(request)
	if err != nil {
		return RegistrationResult{}, fmt.Errorf("ts2021: sending registration request: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	return decodeRegistrationResponse(response, controlURL)
}

func newRegisterRequest(
	nodeKey key.NodePrivate,
	options RegisterOptions,
) tailcfg.RegisterRequest {
	registerRequest := tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			IPNVersion:      options.Version,
			OS:              runtime.GOOS,
			Hostname:        options.Hostname,
			GoArch:          runtime.GOARCH,
			GoVersion:       runtime.Version(),
			NoLogsNoSupport: true,
		},
		Followup: options.FollowupURL,
	}
	if options.AuthKey != "" {
		registerRequest.Auth = &tailcfg.RegisterResponseAuth{AuthKey: options.AuthKey}
	}

	return registerRequest
}

func marshalMaterial(
	machineKey key.MachinePrivate,
	nodeKey key.NodePrivate,
	controlKey key.MachinePublic,
) (KeyMaterial, error) {
	machineText, err := machineKey.MarshalText()
	if err != nil {
		return KeyMaterial{}, fmt.Errorf("ts2021: encoding machine private key: %w", err)
	}
	nodeText, err := nodeKey.MarshalText()
	if err != nil {
		return KeyMaterial{}, fmt.Errorf("ts2021: encoding node private key: %w", err)
	}
	controlText, err := controlKey.MarshalText()
	if err != nil {
		return KeyMaterial{}, fmt.Errorf("ts2021: encoding control public key: %w", err)
	}

	return KeyMaterial{
		MachinePrivateKey: machineText,
		NodePrivateKey:    nodeText,
		ControlPublicKey:  controlText,
	}, nil
}

func parseMaterial(
	material KeyMaterial,
) (key.MachinePrivate, key.NodePrivate, key.MachinePublic, error) {
	var machineKey key.MachinePrivate
	if err := machineKey.UnmarshalText(material.MachinePrivateKey); err != nil || machineKey.IsZero() {
		return key.MachinePrivate{}, key.NodePrivate{}, key.MachinePublic{}, ErrInvalidMaterial
	}
	var nodeKey key.NodePrivate
	if err := nodeKey.UnmarshalText(material.NodePrivateKey); err != nil || nodeKey.IsZero() {
		return key.MachinePrivate{}, key.NodePrivate{}, key.MachinePublic{}, ErrInvalidMaterial
	}
	var controlKey key.MachinePublic
	if err := controlKey.UnmarshalText(material.ControlPublicKey); err != nil || controlKey.IsZero() {
		return key.MachinePrivate{}, key.NodePrivate{}, key.MachinePublic{}, ErrInvalidMaterial
	}

	return machineKey, nodeKey, controlKey, nil
}

func verifyFingerprint(expected, actual string) (string, error) {
	canonical, err := canonicalFingerprint(expected)
	if err != nil {
		return "", err
	}
	if !constantTimeFingerprintEqual(canonical, actual) {
		return "", ErrFingerprintMismatch
	}

	return canonical, nil
}

// VerifyFingerprint compares an operator-provided fingerprint to a canonical
// fingerprint and returns its normalized representation.
func VerifyFingerprint(expected, actual string) (string, error) {
	return verifyFingerprint(expected, actual)
}

func canonicalFingerprint(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) != len("sha256:")+64 || !strings.EqualFold(value[:len("sha256:")], "sha256:") {
		return "", ErrInvalidFingerprint
	}
	digest, err := hex.DecodeString(value[len("sha256:"):])
	if err != nil || len(digest) != 32 {
		return "", ErrInvalidFingerprint
	}

	return "sha256:" + hex.EncodeToString(digest), nil
}

func constantTimeFingerprintEqual(left, right string) bool {
	leftCanonical, leftErr := canonicalFingerprint(left)
	rightCanonical, rightErr := canonicalFingerprint(right)
	if leftErr != nil || rightErr != nil {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(leftCanonical), []byte(rightCanonical)) == 1
}

func validateRegisterOptions(controlURL string, options RegisterOptions) error {
	if _, err := canonicalFingerprint(options.PinnedFingerprint); err != nil {
		return err
	}
	if options.AuthKey != "" && options.FollowupURL != "" {
		return errors.New("ts2021: auth key and browser followup are mutually exclusive")
	}
	if len(options.AuthKey) > maxCredentialBytes || !utf8.ValidString(options.AuthKey) ||
		strings.TrimSpace(options.AuthKey) != options.AuthKey {
		return errors.New("ts2021: auth key format is invalid")
	}
	for _, character := range options.AuthKey {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return errors.New("ts2021: auth key format is invalid")
		}
	}
	if err := validateDisplayText("hostname", options.Hostname, maxHostnameRunes); err != nil {
		return err
	}
	if err := validateDisplayText("version", options.Version, maxVersionRunes); err != nil {
		return err
	}
	if options.FollowupURL != "" {
		if _, err := validateAuthURL(controlURL, options.FollowupURL); err != nil {
			return err
		}
	}

	return nil
}

func validateDisplayText(name, value string, maxRunes int) error {
	if value == "" || strings.TrimSpace(value) != value || !utf8.ValidString(value) ||
		utf8.RuneCountInString(value) > maxRunes {
		return fmt.Errorf("ts2021: %s is invalid", name)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("ts2021: %s contains control characters", name)
		}
	}

	return nil
}

func registrationEndpoint(keyURL *url.URL) *url.URL {
	endpoint := *keyURL
	endpoint.RawQuery = ""
	endpoint.Path = path.Join("/", path.Dir(keyURL.Path), "machine/register")

	return &endpoint
}

func decodeRegistrationResponse(
	response *http.Response,
	controlURL string,
) (RegistrationResult, error) {
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxRegistrationResponseBytes))

		return RegistrationResult{}, fmt.Errorf(
			"%w: control endpoint returned http %d",
			ErrRegistration,
			response.StatusCode,
		)
	}
	if err := validateJSONContentType(response.Header.Get("Content-Type")); err != nil {
		return RegistrationResult{}, fmt.Errorf("%w: %w", ErrRegistration, err)
	}
	if response.ContentLength > maxRegistrationResponseBytes {
		return RegistrationResult{}, fmt.Errorf(
			"%w: response exceeds %d bytes",
			ErrRegistration,
			maxRegistrationResponseBytes,
		)
	}

	encoded, err := io.ReadAll(io.LimitReader(response.Body, maxRegistrationResponseBytes+1))
	if err != nil {
		return RegistrationResult{}, fmt.Errorf("%w: reading response: %w", ErrRegistration, err)
	}
	if len(encoded) > maxRegistrationResponseBytes {
		return RegistrationResult{}, fmt.Errorf(
			"%w: response exceeds %d bytes",
			ErrRegistration,
			maxRegistrationResponseBytes,
		)
	}
	registerResponse := tailcfg.RegisterResponse{}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if err := decoder.Decode(&registerResponse); err != nil {
		return RegistrationResult{}, fmt.Errorf("%w: decoding response: %w", ErrRegistration, err)
	}
	if err := ensureEOF(decoder); err != nil {
		return RegistrationResult{}, fmt.Errorf("%w: response contains trailing data", ErrRegistration)
	}
	if registerResponse.Error != "" {
		return RegistrationResult{}, fmt.Errorf(
			"%w: control server rejected the request: %s",
			ErrRegistration,
			sanitizeServerError(registerResponse.Error),
		)
	}
	if registerResponse.NodeKeyExpired {
		return RegistrationResult{}, ErrNodeKeyExpired
	}
	if registerResponse.MachineAuthorized && registerResponse.AuthURL != "" {
		return RegistrationResult{}, fmt.Errorf(
			"%w: response is both authorized and pending",
			ErrRegistration,
		)
	}
	if registerResponse.MachineAuthorized {
		return RegistrationResult{
			State:             RegistrationStateAuthorized,
			MachineAuthorized: true,
		}, nil
	}
	if registerResponse.AuthURL == "" {
		return RegistrationResult{}, fmt.Errorf(
			"%w: response is neither authorized nor pending",
			ErrRegistration,
		)
	}
	authURL, err := validateAuthURL(controlURL, registerResponse.AuthURL)
	if err != nil {
		return RegistrationResult{}, fmt.Errorf("%w: %w", ErrRegistration, err)
	}

	return RegistrationResult{
		State:   RegistrationStateAuthorizationRequired,
		AuthURL: authURL,
	}, nil
}

func validateAuthURL(controlURL, rawAuthURL string) (string, error) {
	if len(rawAuthURL) > maxCredentialBytes {
		return "", errors.New("ts2021: authorization url is too long")
	}
	controlEndpoint, err := keyEndpoint(controlURL)
	if err != nil {
		return "", err
	}
	control, err := url.Parse(controlEndpoint)
	if err != nil {
		return "", errors.New("ts2021: validated control url could not be parsed")
	}
	auth, err := url.Parse(rawAuthURL)
	if err != nil || auth.Opaque != "" || auth.Scheme != "https" || auth.Hostname() == "" {
		return "", errors.New("ts2021: authorization url must use https")
	}
	if auth.User != nil || auth.Fragment != "" || auth.RawPath != "" || auth.RawQuery != "" {
		return "", errors.New("ts2021: authorization url contains unsupported components")
	}
	if port := auth.Port(); port != "" && port != "443" {
		return "", errors.New("ts2021: authorization url must use port 443")
	}
	if !strings.EqualFold(auth.Hostname(), control.Hostname()) || normalizedPort(auth) != normalizedPort(control) {
		return "", errors.New("ts2021: authorization url must use the control origin")
	}
	if !strings.Contains(auth.EscapedPath(), "/register/") {
		return "", errors.New("ts2021: authorization url has an unexpected path")
	}

	return auth.String(), nil
}

func normalizedPort(value *url.URL) string {
	if value.Port() == "" {
		return "443"
	}

	return value.Port()
}

func sanitizeServerError(value string) string {
	value = strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return -1
		}

		return character
	}, value)
	value = strings.TrimSpace(value)
	runes := []rune(value)
	if len(runes) > maxServerErrorRunes {
		value = string(runes[:maxServerErrorRunes])
	}
	if value == "" {
		return "unspecified error"
	}

	return value
}
