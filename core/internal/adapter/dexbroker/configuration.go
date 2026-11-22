//go:build dexbroker

package dexbroker

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/netip"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"

	"meshtransit.net/core/internal/platform/config"
)

const (
	configurationFingerprintDomain = "meshtransit/identity-runtime-configuration/v2\x00"
	configurationFingerprintPrefix = "sha256-v2:"
	minimumClientSecretBytes       = 32
	maximumStaticConnectors        = 16
	maximumStaticClients           = 16
	// connectorOptionsDomain names the V1-22 connector options in the
	// fingerprint; a connector without options adds nothing.
	connectorOptionsDomain  = "meshtransit/identity-oidc-connector-options/v1\x00"
	maximumConnectorCABytes = 64 * 1024
	maximumPrivateNetworks  = 8
)

var errInvalidConfiguration = errors.New("invalid dex broker immutable configuration")

const redactedConfiguration = "[REDACTED]"

// OIDCConnectorOptions is a product-owned generic-OIDC connector contract.
// It contains no Dex type and keeps the client secret file-backed until start.
type OIDCConnectorOptions struct {
	ID               string
	DisplayName      string
	Generation       uint64
	Issuer           string
	Endpoints        OIDCProviderEndpoints
	ClientID         string
	ClientSecretFile config.SecretFile

	// The options below came with generic OIDC (V1-22). Their zero values
	// are the Google connector's behaviour before them and add nothing to
	// the fingerprint, so an approved Google configuration stays approved.

	// Prompt is what the authorization URL asks of the upstream provider.
	Prompt ConnectorPrompt
	// NameClaim is the claim Dex names the person by (Dex userNameKey);
	// empty: "name".
	NameClaim string
	// EmailMode says whether a missing email_verified claim may pass.
	EmailMode EmailMode
	// TokenAuth pins how the client authenticates at the token endpoint;
	// empty: Dex tries Basic, then the request body.
	TokenAuth TokenAuth
	// CAFile adds a private CA to the system roots for this provider; never
	// a way to skip verification.
	CAFile config.TrustFile
	// PrivateNetworks are the private ranges the provider may be reached in;
	// metadata, loopback, link-local and tunnelled addresses stay refused.
	PrivateNetworks []netip.Prefix
}

// ConnectorPrompt is the prompt the broker puts on the upstream
// authorization URL.
type ConnectorPrompt string

// Upstream prompts.
const (
	// PromptSelectAccount (the zero value) shows the account chooser.
	PromptSelectAccount ConnectorPrompt = ""
	// PromptLogin asks the person to sign in again.
	PromptLogin ConnectorPrompt = "login"
	// PromptOmit adds no prompt: an upstream SSO session signs in silently.
	PromptOmit ConnectorPrompt = "omit"
)

// EmailMode is how far the broker trusts the provider's email claim.
type EmailMode string

// Email modes.
const (
	// EmailRequired (the zero value): the token must say email_verified.
	EmailRequired EmailMode = ""
	// EmailAssume treats a token without email_verified as verified (a
	// single-tenant provider that never sends it, such as Entra).
	EmailAssume EmailMode = "assume"
)

// TokenAuth is the token endpoint client authentication.
type TokenAuth string

// Token endpoint authentications.
const (
	TokenAuthProbe TokenAuth = ""
	TokenAuthBasic TokenAuth = "basic"
	TokenAuthPost  TokenAuth = "post"
)

// OIDCProviderEndpoints pins the discovery result used by one connector.
// The issuer discovery document is still fetched and issuer-validated, while
// browser authorization, token exchange, and key retrieval cannot redirect
// trust to an endpoint outside this approved set.
type OIDCProviderEndpoints struct {
	DiscoveryURL     string
	AuthorizationURL string
	TokenURL         string
	JWKSURL          string
	// UserInfoURL, when set, has Dex read the userinfo endpoint. Dex reads
	// it from discovery, so it must equal the discovery document's; the
	// broker only allows the call.
	UserInfoURL string
}

// ClientOptions is a product-owned confidential broker client contract.
type ClientOptions struct {
	ID          string
	DisplayName string
	Generation  uint64
	SecretFile  config.SecretFile
	RedirectURI string
}

// ConfigurationFingerprint is an approved immutable-configuration digest.
// It is comparable for validation but refuses all ordinary formatting.
type ConfigurationFingerprint [sha256.Size]byte

type componentConfiguration struct {
	connectors []componentOIDCConnector
	clients    []componentClient
}

type componentOIDCConnector struct {
	id           string
	displayName  string
	generation   uint64
	issuer       string
	endpoints    OIDCProviderEndpoints
	clientID     string
	clientSecret string
	prompt       ConnectorPrompt
	nameClaim    string
	emailMode    EmailMode
	tokenAuth    TokenAuth
	caPEM        []byte
	privateNets  []netip.Prefix
}

// hasOptions reports options beyond the pre-V1-22 Google connector.
func (connector componentOIDCConnector) hasOptions() bool {
	return connector.prompt != PromptSelectAccount || connector.nameClaim != "" ||
		connector.emailMode != EmailRequired || connector.tokenAuth != TokenAuthProbe ||
		connector.endpoints.UserInfoURL != "" || len(connector.caPEM) != 0 || len(connector.privateNets) != 0
}

type componentClient struct {
	id          string
	displayName string
	generation  uint64
	secret      string
	redirectURI string
}

// CalculateConfigurationFingerprint reads the bounded secret files and returns
// the stable digest an operator must approve before serving this configuration.
func CalculateConfigurationFingerprint(options ServiceOptions) (string, error) {
	configuration, fingerprint, err := resolveConfiguration(options)
	clearComponentConfiguration(&configuration)
	if err != nil {
		return "", errInvalidConfiguration
	}
	return configurationFingerprintPrefix + hex.EncodeToString(fingerprint[:]), nil
}

func resolveConfiguration(
	options ServiceOptions,
) (componentConfiguration, [sha256.Size]byte, error) {
	if !validFingerprintOptions(options) {
		return componentConfiguration{}, [sha256.Size]byte{}, errInvalidConfiguration
	}
	configuration := componentConfiguration{
		connectors: make([]componentOIDCConnector, 0, len(options.OIDCConnectors)),
		clients:    make([]componentClient, 0, len(options.Clients)),
	}
	for _, connector := range options.OIDCConnectors {
		secret, err := connector.ClientSecretFile.Read()
		if err != nil || len(secret) < minimumClientSecretBytes {
			clearComponentConfiguration(&configuration)
			return componentConfiguration{}, [sha256.Size]byte{}, errInvalidConfiguration
		}
		var caPEM []byte
		if connector.CAFile.IsSet() {
			caPEM, err = connector.CAFile.Read()
			if err != nil || len(caPEM) == 0 || len(caPEM) > maximumConnectorCABytes || !validCAPEM(caPEM) {
				clearComponentConfiguration(&configuration)
				return componentConfiguration{}, [sha256.Size]byte{}, errInvalidConfiguration
			}
		}
		configuration.connectors = append(configuration.connectors, componentOIDCConnector{
			id: connector.ID, displayName: connector.DisplayName, generation: connector.Generation,
			issuer: connector.Issuer, endpoints: connector.Endpoints,
			clientID: connector.ClientID, clientSecret: secret,
			prompt: connector.Prompt, nameClaim: connector.NameClaim, emailMode: connector.EmailMode,
			tokenAuth: connector.TokenAuth, caPEM: caPEM, privateNets: slices.Clone(connector.PrivateNetworks),
		})
	}
	for _, client := range options.Clients {
		secret, err := client.SecretFile.Read()
		if err != nil || len(secret) < minimumClientSecretBytes {
			clearComponentConfiguration(&configuration)
			return componentConfiguration{}, [sha256.Size]byte{}, errInvalidConfiguration
		}
		configuration.clients = append(configuration.clients, componentClient{
			id: client.ID, displayName: client.DisplayName, generation: client.Generation,
			secret: secret, redirectURI: client.RedirectURI,
		})
	}
	return configuration, fingerprintConfiguration(options, configuration), nil
}

func validFingerprintOptions(options ServiceOptions) bool {
	return validIssuer(options.Issuer) &&
		options.IDTokenLifetime > 0 &&
		options.AuthRequestLifetime > 0 &&
		options.SigningKeyRotation > 0 &&
		options.GarbageCollectionInterval > 0 &&
		validConfigurationOptions(options)
}

func fingerprintConfiguration(
	options ServiceOptions,
	configuration componentConfiguration,
) [sha256.Size]byte {
	connectors := slices.Clone(configuration.connectors)
	clients := slices.Clone(configuration.clients)
	slices.SortFunc(connectors, func(left, right componentOIDCConnector) int {
		return strings.Compare(left.id, right.id)
	})
	slices.SortFunc(clients, func(left, right componentClient) int {
		return strings.Compare(left.id, right.id)
	})

	material := make([]byte, 0, 2048)
	material = appendFingerprintField(material, configurationFingerprintDomain)
	material = appendFingerprintField(material, options.Issuer)
	material = appendFingerprintField(material, strconv.FormatInt(int64(options.IDTokenLifetime), 10))
	material = appendFingerprintField(material, strconv.FormatInt(int64(options.AuthRequestLifetime), 10))
	material = appendFingerprintField(material, strconv.FormatInt(int64(options.SigningKeyRotation), 10))
	material = appendFingerprintField(material, strconv.FormatInt(int64(options.GarbageCollectionInterval), 10))
	material = appendFingerprintField(material, authorizationCodeGrant)
	material = appendFingerprintField(material, codeResponseType)
	material = appendFingerprintField(material, "openid profile email")
	material = appendFingerprintField(material, "S256")
	material = appendFingerprintField(material, "prompt="+upstreamAccountPrompt)
	material = appendFingerprintField(material, outboundHTTPPolicyVersion)
	material = appendFingerprintField(material, outboundRequestTimeout.String())
	material = appendFingerprintField(material, outboundDialTimeout.String())
	material = appendFingerprintField(material, outboundTLSHandshakeTimeout.String())
	material = appendFingerprintField(material, outboundResponseHeaderTimeout.String())
	material = appendFingerprintField(material, outboundIdleConnectionTimeout.String())
	material = appendFingerprintUint64(material, uint64(outboundMaxResponseHeaderBytes))
	material = appendFingerprintUint64(material, uint64(outboundMaxConnectionsPerHost))
	material = appendFingerprintUint64(material, uint64(outboundMaxIdleConnections))
	material = appendFingerprintUint64(material, uint64(outboundMaxResolvedIPs))
	material = appendFingerprintUint64(material, uint64(len(connectors)))
	for _, connector := range connectors {
		material = appendFingerprintField(material, connector.id)
		material = appendFingerprintField(material, connector.displayName)
		material = appendFingerprintUint64(material, connector.generation)
		material = appendFingerprintField(material, connector.issuer)
		material = appendFingerprintField(material, connector.endpoints.DiscoveryURL)
		material = appendFingerprintField(material, connector.endpoints.AuthorizationURL)
		material = appendFingerprintField(material, connector.endpoints.TokenURL)
		material = appendFingerprintField(material, connector.endpoints.JWKSURL)
		material = appendFingerprintField(material, connector.clientID)
		material = appendFingerprintField(material, connector.clientSecret)
		material = appendFingerprintField(material, options.Issuer+"/callback")
		if connector.hasOptions() {
			material = appendConnectorOptions(material, connector)
		}
	}
	material = appendFingerprintUint64(material, uint64(len(clients)))
	for _, client := range clients {
		material = appendFingerprintField(material, client.id)
		material = appendFingerprintField(material, client.displayName)
		material = appendFingerprintUint64(material, client.generation)
		material = appendFingerprintField(material, client.secret)
		material = appendFingerprintField(material, client.redirectURI)
	}
	fingerprint := sha256.Sum256(material)
	clear(material)
	return fingerprint
}

// appendConnectorOptions adds the V1-22 options of a connector that has any.
func appendConnectorOptions(material []byte, connector componentOIDCConnector) []byte {
	material = appendFingerprintField(material, connectorOptionsDomain)
	material = appendFingerprintField(material, string(connector.prompt))
	material = appendFingerprintField(material, connector.nameClaim)
	material = appendFingerprintField(material, string(connector.emailMode))
	material = appendFingerprintField(material, string(connector.tokenAuth))
	material = appendFingerprintField(material, connector.endpoints.UserInfoURL)
	caDigest := sha256.Sum256(connector.caPEM)
	if len(connector.caPEM) == 0 {
		caDigest = [sha256.Size]byte{}
	}
	material = append(material, caDigest[:]...)
	material = appendFingerprintUint64(material, uint64(len(connector.privateNets)))
	for _, prefix := range connector.privateNets {
		material = appendFingerprintField(material, prefix.String())
	}
	return material
}

func appendFingerprintField(destination []byte, value string) []byte {
	destination = binary.BigEndian.AppendUint64(destination, uint64(len(value)))
	return append(destination, value...)
}

func appendFingerprintUint64(destination []byte, value uint64) []byte {
	return binary.BigEndian.AppendUint64(destination, value)
}

func fingerprintMatches(expected ConfigurationFingerprint, actual [sha256.Size]byte) bool {
	return subtle.ConstantTimeCompare(expected[:], actual[:]) == 1
}

func validConfigurationOptions(options ServiceOptions) bool {
	connectorCount := len(options.OIDCConnectors)
	clientCount := len(options.Clients)
	if connectorCount == 0 || connectorCount > maximumStaticConnectors ||
		clientCount == 0 || clientCount > maximumStaticClients {
		return false
	}
	connectorIDs := make(map[string]struct{}, connectorCount)
	for _, connector := range options.OIDCConnectors {
		if !validObjectID(connector.ID) || !validDisplayName(connector.DisplayName) ||
			connector.Generation == 0 || !validConnectorIssuer(connector.Issuer) ||
			!validProviderEndpoints(connector.Issuer, connector.Endpoints) ||
			!validClientID(connector.ClientID) || !validConnectorOptions(connector) {
			return false
		}
		if _, exists := connectorIDs[connector.ID]; exists {
			return false
		}
		connectorIDs[connector.ID] = struct{}{}
	}
	clientIDs := make(map[string]struct{}, clientCount)
	for _, client := range options.Clients {
		if !validObjectID(client.ID) || !validDisplayName(client.DisplayName) ||
			client.Generation == 0 || !validHTTPSURL(client.RedirectURI, true) {
			return false
		}
		if _, exists := clientIDs[client.ID]; exists {
			return false
		}
		clientIDs[client.ID] = struct{}{}
	}
	return true
}

// ProviderEndpointsFor pins a provider's endpoints with the discovery URL of
// its issuer. The broker checks them when it starts.
func ProviderEndpointsFor(issuer string, endpoints OIDCProviderEndpoints) OIDCProviderEndpoints {
	endpoints.DiscoveryURL = discoveryURLOf(issuer)
	return endpoints
}

// discoveryURLOf is an issuer's discovery URL: a trailing "/" (Auth0) is
// dropped first, as go-oidc does.
func discoveryURLOf(issuer string) string {
	return strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
}

// validConnectorIssuer accepts an https issuer, with one trailing "/" at
// most, and an explicit port other than 443.
func validConnectorIssuer(issuer string) bool {
	trimmed := strings.TrimSuffix(issuer, "/")
	return validHTTPSURL(trimmed, false) && validEndpointPort(trimmed)
}

// validEndpointPort refuses an explicit :443 (issuer and outbound rules are
// compared as written) and anything but a number from 1 to 65535.
func validEndpointPort(endpoint string) bool {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	port := parsed.Port()
	if port == "" {
		return true
	}
	number, err := strconv.Atoi(port)
	return err == nil && number >= 1 && number <= 65535 && number != 443 && strconv.Itoa(number) == port
}

func validProviderEndpoints(issuer string, endpoints OIDCProviderEndpoints) bool {
	if endpoints.DiscoveryURL != discoveryURLOf(issuer) {
		return false
	}
	urls := []string{endpoints.DiscoveryURL, endpoints.AuthorizationURL, endpoints.TokenURL, endpoints.JWKSURL}
	if endpoints.UserInfoURL != "" {
		urls = append(urls, endpoints.UserInfoURL)
	}
	for _, endpoint := range urls {
		if !validHTTPSURL(endpoint, true) || !validEndpointPort(endpoint) {
			return false
		}
	}
	return true
}

// validConnectorOptions checks the V1-22 options.
func validConnectorOptions(connector OIDCConnectorOptions) bool {
	switch connector.Prompt {
	case PromptSelectAccount, PromptLogin, PromptOmit:
	default:
		return false
	}
	switch connector.EmailMode {
	case EmailRequired, EmailAssume:
	default:
		return false
	}
	switch connector.TokenAuth {
	case TokenAuthProbe, TokenAuthBasic, TokenAuthPost:
	default:
		return false
	}
	if connector.NameClaim != "" && !validClaimName(connector.NameClaim) {
		return false
	}
	if len(connector.PrivateNetworks) > maximumPrivateNetworks {
		return false
	}
	for _, prefix := range connector.PrivateNetworks {
		if !validPrivateNetwork(prefix) {
			return false
		}
	}
	return true
}

// validCAPEM is a bundle of one or more PEM CA certificates and nothing
// else: a private key, a leaf certificate or text between blocks is refused.
func validCAPEM(bundle []byte) bool {
	certificates := 0
	for rest := bytes.TrimSpace(bundle); len(rest) != 0; rest = bytes.TrimSpace(rest) {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
			return false
		}
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return false
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid {
			return false
		}
		certificates++
	}
	return certificates > 0
}

// validClaimName is a plain JSON claim name, such as preferred_username.
func validClaimName(value string) bool {
	if len(value) > 64 || value == "" {
		return false
	}
	for index, character := range value {
		letter := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
		digit := character >= '0' && character <= '9'
		if !letter && (index == 0 || !digit && character != '_' && character != '-' && character != '.') {
			return false
		}
	}
	return true
}

func validObjectID(value string) bool {
	if len(value) == 0 || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value {
		isLower := character >= 'a' && character <= 'z'
		isDigit := character >= '0' && character <= '9'
		if !isLower && !isDigit && character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

func validDisplayName(value string) bool {
	if len(value) == 0 || len(value) > 80 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < ' ' || character == 127 {
			return false
		}
	}
	return true
}

func validClientID(value string) bool {
	if len(value) == 0 || len(value) > 256 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character <= ' ' || character == 127 {
			return false
		}
	}
	return true
}

func validHTTPSURL(value string, requirePath bool) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" {
		return false
	}
	if parsed.Opaque != "" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.RawPath != "" || parsed.Path == "/" ||
		strings.HasSuffix(parsed.Path, "/") {
		return false
	}
	if parsed.Path != "" && path.Clean(parsed.Path) != parsed.Path {
		return false
	}
	return !requirePath || parsed.Path != ""
}

func clearComponentConfiguration(configuration *componentConfiguration) {
	if configuration == nil {
		return
	}
	for index := range configuration.connectors {
		configuration.connectors[index].clientSecret = ""
	}
	for index := range configuration.clients {
		configuration.clients[index].secret = ""
	}
	configuration.connectors = nil
	configuration.clients = nil
}

func configurationGeneration(version uint64) string {
	return strconv.FormatUint(version, 10)
}

// String redacts connector metadata and secret references.
func (OIDCConnectorOptions) String() string { return redactedConfiguration }

// GoString redacts detailed connector formatting.
func (OIDCConnectorOptions) GoString() string { return redactedConfiguration }

// LogValue redacts connector metadata from structured logs.
func (OIDCConnectorOptions) LogValue() slog.Value { return slog.StringValue(redactedConfiguration) }

// MarshalJSON refuses accidental connector publication.
func (OIDCConnectorOptions) MarshalJSON() ([]byte, error) { return nil, ErrInvalidService }

// String redacts the approved provider endpoint set.
func (OIDCProviderEndpoints) String() string { return redactedConfiguration }

// GoString redacts detailed provider endpoint formatting.
func (OIDCProviderEndpoints) GoString() string { return redactedConfiguration }

// LogValue redacts provider endpoints from structured logs.
func (OIDCProviderEndpoints) LogValue() slog.Value { return slog.StringValue(redactedConfiguration) }

// MarshalJSON refuses accidental provider endpoint publication.
func (OIDCProviderEndpoints) MarshalJSON() ([]byte, error) { return nil, ErrInvalidService }

// String redacts confidential client metadata and secret references.
func (ClientOptions) String() string { return redactedConfiguration }

// GoString redacts detailed client formatting.
func (ClientOptions) GoString() string { return redactedConfiguration }

// LogValue redacts client metadata from structured logs.
func (ClientOptions) LogValue() slog.Value { return slog.StringValue(redactedConfiguration) }

// MarshalJSON refuses accidental client publication.
func (ClientOptions) MarshalJSON() ([]byte, error) { return nil, ErrInvalidService }

// String redacts the approved configuration fingerprint.
func (ConfigurationFingerprint) String() string { return redactedConfiguration }

// GoString redacts detailed fingerprint formatting.
func (ConfigurationFingerprint) GoString() string { return redactedConfiguration }

// LogValue redacts the fingerprint from structured logs.
func (ConfigurationFingerprint) LogValue() slog.Value { return slog.StringValue(redactedConfiguration) }

// MarshalJSON refuses accidental fingerprint publication.
func (ConfigurationFingerprint) MarshalJSON() ([]byte, error) { return nil, ErrInvalidService }

var _ json.Marshaler = OIDCConnectorOptions{}
var _ json.Marshaler = OIDCProviderEndpoints{}
var _ json.Marshaler = ClientOptions{}
var _ json.Marshaler = ConfigurationFingerprint{}
