//go:build dexbroker

package dexbroker

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/meshtransit/meshtransit/internal/config"
)

const (
	configurationFingerprintDomain = "meshtransit/identity-runtime-configuration/v2\x00"
	configurationFingerprintPrefix = "sha256-v2:"
	minimumClientSecretBytes       = 32
	maximumStaticConnectors        = 16
	maximumStaticClients           = 16
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
}

// OIDCProviderEndpoints pins the discovery result used by one connector.
// The issuer discovery document is still fetched and issuer-validated, while
// browser authorization, token exchange, and key retrieval cannot redirect
// trust to an endpoint outside this approved set.
type OIDCProviderEndpoints struct {
	DiscoveryURL     string
	AuthorizationURL string
	TokenURL         string
	JWKSURL          string
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
		configuration.connectors = append(configuration.connectors, componentOIDCConnector{
			id: connector.ID, displayName: connector.DisplayName, generation: connector.Generation,
			issuer: connector.Issuer, endpoints: connector.Endpoints,
			clientID: connector.ClientID, clientSecret: secret,
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
			connector.Generation == 0 || !validHTTPSURL(connector.Issuer, false) ||
			!validProviderEndpoints(connector.Issuer, connector.Endpoints) ||
			!validClientID(connector.ClientID) {
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

func validProviderEndpoints(issuer string, endpoints OIDCProviderEndpoints) bool {
	if endpoints.DiscoveryURL != issuer+"/.well-known/openid-configuration" {
		return false
	}
	for _, endpoint := range [...]string{
		endpoints.DiscoveryURL,
		endpoints.AuthorizationURL,
		endpoints.TokenURL,
		endpoints.JWKSURL,
	} {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Port() != "" || !validHTTPSURL(endpoint, true) {
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
