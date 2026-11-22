package config

import (
	"net/netip"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
)

// V1-22 generic OIDC connector settings. Every one is optional: a Google
// connector sets none of them and keeps its configuration fingerprint.
const (
	envIdentityOIDCConnectorAuthorizationURL = "MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_AUTHORIZATION_URL"
	envIdentityOIDCConnectorTokenURL         = "MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_TOKEN_URL" //nolint:gosec // G101: environment name, not a credential.
	envIdentityOIDCConnectorJWKSURL          = "MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_JWKS_URL"
	envIdentityOIDCConnectorUserInfoURL      = "MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_USERINFO_URL"
	envIdentityOIDCConnectorNameClaim        = "MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_NAME_CLAIM"
	envIdentityOIDCConnectorEmail            = "MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_EMAIL"
	envIdentityOIDCConnectorTokenAuth        = "MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_TOKEN_AUTH" //nolint:gosec // G101: environment name, not a credential.
	envIdentityOIDCConnectorPrompt           = "MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_PROMPT"
	envIdentityOIDCConnectorCAFile           = "MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_CA_FILE"
	envIdentityOIDCConnectorPrivateNetworks  = "MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_PRIVATE_NETWORK_CIDRS"

	identityGoogleAuthorizationURL = "https://accounts.google.com/o/oauth2/v2/auth"
	identityGoogleTokenURL         = "https://oauth2.googleapis.com/token" //nolint:gosec // Public OIDC endpoint, not a credential.
	identityGoogleJWKSURL          = "https://www.googleapis.com/oauth2/v3/certs"

	maximumIdentityPrivateNetworks = 8
)

// IdentityOIDCConnectorEndpoints are the provider URLs a connector pins.
// They are empty for Google, whose endpoints the broker knows.
type IdentityOIDCConnectorEndpoints struct {
	AuthorizationURL string
	TokenURL         string
	JWKSURL          string
	UserInfoURL      string
}

// IdentityOIDCConnectorBehaviour is how the broker talks to the provider.
// The zero value is the Google behaviour: account chooser, verified email,
// token authentication detected by Dex, the name claim "name".
type IdentityOIDCConnectorBehaviour struct {
	// Prompt is "" (select_account), "login" or "omit".
	Prompt string
	// EmailMode is "" (email_verified required) or "assume".
	EmailMode string
	// TokenAuth is "" (detected), "basic" or "post".
	TokenAuth string
	// NameClaim is the claim that holds the display name; "" is "name".
	NameClaim string
	// CAFile adds a private CA to the provider's TLS roots.
	CAFile TrustFile
	// PrivateNetworks are the private ranges the provider may be reached in.
	PrivateNetworks []netip.Prefix
}

func loadIdentityOIDCConnectorOptions(
	lookup LookupFunc,
	issuer string,
) (IdentityOIDCConnectorEndpoints, IdentityOIDCConnectorBehaviour, error) {
	endpoints, err := loadIdentityOIDCEndpoints(lookup, issuer)
	if err != nil {
		return IdentityOIDCConnectorEndpoints{}, IdentityOIDCConnectorBehaviour{}, err
	}
	behaviour, err := loadIdentityOIDCBehaviour(lookup)
	if err != nil {
		return IdentityOIDCConnectorEndpoints{}, IdentityOIDCConnectorBehaviour{}, err
	}
	if issuer != identityGoogleIssuer && behaviour.TokenAuth == "" {
		// Another provider pins how it receives the client secret: probing
		// would send the authorization code twice (design §2.1).
		behaviour.TokenAuth = "basic"
	}
	return endpoints, behaviour, nil
}

func loadIdentityOIDCEndpoints(lookup LookupFunc, issuer string) (IdentityOIDCConnectorEndpoints, error) {
	settings := []struct {
		key    string
		google string
		value  *string
	}{
		{key: envIdentityOIDCConnectorAuthorizationURL, google: identityGoogleAuthorizationURL},
		{key: envIdentityOIDCConnectorTokenURL, google: identityGoogleTokenURL},
		{key: envIdentityOIDCConnectorJWKSURL, google: identityGoogleJWKSURL},
	}
	var endpoints IdentityOIDCConnectorEndpoints
	settings[0].value, settings[1].value, settings[2].value =
		&endpoints.AuthorizationURL, &endpoints.TokenURL, &endpoints.JWKSURL
	google := issuer == identityGoogleIssuer
	if strings.TrimSuffix(issuer, "/") == identityGoogleIssuer && !google {
		// Google's issuer has no trailing "/": go-oidc would refuse it.
		return IdentityOIDCConnectorEndpoints{}, settingError(envIdentityOIDCConnectorIssuer)
	}
	for _, setting := range settings {
		value, ok := lookup(setting.key)
		switch {
		case google && (!ok || value == setting.google):
			// Google's endpoints are the broker's own; naming them changes nothing.
		case google, !ok:
			return IdentityOIDCConnectorEndpoints{}, settingError(setting.key)
		case validateIdentityProviderURL(value) != nil:
			return IdentityOIDCConnectorEndpoints{}, settingError(setting.key)
		default:
			*setting.value = value
		}
	}
	if value, ok := lookup(envIdentityOIDCConnectorUserInfoURL); ok && value != "" {
		// Google's ID token carries every claim the broker reads.
		if google || validateIdentityProviderURL(value) != nil {
			return IdentityOIDCConnectorEndpoints{}, settingError(envIdentityOIDCConnectorUserInfoURL)
		}
		endpoints.UserInfoURL = value
	}
	return endpoints, nil
}

func loadIdentityOIDCBehaviour(lookup LookupFunc) (IdentityOIDCConnectorBehaviour, error) {
	var behaviour IdentityOIDCConnectorBehaviour
	choices := []struct {
		key     string
		target  *string
		allowed map[string]string
	}{
		{key: envIdentityOIDCConnectorPrompt, target: &behaviour.Prompt,
			allowed: map[string]string{"select_account": "", "login": "login", "omit": "omit"}},
		// "untrusted" (no email) waits for v1.1.
		{key: envIdentityOIDCConnectorEmail, target: &behaviour.EmailMode,
			allowed: map[string]string{"required": "", "assume": "assume"}},
		{key: envIdentityOIDCConnectorTokenAuth, target: &behaviour.TokenAuth,
			allowed: map[string]string{"basic": "basic", "post": "post"}},
	}
	for _, choice := range choices {
		value, ok := lookup(choice.key)
		if !ok || value == "" {
			continue
		}
		normalized, known := choice.allowed[value]
		if !known {
			return IdentityOIDCConnectorBehaviour{}, settingError(choice.key)
		}
		*choice.target = normalized
	}
	if value, ok := lookup(envIdentityOIDCConnectorNameClaim); ok && value != "" {
		if !validIdentityClaimName(value) {
			return IdentityOIDCConnectorBehaviour{}, settingError(envIdentityOIDCConnectorNameClaim)
		}
		behaviour.NameClaim = value
	}
	if value, ok := lookup(envIdentityOIDCConnectorCAFile); ok && value != "" {
		if validateFilePath(value) != nil {
			return IdentityOIDCConnectorBehaviour{}, settingError(envIdentityOIDCConnectorCAFile)
		}
		behaviour.CAFile = TrustFile{path: value}
	}
	if value, ok := lookup(envIdentityOIDCConnectorPrivateNetworks); ok && value != "" {
		networks, err := parseIdentityPrivateNetworks(value)
		if err != nil {
			return IdentityOIDCConnectorBehaviour{}, settingError(envIdentityOIDCConnectorPrivateNetworks)
		}
		behaviour.PrivateNetworks = networks
	}
	return behaviour, nil
}

// identityPrivateRanges are the ranges a connector may list a part of; the
// broker applies the same rule (validPrivateNetwork).
var identityPrivateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

func identityPrivateNetwork(prefix netip.Prefix) bool {
	// 100.64/10 (a mesh overlay or carrier NAT) only by a /16 or narrower.
	if identityPrivateRanges[1].Contains(prefix.Addr()) && prefix.Bits() < 16 {
		return false
	}
	for _, private := range identityPrivateRanges {
		if private.Bits() <= prefix.Bits() && private.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

// parseIdentityPrivateNetworks reads comma-separated masked prefixes, each
// inside a private range.
func parseIdentityPrivateNetworks(value string) ([]netip.Prefix, error) {
	parts := strings.Split(value, ",")
	if len(parts) > maximumIdentityPrivateNetworks {
		return nil, ErrInvalid
	}
	networks := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err != nil || prefix.Masked() != prefix || !identityPrivateNetwork(prefix) {
			return nil, ErrInvalid
		}
		for _, existing := range networks {
			if existing == prefix {
				return nil, ErrInvalid
			}
		}
		networks = append(networks, prefix)
	}
	return networks, nil
}

// microsoftLoginHosts are the Microsoft identity platform's issuer hosts,
// in every cloud.
var microsoftLoginHosts = []string{
	"login.microsoftonline.com", "login.microsoft.com", "sts.windows.net", "login.windows.net",
	"login.microsoftonline.us", "login.partner.microsoftonline.cn", "login.chinacloudapi.cn",
}

// microsoftOpenTenants are tenants anyone can join: the multi-tenant names
// and the personal Microsoft account tenant by its ID.
var microsoftOpenTenants = []string{
	"", "common", "organizations", "consumers", "9188040d-6c67-4c5b-b112-36a304b66dad",
}

// validateConnectorIssuer accepts an https issuer with one trailing "/" at
// most (Auth0) and an explicit port other than 443. A Microsoft issuer must
// name one organisation's tenant.
func validateConnectorIssuer(value string) error {
	trimmed := strings.TrimSuffix(value, "/")
	if validateIdentityIssuer(trimmed) != nil || !validIdentityProviderPort(trimmed) {
		return ErrInvalid
	}
	parsed, _ := url.Parse(trimmed)
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if slices.Contains(microsoftLoginHosts, host) {
		tenant, _, _ := strings.Cut(strings.TrimPrefix(parsed.Path, "/"), "/")
		if slices.Contains(microsoftOpenTenants, strings.ToLower(tenant)) {
			return ErrInvalid
		}
	}
	return nil
}

// validateIdentityProviderURL is an https endpoint with a clean path, no
// query, fragment or user, and an explicit port other than 443.
func validateIdentityProviderURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.Opaque != "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.RawPath != "" || parsed.Path == "" || parsed.Path == "/" ||
		strings.HasSuffix(parsed.Path, "/") || path.Clean(parsed.Path) != parsed.Path ||
		!validIdentityProviderPort(value) {
		return ErrInvalid
	}
	return nil
}

func validIdentityProviderPort(value string) bool {
	parsed, err := url.Parse(value)
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

// validIdentityClaimName is a plain claim name, such as preferred_username.
func validIdentityClaimName(value string) bool {
	if value == "" || len(value) > 64 {
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
