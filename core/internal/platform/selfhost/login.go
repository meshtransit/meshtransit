package selfhost

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"maps"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

// V1-22: the login provider is Google or any OIDC provider
// (v1-22-generic-oidc-design.md §2).
const (
	providerGoogle      = "google"
	providerOIDC        = "oidc"
	googleIssuer        = "https://accounts.google.com"
	googleConnectorID   = "google-v1"
	googleDisplayName   = "Google"
	maximumLoginCIDRs   = 8
	maximumSubjectBytes = 255
)

// Login is the upstream sign-in provider the identity broker federates.
// Google needs only the client; an OIDC provider names its endpoints, which
// "setup check" compares with its discovery document.
type Login struct {
	Provider            string   `yaml:"provider"`
	DisplayName         string   `yaml:"display_name"`
	Issuer              string   `yaml:"issuer"`
	ClientID            string   `yaml:"client_id"`
	ClientSecretFile    string   `yaml:"client_secret_file"`
	AuthorizationURL    string   `yaml:"authorization_url"`
	TokenURL            string   `yaml:"token_url"`
	JWKSURL             string   `yaml:"jwks_url"`
	UserInfoURL         string   `yaml:"userinfo_url"`
	NameClaim           string   `yaml:"name_claim"`
	Email               string   `yaml:"email"`
	TokenAuth           string   `yaml:"token_auth"`
	Prompt              string   `yaml:"prompt"`
	CAFile              string   `yaml:"ca_file"`
	PrivateNetworkCIDRs []string `yaml:"private_network_cidrs"`
}

// issuer is the upstream issuer: Google's, or the one configured.
func (login Login) issuer() string {
	if login.Provider == providerGoogle {
		return googleIssuer
	}
	return login.Issuer
}

func (login Login) displayName() string {
	if login.Provider == providerGoogle {
		return googleDisplayName
	}
	return login.DisplayName
}

// connectorID ties the broker's connector to the issuer: Dex puts it in every
// subject, so another issuer never maps onto the same Accounts. Google keeps
// google-v1 whichever provider names it.
func (login Login) connectorID() string {
	issuer := login.issuer()
	if issuer == googleIssuer {
		return googleConnectorID
	}
	digest := sha256.Sum256([]byte(normalizedIssuer(issuer)))
	return "oidc-" + hex.EncodeToString(digest[:8])
}

// normalizedIssuer lower-cases the scheme and host and drops one trailing
// "/": spellings of one issuer get one connector ID.
func normalizedIssuer(issuer string) string {
	parsed, err := url.Parse(strings.TrimSuffix(issuer, "/"))
	if err != nil {
		return issuer
	}
	parsed.Scheme, parsed.Host = strings.ToLower(parsed.Scheme), strings.ToLower(parsed.Host)
	return parsed.String()
}

func (login Login) validate() error {
	switch login.Provider {
	case providerGoogle:
		return login.validateGoogle()
	case providerOIDC:
		return login.validateOIDC()
	default:
		return invalid("login.provider")
	}
}

func (login Login) validateCommon() error {
	switch {
	case !validValue(login.ClientID, 1, 256) || !safeEnvValue(login.ClientID):
		return invalid("login.client_id")
	case !validPath(login.ClientSecretFile):
		return invalid("login.client_secret_file")
	}
	return nil
}

// validateGoogle refuses the OIDC fields: Google's are fixed.
func (login Login) validateGoogle() error {
	if err := login.validateCommon(); err != nil {
		return err
	}
	fields := map[string]string{
		"login.display_name": login.DisplayName, "login.issuer": login.Issuer,
		"login.authorization_url": login.AuthorizationURL, "login.token_url": login.TokenURL,
		"login.jwks_url": login.JWKSURL, "login.userinfo_url": login.UserInfoURL,
		"login.name_claim": login.NameClaim, "login.email": login.Email, "login.token_auth": login.TokenAuth,
		"login.prompt": login.Prompt, "login.ca_file": login.CAFile,
	}
	for _, field := range slices.Sorted(maps.Keys(fields)) {
		if fields[field] != "" {
			return invalid(field + " (provider oidc only)")
		}
	}
	if len(login.PrivateNetworkCIDRs) != 0 {
		return invalid("login.private_network_cidrs (provider oidc only)")
	}
	return nil
}

// validateOIDC checks the shape of every field; Core's loader and the broker
// check them again in full when setup fingerprints the identity settings.
func (login Login) validateOIDC() error {
	if err := login.validateCommon(); err != nil {
		return err
	}
	checks := []struct {
		field string
		ok    bool
	}{
		{"login.display_name", validValue(login.DisplayName, 1, 80) && safeEnvValue(login.DisplayName)},
		{"login.issuer", httpsURL(strings.TrimSuffix(login.Issuer, "/"), false)},
		{"login.authorization_url", httpsURL(login.AuthorizationURL, true)},
		{"login.token_url", httpsURL(login.TokenURL, true)},
		{"login.jwks_url", httpsURL(login.JWKSURL, true)},
		{"login.userinfo_url", login.UserInfoURL == "" || httpsURL(login.UserInfoURL, true)},
		{"login.name_claim", login.NameClaim == "" || validValue(login.NameClaim, 1, 64) && safeEnvValue(login.NameClaim)},
		{"login.email", slices.Contains([]string{"", "required", "assume"}, login.Email)},
		{"login.token_auth", slices.Contains([]string{"", "basic", "post"}, login.TokenAuth)},
		{"login.prompt", slices.Contains([]string{"", "select_account", "login", "omit"}, login.Prompt)},
		{"login.ca_file", login.CAFile == "" || validPath(login.CAFile)},
		{"login.private_network_cidrs", validLoginCIDRs(login.PrivateNetworkCIDRs)},
	}
	for _, check := range checks {
		if !check.ok {
			return invalid(check.field)
		}
	}
	return nil
}

func httpsURL(value string, requirePath bool) bool {
	parsed, err := url.Parse(value)
	return err == nil && safeEnvValue(value) && validValue(value, 9, 1024) && parsed.Scheme == "https" &&
		parsed.Hostname() != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" &&
		(!requirePath || parsed.Path != "")
}

func validLoginCIDRs(values []string) bool {
	if len(values) > maximumLoginCIDRs {
		return false
	}
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Masked() != prefix || prefix.String() != value {
			return false
		}
	}
	return true
}

// connectorSettings are the identity broker's settings for an OIDC
// provider. Google renders none of them, so its broker fingerprint is the
// one it had before V1-22.
func (login Login) connectorSettings() map[string]string {
	if login.Provider == providerGoogle {
		return map[string]string{}
	}
	settings := map[string]string{
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_AUTHORIZATION_URL": login.AuthorizationURL,
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_TOKEN_URL":         login.TokenURL,
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_JWKS_URL":          login.JWKSURL,
		// The defaults of an OIDC provider: the password asked again,
		// the client secret in the Authorization header.
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_PROMPT":     valueOr(login.Prompt, "login"),
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_TOKEN_AUTH": valueOr(login.TokenAuth, "basic"),
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_EMAIL":      valueOr(login.Email, "required"),
	}
	optional := map[string]string{
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_USERINFO_URL":          login.UserInfoURL,
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_NAME_CLAIM":            login.NameClaim,
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_CA_FILE":               login.CAFile,
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_PRIVATE_NETWORK_CIDRS": strings.Join(login.PrivateNetworkCIDRs, ","),
	}
	for key, value := range optional {
		if value != "" {
			settings[key] = value
		}
	}
	return settings
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// dexSubject is the subject Dex issues for an upstream subject: the
// unpadded base64url of the IDTokenSubject protobuf {user_id: 1,
// conn_id: 2}. Core keys Accounts by this subject, never by the upstream one
// (TD-CORE-160). A test pins it against vectors Dex v2.45.1 produced.
func dexSubject(upstreamSubject, connectorID string) string {
	var message []byte
	message = protowire.AppendTag(message, 1, protowire.BytesType)
	message = protowire.AppendString(message, upstreamSubject)
	message = protowire.AppendTag(message, 2, protowire.BytesType)
	message = protowire.AppendString(message, connectorID)
	return base64.RawURLEncoding.EncodeToString(message)
}

// isDexSubject reports a value that already is a Dex subject of the
// connector: someone who worked around TD-CORE-160 by hand would otherwise
// be encoded twice.
func isDexSubject(value, connectorID string) bool {
	message, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return false
	}
	var connector string
	for len(message) > 0 {
		number, kind, length := protowire.ConsumeTag(message)
		if length < 0 || kind != protowire.BytesType {
			return false
		}
		message = message[length:]
		field, length := protowire.ConsumeString(message)
		if length < 0 {
			return false
		}
		message = message[length:]
		if number == 2 {
			connector = field
		}
	}
	return connector == connectorID
}

// firstAdminSubject is the Dex subject of first_admin.subject, or a reason
// it cannot be one.
func (config Config) firstAdminSubject() (string, error) {
	upstream := config.FirstAdmin.Subject
	connector := config.Login.connectorID()
	if isDexSubject(upstream, connector) {
		return "", invalid("first_admin.subject (give the provider's sub claim, not a MeshTransit subject)")
	}
	subject := dexSubject(upstream, connector)
	if len(subject) > maximumSubjectBytes {
		return "", invalid("first_admin.subject (longer than " + strconv.Itoa(maximumSubjectBytes) +
			" bytes once encoded)")
	}
	return subject, nil
}
