package config

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func genericIdentityValues(overrides map[string]string) map[string]string {
	issuer := "https://sso.example.test:8443/realms/corp"
	values := validIdentityProcessValues(map[string]string{
		envIdentityOIDCConnectorID:               "oidc-0123456789abcdef",
		envIdentityOIDCConnectorDisplayName:      "Corp SSO",
		envIdentityOIDCConnectorIssuer:           issuer,
		envIdentityOIDCConnectorClientID:         "meshtransit",
		envIdentityOIDCConnectorAuthorizationURL: issuer + "/protocol/openid-connect/auth",
		envIdentityOIDCConnectorTokenURL:         issuer + "/protocol/openid-connect/token",
		envIdentityOIDCConnectorJWKSURL:          issuer + "/protocol/openid-connect/certs",
	})
	for key, value := range overrides {
		values[key] = value
	}
	return values
}

func TestLoadIdentityGoogleKeepsZeroConnectorOptions(t *testing.T) {
	t.Parallel()

	for _, values := range []map[string]string{
		validIdentityProcessValues(nil),
		validIdentityProcessValues(map[string]string{
			envIdentityOIDCConnectorAuthorizationURL: identityGoogleAuthorizationURL,
			envIdentityOIDCConnectorTokenURL:         identityGoogleTokenURL,
			envIdentityOIDCConnectorJWKSURL:          identityGoogleJWKSURL,
			envIdentityOIDCConnectorPrompt:           "select_account",
			envIdentityOIDCConnectorEmail:            "required",
		}),
	} {
		cfg, err := Load(mapLookup(values))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		connector := cfg.Identity.OIDCConnectors[0]
		if connector.Endpoints != (IdentityOIDCConnectorEndpoints{}) || connector.Behaviour.Prompt != "" ||
			connector.Behaviour.EmailMode != "" || connector.Behaviour.TokenAuth != "" ||
			connector.Behaviour.NameClaim != "" || connector.Behaviour.CAFile.IsSet() ||
			len(connector.Behaviour.PrivateNetworks) != 0 {
			t.Fatal("Google connector carries generic options")
		}
	}
}

func TestLoadIdentityReadsGenericConnector(t *testing.T) {
	t.Parallel()

	cfg, err := Load(mapLookup(genericIdentityValues(map[string]string{
		envIdentityOIDCConnectorUserInfoURL:     "https://sso.example.test:8443/realms/corp/protocol/openid-connect/userinfo",
		envIdentityOIDCConnectorNameClaim:       "preferred_username",
		envIdentityOIDCConnectorEmail:           "assume",
		envIdentityOIDCConnectorTokenAuth:       "post",
		envIdentityOIDCConnectorPrompt:          "login",
		envIdentityOIDCConnectorCAFile:          "/etc/meshtransit/operator/oidc-ca.pem",
		envIdentityOIDCConnectorPrivateNetworks: "10.20.0.0/16, fd12:3456::/32",
	})))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	connector := cfg.Identity.OIDCConnectors[0]
	behaviour := connector.Behaviour
	if connector.Endpoints.TokenURL != "https://sso.example.test:8443/realms/corp/protocol/openid-connect/token" ||
		connector.Endpoints.UserInfoURL == "" || behaviour.Prompt != "login" || behaviour.EmailMode != "assume" ||
		behaviour.TokenAuth != "post" || behaviour.NameClaim != "preferred_username" || !behaviour.CAFile.IsSet() ||
		len(behaviour.PrivateNetworks) != 2 || behaviour.PrivateNetworks[1] != netip.MustParsePrefix("fd12:3456::/32") {
		t.Fatal("generic connector options mismatch")
	}
	defaults, err := Load(mapLookup(genericIdentityValues(nil)))
	if err != nil || defaults.Identity.OIDCConnectors[0].Behaviour.TokenAuth != "basic" {
		t.Fatalf("generic connector token auth default = %v", err)
	}
	auth0 := "https://tenant.eu.auth0.example/"
	if _, err := Load(mapLookup(genericIdentityValues(map[string]string{
		envIdentityOIDCConnectorIssuer: auth0,
	}))); err != nil {
		t.Fatalf("issuer with trailing slash: %v", err)
	}
}

func TestLoadIdentityRejectsUnsafeGenericConnector(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, key, value string
	}{
		{name: "google other token url", key: envIdentityOIDCConnectorTokenURL, value: "https://evil.example.test/token"},
		{name: "issuer two slashes", key: envIdentityOIDCConnectorIssuer, value: "https://sso.example.test//"},
		{name: "issuer port 443", key: envIdentityOIDCConnectorIssuer, value: "https://sso.example.test:443/realms/corp"},
		{name: "issuer http", key: envIdentityOIDCConnectorIssuer, value: "http://sso.example.test/realms/corp"},
		{name: "entra common", key: envIdentityOIDCConnectorIssuer, value: "https://login.microsoftonline.com/common/v2.0"},
		{name: "entra organizations", key: envIdentityOIDCConnectorIssuer, value: "https://login.microsoftonline.com/Organizations/v2.0"},
		{name: "entra consumer tenant", key: envIdentityOIDCConnectorIssuer, value: "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"},
		{name: "entra other host", key: envIdentityOIDCConnectorIssuer, value: "https://login.microsoft.com/common/v2.0"},
		{name: "entra sts host", key: envIdentityOIDCConnectorIssuer, value: "https://sts.windows.net/consumers/"},
		{name: "google trailing slash", key: envIdentityOIDCConnectorIssuer, value: "https://accounts.google.com/"},
		{name: "google userinfo", key: envIdentityOIDCConnectorUserInfoURL, value: "https://openidconnect.googleapis.com/v1/userinfo"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			values := validIdentityProcessValues(map[string]string{test.key: test.value})
			if _, err := Load(mapLookup(values)); !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), test.value) {
				t.Fatalf("Load() error = %v", err)
			}
		})
	}
	generic := []struct {
		name, key, value string
	}{
		{name: "missing token url", key: envIdentityOIDCConnectorTokenURL, value: ""},
		{name: "token url query", key: envIdentityOIDCConnectorTokenURL, value: "https://sso.example.test/token?x=1"},
		{name: "jwks http", key: envIdentityOIDCConnectorJWKSURL, value: "http://sso.example.test/certs"},
		{name: "auth url port 443", key: envIdentityOIDCConnectorAuthorizationURL, value: "https://sso.example.test:443/auth"},
		{name: "userinfo fragment", key: envIdentityOIDCConnectorUserInfoURL, value: "https://sso.example.test/userinfo#x"},
		{name: "email untrusted", key: envIdentityOIDCConnectorEmail, value: "untrusted"},
		{name: "prompt consent", key: envIdentityOIDCConnectorPrompt, value: "consent"},
		{name: "token auth jwt", key: envIdentityOIDCConnectorTokenAuth, value: "private_key_jwt"},
		{name: "claim space", key: envIdentityOIDCConnectorNameClaim, value: "given name"},
		{name: "relative ca", key: envIdentityOIDCConnectorCAFile, value: "ca.pem"},
		{name: "unmasked cidr", key: envIdentityOIDCConnectorPrivateNetworks, value: "10.20.1.1/16"},
		{name: "public cidr", key: envIdentityOIDCConnectorPrivateNetworks, value: "8.8.8.0/24"},
		{name: "all shared space", key: envIdentityOIDCConnectorPrivateNetworks, value: "100.64.0.0/10"},
		{name: "half shared space", key: envIdentityOIDCConnectorPrivateNetworks, value: "100.64.0.0/11,100.96.0.0/11"},
		{name: "everything", key: envIdentityOIDCConnectorPrivateNetworks, value: "0.0.0.0/0"},
		{name: "duplicate cidr", key: envIdentityOIDCConnectorPrivateNetworks, value: "10.20.0.0/16,10.20.0.0/16"},
		{name: "too many cidrs", key: envIdentityOIDCConnectorPrivateNetworks, value: "10.1.0.0/16,10.2.0.0/16,10.3.0.0/16,10.4.0.0/16,10.5.0.0/16,10.6.0.0/16,10.7.0.0/16,10.8.0.0/16,10.9.0.0/16"},
	}
	for _, test := range generic {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			values := genericIdentityValues(map[string]string{test.key: test.value})
			if test.value == "" {
				delete(values, test.key)
			}
			if _, err := Load(mapLookup(values)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Load() error = %v", err)
			}
		})
	}
}
