package main

import (
	"testing"

	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/core/internal/platform/selfhost"
)

// TestSetupOIDCLoginRendersSettingsCoreAccepts checks that what setup
// renders for an OIDC provider passes Core's identity loader unchanged.
func TestSetupOIDCLoginRendersSettingsCoreAccepts(t *testing.T) {
	text := `version: 1
domain: mesh.example.com
login:
  provider: oidc
  display_name: Corp SSO
  issuer: https://sso.example.test:8443/realms/corp
  client_id: meshtransit
  client_secret_file: /etc/meshtransit/oidc-client-secret
  authorization_url: https://sso.example.test:8443/realms/corp/protocol/openid-connect/auth
  token_url: https://sso.example.test:8443/realms/corp/protocol/openid-connect/token
  jwks_url: https://sso.example.test:8443/realms/corp/protocol/openid-connect/certs
  userinfo_url: https://sso.example.test:8443/realms/corp/protocol/openid-connect/userinfo
  name_claim: preferred_username
  email: assume
  token_auth: post
  prompt: omit
  ca_file: /etc/meshtransit/oidc-ca.pem
  private_network_cidrs: [10.20.0.0/16, fd12:3456::/32]
first_admin:
  subject: "4f2c0d4e-0000-4000-8000-000000000001"
  display_name: Ada Admin
  workspace: Example
relay:
  public_ipv4: 203.0.113.10
images:
  core: meshtransit/mesh-core:dexbroker-test
  console: meshtransit/mesh-console:test
  relay: meshtransit/mesh-relay:test
`
	parsed, err := selfhost.ParseConfig([]byte(text))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	state := selfhost.State{ConnectorGeneration: 1, CoreClientGeneration: 1}
	layout := selfhost.Layout{SecretsDir: "/var/lib/meshtransit/secrets", RunDir: "/var/lib/meshtransit/run"} //nolint:gosec // directory paths, no secret
	settings := selfhost.IdentitySettings(parsed, state, layout)
	identity, err := config.LoadIdentityFingerprintInput(settingsLookup(settings))
	if err != nil {
		t.Fatalf("LoadIdentityFingerprintInput() error = %v", err)
	}
	connector := identity.OIDCConnectors[0]
	behaviour := connector.Behaviour
	if connector.Issuer != "https://sso.example.test:8443/realms/corp" || connector.Endpoints.UserInfoURL == "" ||
		behaviour.Prompt != "omit" || behaviour.EmailMode != "assume" || behaviour.TokenAuth != "post" ||
		behaviour.NameClaim != "preferred_username" || !behaviour.CAFile.IsSet() || len(behaviour.PrivateNetworks) != 2 {
		t.Fatal("rendered OIDC settings lost an option")
	}
}
