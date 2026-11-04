package selfhost

import (
	"errors"
	"strings"
	"testing"
)

const validConfig = `version: 1
domain: mesh.example.com
acme_email: ops@example.com
login:
  provider: google
  client_id: 1234.apps.googleusercontent.com
  client_secret_file: /etc/meshtransit/google-client-secret
first_admin:
  subject: "110169484474386276334"
  display_name: Ada Admin
  workspace: Example
relay:
  public_ipv4: 203.0.113.10
`

func TestParseConfigDerivesHosts(t *testing.T) {
	t.Parallel()
	config, err := ParseConfig([]byte(validConfig))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if config.Domain != "mesh.example.com" || config.IdentityHost() != "id.mesh.example.com" ||
		config.Login.ClientID != "1234.apps.googleusercontent.com" || config.Relay.PublicIPv4.String() != "203.0.113.10" {
		t.Fatalf("config = %+v", config)
	}
	if config.Mail != nil || len(config.Advanced) != 0 {
		t.Fatalf("absent sections = %+v, %+v", config.Mail, config.Advanced)
	}
	withHost, err := ParseConfig([]byte(validConfig + "identity_host: login.example.net\n"))
	if err != nil || withHost.IdentityHost() != "login.example.net" {
		t.Fatalf("identity_host override = %q, %v", withHost.IdentityHost(), err)
	}
}

func TestParseConfigRefusesUnsafeOrUnknownInput(t *testing.T) {
	t.Parallel()
	for name, text := range map[string]string{
		"unknown field":       validConfig + "domian: typo.example.com\n",
		"no version":          strings.Replace(validConfig, "version: 1\n", "", 1),
		"future version":      strings.Replace(validConfig, "version: 1", "version: 2", 1),
		"anchor and alias":    validConfig + "mail: &m {from: a@example.com}\nadvanced: *m\n",
		"merge key":           strings.Replace(validConfig, "relay:\n", "relay:\n  <<: {public_ipv4: 203.0.113.11}\n", 1),
		"two documents":       validConfig + "---\nversion: 1\n",
		"bad domain":          strings.Replace(validConfig, "mesh.example.com", "mesh_example", 1),
		"domain with scheme":  strings.Replace(validConfig, "mesh.example.com", "https://mesh.example.com", 1),
		"identity host equal": validConfig + "identity_host: mesh.example.com\n",
		"other provider":      strings.Replace(validConfig, "provider: google", "provider: okta", 1),
		"relative secret":     strings.Replace(validConfig, "/etc/meshtransit/google-client-secret", "google-secret", 1),
		"secret elsewhere":    strings.Replace(validConfig, "/etc/meshtransit/google-client-secret", "/root/google-secret", 1),
		"private relay ip":    strings.Replace(validConfig, "203.0.113.10", "10.0.0.5", 1),
		"no admin subject":    strings.Replace(validConfig, "  subject: \"110169484474386276334\"\n", "", 1),
		"advanced derived":    validConfig + "advanced:\n  MESHTRANSIT_IDENTITY_ISSUER: https://x.example.com\n",
		"advanced secret":     validConfig + "advanced:\n  MESHTRANSIT_REDIS_PASSWORD_FILE: /tmp/p\n",
		"advanced unknown":    validConfig + "advanced:\n  PATH: /bin\n",
		"advanced trust":      validConfig + "advanced:\n  MESHTRANSIT_FLOWLOG_TOKEN_PUBLIC_KEYS: x\n",
		"advanced expansion":  validConfig + "advanced:\n  MESHTRANSIT_LOG_LEVEL: $HOME\n",
		"client id quote":     strings.Replace(validConfig, "client_id: 1234", "client_id: \"a'b\"\n  # ", 1),
		"too large":           validConfig + "# " + strings.Repeat("x", maximumConfigBytes) + "\n",
	} {
		if _, err := ParseConfig([]byte(text)); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: ParseConfig() error = %v, want ErrInvalidConfig", name, err)
		}
	}
}

func TestParseConfigAcceptsAdvancedTunables(t *testing.T) {
	t.Parallel()
	config, err := ParseConfig([]byte(validConfig + "advanced:\n  MESHTRANSIT_LOG_LEVEL: debug\n"))
	if err != nil || config.Advanced["MESHTRANSIT_LOG_LEVEL"] != "debug" {
		t.Fatalf("advanced = %v, %v", config.Advanced, err)
	}
}

func TestSampleConfigParses(t *testing.T) {
	t.Parallel()
	if _, err := ParseConfig(SampleConfig()); err != nil {
		t.Fatalf("SampleConfig() does not parse: %v", err)
	}
}
