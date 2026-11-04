package selfhost

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrIdentityNotApproved means state.json holds no approved identity
	// fingerprint yet: run "setup approve-identity" (setup apply does it once).
	ErrIdentityNotApproved = errors.New("self-host identity configuration not approved")
	// ErrPublicNamesChanged means domain or identity_host moved after the
	// first approval: the issuer, origin and redirect are in the database
	// since bootstrap, and changing them is not supported.
	ErrPublicNamesChanged = errors.New("self-host domain or identity host changed after installation")
	// ErrUnsafeValue means a rendered setting holds characters env files
	// would change.
	ErrUnsafeValue = errors.New("self-host setting is not safe in an env file")
)

// Layout is where the files live. The setup command and every container
// mount the same host paths at the same paths, so one path is right on both
// sides.
type Layout struct {
	SecretsDir string // generated secrets and state.json
	RunDir     string // rendered files
}

// The server's private network (compose) and the listeners inside the
// meshcore container. Only the public proxy's fixed address is a trusted
// proxy: the bridge gateway and every other container are not, so nothing
// but the proxy can claim a client address.
const (
	privateSubnet    = "172.30.0.0/24" // the compose network (S2)
	proxyAddress     = "172.30.0.10"
	trustedProxy     = proxyAddress + "/32"
	healthAddress    = "0.0.0.0:8081"
	controlAddress   = "0.0.0.0:8443"
	apiAddress       = "0.0.0.0:8444"
	loginAddress     = "0.0.0.0:9443"
	identityAddress  = "0.0.0.0:9444"
	postgresAddress  = "postgres." + internalDomain + ":5432"
	redisAddress     = "redis." + internalDomain + ":6379"
	coreDatabase     = "meshtransit"
	identityDatabase = "meshtransit_identity"
	connectorID      = "google-v1"
	coreClientID     = "meshtransit-console"
	relayTLSPort     = 4443
)

// Rendered is every file render produces, by name under Layout.RunDir.
type Rendered struct {
	Files map[string][]byte
}

// IdentityFingerprint computes the broker's configuration fingerprint from
// identity settings (meshcore identity fingerprint, which needs the
// dexbroker build): the setup command passes it in.
type IdentityFingerprint func(settings map[string]string) (string, error)

// Render produces the processes' settings and files from config.yaml, the
// generated secrets and state.json. It reads nothing and writes nothing:
// the same inputs give the same output.
func Render(config Config, state State, layout Layout) (Rendered, error) {
	if state.IdentityFingerprint == "" {
		return Rendered{}, ErrIdentityNotApproved
	}
	if !state.publicNamesMatch(config) {
		return Rendered{}, ErrPublicNamesChanged
	}
	if !filepath.IsAbs(layout.SecretsDir) || !filepath.IsAbs(layout.RunDir) {
		return Rendered{}, fmt.Errorf("%w: layout paths must be absolute", ErrInvalidConfig)
	}
	relayDirectory, err := relayDirectoryJSON(config)
	if err != nil {
		return Rendered{}, err
	}
	login, err := loginProfileJSON(config, state, layout)
	if err != nil {
		return Rendered{}, err
	}
	plan, err := bootstrapPlanJSON(config)
	if err != nil {
		return Rendered{}, err
	}
	relayDigest := sha256.Sum256(relayDirectory)
	core := coreSettings(config, state, layout, "sha256:"+hex.EncodeToString(relayDigest[:]))
	migrator := migratorSettings(layout)
	// Bootstrap needs the migrator, never the superuser.
	bootstrap := mergeSettings(core, migrator, map[string]string{
		"MESHTRANSIT_ROLE":                "api",
		"MESHTRANSIT_BOOTSTRAP_PLAN_FILE": filepath.Join(layout.RunDir, "bootstrap-plan.json"),
	})
	files := map[string][]byte{
		"private-login.json":   login,
		"relay-directory.json": relayDirectory,
		"bootstrap-plan.json":  plan,
	}
	for name, settings := range map[string]map[string]string{
		"core.env": core, "migrate.env": mergeSettings(migrator, operatorSettings(layout)), "bootstrap.env": bootstrap,
	} {
		contents, err := envFile(settings)
		if err != nil {
			return Rendered{}, fmt.Errorf("%s: %w", name, err)
		}
		files[name] = contents
	}
	return Rendered{Files: files}, nil
}

// IdentitySettings are the identity broker's settings without the pinned
// fingerprint: what "setup approve-identity" fingerprints.
func IdentitySettings(config Config, state State, layout Layout) map[string]string {
	secret := func(name string) string { return filepath.Join(layout.SecretsDir, name) }
	return map[string]string{
		"MESHTRANSIT_ROLE":                                       "identity",
		"MESHTRANSIT_IDENTITY_ISSUER":                            issuer(config),
		"MESHTRANSIT_IDENTITY_ADDRESS":                           identityAddress,
		"MESHTRANSIT_IDENTITY_TLS_CERTIFICATE_FILE":              secret("identity.crt"),
		"MESHTRANSIT_IDENTITY_TLS_PRIVATE_KEY_FILE":              secret("identity.key"),
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_ID":                 connectorID,
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_DISPLAY_NAME":       "Google",
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_GENERATION":         strconv.FormatInt(state.ConnectorGeneration, 10),
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_ISSUER":             "https://accounts.google.com",
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_CLIENT_ID":          config.Login.ClientID,
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_CLIENT_SECRET_FILE": config.Login.ClientSecretFile,
		"MESHTRANSIT_IDENTITY_CORE_CLIENT_ID":                    coreClientID,
		"MESHTRANSIT_IDENTITY_CORE_CLIENT_DISPLAY_NAME":          "MeshTransit Console",
		"MESHTRANSIT_IDENTITY_CORE_CLIENT_GENERATION":            strconv.FormatInt(state.CoreClientGeneration, 10),
		"MESHTRANSIT_IDENTITY_CORE_CLIENT_SECRET_FILE":           secret("identity-core-client-secret"),
		"MESHTRANSIT_IDENTITY_CORE_CLIENT_REDIRECT_URI":          consoleOrigin(config) + "/auth/v1/callback",
		"MESHTRANSIT_IDENTITY_POSTGRES_ADDRESS":                  postgresAddress,
		"MESHTRANSIT_IDENTITY_POSTGRES_DATABASE":                 identityDatabase,
		"MESHTRANSIT_IDENTITY_POSTGRES_RUNTIME_USER":             "identity_runtime",
		"MESHTRANSIT_IDENTITY_POSTGRES_RUNTIME_PASSWORD_FILE":    secret("identity-runtime-password"),
		"MESHTRANSIT_IDENTITY_POSTGRES_CA_FILE":                  secret("ca.crt"),
	}
}

func issuer(config Config) string        { return "https://" + config.IdentityHost() + "/oauth2" }
func consoleOrigin(config Config) string { return "https://" + config.Domain }

func coreSettings(config Config, state State, layout Layout, relayDigest string) map[string]string {
	secret := func(name string) string { return filepath.Join(layout.SecretsDir, name) }
	denied := relayPrefixes(config)
	settings := map[string]string{
		"MESHTRANSIT_ROLE":                                       "all",
		"MESHTRANSIT_HEALTH_ADDRESS":                             healthAddress,
		"MESHTRANSIT_POSTGRES_ADDRESS":                           postgresAddress,
		"MESHTRANSIT_POSTGRES_DATABASE":                          coreDatabase,
		"MESHTRANSIT_POSTGRES_CA_FILE":                           secret("ca.crt"),
		"MESHTRANSIT_POSTGRES_RUNTIME_USER":                      "mesh_runtime",
		"MESHTRANSIT_POSTGRES_RUNTIME_PASSWORD_FILE":             secret("postgres-runtime-password"),
		"MESHTRANSIT_POSTGRES_WORKER_USER":                       "mesh_worker",
		"MESHTRANSIT_POSTGRES_WORKER_PASSWORD_FILE":              secret("postgres-worker-password"),
		"MESHTRANSIT_REDIS_ADDRESS":                              redisAddress,
		"MESHTRANSIT_REDIS_USERNAME":                             "meshtransit",
		"MESHTRANSIT_REDIS_PASSWORD_FILE":                        secret("redis-password"),
		"MESHTRANSIT_REDIS_CA_FILE":                              secret("ca.crt"),
		"MESHTRANSIT_RELAY_DIRECTORY_FILE":                       filepath.Join(layout.RunDir, "relay-directory.json"),
		"MESHTRANSIT_RELAY_DIRECTORY_SHA256":                     relayDigest,
		"MESHTRANSIT_ENROLLMENT_DIGEST_ACTIVE_KEY_ID":            "enrollment-v1",
		"MESHTRANSIT_ENROLLMENT_DIGEST_ACTIVE_KEY_FILE":          secret("enrollment-digest.key"),
		"MESHTRANSIT_CONTROL_ADDRESS":                            controlAddress,
		"MESHTRANSIT_CONTROL_TLS_CERTIFICATE_FILE":               secret("control.crt"),
		"MESHTRANSIT_CONTROL_TLS_PRIVATE_KEY_FILE":               secret("control.key"),
		"MESHTRANSIT_CONTROL_NOISE_PRIVATE_KEY_FILE":             secret("control-noise.key"),
		"MESHTRANSIT_CONTROL_MTCP_KEY_NOT_AFTER":                 state.MTCPKeyNotAfter.UTC().Format(time.RFC3339),
		"MESHTRANSIT_CONTROL_MTCP_TRUSTED_PROXY_CIDRS":           trustedProxy,
		"MESHTRANSIT_CONTROL_MTCP_DENIED_ENDPOINT_CIDRS":         denied,
		"MESHTRANSIT_SITE_DENIED_CIDRS":                          denied,
		"MESHTRANSIT_DNS_PROTECTED_NAMES":                        config.Domain + "," + config.IdentityHost(),
		"MESHTRANSIT_API_ADDRESS":                                apiAddress,
		"MESHTRANSIT_API_TLS_CERTIFICATE_FILE":                   secret("api.crt"),
		"MESHTRANSIT_API_TLS_PRIVATE_KEY_FILE":                   secret("api.key"),
		"MESHTRANSIT_API_TRUSTED_PROXY_CIDRS":                    trustedProxy,
		"MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_ACTIVE_KEY_ID":   "account-session-v1",
		"MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_ACTIVE_KEY_FILE": secret("account-session-digest.key"),
		"MESHTRANSIT_API_IDEMPOTENCY_DIGEST_KEY_ID":              "idempotency-v1",
		"MESHTRANSIT_API_IDEMPOTENCY_DIGEST_KEY_FILE":            secret("idempotency-digest.key"),
		"MESHTRANSIT_API_RATE_LIMIT_DIGEST_KEY_ID":               "rate-limit-v1",
		"MESHTRANSIT_API_RATE_LIMIT_DIGEST_KEY_FILE":             secret("rate-limit-digest.key"),
		"MESHTRANSIT_PRIVATE_LOGIN_CONFIG_FILE":                  filepath.Join(layout.RunDir, "private-login.json"),
		"MESHTRANSIT_BROWSER_REGISTRATION_ORIGIN":                consoleOrigin(config),
		"MESHTRANSIT_BROWSER_REGISTRATION_DEPLOYMENT_ID":         state.DeploymentID,
		"MESHTRANSIT_BROWSER_REGISTRATION_RECOVERY_EPOCH":        strconv.FormatInt(state.RecoveryEpoch, 10),
		"MESHTRANSIT_BROWSER_REGISTRATION_KEY_ID":                "browser-v1",
		"MESHTRANSIT_BROWSER_REGISTRATION_KEY_FILE":              secret("browser-registration.key"),
		"MESHTRANSIT_IDENTITY_CONFIGURATION_FINGERPRINT":         state.IdentityFingerprint,
	}
	if mail := config.Mail; mail != nil {
		settings["MESHTRANSIT_MAIL_TRANSPORT"] = "smtp"
		settings["MESHTRANSIT_MAIL_FROM"] = mail.From
		settings["MESHTRANSIT_MAIL_SMTP_HOST"] = mail.SMTP.Host
		settings["MESHTRANSIT_MAIL_SMTP_PORT"] = strconv.Itoa(mail.SMTP.Port)
		settings["MESHTRANSIT_MAIL_SMTP_TLS"] = mail.SMTP.TLS
		if mail.SMTP.Username != "" {
			settings["MESHTRANSIT_MAIL_SMTP_USERNAME"] = mail.SMTP.Username
			settings["MESHTRANSIT_MAIL_SMTP_PASSWORD_FILE"] = mail.SMTP.PasswordFile
		}
	}
	identity := IdentitySettings(config, state, layout)
	delete(identity, "MESHTRANSIT_ROLE")
	return mergeSettings(settings, identity, config.Advanced)
}

// migratorSettings run "migrate" and bootstrap.
func migratorSettings(layout Layout) map[string]string {
	secret := func(name string) string { return filepath.Join(layout.SecretsDir, name) }
	return map[string]string{
		"MESHTRANSIT_MIGRATION_POSTGRES_ADDRESS":       postgresAddress,
		"MESHTRANSIT_MIGRATION_POSTGRES_DATABASE":      coreDatabase,
		"MESHTRANSIT_MIGRATION_POSTGRES_USER":          "mesh_migrator",
		"MESHTRANSIT_MIGRATION_POSTGRES_PASSWORD_FILE": secret("postgres-migrator-password"),
		"MESHTRANSIT_MIGRATION_POSTGRES_CA_FILE":       secret("ca.crt"),
		"MESHTRANSIT_MIGRATION_ACTOR":                  "setup",
	}
}

// operatorSettings run "migrate operator" as the bundled PostgreSQL's
// superuser; only migrate.env holds them.
func operatorSettings(layout Layout) map[string]string {
	secret := func(name string) string { return filepath.Join(layout.SecretsDir, name) }
	return map[string]string{
		"MESHTRANSIT_OPERATOR_POSTGRES_ADDRESS":       postgresAddress,
		"MESHTRANSIT_OPERATOR_POSTGRES_DATABASE":      coreDatabase,
		"MESHTRANSIT_OPERATOR_POSTGRES_USER":          "postgres",
		"MESHTRANSIT_OPERATOR_POSTGRES_PASSWORD_FILE": secret("postgres-superuser-password"),
		"MESHTRANSIT_OPERATOR_POSTGRES_CA_FILE":       secret("ca.crt"),
	}
}

// relayPrefixes are the relay's addresses, which no Site may cover and no
// endpoint report may carry.
func relayPrefixes(config Config) string {
	prefixes := []string{netip.PrefixFrom(config.Relay.PublicIPv4, 32).String()}
	if config.Relay.PublicIPv6.IsValid() {
		prefixes = append(prefixes, netip.PrefixFrom(config.Relay.PublicIPv6, 128).String())
	}
	return strings.Join(prefixes, ",")
}

func relayDirectoryJSON(config Config) ([]byte, error) {
	ipv6 := ""
	if config.Relay.PublicIPv6.IsValid() {
		ipv6 = config.Relay.PublicIPv6.String()
	}
	type node struct {
		Name      string `json:"name"`
		HostName  string `json:"host_name"`
		CertName  string `json:"cert_name"`
		IPv4      string `json:"ipv4"`
		IPv6      string `json:"ipv6"`
		STUNPort  int    `json:"stun_port"`
		RelayPort int    `json:"relay_port"`
		STUNOnly  bool   `json:"stun_only"`
	}
	type region struct {
		ID    int    `json:"id"`
		Code  string `json:"code"`
		Name  string `json:"name"`
		Nodes []node `json:"nodes"`
	}
	directory := struct {
		SchemaVersion int      `json:"schema_version"`
		Revision      int      `json:"revision"`
		Regions       []region `json:"regions"`
	}{SchemaVersion: 1, Revision: 1, Regions: []region{{ID: 1, Code: "own", Name: "Self-hosted", Nodes: []node{{
		Name: "1a", HostName: config.Domain, IPv4: config.Relay.PublicIPv4.String(), IPv6: ipv6,
		STUNPort: 3478, RelayPort: relayTLSPort,
	}}}}}
	return marshal(directory)
}

func loginProfileJSON(config Config, state State, layout Layout) ([]byte, error) {
	secret := func(name string) string { return filepath.Join(layout.SecretsDir, name) }
	type key struct {
		ID   string `json:"id"`
		File string `json:"file"`
	}
	keys := map[string]key{}
	for _, purpose := range []string{"initiation", "capture", "continuation", "management_csrf",
		"transaction_digest", "verifier_encryption", "subject_active", "provider_session"} {
		file := "login-" + strings.ReplaceAll(purpose, "_", "-") + ".key"
		keys[purpose] = key{ID: strings.ReplaceAll(purpose, "_", "-") + "-v1", File: secret(file)}
	}
	base := issuer(config)
	profile := map[string]any{
		"version": 4, "address": loginAddress, "origin": consoleOrigin(config),
		"trusted_proxy_prefixes": []string{trustedProxy},
		"deployment_id":          state.DeploymentID, "provider_id": state.ProviderID, "client_id": state.ClientID,
		"provider_generation": state.ProviderGeneration, "recovery_epoch": state.RecoveryEpoch,
		"issuer": base, "discovery_uri": base + "/.well-known/openid-configuration",
		"authorization_endpoint": base + "/auth", "token_endpoint": base + "/token", "jwks_uri": base + "/keys",
		"oidc_client_id": coreClientID, "redirect_id": "console-callback", "return_route_id": "console",
		"connector_id": connectorID, "scopes": []string{"openid", "email", "federated:id"},
		"tls_certificate_file": secret("login.crt"), "tls_private_key_file": secret("login.key"),
		"client_secret_file": secret("login-client-secret"), "keys": keys,
	}
	return marshal(profile)
}

func bootstrapPlanJSON(config Config) ([]byte, error) {
	return marshal(map[string]any{
		"format": "meshtransit-bootstrap/v1", "profile": "self_hosted",
		"accounts": []map[string]string{{
			"subject": config.FirstAdmin.Subject, "display_name": config.FirstAdmin.DisplayName,
			"workspace_name": config.FirstAdmin.Workspace,
		}},
	})
}

func marshal(value any) ([]byte, error) {
	contents, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	return append(contents, '\n'), nil
}

func mergeSettings(layers ...map[string]string) map[string]string {
	merged := map[string]string{}
	for _, layer := range layers {
		for name, value := range layer {
			merged[name] = value
		}
	}
	return merged
}

// envFile writes NAME=value lines in name order, the format compose's
// env_file reads, refusing any value it would change.
func envFile(settings map[string]string) ([]byte, error) {
	names := make([]string, 0, len(settings))
	for name := range settings {
		names = append(names, name)
	}
	slices.Sort(names)
	var builder strings.Builder
	for _, name := range names {
		if !safeEnvValue(settings[name]) {
			return nil, fmt.Errorf("%w: %s", ErrUnsafeValue, name)
		}
		builder.WriteString(name + "=" + settings[name] + "\n")
	}
	return []byte(builder.String()), nil
}
