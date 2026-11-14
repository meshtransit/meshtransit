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
	relayUDPPort     = 3479
	relaySTUNPort    = 3478
	relaySTUNAltPort = 3480
)

// Rendered is every file render produces, by name under Layout.RunDir.
type Rendered struct {
	Files map[string][]byte
}

// IdentityFingerprint computes the broker's configuration fingerprint from
// identity settings (meshcore identity fingerprint, which needs the
// dexbroker build): the setup command passes it in.
type IdentityFingerprint func(settings map[string]string) (string, error)

// controlKeyLifetime rolls the control key a year from every answer, so an
// install never reaches its expiry (auto-renewal design §2.2).
const controlKeyLifetime = "8760h"

// Render produces the processes' settings and files from config.yaml, the
// generated secrets and state.json. It reads nothing and writes nothing:
// the same inputs give the same output.
func Render(config Config, state State, keys PublicKeys, layout Layout) (Rendered, error) {
	if state.IdentityFingerprint == "" {
		return Rendered{}, ErrIdentityNotApproved
	}
	if !state.publicNamesMatch(config) {
		return Rendered{}, ErrPublicNamesChanged
	}
	if !filepath.IsAbs(layout.SecretsDir) || !filepath.IsAbs(layout.RunDir) {
		return Rendered{}, fmt.Errorf("%w: layout paths must be absolute", ErrInvalidConfig)
	}
	if !strings.HasPrefix(keys.Relay, "mtrelay:") || !strings.HasPrefix(keys.Signing, "mtsign:") {
		return Rendered{}, fmt.Errorf("%w: relay public keys", ErrInvalidConfig)
	}
	relayMap, err := relayMapJSON(config, keys)
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
	relayDigest := sha256.Sum256(relayMap)
	core := coreSettings(config, state, layout, "sha256:"+hex.EncodeToString(relayDigest[:]))
	migrator := migratorSettings(layout)
	// Bootstrap runs as the api role with the migrator, never the superuser;
	// the api role refuses the relay authority's settings.
	bootstrap := mergeSettings(withoutPrefix(core, "MESHTRANSIT_RELAY_"), migrator, map[string]string{
		"MESHTRANSIT_ROLE":                "api",
		"MESHTRANSIT_BOOTSTRAP_PLAN_FILE": filepath.Join(layout.RunDir, "bootstrap-plan.json"),
	})
	files := map[string][]byte{
		"private-login.json":  login,
		"relay-map.json":      relayMap,
		"bootstrap-plan.json": plan,
	}
	for name, settings := range map[string]map[string]string{
		"core.env": core, "migrate.env": mergeSettings(migrator, operatorSettings(layout)), "bootstrap.env": bootstrap,
		"identity-migrate.env": identityMigratorSettings(layout), "relay.env": relaySettings(config, keys, layout),
	} {
		contents, err := envFile(settings)
		if err != nil {
			return Rendered{}, fmt.Errorf("%s: %w", name, err)
		}
		files[name] = contents
	}
	envFiles := []string{"migrate.env", "bootstrap.env", "identity-migrate.env"}
	migrateSettings := mergeSettings(bootstrap, migrator, operatorSettings(layout), identityMigratorSettings(layout))
	mounts := serviceMounts{
		core: pathsIn(layout, core, loginFiles(layout)),
		migrate: pathsIn(layout, migrateSettings, loginFiles(layout),
			runPaths(layout, envFiles), loginPasswordFiles(layout)),
	}
	connections, err := postgresConnections(core)
	if err != nil {
		return Rendered{}, err
	}
	bundle, err := composeFiles(config, layout, mounts, connections)
	if err != nil {
		return Rendered{}, err
	}
	for name, contents := range bundle {
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
		"MESHTRANSIT_IDENTITY_POSTGRES_RUNTIME_USER":             IdentityRuntimeRole,
		"MESHTRANSIT_IDENTITY_POSTGRES_RUNTIME_PASSWORD_FILE":    secret("identity-runtime-password"),
		"MESHTRANSIT_IDENTITY_POSTGRES_CA_FILE":                  secret("ca.crt"),
	}
}

func issuer(config Config) string        { return "https://" + config.IdentityHost() + "/oauth2" }
func consoleOrigin(config Config) string { return "https://" + config.Domain }

// postgresConnections is the bundled PostgreSQL's max_connections: every
// pool Core may open (after advanced:) plus room for setup migrate,
// bootstrap and an operator's psql. A higher value only costs a little
// shared memory; a lower one would refuse Core's own pools.
func postgresConnections(core map[string]string) (int, error) {
	total := postgresReserved
	for _, name := range []string{
		"MESHTRANSIT_POSTGRES_RUNTIME_MAX_CONNECTIONS",
		"MESHTRANSIT_POSTGRES_WORKER_MAX_CONNECTIONS",
		"MESHTRANSIT_IDENTITY_POSTGRES_MAX_OPEN_CONNECTIONS",
	} {
		value, err := strconv.Atoi(core[name])
		if err != nil || value < 1 || value > 50 {
			return 0, fmt.Errorf("%w: %s must be 1 to 50", ErrInvalidConfig, name)
		}
		total += value
	}
	return total, nil
}

// postgresReserved are connections beyond Core's pools: migrate's
// migrator and superuser, bootstrap, the broker's migration and an
// operator's psql.
const postgresReserved = 10

// onePostgresBudget are the connection pools of the one-server installation.
var onePostgresBudget = map[string]string{
	"MESHTRANSIT_POSTGRES_RUNTIME_MAX_CONNECTIONS":       "4",
	"MESHTRANSIT_POSTGRES_WORKER_MAX_CONNECTIONS":        "2",
	"MESHTRANSIT_IDENTITY_POSTGRES_MAX_OPEN_CONNECTIONS": "4",
	"MESHTRANSIT_IDENTITY_POSTGRES_MAX_IDLE_CONNECTIONS": "2",
}

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
		"MESHTRANSIT_RELAY_AUTHORITY_ENABLED":                    "true",
		"MESHTRANSIT_RELAY_SIGNING_KEY_FILE":                     secret("relay-signing.key"),
		"MESHTRANSIT_RELAY_MAP_FILE":                             filepath.Join(layout.RunDir, "relay-map.json"),
		"MESHTRANSIT_RELAY_MAP_SHA256":                           relayDigest,
		"MESHTRANSIT_RELAY_TRUSTED_PROXY_CIDRS":                  trustedProxy,
		"MESHTRANSIT_RELAY_DEPLOYMENT_PUBLIC_ID":                 state.DeploymentID,
		"MESHTRANSIT_ENROLLMENT_DIGEST_ACTIVE_KEY_ID":            "enrollment-v1",
		"MESHTRANSIT_ENROLLMENT_DIGEST_ACTIVE_KEY_FILE":          secret("enrollment-digest.key"),
		"MESHTRANSIT_CONTROL_ADDRESS":                            controlAddress,
		"MESHTRANSIT_CONTROL_TLS_CERTIFICATE_FILE":               secret("control.crt"),
		"MESHTRANSIT_CONTROL_TLS_PRIVATE_KEY_FILE":               secret("control.key"),
		"MESHTRANSIT_CONTROL_NOISE_PRIVATE_KEY_FILE":             secret("control-noise.key"),
		"MESHTRANSIT_CONTROL_MTCP_KEY_LIFETIME":                  controlKeyLifetime,
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
	// One server: each hot backend holds 30–45 MiB of compiled functions and
	// plans (docs: database-capacity.md), so the pools are sized for it:
	// 4 runtime + 2 worker + 4 broker connections at most. `advanced:` may
	// raise them for a larger server.
	for name, value := range onePostgresBudget {
		settings[name] = value
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

// IdentityRuntimeRole is the broker database's runtime role, which setup
// migrate grants data access after migrating the broker's schema.
const IdentityRuntimeRole = "identity_runtime"

// identityMigratorSettings migrate the broker's own database with its
// migration identity, the database's owner (setup migrate).
func identityMigratorSettings(layout Layout) map[string]string {
	secret := func(name string) string { return filepath.Join(layout.SecretsDir, name) }
	return map[string]string{
		"MESHTRANSIT_MIGRATION_POSTGRES_ADDRESS":       postgresAddress,
		"MESHTRANSIT_MIGRATION_POSTGRES_DATABASE":      identityDatabase,
		"MESHTRANSIT_MIGRATION_POSTGRES_USER":          "identity_migrator",
		"MESHTRANSIT_MIGRATION_POSTGRES_PASSWORD_FILE": secret("identity-migrator-password"),
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

// relayMapJSON is the relay authority's map (deployment.md "Relays"): the
// one relay on this server, by its public key. The revision stays 1 while
// the relay does not change.
func relayMapJSON(config Config, keys PublicKeys) ([]byte, error) {
	type node struct {
		Name        string `json:"name"`
		HostName    string `json:"host_name"`
		IPv4        string `json:"ipv4"`
		IPv6        string `json:"ipv6,omitempty"`
		Key         string `json:"key"`
		UDPPort     int    `json:"udp_port"`
		TLSPort     int    `json:"tls_port,omitempty"`
		STUNPort    int    `json:"stun_port"`
		STUNAltPort int    `json:"stun_alt_port"`
		Weight      int    `json:"weight"`
	}
	type region struct {
		ID    int    `json:"id"`
		Code  string `json:"code"`
		Name  string `json:"name"`
		Nodes []node `json:"nodes"`
	}
	relay := node{
		Name: "own1", HostName: config.Domain, IPv4: config.Relay.PublicIPv4.String(), Key: keys.Relay,
		UDPPort: relayUDPPort, STUNPort: relaySTUNPort, STUNAltPort: relaySTUNAltPort,
		Weight: 100,
	}
	if config.Relay.PublicIPv6.IsValid() {
		relay.IPv6 = config.Relay.PublicIPv6.String()
	}
	return marshal(struct {
		SchemaVersion int      `json:"schema_version"`
		Revision      int      `json:"revision"`
		Regions       []region `json:"regions"`
	}{SchemaVersion: 1, Revision: 1, Regions: []region{{ID: 1, Code: "own", Name: "Self-hosted", Nodes: []node{relay}}}})
}

// relaySettings run the relay on this server ("meshrelay serve", every flag
// as MESHRELAY_<FLAG>). It trusts Core's relay signing key and polls Core
// through the public name. It serves UDP and STUN only: the public proxy
// owns TCP 443 and keeps its certificate keys to itself, so the TLS
// fallback waits for a later slice (TD-CORE-135).
func relaySettings(config Config, keys PublicKeys, layout Layout) map[string]string {
	settings := map[string]string{
		"MESHRELAY_KEY_FILE":             filepath.Join(layout.SecretsDir, "relay.key"),
		"MESHRELAY_TRUSTED_SIGNING_KEYS": keys.Signing,
		"MESHRELAY_CORE_URL":             consoleOrigin(config),
		"MESHRELAY_PUBLIC_IP":            config.Relay.PublicIPv4.String(),
		"MESHRELAY_UDP":                  "0.0.0.0:" + strconv.Itoa(relayUDPPort),
		"MESHRELAY_STUN":                 "0.0.0.0:" + strconv.Itoa(relaySTUNPort),
		"MESHRELAY_STUN_ALT":             "0.0.0.0:" + strconv.Itoa(relaySTUNAltPort),
	}
	if config.Relay.PublicIPv6.IsValid() {
		settings["MESHRELAY_PUBLIC_IPV6"] = config.Relay.PublicIPv6.String()
	}
	return settings
}

// loginKeyPurposes are the login profile's purpose keys.
var loginKeyPurposes = []string{"initiation", "capture", "continuation", "management_csrf",
	"transaction_digest", "verifier_encryption", "subject_active", "provider_session"}

func loginProfileJSON(config Config, state State, layout Layout) ([]byte, error) {
	secret := func(name string) string { return filepath.Join(layout.SecretsDir, name) }
	type key struct {
		ID   string `json:"id"`
		File string `json:"file"`
	}
	keys := map[string]key{}
	for _, purpose := range loginKeyPurposes {
		file := "login-" + strings.ReplaceAll(purpose, "_", "-") + ".key"
		keys[purpose] = key{ID: strings.ReplaceAll(purpose, "_", "-") + "-v1", File: secret(file)}
	}
	base := issuer(config)
	profile := map[string]any{
		"version": 4, "address": loginAddress, "origin": consoleOrigin(config),
		// The proxy sends browser registration here, the Console the rest.
		"trusted_proxy_prefixes": []string{trustedProxy, consoleAddress + "/32"},
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

// loginFiles are the files the login profile names.
func loginFiles(layout Layout) []string {
	files := []string{"login.crt", "login.key", "login-client-secret"}
	for _, purpose := range loginKeyPurposes {
		files = append(files, "login-"+strings.ReplaceAll(purpose, "_", "-")+".key")
	}
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, filepath.Join(layout.SecretsDir, file))
	}
	return paths
}

func runPaths(layout Layout, names []string) []string {
	paths := make([]string, 0, len(names))
	for _, name := range names {
		paths = append(paths, filepath.Join(layout.RunDir, name))
	}
	return paths
}

// pathsIn are the setup-owned files the settings name (values under the
// secrets or run directory) plus extra, sorted and without repeats: the
// files a container needs and may see.
func pathsIn(layout Layout, settings map[string]string, extra ...[]string) []string {
	var paths []string
	for _, value := range settings {
		if strings.HasPrefix(value, layout.SecretsDir+"/") || strings.HasPrefix(value, layout.RunDir+"/") {
			paths = append(paths, value)
		}
	}
	for _, more := range extra {
		paths = append(paths, more...)
	}
	slices.Sort(paths)
	return slices.Compact(paths)
}

func withoutPrefix(settings map[string]string, prefix string) map[string]string {
	kept := make(map[string]string, len(settings))
	for name, value := range settings {
		if !strings.HasPrefix(name, prefix) {
			kept[name] = value
		}
	}
	return kept
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
