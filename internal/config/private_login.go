package config

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/meshtransit/meshtransit/internal/app"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const envPrivateLoginConfigFile = "MESHTRANSIT_PRIVATE_LOGIN_CONFIG_FILE"

// PrivateLoginFile is an opt-in operator reference, not public SSO enablement.
type PrivateLoginFile struct{ file SecretFile }

// PrivateLoginConfig owns one immutable direct-TLS backend and browser origin.
// There are no setters, replacement ports or qualification-waiver flags.
type PrivateLoginConfig struct {
	address, origin                string
	trustedProxyPrefixes           []netip.Prefix
	route                          oidcauth.Route
	keys                           *PrivateIdentityKeyFiles
	cert, privateKey, clientSecret SecretFile
	source                         privateLoginFileSnapshot
}

func loadPrivateLoginFile(lookup LookupFunc, role app.Role) (*PrivateLoginFile, error) {
	value, present := lookup(envPrivateLoginConfigFile)
	if !present {
		return nil, nil
	}
	if role != app.RoleAPI && role != app.RoleAll {
		return nil, settingError(envPrivateLoginConfigFile)
	}
	file, err := NewSecretFile(value)
	if err != nil || len(value) > 4096 {
		return nil, settingError(envPrivateLoginConfigFile)
	}
	return &PrivateLoginFile{file: file}, nil
}

// Load explicitly reads one bounded protected candidate before dependency or
// listener startup. File/provider details never cross this diagnostic boundary.
func (reference *PrivateLoginFile) Load(ctx context.Context, process Config) (*PrivateLoginConfig, error) {
	validRole := process.Role == app.RoleAPI || process.Role == app.RoleAll
	if reference == nil || ctx == nil || ctx.Err() != nil || !validRole || process.API == nil {
		return nil, settingError(envPrivateLoginConfigFile)
	}
	ctx, cancel := context.WithTimeout(ctx, privateIdentityKeyTimeout)
	defer cancel()
	contents, snapshot, err := readPrivateLoginFileSnapshot(ctx, reference.file, 16*1024)
	if err != nil {
		return nil, settingError(envPrivateLoginConfigFile)
	}
	defer clear(contents)
	result, err := parsePrivateLoginConfig(contents, process)
	if err != nil || ctx.Err() != nil {
		return nil, settingError(envPrivateLoginConfigFile)
	}
	result.source = snapshot
	return result, nil
}

func parsePrivateLoginConfig(contents []byte, process Config) (*PrivateLoginConfig, error) {
	if len(contents) == 0 || len(contents) > 16*1024 || process.API == nil {
		return nil, ErrInvalid
	}
	fields, err := privateLoginObject(contents, []string{
		"version", "address", "origin", "trusted_proxy_prefixes",
		"deployment_id", "workspace_id", "provider_id", "client_id",
		"provider_generation", "recovery_epoch", "issuer", "discovery_uri", "authorization_endpoint",
		"token_endpoint", "jwks_uri", "oidc_client_id", "redirect_id", "return_route_id",
		"tls_certificate_file", "tls_private_key_file", "client_secret_file", "keys",
	})
	if err != nil {
		return nil, ErrInvalid
	}
	var version int
	if !privateLoginField(fields, "version", &version) || version != 1 && version != 2 {
		return nil, ErrInvalid
	}
	expectedFields := 20
	if version == 2 {
		expectedFields = 22
	}
	if len(fields) != expectedFields {
		return nil, ErrInvalid
	}
	result := &PrivateLoginConfig{}
	if !privateLoginField(fields, "address", &result.address) {
		return nil, ErrInvalid
	}
	address, err := netip.ParseAddrPort(result.address)
	validBind := err == nil && address.String() == result.address && address.Port() != 0
	allowedBind := address.Addr().IsLoopback() ||
		version == 2 && (address.Addr().IsPrivate() || address.Addr().IsUnspecified())
	if !validBind || !allowedBind || address.Addr().Is4In6() || address.Addr().Zone() != "" {
		return nil, ErrInvalid
	}
	if addressesConflict(result.address, process.HealthAddress) || addressesConflict(result.address, process.API.Address) {
		return nil, ErrInvalid
	}
	if process.Control != nil && addressesConflict(result.address, process.Control.Address) {
		return nil, ErrInvalid
	}
	if version == 1 {
		result.origin = "https://" + result.address
	} else if !privateLoginField(fields, "origin", &result.origin) || !validPrivateLoginOrigin(result.origin) {
		return nil, ErrInvalid
	}
	if version == 2 {
		var prefixes []string
		if !privateLoginField(fields, "trusted_proxy_prefixes", &prefixes) {
			return nil, ErrInvalid
		}
		result.trustedProxyPrefixes, err = parsePrivateLoginTrustedProxyPrefixes(prefixes)
		if err != nil {
			return nil, ErrInvalid
		}
	}
	params := oidcauth.RouteParams{
		ClientKind: "confidential", ClientAuthMethod: "client_secret_basic",
		Scopes: []string{"openid"}, AllowedAlgorithms: []string{"RS256"},
		RedirectURI: result.Origin() + "/auth/v1/callback",
	}
	var dep, work, provider, client string
	for _, field := range []struct {
		name        string
		destination *string
	}{
		{name: "deployment_id", destination: &dep}, {name: "workspace_id", destination: &work},
		{name: "provider_id", destination: &provider}, {name: "client_id", destination: &client},
		{name: "issuer", destination: &params.Issuer}, {name: "discovery_uri", destination: &params.DiscoveryURI},
		{name: "authorization_endpoint", destination: &params.AuthorizationEndpoint},
		{name: "token_endpoint", destination: &params.TokenEndpoint}, {name: "jwks_uri", destination: &params.JWKSURI},
		{name: "oidc_client_id", destination: &params.OIDCClientID}, {name: "redirect_id", destination: &params.RedirectID},
		{name: "return_route_id", destination: &params.ReturnRouteID},
	} {
		if !privateLoginField(fields, field.name, field.destination) {
			return nil, ErrInvalid
		}
	}
	params.DeploymentID, err = deployment.ParseID(dep)
	if err != nil {
		return nil, ErrInvalid
	}
	params.WorkspaceID, err = workspace.ParseID(work)
	if err != nil {
		return nil, ErrInvalid
	}
	params.ProviderID, err = oidcauth.ParseProviderID(provider)
	if err != nil {
		return nil, ErrInvalid
	}
	params.ClientID, err = oidcauth.ParseClientID(client)
	if err != nil {
		return nil, ErrInvalid
	}
	if !privateLoginField(fields, "provider_generation", &params.ProviderGeneration) ||
		!privateLoginField(fields, "recovery_epoch", &params.RecoveryEpoch) {
		return nil, ErrInvalid
	}
	result.route, err = oidcauth.NewRoute(params)
	if err != nil {
		return nil, ErrInvalid
	}
	if version == 2 {
		issuer, issuerErr := url.Parse(result.route.Issuer())
		origin, originErr := url.Parse(result.origin)
		if issuerErr != nil || originErr != nil || strings.EqualFold(issuer.Hostname(), origin.Hostname()) {
			return nil, ErrInvalid
		}
	}
	for _, field := range []struct {
		name        string
		destination *SecretFile
	}{
		{name: "tls_certificate_file", destination: &result.cert},
		{name: "tls_private_key_file", destination: &result.privateKey},
		{name: "client_secret_file", destination: &result.clientSecret},
	} {
		var path string
		if !privateLoginField(fields, field.name, &path) || len(path) > 4096 {
			return nil, ErrInvalid
		}
		*field.destination, err = NewSecretFile(path)
		if err != nil {
			return nil, ErrInvalid
		}
	}
	result.keys, err = privateLoginKeys(fields["keys"], *process.API)
	if err != nil || !result.validOwnership(process) {
		return nil, ErrInvalid
	}
	return result, nil
}

func privateLoginKeys(contents []byte, api APIConfig) (*PrivateIdentityKeyFiles, error) {
	fields, err := privateLoginObject(contents, []string{
		"initiation", "capture", "continuation", "management_csrf", "transaction_digest",
		"verifier_encryption", "subject_active", "subject_previous", "provider_session",
	})
	if err != nil {
		return nil, ErrInvalid
	}
	options := PrivateIdentityKeyOptions{
		SessionActive: ResidentKeyFile{
			ID: api.AccountSessionDigest.Active.ID.String(), File: api.AccountSessionDigest.Active.MaterialFile,
		},
		Idempotency: ResidentKeyFile{ID: api.IdempotencyDigest.ID.String(), File: api.IdempotencyDigest.MaterialFile},
		RateLimit:   ResidentKeyFile{ID: api.RateLimitDigest.ID.String(), File: api.RateLimitDigest.MaterialFile},
	}
	if api.AccountSessionDigest.Previous != nil {
		options.SessionPrevious = &ResidentKeyFile{ID: api.AccountSessionDigest.Previous.ID.String(),
			File: api.AccountSessionDigest.Previous.MaterialFile}
	}
	for _, field := range []struct {
		name        string
		destination *ResidentKeyFile
	}{
		{name: "initiation", destination: &options.Initiation}, {name: "capture", destination: &options.Capture},
		{name: "continuation", destination: &options.Continuation},
		{name: "management_csrf", destination: &options.ManagementCSRF},
		{name: "transaction_digest", destination: &options.TransactionDigest},
		{name: "verifier_encryption", destination: &options.VerifierEncryption},
		{name: "subject_active", destination: &options.SubjectActive},
		{name: "provider_session", destination: &options.ProviderSession},
	} {
		*field.destination, err = privateLoginKey(fields[field.name])
		if err != nil {
			return nil, ErrInvalid
		}
	}
	if raw, present := fields["subject_previous"]; present {
		key, keyErr := privateLoginKey(raw)
		if keyErr != nil {
			return nil, ErrInvalid
		}
		options.SubjectPrevious = &key
	}
	return NewPrivateIdentityKeyFiles(options)
}

func privateLoginKey(contents []byte) (ResidentKeyFile, error) {
	fields, err := privateLoginObject(contents, []string{"id", "file"})
	var id, path string
	complete := err == nil && len(fields) == 2
	if !complete || !privateLoginField(fields, "id", &id) || !privateLoginField(fields, "file", &path) {
		return ResidentKeyFile{}, ErrInvalid
	}
	file, err := NewSecretFile(path)
	if err != nil {
		return ResidentKeyFile{}, ErrInvalid
	}
	return ResidentKeyFile{ID: id, File: file}, nil
}

// Exact names and object members are checked before typed decoding; encoding/json
// alone accepts duplicate fields, case aliases and null into scalar destinations.
func privateLoginObject(contents []byte, allowed []string) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, ErrInvalid
	}
	fields := make(map[string]json.RawMessage, len(allowed))
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok || !slices.Contains(allowed, name) {
			return nil, ErrInvalid
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, ErrInvalid
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, ErrInvalid
		}
		fields[name] = raw
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, ErrInvalid
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return nil, ErrInvalid
	}
	return fields, nil
}

func privateLoginField(fields map[string]json.RawMessage, name string, destination any) bool {
	raw, present := fields[name]
	return present && json.Unmarshal(raw, destination) == nil
}

func validPrivateLoginOrigin(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Host != parsed.Hostname() ||
		parsed.User != nil || parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" ||
		parsed.Opaque != "" || parsed.Fragment != "" || parsed.RawFragment != "" || parsed.ForceQuery {
		return false
	}
	hostname := parsed.Hostname()
	if hostname != strings.ToLower(hostname) || !strings.Contains(hostname, ".") || !validHost(hostname) {
		return false
	}
	_, err = netip.ParseAddr(hostname)
	return err != nil && parsed.String() == value
}

func parsePrivateLoginTrustedProxyPrefixes(values []string) ([]netip.Prefix, error) {
	if len(values) == 0 || len(values) > 16 {
		return nil, ErrInvalid
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		trustedAddress := err == nil && (prefix.Addr().IsLoopback() || prefix.Addr().IsPrivate())
		invalid := err != nil || !prefix.IsValid() || prefix.String() != value || prefix != prefix.Masked() ||
			!trustedAddress || prefix.Bits() == 0 || prefix.Addr().Is4In6() || prefix.Addr().Zone() != ""
		if invalid || slices.Contains(prefixes, prefix) {
			return nil, ErrInvalid
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func (profile *PrivateLoginConfig) validOwnership(process Config) bool {
	owned := []SecretFile{profile.cert, profile.privateKey, profile.clientSecret}
	for _, key := range profile.keys.keys {
		if key != (ResidentKeyFile{}) {
			owned = append(owned, key.File)
		}
	}
	for index, file := range owned {
		if slices.Contains(owned[:index], file) {
			return false
		}
	}
	external := []SecretFile{{path: process.API.TLSPrivateKeyFile.path}}
	if process.Control != nil {
		external = append(external,
			SecretFile{path: process.Control.TLSPrivateKeyFile.path}, process.Control.NoisePrivateKeyFile,
		)
	}
	if process.Enrollment != nil {
		for _, key := range profile.keys.keys {
			currentAlias := key.ID == process.Enrollment.CredentialDigest.Active.ID.String()
			previous := process.Enrollment.CredentialDigest.Previous
			previousAlias := previous != nil && key.ID == previous.ID.String()
			if currentAlias || previousAlias {
				return false
			}
		}
		external = append(external, process.Enrollment.CredentialDigest.Active.MaterialFile)
		if process.Enrollment.CredentialDigest.Previous != nil {
			external = append(external, process.Enrollment.CredentialDigest.Previous.MaterialFile)
		}
	}
	if process.Storage != nil {
		external = append(external, process.Storage.Redis.PasswordFile)
		if process.Storage.PostgreSQL.Runtime != nil {
			external = append(external, process.Storage.PostgreSQL.Runtime.PasswordFile)
		}
		if process.Storage.PostgreSQL.Worker != nil {
			external = append(external, process.Storage.PostgreSQL.Worker.PasswordFile)
		}
	}
	for _, file := range external {
		if file != (SecretFile{}) && slices.Contains(owned, file) {
			return false
		}
	}
	return true
}

// Address returns the explicit canonical backend socket address.
func (profile *PrivateLoginConfig) Address() string { return profile.address }

// Origin returns the exact same-origin TLS authority, not an operator redirect.
func (profile *PrivateLoginConfig) Origin() string { return profile.origin }

// TrustedProxyPrefixes returns a defensive copy of the exact public-edge peers.
func (profile *PrivateLoginConfig) TrustedProxyPrefixes() []netip.Prefix {
	return slices.Clone(profile.trustedProxyPrefixes)
}

// Route returns the immutable Core-controlled trust decision.
func (profile *PrivateLoginConfig) Route() oidcauth.Route { return profile.route }

// Keys returns the immutable complete purpose-owned file bundle.
func (profile *PrivateLoginConfig) Keys() *PrivateIdentityKeyFiles { return profile.keys }

// String redacts the operator reference.
func (PrivateLoginFile) String() string { return redactedValue }

// GoString redacts the operator reference under Go-syntax formatting.
func (PrivateLoginFile) GoString() string { return redactedValue }

// LogValue redacts the operator reference in structured logs.
func (PrivateLoginFile) LogValue() slog.Value { return slog.StringValue(redactedValue) }

// MarshalJSON refuses serialization of the operator reference.
func (PrivateLoginFile) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// String redacts the complete private profile.
func (PrivateLoginConfig) String() string { return redactedValue }

// GoString redacts the complete private profile under Go-syntax formatting.
func (PrivateLoginConfig) GoString() string { return redactedValue }

// LogValue redacts the complete private profile in structured logs.
func (PrivateLoginConfig) LogValue() slog.Value { return slog.StringValue(redactedValue) }

// MarshalJSON refuses serialization of the complete private profile.
func (PrivateLoginConfig) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
