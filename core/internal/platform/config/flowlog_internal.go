package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"log/slog"
	"net/url"
	"strings"

	"meshtransit.net/core/internal/platform/app"
)

const (
	envFlowLogInternalAddr     = "MESHTRANSIT_FLOWLOG_INTERNAL_ADDR"
	envFlowLogInternalCertFile = "MESHTRANSIT_FLOWLOG_INTERNAL_TLS_CERT_FILE"
	envFlowLogInternalKeyFile  = "MESHTRANSIT_FLOWLOG_INTERNAL_TLS_KEY_FILE"
	envFlowLogInternalClientCA = "MESHTRANSIT_FLOWLOG_INTERNAL_CLIENT_CA_FILE"
	envFlowLogInternalClientID = "MESHTRANSIT_FLOWLOG_INTERNAL_CLIENT_URI"
	envFlowLogTokenPublicKeys  = "MESHTRANSIT_FLOWLOG_TOKEN_PUBLIC_KEYS"

	maxFlowTokenPublicKeys = 4
)

// Token key states (connection logs design C45).
const (
	FlowTokenKeyCurrent  = "current"
	FlowTokenKeyNext     = "next"
	FlowTokenKeyRetiring = "retiring"
	FlowTokenKeyRevoked  = "revoked"
)

// FlowTokenPublicKey is one public token signing key and its state.
type FlowTokenPublicKey struct {
	State string
	Key   ed25519.PublicKey
}

// FlowLogInternalConfig opens Core's internal API to the connection log
// receiver (connection logs design §16c, C38, C45): a listener only for the
// receiver, over TLS 1.3 with a client certificate from the receiver's own
// CA naming ClientURI. The certificate, key and CA files are read again
// while serving, so they rotate without a restart. TokenKeys are the public
// halves of the control role's token signing keys: the api role never holds
// the private ones.
type FlowLogInternalConfig struct {
	Address      string
	CertFile     string
	KeyFile      string
	ClientCAFile string
	ClientURI    *url.URL
	TokenKeys    []FlowTokenPublicKey
}

// String redacts the configuration in generic formatting.
func (FlowLogInternalConfig) String() string { return redactedValue }

// GoString redacts detailed formatting.
func (FlowLogInternalConfig) GoString() string { return "config.FlowLogInternalConfig([REDACTED])" }

// LogValue redacts structured formatting.
func (FlowLogInternalConfig) LogValue() slog.Value { return slog.StringValue(redactedValue) }

// loadFlowLogInternalConfig is all-or-nothing and only for roles that serve
// the management API.
func loadFlowLogInternalConfig(lookup LookupFunc, role app.Role) (*FlowLogInternalConfig, error) {
	names := []string{
		envFlowLogInternalAddr, envFlowLogInternalCertFile, envFlowLogInternalKeyFile, envFlowLogInternalClientCA,
		envFlowLogInternalClientID, envFlowLogTokenPublicKeys,
	}
	values := make(map[string]string, len(names))
	for _, name := range names {
		if value, present := lookup(name); present {
			values[name] = value
		}
	}
	if len(values) == 0 {
		return nil, nil
	}
	for _, name := range names {
		if _, present := values[name]; !present {
			return nil, settingError(name)
		}
	}
	if role != app.RoleAPI && role != app.RoleAll {
		return nil, settingError(envFlowLogInternalAddr)
	}
	if validateAddress(values[envFlowLogInternalAddr]) != nil {
		return nil, settingError(envFlowLogInternalAddr)
	}
	for _, name := range []string{envFlowLogInternalCertFile, envFlowLogInternalKeyFile, envFlowLogInternalClientCA} {
		if validateFilePath(values[name]) != nil {
			return nil, settingError(name)
		}
	}
	clientURI, ok := parseFlowLogClientURI(values[envFlowLogInternalClientID])
	if !ok {
		return nil, settingError(envFlowLogInternalClientID)
	}
	keys, ok := parseFlowTokenPublicKeys(values[envFlowLogTokenPublicKeys])
	if !ok {
		return nil, settingError(envFlowLogTokenPublicKeys)
	}
	return &FlowLogInternalConfig{
		Address: values[envFlowLogInternalAddr], CertFile: values[envFlowLogInternalCertFile],
		KeyFile: values[envFlowLogInternalKeyFile], ClientCAFile: values[envFlowLogInternalClientCA],
		ClientURI: clientURI, TokenKeys: keys,
	}, nil
}

// parseFlowLogClientURI reads the receiver's identity: a spiffe URI with a
// lowercase trust domain and the path /meshflow, nothing else (C38).
func parseFlowLogClientURI(text string) (*url.URL, bool) {
	if len(text) > 256 || strings.TrimSpace(text) != text {
		return nil, false
	}
	parsed, err := url.Parse(text)
	if err != nil || parsed.Scheme != "spiffe" || parsed.Host == "" || parsed.Host != strings.ToLower(parsed.Host) ||
		parsed.Path != "/meshflow" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Port() != "" ||
		parsed.String() != text {
		return nil, false
	}
	return parsed, true
}

// parseFlowTokenPublicKeys reads "state=key,…": one to four Ed25519 public
// keys in base64url without padding, exactly one current, none twice.
func parseFlowTokenPublicKeys(text string) ([]FlowTokenPublicKey, bool) {
	entries := strings.Split(text, ",")
	if text == "" || len(entries) > maxFlowTokenPublicKeys {
		return nil, false
	}
	keys := make([]FlowTokenPublicKey, 0, len(entries))
	current := 0
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		state, encoded, found := strings.Cut(strings.TrimSpace(entry), "=")
		switch state {
		case FlowTokenKeyCurrent:
			current++
		case FlowTokenKeyNext, FlowTokenKeyRetiring, FlowTokenKeyRevoked:
		default:
			return nil, false
		}
		raw, err := base64.RawURLEncoding.DecodeString(encoded)
		if !found || err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, false
		}
		if _, duplicate := seen[string(raw)]; duplicate {
			return nil, false
		}
		seen[string(raw)] = struct{}{}
		keys = append(keys, FlowTokenPublicKey{State: state, Key: ed25519.PublicKey(raw)})
	}
	if current != 1 {
		return nil, false
	}
	return keys, true
}
