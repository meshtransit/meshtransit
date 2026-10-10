package config

import (
	"net/url"
	"slices"
	"strings"

	"meshtransit.net/shared/key"
)

const (
	envInterchangeCoreURL     = "MESHTRANSIT_INTERCHANGE_CORE_URL"
	envInterchangeSigningKeys = "MESHTRANSIT_INTERCHANGE_RELAY_SIGNING_KEYS"
	maxInterchangeSigningKeys = 4
)

// InterchangeConfig is what the Console shows in the command that starts a
// Private Interchange relay: the control URL relays poll and Core's relay
// signing keys. Both are public; without them the Console shows
// placeholders.
type InterchangeConfig struct {
	CoreURL     string
	signingKeys []key.SigningPublic
}

// SigningKeys returns a defensive copy.
func (cfg InterchangeConfig) SigningKeys() []key.SigningPublic { return slices.Clone(cfg.signingKeys) }

// loadInterchangeConfig returns nil unless both settings are present.
func loadInterchangeConfig(lookup LookupFunc) (*InterchangeConfig, error) {
	coreURL, hasURL := lookup(envInterchangeCoreURL)
	keys, hasKeys := lookup(envInterchangeSigningKeys)
	if !hasURL && !hasKeys {
		return nil, nil
	}
	parsed, err := url.Parse(coreURL)
	if !hasURL || err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, settingError(envInterchangeCoreURL)
	}
	cfg := &InterchangeConfig{CoreURL: "https://" + parsed.Host}
	for _, text := range strings.Split(keys, ",") {
		signing, err := key.ParseSigningPublic(strings.TrimSpace(text))
		if err != nil || slices.Contains(cfg.signingKeys, signing) {
			return nil, settingError(envInterchangeSigningKeys)
		}
		cfg.signingKeys = append(cfg.signingKeys, signing)
	}
	if !hasKeys || len(cfg.signingKeys) == 0 || len(cfg.signingKeys) > maxInterchangeSigningKeys {
		return nil, settingError(envInterchangeSigningKeys)
	}
	return cfg, nil
}
