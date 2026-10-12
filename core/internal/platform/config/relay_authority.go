package config

import (
	"context"
	"crypto/sha256"
	"log/slog"
	"net/netip"
	"strings"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/platform/app"
	"meshtransit.net/shared/key"
)

const (
	envRelayAuthorityEnabled = "MESHTRANSIT_RELAY_AUTHORITY_ENABLED"
	envRelaySigningKeyFile   = "MESHTRANSIT_RELAY_SIGNING_KEY_FILE"
	envRelayNextSigningKey   = "MESHTRANSIT_RELAY_NEXT_SIGNING_KEY_FILE"
	envRelayMapFile          = "MESHTRANSIT_RELAY_MAP_FILE"
	envRelayMapSHA256        = "MESHTRANSIT_RELAY_MAP_SHA256"
	envRelayDrain            = "MESHTRANSIT_RELAY_DRAIN"
	envRelayTrustedProxies   = "MESHTRANSIT_RELAY_TRUSTED_PROXY_CIDRS"
	envRelayDeploymentID     = "MESHTRANSIT_RELAY_DEPLOYMENT_PUBLIC_ID"
	envRelayTicketZonesV2    = "MESHTRANSIT_RELAY_TICKET_ZONES_V2"

	maxRelayDrainEntries = 64
)

// RelayAuthorityConfig lets the control role act as the Interchange relay
// authority (docs/protocol/mtrp-v1.md §8, §9): it signs the relay state that
// relays poll and the relay map nodes use.
//
// The signing key files hold a 32-byte Ed25519 seed as 43 base64url
// characters with mode 0400, 0440, 0600 or 0640. The optional next key is
// published to relays ahead of a rotation; promoting it means swapping the
// files and restarting.
type RelayAuthorityConfig struct {
	SigningKeyFile     SecretFile
	NextSigningKeyFile *SecretFile
	MapFile            string // optional: without it the relay map is not served
	MapDigest          [sha256.Size]byte
	Drain              []key.RelayPublic
	// TrustedProxyPrefixes are the reverse proxies whose X-Forwarded-For
	// selects the client address for per-source rate limiting.
	TrustedProxyPrefixes []netip.Prefix
	// TicketDeployment, when set, makes Core issue relay tickets to nodes;
	// it is the deployment public ID the tickets name (the entitlement's).
	TicketDeployment *deployment.ID
	// TicketZonesV2 offers clients relay.zones2: tickets for more than 31
	// shares (MTT2). Enable it only once every relay in the relay maps
	// accepts MTT2 and ZONES frames.
	TicketZonesV2 bool
}

// String redacts the configuration in generic formatting.
func (RelayAuthorityConfig) String() string { return redactedValue }

// GoString redacts detailed formatting.
func (RelayAuthorityConfig) GoString() string { return "config.RelayAuthorityConfig([REDACTED])" }

// LogValue redacts structured formatting.
func (RelayAuthorityConfig) LogValue() slog.Value { return slog.StringValue(redactedValue) }

// SigningKeys reads the current and, when configured, next signing keys.
func (c RelayAuthorityConfig) SigningKeys(ctx context.Context) (key.SigningPrivate, *key.SigningPrivate, error) {
	seed, err := c.SigningKeyFile.readPrivateIdentityKey(ctx)
	defer clear(seed[:])
	if err != nil {
		return key.SigningPrivate{}, nil, settingError(envRelaySigningKeyFile)
	}
	current, err := key.SigningPrivateFromSeed(seed[:])
	if err != nil {
		return key.SigningPrivate{}, nil, settingError(envRelaySigningKeyFile)
	}
	if c.NextSigningKeyFile == nil {
		return current, nil, nil
	}
	nextSeed, err := c.NextSigningKeyFile.readPrivateIdentityKey(ctx)
	defer clear(nextSeed[:])
	if err != nil {
		return key.SigningPrivate{}, nil, settingError(envRelayNextSigningKey)
	}
	next, err := key.SigningPrivateFromSeed(nextSeed[:])
	if err != nil || next.Public() == current.Public() {
		return key.SigningPrivate{}, nil, settingError(envRelayNextSigningKey)
	}
	return current, &next, nil
}

func loadRelayAuthorityConfig(lookup LookupFunc, role app.Role) (*RelayAuthorityConfig, error) {
	enabled := valueOrDefault(lookup, envRelayAuthorityEnabled, "false")
	if enabled != "true" && enabled != "false" {
		return nil, settingError(envRelayAuthorityEnabled)
	}
	settings := []string{envRelaySigningKeyFile, envRelayNextSigningKey, envRelayMapFile, envRelayMapSHA256, envRelayDrain, envRelayTrustedProxies, envRelayDeploymentID, envRelayTicketZonesV2}
	if enabled == "false" {
		for _, name := range settings {
			if _, present := lookup(name); present {
				return nil, settingError(name)
			}
		}
		return nil, nil
	}
	if role != app.RoleAll && role != app.RoleControl {
		return nil, settingError(envRelayAuthorityEnabled)
	}
	signing, err := NewSecretFile(valueOrDefault(lookup, envRelaySigningKeyFile, ""))
	if err != nil {
		return nil, settingError(envRelaySigningKeyFile)
	}
	cfg := &RelayAuthorityConfig{SigningKeyFile: signing}
	if path, present := lookup(envRelayNextSigningKey); present {
		next, err := NewSecretFile(path)
		if err != nil || path == signing.path {
			return nil, settingError(envRelayNextSigningKey)
		}
		cfg.NextSigningKeyFile = &next
	}
	mapPath, hasMap := lookup(envRelayMapFile)
	digest, hasDigest := lookup(envRelayMapSHA256)
	switch {
	case hasMap != hasDigest:
		return nil, settingError(envRelayMapSHA256)
	case hasMap:
		if validateFilePath(mapPath) != nil {
			return nil, settingError(envRelayMapFile)
		}
		parsed, err := parseRelayDirectoryDigest(digest)
		if err != nil {
			return nil, settingError(envRelayMapSHA256)
		}
		cfg.MapFile, cfg.MapDigest = mapPath, parsed
	}
	if drain, present := lookup(envRelayDrain); present {
		entries := strings.Split(drain, ",")
		if len(entries) > maxRelayDrainEntries {
			return nil, settingError(envRelayDrain)
		}
		for _, entry := range entries {
			relay, err := key.ParseRelayPublic(strings.TrimSpace(entry))
			if err != nil {
				return nil, settingError(envRelayDrain)
			}
			cfg.Drain = append(cfg.Drain, relay)
		}
	}
	proxies, err := parseTrustedProxyPrefixes(valueOrDefault(lookup, envRelayTrustedProxies, ""))
	if err != nil {
		return nil, settingError(envRelayTrustedProxies)
	}
	cfg.TrustedProxyPrefixes = proxies
	if value, present := lookup(envRelayDeploymentID); present {
		id, err := deployment.ParseID(value)
		if err != nil || cfg.MapFile == "" {
			// Tickets are useless without a relay map to find relays in.
			return nil, settingError(envRelayDeploymentID)
		}
		cfg.TicketDeployment = &id
	}
	if value, present := lookup(envRelayTicketZonesV2); present {
		if value != "true" && value != "false" || value == "true" && cfg.TicketDeployment == nil {
			// MTT2 is a kind of ticket; without tickets it means nothing.
			return nil, settingError(envRelayTicketZonesV2)
		}
		cfg.TicketZonesV2 = value == "true"
	}
	return cfg, nil
}
