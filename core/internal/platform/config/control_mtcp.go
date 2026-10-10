package config

import (
	"net/netip"
	"slices"
	"time"
)

const (
	envControlMTCPEnabled        = "MESHTRANSIT_CONTROL_MTCP_ENABLED"
	envControlMTCPKeyNotAfter    = "MESHTRANSIT_CONTROL_MTCP_KEY_NOT_AFTER"
	envControlMTCPTrustedProxies = "MESHTRANSIT_CONTROL_MTCP_TRUSTED_PROXY_CIDRS"
	// The advertised key lifetime is bounded so a forgotten value cannot
	// pin clients to one key indefinitely.
	maxControlMTCPKeyLifetime = 5 * 365 * 24 * time.Hour
)

// ControlMTCPConfig configures MTCP v1, the control protocol. The control
// key is MESHTRANSIT_CONTROL_NOISE_PRIVATE_KEY_FILE.
type ControlMTCPConfig struct {
	// KeyNotAfter is the expiry advertised for the control key in the key
	// document (mtcp-v1 §2.2).
	KeyNotAfter time.Time
	// TrustedProxyPrefixes are the reverse proxies whose X-Forwarded-For
	// names the client for per-source admission; empty uses the peer.
	trustedProxyPrefixes []netip.Prefix
}

// TrustedProxyPrefixes returns a defensive copy.
func (cfg ControlMTCPConfig) TrustedProxyPrefixes() []netip.Prefix {
	return slices.Clone(cfg.trustedProxyPrefixes)
}

func loadControlMTCPConfig(lookup LookupFunc, now time.Time) (ControlMTCPConfig, error) {
	// MTCP is the only control protocol; the switch stays readable so
	// existing deployments that set it to true keep starting.
	if enabled, present := lookup(envControlMTCPEnabled); present && enabled != "true" {
		return ControlMTCPConfig{}, settingError(envControlMTCPEnabled)
	}
	notAfter, err := time.Parse(time.RFC3339, valueOrDefault(lookup, envControlMTCPKeyNotAfter, ""))
	if err != nil || !notAfter.After(now) || notAfter.Sub(now) > maxControlMTCPKeyLifetime {
		return ControlMTCPConfig{}, settingError(envControlMTCPKeyNotAfter)
	}
	proxies, err := parseTrustedProxyPrefixes(valueOrDefault(lookup, envControlMTCPTrustedProxies, ""))
	if err != nil {
		return ControlMTCPConfig{}, settingError(envControlMTCPTrustedProxies)
	}
	return ControlMTCPConfig{KeyNotAfter: notAfter.UTC(), trustedProxyPrefixes: proxies}, nil
}
