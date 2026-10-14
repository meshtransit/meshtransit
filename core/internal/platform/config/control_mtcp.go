package config

import (
	"net/netip"
	"slices"
	"strconv"
	"time"
)

const (
	envControlMTCPEnabled     = "MESHTRANSIT_CONTROL_MTCP_ENABLED"
	envControlMTCPKeyNotAfter = "MESHTRANSIT_CONTROL_MTCP_KEY_NOT_AFTER"
	// envControlMTCPNextKeyNotAfter is the next control key's expiry; it is
	// required exactly when MESHTRANSIT_CONTROL_NOISE_NEXT_PRIVATE_KEY_FILE
	// is set.
	envControlMTCPNextKeyNotAfter = "MESHTRANSIT_CONTROL_MTCP_NEXT_KEY_NOT_AFTER"
	envControlMTCPTrustedProxies  = "MESHTRANSIT_CONTROL_MTCP_TRUSTED_PROXY_CIDRS"
	// Per-source handshake admission (mtcp-v1 §14). A source is an IPv4
	// address or IPv6 /64; raise these where many Devices share one NAT.
	envControlMTCPHandshakeRate      = "MESHTRANSIT_CONTROL_MTCP_HANDSHAKE_RATE"
	envControlMTCPHandshakeBurst     = "MESHTRANSIT_CONTROL_MTCP_HANDSHAKE_BURST"
	defaultControlMTCPHandshakeRate  = 10
	defaultControlMTCPHandshakeBurst = 50
	maxControlMTCPHandshakeRate      = 10000
	maxControlMTCPHandshakeBurst     = 100000
	// Connections per source that serve no Device yet: handshakes in progress
	// and sessions without a map snapshot (mtcp-v1 §14). The default admits
	// a full burst plus 10 seconds (the default map request timeout) at the
	// handshake rate, so a slow Core paces a reconnect storm from one NAT
	// instead of refusing it: 150 with the default rate and burst.
	envControlMTCPUnauthenticatedPerSource = "MESHTRANSIT_CONTROL_MTCP_UNAUTHENTICATED_PER_SOURCE"
	controlMTCPSnapshotAllowanceSeconds    = 10
	maxControlMTCPUnauthenticatedPerSource = 10000
	// How long a session may stay open without proving a Device. It must
	// outlast a browser approval (10 min), so an approval requested when the
	// session opens is never cut off.
	envControlMTCPUnprovenLifetime     = "MESHTRANSIT_CONTROL_MTCP_UNPROVEN_SESSION_LIFETIME"
	defaultControlMTCPUnprovenLifetime = 15 * time.Minute
	minControlMTCPUnprovenLifetime     = 11 * time.Minute
	maxControlMTCPUnprovenLifetime     = 24 * time.Hour
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
	// NextKeyNotAfter is the next control key's expiry, zero without one.
	NextKeyNotAfter time.Time
	// HandshakeRate and HandshakeBurst bound new handshakes per source and
	// second, before any cryptography.
	HandshakeRate  int
	HandshakeBurst int
	// UnauthenticatedPerSource bounds a source's connections that serve no
	// Device yet; UnprovenLifetime closes a session that proves none.
	UnauthenticatedPerSource int
	UnprovenLifetime         time.Duration
	// TrustedProxyPrefixes are the reverse proxies whose X-Forwarded-For
	// names the client for per-source admission; empty uses the peer.
	trustedProxyPrefixes []netip.Prefix
}

// TrustedProxyPrefixes returns a defensive copy.
func (cfg ControlMTCPConfig) TrustedProxyPrefixes() []netip.Prefix {
	return slices.Clone(cfg.trustedProxyPrefixes)
}

func loadControlMTCPConfig(lookup LookupFunc, now time.Time, hasNextKey bool) (ControlMTCPConfig, error) {
	// MTCP is the only control protocol; the switch stays readable so
	// existing deployments that set it to true keep starting.
	if enabled, present := lookup(envControlMTCPEnabled); present && enabled != "true" {
		return ControlMTCPConfig{}, settingError(envControlMTCPEnabled)
	}
	notAfter, err := time.Parse(time.RFC3339, valueOrDefault(lookup, envControlMTCPKeyNotAfter, ""))
	if err != nil || !notAfter.After(now) || notAfter.Sub(now) > maxControlMTCPKeyLifetime {
		return ControlMTCPConfig{}, settingError(envControlMTCPKeyNotAfter)
	}
	var nextNotAfter time.Time
	if value, present := lookup(envControlMTCPNextKeyNotAfter); present != hasNextKey {
		return ControlMTCPConfig{}, settingError(envControlMTCPNextKeyNotAfter)
	} else if present {
		nextNotAfter, err = time.Parse(time.RFC3339, value)
		if err != nil || !nextNotAfter.After(now) || nextNotAfter.Sub(now) > maxControlMTCPKeyLifetime {
			return ControlMTCPConfig{}, settingError(envControlMTCPNextKeyNotAfter)
		}
	}
	proxies, err := parseTrustedProxyPrefixes(valueOrDefault(lookup, envControlMTCPTrustedProxies, ""))
	if err != nil {
		return ControlMTCPConfig{}, settingError(envControlMTCPTrustedProxies)
	}
	rate, err := parseIntInRange(valueOrDefault(lookup, envControlMTCPHandshakeRate,
		strconv.Itoa(defaultControlMTCPHandshakeRate)), 1, maxControlMTCPHandshakeRate)
	if err != nil {
		return ControlMTCPConfig{}, settingError(envControlMTCPHandshakeRate)
	}
	burst, err := parseIntInRange(valueOrDefault(lookup, envControlMTCPHandshakeBurst,
		strconv.Itoa(max(defaultControlMTCPHandshakeBurst, rate))), 1, maxControlMTCPHandshakeBurst)
	if err != nil || burst < rate {
		return ControlMTCPConfig{}, settingError(envControlMTCPHandshakeBurst)
	}
	unauthenticated, err := parseIntInRange(valueOrDefault(lookup, envControlMTCPUnauthenticatedPerSource,
		strconv.Itoa(min(burst+rate*controlMTCPSnapshotAllowanceSeconds, maxControlMTCPUnauthenticatedPerSource))),
		1, maxControlMTCPUnauthenticatedPerSource)
	if err != nil {
		return ControlMTCPConfig{}, settingError(envControlMTCPUnauthenticatedPerSource)
	}
	unprovenLifetime, err := time.ParseDuration(valueOrDefault(lookup, envControlMTCPUnprovenLifetime,
		defaultControlMTCPUnprovenLifetime.String()))
	if err != nil || unprovenLifetime < minControlMTCPUnprovenLifetime || unprovenLifetime > maxControlMTCPUnprovenLifetime {
		return ControlMTCPConfig{}, settingError(envControlMTCPUnprovenLifetime)
	}
	if !nextNotAfter.IsZero() {
		nextNotAfter = nextNotAfter.UTC()
	}
	return ControlMTCPConfig{KeyNotAfter: notAfter.UTC(), NextKeyNotAfter: nextNotAfter, HandshakeRate: rate, HandshakeBurst: burst,
		UnauthenticatedPerSource: unauthenticated, UnprovenLifetime: unprovenLifetime,
		trustedProxyPrefixes: proxies}, nil
}
