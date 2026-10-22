package config

import (
	"net/url"
	"slices"
	"strings"
)

// envDNSZonesEnabled lets Network admins create and change DNS zones (DNS
// design D1). Off by default: turn it on once the clients that use zones
// (dns.forward1) run on the Devices that should, and set it the same on
// every role.
const envDNSZonesEnabled = "MESHTRANSIT_DNS_ZONES_ENABLED"

// envDNSProtectedNames lists, comma separated, host names no DNS zone may
// hold: the names clients reach Core by (control, API, Console) and any
// CNAME of them. The issuer, the browser registration origin and the
// interchange URL are protected without being listed.
const envDNSProtectedNames = "MESHTRANSIT_DNS_PROTECTED_NAMES"

// maximumDNSProtectedNames bounds the list.
const maximumDNSProtectedNames = 64

// DNSZonesConfig is the deployment's DNS zone settings.
type DNSZonesConfig struct {
	Enabled bool
	// ProtectedNames are lowercase host names without a trailing dot.
	ProtectedNames []string
}

func loadDNSZones(lookup LookupFunc) (DNSZonesConfig, error) {
	var zones DNSZonesConfig
	switch valueOrDefault(lookup, envDNSZonesEnabled, "false") {
	case "true":
		zones.Enabled = true
	case "false":
	default:
		return DNSZonesConfig{}, settingError(envDNSZonesEnabled)
	}
	value := valueOrDefault(lookup, envDNSProtectedNames, "")
	if value == "" {
		return zones, nil
	}
	for item := range strings.SplitSeq(value, ",") {
		name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(item)), ".")
		if !protectableName(name) || len(zones.ProtectedNames) == maximumDNSProtectedNames {
			return DNSZonesConfig{}, settingError(envDNSProtectedNames)
		}
		if !slices.Contains(zones.ProtectedNames, name) {
			zones.ProtectedNames = append(zones.ProtectedNames, name)
		}
	}
	return zones, nil
}

// protectableName reports a host name of letters, digits, hyphens and dots.
func protectableName(name string) bool {
	if name == "" || len(name) > 253 || strings.HasPrefix(name, ".") || strings.Contains(name, "..") {
		return false
	}
	for _, character := range name {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
			character != '-' && character != '.' {
			return false
		}
	}
	return true
}

// DNSProtectedNames are the configured protected names and the hosts of the
// identity issuer, the browser registration origin and the interchange URL.
func (config Config) DNSProtectedNames() []string {
	names := slices.Clone(config.DNSZones.ProtectedNames)
	add := func(raw string) {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Hostname() == "" {
			return
		}
		host := strings.ToLower(parsed.Hostname())
		if protectableName(host) && !slices.Contains(names, host) {
			names = append(names, host)
		}
	}
	if config.Identity != nil {
		add(config.Identity.Issuer)
	}
	if config.BrowserRegistration != nil {
		add(config.BrowserRegistration.Origin)
	}
	if config.Interchange != nil {
		add(config.Interchange.CoreURL)
	}
	return names
}
