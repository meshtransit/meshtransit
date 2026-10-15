package config

import "meshtransit.net/core/internal/domain/dnsname"

// envDNSSuffix names the deployment's DNS suffix: Devices are
// <label>.<workspace code>.<network code>.<suffix> and shares
// <label>.<workspace code>.<network code>.shared.<suffix>.
const envDNSSuffix = "MESHTRANSIT_DNS_SUFFIX"

// loadDNSSuffix returns the configured suffix, canonical lowercase, or
// dnsname.DefaultSuffix. Every role reads it so that the roles that encode
// maps and the roles that return names always agree.
func loadDNSSuffix(lookup LookupFunc) (dnsname.Suffix, error) {
	value, present := lookup(envDNSSuffix)
	if !present {
		return dnsname.Default(), nil
	}
	suffix, err := dnsname.ParseSuffix(value)
	if err != nil {
		return dnsname.Suffix{}, settingError(envDNSSuffix)
	}
	return suffix, nil
}
