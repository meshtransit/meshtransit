package config

// envGeoIPCountryFile names a DB-IP "IP to Country Lite" CSV file (plain
// or .gz). When set, Console Device reads place each Device's public
// addresses in a country; unset, they show the addresses only.
const envGeoIPCountryFile = "MESHTRANSIT_GEOIP_COUNTRY_FILE"

func loadGeoIPCountryFile(lookup LookupFunc) (string, error) {
	if _, present := lookup(envGeoIPCountryFile); !present {
		return "", nil
	}
	return requiredFile(lookup, envGeoIPCountryFile)
}
