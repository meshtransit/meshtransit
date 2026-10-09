package legacyts2021

import (
	"tailscale.com/tailcfg"

	"github.com/meshtransit/meshtransit/core/internal/control/mapsession"
)

// mapDNSConfig returns the complete DNS configuration for one map. It is
// never nil on full maps, authority deltas or withdrawals: within a stream a
// nil configuration means "unchanged", so an omitted value could keep a
// revoked name resolvable. Only exact imported share names are published, as
// locally authoritative A/AAAA records; no resolver or search domain is set.
func mapDNSConfig(snapshot mapsession.Snapshot) (*tailcfg.DNSConfig, error) {
	records, err := snapshot.SharedDNSRecords()
	if err != nil {
		return nil, ErrMapResponse
	}
	config := &tailcfg.DNSConfig{}
	for _, record := range records {
		for _, address := range record.Addresses {
			recordType := "AAAA"
			if address.Is4() {
				recordType = "A"
			}
			config.ExtraRecords = append(config.ExtraRecords, tailcfg.DNSRecord{
				Name: record.Name, Type: recordType, Value: address.String(),
			})
		}
	}
	return config, nil
}
