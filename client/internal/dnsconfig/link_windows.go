//go:build windows

package dnsconfig

import (
	"errors"

	"meshtransit.net/client/internal/netadmin"
)

// validateDNSLink checks the Windows endpoint: NRPT sends queries to port 53
// only, so the resolver listens on a loopback address of its own, which no
// other machine can reach and which needs no adapter.
func validateDNSLink(link netadmin.DNSLink) error {
	resolver := link.Endpoint.Resolver
	if link.File != nil || !resolver.IsValid() || !resolver.Addr().Is4() ||
		!resolver.Addr().IsLoopback() || resolver.Port() != 53 {
		return errors.New("dnsconfig: invalid windows dns endpoint")
	}

	return nil
}
