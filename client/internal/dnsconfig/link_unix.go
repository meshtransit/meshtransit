//go:build !windows

package dnsconfig

import (
	"errors"

	"meshtransit.net/client/internal/netadmin"
)

// validateDNSLink checks what meshnetd returned: the descriptor of a
// dedicated link and an unprivileged resolver port on a routable address.
func validateDNSLink(link netadmin.DNSLink) error {
	endpoint := link.Endpoint
	if link.File == nil || endpoint.InterfaceName == "" ||
		!netadmin.ValidInterfaceName(endpoint.InterfaceName) ||
		!endpoint.Resolver.IsValid() || endpoint.Resolver.Addr().Is4In6() ||
		!endpoint.Resolver.Addr().IsGlobalUnicast() ||
		endpoint.Resolver.Addr().IsLinkLocalUnicast() || endpoint.Resolver.Port() < 1024 {
		return errors.New("dnsconfig: helper returned invalid dns link metadata")
	}

	return nil
}
