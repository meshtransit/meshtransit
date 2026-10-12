//go:build windows

package windns

import (
	"context"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/winadapter"
)

// Opener gives the resolver its Windows endpoint. There is no link to open:
// the service binds the loopback address itself.
type Opener struct{}

// OpenDNS returns the resolver endpoint.
func (Opener) OpenDNS(ctx context.Context) (netadmin.DNSLink, error) {
	if err := ctx.Err(); err != nil {
		return netadmin.DNSLink{}, err
	}

	return netadmin.DNSLink{Endpoint: netadmin.DNSEndpoint{
		InterfaceName: winadapter.Name,
		Resolver:      ResolverAddress,
	}}, nil
}
