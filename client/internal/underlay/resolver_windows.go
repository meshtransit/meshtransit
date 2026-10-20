package underlay

import (
	"context"
	"net"
)

// physicalResolver asks the DNS servers of the host's own interfaces
// directly, from sockets bound to the physical path: while the host routes
// the Internet into the mesh, the system resolver follows the NRPT rule to
// the MeshTransit resolver, which cannot answer before the mesh is up, and
// the kill switch drops every other process's queries.
var physicalResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Control: Control}).DialContext(ctx, network, address)
	},
}

// resolver is the resolver of the client's own dials: the system one, or
// physicalResolver while the host routes the Internet into the mesh.
func resolver() *net.Resolver {
	if ExitBound() {
		return physicalResolver
	}
	return nil
}

// Resolver returns the resolver of the client's own lookups.
func Resolver() *net.Resolver {
	if ExitBound() {
		return physicalResolver
	}
	return net.DefaultResolver
}
