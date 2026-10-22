// Package dnszone holds the DNS zones of a Network (DNS design D1): domains
// whose names its Devices ask chosen resolvers for, a Device of the Network
// or an address on the Internet. Go validates domains and resolvers and
// enforces the limits; PostgreSQL stores zones, checks permissions and the
// eligibility of resolver Devices, and records the evidence. A zone grants
// nothing: policy still decides whether a Device may reach a resolver.
package dnszone

import "errors"

var (
	// ErrInvalid reports a malformed zone, change or result.
	ErrInvalid = errors.New("dnszone: invalid request or result")
	// ErrDomainSpecialUse reports a special-use name (local, test, arpa, ...).
	ErrDomainSpecialUse = errors.New("dnszone: special-use domain")
	// ErrDomainPublicSuffix reports a public suffix (com, co.uk, ...):
	// forwarding it would take every name under it.
	ErrDomainPublicSuffix = errors.New("dnszone: public suffix")
	// ErrDomainMeshSuffix reports a domain that is, holds or lies under the
	// names MeshTransit gives Devices and shares.
	ErrDomainMeshSuffix = errors.New("dnszone: domain overlaps the mesh names")
	// ErrDomainCoversControl reports a domain that holds a name of the
	// deployment's own services: Devices must always reach them.
	ErrDomainCoversControl = errors.New("dnszone: domain covers the deployment's own names")
	// ErrPublicUnconfirmed reports a domain on the Internet the request did
	// not confirm.
	ErrPublicUnconfirmed = errors.New("dnszone: public domain not confirmed")
	// ErrResolverNotInternet reports a resolver address that is not on the
	// Internet; private resolvers wait for DNS for Sites.
	ErrResolverNotInternet = errors.New("dnszone: resolver address is not on the Internet")
	// ErrRootUnavailable reports a root zone ("every other name") before this
	// deployment offers it (D1b).
	ErrRootUnavailable = errors.New("dnszone: root zone unavailable")
	// ErrDisabled reports a deployment that has not turned DNS zones on.
	ErrDisabled = errors.New("dnszone: DNS zones disabled")
	// ErrForbidden conceals missing authority or an unavailable Network.
	ErrForbidden = errors.New("dnszone: permission denied")
	// ErrNotFound reports an unknown or deleted zone.
	ErrNotFound = errors.New("dnszone: not found")
	// ErrVersionConflict reports a stale expected version.
	ErrVersionConflict = errors.New("dnszone: version conflict")
	// ErrDomainTaken reports another active zone of the Network for the
	// domain.
	ErrDomainTaken = errors.New("dnszone: domain taken")
	// ErrZoneLimit reports a Network that already has the plan's zones.
	ErrZoneLimit = errors.New("dnszone: zone limit reached")
	// ErrSearchLimit reports a Network that already has the maximum search
	// domains.
	ErrSearchLimit = errors.New("dnszone: search domain limit reached")
	// ErrResolverNotEligible reports a resolver Device that is not an
	// active, Workspace-owned Device of the Network, or is an exit node.
	ErrResolverNotEligible = errors.New("dnszone: Device cannot be a DNS resolver")
	// ErrResolverPeerLimit reports a resolver Device that would serve more
	// Devices than one map holds.
	ErrResolverPeerLimit = errors.New("dnszone: DNS resolver would serve too many Devices")
	// ErrGroupNotFound reports a Device Group that is not an active group of
	// the Network.
	ErrGroupNotFound = errors.New("dnszone: Device Group not found")
	// ErrUnavailable reports an unavailable or uncertain durable operation.
	ErrUnavailable = errors.New("dnszone: unavailable")
)
