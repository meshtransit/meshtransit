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
	// ErrReverseMeshRange reports a reverse zone of the mesh's own ranges,
	// whose reverse names every Device answers (TD-CLI-73).
	ErrReverseMeshRange = errors.New("dnszone: reverse zone of the mesh's ranges")
	// ErrReverseReservedRange reports a reverse zone of a range no resolver
	// holds: this host, link-local, multicast, reserved.
	ErrReverseReservedRange = errors.New("dnszone: reverse zone of a reserved range")
	// ErrOtherNamesInvalid reports a kind of zone sent with what only
	// another kind takes: resolvers or a failure mode for nxdomain or host,
	// none for forward (TD-CORE-77).
	ErrOtherNamesInvalid = errors.New("dnszone: other names do not match the resolvers")
	// ErrReverseKind reports a reverse zone that does not only forward, or
	// that is a search domain.
	ErrReverseKind = errors.New("dnszone: a reverse zone only forwards")
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
	// ErrNXDomainPublic reports a zone on the Internet that would answer
	// nxdomain: every Device it is sent to would lose the domain.
	ErrNXDomainPublic = errors.New("dnszone: a domain on the Internet is never nxdomain")
	// ErrZoneHoldsNames reports a zone deleted while it holds names, or
	// created over names a shorter zone holds, without saying what happens
	// to them.
	ErrZoneHoldsNames = errors.New("dnszone: zone holds names")
	// ErrNameNotFound reports an unknown or deleted name of the zone.
	ErrNameNotFound = errors.New("dnszone: name not found")
	// ErrNameTaken reports another active name of the Network.
	ErrNameTaken = errors.New("dnszone: name taken")
	// ErrNameInOtherZone reports a name a longer zone of the Network holds.
	ErrNameInOtherZone = errors.New("dnszone: a longer zone holds the name")
	// ErrNameLimit reports a zone, a Network or the host zones of a Network
	// that already hold the most names.
	ErrNameLimit = errors.New("dnszone: name limit reached")
	// ErrNameTargetInvalid reports a target no name may point at: a Device
	// that is not an active Device of the Network, an address no answer may
	// carry, or a CNAME to a mesh or special-use name.
	ErrNameTargetInvalid = errors.New("dnszone: invalid name target")
	// ErrShareTargetInvalid reports a share no name may point at now: one
	// the Network does not import, or whose contract no longer runs.
	ErrShareTargetInvalid = errors.New("dnszone: invalid share target")
	// ErrCNAMEAtApex reports a CNAME at a zone's own domain.
	ErrCNAMEAtApex = errors.New("dnszone: CNAME at the zone's own domain")
	// ErrCNAMELoop reports CNAMEs among the Network's names that loop or
	// chain more than MaximumCNAMEChain times.
	ErrCNAMELoop = errors.New("dnszone: CNAME chain loops or is too long")
)

// OperationError is the error of one operation of a name change: Index is
// its position in the request, from 0.
type OperationError struct {
	Index int
	Err   error
}

func (failure *OperationError) Error() string { return failure.Err.Error() }

// Unwrap returns the operation's error.
func (failure *OperationError) Unwrap() error { return failure.Err }
