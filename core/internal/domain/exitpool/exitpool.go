// Package exitpool holds the Exit Pools of a Network: groups of exit nodes,
// Devices that forward other Devices' Internet traffic (exit node design
// §5). An Exit Pool is its own entity, never a kind of Site: a Site is an
// address space to reach, an Exit Pool a way out to the Internet. Go
// validates names, limits and the Internet addresses a pool is configured
// with; PostgreSQL stores pools, checks permissions and records the
// evidence.
package exitpool

import "errors"

var (
	// ErrInvalid reports a malformed pool, change or result.
	ErrInvalid = errors.New("exitpool: invalid request or result")
	// ErrNotInternet reports a resolver or probe address that is not on the
	// Internet: an exit node never forwards there.
	ErrNotInternet = errors.New("exitpool: address is not on the Internet")
	// ErrForbidden conceals missing authority or an unavailable Network.
	ErrForbidden = errors.New("exitpool: permission denied")
	// ErrNotFound reports an unknown or deleted pool, or an unknown exit node.
	ErrNotFound = errors.New("exitpool: not found")
	// ErrVersionConflict reports a stale expected version.
	ErrVersionConflict = errors.New("exitpool: version conflict")
	// ErrNameTaken reports another active pool of the Network with the name.
	ErrNameTaken = errors.New("exitpool: name taken")
	// ErrPoolLimit reports a Network that already has the plan's pools.
	ErrPoolLimit = errors.New("exitpool: pool limit reached")
	// ErrNodeLimit reports a pool that already has the plan's exit nodes.
	ErrNodeLimit = errors.New("exitpool: exit node limit reached")
	// ErrNodeNotEligible reports a Device that is not an active,
	// Workspace-owned Device of the Network.
	ErrNodeNotEligible = errors.New("exitpool: Device cannot be an exit node")
	// ErrNodeInOtherPool reports a Device that is already an exit node of
	// another pool: a Device is an exit node of one pool at most.
	ErrNodeInOtherPool = errors.New("exitpool: Device is an exit node of another pool")
	// ErrNodeIsDNSResolver reports a Device that is a resolver of a DNS
	// zone: an exit node takes port 53 on its mesh addresses for its own
	// DNS forwarder.
	ErrNodeIsDNSResolver = errors.New("exitpool: Device is a DNS resolver")
	// ErrInUse reports a pool that rules of the active policy release name.
	ErrInUse = errors.New("exitpool: named by active rules")
	// ErrUnavailable reports an unavailable or uncertain durable operation.
	ErrUnavailable = errors.New("exitpool: unavailable")
)
