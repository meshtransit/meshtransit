// Package site holds the Sites of a Network: address spaces behind the mesh,
// such as an office LAN or a VPC, that routers forward into
// (docs/protocol/mtcp-v1.md §7.6). A Site is a route domain: two Sites of a
// Network may use the same prefixes, and policy grants nodes parts of a
// Site through Subnet Resources. Go validates prefixes and limits;
// PostgreSQL stores Sites, checks permissions and records the evidence.
package site

import "errors"

var (
	// ErrInvalid reports a malformed Site, change or result.
	ErrInvalid = errors.New("site: invalid request or result")
	// ErrInvalidPrefix reports a prefix a Site cannot use.
	ErrInvalidPrefix = errors.New("site: invalid prefix")
	// ErrPrefixLimit reports more prefixes than the plan allows.
	ErrPrefixLimit = errors.New("site: prefix limit reached")
	// ErrForbidden conceals missing authority or an unavailable Network.
	ErrForbidden = errors.New("site: permission denied")
	// ErrNotFound reports an unknown or deleted Site, or an unknown router.
	ErrNotFound = errors.New("site: not found")
	// ErrVersionConflict reports a stale expected version.
	ErrVersionConflict = errors.New("site: version conflict")
	// ErrNameTaken reports another active Site of the Network with the name.
	ErrNameTaken = errors.New("site: name taken")
	// ErrSiteLimit reports a Network that already has the plan's Sites.
	ErrSiteLimit = errors.New("site: Site limit reached")
	// ErrRouterLimit reports a Site that already has the plan's routers.
	ErrRouterLimit = errors.New("site: router limit reached")
	// ErrRouterNotEligible reports a Device that is not an active,
	// Workspace-owned Device of the Network.
	ErrRouterNotEligible = errors.New("site: Device cannot be a router")
	// ErrRouterNotOffering reports a Device whose own configuration does not
	// offer the Site's prefixes.
	ErrRouterNotOffering = errors.New("site: Device does not offer the Site prefixes")
	// ErrUnavailable reports an unavailable or uncertain durable operation.
	ErrUnavailable = errors.New("site: unavailable")
)
