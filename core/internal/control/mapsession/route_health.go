package mapsession

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/shared/routedigest"
)

const (
	// MaximumRouteHealthSites bounds one RouteHealthReport (mtcp-v1 §8.3),
	// as many Sites as one map serves.
	MaximumRouteHealthSites = 1024
	// maximumRouteHealthCode bounds a Site's health code.
	maximumRouteHealthCode = 64
	maximumSiteReference   = 64
)

// ErrInvalidRouteHealth reports a malformed route health report.
var ErrInvalidRouteHealth = errors.New("map session: invalid route health report")

// RouteHealthState is a served Site's state as its router measures it.
type RouteHealthState int

// The states of mtcp-v1 §8.3.
const (
	RouteHealthOK RouteHealthState = iota + 1
	// RouteHealthDegraded is a warning only.
	RouteHealthDegraded
	RouteHealthFailed
)

// SiteHealth is one served Site's health.
type SiteHealth struct {
	Ref   string
	State RouteHealthState
	Code  string
}

// ValidSiteHealth reports Sites sorted by reference and listed once, each
// with a known state and a short code of lower-case letters, digits and
// underscores.
func ValidSiteHealth(sites []SiteHealth) bool {
	if len(sites) > MaximumRouteHealthSites {
		return false
	}
	previous := ""
	for index, site := range sites {
		if site.Ref == "" || len(site.Ref) > maximumSiteReference || !utf8.ValidString(site.Ref) ||
			(index > 0 && previous >= site.Ref) ||
			site.State < RouteHealthOK || site.State > RouteHealthFailed ||
			site.Code == "" || len(site.Code) > maximumRouteHealthCode ||
			strings.IndexFunc(site.Code, func(r rune) bool { return (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' }) >= 0 {
			return false
		}
		previous = site.Ref
	}
	return true
}

// ExitFamilies are the address families an exit node reaches the Internet
// in (mtcp-v1 §7.7).
type ExitFamilies int

// The families of mtcp-v1 §7.7; the zero value is not known.
const (
	ExitFamiliesUnknown ExitFamilies = iota
	ExitFamiliesV4
	ExitFamiliesV6
	ExitFamiliesBoth
)

// ExitHealth is an exit node's health of the Exit Pool it serves, as it
// measures it itself (mtcp-v1 §8.3).
type ExitHealth struct {
	Ref      string
	State    RouteHealthState
	Code     string
	Families ExitFamilies
}

// ValidExitHealth reports a pool reference, a known state and families,
// and a code as for a Site.
func ValidExitHealth(health ExitHealth) bool {
	return health.Families >= ExitFamiliesUnknown && health.Families <= ExitFamiliesBoth &&
		ValidSiteHealth([]SiteHealth{{Ref: health.Ref, State: health.State, Code: health.Code}})
}

// ServedExitOnly keeps exit health of the pool served: an exit node reports
// only on what Core sent it, and nothing else is stored.
func ServedExitOnly(health *ExitHealth, served []ServedExit) *ExitHealth {
	if health == nil || !slices.ContainsFunc(served, func(pool ServedExit) bool { return pool.Ref == health.Ref }) {
		return nil
	}
	kept := *health
	return &kept
}

// RouteHealth is one route health report, bound to the authenticated node
// that sent it; the recorder ties it to that node's current map session.
// Exit is the health of the Exit Pool the node serves; nil: none.
type RouteHealth struct {
	NodeKey            node.Key
	MachineFingerprint [32]byte
	Sites              []SiteHealth
	Exit               *ExitHealth
	ReportedAt         time.Time
}

// RouteHealthRecorder stores the latest route health of a node's current
// map session. It reports false when the node has no current session or the
// session belongs to another machine.
type RouteHealthRecorder interface {
	RecordRouteHealth(context.Context, RouteHealth) (bool, error)
}

// ReportRouteHealth stores the health of the Sites a router serves and of
// the Exit Pool an exit node serves (mtcp-v1 §8.3). Sites and exit must
// already be those the session was sent; the recorder is the enforcement
// recorder when it also records route health.
func (service *StreamService) ReportRouteHealth(ctx context.Context, machine control.AuthenticatedMachine,
	nodeKey node.Key, sites []SiteHealth, exit *ExitHealth,
) error {
	if ctx == nil || service == nil || !machine.IsValid() {
		return ErrInvalidStreamService
	}
	recorder, ok := service.enforcement.(RouteHealthRecorder)
	if !ok {
		return ErrEnforcementUnavailable
	}
	identity, err := machine.BindNodeKey(nodeKey)
	if err != nil || !ValidSiteHealth(sites) || (exit != nil && !ValidExitHealth(*exit)) {
		return ErrInvalidRouteHealth
	}
	var stored *ExitHealth
	if exit != nil {
		copied := *exit
		stored = &copied
	}
	operationCtx, cancel := context.WithTimeout(ctx, service.options.CoordinationTimeout)
	defer cancel()
	recorded, err := recorder.RecordRouteHealth(operationCtx, RouteHealth{
		NodeKey: identity.NodeKey(), MachineFingerprint: identity.MachineFingerprint(),
		Sites: slices.Clone(sites), Exit: stored, ReportedAt: time.Now().UTC(),
	})
	if err != nil {
		return errors.Join(ErrEnforcementUnavailable, err)
	}
	if !recorded {
		return ErrNoEnforcementStream
	}
	return nil
}

// RouteDigest is the route digest v1 of the served routes of a router's map
// (docs/protocol/route-digest-v1.md) and how many entries it covers.
type RouteDigest struct {
	digest  routedigest.Digest
	entries int
}

// NewRouteDigest validates a computed route digest.
func NewRouteDigest(digest routedigest.Digest, entries int) (RouteDigest, error) {
	if digest.IsZero() || entries < 0 || entries > routedigest.MaximumEntries {
		return RouteDigest{}, ErrInvalidEnforcementReport
	}
	return RouteDigest{digest: digest, entries: entries}, nil
}

// Digest returns the digest value.
func (routes RouteDigest) Digest() routedigest.Digest { return routes.digest }

// Entries returns how many entries the digest covers.
func (routes RouteDigest) Entries() int { return routes.entries }

// IsValid reports a computed digest; a map of a session that cannot route
// has none.
func (routes RouteDigest) IsValid() bool { return !routes.digest.IsZero() }

// routeDigestOf is the route digest of the served routes snapshot sends,
// for a session that can route; zero otherwise.
func routeDigestOf(snapshot Snapshot) RouteDigest {
	capabilities, known := snapshot.RouteCapabilities()
	if !known || !capabilities.Router {
		return RouteDigest{}
	}
	var entries []routedigest.Entry
	for _, site := range snapshot.Routes().Served() {
		for _, prefix := range site.Prefixes {
			entries = append(entries, routedigest.Entry{SiteRef: site.Ref, Prefix: prefix, Masquerade: site.Masquerade})
		}
	}
	digest, count, err := routedigest.Compute(entries)
	if err != nil {
		return RouteDigest{}
	}
	routes, _ := NewRouteDigest(digest, count)
	return routes
}
