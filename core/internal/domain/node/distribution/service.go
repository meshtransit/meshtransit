// Package distribution reports, per Device, whether it runs the Network's
// current policy: the intended Network revision from durable authority against
// what the control plane last delivered to the Device (R1-65).
package distribution

import (
	"context"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

// MaximumObservationBatch bounds the Devices one delivery record load reads.
const MaximumObservationBatch = 100

var (
	// ErrInvalidRequest reports invalid input before any read.
	ErrInvalidRequest = errors.New("device distribution: invalid request")
	// ErrInvalidResult conceals malformed storage evidence.
	ErrInvalidResult = errors.New("device distribution: invalid result")
	// ErrForbidden conceals missing or revoked exact-scope authority.
	ErrForbidden = errors.New("device distribution: forbidden")
	// ErrUnavailable reports a failed durable dependency.
	ErrUnavailable = errors.New("device distribution: unavailable")
	// ErrNotFound reports a Device the scope does not hold as active or
	// suspended: removed and expired Devices receive no policy.
	ErrNotFound = errors.New("device distribution: not found")
)

// Status is how a Device stands against the Network's current revision.
type Status string

const (
	// StatusInSync is online and holding the current Network revision.
	StatusInSync Status = "in_sync"
	// StatusBehind is online but last given an older revision.
	StatusBehind Status = "behind"
	// StatusOffline has no live stream; it may hold an older revision.
	StatusOffline Status = "offline"
	// StatusNeverConnected has never received a map.
	StatusNeverConnected Status = "never_connected"
	// StatusUnknown means delivery records could not be read right now.
	StatusUnknown Status = "unknown"
)

// Observation is what the control plane recorded for one Device. Known is
// false when it never recorded a delivery; Online reflects a live presence
// lease. Filter is the digest of the last delivered packet filter; Enforced,
// AppliedAt and ReportedAt are the Device's own report for the same session.
type Observation struct {
	Known             bool
	SessionGeneration int64
	NetworkRevision   int64
	PolicyRevision    int64
	DeliveredAt       time.Time
	SeenAt            time.Time
	Online            bool
	Filter            FilterSummary
	Enforced          FilterSummary
	AppliedAt         time.Time
	ReportedAt        time.Time
	// Paths is the Device's latest path report for the session, if any.
	Paths *PathReport
	// Connectivity is the Device's latest NAT, IPv6 and port mapping report
	// for the session, if any.
	Connectivity *Connectivity
	// PeerLimit is set when the last map was cut to a peer limit.
	PeerLimit PeerLimit
	// Routes is the route digest of the served routes last delivered to a
	// router, EnforcedRoutes the one it reports.
	Routes, EnforcedRoutes RouteSummary
	// RouteHealth is the router's latest Site health and RouteHealthAt when
	// Core received it.
	RouteHealth   []SiteHealth
	RouteHealthAt time.Time
	// ExitHealth is an exit node's latest health of the Exit Pool it serves,
	// received with its Site health at RouteHealthAt; nil when it reported
	// none.
	ExitHealth *ExitHealth
	// RouteSelection is the router the node last reported using for each
	// Site and RouteSelectionAt when Core received it.
	RouteSelection   []SiteRouter
	RouteSelectionAt time.Time
}

// PeerLimit is how many peers a limited map carried and how many the
// policy authorized; the zero value means the map was not limited.
type PeerLimit struct {
	Sent       int
	Authorized int
}

// IsZero reports a map that was not limited.
func (limit PeerLimit) IsZero() bool { return limit == PeerLimit{} }

// IsValid reports a limit that cut something.
func (limit PeerLimit) IsValid() bool { return limit.Sent > 0 && limit.Authorized > limit.Sent }

// IsValid reports a self-consistent observation.
func (observation Observation) IsValid() bool {
	if !observation.Known {
		return observation.SessionGeneration == 0 && observation.NetworkRevision == 0 &&
			observation.PolicyRevision == 0 && observation.DeliveredAt.IsZero() && observation.SeenAt.IsZero() &&
			observation.Filter.IsZero() && observation.Enforced.IsZero() &&
			observation.AppliedAt.IsZero() && observation.ReportedAt.IsZero() && observation.Paths == nil &&
			observation.Connectivity == nil && observation.PeerLimit.IsZero() &&
			observation.Routes.IsZero() && observation.EnforcedRoutes.IsZero() &&
			observation.RouteHealth == nil && observation.RouteHealthAt.IsZero() && observation.ExitHealth == nil &&
			observation.RouteSelection == nil && observation.RouteSelectionAt.IsZero()
	}
	if !observation.PeerLimit.IsZero() && !observation.PeerLimit.IsValid() {
		return false
	}
	if observation.Paths != nil && !observation.Paths.IsValid() {
		return false
	}
	if observation.Connectivity != nil && !observation.Connectivity.IsValid() {
		return false
	}
	return observation.SessionGeneration > 0 && observation.NetworkRevision > 0 &&
		observation.PolicyRevision >= 0 && !observation.DeliveredAt.IsZero() &&
		!observation.SeenAt.Before(observation.DeliveredAt) && validEnforcement(observation) &&
		validRoutes(observation) && validExitHealth(observation)
}

// TargetDevice is a Device that should hold the current revision.
type TargetDevice struct {
	ID       node.ID
	Hostname string
	State    string
}

// Target is the durable side of one Device's report: the current revisions
// and the Device when it is active or suspended.
type Target struct {
	Scope           network.Scope
	NetworkRevision int64
	PolicyRevision  int64
	Devices         []TargetDevice
}

// Reader authorizes and reads the durable side under device.read on the
// database clock.
type Reader interface {
	ReadTarget(context.Context, accountsession.Session, network.Scope, node.ID) (Target, error)
}

// ObservationLoader returns one observation per requested Device, in order.
type ObservationLoader interface {
	LoadObservations(context.Context, []node.ID) ([]Observation, error)
}

// Clock supplies this host's time to age delivery records, which MeshCore
// hosts stamp on their own clocks; durable authority is evaluated on the
// database clock.
type Clock interface{ Now() time.Time }

// Device is one row of the distribution report.
type Device struct {
	ID          node.ID
	Hostname    string
	State       string
	Status      Status
	Enforcement Enforcement
	Observation Observation
	// RouteEnforcement compares a router's reported route digest with the
	// served routes it was delivered; RouteHealth is its current Site
	// health, empty when it has none or it is older than RouteHealthStale.
	RouteEnforcement Enforcement
	RouteHealth      []SiteHealth
	// RouteSelection is the router the Device uses for each Site it
	// reaches, empty when it reported none within RouteSelectionStale.
	RouteSelection []SiteRouter
}

// Report is one Device's standing against the Network's current revisions.
type Report struct {
	Scope           network.Scope
	NetworkRevision int64
	PolicyRevision  int64
	// ObservationsAvailable is false when delivery records could not be read;
	// the Device then reports StatusUnknown.
	ObservationsAvailable bool
	Device                Device
}

// Service joins durable intent with recorded delivery.
type Service struct {
	reader       Reader
	observations ObservationLoader
	clock        Clock
}

// NewService constructs a distribution reader through explicit dependencies.
func NewService(reader Reader, observations ObservationLoader, clock Clock) (*Service, error) {
	if reader == nil || observations == nil || clock == nil {
		return nil, ErrInvalidRequest
	}
	return &Service{reader: reader, observations: observations, clock: clock}, nil
}

// ReadDevice reports one Device of the scope.
func (service *Service) ReadDevice(ctx context.Context, session accountsession.Session, scope network.Scope,
	id node.ID) (Report, error) {
	if service == nil || ctx == nil || !session.IsValid() || !scope.IsValid() || !id.IsValid() {
		return Report{}, ErrInvalidRequest
	}
	target, err := service.reader.ReadTarget(ctx, session, scope, id)
	if err != nil {
		return Report{}, err
	}
	if !validTarget(target, scope, id) {
		return Report{}, ErrInvalidResult
	}
	if len(target.Devices) == 0 {
		return Report{}, ErrNotFound
	}
	held := target.Devices[0]
	report := Report{Scope: scope, NetworkRevision: target.NetworkRevision, PolicyRevision: target.PolicyRevision,
		Device: Device{ID: held.ID, Hostname: held.Hostname, State: held.State, Status: StatusUnknown,
			Enforcement: EnforcementUnknown, RouteEnforcement: EnforcementUnknown}}
	observations, err := service.observations.LoadObservations(ctx, []node.ID{id})
	if err != nil || len(observations) != 1 || !observations[0].IsValid() {
		// Delivery records are operational; the durable answer still stands.
		return report, nil
	}
	report.Device.Observation = observations[0]
	report.Device.Status = Classify(target.NetworkRevision, observations[0])
	now := service.clock.Now()
	report.Device.Enforcement = ClassifyEnforcement(observations[0], now)
	report.Device.RouteEnforcement = ClassifyRouteEnforcement(observations[0], now)
	report.Device.RouteHealth, _ = CurrentRouteHealth(observations[0], now)
	report.Device.RouteSelection, _ = CurrentRouteSelection(observations[0], now)
	report.ObservationsAvailable = true
	return report, nil
}

// Page is the standing of one page of a Device list against the Network's
// current revisions (D-1). Devices holds one row per requested Device, in
// order; a row is StatusUnknown when delivery records could not be read.
type Page struct {
	Scope                 network.Scope
	NetworkRevision       int64
	PolicyRevision        int64
	ObservationsAvailable bool
	Devices               []Device
}

// ReadPage reports up to MaximumObservationBatch Devices the caller already
// read from the inventory as active or suspended: one durable read of the
// current revisions under device.read, and one batch load of delivery
// records. It never scans the Network. A Device revoked or expired between
// the inventory read and this one keeps its listed state for this page; its
// status is still only read for an ID of the scope.
func (service *Service) ReadPage(ctx context.Context, session accountsession.Session, scope network.Scope,
	devices []TargetDevice) (Page, error) {
	if service == nil || ctx == nil || !session.IsValid() || !scope.IsValid() || len(devices) == 0 ||
		len(devices) > MaximumObservationBatch {
		return Page{}, ErrInvalidRequest
	}
	ids := make([]node.ID, len(devices))
	seen := make(map[node.ID]struct{}, len(devices))
	for index, device := range devices {
		if _, duplicate := seen[device.ID]; duplicate || !device.ID.IsValid() || device.Hostname == "" ||
			(device.State != "active" && device.State != "suspended") {
			return Page{}, ErrInvalidRequest
		}
		seen[device.ID] = struct{}{}
		ids[index] = device.ID
	}
	// The target read authorizes device.read and returns the revisions even
	// when the Device it names was removed since the inventory read.
	target, err := service.reader.ReadTarget(ctx, session, scope, ids[0])
	if err != nil {
		return Page{}, err
	}
	if !validRevisions(target, scope, ids[0]) {
		return Page{}, ErrInvalidResult
	}
	page := Page{Scope: scope, NetworkRevision: target.NetworkRevision, PolicyRevision: target.PolicyRevision,
		Devices: make([]Device, len(devices))}
	for index, held := range devices {
		page.Devices[index] = Device{ID: held.ID, Hostname: held.Hostname, State: held.State, Status: StatusUnknown,
			Enforcement: EnforcementUnknown, RouteEnforcement: EnforcementUnknown}
	}
	observations, err := service.observations.LoadObservations(ctx, ids)
	if err != nil || len(observations) != len(ids) {
		// Delivery records are operational; the list still stands.
		return page, nil
	}
	for _, observation := range observations {
		if !observation.IsValid() {
			return page, nil
		}
	}
	now := service.clock.Now()
	for index, observation := range observations {
		row := &page.Devices[index]
		row.Observation = observation
		row.Status = Classify(target.NetworkRevision, observation)
		row.Enforcement = ClassifyEnforcement(observation, now)
		row.RouteEnforcement = ClassifyRouteEnforcement(observation, now)
	}
	page.ObservationsAvailable = true
	return page, nil
}

// validRevisions accepts a target read for its revisions: the scope asked,
// and at most the one Device asked.
func validRevisions(target Target, scope network.Scope, id node.ID) bool {
	if target.Scope != scope || target.NetworkRevision < 1 || target.PolicyRevision < 0 || len(target.Devices) > 1 {
		return false
	}
	return len(target.Devices) == 0 || target.Devices[0].ID == id
}

// Classify compares one observation with the current Network revision.
func Classify(networkRevision int64, observation Observation) Status {
	switch {
	case observation.Online && observation.Known && observation.NetworkRevision >= networkRevision:
		return StatusInSync
	case observation.Online:
		return StatusBehind
	case observation.Known:
		return StatusOffline
	default:
		return StatusNeverConnected
	}
}

func validTarget(target Target, scope network.Scope, id node.ID) bool {
	if target.Scope != scope || target.NetworkRevision < 1 || target.PolicyRevision < 0 || len(target.Devices) > 1 {
		return false
	}
	for _, device := range target.Devices {
		if device.ID != id || device.Hostname == "" || (device.State != "active" && device.State != "suspended") {
			return false
		}
	}
	return true
}
