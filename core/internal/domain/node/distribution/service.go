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

// MaximumPageSize bounds each authenticated distribution page.
const MaximumPageSize = 100

var (
	// ErrInvalidRequest reports invalid input before any read.
	ErrInvalidRequest = errors.New("device distribution: invalid request")
	// ErrInvalidResult conceals malformed storage evidence.
	ErrInvalidResult = errors.New("device distribution: invalid result")
	// ErrForbidden conceals missing or revoked exact-scope authority.
	ErrForbidden = errors.New("device distribution: forbidden")
	// ErrUnavailable reports a failed durable dependency.
	ErrUnavailable = errors.New("device distribution: unavailable")
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
			observation.Connectivity == nil && observation.PeerLimit.IsZero()
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
		!observation.SeenAt.Before(observation.DeliveredAt) && validEnforcement(observation)
}

// TargetDevice is a Device that should hold the current revision.
type TargetDevice struct {
	ID       node.ID
	Hostname string
	State    string
}

// Target is the durable side of one page: the current revisions and the
// active or suspended Devices, ordered by public ID.
type Target struct {
	Scope           network.Scope
	NetworkRevision int64
	PolicyRevision  int64
	Devices         []TargetDevice
}

// Reader authorizes and reads the durable side under device.read on the
// database clock.
type Reader interface {
	ReadDistribution(context.Context, accountsession.Session, network.Scope, node.ID, int) (Target, error)
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
}

// Page is one ordered page of the report.
type Page struct {
	Scope           network.Scope
	NetworkRevision int64
	PolicyRevision  int64
	// ObservationsAvailable is false when delivery records could not be read;
	// every Device then reports StatusUnknown.
	ObservationsAvailable bool
	Devices               []Device
	// Next is the public ID to continue after, or the zero ID on the last page.
	Next node.ID
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

// Read returns one page. after is the zero ID for the first page.
func (service *Service) Read(ctx context.Context, session accountsession.Session, scope network.Scope,
	after node.ID, limit int) (Page, error) {
	if service == nil || ctx == nil || !session.IsValid() || !scope.IsValid() ||
		limit < 1 || limit > MaximumPageSize || (after != node.ID{} && !after.IsValid()) {
		return Page{}, ErrInvalidRequest
	}
	target, err := service.reader.ReadDistribution(ctx, session, scope, after, limit+1)
	if err != nil {
		return Page{}, err
	}
	if !validTarget(target, scope, after, limit+1) {
		return Page{}, ErrInvalidResult
	}
	page := Page{Scope: scope, NetworkRevision: target.NetworkRevision, PolicyRevision: target.PolicyRevision}
	devices := target.Devices
	if len(devices) > limit {
		devices = devices[:limit]
		page.Next = devices[limit-1].ID
	}
	page.Devices = make([]Device, len(devices))
	ids := make([]node.ID, len(devices))
	for index, device := range devices {
		ids[index] = device.ID
		page.Devices[index] = Device{ID: device.ID, Hostname: device.Hostname, State: device.State,
			Status: StatusUnknown, Enforcement: EnforcementUnknown}
	}
	if len(ids) == 0 {
		page.ObservationsAvailable = true
		return page, nil
	}
	observations, err := service.observations.LoadObservations(ctx, ids)
	if err != nil || len(observations) != len(ids) {
		// Delivery records are operational; the durable list still answers.
		return page, nil
	}
	now := service.clock.Now()
	for index, observation := range observations {
		if !observation.IsValid() {
			return page, nil
		}
		page.Devices[index].Observation = observation
		page.Devices[index].Status = Classify(target.NetworkRevision, observation)
		page.Devices[index].Enforcement = ClassifyEnforcement(observation, now)
	}
	page.ObservationsAvailable = true
	return page, nil
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

func validTarget(target Target, scope network.Scope, after node.ID, limit int) bool {
	if target.Scope != scope || target.NetworkRevision < 1 || target.PolicyRevision < 0 ||
		len(target.Devices) > limit {
		return false
	}
	previous := after
	for _, device := range target.Devices {
		validState := device.State == "active" || device.State == "suspended"
		if !device.ID.IsValid() || device.Hostname == "" || !validState ||
			(previous != node.ID{} && device.ID.String() <= previous.String()) {
			return false
		}
		previous = device.ID
	}
	return true
}
