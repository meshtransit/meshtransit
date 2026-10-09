// Package distribution reports, per Device, whether it runs the Network's
// current policy: the intended Network revision from durable authority against
// what the control plane last delivered to the Device (R1-65).
package distribution

import (
	"context"
	"errors"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
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
// lease.
type Observation struct {
	Known             bool
	SessionGeneration int64
	NetworkRevision   int64
	PolicyRevision    int64
	DeliveredAt       time.Time
	SeenAt            time.Time
	Online            bool
}

// IsValid reports a self-consistent observation.
func (observation Observation) IsValid() bool {
	if !observation.Known {
		return observation.SessionGeneration == 0 && observation.NetworkRevision == 0 &&
			observation.PolicyRevision == 0 && observation.DeliveredAt.IsZero() && observation.SeenAt.IsZero()
	}
	return observation.SessionGeneration > 0 && observation.NetworkRevision > 0 &&
		observation.PolicyRevision >= 0 && !observation.DeliveredAt.IsZero() &&
		!observation.SeenAt.Before(observation.DeliveredAt)
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

// Reader authorizes and reads the durable side under device.read.
type Reader interface {
	ReadDistribution(context.Context, accountsession.Session, network.Scope, node.ID, int, time.Time) (Target, error)
}

// ObservationLoader returns one observation per requested Device, in order.
type ObservationLoader interface {
	LoadObservations(context.Context, []node.ID) ([]Observation, error)
}

// Clock provides the current authority-evaluation instant.
type Clock interface{ Now() time.Time }

// Device is one row of the distribution report.
type Device struct {
	ID          node.ID
	Hostname    string
	State       string
	Status      Status
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
	target, err := service.reader.ReadDistribution(ctx, session, scope, after, limit+1, service.clock.Now())
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
			Status: StatusUnknown}
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
	for index, observation := range observations {
		if !observation.IsValid() {
			return page, nil
		}
		page.Devices[index].Observation = observation
		page.Devices[index].Status = Classify(target.NetworkRevision, observation)
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
