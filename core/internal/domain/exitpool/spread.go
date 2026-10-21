package exitpool

import (
	"context"
	"crypto/rand"
	"errors"
	"slices"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

// Mode is how a pool serves its consumers (exit node design §16).
type Mode string

const (
	// ModeKeep, in an update, keeps the stored mode: a client that does not
	// know modes never changes one.
	ModeKeep Mode = ""
	// ModeFailover sends every consumer through the elected primary.
	ModeFailover Mode = "failover"
	// ModeSpread gives each consumer its own exit node of the serving set.
	ModeSpread Mode = "spread"
)

// IsKnown reports failover or spread.
func (mode Mode) IsKnown() bool { return mode == ModeFailover || mode == ModeSpread }

// ErrSpreadDisabled reports a change to spread while the deployment has not
// enabled it (MESHTRANSIT_EXIT_SPREAD_ENABLED).
var ErrSpreadDisabled = errors.New("exitpool: spread pools are disabled")

// SpreadSaltSize is the size of a pool's assignment salt.
const SpreadSaltSize = 16

// NewSpreadSalt returns fresh random bytes; the store keeps a pool's first
// salt and never replaces it.
func NewSpreadSalt() ([SpreadSaltSize]byte, error) {
	var salt [SpreadSaltSize]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return salt, err
	}
	return salt, nil
}

// Serving is the serving set Core elected for a spread pool.
type Serving struct {
	// Devices are the exit nodes consumers are assigned to, in Device
	// order; empty when none can serve.
	Devices    []node.ID
	Generation int64
	Reason     string
	ChangedAt  time.Time
}

// Serving set change reasons.
const (
	ServingElected    = "elected"    // the first set of the pool
	ServingJoined     = "joined"     // exit nodes joined
	ServingFailover   = "failover"   // exit nodes failed, went silent or stopped serving
	ServingOverloaded = "overloaded" // exit nodes left while overloaded or without IPv4
	ServingRecovered  = "recovered"  // overloaded exit nodes came back
	ServingNone       = "none"       // no exit node can serve
)

// IsValidServingReason reports a reason a serving election records.
func IsValidServingReason(reason string) bool {
	switch reason {
	case ServingElected, ServingJoined, ServingFailover, ServingOverloaded, ServingRecovered, ServingNone:
		return true
	default:
		return false
	}
}

func validDevices(devices []node.ID) bool {
	if len(devices) > MaximumNodesPerPool {
		return false
	}
	for index, device := range devices {
		if !device.IsValid() || slices.Contains(devices[:index], device) {
			return false
		}
	}
	return true
}

// IsValid reports a self-consistent serving set.
func (serving Serving) IsValid() bool {
	return validDevices(serving.Devices) && serving.Generation > 0 && IsValidServingReason(serving.Reason) &&
		!serving.ChangedAt.IsZero()
}

// ServingChange is one change of a pool's serving set, as audited.
type ServingChange struct {
	EventID           publicid.ID
	OccurredAt        time.Time
	Devices, Previous []node.ID
	Reason            string
	Generation        int64
}

// IsValid reports a self-consistent change.
func (change ServingChange) IsValid() bool {
	return change.EventID.IsValid() && !change.OccurredAt.IsZero() && validDevices(change.Devices) &&
		validDevices(change.Previous) && IsValidServingReason(change.Reason) && change.Generation > 0
}

// ServingHistory is one page of a pool's serving set changes, newest first.
type ServingHistory struct {
	Changes []ServingChange
	HasMore bool
}

// ServingHistoryStore reads a pool's serving set changes from the audit
// history.
type ServingHistoryStore interface {
	ServingChanges(ctx context.Context, session accountsession.Session, scope network.Scope, pool ID,
		after publicid.ID, limit int) (ServingHistory, error)
}

// WithSpread returns the service allowing pools to become spread when
// enabled is true; a pool already spread stays editable either way.
func (service *Service) WithSpread(enabled bool) (*Service, error) {
	if service == nil {
		return nil, ErrInvalid
	}
	extended := *service
	extended.spread = enabled
	return &extended, nil
}

// WithServingHistory returns the service reading spread pools' serving set
// changes from history.
func (service *Service) WithServingHistory(history ServingHistoryStore) (*Service, error) {
	if service == nil || history == nil {
		return nil, ErrInvalid
	}
	extended := *service
	extended.servingHistory = history
	return &extended, nil
}

// admitMode refuses a pool becoming spread while spread is disabled; stored
// is the pool's mode now (failover for a new pool).
func (service *Service) admitMode(requested, stored Mode) error {
	if requested == ModeSpread && stored != ModeSpread && !service.spread {
		return ErrSpreadDisabled
	}
	return nil
}

// ServingChanges returns one page of a spread pool's serving set changes,
// newest first, after the change after when it is set.
func (service *Service) ServingChanges(ctx context.Context, session accountsession.Session, scope network.Scope,
	pool ID, after publicid.ID, limit int) (ServingHistory, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return ServingHistory{}, err
	}
	if service.servingHistory == nil {
		return ServingHistory{}, ErrUnavailable
	}
	if !pool.IsValid() || limit < 1 || limit > MaximumHistoryPage || (after != publicid.ID{} && !after.IsValid()) {
		return ServingHistory{}, ErrInvalid
	}
	history, err := service.servingHistory.ServingChanges(ctx, session, scope, pool, after, limit)
	if err != nil {
		return ServingHistory{}, err
	}
	if len(history.Changes) > limit {
		return ServingHistory{}, ErrInvalid
	}
	for _, change := range history.Changes {
		if !change.IsValid() {
			return ServingHistory{}, ErrInvalid
		}
	}
	return history, nil
}
