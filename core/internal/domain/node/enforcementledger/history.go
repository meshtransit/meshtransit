package enforcementledger

import (
	"context"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
)

// MaximumHistoryPageSize bounds each authenticated history page.
const MaximumHistoryPageSize = 100

var (
	// ErrInvalidRequest reports invalid input before any read.
	ErrInvalidRequest = errors.New("enforcement history: invalid request")
	// ErrInvalidResult conceals malformed storage evidence.
	ErrInvalidResult = errors.New("enforcement history: invalid result")
	// ErrForbidden conceals missing or revoked exact-scope authority.
	ErrForbidden = errors.New("enforcement history: forbidden")
	// ErrUnavailable reports a failed durable dependency.
	ErrUnavailable = errors.New("enforcement history: unavailable")
)

// Evidence is what one Device was shown to enforce over one interval.
// ValidTo is zero while the interval is open; Hostname is empty when the
// Device no longer exists.
type Evidence struct {
	DeviceID        node.ID
	Hostname        string
	State           State
	NetworkRevision int64
	Delivered       distribution.FilterSummary
	Enforced        distribution.FilterSummary
	AppliedAt       time.Time
	ReportedAt      time.Time
	ValidFrom       time.Time
	ValidTo         time.Time
}

// HistoryResult is the durable side of one history page.
type HistoryResult struct {
	Scope         network.Scope
	At            time.Time
	RecordedSince time.Time
	Devices       []Evidence
}

// HistoryReader authorizes and reads evidence at an instant under
// device.read, on the database clock: a zero at reads the database's present,
// and an at after it is refused with ErrInvalidRequest.
type HistoryReader interface {
	ReadEnforcementHistory(ctx context.Context, session accountsession.Session, scope network.Scope, at time.Time,
		after node.ID, limit int) (HistoryResult, error)
}

// HistoryPage is one ordered page of evidence in effect at At.
type HistoryPage struct {
	Scope         network.Scope
	At            time.Time
	RecordedSince time.Time
	Devices       []Evidence
	Next          node.ID
}

// HistoryService reads enforcement evidence at an instant.
type HistoryService struct {
	reader HistoryReader
}

// NewHistoryService validates its dependencies.
func NewHistoryService(reader HistoryReader) (*HistoryService, error) {
	if nilPort(reader) {
		return nil, ErrInvalidRequest
	}
	return &HistoryService{reader: reader}, nil
}

// Read returns one page of evidence in effect at at; a zero at reads the
// present. Instants in the future are refused. Present and future are the
// database clock's.
func (service *HistoryService) Read(ctx context.Context, session accountsession.Session, scope network.Scope,
	at time.Time, after node.ID, limit int) (HistoryPage, error) {
	if service == nil || ctx == nil || !session.IsValid() || !scope.IsValid() ||
		limit < 1 || limit > MaximumHistoryPageSize || (after != node.ID{} && !after.IsValid()) {
		return HistoryPage{}, ErrInvalidRequest
	}
	if !at.IsZero() {
		at = at.UTC().Truncate(time.Microsecond)
	}
	result, err := service.reader.ReadEnforcementHistory(ctx, session, scope, at, after, limit+1)
	if err != nil {
		return HistoryPage{}, err
	}
	if at.IsZero() {
		// The reader read the database's present.
		at = result.At
	}
	if at.IsZero() || !validHistory(result, scope, at, after, limit+1) {
		return HistoryPage{}, ErrInvalidResult
	}
	page := HistoryPage{Scope: scope, At: at, RecordedSince: result.RecordedSince, Devices: result.Devices}
	if len(page.Devices) > limit {
		page.Devices = page.Devices[:limit]
		page.Next = page.Devices[limit-1].DeviceID
	}
	return page, nil
}

func validHistory(result HistoryResult, scope network.Scope, at time.Time, after node.ID, limit int) bool {
	if result.Scope != scope || !result.At.Equal(at) || len(result.Devices) > limit ||
		(len(result.Devices) > 0 && (result.RecordedSince.IsZero() || result.RecordedSince.After(at))) {
		return false
	}
	previous := after
	for _, evidence := range result.Devices {
		agrees := (evidence.State == StateEnforced) == (evidence.Delivered.Digest == evidence.Enforced.Digest)
		inEffect := !evidence.ValidFrom.After(at) && (evidence.ValidTo.IsZero() || evidence.ValidTo.After(at))
		if !evidence.DeviceID.IsValid() || (previous != node.ID{} && evidence.DeviceID.String() <= previous.String()) ||
			(evidence.State != StateEnforced && evidence.State != StateMismatch) || !agrees || !inEffect ||
			evidence.NetworkRevision < 1 || evidence.Delivered.IsZero() || evidence.Enforced.IsZero() ||
			evidence.AppliedAt.IsZero() || evidence.ReportedAt.After(evidence.ValidFrom.Add(time.Minute)) {
			return false
		}
		previous = evidence.DeviceID
	}
	return true
}
