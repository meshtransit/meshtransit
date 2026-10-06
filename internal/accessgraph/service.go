package accessgraph

import (
	"context"
	"errors"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
)

// Reader loads one freshly authorized effective-policy snapshot.
type Reader interface {
	ReadActive(
		context.Context,
		accountsession.Session,
		Query,
		time.Time,
	) (Snapshot, error)
}

// Clock supplies the permission evaluation time.
type Clock interface{ Now() time.Time }

// SystemClock uses the process wall clock.
type SystemClock struct{}

// Now returns the current time.
func (SystemClock) Now() time.Time { return time.Now() }

// Dependencies contains explicit Access Graph effects.
type Dependencies struct {
	Reader Reader
	Clock  Clock
	// GraphReader lists the effective graph; nil makes Graph unavailable.
	GraphReader GraphReader
}

// Service owns bounded, read-only policy explanation orchestration.
type Service struct {
	reader      Reader
	clock       Clock
	graphReader GraphReader
}

// NewService validates and constructs an Access Graph service.
func NewService(dependencies Dependencies) (*Service, error) {
	if dependencies.Reader == nil || dependencies.Clock == nil {
		return nil, ErrUnavailable
	}
	return &Service{
		reader: dependencies.Reader, clock: dependencies.Clock, graphReader: dependencies.GraphReader,
	}, nil
}

// Explain derives allow or deny exclusively from the active compiled policy.
func (service *Service) Explain(
	ctx context.Context,
	session accountsession.Session,
	query Query,
) (Result, error) {
	if ctx == nil || service == nil || service.reader == nil || service.clock == nil ||
		!session.IsValid() || !query.IsValid() {
		return Result{}, ErrInvalidQuery
	}
	if err := ctx.Err(); err != nil {
		return Result{}, errors.Join(ErrUnavailable, err)
	}
	evaluatedAt := service.clock.Now().UTC()
	if evaluatedAt.IsZero() {
		return Result{}, ErrUnavailable
	}
	snapshot, err := service.reader.ReadActive(ctx, session, query, evaluatedAt)
	if err != nil {
		return Result{}, err
	}
	return newResult(query, snapshot)
}
