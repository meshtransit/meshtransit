package accessgraph

import (
	"context"
	"errors"

	"meshtransit.net/core/internal/domain/identity/accountsession"
)

// Reader loads one freshly authorized effective-policy snapshot. It
// authorizes and evaluates expiry on the database clock.
type Reader interface {
	ReadActive(
		context.Context,
		accountsession.Session,
		Query,
	) (Snapshot, error)
}

// Dependencies contains explicit Access Graph effects.
type Dependencies struct {
	Reader Reader
	// GraphReader lists the effective graph; nil makes Graph unavailable.
	GraphReader GraphReader
}

// Service owns bounded, read-only policy explanation orchestration.
type Service struct {
	reader      Reader
	graphReader GraphReader
}

// NewService validates and constructs an Access Graph service.
func NewService(dependencies Dependencies) (*Service, error) {
	if dependencies.Reader == nil {
		return nil, ErrUnavailable
	}
	return &Service{reader: dependencies.Reader, graphReader: dependencies.GraphReader}, nil
}

// Explain derives allow or deny exclusively from the active compiled policy.
func (service *Service) Explain(
	ctx context.Context,
	session accountsession.Session,
	query Query,
) (Result, error) {
	if ctx == nil || service == nil || service.reader == nil ||
		!session.IsValid() || !query.IsValid() {
		return Result{}, ErrInvalidQuery
	}
	if err := ctx.Err(); err != nil {
		return Result{}, errors.Join(ErrUnavailable, err)
	}
	snapshot, err := service.reader.ReadActive(ctx, session, query)
	if err != nil {
		return Result{}, err
	}
	return newResult(query, snapshot)
}
