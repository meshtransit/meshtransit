package simulation

import (
	"context"
	"errors"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/policy/publication"
)

// BaselineReader returns freshly authorized complete active-policy evidence.
// Each read authorizes and evaluates expiry on the database clock of its own
// transaction. Implementations must not mutate policy authority.
type BaselineReader interface {
	ReadSimulationBaseline(
		context.Context,
		accountsession.Session,
		network.Scope,
	) (Baseline, error)
}

// Compiler is the publication compiler seam. Production must inject the same
// implementation used to build publishable policy candidates.
type Compiler interface {
	Compile(
		context.Context,
		accountsession.Session,
		compilation.Request,
	) (publication.Candidate, error)
}

// Dependencies contains the only effects used by simulation.
type Dependencies struct {
	Baselines BaselineReader
	Compiler  Compiler
}

// Service brackets the publication compiler with two authoritative baseline reads.
type Service struct {
	baselines BaselineReader
	compiler  Compiler
}

// NewService validates and constructs a read-only policy simulation service.
func NewService(dependencies Dependencies) (*Service, error) {
	if dependencies.Baselines == nil || dependencies.Compiler == nil {
		return nil, ErrUnavailable
	}
	return &Service{
		baselines: dependencies.Baselines,
		compiler:  dependencies.Compiler,
	}, nil
}

// Simulate compiles one draft with the publication compiler and derives an
// impact only when the complete authority baseline remains unchanged.
func (service *Service) Simulate(
	ctx context.Context,
	session accountsession.Session,
	request compilation.Request,
) (Result, error) {
	if ctx == nil || service == nil || service.baselines == nil || service.compiler == nil ||
		!session.IsValid() || !request.IsValid() {
		return Result{}, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return Result{}, errors.Join(ErrUnavailable, err)
	}
	before, err := service.baselines.ReadSimulationBaseline(ctx, session, request.Scope())
	if err != nil {
		return Result{}, err
	}
	if !before.IsValid() || before.Scope() != request.Scope() {
		return Result{}, ErrInvalidBaseline
	}
	if request.Revision() != before.RevisionVector().PolicyRevision()+1 {
		return Result{}, ErrStaleInputs
	}
	proposed, err := service.compiler.Compile(ctx, session, request)
	if err != nil {
		return Result{}, err
	}
	if !proposed.IsValid() || proposed.Snapshot().Scope() != request.Scope() ||
		proposed.Snapshot().Revision() != request.Revision() {
		return Result{}, ErrInvalidResult
	}
	after, err := service.baselines.ReadSimulationBaseline(ctx, session, request.Scope())
	if err != nil {
		return Result{}, err
	}
	if !after.IsValid() || after.Scope() != request.Scope() {
		return Result{}, ErrInvalidBaseline
	}
	if !before.Equal(after) {
		return Result{}, ErrStaleInputs
	}
	return newResult(before, proposed)
}
