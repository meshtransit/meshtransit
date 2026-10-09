package simulation

import (
	"context"
	"errors"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/policy/compilation"
	"github.com/meshtransit/meshtransit/core/internal/domain/policy/publication"
)

// BaselineReader returns freshly authorized complete active-policy evidence.
// Implementations must not mutate policy authority.
type BaselineReader interface {
	ReadSimulationBaseline(
		context.Context,
		accountsession.Session,
		network.Scope,
		time.Time,
	) (Baseline, error)
}

// Clock supplies the permission evaluation time for each authority read.
type Clock interface{ Now() time.Time }

// SystemClock uses the process wall clock.
type SystemClock struct{}

// Now returns the current time.
func (SystemClock) Now() time.Time { return time.Now() }

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
	Clock     Clock
}

// Service brackets the publication compiler with two authoritative baseline reads.
type Service struct {
	baselines BaselineReader
	compiler  Compiler
	clock     Clock
}

// NewService validates and constructs a read-only policy simulation service.
func NewService(dependencies Dependencies) (*Service, error) {
	if dependencies.Baselines == nil || dependencies.Compiler == nil || dependencies.Clock == nil {
		return nil, ErrUnavailable
	}
	return &Service{
		baselines: dependencies.Baselines,
		compiler:  dependencies.Compiler,
		clock:     dependencies.Clock,
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
		service.clock == nil ||
		!session.IsValid() || !request.IsValid() {
		return Result{}, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return Result{}, errors.Join(ErrUnavailable, err)
	}
	beforeEvaluatedAt := service.clock.Now().UTC()
	if beforeEvaluatedAt.IsZero() {
		return Result{}, ErrUnavailable
	}
	before, err := service.baselines.ReadSimulationBaseline(
		ctx,
		session,
		request.Scope(),
		beforeEvaluatedAt,
	)
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
	afterEvaluatedAt := service.clock.Now().UTC()
	if afterEvaluatedAt.IsZero() {
		return Result{}, ErrUnavailable
	}
	after, err := service.baselines.ReadSimulationBaseline(
		ctx,
		session,
		request.Scope(),
		afterEvaluatedAt,
	)
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
