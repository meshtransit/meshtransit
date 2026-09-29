package sharing

import (
	"context"
	"errors"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
)

// Repository is the authoritative, transaction-owning Resource Sharing boundary.
// Implementations must authorize against current PostgreSQL authority and commit
// lifecycle mutation, audit evidence, outbox evidence, and idempotency together.
type Repository interface {
	CreateOffer(context.Context, CreateOffer, time.Time) (MutationResult, error)
	DecideOffer(context.Context, DecideOffer, time.Time) (MutationResult, error)
	ActivateContract(context.Context, ActivateContract, time.Time) (MutationResult, error)
	RevokeContract(context.Context, RevokeContract, time.Time) (MutationResult, error)
	GetOffer(
		context.Context, accountsession.Session, network.Scope, OfferID, time.Time,
	) (OfferSnapshot, error)
	ListOffers(
		context.Context,
		accountsession.Session,
		network.Scope,
		Direction,
		OfferState,
		int,
		PageCursor,
		time.Time,
	) (OfferPage, error)
}

// ActivateContract makes accepted bilateral authority eligible for policy
// compilation. Endpoint and policy evaluation remain independently fail closed.
func (service *Service) ActivateContract(
	ctx context.Context,
	command ActivateContract,
) (MutationResult, error) {
	if ctx == nil || service == nil || service.repository == nil || service.clock == nil ||
		!command.IsValid() {
		return MutationResult{}, ErrInvalidManagementRequest
	}
	evaluatedAt, err := service.evaluatedAt(ctx)
	if err != nil {
		return MutationResult{}, err
	}
	result, err := service.repository.ActivateContract(ctx, command, evaluatedAt)
	if err != nil {
		return MutationResult{}, err
	}
	if !activateContractResultMatches(result, command) {
		return MutationResult{}, ErrUnavailable
	}
	return result, nil
}

// Clock supplies the security evaluation instant.
type Clock interface{ Now() time.Time }

// Service validates the Resource Sharing application boundary around one authority repository.
type Service struct {
	repository Repository
	clock      Clock
}

// NewService rejects incomplete application dependencies.
func NewService(repository Repository, clock Clock) (*Service, error) {
	if repository == nil || clock == nil {
		return nil, ErrUnavailable
	}
	return &Service{repository: repository, clock: clock}, nil
}

// CreateOffer commits one provider-bounded export and targeted offer.
func (service *Service) CreateOffer(
	ctx context.Context,
	command CreateOffer,
) (MutationResult, error) {
	if ctx == nil || service == nil || service.repository == nil || service.clock == nil ||
		!command.IsValid() {
		return MutationResult{}, ErrInvalidManagementRequest
	}
	evaluatedAt, err := service.evaluatedAt(ctx)
	if err != nil {
		return MutationResult{}, err
	}
	result, err := service.repository.CreateOffer(ctx, command, evaluatedAt)
	if err != nil {
		return MutationResult{}, err
	}
	if !createOfferResultMatches(result, command) {
		return MutationResult{}, ErrUnavailable
	}
	return result, nil
}

// DecideOffer commits one consumer acceptance/rejection or provider withdrawal.
func (service *Service) DecideOffer(
	ctx context.Context,
	command DecideOffer,
) (MutationResult, error) {
	if ctx == nil || service == nil || service.repository == nil || service.clock == nil ||
		!command.IsValid() {
		return MutationResult{}, ErrInvalidManagementRequest
	}
	evaluatedAt, err := service.evaluatedAt(ctx)
	if err != nil {
		return MutationResult{}, err
	}
	result, err := service.repository.DecideOffer(ctx, command, evaluatedAt)
	if err != nil {
		return MutationResult{}, err
	}
	if !decideOfferResultMatches(result, command) {
		return MutationResult{}, ErrUnavailable
	}
	return result, nil
}

// RevokeContract terminally removes a bilateral Trust Contract from either side.
func (service *Service) RevokeContract(
	ctx context.Context,
	command RevokeContract,
) (MutationResult, error) {
	if ctx == nil || service == nil || service.repository == nil || service.clock == nil ||
		!command.IsValid() {
		return MutationResult{}, ErrInvalidManagementRequest
	}
	evaluatedAt, err := service.evaluatedAt(ctx)
	if err != nil {
		return MutationResult{}, err
	}
	result, err := service.repository.RevokeContract(ctx, command, evaluatedAt)
	if err != nil {
		return MutationResult{}, err
	}
	if !revokeContractResultMatches(result, command) {
		return MutationResult{}, ErrUnavailable
	}
	return result, nil
}

// GetOffer returns one freshly authorized offer visible from the exact local side.
func (service *Service) GetOffer(
	ctx context.Context,
	session accountsession.Session,
	scope network.Scope,
	id OfferID,
) (OfferSnapshot, error) {
	if ctx == nil || service == nil || service.repository == nil || service.clock == nil ||
		!session.IsValid() || !scope.IsValid() || !id.IsValid() {
		return OfferSnapshot{}, ErrInvalidManagementRequest
	}
	evaluatedAt, err := service.evaluatedAt(ctx)
	if err != nil {
		return OfferSnapshot{}, err
	}
	snapshot, err := service.repository.GetOffer(ctx, session, scope, id, evaluatedAt)
	if err != nil {
		return OfferSnapshot{}, err
	}
	if !snapshot.IsValid() || snapshot.Offer().ID() != id || !offerContainsScope(snapshot, scope) {
		return OfferSnapshot{}, ErrUnavailable
	}
	return snapshot, nil
}

// ListOffers returns one revision-pinned page from one local side.
func (service *Service) ListOffers(
	ctx context.Context,
	session accountsession.Session,
	scope network.Scope,
	direction Direction,
	state OfferState,
	limit int,
	cursor PageCursor,
) (OfferPage, error) {
	if ctx == nil || service == nil || service.repository == nil || service.clock == nil ||
		!session.IsValid() || !scope.IsValid() || !direction.IsValid() ||
		(state != OfferStateUnknown && !validManagementOfferState(state)) ||
		limit < 1 || limit > MaximumManagementPageSize ||
		(cursor != (PageCursor{}) && !cursor.IsValid()) {
		return OfferPage{}, ErrInvalidManagementRequest
	}
	evaluatedAt, err := service.evaluatedAt(ctx)
	if err != nil {
		return OfferPage{}, err
	}
	page, err := service.repository.ListOffers(
		ctx, session, scope, direction, state, limit, cursor, evaluatedAt,
	)
	if err != nil {
		return OfferPage{}, err
	}
	if !offerPageMatches(page, scope, direction, state, limit, cursor) {
		return OfferPage{}, ErrUnavailable
	}
	return page, nil
}

func (service *Service) evaluatedAt(ctx context.Context) (time.Time, error) {
	if err := ctx.Err(); err != nil {
		return time.Time{}, errors.Join(ErrUnavailable, err)
	}
	evaluatedAt := service.clock.Now().UTC()
	if evaluatedAt.IsZero() {
		return time.Time{}, ErrUnavailable
	}
	return evaluatedAt, nil
}

func createOfferResultMatches(result MutationResult, command CreateOffer) bool {
	offer, hasOffer := result.Offer()
	token, hasToken := result.Token()
	_, hasContract := result.Contract()
	return result.IsValid() && hasOffer && hasToken && token.IsValid() && !hasContract &&
		offer.Offer().State() == OfferStateOffered && offer.Offer().Version() == 1 &&
		offer.Offer().ProviderScope() == command.ProviderScope() &&
		offer.Offer().ConsumerScope() == command.ConsumerScope() &&
		offer.Resource().ResourceID() == command.ResourceID() &&
		offer.Offer().MaximumTraffic().Hash() == command.MaximumTraffic().Hash() &&
		offer.Offer().ExpiresAt().Equal(command.ExpiresAt())
}

func decideOfferResultMatches(result MutationResult, command DecideOffer) bool {
	offer, hasOffer := result.Offer()
	contract, hasContract := result.Contract()
	_, hasToken := result.Token()
	if !result.IsValid() || !hasOffer || hasToken || offer.Offer().ID() != command.OfferID() ||
		offer.Offer().ProviderScope() != command.ProviderScope() ||
		offer.Offer().ConsumerScope() != command.ConsumerScope() ||
		offer.Offer().Version() != command.ExpectedOfferVersion()+1 {
		return false
	}
	switch command.Action() {
	case DecisionActionAccept:
		return hasContract && offer.Offer().State() == OfferStateAccepted &&
			contract.ID() == offer.Offer().AcceptedContractID() &&
			contract.State() == ContractStateActivating && contract.Version() == 1 &&
			contract.ProviderScope() == command.ProviderScope() &&
			contract.ConsumerScope() == command.ConsumerScope() &&
			contract.Resource() == offer.Resource() &&
			contract.MaximumTraffic().Hash() == offer.Offer().MaximumTraffic().Hash()
	case DecisionActionReject:
		return !hasContract && offer.Offer().State() == OfferStateRejected
	case DecisionActionRevoke:
		return !hasContract && offer.Offer().State() == OfferStateRevoked
	default:
		return false
	}
}

func revokeContractResultMatches(result MutationResult, command RevokeContract) bool {
	offer, hasOffer := result.Offer()
	contract, hasContract := result.Contract()
	_, hasToken := result.Token()
	return result.IsValid() && hasOffer && hasContract && !hasToken &&
		contract.ID() == command.ContractID() && contract.State() == ContractStateRevoked &&
		contract.Version() == command.ExpectedContractVersion()+1 &&
		contract.ProviderScope() == command.ProviderScope() &&
		contract.ConsumerScope() == command.ConsumerScope() &&
		offer.Offer().ID() == contract.OfferID() && offer.Offer().State() == OfferStateAccepted
}

func activateContractResultMatches(result MutationResult, command ActivateContract) bool {
	offer, hasOffer := result.Offer()
	contract, hasContract := result.Contract()
	_, hasToken := result.Token()
	return result.IsValid() && hasOffer && hasContract && !hasToken &&
		contract.ID() == command.ContractID() && contract.State() == ContractStateActive &&
		contract.Version() == command.ExpectedContractVersion()+1 &&
		contract.ProviderScope() == command.ProviderScope() &&
		contract.ConsumerScope() == command.ConsumerScope() &&
		offer.Offer().ID() == contract.OfferID() && offer.Offer().State() == OfferStateAccepted
}

func offerContainsScope(snapshot OfferSnapshot, scope network.Scope) bool {
	return snapshot.Offer().ProviderScope() == scope || snapshot.Offer().ConsumerScope() == scope
}

func offerPageMatches(
	page OfferPage,
	scope network.Scope,
	direction Direction,
	state OfferState,
	limit int,
	cursor PageCursor,
) bool {
	if !page.IsValid() || len(page.Items()) > limit ||
		(cursor.IsValid() && page.Revision() != cursor.Revision()) {
		return false
	}
	for _, snapshot := range page.Items() {
		offer := snapshot.Offer()
		if direction == DirectionOutgoing && offer.ProviderScope() != scope ||
			direction == DirectionIncoming && offer.ConsumerScope() != scope ||
			state != OfferStateUnknown && offer.State() != state {
			return false
		}
	}
	return true
}

func validManagementOfferState(state OfferState) bool {
	return state == OfferStateOffered || state == OfferStateAccepted ||
		state == OfferStateRejected || state == OfferStateExpired || state == OfferStateRevoked
}

// SystemClock supplies the current UTC time.
type SystemClock struct{}

// Now reads wall time.
func (SystemClock) Now() time.Time { return time.Now().UTC() }
