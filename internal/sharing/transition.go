package sharing

import "time"

// OfferAction is one explicit Share Offer state transition.
type OfferAction uint8

const (
	// OfferActionUnknown is the unusable zero value.
	OfferActionUnknown OfferAction = iota
	// OfferActionAccept records consumer acceptance.
	OfferActionAccept
	// OfferActionReject records consumer rejection.
	OfferActionReject
	// OfferActionExpire records deadline exhaustion.
	OfferActionExpire
	// OfferActionRevoke records provider withdrawal before acceptance.
	OfferActionRevoke
)

// TransitionOffer applies one monotonic CAS transition to an offered snapshot.
func TransitionOffer(
	offer Offer,
	action OfferAction,
	contractID ContractID,
	evaluatedAt time.Time,
) (Offer, error) {
	if !offer.IsValid() || evaluatedAt.IsZero() || offer.params.State != OfferStateOffered {
		return Offer{}, ErrInvalidTransition
	}
	evaluatedAt = evaluatedAt.UTC()

	var nextState OfferState
	switch action {
	case OfferActionAccept:
		if !contractID.IsValid() || !evaluatedAt.Before(offer.params.ExpiresAt) {
			return Offer{}, ErrInvalidTransition
		}
		nextState = OfferStateAccepted
	case OfferActionReject:
		if contractID.IsValid() || !evaluatedAt.Before(offer.params.ExpiresAt) {
			return Offer{}, ErrInvalidTransition
		}
		nextState = OfferStateRejected
	case OfferActionRevoke:
		if contractID.IsValid() || !evaluatedAt.Before(offer.params.ExpiresAt) {
			return Offer{}, ErrInvalidTransition
		}
		nextState = OfferStateRevoked
	case OfferActionExpire:
		if contractID.IsValid() || evaluatedAt.Before(offer.params.ExpiresAt) {
			return Offer{}, ErrInvalidTransition
		}
		nextState = OfferStateExpired
	default:
		return Offer{}, ErrInvalidTransition
	}

	params := offer.params
	params.State = nextState
	params.Version++
	params.DecidedAt = evaluatedAt
	params.AcceptedContractID = contractID
	return NewOffer(params)
}

// ContractAction is one terminal Trust Contract transition.
type ContractAction uint8

const (
	// ContractActionUnknown is the unusable zero value.
	ContractActionUnknown ContractAction = iota
	// ContractActionActivate publishes a safely resolved path for an accepted contract.
	ContractActionActivate
	// ContractActionRevoke records unilateral provider or consumer revocation.
	ContractActionRevoke
	// ContractActionExpire records validity-window exhaustion.
	ContractActionExpire
	// ContractActionInvalidate records stale Resource, generation, or recovery authority.
	ContractActionInvalidate
)

// TransitionContract applies one terminal transition to an active contract.
func TransitionContract(
	contract Contract,
	action ContractAction,
	evaluatedAt time.Time,
) (Contract, error) {
	if !contract.IsValid() || evaluatedAt.IsZero() ||
		(contract.params.State != ContractStateActivating && contract.params.State != ContractStateActive) {
		return Contract{}, ErrInvalidTransition
	}
	evaluatedAt = evaluatedAt.UTC()

	var nextState ContractState
	switch action {
	case ContractActionActivate:
		if contract.params.State != ContractStateActivating ||
			!evaluatedAt.Before(contract.params.ExpiresAt) {
			return Contract{}, ErrInvalidTransition
		}
		nextState = ContractStateActive
	case ContractActionRevoke:
		if !evaluatedAt.Before(contract.params.ExpiresAt) {
			return Contract{}, ErrInvalidTransition
		}
		nextState = ContractStateRevoked
	case ContractActionExpire:
		if evaluatedAt.Before(contract.params.ExpiresAt) {
			return Contract{}, ErrInvalidTransition
		}
		nextState = ContractStateExpired
	case ContractActionInvalidate:
		nextState = ContractStateInvalidated
	default:
		return Contract{}, ErrInvalidTransition
	}

	params := contract.params
	params.State = nextState
	params.Version++
	if nextState != ContractStateActive {
		params.EndedAt = evaluatedAt
	}
	return NewContract(params)
}
