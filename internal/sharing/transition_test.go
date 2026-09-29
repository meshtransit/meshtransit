package sharing

import (
	"errors"
	"testing"
)

func TestTransitionOfferEnforcesSingleTerminalDecisionAndExclusiveExpiry(t *testing.T) {
	t.Parallel()

	offer := mustOffer(t)
	contractID, err := ParseContractID(uuidWithSuffix(10))
	if err != nil {
		t.Fatalf("ParseContractID() error = %v", err)
	}
	accepted, err := TransitionOffer(
		offer,
		OfferActionAccept,
		contractID,
		offer.ExpiresAt().Add(-1),
	)
	if err != nil {
		t.Fatalf("TransitionOffer() error = %v", err)
	}
	if accepted.State() != OfferStateAccepted || accepted.Version() != offer.Version()+1 ||
		accepted.AcceptedContractID() != contractID {
		t.Fatalf("accepted offer = %#v, want terminal accepted version", accepted)
	}
	if _, err := TransitionOffer(
		accepted,
		OfferActionReject,
		ContractID{},
		accepted.DecidedAt(),
	); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("second decision error = %v, want ErrInvalidTransition", err)
	}
	if _, err := TransitionOffer(
		offer,
		OfferActionAccept,
		contractID,
		offer.ExpiresAt(),
	); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("deadline acceptance error = %v, want ErrInvalidTransition", err)
	}
	expired, err := TransitionOffer(
		offer,
		OfferActionExpire,
		ContractID{},
		offer.ExpiresAt(),
	)
	if err != nil || expired.State() != OfferStateExpired {
		t.Fatalf("expiry = %#v, %v, want terminal expired", expired, err)
	}
}

func TestTransitionContractIsTerminalAndMonotonic(t *testing.T) {
	t.Parallel()

	contract := mustContract(t)
	revoked, err := TransitionContract(
		contract,
		ContractActionRevoke,
		contract.ExpiresAt().Add(-1),
	)
	if err != nil {
		t.Fatalf("TransitionContract() error = %v", err)
	}
	if revoked.State() != ContractStateRevoked || revoked.Version() != contract.Version()+1 {
		t.Fatalf("revoked contract = %#v, want terminal version", revoked)
	}
	if _, err := TransitionContract(
		revoked,
		ContractActionInvalidate,
		revoked.EndedAt(),
	); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("second transition error = %v, want ErrInvalidTransition", err)
	}
	if _, err := TransitionContract(
		contract,
		ContractActionExpire,
		contract.ExpiresAt().Add(-1),
	); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("early expiry error = %v, want ErrInvalidTransition", err)
	}
}
