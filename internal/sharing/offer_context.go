package sharing

import "github.com/meshtransit/meshtransit/internal/identity"

// OfferDisplayCodes names both ends of an offer with their twelve-digit
// display codes. Each side already knows them: the provider typed the
// consumer Network code and the consumer reaches the provider by name. A code
// is zero when its tenant has none.
type OfferDisplayCodes struct {
	ProviderWorkspace identity.DisplayCode
	ProviderNetwork   identity.DisplayCode
	ConsumerWorkspace identity.DisplayCode
	ConsumerNetwork   identity.DisplayCode
}

// IsValid reports whether every present code is a complete display code.
func (codes OfferDisplayCodes) IsValid() bool {
	for _, code := range []identity.DisplayCode{
		codes.ProviderWorkspace, codes.ProviderNetwork, codes.ConsumerWorkspace, codes.ConsumerNetwork,
	} {
		if code != "" && !code.IsValid() {
			return false
		}
	}
	return true
}

// WithContract returns a copy carrying the Trust Contract the offer was
// accepted into, so a listing can show its state and expiry. The contract
// must be the one the offer names.
func (snapshot OfferSnapshot) WithContract(contract Contract) (OfferSnapshot, error) {
	if !contract.IsValid() || contract.OfferID() != snapshot.offer.ID() ||
		contract.ID() != snapshot.offer.AcceptedContractID() {
		return OfferSnapshot{}, ErrInvalidManagementRequest
	}
	snapshot.contract, snapshot.hasContract = contract, true
	return snapshot, nil
}

// Contract returns the accepted Trust Contract and false before acceptance.
func (snapshot OfferSnapshot) Contract() (Contract, bool) {
	return snapshot.contract, snapshot.hasContract
}

// WithDisplayCodes returns a copy carrying both ends' display codes.
func (snapshot OfferSnapshot) WithDisplayCodes(codes OfferDisplayCodes) (OfferSnapshot, error) {
	if !codes.IsValid() {
		return OfferSnapshot{}, ErrInvalidManagementRequest
	}
	snapshot.displayCodes = codes
	return snapshot, nil
}

// DisplayCodes returns both ends' display codes; absent codes are zero.
func (snapshot OfferSnapshot) DisplayCodes() OfferDisplayCodes { return snapshot.displayCodes }
