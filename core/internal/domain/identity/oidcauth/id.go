package oidcauth

import (
	"errors"

	"meshtransit.net/core/internal/domain/publicid"
)

var (
	// ErrInvalidTransactionID reports an absent or malformed login transaction ID.
	ErrInvalidTransactionID = errors.New("oidc auth: invalid transaction id")
	// ErrInvalidProviderID reports an absent or malformed identity provider ID.
	ErrInvalidProviderID = errors.New("oidc auth: invalid provider id")
	// ErrInvalidClientID reports an absent or malformed identity provider client ID.
	ErrInvalidClientID = errors.New("oidc auth: invalid client id")
)

// TransactionID is a validated UUIDv7 for one single-use login transaction.
type TransactionID publicid.ID

// NewTransactionID validates a binary login transaction ID.
func NewTransactionID(value [16]byte) (TransactionID, error) {
	id, err := publicid.FromBytes(value)
	if err != nil {
		return TransactionID{}, ErrInvalidTransactionID
	}
	return TransactionID(id), nil
}

// ParseTransactionID validates a canonical login transaction ID.
func ParseTransactionID(value string) (TransactionID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return TransactionID{}, ErrInvalidTransactionID
	}
	return TransactionID(id), nil
}

// Bytes returns a defensive binary copy.
func (id TransactionID) Bytes() [16]byte { return publicid.ID(id).Bytes() }

// String returns the canonical UUID representation.
func (id TransactionID) String() string { return publicid.ID(id).String() }

// IsValid reports whether the transaction ID remains canonical.
func (id TransactionID) IsValid() bool { return publicid.ID(id).IsValid() }

// ProviderID is a validated UUIDv7 for one configured OIDC trust anchor.
type ProviderID publicid.ID

// NewProviderID validates a binary provider ID.
func NewProviderID(value [16]byte) (ProviderID, error) {
	id, err := publicid.FromBytes(value)
	if err != nil {
		return ProviderID{}, ErrInvalidProviderID
	}
	return ProviderID(id), nil
}

// ParseProviderID validates a canonical provider ID.
func ParseProviderID(value string) (ProviderID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return ProviderID{}, ErrInvalidProviderID
	}
	return ProviderID(id), nil
}

// Bytes returns a defensive binary copy.
func (id ProviderID) Bytes() [16]byte { return publicid.ID(id).Bytes() }

// String returns the canonical UUID representation.
func (id ProviderID) String() string { return publicid.ID(id).String() }

// IsValid reports whether the provider ID remains canonical.
func (id ProviderID) IsValid() bool { return publicid.ID(id).IsValid() }

// ClientID is a validated UUIDv7 for one exact OIDC client registration.
type ClientID publicid.ID

// NewClientID validates a binary provider-client ID.
func NewClientID(value [16]byte) (ClientID, error) {
	id, err := publicid.FromBytes(value)
	if err != nil {
		return ClientID{}, ErrInvalidClientID
	}
	return ClientID(id), nil
}

// ParseClientID validates a canonical provider-client ID.
func ParseClientID(value string) (ClientID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return ClientID{}, ErrInvalidClientID
	}
	return ClientID(id), nil
}

// Bytes returns a defensive binary copy.
func (id ClientID) Bytes() [16]byte { return publicid.ID(id).Bytes() }

// String returns the canonical UUID representation.
func (id ClientID) String() string { return publicid.ID(id).String() }

// IsValid reports whether the provider-client ID remains canonical.
func (id ClientID) IsValid() bool { return publicid.ID(id).IsValid() }
