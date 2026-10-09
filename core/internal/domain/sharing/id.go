// Package sharing owns bilateral Resource export, offer, acceptance, and
// revocation semantics without importing transport or persistence concerns.
package sharing

import (
	"errors"

	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

var (
	// ErrInvalidExportID reports an absent or malformed Resource Export ID.
	ErrInvalidExportID = errors.New("sharing: invalid export id")
	// ErrInvalidOfferID reports an absent or malformed Share Offer ID.
	ErrInvalidOfferID = errors.New("sharing: invalid offer id")
	// ErrInvalidContractID reports an absent or malformed Trust Contract ID.
	ErrInvalidContractID = errors.New("sharing: invalid contract id")
	// ErrInvalidImportedResourceID reports an absent or malformed Imported Resource ID.
	ErrInvalidImportedResourceID = errors.New("sharing: invalid imported resource id")
	// ErrInvalidPrivateEndpointID reports an absent or malformed Private Endpoint ID.
	ErrInvalidPrivateEndpointID = errors.New("sharing: invalid private endpoint id")
)

// ExportID is a validated opaque UUIDv7 identifying one Resource Export.
type ExportID publicid.ID

// ParseExportID validates a Resource Export ID from its canonical string.
func ParseExportID(value string) (ExportID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return ExportID{}, ErrInvalidExportID
	}
	return ExportID(id), nil
}

// String returns the lowercase canonical UUID representation.
func (id ExportID) String() string { return publicid.ID(id).String() }

// Bytes returns a copy of the binary UUID representation.
func (id ExportID) Bytes() [16]byte { return publicid.ID(id).Bytes() }

// IsValid reports whether the ID satisfies the public identity contract.
func (id ExportID) IsValid() bool { return publicid.ID(id).IsValid() }

// OfferID is a validated opaque UUIDv7 identifying one Share Offer.
type OfferID publicid.ID

// ParseOfferID validates a Share Offer ID from its canonical string.
func ParseOfferID(value string) (OfferID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return OfferID{}, ErrInvalidOfferID
	}
	return OfferID(id), nil
}

// String returns the lowercase canonical UUID representation.
func (id OfferID) String() string { return publicid.ID(id).String() }

// Bytes returns a copy of the binary UUID representation.
func (id OfferID) Bytes() [16]byte { return publicid.ID(id).Bytes() }

// IsValid reports whether the ID satisfies the public identity contract.
func (id OfferID) IsValid() bool { return publicid.ID(id).IsValid() }

// ContractID is a validated opaque UUIDv7 identifying one Trust Contract.
type ContractID publicid.ID

// ParseContractID validates a Trust Contract ID from its canonical string.
func ParseContractID(value string) (ContractID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return ContractID{}, ErrInvalidContractID
	}
	return ContractID(id), nil
}

// String returns the lowercase canonical UUID representation.
func (id ContractID) String() string { return publicid.ID(id).String() }

// Bytes returns a copy of the binary UUID representation.
func (id ContractID) Bytes() [16]byte { return publicid.ID(id).Bytes() }

// IsValid reports whether the ID satisfies the public identity contract.
func (id ContractID) IsValid() bool { return publicid.ID(id).IsValid() }

// ImportedResourceID is a validated opaque UUIDv7 identifying one consumer-local Resource.
type ImportedResourceID publicid.ID

// ParseImportedResourceID validates an Imported Resource ID from its canonical string.
func ParseImportedResourceID(value string) (ImportedResourceID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return ImportedResourceID{}, ErrInvalidImportedResourceID
	}
	return ImportedResourceID(id), nil
}

// String returns the lowercase canonical UUID representation.
func (id ImportedResourceID) String() string { return publicid.ID(id).String() }

// Bytes returns a copy of the binary UUID representation.
func (id ImportedResourceID) Bytes() [16]byte { return publicid.ID(id).Bytes() }

// IsValid reports whether the ID satisfies the public identity contract.
func (id ImportedResourceID) IsValid() bool { return publicid.ID(id).IsValid() }

// PrivateEndpointID is a validated opaque UUIDv7 identifying one endpoint generation authority.
type PrivateEndpointID publicid.ID

// ParsePrivateEndpointID validates a Private Endpoint ID from its canonical string.
func ParsePrivateEndpointID(value string) (PrivateEndpointID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return PrivateEndpointID{}, ErrInvalidPrivateEndpointID
	}
	return PrivateEndpointID(id), nil
}

// String returns the lowercase canonical UUID representation.
func (id PrivateEndpointID) String() string { return publicid.ID(id).String() }

// Bytes returns a copy of the binary UUID representation.
func (id PrivateEndpointID) Bytes() [16]byte { return publicid.ID(id).Bytes() }

// IsValid reports whether the ID satisfies the public identity contract.
func (id PrivateEndpointID) IsValid() bool { return publicid.ID(id).IsValid() }
