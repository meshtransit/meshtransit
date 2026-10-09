package intake

import (
	"fmt"

	"github.com/meshtransit/meshtransit/core/internal/domain/enrollment"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

// PublicRegistrationIDGenerator creates UUIDv7 registration intent IDs from
// operating-system entropy. It owns no mutable state and starts no goroutines.
type PublicRegistrationIDGenerator struct{}

// NewRegistrationID returns one fresh server-owned registration intent ID.
func (PublicRegistrationIDGenerator) NewRegistrationID() (enrollment.RegistrationID, error) {
	return generateRegistrationID(publicid.New)
}

func generateRegistrationID(newID func() (publicid.ID, error)) (enrollment.RegistrationID, error) {
	if newID == nil {
		return enrollment.RegistrationID{}, enrollment.ErrInvalidID
	}
	id, err := newID()
	if err != nil {
		return enrollment.RegistrationID{}, fmt.Errorf("generate registration intent id: %w", err)
	}
	registrationID := enrollment.RegistrationID(id)
	if !registrationID.IsValid() {
		return enrollment.RegistrationID{}, enrollment.ErrInvalidID
	}
	return registrationID, nil
}

// PublicEvidenceIDGenerator creates durable audit and outbox identities from
// operating-system entropy. It owns no mutable state and starts no goroutines.
type PublicEvidenceIDGenerator struct{}

// NewEvidenceIDs returns one fresh, distinct identity set.
func (PublicEvidenceIDGenerator) NewEvidenceIDs() (EvidenceIDs, error) {
	return generateEvidenceIDs(publicid.New)
}

func generateEvidenceIDs(newID func() (publicid.ID, error)) (EvidenceIDs, error) {
	if newID == nil {
		return EvidenceIDs{}, ErrInvalidEvidenceIDs
	}

	var generated [3]publicid.ID
	for index := range generated {
		id, err := newID()
		if err != nil {
			return EvidenceIDs{}, fmt.Errorf("generate registration intake evidence ID: %w", err)
		}
		generated[index] = id
	}
	ids, err := NewEvidenceIDs(generated[0], generated[1], generated[2])
	if err != nil {
		return EvidenceIDs{}, fmt.Errorf("construct registration intake evidence IDs: %w", err)
	}
	return ids, nil
}
