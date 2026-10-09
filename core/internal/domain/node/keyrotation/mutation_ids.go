package keyrotation

import (
	"errors"
	"fmt"

	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

var errInvalidMutationIDs = errors.New("node key rotation: invalid mutation IDs")

// MutationIDParams names every durable identity written by one rotation.
type MutationIDParams struct {
	ChangeID       publicid.ID
	NodeKeyEpochID publicid.ID
	AuditEventID   publicid.ID
	OutboxEventID  publicid.ID
}

// MutationIDs is a validated, non-aliased set reused across transaction retries.
type MutationIDs struct {
	changeID       publicid.ID
	nodeKeyEpochID publicid.ID
	auditEventID   publicid.ID
	outboxEventID  publicid.ID
}

// NewMutationIDs validates four distinct UUIDv7 values.
func NewMutationIDs(params MutationIDParams) (MutationIDs, error) {
	values := [...]publicid.ID{
		params.ChangeID,
		params.NodeKeyEpochID,
		params.AuditEventID,
		params.OutboxEventID,
	}
	for index, value := range values {
		if !value.IsValid() {
			return MutationIDs{}, errInvalidMutationIDs
		}
		for previous := range index {
			if value == values[previous] {
				return MutationIDs{}, errInvalidMutationIDs
			}
		}
	}
	return MutationIDs{
		changeID:       params.ChangeID,
		nodeKeyEpochID: params.NodeKeyEpochID,
		auditEventID:   params.AuditEventID,
		outboxEventID:  params.OutboxEventID,
	}, nil
}

// ChangeID returns the authority-mutation correlation ID.
func (ids MutationIDs) ChangeID() publicid.ID { return ids.changeID }

// NodeKeyEpochID returns the new immutable key-epoch identity.
func (ids MutationIDs) NodeKeyEpochID() publicid.ID { return ids.nodeKeyEpochID }

// AuditEventID returns the append-only audit identity.
func (ids MutationIDs) AuditEventID() publicid.ID { return ids.auditEventID }

// OutboxEventID returns the durable revision-event identity.
func (ids MutationIDs) OutboxEventID() publicid.ID { return ids.outboxEventID }

// IsValid reports whether every ID is present and distinct.
func (ids MutationIDs) IsValid() bool {
	validated, err := NewMutationIDs(MutationIDParams{
		ChangeID:       ids.changeID,
		NodeKeyEpochID: ids.nodeKeyEpochID,
		AuditEventID:   ids.auditEventID,
		OutboxEventID:  ids.outboxEventID,
	})
	return err == nil && validated == ids
}

// PublicMutationIDGenerator creates rotation row identities from OS entropy.
type PublicMutationIDGenerator struct{}

// NewMutationIDs returns a fresh non-aliased mutation ID set.
func (PublicMutationIDGenerator) NewMutationIDs() (MutationIDs, error) {
	var generated [4]publicid.ID
	for index := range generated {
		id, err := publicid.New()
		if err != nil {
			return MutationIDs{}, fmt.Errorf("generate Node-key rotation public ID: %w", err)
		}
		generated[index] = id
	}
	ids, err := NewMutationIDs(MutationIDParams{
		ChangeID:       generated[0],
		NodeKeyEpochID: generated[1],
		AuditEventID:   generated[2],
		OutboxEventID:  generated[3],
	})
	if err != nil {
		return MutationIDs{}, fmt.Errorf("construct Node-key rotation IDs: %w", err)
	}
	return ids, nil
}
