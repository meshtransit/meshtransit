package registration

import (
	"errors"

	"github.com/meshtransit/meshtransit/internal/publicid"
)

// ErrInvalidMutationIDs reports an incomplete or aliased registration ID set.
var ErrInvalidMutationIDs = errors.New("registration: invalid mutation IDs")

// MutationIDParams names every public identity that may be used by one atomic
// registration mutation. IDs are generated once before a replayable write and
// remain stable across whole-transaction retries.
type MutationIDParams struct {
	ChangeID          publicid.ID
	AuditEventID      publicid.ID
	OutboxEventID     publicid.ID
	CredentialUseID   publicid.ID
	MachineKeyEpochID publicid.ID
	NodeKeyEpochID    publicid.ID
	IPv4LeaseID       publicid.ID
	IPv6LeaseID       publicid.ID
}

// MutationIDs is an immutable, non-aliased set of application-generated IDs
// for the durable rows and evidence belonging to one registration decision.
type MutationIDs struct {
	changeID          publicid.ID
	auditEventID      publicid.ID
	outboxEventID     publicid.ID
	credentialUseID   publicid.ID
	machineKeyEpochID publicid.ID
	nodeKeyEpochID    publicid.ID
	ipv4LeaseID       publicid.ID
	ipv6LeaseID       publicid.ID
}

// NewMutationIDs validates that every required ID is a distinct UUIDv7.
func NewMutationIDs(params MutationIDParams) (MutationIDs, error) {
	values := [...]publicid.ID{
		params.ChangeID,
		params.AuditEventID,
		params.OutboxEventID,
		params.CredentialUseID,
		params.MachineKeyEpochID,
		params.NodeKeyEpochID,
		params.IPv4LeaseID,
		params.IPv6LeaseID,
	}
	for index, value := range values {
		if !value.IsValid() {
			return MutationIDs{}, ErrInvalidMutationIDs
		}
		for previous := range index {
			if value == values[previous] {
				return MutationIDs{}, ErrInvalidMutationIDs
			}
		}
	}
	return MutationIDs{
		changeID:          params.ChangeID,
		auditEventID:      params.AuditEventID,
		outboxEventID:     params.OutboxEventID,
		credentialUseID:   params.CredentialUseID,
		machineKeyEpochID: params.MachineKeyEpochID,
		nodeKeyEpochID:    params.NodeKeyEpochID,
		ipv4LeaseID:       params.IPv4LeaseID,
		ipv6LeaseID:       params.IPv6LeaseID,
	}, nil
}

// ChangeID returns the transaction's authority-mutation correlation ID.
func (ids MutationIDs) ChangeID() publicid.ID { return ids.changeID }

// AuditEventID returns the immutable audit event identity.
func (ids MutationIDs) AuditEventID() publicid.ID { return ids.auditEventID }

// OutboxEventID returns the durable outbox event identity.
func (ids MutationIDs) OutboxEventID() publicid.ID { return ids.outboxEventID }

// CredentialUseID returns the immutable credential-use identity.
func (ids MutationIDs) CredentialUseID() publicid.ID { return ids.credentialUseID }

// MachineKeyEpochID returns the machine-key epoch identity reserved for a new Device.
func (ids MutationIDs) MachineKeyEpochID() publicid.ID { return ids.machineKeyEpochID }

// NodeKeyEpochID returns the Node-key epoch identity reserved for a new Device.
func (ids MutationIDs) NodeKeyEpochID() publicid.ID { return ids.nodeKeyEpochID }

// IPv4LeaseID returns the IPv4 lease identity reserved for address allocation.
func (ids MutationIDs) IPv4LeaseID() publicid.ID { return ids.ipv4LeaseID }

// IPv6LeaseID returns the IPv6 lease identity reserved for address allocation.
func (ids MutationIDs) IPv6LeaseID() publicid.ID { return ids.ipv6LeaseID }

// IsValid reports whether the complete ID set is distinct and usable.
func (ids MutationIDs) IsValid() bool {
	validated, err := NewMutationIDs(MutationIDParams{
		ChangeID:          ids.changeID,
		AuditEventID:      ids.auditEventID,
		OutboxEventID:     ids.outboxEventID,
		CredentialUseID:   ids.credentialUseID,
		MachineKeyEpochID: ids.machineKeyEpochID,
		NodeKeyEpochID:    ids.nodeKeyEpochID,
		IPv4LeaseID:       ids.ipv4LeaseID,
		IPv6LeaseID:       ids.ipv6LeaseID,
	})
	return err == nil && validated == ids
}
