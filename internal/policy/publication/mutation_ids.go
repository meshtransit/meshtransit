package publication

import (
	"errors"
	"fmt"
	"slices"

	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

// ErrInvalidMutationIDs reports incomplete, aliased, or unbounded publication IDs.
var ErrInvalidMutationIDs = errors.New("policy publication: invalid mutation IDs")

// MutationIDParams names every public identity written by one publication.
type MutationIDParams struct {
	ChangeID      publicid.ID
	AuditEventID  publicid.ID
	OutboxEventID publicid.ID
	ReleaseID     ReleaseID
	ProjectionIDs []ProjectionID
}

// MutationIDs is an immutable set of stable IDs reused across transaction retries.
type MutationIDs struct {
	changeID      publicid.ID
	auditEventID  publicid.ID
	outboxEventID publicid.ID
	releaseID     ReleaseID
	projectionIDs []ProjectionID
}

// NewMutationIDs validates all IDs and owns the projection collection.
func NewMutationIDs(params MutationIDParams) (MutationIDs, error) {
	if params.ProjectionIDs == nil || len(params.ProjectionIDs) > policy.MaximumRules {
		return MutationIDs{}, ErrInvalidMutationIDs
	}
	seen := make(map[publicid.ID]struct{}, len(params.ProjectionIDs)+4)
	base := [...]publicid.ID{
		params.ChangeID,
		params.AuditEventID,
		params.OutboxEventID,
		publicid.ID(params.ReleaseID),
	}
	for _, id := range base {
		if !id.IsValid() || hasPublicationID(seen, id) {
			return MutationIDs{}, ErrInvalidMutationIDs
		}
		seen[id] = struct{}{}
	}
	projectionIDs := slices.Clone(params.ProjectionIDs)
	for _, projectionID := range projectionIDs {
		id := publicid.ID(projectionID)
		if !projectionID.IsValid() || hasPublicationID(seen, id) {
			return MutationIDs{}, ErrInvalidMutationIDs
		}
		seen[id] = struct{}{}
	}
	return MutationIDs{
		changeID:      params.ChangeID,
		auditEventID:  params.AuditEventID,
		outboxEventID: params.OutboxEventID,
		releaseID:     params.ReleaseID,
		projectionIDs: projectionIDs,
	}, nil
}

// ChangeID returns the transaction authority correlation ID.
func (ids MutationIDs) ChangeID() publicid.ID { return ids.changeID }

// AuditEventID returns the immutable audit identity.
func (ids MutationIDs) AuditEventID() publicid.ID { return ids.auditEventID }

// OutboxEventID returns the durable wakeup identity.
func (ids MutationIDs) OutboxEventID() publicid.ID { return ids.outboxEventID }

// ReleaseID returns the immutable Policy Release identity.
func (ids MutationIDs) ReleaseID() ReleaseID { return ids.releaseID }

// ProjectionIDs returns caller-owned compiled-rule identities.
func (ids MutationIDs) ProjectionIDs() []ProjectionID { return slices.Clone(ids.projectionIDs) }

// IsValid reports whether all IDs remain distinct and bounded.
func (ids MutationIDs) IsValid() bool {
	validated, err := NewMutationIDs(MutationIDParams{
		ChangeID:      ids.changeID,
		AuditEventID:  ids.auditEventID,
		OutboxEventID: ids.outboxEventID,
		ReleaseID:     ids.releaseID,
		ProjectionIDs: ids.projectionIDs,
	})
	return err == nil && ids.Equal(validated)
}

// Equal reports whether both immutable identity sets are identical.
func (ids MutationIDs) Equal(other MutationIDs) bool {
	return ids.changeID == other.changeID && ids.auditEventID == other.auditEventID &&
		ids.outboxEventID == other.outboxEventID && ids.releaseID == other.releaseID &&
		slices.Equal(ids.projectionIDs, other.projectionIDs)
}

// PublicMutationIDGenerator creates UUIDv7 identities from operating-system entropy.
type PublicMutationIDGenerator struct{}

// NewMutationIDs returns one fresh, non-aliased identity set of the requested size.
func (PublicMutationIDGenerator) NewMutationIDs(ruleCount int) (MutationIDs, error) {
	if ruleCount < 0 || ruleCount > policy.MaximumRules {
		return MutationIDs{}, ErrInvalidMutationIDs
	}
	generated := make([]publicid.ID, ruleCount+4)
	for index := range generated {
		id, err := publicid.New()
		if err != nil {
			return MutationIDs{}, fmt.Errorf("generate policy publication public ID: %w", err)
		}
		generated[index] = id
	}
	projectionIDs := make([]ProjectionID, ruleCount)
	for index := range projectionIDs {
		projectionIDs[index] = ProjectionID(generated[index+4])
	}
	return NewMutationIDs(MutationIDParams{
		ChangeID:      generated[0],
		AuditEventID:  generated[1],
		OutboxEventID: generated[2],
		ReleaseID:     ReleaseID(generated[3]),
		ProjectionIDs: projectionIDs,
	})
}

func hasPublicationID(seen map[publicid.ID]struct{}, id publicid.ID) bool {
	_, exists := seen[id]
	return exists
}
