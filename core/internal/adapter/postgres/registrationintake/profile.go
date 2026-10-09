package registrationintake

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/enrollment"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
)

type profileRecord struct {
	internalID          int64
	publicID            string
	nodeLifetimeSeconds int64
	ephemeralMode       string
	useLimitKind        string
	maximumUses         sql.NullInt64
	state               string
	version             int64
}

func (transaction *transaction) lockProfile(
	ctx context.Context,
	profileInternalID int64,
) (profileRecord, error) {
	var record profileRecord
	if err := transaction.database.QueryRow(ctx, lockProfileSQL, profileInternalID).Scan(
		&record.internalID,
		&record.publicID,
		&record.nodeLifetimeSeconds,
		&record.ephemeralMode,
		&record.useLimitKind,
		&record.maximumUses,
		&record.state,
		&record.version,
	); err != nil {
		return profileRecord{}, fmt.Errorf("lock enrollment profile: %w", err)
	}
	return record, nil
}

func (record profileRecord) domainValue(scope network.Scope) (enrollment.Profile, error) {
	if record.internalID <= 0 || record.nodeLifetimeSeconds <= 0 ||
		record.nodeLifetimeSeconds > int64((1<<63-1)/time.Second) || record.version <= 0 {
		return enrollment.Profile{}, ErrEvidence
	}
	profileID, err := enrollment.ParseProfileID(record.publicID)
	if err != nil {
		return enrollment.Profile{}, ErrEvidence
	}
	state, err := profileState(record.state)
	if err != nil {
		return enrollment.Profile{}, err
	}
	ephemeralMode, err := ephemeralMode(record.ephemeralMode)
	if err != nil {
		return enrollment.Profile{}, err
	}
	limit, err := useLimit(record.useLimitKind, record.maximumUses)
	if err != nil {
		return enrollment.Profile{}, err
	}
	profile, err := enrollment.NewProfile(enrollment.ProfileParams{
		ID:                 profileID,
		Scope:              scope,
		State:              state,
		NodeLifetime:       time.Duration(record.nodeLifetimeSeconds) * time.Second,
		EphemeralMode:      ephemeralMode,
		CredentialUseLimit: limit,
	})
	if err != nil {
		return enrollment.Profile{}, ErrEvidence
	}
	return profile, nil
}

func profileState(value string) (enrollment.ProfileState, error) {
	switch value {
	case "active":
		return enrollment.ProfileStateActive, nil
	case "suspended":
		return enrollment.ProfileStateSuspended, nil
	case "deleted":
		return enrollment.ProfileStateDeleted, nil
	default:
		return enrollment.ProfileStateUnknown, ErrEvidence
	}
}

func ephemeralMode(value string) (enrollment.EphemeralMode, error) {
	switch value {
	case "persistent":
		return enrollment.EphemeralModePersistent, nil
	case "ephemeral":
		return enrollment.EphemeralModeEphemeral, nil
	default:
		return enrollment.EphemeralModeUnknown, ErrEvidence
	}
}
