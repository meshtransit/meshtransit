package registrationintake

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"fmt"
	"time"

	"github.com/meshtransit/meshtransit/internal/enrollment"
	"github.com/meshtransit/meshtransit/internal/identity"
)

type credentialRecord struct {
	internalID          int64
	profileInternalID   int64
	issuerInternalID    int64
	issuerPublicID      string
	state               string
	useLimitKind        string
	maximumUses         sql.NullInt64
	usedCount           int64
	issuedRecoveryEpoch int64
	validFrom           time.Time
	expiresAt           time.Time
	version             int64
}

func (transaction *transaction) lockCredential(
	ctx context.Context,
	credentialID enrollment.CredentialID,
) (credentialRecord, error) {
	var record credentialRecord
	if err := transaction.database.QueryRow(
		ctx,
		lockEnrollmentAuthoritySQL,
		credentialID.String(),
	).Scan(
		&record.internalID,
		&record.profileInternalID,
		&record.issuerInternalID,
		&record.issuerPublicID,
		&record.state,
		&record.useLimitKind,
		&record.maximumUses,
		&record.usedCount,
		&record.issuedRecoveryEpoch,
		&record.validFrom,
		&record.expiresAt,
		&record.version,
	); err != nil {
		return credentialRecord{}, fmt.Errorf("lock enrollment credential: %w", err)
	}
	return record, nil
}

func (record credentialRecord) domainValue(
	credentialID enrollment.CredentialID,
	profileID enrollment.ProfileID,
) (enrollment.Credential, error) {
	if record.internalID <= 0 || record.profileInternalID <= 0 || record.issuerInternalID <= 0 ||
		record.version <= 0 {
		return enrollment.Credential{}, ErrEvidence
	}
	issuerID, err := identity.ParsePrincipalID(record.issuerPublicID)
	if err != nil {
		return enrollment.Credential{}, ErrEvidence
	}
	state, err := credentialState(record.state)
	if err != nil {
		return enrollment.Credential{}, err
	}
	useLimit, err := useLimit(record.useLimitKind, record.maximumUses)
	if err != nil {
		return enrollment.Credential{}, err
	}
	credential, err := enrollment.NewCredential(enrollment.CredentialParams{
		ID:                  credentialID,
		ProfileID:           profileID,
		IssuerID:            issuerID,
		State:               state,
		UseLimit:            useLimit,
		UsedCount:           record.usedCount,
		IssuedRecoveryEpoch: record.issuedRecoveryEpoch,
		ValidFrom:           record.validFrom,
		ExpiresAt:           record.expiresAt,
	})
	if err != nil {
		return enrollment.Credential{}, ErrEvidence
	}
	return credential, nil
}

func (transaction *transaction) loadDigest(
	ctx context.Context,
	credentialID enrollment.CredentialID,
) (enrollment.CredentialDigest, error) {
	var algorithm, keyIDValue string
	var digestBytes, fingerprintBytes []byte
	if err := transaction.database.QueryRow(ctx, loadDigestSQL, credentialID.String()).Scan(
		&algorithm,
		&keyIDValue,
		&digestBytes,
		&fingerprintBytes,
	); err != nil {
		return enrollment.CredentialDigest{}, fmt.Errorf("load credential digest: %w", err)
	}
	if algorithm != enrollment.DigestAlgorithmHMACSHA256 || len(digestBytes) != 32 ||
		len(fingerprintBytes) != 16 {
		return enrollment.CredentialDigest{}, ErrEvidence
	}
	keyID, err := enrollment.NewDigestKeyID(keyIDValue)
	if err != nil {
		return enrollment.CredentialDigest{}, ErrEvidence
	}
	var digestValue [32]byte
	copy(digestValue[:], digestBytes)
	digest, err := enrollment.NewCredentialDigest(keyID, digestValue)
	if err != nil {
		return enrollment.CredentialDigest{}, ErrEvidence
	}
	fingerprint := digest.Fingerprint()
	if subtle.ConstantTimeCompare(fingerprint[:], fingerprintBytes) != 1 {
		return enrollment.CredentialDigest{}, ErrEvidence
	}
	return digest, nil
}

func useLimit(kind string, maximum sql.NullInt64) (enrollment.UseLimit, error) {
	switch kind {
	case "bounded":
		if !maximum.Valid {
			return enrollment.UseLimit{}, ErrEvidence
		}
		limit, err := enrollment.NewBoundedUseLimit(maximum.Int64)
		if err != nil {
			return enrollment.UseLimit{}, ErrEvidence
		}
		return limit, nil
	case "unlimited":
		if maximum.Valid {
			return enrollment.UseLimit{}, ErrEvidence
		}
		return enrollment.NewUnlimitedUseLimit(), nil
	default:
		return enrollment.UseLimit{}, ErrEvidence
	}
}

func credentialState(value string) (enrollment.CredentialState, error) {
	switch value {
	case "active":
		return enrollment.CredentialStateActive, nil
	case "revoked":
		return enrollment.CredentialStateRevoked, nil
	default:
		return enrollment.CredentialStateUnknown, ErrEvidence
	}
}
