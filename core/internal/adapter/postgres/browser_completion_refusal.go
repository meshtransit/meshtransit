package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

const endRefusedBrowserIntentSQL = `SELECT ended_registration_version, registration_expires_at
FROM mesh_ops.end_refused_browser_intent_v1($1::UUID, $2::UUID, $3::BYTEA, $4::BYTEA, $5::BYTEA)`

// refused wraps a completion refused for good (registration.RefusedForGood)
// after ending its approval in a second, short
// transaction (TD-CORE-150 M1): the node's next sign-in gets a new approval
// at once instead of this one until it expires. The refusal stands whether
// or not the approval could be ended.
func (store *BrowserCompletionStore) refused(
	ctx context.Context, identityValue node.RegistrationIdentity, hostname node.Hostname,
	digest enrollment.BrowserIntentDigest, refusal error,
) error {
	intentID, ended, err := store.endRefusedIntent(ctx, identityValue, hostname, digest,
		registration.RefusalReason(refusal))
	return &registration.RefusedIntentError{IntentID: intentID, Ended: ended, EndErr: err, Err: refusal}
}

// endRefusedIntent locks the approval through the completion authority (the
// token and the Noise-bound keys prove it, and it sets the Network scope),
// ends the intent and its authorized registration, and appends
// registration.expired in the Network's stream under one change. It finds
// nothing to end when the approval completed, expired or was ended already.
func (store *BrowserCompletionStore) endRefusedIntent(
	ctx context.Context, identityValue node.RegistrationIdentity, hostname node.Hostname,
	digest enrollment.BrowserIntentDigest, reason string,
) (_ string, ended bool, resultErr error) {
	tx, err := store.database.Begin(ctx)
	if err != nil {
		return "", false, err
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackRegistrationSetup(tx))
		}
	}()
	if _, err := tx.Exec(ctx, configureRegistrationTransactionSQL,
		postgresTimeout(store.options.StatementTimeout),
		postgresTimeout(store.options.LockTimeout),
		postgresTimeout(store.options.IdleTimeout)); err != nil {
		return "", false, err
	}
	authority, found, err := store.lockRefusedAuthority(ctx, tx, identityValue, hostname, digest)
	if err != nil || !found {
		return "", false, err
	}
	evidence, err := refusedIntentEvidence(authority, reason)
	if err != nil {
		return authority.intentPublicID, false, err
	}
	if _, err := tx.Exec(ctx, setBrowserIntentChangeSQL, evidence.changeID.String()); err != nil {
		return authority.intentPublicID, false, err
	}
	fingerprint := identityValue.MachineKey().Fingerprint()
	nodeKey := identityValue.NodeKey().Bytes()
	digestBytes := digest.Bytes()
	var version int64
	var expires time.Time
	err = tx.QueryRow(ctx, endRefusedBrowserIntentSQL, authority.intentPublicID, authority.registrationPublicID,
		digestBytes[:], fingerprint[:], nodeKey[:]).Scan(&version, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return authority.intentPublicID, false, nil
	}
	if err != nil {
		return authority.intentPublicID, false, err
	}
	if version != authority.registrationVersion+1 || expires.IsZero() {
		return authority.intentPublicID, false, ErrRegistrationEvidence
	}
	if evidence.beforeHash, err = browserApprovalExpiryHash(evidence.registrationID, "authorized",
		authority.registrationVersion, expires); err != nil {
		return authority.intentPublicID, false, err
	}
	if evidence.requestHash, err = browserApprovalExpiryHash(evidence.registrationID, "expired",
		version, expires); err != nil {
		return authority.intentPublicID, false, err
	}
	evidence.version = version
	if err := appendBrowserApprovalEvidenceRows(ctx, func(ctx context.Context, query string, args ...any) evidenceRow {
		return tx.QueryRow(ctx, query, args...)
	}, evidence); err != nil {
		return authority.intentPublicID, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return authority.intentPublicID, false, err
	}
	closed = true
	return authority.intentPublicID, true, nil
}

func (store *BrowserCompletionStore) lockRefusedAuthority(
	ctx context.Context, tx registrationDatabaseTransaction,
	identityValue node.RegistrationIdentity, hostname node.Hostname, digest enrollment.BrowserIntentDigest,
) (browserCompletionAuthority, bool, error) {
	machineKey := identityValue.MachineKey().Bytes()
	fingerprint := identityValue.MachineKey().Fingerprint()
	nodeKey := identityValue.NodeKey().Bytes()
	digestBytes := digest.Bytes()
	var authority browserCompletionAuthority
	err := tx.QueryRow(ctx, lockBrowserCompletionSQL,
		store.deploymentID.String(), store.recoveryEpoch, digestBytes[:],
		machineKey[:], fingerprint[:], nodeKey[:], hostname.String(),
	).Scan(
		&authority.intentInternalID, &authority.intentPublicID,
		&authority.registrationInternalID, &authority.registrationPublicID,
		&authority.registrationVersion, &authority.workspaceInternalID,
		&authority.workspacePublicID, &authority.networkInternalID,
		&authority.networkPublicID, &authority.profileInternalID,
		&authority.profilePublicID, &authority.principalInternalID,
		&authority.principalPublicID, &authority.sessionPublicID,
		&authority.currentNetworkRevision, &authority.lifetimeSeconds,
		&authority.ephemeralMode, &authority.requestHash,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return browserCompletionAuthority{}, false, nil
	}
	if err != nil {
		return browserCompletionAuthority{}, false, err
	}
	return authority, true, nil
}

// refusedIntentEvidence is the registration.expired event of an approval a
// refusal ended, as for one that expired on time, naming the refusal. Its
// actor is the approver, as for an approval that expired on time: the event
// is about their approval, and the payload's reason says control ended it.
func refusedIntentEvidence(authority browserCompletionAuthority, reason string) (browserApprovalEvidence, error) {
	registrationID, registrationErr := publicid.Parse(authority.registrationPublicID)
	intentID, intentErr := publicid.Parse(authority.intentPublicID)
	sessionID, sessionErr := publicid.Parse(authority.sessionPublicID)
	principalID, principalErr := publicid.Parse(authority.principalPublicID)
	networkID, networkErr := network.ParseID(authority.networkPublicID)
	if err := errors.Join(registrationErr, intentErr, sessionErr, principalErr, networkErr); err != nil ||
		authority.registrationVersion <= 0 || authority.currentNetworkRevision <= 0 {
		return browserApprovalEvidence{}, errors.Join(ErrRegistrationEvidence, err)
	}
	var workspaceID workspace.ID
	if authority.workspacePublicID != "" {
		parsed, err := workspace.ParseID(authority.workspacePublicID)
		if err != nil {
			return browserApprovalEvidence{}, errors.Join(ErrRegistrationEvidence, err)
		}
		workspaceID = parsed
	}
	changeID, changeErr := publicid.New()
	eventID, eventErr := publicid.New()
	outboxID, outboxErr := publicid.New()
	if err := errors.Join(changeErr, eventErr, outboxErr); err != nil {
		return browserApprovalEvidence{}, err
	}
	return browserApprovalEvidence{
		registrationID: registrationID, changeID: changeID, eventID: eventID, outboxID: outboxID,
		intentID: intentID, sessionID: sessionID, principalID: principalID,
		networkID: networkID, workspaceID: workspaceID,
		networkRevision: authority.currentNetworkRevision, expired: true, reason: reason,
	}, nil
}
