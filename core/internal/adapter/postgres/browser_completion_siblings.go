package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/node"
)

const lookupBrowserJoinedSQL = `SELECT sibling_machine_key FROM mesh_ops.lookup_browser_joined_v1(
    $1::UUID, $2::BIGINT, $3::BYTEA, $4::BYTEA, $5::BYTEA, $6::BYTEA
)`

const browserSiblingConflictSQL = `SELECT mesh_ops.browser_sibling_conflict_v1(
    $1::UUID, $2::BIGINT, $3::BYTEA, $4::BYTEA, $5::BYTEA[], $6::UUID, $7::UUID, $8::UUID
) IS NOT NULL`

const clearBrowserIntentSiblingsSQL = `SELECT mesh_ops.clear_browser_intent_siblings_v1($1::UUID, $2::BIGINT, $3::BYTEA)`

// readJoined returns the answer of a sign-in the approver ended with "Use
// that account": the machine key the chosen Device holds now. Nil when this
// sign-in was not ended so, or that Device no longer holds an active key.
func (store *BrowserCompletionStore) readJoined(
	ctx context.Context, tx registrationDatabaseTransaction,
	identityValue node.RegistrationIdentity, digest enrollment.BrowserIntentDigest,
) (*registration.JoinedExistingError, error) {
	machineKey := identityValue.MachineKey().Bytes()
	fingerprint := identityValue.MachineKey().Fingerprint()
	nodeKey := identityValue.NodeKey().Bytes()
	digestBytes := digest.Bytes()
	var sibling []byte
	err := tx.QueryRow(ctx, lookupBrowserJoinedSQL, store.deploymentID.String(), store.recoveryEpoch,
		digestBytes[:], machineKey[:], fingerprint[:], nodeKey[:]).Scan(&sibling)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(sibling) != 32 {
		return nil, ErrRegistrationEvidence
	}
	joined := &registration.JoinedExistingError{}
	copy(joined.SiblingMachineKey[:], sibling)
	return joined, nil
}

// siblingConflict reports whether a sibling key (stored, or proven in the
// completing session) holds the approver's Device in the approved Network.
func (store *BrowserCompletionStore) siblingConflict(
	ctx context.Context, tx registrationDatabaseTransaction, identityValue node.RegistrationIdentity,
	digest enrollment.BrowserIntentDigest, siblings [][32]byte, authority browserCompletionAuthority,
) (bool, error) {
	if len(siblings) > MaxBrowserSiblings {
		siblings = siblings[:MaxBrowserSiblings]
	}
	keys := make([][]byte, 0, len(siblings))
	for _, sibling := range siblings {
		keys = append(keys, sibling[:])
	}
	machineKey := identityValue.MachineKey().Bytes()
	digestBytes := digest.Bytes()
	var conflict bool
	err := tx.QueryRow(ctx, browserSiblingConflictSQL, store.deploymentID.String(), store.recoveryEpoch,
		digestBytes[:], machineKey[:], keys, authority.principalPublicID, authority.workspacePublicID,
		authority.networkPublicID).Scan(&conflict)
	return conflict, err
}

// clearSiblings drops the sign-in's sibling keys once it ends (design §6.3).
func (store *BrowserCompletionStore) clearSiblings(
	ctx context.Context, tx registrationDatabaseTransaction, digest enrollment.BrowserIntentDigest,
) error {
	digestBytes := digest.Bytes()
	var cleared int
	return tx.QueryRow(ctx, clearBrowserIntentSiblingsSQL, store.deploymentID.String(), store.recoveryEpoch,
		digestBytes[:]).Scan(&cleared)
}
