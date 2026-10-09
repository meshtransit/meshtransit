package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"time"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/publicid"
)

const accountSessionLogoutEndReason = "local_logout"

type accountSessionLogoutEvidenceIDs struct {
	changeID publicid.ID
	auditID  publicid.ID
	outboxID publicid.ID
}

func newAccountSessionLogoutEvidenceIDs(ctx context.Context) (accountSessionLogoutEvidenceIDs, error) {
	if ctx == nil || ctx.Err() != nil {
		return accountSessionLogoutEvidenceIDs{}, ErrAccountSessionLogoutEvidence
	}
	var values [3]publicid.ID
	for index := range values {
		if ctx.Err() != nil {
			return accountSessionLogoutEvidenceIDs{}, ErrAccountSessionLogoutEvidence
		}
		value, err := publicid.New()
		if err != nil {
			return accountSessionLogoutEvidenceIDs{}, ErrAccountSessionLogoutEvidence
		}
		values[index] = value
	}
	return accountSessionLogoutEvidenceIDs{
		changeID: values[0],
		auditID:  values[1],
		outboxID: values[2],
	}, nil
}

type accountSessionLogoutAuditHead struct {
	streamInternalID int64
	nextSequence     int64
	previousHash     [sha256.Size]byte
}

type accountSessionLogoutPayload struct {
	SessionID      string    `json:"session_public_id"`
	DeploymentID   string    `json:"deployment_public_id"`
	PrincipalID    string    `json:"principal_public_id"`
	RecoveryEpoch  int64     `json:"deployment_recovery_epoch"`
	SessionVersion int64     `json:"session_version"`
	EndReason      string    `json:"end_reason"`
	EndedAt        time.Time `json:"ended_at"`
}

type accountSessionLogoutEvidence struct {
	payload   []byte
	afterHash [sha256.Size]byte
	eventHash [sha256.Size]byte
}

func buildAccountSessionLogoutEvidence(
	ids accountSessionLogoutEvidenceIDs,
	head accountSessionLogoutAuditHead,
	deploymentID deployment.ID,
	recoveryEpoch int64,
	sessionID accountsession.ID,
	principalID publicid.ID,
	version int64,
	endedAt time.Time,
) (accountSessionLogoutEvidence, error) {
	if !ids.changeID.IsValid() || !ids.auditID.IsValid() || !ids.outboxID.IsValid() ||
		head.streamInternalID <= 0 || head.nextSequence <= 0 || !deploymentID.IsValid() ||
		recoveryEpoch <= 0 || !sessionID.IsValid() || !principalID.IsValid() ||
		version < 2 || endedAt.IsZero() {
		return accountSessionLogoutEvidence{}, ErrAccountSessionLogoutEvidence
	}
	endedAt = endedAt.UTC()
	payload, err := json.Marshal(accountSessionLogoutPayload{
		SessionID: sessionID.String(), DeploymentID: deploymentID.String(),
		PrincipalID: principalID.String(), RecoveryEpoch: recoveryEpoch,
		SessionVersion: version, EndReason: accountSessionLogoutEndReason, EndedAt: endedAt,
	})
	if err != nil {
		return accountSessionLogoutEvidence{}, ErrAccountSessionLogoutEvidence
	}
	afterHash := hashAccountSessionLogoutState(
		deploymentID,
		recoveryEpoch,
		sessionID,
		principalID,
		version,
		endedAt,
	)
	payloadHash := sha256.Sum256(payload)
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash:      head.previousHash,
		EventID:           ids.auditID,
		ChangeID:          ids.changeID,
		AggregateKind:     "account_session",
		AggregateID:       publicid.ID(sessionID),
		AggregateVersion:  version,
		ActorPrincipalID:  principalID,
		Action:            "account_session.revoked",
		Permission:        "identity.logout",
		CorrelationID:     publicid.ID(sessionID),
		AfterSemanticHash: afterHash,
		AuditPayloadHash:  payloadHash,
		OutboxEventClass:  "identity.account_session.revoked",
		OutboxPayloadHash: payloadHash,
	})
	if err != nil {
		return accountSessionLogoutEvidence{}, ErrAccountSessionLogoutEvidence
	}
	return accountSessionLogoutEvidence{payload: payload, afterHash: afterHash, eventHash: eventHash}, nil
}

func hashAccountSessionLogoutState(
	deploymentID deployment.ID,
	recoveryEpoch int64,
	sessionID accountsession.ID,
	principalID publicid.ID,
	version int64,
	endedAt time.Time,
) [sha256.Size]byte {
	input := []byte("meshtransit/account-session/logout/v1\x00")
	for _, value := range [3]publicid.ID{
		publicid.ID(deploymentID),
		publicid.ID(sessionID),
		principalID,
	} {
		encoded := value.Bytes()
		input = append(input, encoded[:]...)
	}
	// Values are validated positive above. Keep the unsigned fixed-width encoding
	// stable because these bytes are part of the persisted audit hash contract.
	input = binary.BigEndian.AppendUint64(input, uint64(recoveryEpoch)) //nolint:gosec // validated positive
	input = binary.BigEndian.AppendUint64(input, uint64(version))       //nolint:gosec // validated positive
	input = binary.AppendVarint(input, endedAt.UTC().UnixMicro())
	input = append(input, accountSessionLogoutEndReason...)
	return sha256.Sum256(input)
}
