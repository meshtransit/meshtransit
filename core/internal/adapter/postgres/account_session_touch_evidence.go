package postgres

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"time"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/publicid"
)

type accountSessionTouchPayload struct {
	SessionID      string    `json:"session_public_id"`
	DeploymentID   string    `json:"deployment_public_id"`
	PrincipalID    string    `json:"principal_public_id"`
	RecoveryEpoch  int64     `json:"deployment_recovery_epoch"`
	SessionVersion int64     `json:"session_version"`
	LastUsedAt     time.Time `json:"last_used_at"`
	IdleExpiresAt  time.Time `json:"idle_expires_at"`
}

func buildAccountSessionTouchEvidence(
	ids accountSessionLogoutEvidenceIDs,
	head accountSessionLogoutAuditHead,
	deploymentID deployment.ID,
	recoveryEpoch int64,
	sessionID accountsession.ID,
	principalID publicid.ID,
	version int64,
	lastUsedAt, idleExpiresAt time.Time,
) (accountSessionLogoutEvidence, error) {
	if !ids.changeID.IsValid() || !ids.auditID.IsValid() || !ids.outboxID.IsValid() ||
		head.streamInternalID <= 0 || head.nextSequence <= 0 || !deploymentID.IsValid() ||
		recoveryEpoch <= 0 || !sessionID.IsValid() || !principalID.IsValid() || version < 2 ||
		lastUsedAt.IsZero() || !idleExpiresAt.After(lastUsedAt) {
		return accountSessionLogoutEvidence{}, ErrAccountSessionLogoutEvidence
	}
	lastUsedAt, idleExpiresAt = lastUsedAt.UTC(), idleExpiresAt.UTC()
	payload, err := json.Marshal(accountSessionTouchPayload{
		SessionID: sessionID.String(), DeploymentID: deploymentID.String(),
		PrincipalID: principalID.String(), RecoveryEpoch: recoveryEpoch,
		SessionVersion: version, LastUsedAt: lastUsedAt, IdleExpiresAt: idleExpiresAt,
	})
	if err != nil {
		return accountSessionLogoutEvidence{}, ErrAccountSessionLogoutEvidence
	}
	input := []byte("meshtransit/account-session/touch/v1\x00")
	for _, id := range [3]publicid.ID{publicid.ID(deploymentID), publicid.ID(sessionID), principalID} {
		encoded := id.Bytes()
		input = append(input, encoded[:]...)
	}
	input = binary.BigEndian.AppendUint64(input, uint64(recoveryEpoch))
	input = binary.BigEndian.AppendUint64(input, uint64(version))
	input = binary.AppendVarint(input, lastUsedAt.UnixMicro())
	input = binary.AppendVarint(input, idleExpiresAt.UnixMicro())
	afterHash := sha256.Sum256(input)
	payloadHash := sha256.Sum256(payload)
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: head.previousHash, EventID: ids.auditID, ChangeID: ids.changeID,
		AggregateKind: "account_session", AggregateID: publicid.ID(sessionID),
		AggregateVersion: version, ActorPrincipalID: principalID,
		Action: "account_session.touched", Permission: "identity.session",
		CorrelationID: publicid.ID(sessionID), AfterSemanticHash: afterHash,
		AuditPayloadHash: payloadHash, OutboxEventClass: "identity.account_session.touched",
		OutboxPayloadHash: payloadHash,
	})
	if err != nil {
		return accountSessionLogoutEvidence{}, ErrAccountSessionLogoutEvidence
	}
	return accountSessionLogoutEvidence{payload: payload, afterHash: afterHash, eventHash: eventHash}, nil
}
