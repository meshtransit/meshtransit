package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

// A browser sign-in moves its machine (schema 290, sign-in-moves-machine §6):
// the person's own Device that holds the machine key in another Network is
// revoked in the same transaction that creates the Device the person
// approved, once the approval page showed it and the person confirmed.

const lockBrowserMoveRevisionsSQL = `SELECT source_workspace_id, source_network_id, source_device_id,
    movable, owned, acknowledged, same_node_key
FROM mesh_ops.lock_browser_move_revisions_v1(
    $1::UUID, $2::BIGINT, $3::BYTEA, $4::BYTEA, $5::BYTEA, $6::BYTEA
)`

const moveOutBrowserDeviceSQL = `SELECT mesh_ops.move_out_browser_device_v1(
    $1::UUID, $2::UUID, $3::BIGINT, $4::BYTEA, $5::BYTEA, $6::BYTEA, $7::UUID
)::TEXT`

const finalizeBrowserMoveSQL = `SELECT mesh_ops.finalize_browser_move_v1($1::UUID, $2::JSONB)`

const browserMoveAction = "device.moved_out"

// browserMoveSource is what the revision lock found: a Device holding the
// machine key outside the approved Network.
type browserMoveSource struct {
	found                                     bool
	workspaceInternalID, networkInternalID    int64
	deviceInternalID                          int64
	movable, owned, acknowledged, sameNodeKey bool
}

// lockBrowserMoveRevisions runs before the completion authority, so both
// Networks' revisions are taken in ascending order (M2 of the design review).
func lockBrowserMoveRevisions(ctx context.Context, tx registrationDatabaseTransaction,
	deploymentID deployment.ID, epoch int64, digest enrollment.BrowserIntentDigest,
	identityValue node.RegistrationIdentity,
) (browserMoveSource, error) {
	machine := identityValue.MachineKey().Bytes()
	fingerprint := identityValue.MachineKey().Fingerprint()
	key := identityValue.NodeKey().Bytes()
	proof := digest.Bytes()
	var source browserMoveSource
	err := tx.QueryRow(ctx, lockBrowserMoveRevisionsSQL, deploymentID.String(), epoch,
		proof[:], machine[:], fingerprint[:], key[:],
	).Scan(&source.workspaceInternalID, &source.networkInternalID, &source.deviceInternalID,
		&source.movable, &source.owned, &source.acknowledged, &source.sameNodeKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return browserMoveSource{}, nil
	}
	if err != nil {
		return browserMoveSource{}, err
	}
	if source.workspaceInternalID <= 0 || source.networkInternalID <= 0 || source.deviceInternalID <= 0 {
		return browserMoveSource{}, ErrRegistrationEvidence
	}
	source.found = true
	return source, nil
}

// refusal names why the found source cannot move, or nil when it can.
func (source browserMoveSource) refusal() error {
	switch {
	case !source.found:
		return nil
	case !source.owned:
		return registration.ErrMachineOfAnotherAccount
	case !source.movable:
		return registration.ErrMachineNotMovable
	case source.sameNodeKey:
		return registration.ErrMoveNeedsNewClient
	case !source.acknowledged:
		return registration.ErrMoveNotConfirmed
	}
	return nil
}

type browserMoveProof struct {
	ChangeID            string `json:"change_id"`
	WorkspaceInternalID int64  `json:"workspace_internal_id"`
	NetworkInternalID   int64  `json:"network_internal_id"`
	SameWorkspace       bool   `json:"same_workspace"`
	DeviceID            string `json:"device_id"`
	AggregateVersion    int64  `json:"aggregate_version"`
	PrincipalID         string `json:"principal_id"`
	Action              string `json:"action"`
	StreamID            int64  `json:"stream_id"`
	Sequence            int64  `json:"sequence"`
	PreviousHash        string `json:"previous_hash"`
	NetworkRevision     int64  `json:"network_revision"`
	AuditPayload        string `json:"audit_payload"`
	OutboxPayload       string `json:"outbox_payload"`
}

func decodeBrowserMoveProof(encoded string, change publicid.ID, source browserMoveSource) (browserMoveProof, error) {
	if len(encoded) == 0 || len(encoded) > 65536 {
		return browserMoveProof{}, ErrRegistrationEvidence
	}
	var proof browserMoveProof
	decoder := json.NewDecoder(bytes.NewReader([]byte(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil {
		return browserMoveProof{}, ErrRegistrationEvidence
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return browserMoveProof{}, ErrRegistrationEvidence
	}
	previous, err := hex.DecodeString(proof.PreviousHash)
	deviceID, deviceErr := publicid.Parse(proof.DeviceID)
	principalID, principalErr := publicid.Parse(proof.PrincipalID)
	if err != nil || deviceErr != nil || principalErr != nil || len(previous) != sha256.Size ||
		proof.ChangeID != change.String() || deviceID.String() != proof.DeviceID ||
		principalID.String() != proof.PrincipalID ||
		proof.WorkspaceInternalID != source.workspaceInternalID ||
		proof.NetworkInternalID != source.networkInternalID ||
		proof.AggregateVersion <= 0 || proof.StreamID <= 0 || proof.Sequence <= 0 ||
		proof.NetworkRevision <= 0 || proof.Action != browserMoveAction ||
		!json.Valid([]byte(proof.AuditPayload)) || !json.Valid([]byte(proof.OutboxPayload)) ||
		len(proof.AuditPayload) > 16384 || len(proof.OutboxPayload) > 16384 {
		return browserMoveProof{}, ErrRegistrationEvidence
	}
	return proof, nil
}

func hashBrowserMove(proof browserMoveProof, change, eventID, outboxID publicid.ID) ([]byte, error) {
	previous, err := hex.DecodeString(proof.PreviousHash)
	if err != nil || len(previous) != sha256.Size {
		return nil, ErrRegistrationEvidence
	}
	deviceID, deviceErr := publicid.Parse(proof.DeviceID)
	principalID, principalErr := publicid.Parse(proof.PrincipalID)
	if deviceErr != nil || principalErr != nil {
		return nil, ErrRegistrationEvidence
	}
	hash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: [32]byte(previous), EventID: eventID, ChangeID: change,
		AggregateKind: "device", AggregateID: deviceID, AggregateVersion: proof.AggregateVersion,
		NetworkRevision: proof.NetworkRevision, ActorPrincipalID: principalID,
		Action: proof.Action, Permission: "device.register",
		AuditPayloadHash:  sha256.Sum256([]byte(proof.AuditPayload)),
		OutboxEventClass:  "network.revision.advanced",
		OutboxPayloadHash: sha256.Sum256([]byte(proof.OutboxPayload)),
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		StreamID      int64  `json:"stream_id"`
		Sequence      int64  `json:"sequence"`
		PreviousHash  string `json:"previous_hash"`
		AuditPayload  string `json:"audit_payload"`
		OutboxPayload string `json:"outbox_payload"`
		EventID       string `json:"event_id"`
		OutboxID      string `json:"outbox_id"`
		EventHash     string `json:"event_hash"`
	}{proof.StreamID, proof.Sequence, proof.PreviousHash, proof.AuditPayload, proof.OutboxPayload,
		eventID.String(), outboxID.String(), hex.EncodeToString(hash[:])})
}

// moveOutBrowserDevice revokes the acknowledged source Device in its Network
// and appends that Network's evidence, under the move's own change. The
// caller's scope and change are what they were before.
func moveOutBrowserDevice(ctx context.Context, tx registrationDatabaseTransaction,
	deploymentID deployment.ID, epoch int64, digest enrollment.BrowserIntentDigest,
	identityValue node.RegistrationIdentity, authority browserCompletionAuthority,
	source browserMoveSource, ids browserCompletionIDs,
) error {
	machine := identityValue.MachineKey().Bytes()
	fingerprint := identityValue.MachineKey().Fingerprint()
	proofDigest := digest.Bytes()
	var encoded string
	err := tx.QueryRow(ctx, moveOutBrowserDeviceSQL, ids.moveChange.String(), deploymentID.String(), epoch,
		proofDigest[:], machine[:], fingerprint[:], authority.registrationPublicID).Scan(&encoded)
	if err != nil {
		var postgresError *pgconn.PgError
		// MTM03: the source changed since the lock (another writer revoked or
		// moved it): this approval cannot move it any more.
		if errors.As(err, &postgresError) && postgresError.Code == "MTM03" {
			return registration.ErrMachineNotMovable
		}
		// MTL05 (source Network being deleted) and lock errors are retried.
		return err
	}
	proof, err := decodeBrowserMoveProof(encoded, ids.moveChange, source)
	if err != nil {
		return err
	}
	event, err := hashBrowserMove(proof, ids.moveChange, ids.moveEvent, ids.moveOutbox)
	if err != nil {
		return errors.Join(ErrRegistrationEvidence, err)
	}
	var sequence int64
	if err := tx.QueryRow(ctx, finalizeBrowserMoveSQL, ids.moveChange.String(), string(event)).Scan(&sequence); err != nil ||
		sequence != proof.Sequence {
		return errors.Join(ErrRegistrationEvidence, err)
	}
	return nil
}
