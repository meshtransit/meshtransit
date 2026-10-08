package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"

	"github.com/meshtransit/meshtransit/internal/audit"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/identitygroup"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const maximumIdentityCatalogDocumentBytes = 1 << 20

const appendIdentityCatalogEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
 $1::BIGINT,$2::UUID,$3::UUID,$4::BIGINT,$5::BYTEA,$6::BYTEA,
 $7::TEXT,$8::UUID,$9::BIGINT,$10::BIGINT,$11::UUID,$12::TEXT,$13::TEXT,
 $14::UUID,$15::BYTEA,$16::BYTEA,$17::JSONB,$18::TEXT,$19::JSONB)`

const lockWorkspaceNetworkStreamHeadSQL = `SELECT stream_internal_id,next_sequence,latest_event_hash
FROM mesh_audit.lock_workspace_network_stream_head_v1($1::UUID)`

var errIdentityCatalogEvidence = errors.New("identity catalog: invalid evidence")

// decodeIdentityCatalogJSON decodes one bounded document, rejecting unknown
// fields and trailing data.
func decodeIdentityCatalogJSON(encoded []byte, target any) error {
	if len(encoded) == 0 || len(encoded) > maximumIdentityCatalogDocumentBytes {
		return errIdentityCatalogEvidence
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errIdentityCatalogEvidence
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errIdentityCatalogEvidence
	}
	return nil
}

// catalogAuthority is the authority PostgreSQL resolved for a Workspace
// change, recorded with its evidence.
type catalogAuthority struct {
	BindingID            string `json:"binding_id,omitempty"`
	RoleID               string `json:"role_id,omitempty"`
	BindingGeneration    int64  `json:"binding_generation"`
	MembershipGeneration int64  `json:"membership_generation"`
	OwnerGeneration      int64  `json:"owner_generation"`
}

// catalogEvent is one evidence record of an identity catalog change.
type catalogEvent struct {
	session        accountsession.Session
	correlationID  publicid.ID
	changeID       publicid.ID
	aggregateKind  string
	aggregateID    publicid.ID
	version        int64
	action         string
	permission     string
	before         *[32]byte
	after          [32]byte
	payload        any
	outboxClass    string
	outbox         any
	networkVersion int64
	// actor and deployment replace the session's when no session exists yet,
	// such as an invitation accepted at sign-in.
	actor      publicid.ID
	deployment string
}

func appendCatalogEvent(ctx context.Context, tx accountSessionTransaction, streamID, sequence int64,
	previous []byte, event catalogEvent) error {
	if streamID <= 0 || sequence <= 0 || len(previous) != sha256.Size {
		return errIdentityCatalogEvidence
	}
	payload, err := json.Marshal(event.payload)
	if err != nil {
		return err
	}
	outbox, err := json.Marshal(event.outbox)
	if err != nil {
		return err
	}
	eventID, err := publicid.New()
	if err != nil {
		return err
	}
	outboxID, err := publicid.New()
	if err != nil {
		return err
	}
	var previousHash, before [32]byte
	copy(previousHash[:], previous)
	var beforeArgument, networkRevision any
	if event.before != nil {
		before = *event.before
		beforeArgument = before[:]
	}
	if event.networkVersion > 0 {
		networkRevision = event.networkVersion
	}
	principal := publicid.ID(event.session.PrincipalID())
	if event.actor.IsValid() {
		principal = event.actor
	}
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previousHash, EventID: eventID, ChangeID: event.changeID,
		AggregateKind: event.aggregateKind, AggregateID: event.aggregateID, AggregateVersion: event.version,
		NetworkRevision: event.networkVersion, ActorPrincipalID: principal, Action: event.action,
		Permission: event.permission, CorrelationID: event.correlationID,
		BeforeSemanticHash: before, AfterSemanticHash: event.after, AuditPayloadHash: sha256.Sum256(payload),
		OutboxEventClass: event.outboxClass, OutboxPayloadHash: sha256.Sum256(outbox),
	})
	if err != nil {
		return err
	}
	var appended int64
	if err := tx.QueryRow(ctx, appendIdentityCatalogEvidenceSQL, streamID, eventID.String(), outboxID.String(),
		sequence, previousHash[:], eventHash[:], event.aggregateKind, event.aggregateID.String(), event.version,
		networkRevision, principal.String(), event.action, event.permission, event.correlationID.String(),
		beforeArgument, event.after[:], payload, event.outboxClass, outbox).Scan(&appended); err != nil {
		return err
	}
	if appended != sequence {
		return errIdentityCatalogEvidence
	}
	return nil
}

// appendWorkspaceCatalogEvent records a change on the Workspace stream.
func appendWorkspaceCatalogEvent(ctx context.Context, tx accountSessionTransaction, workspaceID workspace.ID,
	event catalogEvent) error {
	var streamID, sequence int64
	var previous []byte
	deployment := event.deployment
	if deployment == "" {
		deployment = event.session.DeploymentID().String()
	}
	if err := tx.QueryRow(ctx, lockWorkspaceStreamHeadSQL, deployment,
		workspaceID.String()).Scan(&streamID, &sequence, &previous); err != nil {
		return err
	}
	return appendCatalogEvent(ctx, tx, streamID, sequence, previous, event)
}

// appendNetworkWakeEvents records, on each rebuilt Network's own stream, why
// its revision advanced, with the outbox wakeup that rebuilds its maps.
func appendNetworkWakeEvents(ctx context.Context, tx accountSessionTransaction, networks []identitygroup.AdvancedNetwork,
	base catalogEvent, reason any) error {
	for _, advanced := range networks {
		var streamID, sequence int64
		var previous []byte
		if err := tx.QueryRow(ctx, lockWorkspaceNetworkStreamHeadSQL, advanced.NetworkID.String()).
			Scan(&streamID, &sequence, &previous); err != nil {
			return err
		}
		event := base
		event.networkVersion = advanced.NetworkRevision
		event.payload = struct {
			NetworkID string `json:"network_id"`
			Reason    any    `json:"reason"`
		}{advanced.NetworkID.String(), reason}
		event.outboxClass = "network.revision.advanced"
		event.outbox = struct {
			NetworkID       string `json:"network_id"`
			Aggregate       string `json:"aggregate_kind"`
			AggregateID     string `json:"aggregate_id"`
			NetworkRevision int64  `json:"network_revision"`
			GroupRevision   int64  `json:"group_revision"`
		}{advanced.NetworkID.String(), base.aggregateKind, base.aggregateID.String(), advanced.NetworkRevision,
			advanced.GroupRevision}
		if err := appendCatalogEvent(ctx, tx, streamID, sequence, previous, event); err != nil {
			return err
		}
	}
	return nil
}
