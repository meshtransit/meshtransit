package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/meshtransit/meshtransit/internal/audit"
	"github.com/meshtransit/meshtransit/internal/guardrail"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const maximumGuardrailDocumentBytes = 2 << 20

const listWorkspaceGuardrailsSQL = `SELECT mesh_ops.list_workspace_guardrails_v1(` + sessionArguments + `,$10::UUID)::TEXT`

const changeWorkspaceGuardrailSQL = `SELECT guardrail::TEXT, previous_semantic_hash,
 COALESCE(actor_binding_public_id::TEXT,''), COALESCE(actor_role_public_id::TEXT,''),
 COALESCE(actor_binding_generation,0), COALESCE(actor_membership_generation,0), COALESCE(actor_owner_generation,0)
FROM mesh_ops.change_workspace_guardrail_v1(` + sessionArguments + `,
 $10::UUID,$11::TEXT,$12::UUID,$13::BIGINT,$14::TEXT,$15::TEXT,$16::TEXT,$17::TEXT,$18::JSONB,$19::BYTEA,
 $20::UUID[],$21::TEXT,$22::UUID)`

// activeWorkspaceGuardrailsSQL reads the guardrails of the Workspace bound to
// the current transaction's verified scope.
const activeWorkspaceGuardrailsSQL = `SELECT mesh_ops.active_workspace_guardrails_v1()::TEXT`

const appendGuardrailEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
 $1::BIGINT,$2::UUID,$3::UUID,$4::BIGINT,$5::BYTEA,$6::BYTEA,
 'guardrail',$7::UUID,$8::BIGINT,NULL::BIGINT,$9::UUID,$10::TEXT,$11::TEXT,
 $12::UUID,$13::BYTEA,$14::BYTEA,$15::JSONB,$10::TEXT,$16::JSONB)`

// GuardrailStore reads and changes Workspace guardrails through the runtime
// pool. Each change commits with its audit evidence on the Workspace stream.
type GuardrailStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

var _ guardrail.Store = (*GuardrailStore)(nil)

// NewGuardrailStore uses the runtime pool.
func NewGuardrailStore(pool *Pool, options AccountSessionOptions) (*GuardrailStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, guardrail.ErrInvalid
	}
	return &GuardrailStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

type guardrailDocument struct {
	ID          string          `json:"guardrail_id"`
	Kind        string          `json:"kind"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Mode        string          `json:"mode"`
	Params      json.RawMessage `json:"params"`
	Version     int64           `json:"version"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	State       string          `json:"state,omitempty"`
}

func (document guardrailDocument) guardrail() (guardrail.Guardrail, error) {
	id, err := publicid.Parse(document.ID)
	if err != nil || document.Version <= 0 {
		return guardrail.Guardrail{}, guardrail.ErrInvalid
	}
	result := guardrail.Guardrail{ID: id, Version: document.Version}
	if err := guardrail.ParseParams(guardrail.Kind(document.Kind), document.Params, &result.Spec); err != nil {
		return guardrail.Guardrail{}, err
	}
	result.Name, result.Description, result.Mode = document.Name, document.Description, guardrail.Mode(document.Mode)
	if !result.IsValid() {
		return guardrail.Guardrail{}, guardrail.ErrInvalid
	}
	return result, nil
}

func strictJSON(encoded []byte, target any) error {
	if len(encoded) == 0 || len(encoded) > maximumGuardrailDocumentBytes {
		return guardrail.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return guardrail.ErrInvalid
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return guardrail.ErrInvalid
	}
	return nil
}

// decodeActiveGuardrails reads the active set returned by
// mesh_ops.active_workspace_guardrails_v1 for an enforcing transaction.
func decodeActiveGuardrails(encoded string) ([]guardrail.Guardrail, error) {
	var documents []guardrailDocument
	if err := strictJSON([]byte(encoded), &documents); err != nil || documents == nil ||
		len(documents) > guardrail.MaximumGuardrails {
		return nil, guardrail.ErrInvalid
	}
	guardrails := make([]guardrail.Guardrail, 0, len(documents))
	for _, document := range documents {
		item, err := document.guardrail()
		if err != nil {
			return nil, err
		}
		guardrails = append(guardrails, item)
	}
	return guardrails, nil
}

func guardrailDatabaseError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "42501":
			return guardrail.ErrForbidden
		case "P0002":
			return guardrail.ErrNotFound
		case "40001":
			return guardrail.ErrVersionConflict
		case "MTG01":
			return guardrail.ErrUnknownNetwork
		case "MTG02":
			return guardrail.ErrLimit
		case "22023", "22P02", "23514":
			return guardrail.ErrInvalid
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return guardrail.ErrForbidden
	}
	return errors.Join(guardrail.ErrUnavailable, err)
}

func (store *GuardrailStore) begin(ctx context.Context) (accountSessionTransaction, error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) {
		return nil, guardrail.ErrInvalid
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return nil, errors.Join(guardrail.ErrUnavailable, err)
	}
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return tx, errors.Join(guardrail.ErrUnavailable, err)
	}
	return tx, nil
}

// List authorizes guardrail.read and returns the active guardrails with
// whether the Session may manage and weaken them.
func (store *GuardrailStore) List(ctx context.Context, session accountsession.Session,
	workspaceID workspace.ID) (_ guardrail.Listing, resultErr error) {
	if !session.IsValid() || !workspaceID.IsValid() {
		return guardrail.Listing{}, guardrail.ErrInvalid
	}
	tx, err := store.begin(ctx)
	if tx != nil {
		defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	}
	if err != nil {
		return guardrail.Listing{}, err
	}
	var encoded *string
	if err := tx.QueryRow(ctx, listWorkspaceGuardrailsSQL,
		append(sessionQueryArguments(session), workspaceID.String())...).Scan(&encoded); err != nil {
		return guardrail.Listing{}, guardrailDatabaseError(err)
	}
	if encoded == nil {
		return guardrail.Listing{}, guardrail.ErrForbidden
	}
	var envelope struct {
		Guardrails []guardrailDocument `json:"guardrails"`
		CanManage  bool                `json:"can_manage"`
		CanWeaken  bool                `json:"can_weaken"`
	}
	if err := strictJSON([]byte(*encoded), &envelope); err != nil || envelope.Guardrails == nil {
		return guardrail.Listing{}, guardrail.ErrInvalid
	}
	guardrails := make([]guardrail.Guardrail, 0, len(envelope.Guardrails))
	for _, document := range envelope.Guardrails {
		item, err := document.guardrail()
		if err != nil {
			return guardrail.Listing{}, err
		}
		guardrails = append(guardrails, item)
	}
	return guardrail.Listing{Guardrails: guardrails, CanManage: envelope.CanManage, CanWeaken: envelope.CanWeaken}, nil
}

type guardrailActorEvidence struct {
	BindingID            string `json:"binding_id,omitempty"`
	RoleID               string `json:"role_id,omitempty"`
	BindingGeneration    int64  `json:"binding_generation"`
	MembershipGeneration int64  `json:"membership_generation"`
	OwnerGeneration      int64  `json:"owner_generation"`
}

// Change commits one guardrail change and its evidence in one transaction.
func (store *GuardrailStore) Change(ctx context.Context, change guardrail.Change) (_ guardrail.Result, resultErr error) {
	if !change.Session.IsValid() || !change.WorkspaceID.IsValid() || !change.GuardrailID.IsValid() ||
		!change.CorrelationID.IsValid() || !change.Spec.IsValid() {
		return guardrail.Result{}, guardrail.ErrInvalid
	}
	params, err := change.Spec.ParamsDocument()
	if err != nil {
		return guardrail.Result{}, err
	}
	semantic, err := change.Spec.SemanticHash()
	if err != nil {
		return guardrail.Result{}, err
	}
	networks := change.Spec.Networks()
	networkTexts := make([]string, len(networks))
	for index, id := range networks {
		networkTexts[index] = id.String()
	}
	changeID, err := publicid.New()
	if err != nil {
		return guardrail.Result{}, guardrail.ErrUnavailable
	}
	var expected *int64
	if change.Operation != guardrail.OperationCreate {
		version := change.ExpectedVersion
		expected = &version
	}
	tx, err := store.begin(ctx)
	if tx != nil {
		defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	}
	if err != nil {
		return guardrail.Result{}, err
	}
	args := append(sessionQueryArguments(change.Session), change.WorkspaceID.String(), string(change.Operation),
		change.GuardrailID.String(), expected, string(change.Spec.Kind), change.Spec.Name, change.Spec.Description,
		string(change.Spec.Mode), string(params), semantic[:], networkTexts, string(change.Permission),
		changeID.String())
	var encoded string
	var previousHash []byte
	var actor guardrailActorEvidence
	if err := tx.QueryRow(ctx, changeWorkspaceGuardrailSQL, args...).Scan(&encoded, &previousHash,
		&actor.BindingID, &actor.RoleID, &actor.BindingGeneration, &actor.MembershipGeneration,
		&actor.OwnerGeneration); err != nil {
		return guardrail.Result{}, guardrailDatabaseError(err)
	}
	var document guardrailDocument
	if err := strictJSON([]byte(encoded), &document); err != nil {
		return guardrail.Result{}, err
	}
	saved, err := document.guardrail()
	if err != nil || saved.ID != change.GuardrailID {
		return guardrail.Result{}, guardrail.ErrInvalid
	}
	deleted := document.State == "deleted"
	if deleted != (change.Operation == guardrail.OperationDelete) ||
		(change.Operation == guardrail.OperationCreate) != (saved.Version == 1) ||
		(change.Operation != guardrail.OperationCreate && saved.Version != change.ExpectedVersion+1) {
		return guardrail.Result{}, guardrail.ErrInvalid
	}
	if err := appendGuardrailEvidence(ctx, tx, change, saved, previousHash, actor, changeID); err != nil {
		return guardrail.Result{}, errors.Join(guardrail.ErrUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return guardrail.Result{}, errors.Join(guardrail.ErrUnavailable, err)
	}
	return guardrail.Result{Guardrail: saved, Deleted: deleted, UpdatedAt: document.UpdatedAt}, nil
}

func appendGuardrailEvidence(ctx context.Context, tx accountSessionTransaction, change guardrail.Change,
	saved guardrail.Guardrail, previousHash []byte, actor guardrailActorEvidence, changeID publicid.ID) error {
	var streamID, sequence int64
	var previous []byte
	if err := tx.QueryRow(ctx, lockWorkspaceStreamHeadSQL, change.Session.DeploymentID().String(),
		change.WorkspaceID.String()).Scan(&streamID, &sequence, &previous); err != nil {
		return err
	}
	if streamID <= 0 || sequence <= 0 || len(previous) != sha256.Size {
		return guardrail.ErrInvalid
	}
	action := "guardrail." + map[guardrail.Operation]string{
		guardrail.OperationCreate: "created", guardrail.OperationUpdate: "updated", guardrail.OperationDelete: "deleted",
	}[change.Operation]
	after, err := saved.SemanticHash()
	if err != nil {
		return err
	}
	var before [32]byte
	var beforeArgument any
	if len(previousHash) == sha256.Size {
		copy(before[:], previousHash)
		beforeArgument = before[:]
	}
	params, err := saved.ParamsDocument()
	if err != nil {
		return err
	}
	payload, err := json.Marshal(struct {
		WorkspaceID string                 `json:"workspace_id"`
		SessionID   string                 `json:"session_id"`
		GuardrailID string                 `json:"guardrail_id"`
		Kind        string                 `json:"kind"`
		Name        string                 `json:"display_name"`
		Mode        string                 `json:"mode"`
		Params      json.RawMessage        `json:"params"`
		Weakened    bool                   `json:"weakened"`
		Authority   guardrailActorEvidence `json:"authority"`
	}{change.WorkspaceID.String(), change.Session.ID().String(), saved.ID.String(), string(saved.Kind), saved.Name,
		string(saved.Mode), params, string(change.Permission) == "guardrail.weaken", actor})
	if err != nil {
		return err
	}
	outbox, err := json.Marshal(struct {
		WorkspaceID string `json:"workspace_id"`
		GuardrailID string `json:"guardrail_id"`
		Version     int64  `json:"version"`
	}{change.WorkspaceID.String(), saved.ID.String(), saved.Version})
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
	var previousEvent [32]byte
	copy(previousEvent[:], previous)
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previousEvent, EventID: eventID, ChangeID: changeID,
		AggregateKind: "guardrail", AggregateID: saved.ID, AggregateVersion: saved.Version,
		ActorPrincipalID: publicid.ID(change.Session.PrincipalID()), Action: action,
		Permission: string(change.Permission), CorrelationID: change.CorrelationID,
		BeforeSemanticHash: before, AfterSemanticHash: after, AuditPayloadHash: sha256.Sum256(payload),
		OutboxEventClass: action, OutboxPayloadHash: sha256.Sum256(outbox),
	})
	if err != nil {
		return err
	}
	var appended int64
	if err := tx.QueryRow(ctx, appendGuardrailEvidenceSQL, streamID, eventID.String(), outboxID.String(), sequence,
		previousEvent[:], eventHash[:], saved.ID.String(), saved.Version, change.Session.PrincipalID().String(),
		action, string(change.Permission), change.CorrelationID.String(), beforeArgument, after[:], payload,
		outbox).Scan(&appended); err != nil {
		return err
	}
	if appended != sequence {
		return guardrail.ErrInvalid
	}
	return nil
}
