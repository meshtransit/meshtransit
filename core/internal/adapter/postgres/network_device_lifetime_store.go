package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/authorization"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/network/devicelifetime"
	"meshtransit.net/core/internal/domain/publicid"
)

const readNetworkDeviceLifetimeSQL = `SELECT profile_version, name_key, node_lifetime_seconds,
 device_lifetime_seconds, device_never_expires
FROM mesh_ops.read_network_device_lifetime_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::TIMESTAMPTZ)`

const setNetworkDeviceLifetimeSQL = `SELECT changed, role_binding_id::TEXT, network_revision, name_key,
 before_version, before_node_lifetime_seconds, before_device_lifetime_seconds, before_device_never_expires,
 after_version, after_node_lifetime_seconds, after_device_lifetime_seconds, after_device_never_expires
FROM mesh_ops.set_network_device_lifetime_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::BIGINT,$13::BIGINT,$14::BOOLEAN,$15::UUID,$16::TIMESTAMPTZ)`

const appendNetworkDeviceLifetimeEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
 $1::BIGINT,$2::UUID,$3::UUID,$4::BIGINT,$5::BYTEA,$6::BYTEA,
 'network',$7::UUID,$8::BIGINT,$15::BIGINT,$9::UUID,'network.device_lifetime.updated','network.update',
 $10::UUID,$11::BYTEA,$12::BYTEA,$13::JSONB,'network.device_lifetime.updated',$14::JSONB)`

// NetworkDeviceLifetimeStore reads and sets how long signed-in Devices of a
// Network live, through the runtime pool. Each call is one short
// exact-Network transaction.
type NetworkDeviceLifetimeStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

var _ devicelifetime.Store = (*NetworkDeviceLifetimeStore)(nil)

// NewNetworkDeviceLifetimeStore uses the runtime pool.
func NewNetworkDeviceLifetimeStore(pool *Pool, options AccountSessionOptions) (*NetworkDeviceLifetimeStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, devicelifetime.ErrInvalid
	}
	return &NetworkDeviceLifetimeStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

func networkDeviceLifetimeError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "42501":
			return devicelifetime.ErrForbidden
		case "MTL01":
			return devicelifetime.ErrNoInteractiveProfile
		case "MTL02":
			return devicelifetime.ErrVersionConflict
		case "22023", "22P02":
			return devicelifetime.ErrInvalid
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return devicelifetime.ErrForbidden
	}
	return errors.Join(devicelifetime.ErrUnavailable, err)
}

// begin starts one exact-Network unit of work and reads its time on the
// database clock, which authorizes it and stamps everything it writes.
func (store *NetworkDeviceLifetimeStore) begin(ctx context.Context, scope network.Scope) (accountSessionTransaction,
	time.Time, error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) {
		return nil, time.Time{}, devicelifetime.ErrInvalid
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return nil, time.Time{}, errors.Join(devicelifetime.ErrUnavailable, err)
	}
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return tx, time.Time{}, errors.Join(devicelifetime.ErrUnavailable, err)
	}
	var workspaceInternal, networkInternal int64
	if err := tx.QueryRow(ctx, setResourceAuthorityScopeSQL, scope.WorkspaceID().String(),
		scope.NetworkID().String()).Scan(&workspaceInternal, &networkInternal); err != nil {
		return tx, time.Time{}, networkDeviceLifetimeError(err)
	}
	if workspaceInternal <= 0 || networkInternal <= 0 {
		return tx, time.Time{}, devicelifetime.ErrForbidden
	}
	evaluatedAt, err := readTransactionTime(ctx, tx.QueryRow)
	if err != nil {
		return tx, time.Time{}, errors.Join(devicelifetime.ErrUnavailable, err)
	}
	return tx, evaluatedAt, nil
}

// deviceLifetimeRow is the stored choice of one interactive profile.
type deviceLifetimeRow struct {
	version       int64
	legacySeconds int64
	chosenSeconds sql.NullInt64
	neverExpires  bool
}

func (row deviceLifetimeRow) state(nameKey string) (devicelifetime.State, error) {
	if row.version <= 0 {
		return devicelifetime.State{}, devicelifetime.ErrInvalid
	}
	lifetime, never, err := enrollment.ProfileDeviceLifetime(nameKey, row.legacySeconds,
		nullableSeconds(row.chosenSeconds), row.neverExpires)
	if err != nil {
		return devicelifetime.State{}, devicelifetime.ErrInvalid
	}
	state := devicelifetime.State{Version: row.version, Lifetime: lifetime, NeverExpires: never,
		Default: !never && !row.chosenSeconds.Valid}
	if never {
		state.Lifetime = 0
	}
	if !state.IsValid() {
		return devicelifetime.State{}, devicelifetime.ErrInvalid
	}
	return state, nil
}

// Read authorizes network.read and returns the Network's choice.
func (store *NetworkDeviceLifetimeStore) Read(ctx context.Context, session accountsession.Session,
	scope network.Scope) (_ devicelifetime.State, resultErr error) {
	if !session.IsValid() || !scope.IsValid() {
		return devicelifetime.State{}, devicelifetime.ErrInvalid
	}
	tx, evaluatedAt, err := store.begin(ctx, scope)
	if tx != nil {
		defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	}
	if err != nil {
		return devicelifetime.State{}, err
	}
	args := append(sessionQueryArguments(session), scope.WorkspaceID().String(), scope.NetworkID().String(), evaluatedAt)
	var row deviceLifetimeRow
	var nameKey string
	if err := tx.QueryRow(ctx, readNetworkDeviceLifetimeSQL, args...).Scan(&row.version, &nameKey,
		&row.legacySeconds, &row.chosenSeconds, &row.neverExpires); err != nil {
		return devicelifetime.State{}, networkDeviceLifetimeError(err)
	}
	return row.state(nameKey)
}

// Update authorizes network.update, stores the choice and, when it changed,
// appends one audit and outbox record on the Network stream. An uncertain
// commit returns no success and is not retried.
func (store *NetworkDeviceLifetimeStore) Update(ctx context.Context,
	command devicelifetime.Command) (_ devicelifetime.Result, resultErr error) {
	if !command.IsValid() {
		return devicelifetime.Result{}, devicelifetime.ErrInvalid
	}
	var ids [3]publicid.ID
	for index := range ids {
		id, err := publicid.New()
		if err != nil {
			return devicelifetime.Result{}, devicelifetime.ErrUnavailable
		}
		ids[index] = id
	}
	change, event, outbox := ids[0], ids[1], ids[2]
	tx, evaluatedAt, err := store.begin(ctx, command.Scope)
	committed := false
	if tx != nil {
		defer func() {
			if !committed {
				resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
			}
		}()
	}
	if err != nil {
		return devicelifetime.Result{}, err
	}
	var chosen any
	if !command.NeverExpires {
		chosen = int64(command.Lifetime / time.Second)
	}
	args := append(sessionQueryArguments(command.Session), command.Scope.WorkspaceID().String(),
		command.Scope.NetworkID().String(), command.ExpectedVersion, chosen, command.NeverExpires,
		change.String(), evaluatedAt)
	var changed bool
	var binding sql.NullString
	var networkRevision int64
	var nameKey string
	var before, after deviceLifetimeRow
	if err := tx.QueryRow(ctx, setNetworkDeviceLifetimeSQL, args...).Scan(&changed, &binding, &networkRevision,
		&nameKey, &before.version, &before.legacySeconds, &before.chosenSeconds, &before.neverExpires,
		&after.version, &after.legacySeconds, &after.chosenSeconds, &after.neverExpires); err != nil {
		return devicelifetime.Result{}, networkDeviceLifetimeError(err)
	}
	beforeState, err := before.state(nameKey)
	if err != nil {
		return devicelifetime.Result{}, err
	}
	afterState, err := after.state(nameKey)
	if err != nil {
		return devicelifetime.Result{}, err
	}
	if networkRevision <= 0 || beforeState.Version != command.ExpectedVersion ||
		changed != (afterState.Version > beforeState.Version) {
		return devicelifetime.Result{}, devicelifetime.ErrInvalid
	}
	if changed {
		if err := appendNetworkDeviceLifetimeEvidence(ctx, tx, command, deviceLifetimeEvidence{
			before: beforeState, after: afterState, binding: binding.String, networkRevision: networkRevision,
		}, change, event, outbox); err != nil {
			return devicelifetime.Result{}, errors.Join(devicelifetime.ErrUnavailable, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		committed = true
		return devicelifetime.Result{}, errors.Join(devicelifetime.ErrUnavailable, err)
	}
	committed = true
	return devicelifetime.Result{State: afterState, Changed: changed}, nil
}

// deviceLifetimeView is the audited form of a choice: seconds, null when the
// Device never expires.
type deviceLifetimeView struct {
	Seconds      *int64 `json:"device_lifetime_seconds"`
	NeverExpires bool   `json:"never_expires"`
	Default      bool   `json:"default"`
}

func newDeviceLifetimeView(state devicelifetime.State) deviceLifetimeView {
	view := deviceLifetimeView{NeverExpires: state.NeverExpires, Default: state.Default}
	if !state.NeverExpires {
		seconds := int64(state.Lifetime / time.Second)
		view.Seconds = &seconds
	}
	return view
}

func deviceLifetimeSemanticHash(networkID string, state devicelifetime.State) ([32]byte, error) {
	encoded, err := json.Marshal(struct {
		NetworkID string `json:"network_id"`
		Version   int64  `json:"version"`
		deviceLifetimeView
	}{networkID, state.Version, newDeviceLifetimeView(state)})
	return sha256.Sum256(encoded), err
}

type deviceLifetimeEvidence struct {
	before, after   devicelifetime.State
	binding         string
	networkRevision int64
}

func appendNetworkDeviceLifetimeEvidence(ctx context.Context, tx accountSessionTransaction,
	command devicelifetime.Command, evidence deviceLifetimeEvidence, change, event, outbox publicid.ID) error {
	var streamID, sequence int64
	var previous []byte
	if err := tx.QueryRow(ctx, `SELECT stream_internal_id,next_sequence,latest_event_hash
FROM mesh_audit.lock_network_stream_head()`).Scan(&streamID, &sequence, &previous); err != nil {
		return err
	}
	if streamID <= 0 || sequence <= 0 || len(previous) != sha256.Size {
		return devicelifetime.ErrInvalid
	}
	networkID := command.Scope.NetworkID().String()
	beforeHash, err := deviceLifetimeSemanticHash(networkID, evidence.before)
	if err != nil {
		return err
	}
	afterHash, err := deviceLifetimeSemanticHash(networkID, evidence.after)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(struct {
		NetworkID     string             `json:"network_id"`
		SessionID     string             `json:"session_id"`
		RoleBindingID string             `json:"role_binding_id,omitempty"`
		Before        deviceLifetimeView `json:"before"`
		After         deviceLifetimeView `json:"after"`
	}{networkID, command.Session.ID().String(), evidence.binding, newDeviceLifetimeView(evidence.before),
		newDeviceLifetimeView(evidence.after)})
	if err != nil {
		return err
	}
	outboxPayload, err := json.Marshal(struct {
		NetworkID string `json:"network_id"`
		Version   int64  `json:"version"`
	}{networkID, evidence.after.Version})
	if err != nil {
		return err
	}
	var previousHash [32]byte
	copy(previousHash[:], previous)
	principal := publicid.ID(command.Session.PrincipalID())
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previousHash, EventID: event, ChangeID: change,
		AggregateKind: "network", AggregateID: publicid.ID(command.Scope.NetworkID()),
		AggregateVersion: evidence.after.Version, NetworkRevision: evidence.networkRevision,
		ActorPrincipalID: principal, Action: "network.device_lifetime.updated",
		Permission: string(authorization.PermissionNetworkUpdate), CorrelationID: command.CorrelationID,
		BeforeSemanticHash: beforeHash, AfterSemanticHash: afterHash, AuditPayloadHash: sha256.Sum256(payload),
		OutboxEventClass: "network.device_lifetime.updated", OutboxPayloadHash: sha256.Sum256(outboxPayload),
	})
	if err != nil {
		return err
	}
	var appended int64
	if err := tx.QueryRow(ctx, appendNetworkDeviceLifetimeEvidenceSQL, streamID, event.String(), outbox.String(),
		sequence, previousHash[:], eventHash[:], networkID, evidence.after.Version, principal.String(),
		command.CorrelationID.String(), beforeHash[:], afterHash[:], payload, outboxPayload,
		evidence.networkRevision).Scan(&appended); err != nil {
		return err
	}
	if appended != sequence {
		return devicelifetime.ErrInvalid
	}
	return nil
}
