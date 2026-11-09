package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/network/deletion"
	"meshtransit.net/core/internal/domain/publicid"
)

const deleteNetworkSQL = `SELECT mesh_ops.delete_network_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::BIGINT,$13::TEXT,$14::UUID,$15::TIMESTAMPTZ)::TEXT`

const readNetworkSQL = `SELECT mesh_ops.read_network_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::TIMESTAMPTZ)::TEXT`

// networkDeletePermission authorizes deleting a Network, Workspace-wide.
const networkDeletePermission = "network.delete"

// NetworkDeletionStore deletes and reads one Network through the runtime
// pool, in the transaction's exact Network scope. A deletion commits with
// one network.deleted event on the Network's stream that also wakes its
// map sessions, which control then closes.
type NetworkDeletionStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

var _ deletion.Store = (*NetworkDeletionStore)(nil)

// NewNetworkDeletionStore uses the runtime pool.
func NewNetworkDeletionStore(pool *Pool, options AccountSessionOptions) (*NetworkDeletionStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, deletion.ErrInvalid
	}
	return &NetworkDeletionStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

func networkDeletionDatabaseError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "42501":
			return deletion.ErrForbidden
		case "23503":
			// set_network_scope: no such Network in the Workspace.
			return deletion.ErrNotFound
		case "P0002":
			return deletion.ErrNotFound
		case "40001":
			return deletion.ErrVersionConflict
		case "22023", "22P02", "23514":
			return deletion.ErrInvalid
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return deletion.ErrForbidden
	}
	return errors.Join(deletion.ErrUnavailable, err)
}

// transact runs one exact-Network transaction and commits only when run asks.
func (store *NetworkDeletionStore) transact(ctx context.Context, scope network.Scope,
	run func(tx accountSessionTransaction, now time.Time) (bool, error)) (resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) {
		return deletion.ErrInvalid
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return errors.Join(deletion.ErrUnavailable, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
		}
	}()
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return errors.Join(deletion.ErrUnavailable, err)
	}
	var workspaceInternal, networkInternal int64
	if err := tx.QueryRow(ctx, setResourceAuthorityScopeSQL, scope.WorkspaceID().String(),
		scope.NetworkID().String()).Scan(&workspaceInternal, &networkInternal); err != nil {
		return networkDeletionDatabaseError(err)
	}
	if workspaceInternal <= 0 || networkInternal <= 0 {
		return deletion.ErrForbidden
	}
	now, err := readTransactionTime(ctx, tx.QueryRow)
	if err != nil {
		return errors.Join(deletion.ErrUnavailable, err)
	}
	commit, err := run(tx, now)
	if err != nil || !commit {
		return err
	}
	committed = true
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(deletion.ErrUnavailable, err)
	}
	return nil
}

type networkDeletionDocument struct {
	NetworkID      string     `json:"network_id"`
	State          string     `json:"state"`
	RequestedAt    time.Time  `json:"requested_at"`
	DevicesTotal   int64      `json:"devices_total"`
	DevicesRevoked int64      `json:"devices_revoked"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
}

func (document networkDeletionDocument) progress() (deletion.Progress, error) {
	id, err := network.ParseID(document.NetworkID)
	if err != nil || id.String() != document.NetworkID ||
		(document.State == "deleting") != (document.CompletedAt == nil) ||
		(document.State != "deleting" && document.State != "deleted") {
		return deletion.Progress{}, deletion.ErrInvalid
	}
	progress := deletion.Progress{NetworkID: id, RequestedAt: document.RequestedAt.UTC(),
		DevicesTotal: document.DevicesTotal, DevicesRevoked: document.DevicesRevoked}
	if document.CompletedAt != nil {
		completed := document.CompletedAt.UTC()
		progress.CompletedAt = &completed
	}
	if !progress.IsValid() {
		return deletion.Progress{}, deletion.ErrInvalid
	}
	return progress, nil
}

type networkDeletionBlockerRow struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

type networkDeletionBlockers struct {
	Total              int64                       `json:"total"`
	TrustContracts     int64                       `json:"trust_contracts"`
	KubernetesClusters int64                       `json:"kubernetes_clusters"`
	KubernetesCAs      int64                       `json:"kubernetes_cas"`
	Items              []networkDeletionBlockerRow `json:"items"`
}

func (record networkDeletionBlockers) blockers() (deletion.Blockers, error) {
	items := make([]deletion.Blocker, 0, len(record.Items))
	for _, row := range record.Items {
		id, err := publicid.Parse(row.ID)
		if err != nil || id.String() != row.ID {
			return deletion.Blockers{}, deletion.ErrInvalid
		}
		items = append(items, deletion.Blocker{Kind: row.Kind, ID: id, Name: row.Name})
	}
	blockers := deletion.Blockers{Total: record.Total, TrustContracts: record.TrustContracts,
		KubernetesClusters: record.KubernetesClusters, KubernetesCAs: record.KubernetesCAs, Items: items}
	if !blockers.IsValid() {
		return deletion.Blockers{}, deletion.ErrInvalid
	}
	return blockers, nil
}

type deletedNetworkRow struct {
	NetworkID   string `json:"network_id"`
	DisplayName string `json:"display_name"`
	Version     int64  `json:"version"`
}

type networkDeletionRecord struct {
	Outcome     string                   `json:"outcome"`
	Network     *deletedNetworkRow       `json:"network,omitempty"`
	Deletion    *networkDeletionDocument `json:"deletion,omitempty"`
	Blockers    *networkDeletionBlockers `json:"blockers,omitempty"`
	KeysRevoked int                      `json:"keys_revoked"`
	Networks    []advancedNetworkRow     `json:"networks,omitempty"`
	Authority   *catalogAuthority        `json:"authority,omitempty"`
}

// decode checks the record names exactly this Network and the fields its
// outcome carries, and nothing else.
func (record networkDeletionRecord) decode(command deletion.Command) (deletion.Outcome, error) {
	switch record.Outcome {
	case deletion.OutcomeBlocked:
		if record.Blockers == nil || record.Network != nil || record.Deletion != nil || record.Networks != nil ||
			record.Authority != nil || record.KeysRevoked != 0 {
			return deletion.Outcome{}, deletion.ErrInvalid
		}
		blockers, err := record.Blockers.blockers()
		return deletion.Outcome{Kind: deletion.OutcomeBlocked, Blockers: blockers}, err
	case deletion.OutcomeDeleting:
		if record.Deletion == nil || record.Network != nil || record.Blockers != nil || record.Networks != nil ||
			record.Authority != nil || record.KeysRevoked != 0 {
			return deletion.Outcome{}, deletion.ErrInvalid
		}
		progress, err := record.Deletion.progress()
		return deletion.Outcome{Kind: deletion.OutcomeDeleting, Progress: progress}, err
	case deletion.OutcomeDeleted:
		if record.Deletion == nil || record.Network == nil || record.Blockers != nil || record.Authority == nil ||
			record.KeysRevoked < 0 || record.Network.NetworkID != command.Scope.NetworkID().String() ||
			record.Network.DisplayName == "" {
			return deletion.Outcome{}, deletion.ErrInvalid
		}
		progress, err := record.Deletion.progress()
		if err != nil {
			return deletion.Outcome{}, err
		}
		advanced, err := advancedNetworks(record.Networks)
		if err != nil || len(advanced) != 1 || advanced[0].NetworkID != command.Scope.NetworkID() {
			return deletion.Outcome{}, deletion.ErrInvalid
		}
		return deletion.Outcome{Kind: deletion.OutcomeDeleted, Progress: progress,
			Version: record.Network.Version, KeysRevoked: record.KeysRevoked}, nil
	}
	return deletion.Outcome{}, deletion.ErrInvalid
}

// Delete runs phase 1 and, when it deleted the Network, commits it with one
// network.deleted event. A refusal or a repeat changes nothing and commits
// nothing.
func (store *NetworkDeletionStore) Delete(ctx context.Context, command deletion.Command) (deletion.Outcome, error) {
	if !command.IsValid() {
		return deletion.Outcome{}, deletion.ErrInvalid
	}
	changeID, err := publicid.New()
	if err != nil {
		return deletion.Outcome{}, deletion.ErrUnavailable
	}
	scope := command.Scope
	var outcome deletion.Outcome
	err = store.transact(ctx, scope, func(tx accountSessionTransaction, now time.Time) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, deleteNetworkSQL, append(sessionQueryArguments(command.Session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), command.ExpectedVersion, command.Reason,
			changeID.String(), now)...).Scan(&encoded); err != nil {
			return false, networkDeletionDatabaseError(err)
		}
		var record networkDeletionRecord
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil {
			return false, deletion.ErrInvalid
		}
		decoded, err := record.decode(command)
		if err != nil {
			return false, err
		}
		outcome = decoded
		if decoded.Kind != deletion.OutcomeDeleted {
			return false, nil
		}
		advanced, err := advancedNetworks(record.Networks)
		if err != nil {
			return false, deletion.ErrInvalid
		}
		event, err := networkDeletedEvent(command, changeID, decoded, record.Network.DisplayName,
			advanced[0].NetworkRevision, advanced[0].GroupRevision, *record.Authority)
		if err != nil {
			return false, deletion.ErrInvalid
		}
		if err := appendNetworkMemberEvent(ctx, tx, event); err != nil {
			return false, errors.Join(deletion.ErrUnavailable, err)
		}
		return true, nil
	})
	if err != nil {
		return deletion.Outcome{}, err
	}
	return outcome, nil
}

func networkDeletedEvent(command deletion.Command, changeID publicid.ID, outcome deletion.Outcome,
	displayName string, networkRevision, groupRevision int64, authority catalogAuthority) (catalogEvent, error) {
	networkID := command.Scope.NetworkID()
	state := func(value string, version int64) ([32]byte, error) {
		encoded, err := json.Marshal(struct {
			NetworkID string `json:"network_id"`
			State     string `json:"state"`
			Version   int64  `json:"version"`
		}{networkID.String(), value, version})
		return sha256.Sum256(encoded), err
	}
	before, err := state(deletion.StateActive, command.ExpectedVersion)
	if err != nil {
		return catalogEvent{}, err
	}
	after, err := state("deleted", outcome.Version)
	if err != nil {
		return catalogEvent{}, err
	}
	return catalogEvent{
		session: command.Session, correlationID: command.CorrelationID, changeID: changeID,
		aggregateKind: "network", aggregateID: publicid.ID(networkID), version: outcome.Version,
		networkVersion: networkRevision, action: "network.deleted", permission: networkDeletePermission,
		before: &before, after: after,
		payload: struct {
			NetworkID   string           `json:"network_id"`
			DisplayName string           `json:"display_name"`
			SessionID   string           `json:"session_id"`
			Reason      string           `json:"reason"`
			Devices     int64            `json:"devices"`
			KeysRevoked int              `json:"enrollment_keys_revoked"`
			Authority   catalogAuthority `json:"authority"`
		}{networkID.String(), displayName, command.Session.ID().String(), command.Reason,
			outcome.Progress.DevicesTotal, outcome.KeysRevoked, authority},
		// The Network is gone: wake its map sessions so control closes them.
		outboxClass: "network.revision.advanced",
		outbox: struct {
			NetworkID       string `json:"network_id"`
			Aggregate       string `json:"aggregate_kind"`
			AggregateID     string `json:"aggregate_id"`
			NetworkRevision int64  `json:"network_revision"`
			GroupRevision   int64  `json:"group_revision"`
		}{networkID.String(), "network", networkID.String(), networkRevision, groupRevision},
	}, nil
}

type networkViewRecord struct {
	NetworkID   string                   `json:"network_id"`
	DisplayName string                   `json:"display_name"`
	DisplayCode string                   `json:"display_code,omitempty"`
	State       string                   `json:"state"`
	Version     int64                    `json:"version"`
	CreatedAt   time.Time                `json:"created_at"`
	Deletion    *networkDeletionDocument `json:"deletion,omitempty"`
}

// Read reads one Network, or how far its deletion is, in a transaction that
// changes nothing.
func (store *NetworkDeletionStore) Read(ctx context.Context, session accountsession.Session,
	scope network.Scope) (deletion.View, error) {
	if !session.IsValid() || !scope.IsValid() {
		return deletion.View{}, deletion.ErrInvalid
	}
	var view deletion.View
	err := store.transact(ctx, scope, func(tx accountSessionTransaction, now time.Time) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, readNetworkSQL, append(sessionQueryArguments(session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), now)...).Scan(&encoded); err != nil {
			return false, networkDeletionDatabaseError(err)
		}
		var record networkViewRecord
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil {
			return false, deletion.ErrInvalid
		}
		id, err := network.ParseID(record.NetworkID)
		if err != nil || id.String() != record.NetworkID {
			return false, deletion.ErrInvalid
		}
		view = deletion.View{NetworkID: id, DisplayName: record.DisplayName, DisplayCode: record.DisplayCode,
			State: record.State, Version: record.Version, CreatedAt: record.CreatedAt.UTC()}
		if record.Deletion != nil {
			progress, err := record.Deletion.progress()
			if err != nil {
				return false, err
			}
			view.Deletion = &progress
		}
		return false, nil
	})
	if err != nil {
		return deletion.View{}, err
	}
	return view, nil
}
