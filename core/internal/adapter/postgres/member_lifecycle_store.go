package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/identitygroup"
	"meshtransit.net/core/internal/domain/memberlifecycle"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

const revokeWorkspaceMemberSessionsSQL = `SELECT mesh_ops.revoke_workspace_member_sessions_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::TIMESTAMPTZ)::TEXT`

const changeWorkspaceMemberSQL = `SELECT mesh_ops.change_workspace_member_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::TEXT,$13::UUID,$14::TIMESTAMPTZ)::TEXT`

// MemberLifecycleStore suspends and resumes Workspace members through the
// runtime pool. Each change is recorded on the Workspace stream and, with its
// revision wakeup, on the stream of every Network whose Devices it changed.
type MemberLifecycleStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

var _ memberlifecycle.Store = (*MemberLifecycleStore)(nil)

// NewMemberLifecycleStore uses the runtime pool.
func NewMemberLifecycleStore(pool *Pool, options AccountSessionOptions) (*MemberLifecycleStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, memberlifecycle.ErrInvalid
	}
	return &MemberLifecycleStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

// transact runs one transaction and commits only when run asks; the SQL entry
// point enters the Workspace scope itself. run receives the transaction's
// time on the database clock, which every time it passes to SQL uses.
func (store *MemberLifecycleStore) transact(ctx context.Context,
	run func(tx accountSessionTransaction, now time.Time) (bool, error)) (resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) {
		return memberlifecycle.ErrInvalid
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return errors.Join(memberlifecycle.ErrUnavailable, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
		}
	}()
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return errors.Join(memberlifecycle.ErrUnavailable, err)
	}
	now, err := readTransactionTime(ctx, tx.QueryRow)
	if err != nil {
		return errors.Join(memberlifecycle.ErrUnavailable, err)
	}
	commit, err := run(tx, now)
	if err != nil || !commit {
		return err
	}
	committed = true
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(memberlifecycle.ErrUnavailable, err)
	}
	return nil
}

func memberLifecycleDatabaseError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "42501", "23503":
			return memberlifecycle.ErrForbidden
		case "P0002":
			return memberlifecycle.ErrNotFound
		case "MTM01":
			return memberlifecycle.ErrWrongState
		case "MTM02":
			return memberlifecycle.ErrProtected
		case "MTM03":
			return memberlifecycle.ErrPlan
		case "MTM04":
			return memberlifecycle.ErrNewOwner
		case "22023", "22P02", "23514":
			return memberlifecycle.ErrInvalid
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return memberlifecycle.ErrForbidden
	}
	return errors.Join(memberlifecycle.ErrUnavailable, err)
}

type memberLifecycleDocument struct {
	PrincipalID string     `json:"principal_id"`
	State       string     `json:"state"`
	ExpiresAt   *time.Time `json:"expires_at"`
	Version     int64      `json:"version"`
}

func (document memberLifecycleDocument) member() (memberlifecycle.Member, error) {
	principal, err := publicid.Parse(document.PrincipalID)
	if err != nil || document.Version < 1 ||
		(document.State != "active" && document.State != "suspended" && document.State != "revoked") {
		return memberlifecycle.Member{}, memberlifecycle.ErrInvalid
	}
	return memberlifecycle.Member{
		PrincipalID: principal, State: document.State, ExpiresAt: document.ExpiresAt, Version: document.Version,
	}, nil
}

type memberChangedDeviceRow struct {
	DeviceID  string `json:"device_id"`
	NetworkID string `json:"network_id"`
	Hostname  string `json:"hostname"`
	State     string `json:"state"`
}

type memberLifecycleRecord struct {
	Before        memberLifecycleDocument  `json:"before"`
	After         memberLifecycleDocument  `json:"after"`
	Devices       []memberChangedDeviceRow `json:"devices"`
	SessionsEnded *int                     `json:"sessions_ended"`
	Networks      []advancedNetworkRow     `json:"networks"`
	Authority     catalogAuthority         `json:"authority"`
}

// decode validates the record and returns the result.
func (record memberLifecycleRecord) decode(change memberlifecycle.Change) (memberlifecycle.Result, error) {
	before, err := record.Before.member()
	if err != nil {
		return memberlifecycle.Result{}, err
	}
	after, err := record.After.member()
	if err != nil || before.PrincipalID != change.MemberID || after.PrincipalID != change.MemberID ||
		after.Version != before.Version+1 || record.SessionsEnded == nil || *record.SessionsEnded < 0 ||
		record.Devices == nil || record.Networks == nil {
		return memberlifecycle.Result{}, memberlifecycle.ErrInvalid
	}
	wantState := map[memberlifecycle.Action]string{
		memberlifecycle.ActionSuspend: "suspended", memberlifecycle.ActionResume: "active",
	}[change.Action]
	if after.State != wantState {
		return memberlifecycle.Result{}, memberlifecycle.ErrInvalid
	}
	devices := make([]memberlifecycle.ChangedDevice, 0, len(record.Devices))
	touched := map[network.ID]bool{}
	for _, row := range record.Devices {
		device, deviceErr := node.ParseID(row.DeviceID)
		networkID, networkErr := network.ParseID(row.NetworkID)
		if deviceErr != nil || networkErr != nil || row.State != wantState {
			return memberlifecycle.Result{}, memberlifecycle.ErrInvalid
		}
		touched[networkID] = true
		devices = append(devices, memberlifecycle.ChangedDevice{
			DeviceID: device, NetworkID: networkID, Hostname: row.Hostname, State: row.State,
		})
	}
	advanced, err := advancedNetworks(record.Networks)
	if err != nil || len(advanced) != len(touched) {
		return memberlifecycle.Result{}, memberlifecycle.ErrInvalid
	}
	networks := make([]memberlifecycle.AdvancedNetwork, 0, len(advanced))
	for _, row := range advanced {
		if !touched[row.NetworkID] {
			return memberlifecycle.Result{}, memberlifecycle.ErrInvalid
		}
		networks = append(networks, memberlifecycle.AdvancedNetwork{
			NetworkID: row.NetworkID, NetworkRevision: row.NetworkRevision, GroupRevision: row.GroupRevision,
		})
	}
	return memberlifecycle.Result{
		Before: before, After: after, Devices: devices, SessionsEnded: *record.SessionsEnded, Networks: networks,
	}, nil
}

// identityAdvancedNetworks adapts the advanced Networks to the shared wakeup
// writer.
func identityAdvancedNetworks(networks []memberlifecycle.AdvancedNetwork) []identitygroup.AdvancedNetwork {
	converted := make([]identitygroup.AdvancedNetwork, len(networks))
	for index, advanced := range networks {
		converted[index] = identitygroup.AdvancedNetwork{
			NetworkID: advanced.NetworkID, NetworkRevision: advanced.NetworkRevision,
			GroupRevision: advanced.GroupRevision,
		}
	}
	return converted
}

func memberSemanticHash(member memberlifecycle.Member) ([32]byte, error) {
	encoded, err := json.Marshal(struct {
		PrincipalID string     `json:"principal_id"`
		State       string     `json:"state"`
		ExpiresAt   *time.Time `json:"expires_at"`
	}{member.PrincipalID.String(), member.State, member.ExpiresAt})
	return sha256.Sum256(encoded), err
}

// memberLifecycleAction is the audit action of each change.
var memberLifecycleAction = map[memberlifecycle.Action]string{
	memberlifecycle.ActionSuspend: "member.suspended",
	memberlifecycle.ActionResume:  "member.reactivated",
	// Revoking sessions travels through RevokeSessions.
	memberlifecycle.ActionRevokeSessions: "member.sessions_revoked",
}

// Change authorizes member.manage, applies the change and commits it with its
// evidence.
func (store *MemberLifecycleStore) Change(ctx context.Context, change memberlifecycle.Change) (
	memberlifecycle.Result, error) {
	if !change.IsValid() {
		return memberlifecycle.Result{}, memberlifecycle.ErrInvalid
	}
	if change.Action == memberlifecycle.ActionRevokeSessions {
		return store.revokeSessions(ctx, change)
	}
	changeID, err := publicid.New()
	if err != nil {
		return memberlifecycle.Result{}, memberlifecycle.ErrUnavailable
	}
	var result memberlifecycle.Result
	err = store.transact(ctx, func(tx accountSessionTransaction, now time.Time) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, changeWorkspaceMemberSQL, append(sessionQueryArguments(change.Session),
			change.WorkspaceID.String(), change.MemberID.String(), string(change.Action), changeID.String(),
			now)...).Scan(&encoded); err != nil {
			return false, memberLifecycleDatabaseError(err)
		}
		var record memberLifecycleRecord
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil {
			return false, memberlifecycle.ErrInvalid
		}
		decoded, err := record.decode(change)
		if err != nil {
			return false, err
		}
		result = decoded
		beforeHash, err := memberSemanticHash(result.Before)
		if err != nil {
			return false, err
		}
		afterHash, err := memberSemanticHash(result.After)
		if err != nil {
			return false, err
		}
		deviceIDs := make([]string, len(result.Devices))
		for index, device := range result.Devices {
			deviceIDs[index] = device.DeviceID.String()
		}
		reason := struct {
			MemberID      string   `json:"member_principal_id"`
			Action        string   `json:"action"`
			Reason        string   `json:"reason"`
			Devices       []string `json:"device_ids"`
			SessionsEnded int      `json:"sessions_ended"`
		}{change.MemberID.String(), string(change.Action), change.Reason, deviceIDs, result.SessionsEnded}
		event := catalogEvent{
			session: change.Session, correlationID: change.CorrelationID, changeID: changeID,
			aggregateKind: "workspace_membership", aggregateID: change.MemberID, version: result.After.Version,
			action: memberLifecycleAction[change.Action], permission: "member.manage",
			before: &beforeHash, after: afterHash,
			payload: struct {
				WorkspaceID string           `json:"workspace_id"`
				SessionID   string           `json:"session_id"`
				Change      any              `json:"change"`
				Authority   catalogAuthority `json:"authority"`
			}{change.WorkspaceID.String(), change.Session.ID().String(), reason, record.Authority},
			outboxClass: memberLifecycleAction[change.Action],
			outbox: struct {
				WorkspaceID string `json:"workspace_id"`
				MemberID    string `json:"member_principal_id"`
				Version     int64  `json:"version"`
			}{change.WorkspaceID.String(), change.MemberID.String(), result.After.Version},
		}
		if err := appendWorkspaceCatalogEvent(ctx, tx, change.WorkspaceID, event); err != nil {
			return false, errors.Join(memberlifecycle.ErrUnavailable, err)
		}
		if err := appendNetworkWakeEvents(ctx, tx, identityAdvancedNetworks(result.Networks), event, reason); err != nil {
			return false, errors.Join(memberlifecycle.ErrUnavailable, err)
		}
		return true, nil
	})
	if err != nil {
		return memberlifecycle.Result{}, err
	}
	return result, nil
}

type memberSessionsRecord struct {
	Member        memberLifecycleDocument `json:"member"`
	SessionsEnded *int                    `json:"sessions_ended"`
	Authority     catalogAuthority        `json:"authority"`
}

// revokeSessions authorizes member.manage, ends the member's sessions signed
// in to the Workspace and records it on the Workspace stream. The membership
// itself is unchanged, so the result's member is the same before and after.
// Ending no session changes nothing and records nothing.
func (store *MemberLifecycleStore) revokeSessions(ctx context.Context, change memberlifecycle.Change) (
	memberlifecycle.Result, error) {
	changeID, err := publicid.New()
	if err != nil {
		return memberlifecycle.Result{}, memberlifecycle.ErrUnavailable
	}
	var result memberlifecycle.Result
	err = store.transact(ctx, func(tx accountSessionTransaction, now time.Time) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, revokeWorkspaceMemberSessionsSQL, append(sessionQueryArguments(change.Session),
			change.WorkspaceID.String(), change.MemberID.String(), changeID.String(),
			now)...).Scan(&encoded); err != nil {
			return false, memberLifecycleDatabaseError(err)
		}
		var record memberSessionsRecord
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil {
			return false, memberlifecycle.ErrInvalid
		}
		member, err := record.Member.member()
		if err != nil || member.PrincipalID != change.MemberID || member.State != "active" ||
			record.SessionsEnded == nil || *record.SessionsEnded < 0 {
			return false, memberlifecycle.ErrInvalid
		}
		result = memberlifecycle.Result{
			Before: member, After: member, Devices: []memberlifecycle.ChangedDevice{},
			SessionsEnded: *record.SessionsEnded, Networks: []memberlifecycle.AdvancedNetwork{},
		}
		// No session ended, so nothing changed and there is nothing to record.
		if result.SessionsEnded == 0 {
			return true, nil
		}
		hash, err := memberSemanticHash(member)
		if err != nil {
			return false, err
		}
		action := memberLifecycleAction[change.Action]
		event := catalogEvent{
			session: change.Session, correlationID: change.CorrelationID, changeID: changeID,
			aggregateKind: "workspace_membership", aggregateID: change.MemberID, version: member.Version,
			action: action, permission: "member.manage", before: &hash, after: hash,
			payload: struct {
				WorkspaceID string           `json:"workspace_id"`
				SessionID   string           `json:"session_id"`
				Change      any              `json:"change"`
				Authority   catalogAuthority `json:"authority"`
			}{change.WorkspaceID.String(), change.Session.ID().String(), struct {
				MemberID      string `json:"member_principal_id"`
				Action        string `json:"action"`
				Reason        string `json:"reason"`
				SessionsEnded int    `json:"sessions_ended"`
			}{change.MemberID.String(), string(change.Action), change.Reason, result.SessionsEnded}, record.Authority},
			outboxClass: action,
			outbox: struct {
				WorkspaceID   string `json:"workspace_id"`
				MemberID      string `json:"member_principal_id"`
				SessionsEnded int    `json:"sessions_ended"`
			}{change.WorkspaceID.String(), change.MemberID.String(), result.SessionsEnded},
		}
		if err := appendWorkspaceCatalogEvent(ctx, tx, change.WorkspaceID, event); err != nil {
			return false, errors.Join(memberlifecycle.ErrUnavailable, err)
		}
		return true, nil
	})
	if err != nil {
		return memberlifecycle.Result{}, err
	}
	return result, nil
}
