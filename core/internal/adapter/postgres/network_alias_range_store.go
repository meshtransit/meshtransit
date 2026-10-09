package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/authorization"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/network/aliasrange"
	"meshtransit.net/core/internal/domain/publicid"
)

const maximumAliasRangeStateBytes = 8192

const readNetworkAliasRangesSQL = `SELECT mesh_ops.read_network_alias_ranges_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::TIMESTAMPTZ)::TEXT`

const setNetworkAliasRangesSQL = `SELECT mesh_ops.set_network_alias_ranges_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::BIGINT,$13::BOOLEAN,NULLIF($14::TEXT,'')::CIDR,$15::UUID,
 $16::BOOLEAN,NULLIF($17::TEXT,'')::CIDR,$18::UUID,$19::UUID,$20::TIMESTAMPTZ)::TEXT`

const appendNetworkAliasRangeEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
 $1::BIGINT,$2::UUID,$3::UUID,$4::BIGINT,$5::BYTEA,$6::BYTEA,
 'network',$7::UUID,$8::BIGINT,$15::BIGINT,$9::UUID,'network.alias_range.updated','network.update',
 $10::UUID,$11::BYTEA,$12::BYTEA,$13::JSONB,'network.alias_range.updated',$14::JSONB)`

// NetworkAliasRangeStore reads and commits receiving-Network alias ranges
// through the runtime pool. Each call is one short exact-Network transaction.
type NetworkAliasRangeStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

var _ aliasrange.Store = (*NetworkAliasRangeStore)(nil)

// NewNetworkAliasRangeStore uses the runtime pool.
func NewNetworkAliasRangeStore(pool *Pool, options AccountSessionOptions) (*NetworkAliasRangeStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, aliasrange.ErrInvalid
	}
	return &NetworkAliasRangeStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

func networkAliasRangeError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "42501":
			return aliasrange.ErrForbidden
		case "MTR01":
			return aliasrange.ErrOutsideFrame
		case "MTR02":
			return aliasrange.ErrInUse
		case "MTR03":
			return aliasrange.ErrVersionConflict
		case "22023", "22P02":
			return aliasrange.ErrInvalid
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return aliasrange.ErrForbidden
	}
	return errors.Join(aliasrange.ErrUnavailable, err)
}

func (store *NetworkAliasRangeStore) begin(ctx context.Context, scope network.Scope) (accountSessionTransaction, error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) {
		return nil, aliasrange.ErrInvalid
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return nil, errors.Join(aliasrange.ErrUnavailable, err)
	}
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return tx, errors.Join(aliasrange.ErrUnavailable, err)
	}
	var workspaceInternal, networkInternal int64
	if err := tx.QueryRow(ctx, setResourceAuthorityScopeSQL, scope.WorkspaceID().String(),
		scope.NetworkID().String()).Scan(&workspaceInternal, &networkInternal); err != nil {
		return tx, networkAliasRangeError(err)
	}
	if workspaceInternal <= 0 || networkInternal <= 0 {
		return tx, aliasrange.ErrForbidden
	}
	return tx, nil
}

// Read authorizes network.read and returns the frame, ranges and usage.
func (store *NetworkAliasRangeStore) Read(ctx context.Context, session accountsession.Session, scope network.Scope,
	evaluatedAt time.Time) (_ aliasrange.State, resultErr error) {
	if !session.IsValid() || !scope.IsValid() || evaluatedAt.IsZero() {
		return aliasrange.State{}, aliasrange.ErrInvalid
	}
	tx, err := store.begin(ctx, scope)
	if tx != nil {
		defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	}
	if err != nil {
		return aliasrange.State{}, err
	}
	args := append(sessionQueryArguments(session), scope.WorkspaceID().String(), scope.NetworkID().String(), evaluatedAt)
	var encoded string
	if err := tx.QueryRow(ctx, readNetworkAliasRangesSQL, args...).Scan(&encoded); err != nil {
		return aliasrange.State{}, networkAliasRangeError(err)
	}
	return decodeNetworkAliasRangeState([]byte(encoded))
}

type aliasRangeStateRecord struct {
	Version  *int64 `json:"version"`
	Families []struct {
		Family   int     `json:"family"`
		Frame    *string `json:"frame"`
		Prefix   *string `json:"prefix"`
		Retained int64   `json:"retained"`
	} `json:"families"`
	LiveShares *int64 `json:"live_shares"`
	ShareLimit *int64 `json:"share_limit"`
}

func optionalPrefix(value *string) (netip.Prefix, bool) {
	if value == nil {
		return netip.Prefix{}, true
	}
	prefix, err := netip.ParsePrefix(*value)
	return prefix, err == nil
}

func decodeNetworkAliasRangeState(encoded []byte) (aliasrange.State, error) {
	if len(encoded) == 0 || len(encoded) > maximumAliasRangeStateBytes {
		return aliasrange.State{}, aliasrange.ErrInvalid
	}
	var record aliasRangeStateRecord
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || record.Version == nil || record.LiveShares == nil ||
		record.ShareLimit == nil || len(record.Families) != 2 {
		return aliasrange.State{}, aliasrange.ErrInvalid
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return aliasrange.State{}, aliasrange.ErrInvalid
	}
	state := aliasrange.State{Version: *record.Version, LiveShares: *record.LiveShares, ShareLimit: *record.ShareLimit}
	for index, item := range record.Families {
		frame, frameOK := optionalPrefix(item.Frame)
		prefix, prefixOK := optionalPrefix(item.Prefix)
		if !frameOK || !prefixOK || item.Family != 4+2*index {
			return aliasrange.State{}, aliasrange.ErrInvalid
		}
		family := aliasrange.Family{Family: item.Family, Frame: frame, Prefix: prefix, Retained: item.Retained}
		if index == 0 {
			state.IPv4 = family
		} else {
			state.IPv6 = family
		}
	}
	if !state.IsValid() {
		return aliasrange.State{}, aliasrange.ErrInvalid
	}
	return state, nil
}

type aliasRangeUpdateRecord struct {
	Changed         *bool           `json:"changed"`
	RoleBindingID   *string         `json:"role_binding_id"`
	NetworkRevision *int64          `json:"network_revision"`
	Before          json.RawMessage `json:"before"`
	After           json.RawMessage `json:"after"`
}

func prefixArgument(change aliasrange.Change) string {
	if change.Prefix == (netip.Prefix{}) {
		return ""
	}
	return change.Prefix.String()
}

// Update authorizes network.update, applies the requested ranges and, when
// anything changed, appends one audit and outbox record on the Network
// stream. An uncertain commit returns no success and is not retried.
func (store *NetworkAliasRangeStore) Update(ctx context.Context, command aliasrange.Command,
	evaluatedAt time.Time) (_ aliasrange.Result, resultErr error) {
	if !command.IsValid() || evaluatedAt.IsZero() {
		return aliasrange.Result{}, aliasrange.ErrInvalid
	}
	var ids [5]publicid.ID
	for index := range ids {
		id, err := publicid.New()
		if err != nil {
			return aliasrange.Result{}, aliasrange.ErrUnavailable
		}
		ids[index] = id
	}
	change, ipv4Row, ipv6Row, event, outbox := ids[0], ids[1], ids[2], ids[3], ids[4]
	tx, err := store.begin(ctx, command.Scope)
	committed := false
	if tx != nil {
		defer func() {
			if !committed {
				resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
			}
		}()
	}
	if err != nil {
		return aliasrange.Result{}, err
	}
	args := append(sessionQueryArguments(command.Session), command.Scope.WorkspaceID().String(),
		command.Scope.NetworkID().String(), command.ExpectedVersion,
		command.IPv4.Present, prefixArgument(command.IPv4), ipv4Row.String(),
		command.IPv6.Present, prefixArgument(command.IPv6), ipv6Row.String(),
		change.String(), evaluatedAt)
	var encoded string
	if err := tx.QueryRow(ctx, setNetworkAliasRangesSQL, args...).Scan(&encoded); err != nil {
		return aliasrange.Result{}, networkAliasRangeError(err)
	}
	if len(encoded) > 4*maximumAliasRangeStateBytes {
		return aliasrange.Result{}, aliasrange.ErrInvalid
	}
	var record aliasRangeUpdateRecord
	decoder := json.NewDecoder(bytes.NewReader([]byte(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || record.Changed == nil || record.NetworkRevision == nil ||
		*record.NetworkRevision <= 0 {
		return aliasrange.Result{}, aliasrange.ErrInvalid
	}
	before, err := decodeNetworkAliasRangeState(record.Before)
	if err != nil {
		return aliasrange.Result{}, err
	}
	after, err := decodeNetworkAliasRangeState(record.After)
	if err != nil {
		return aliasrange.Result{}, err
	}
	if before.Version != command.ExpectedVersion || *record.Changed != (after.Version > before.Version) {
		return aliasrange.Result{}, aliasrange.ErrInvalid
	}
	if *record.Changed {
		binding := ""
		if record.RoleBindingID != nil {
			binding = *record.RoleBindingID
		}
		if err := appendNetworkAliasRangeEvidence(ctx, tx, command, aliasRangeEvidence{
			before: before, after: after, binding: binding, networkRevision: *record.NetworkRevision,
		}, change, event, outbox); err != nil {
			return aliasrange.Result{}, errors.Join(aliasrange.ErrUnavailable, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		committed = true
		return aliasrange.Result{}, errors.Join(aliasrange.ErrUnavailable, err)
	}
	committed = true
	return aliasrange.Result{State: after, Changed: *record.Changed}, nil
}

func aliasRangeSemanticHash(networkID string, state aliasrange.State) ([32]byte, error) {
	encoded, err := json.Marshal(struct {
		NetworkID  string `json:"network_id"`
		Version    int64  `json:"version"`
		IPv4Prefix string `json:"ipv4_prefix"`
		IPv6Prefix string `json:"ipv6_prefix"`
	}{networkID, state.Version, prefixText(state.IPv4.Prefix), prefixText(state.IPv6.Prefix)})
	return sha256.Sum256(encoded), err
}

func prefixText(prefix netip.Prefix) string {
	if prefix == (netip.Prefix{}) {
		return ""
	}
	return prefix.String()
}

type aliasRangeEvidence struct {
	before, after   aliasrange.State
	binding         string
	networkRevision int64
}

func appendNetworkAliasRangeEvidence(ctx context.Context, tx accountSessionTransaction, command aliasrange.Command,
	evidence aliasRangeEvidence, change, event, outbox publicid.ID) error {
	before, after, binding := evidence.before, evidence.after, evidence.binding
	var streamID, sequence int64
	var previous []byte
	if err := tx.QueryRow(ctx, `SELECT stream_internal_id,next_sequence,latest_event_hash
FROM mesh_audit.lock_network_stream_head()`).Scan(&streamID, &sequence, &previous); err != nil {
		return err
	}
	if streamID <= 0 || sequence <= 0 || len(previous) != sha256.Size {
		return aliasrange.ErrInvalid
	}
	networkID := command.Scope.NetworkID().String()
	beforeHash, err := aliasRangeSemanticHash(networkID, before)
	if err != nil {
		return err
	}
	afterHash, err := aliasRangeSemanticHash(networkID, after)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(struct {
		NetworkID      string `json:"network_id"`
		SessionID      string `json:"session_id"`
		RoleBindingID  string `json:"role_binding_id,omitempty"`
		BeforeIPv4     string `json:"before_ipv4_prefix"`
		BeforeIPv6     string `json:"before_ipv6_prefix"`
		AfterIPv4      string `json:"ipv4_prefix"`
		AfterIPv6      string `json:"ipv6_prefix"`
		RetainedAtTime int64  `json:"retained_aliases"`
	}{networkID, command.Session.ID().String(), binding, prefixText(before.IPv4.Prefix), prefixText(before.IPv6.Prefix),
		prefixText(after.IPv4.Prefix), prefixText(after.IPv6.Prefix), after.IPv4.Retained + after.IPv6.Retained})
	if err != nil {
		return err
	}
	outboxPayload, err := json.Marshal(struct {
		NetworkID string `json:"network_id"`
		Version   int64  `json:"version"`
	}{networkID, after.Version})
	if err != nil {
		return err
	}
	var previousHash [32]byte
	copy(previousHash[:], previous)
	principal := publicid.ID(command.Session.PrincipalID())
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previousHash, EventID: event, ChangeID: change,
		AggregateKind: "network", AggregateID: publicid.ID(command.Scope.NetworkID()), AggregateVersion: after.Version,
		NetworkRevision: evidence.networkRevision, ActorPrincipalID: principal, Action: "network.alias_range.updated",
		Permission: string(authorization.PermissionNetworkUpdate), CorrelationID: command.CorrelationID,
		BeforeSemanticHash: beforeHash, AfterSemanticHash: afterHash, AuditPayloadHash: sha256.Sum256(payload),
		OutboxEventClass: "network.alias_range.updated", OutboxPayloadHash: sha256.Sum256(outboxPayload),
	})
	if err != nil {
		return err
	}
	var appended int64
	if err := tx.QueryRow(ctx, appendNetworkAliasRangeEvidenceSQL, streamID, event.String(), outbox.String(), sequence,
		previousHash[:], eventHash[:], networkID, after.Version, principal.String(), command.CorrelationID.String(),
		beforeHash[:], afterHash[:], payload, outboxPayload, evidence.networkRevision).Scan(&appended); err != nil {
		return err
	}
	if appended != sequence {
		return aliasrange.ErrInvalid
	}
	return nil
}
