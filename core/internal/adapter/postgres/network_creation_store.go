package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/authorization"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/network/provisioning"
	"meshtransit.net/core/internal/domain/publicid"
)

const createNetworkSQL = `SELECT network_public_id::TEXT, network_display_code, network_version, network_created_at,
 network_ipv4_prefix::TEXT, COALESCE(network_ipv6_prefix::TEXT,''),
 replayed, COALESCE(actor_binding_public_id::TEXT,''), COALESCE(actor_role_public_id::TEXT,''),
 actor_binding_generation, actor_membership_generation, actor_owner_generation
FROM mesh_ops.create_network_v2(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::TEXT,$13::CIDR,NULLIF($14::TEXT,'')::CIDR,$15::UUID,$16::UUID,$17::UUID,$18::UUID,$19::UUID)`

const appendNetworkCreationEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
 $1::BIGINT,$2::UUID,$3::UUID,$4::BIGINT,$5::BYTEA,$6::BYTEA,
 'network',$7::UUID,1,1,$8::UUID,'network.created','network.create',
 $9::UUID,NULL::BYTEA,$10::BYTEA,$11::JSONB,'network.created',$11::JSONB)`

// NetworkCreationStore commits Network creation inside a Workspace.
type NetworkCreationStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

// NewNetworkCreationStore uses the runtime pool.
func NewNetworkCreationStore(pool *Pool, options AccountSessionOptions) (*NetworkCreationStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, provisioning.ErrInvalid
	}
	return &NetworkCreationStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

func networkCreationError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "42501":
			return provisioning.ErrForbidden
		case "23P01":
			return provisioning.ErrPrefixOverlap
		case "23505":
			return errors.Join(provisioning.ErrConflict, err)
		case "MTN01":
			return provisioning.ErrPrefixOutsidePool
		case "22023":
			return provisioning.ErrInvalid
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return provisioning.ErrForbidden
	}
	return errors.Join(provisioning.ErrUnavailable, err)
}

// Create runs create_network_v2 and appends one audit/outbox record on the
// new Network stream. A replay appends nothing. An omitted IPv6 prefix is
// assigned by PostgreSQL and returned in the result.
func (store *NetworkCreationStore) Create(ctx context.Context, command provisioning.Command) (_ provisioning.Result, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !command.IsValid() {
		return provisioning.Result{}, provisioning.ErrInvalid
	}
	var ids [7]publicid.ID
	for index := range ids {
		id, err := publicid.New()
		if err != nil {
			return provisioning.Result{}, provisioning.ErrUnavailable
		}
		ids[index] = id
	}
	change, event, outbox := ids[0], ids[1], ids[2]
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return provisioning.Result{}, provisioning.ErrUnavailable
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
		}
	}()
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return provisioning.Result{}, errors.Join(provisioning.ErrUnavailable, err)
	}
	requestedIPv6 := ""
	if command.IPv6Prefix.IsValid() {
		requestedIPv6 = command.IPv6Prefix.String()
	}
	args := append(sessionQueryArguments(command.Session), command.WorkspaceID.String(), command.NetworkID.String(),
		command.DisplayName, command.IPv4Prefix.String(), requestedIPv6, ids[3].String(),
		ids[4].String(), ids[5].String(), ids[6].String(), change.String())
	var networkID, displayCode, ipv4Text, ipv6Text string
	var version int64
	var createdAt time.Time
	var replayed bool
	var actor workspaceRoleActorEvidence
	if err := tx.QueryRow(ctx, createNetworkSQL, args...).Scan(&networkID, &displayCode, &version, &createdAt,
		&ipv4Text, &ipv6Text, &replayed, &actor.BindingID, &actor.RoleID, &actor.BindingGeneration,
		&actor.MembershipGeneration, &actor.OwnerGeneration); err != nil {
		return provisioning.Result{}, networkCreationError(err)
	}
	code, err := identity.ParseDisplayCode(displayCode)
	ipv4, ipv4Err := netip.ParsePrefix(ipv4Text)
	ipv6, ipv6Err := netip.ParsePrefix(ipv6Text)
	if errors.Join(err, ipv4Err, ipv6Err) != nil || networkID != command.NetworkID.String() || version <= 0 ||
		!actor.isValid() || ipv4 != command.IPv4Prefix || !provisioning.ValidIPv6Prefix(ipv6) {
		return provisioning.Result{}, provisioning.ErrInvalid
	}
	if !replayed {
		if err := appendNetworkCreationEvidence(ctx, tx, command, ipv6, change, event, outbox, code, actor); err != nil {
			return provisioning.Result{}, errors.Join(provisioning.ErrUnavailable, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		committed = true
		return provisioning.Result{}, errors.Join(provisioning.ErrUnavailable, err)
	}
	committed = true
	return provisioning.Result{NetworkID: command.NetworkID, DisplayCode: code, IPv4Prefix: ipv4, IPv6Prefix: ipv6,
		Version: version, CreatedAt: createdAt.UTC(), Replayed: replayed}, nil
}

func appendNetworkCreationEvidence(ctx context.Context, tx accountSessionTransaction, command provisioning.Command,
	ipv6 netip.Prefix, change, event, outbox publicid.ID, code identity.DisplayCode, actor workspaceRoleActorEvidence) error {
	var streamID, sequence int64
	var previous []byte
	if err := tx.QueryRow(ctx, `SELECT stream_internal_id,next_sequence,latest_event_hash
FROM mesh_audit.lock_network_stream_head()`).Scan(&streamID, &sequence, &previous); err != nil {
		return err
	}
	if streamID <= 0 || sequence != 1 || len(previous) != sha256.Size {
		return provisioning.ErrInvalid
	}
	payload, err := json.Marshal(struct {
		WorkspaceID string                     `json:"workspace_id"`
		NetworkID   string                     `json:"network_id"`
		DisplayCode string                     `json:"display_code"`
		IPv4Prefix  string                     `json:"ipv4_prefix"`
		IPv6Prefix  string                     `json:"ipv6_prefix"`
		SessionID   string                     `json:"session_id"`
		Authority   workspaceRoleActorEvidence `json:"authority"`
	}{command.WorkspaceID.String(), command.NetworkID.String(), code.String(), command.IPv4Prefix.String(),
		ipv6.String(), command.Session.ID().String(), actor})
	if err != nil {
		return err
	}
	after := sha256.Sum256(payload)
	var previousHash [32]byte
	copy(previousHash[:], previous)
	principal := publicid.ID(command.Session.PrincipalID())
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previousHash, EventID: event, ChangeID: change,
		AggregateKind: "network", AggregateID: publicid.ID(command.NetworkID), AggregateVersion: 1,
		NetworkRevision: 1, ActorPrincipalID: principal, Action: "network.created",
		Permission: string(authorization.PermissionNetworkCreate), CorrelationID: command.CorrelationID,
		AfterSemanticHash: after, AuditPayloadHash: after, OutboxEventClass: "network.created", OutboxPayloadHash: after,
	})
	if err != nil {
		return err
	}
	var appended int64
	return tx.QueryRow(ctx, appendNetworkCreationEvidenceSQL, streamID, event.String(), outbox.String(), sequence,
		previousHash[:], eventHash[:], command.NetworkID.String(), principal.String(), command.CorrelationID.String(),
		after[:], payload).Scan(&appended)
}
